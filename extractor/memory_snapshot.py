"""Raw Memory Snapshot model and persistence for Phase 5.1.

Stores binary memory dumps and metadata decoupled from DWARF semantic interpretations:
- metadata.json: High-level snapshot summary, timings, consistency, and architecture
- manifest.json: Per-region metadata (start, end, permissions, captured size, status, file)
- maps.json: Complete /proc/<pid>/maps table at capture time
- memory/: Binary region dumps (region_000001.bin, ...)
"""

from dataclasses import asdict, dataclass, field
import errno
import fcntl
import json
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from .snapshot_consistency import NON_ATOMIC, SnapshotConsistency

# Process-local lock registry for canonical directory mutual exclusion across threads
_DIR_LOCK_REGISTRY_LOCK = threading.Lock()
_DIR_LOCK_REGISTRY: Dict[str, threading.Lock] = {}

def _get_process_dir_lock(canonical_path: str) -> threading.Lock:
    with _DIR_LOCK_REGISTRY_LOCK:
        if canonical_path not in _DIR_LOCK_REGISTRY:
            _DIR_LOCK_REGISTRY[canonical_path] = threading.Lock()
        return _DIR_LOCK_REGISTRY[canonical_path]


def _secure_open_write(path: str, encoding: str = "utf-8"):
    """Open file for writing with O_NOFOLLOW to avoid symlink traversal."""
    def opener(p, flags):
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        return os.open(p, flags, 0o644)
    return open(path, "w", encoding=encoding, opener=opener)


def _secure_open_temp_write(path: str, encoding: str = "utf-8"):
    """Open temporary file for exclusive writing with O_CREAT | O_EXCL | O_NOFOLLOW to avoid symlink hijacking."""
    def opener(p, flags):
        flags |= os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        return os.open(p, flags, 0o644)
    return open(path, "w", encoding=encoding, opener=opener)


def _secure_open_read(path: str, encoding: str = "utf-8"):
    """Open file for reading with O_NOFOLLOW | O_CLOEXEC to prevent following symlinks atomically."""
    def opener(p, flags):
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = os.open(p, flags)
        if not hasattr(os, "O_NOFOLLOW") and os.path.islink(p):
            os.close(fd)
            raise OSError(f"Refusing to read symbolic link: {p}")
        return fd
    return open(path, "r", encoding=encoding, opener=opener)

# Snapshot commit lifecycle states
STATE_CAPTURE_IN_PROGRESS = "CAPTURE_IN_PROGRESS"
STATE_COMMITTED = "COMMITTED"
STATE_INVALID = "INVALID"
STATE_INCOMPLETE = "INCOMPLETE"

# Validation verdicts
VERDICT_VALIDATED = "VALIDATED"
VERDICT_UNVERIFIED = "UNVERIFIED"
VERDICT_INVALID = "INVALID"

PROVENANCE_CLASS_IMPORTED_UNVERIFIED = "IMPORTED_UNVERIFIED"
PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE = "LIVE_RUNTIME_CAPTURE"


@dataclass
class CapturedRegion:
    region_id: str
    start: int
    end: int
    size: int
    permissions: str
    category: str
    pathname: str
    requested: int
    captured: int
    status: str                         # "COMPLETE", "PARTIAL", "FAILED"
    filename: Optional[str] = None      # e.g. "memory/region_000001.bin"
    error: Optional[str] = None

    @property
    def start_addr(self) -> int:
        return self.start

    @property
    def end_addr(self) -> int:
        return self.end

    def to_dict(self) -> Dict[str, Any]:
        return {
            "region_id": self.region_id,
            "start": "0x{:x}".format(self.start),
            "end": "0x{:x}".format(self.end),
            "start_addr": self.start,
            "end_addr": self.end,
            "size": self.size,
            "permissions": self.permissions,
            "category": self.category,
            "pathname": self.pathname,
            "requested": self.requested,
            "captured": self.captured,
            "status": self.status,
            "filename": self.filename,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapturedRegion":
        start_val = data.get("start_addr")
        if start_val is None:
            s_str = data.get("start", "0")
            start_val = int(s_str, 16) if isinstance(s_str, str) and s_str.startswith("0x") else int(s_str)
        end_val = data.get("end_addr")
        if end_val is None:
            e_str = data.get("end", "0")
            end_val = int(e_str, 16) if isinstance(e_str, str) and e_str.startswith("0x") else int(e_str)

        return cls(
            region_id=data["region_id"],
            start=start_val,
            end=end_val,
            size=data.get("size", end_val - start_val),
            permissions=data.get("permissions", "r--p"),
            category=data.get("category", "unknown"),
            pathname=data.get("pathname", ""),
            requested=data.get("requested", 0),
            captured=data.get("captured", 0),
            status=data.get("status", "COMPLETE"),
            filename=data.get("filename"),
            error=data.get("error"),
        )


@dataclass
class RawMemorySnapshot:
    """Artifact representing raw physical process memory captured at runtime."""
    snapshot_id: str
    pid: int
    binary: str
    timestamp_ns: int
    capture_mode: str = "LOW_IMPACT"
    backend: str = "process_vm_readv"
    architecture: str = "unknown"
    endianness: str = "UNKNOWN"
    elf_class: Optional[str] = None
    page_size: int = 4096
    status: str = "COMPLETE"            # "COMPLETE", "PARTIAL", "FAILED"
    timed_out: bool = False
    timeout_ms: int = 0
    committed: bool = True
    commit_timestamp_ns: int = 0
    regions_requested: int = 0
    regions_captured: int = 0
    bytes_requested: int = 0
    bytes_captured: int = 0
    partial_reads: int = 0
    failed_reads: int = 0
    duration_us: float = 0.0
    capture_start_ns: int = 0
    capture_end_ns: int = 0
    consistency: Dict[str, Any] = field(default_factory=lambda: {"level": NON_ATOMIC})
    capture: Dict[str, Any] = field(default_factory=lambda: {
        "backend": "process_vm_readv",
        "process_stop": False,
        "ptrace": False,
        "sigstop": False,
        "sigcont": False
    })
    mapping_race_detected: bool = False
    process_exited: bool = False
    process_starttime: int = 0
    modules: List[Dict[str, Any]] = field(default_factory=list)
    output_dir: str = ""
    regions: List[CapturedRegion] = field(default_factory=list)
    maps: List[Dict[str, Any]] = field(default_factory=list)
    integrity_warnings: List[str] = field(default_factory=list)
    validation_verdict: str = VERDICT_UNVERIFIED
    commit_state: str = STATE_COMMITTED
    schema_version: str = "1.0"

    def to_metadata(self) -> Dict[str, Any]:
        actual_captured_cnt = sum(1 for r in self.regions if r.status in ("COMPLETE", "PARTIAL") and r.captured > 0)
        actual_captured_sz = sum(r.captured for r in self.regions)
        actual_requested_cnt = len(self.regions)
        actual_requested_sz = sum(r.requested for r in self.regions)

        reg_captured = self.regions_captured if self.regions_captured > 0 else actual_captured_cnt
        b_captured = self.bytes_captured if self.bytes_captured > 0 else actual_captured_sz
        reg_requested = self.regions_requested if self.regions_requested > 0 else actual_requested_cnt
        b_requested = self.bytes_requested if self.bytes_requested > 0 else actual_requested_sz

        return {
            "snapshot_id": self.snapshot_id,
            "pid": self.pid,
            "binary": self.binary,
            "timestamp_ns": self.timestamp_ns,
            "schema_version": getattr(self, "schema_version", "1.0"),
            "commit_state": getattr(self, "commit_state", STATE_COMMITTED),
            "validation_verdict": getattr(self, "validation_verdict", VERDICT_UNVERIFIED),
            "capture_mode": self.capture_mode,
            "backend": self.backend,
            "architecture": self.architecture,
            "endianness": self.endianness,
            "elf_class": self.elf_class,
            "page_size": self.page_size,
            "status": self.status,
            "timed_out": self.timed_out,
            "timeout_ms": self.timeout_ms,
            "committed": self.committed,
            "commit_timestamp_ns": self.commit_timestamp_ns,
            "integrity_warnings": list(self.integrity_warnings),
            "mapping_race_detected": self.mapping_race_detected,
            "process_exited": self.process_exited,
            "process_starttime": self.process_starttime,
            "capture": self.capture,
            "regions": reg_captured,
            "regions_requested": reg_requested,
            "bytes_requested": b_requested,
            "bytes_captured": b_captured,
            "partial_reads": self.partial_reads,
            "failed_reads": self.failed_reads,
            "duration_us": round(self.duration_us, 3),
            "duration_ms": round(self.duration_us / 1000.0, 3),
            "capture_start_ns": self.capture_start_ns,
            "capture_end_ns": self.capture_end_ns,
            "consistency": self.consistency,
            "modules": [m.to_dict() if hasattr(m, "to_dict") else m for m in self.modules],
        }

    def to_dict(self) -> Dict[str, Any]:
        res = self.to_metadata()
        res["output_dir"] = self.output_dir
        res["manifest"] = [r.to_dict() for r in self.regions]
        return res

    def save(self, output_dir: Optional[str] = None) -> str:
        """Persist metadata, manifest, and maps to the output directory atomically with directory locking."""
        target_dir = output_dir or self.output_dir
        if not target_dir:
            raise ValueError("output_dir must be specified")
        self.output_dir = os.path.abspath(target_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "memory"), exist_ok=True)

        # 1. Process-local thread synchronization on canonical path
        canonical_dir = os.path.realpath(self.output_dir)
        thread_lock = _get_process_dir_lock(canonical_dir)
        acquired_thread_lock = thread_lock.acquire(blocking=False)
        if not acquired_thread_lock:
            raise BlockingIOError(f"Output directory '{self.output_dir}' is locked by another thread in this process")

        try:
            # 2. Cross-process mutual exclusion via .collector.lock
            lock_path = os.path.join(self.output_dir, ".collector.lock")
            # Refuse to follow symlinks when opening lock_path
            open_flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                open_flags |= os.O_NOFOLLOW
            try:
                lock_fd = os.open(lock_path, open_flags, 0o644)
            except OSError as e:
                raise BlockingIOError(f"Failed opening lock file in '{self.output_dir}' (symlink or permission error): {e}")

            try:
                try:
                    fcntl.lockf(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except (IOError, OSError) as e:
                    raise BlockingIOError(f"Output directory '{self.output_dir}' is locked by another process: {e}")

                # Open directory FD early to pin directory identity against parent replacement
                dir_open_flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    dir_open_flags |= os.O_DIRECTORY
                if hasattr(os, "O_CLOEXEC"):
                    dir_open_flags |= os.O_CLOEXEC
                try:
                    dir_fd = os.open(self.output_dir, dir_open_flags)
                except OSError as e:
                    self.commit_state = STATE_INVALID
                    raise OSError(f"Failed opening snapshot directory '{self.output_dir}': {e}") from e

                try:
                    # Safe per-call unique suffix to prevent collisions across threads and processes
                    unique_suffix = f"{os.getpid()}_{time.time_ns()}_{uuid.uuid4().hex[:8]}"

                    # Clear committed state while capture persistence is in progress
                    self.committed = False
                    self.commit_state = STATE_CAPTURE_IN_PROGRESS

                    # Invalidate any pre-existing metadata.json to ensure stale commits never certify partial writes
                    meta_path = os.path.join(self.output_dir, "metadata.json")
                    if os.path.exists(meta_path):
                        try:
                            os.unlink(meta_path)
                        except OSError as e:
                            if e.errno != errno.ENOENT:
                                self.commit_state = STATE_INVALID
                                raise OSError(f"Failed invalidating stale metadata before save: {e}") from e

                    # Track created temporary files to ensure cleanup if writing/fsync fails
                    created_tmps: List[str] = []
                    try:
                        # 1. manifest.json atomically with O_CREAT|O_EXCL
                        manifest_path = os.path.join(self.output_dir, "manifest.json")
                        manifest_tmp = os.path.join(self.output_dir, f"manifest.json.tmp.{unique_suffix}")
                        created_tmps.append(manifest_tmp)
                        with _secure_open_temp_write(manifest_tmp) as f:
                            json.dump([r.to_dict() for r in self.regions], f, indent=2)
                            f.flush()
                            os.fsync(f.fileno())
                        os.replace(manifest_tmp, manifest_path)
                        created_tmps.remove(manifest_tmp)

                        # 2. maps.json atomically with O_CREAT|O_EXCL
                        maps_path = os.path.join(self.output_dir, "maps.json")
                        maps_tmp = os.path.join(self.output_dir, f"maps.json.tmp.{unique_suffix}")
                        created_tmps.append(maps_tmp)
                        with _secure_open_temp_write(maps_tmp) as f:
                            json.dump(self.maps, f, indent=2)
                            f.flush()
                            os.fsync(f.fileno())
                        os.replace(maps_tmp, maps_path)
                        created_tmps.remove(maps_tmp)

                        # 3. modules.json atomically with O_CREAT|O_EXCL
                        modules_path = os.path.join(self.output_dir, "modules.json")
                        modules_tmp = os.path.join(self.output_dir, f"modules.json.tmp.{unique_suffix}")
                        created_tmps.append(modules_tmp)
                        mods_data = [m.to_dict() if hasattr(m, "to_dict") else m for m in self.modules]
                        with _secure_open_temp_write(modules_tmp) as f:
                            json.dump(mods_data, f, indent=2)
                            f.flush()
                            os.fsync(f.fileno())
                        os.replace(modules_tmp, modules_path)
                        created_tmps.remove(modules_tmp)

                        # 4. Flush output directory to persist artifact directory entries BEFORE publishing metadata
                        try:
                            os.fsync(dir_fd)
                        except OSError as e:
                            unsupported_errs = {errno.EINVAL, getattr(errno, "ENOTSUP", 95), getattr(errno, "EOPNOTSUPP", 95), getattr(errno, "ENOSYS", 38)}
                            if e.errno not in unsupported_errs:
                                raise OSError(f"Artifact directory fsync failed on '{self.output_dir}': {e}") from e

                        # 5. Write and fsync metadata temporary file
                        if self.commit_timestamp_ns <= 0:
                            self.commit_timestamp_ns = time.time_ns()
                        meta_tmp = os.path.join(self.output_dir, f"metadata.json.tmp.{unique_suffix}")
                        created_tmps.append(meta_tmp)
                        meta_dict = self.to_metadata()
                        meta_dict["committed"] = True
                        with _secure_open_temp_write(meta_tmp) as f:
                            json.dump(meta_dict, f, indent=2)
                            f.flush()
                            os.fsync(f.fileno())

                        # 6. Atomically rename metadata.json as the final commit marker
                        os.replace(meta_tmp, meta_path)
                        created_tmps.remove(meta_tmp)

                        # 7. Final directory fsync to persist metadata.json directory entry
                        try:
                            os.fsync(dir_fd)
                        except OSError as e:
                            unsupported_errs = {errno.EINVAL, getattr(errno, "ENOTSUP", 95), getattr(errno, "EOPNOTSUPP", 95), getattr(errno, "ENOSYS", 38)}
                            if e.errno not in unsupported_errs:
                                # Safe failure semantics: unpublish metadata immediately so incomplete durability cannot certify uncertain commit
                                try:
                                    os.unlink(meta_path)
                                except OSError:
                                    pass
                                self.committed = False
                                self.commit_state = STATE_INVALID
                                raise OSError(f"Final directory fsync failed; metadata unlinked to prevent uncertain commit: {e}") from e

                        # 8. Report COMMITTED only when all required durability operations have succeeded
                        self.committed = True
                        self.commit_state = STATE_COMMITTED
                        return self.output_dir
                    except Exception:
                        self.committed = False
                        self.commit_state = STATE_INVALID
                        for tmp_p in created_tmps:
                            try:
                                if os.path.exists(tmp_p):
                                    os.unlink(tmp_p)
                            except OSError:
                                pass
                        raise
                finally:
                    os.close(dir_fd)
            finally:
                try:
                    fcntl.lockf(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(lock_fd)
        finally:
            thread_lock.release()

    def validate_integrity(self) -> Tuple[bool, List[str]]:
        """Validates disk artifact integrity (commit status, region files, byte sizes, bounds)."""
        warnings: List[str] = []
        is_valid = True
        has_legacy_unverified = False

        if not self.output_dir:
            self.validation_verdict = VERDICT_INVALID
            return False, ["Snapshot output_dir is not specified."]

        if not os.path.isdir(self.output_dir):
            self.validation_verdict = VERDICT_INVALID
            return False, [f"Snapshot directory does not exist: {self.output_dir}"]

        if os.path.islink(self.output_dir):
            is_valid = False
            warnings.append(f"Snapshot directory is a symbolic link: {self.output_dir}")

        real_out = os.path.abspath(self.output_dir)

        # 1. Validate metadata.json
        meta_file = os.path.join(real_out, "metadata.json")
        meta_raw = None
        try:
            with _secure_open_read(meta_file) as f:
                meta_raw = json.load(f)
                if not isinstance(meta_raw, dict):
                    is_valid = False
                    warnings.append("metadata.json root is not a JSON object")
                else:
                    req_keys = ["snapshot_id", "pid", "status"]
                    for k in req_keys:
                        if k not in meta_raw:
                            is_valid = False
                            warnings.append(f"metadata.json missing required field '{k}'")
                    if "committed" not in meta_raw:
                        has_legacy_unverified = True
                        warnings.append("metadata.json missing legacy 'committed' field; marked UNVERIFIED")
        except FileNotFoundError:
            is_valid = False
            warnings.append(f"Missing metadata.json in {real_out}")
        except OSError as e:
            is_valid = False
            warnings.append(f"metadata.json cannot be securely read or is a symbolic link in {real_out}: {e}")
        except Exception as e:
            is_valid = False
            warnings.append(f"metadata.json is malformed or invalid JSON: {e}")

        # Check committed marker
        if self.committed is False or (meta_raw and meta_raw.get("committed") is False):
            is_valid = False
            self.commit_state = STATE_INVALID
            warnings.append("Snapshot was not cleanly committed (metadata 'committed' is false).")

        # 2. Validate manifest.json exists and is valid JSON list
        manifest_file = os.path.join(real_out, "manifest.json")
        manifest_raw = None
        try:
            with _secure_open_read(manifest_file) as f:
                manifest_raw = json.load(f)
                if not isinstance(manifest_raw, list):
                    is_valid = False
                    warnings.append("manifest.json root is not a JSON list")
                else:
                    seen_manifest_ids = set()
                    for m_idx, m_entry in enumerate(manifest_raw):
                        if not isinstance(m_entry, dict):
                            is_valid = False
                            warnings.append(f"Manifest entry {m_idx} is not a JSON object")
                            continue

                        m_id = m_entry.get("region_id")
                        if not m_id:
                            is_valid = False
                            warnings.append(f"Manifest entry {m_idx} missing region_id")
                        elif m_id in seen_manifest_ids:
                            is_valid = False
                            warnings.append(f"Duplicate region_id '{m_id}' in manifest.json")
                        else:
                            seen_manifest_ids.add(m_id)

                        # Range and size validation on disk manifest entry
                        start_val = m_entry.get("start_addr")
                        end_val = m_entry.get("end_addr")
                        sz_val = m_entry.get("size")
                        req_val = m_entry.get("requested", 0)
                        cap_val = m_entry.get("captured", 0)

                        if start_val is None and "start" in m_entry:
                            try:
                                start_val = int(str(m_entry["start"]), 0)
                            except Exception:
                                pass
                        if end_val is None and "end" in m_entry:
                            try:
                                end_val = int(str(m_entry["end"]), 0)
                            except Exception:
                                pass

                        if start_val is not None and end_val is not None:
                            if start_val < 0 or end_val < 0:
                                is_valid = False
                                warnings.append(f"Manifest entry {m_id} has negative address: start={start_val}, end={end_val}")
                            elif start_val >= end_val:
                                is_valid = False
                                warnings.append(f"Manifest entry {m_id} has inverted/empty address range: start 0x{start_val:x} >= end 0x{end_val:x}")
                            if sz_val is not None and sz_val > 0 and sz_val > (end_val - start_val):
                                is_valid = False
                                warnings.append(f"Manifest entry {m_id} size exceeds address range: size={sz_val} > end-start={end_val - start_val}")

                        if sz_val is not None and sz_val <= 0:
                            is_valid = False
                            warnings.append(f"Manifest entry {m_id} has non-positive size: {sz_val}")

                        if req_val is not None and req_val < 0:
                            is_valid = False
                            warnings.append(f"Manifest entry {m_id} has negative requested bytes: {req_val}")

                        if cap_val is not None and cap_val < 0:
                            is_valid = False
                            warnings.append(f"Manifest entry {m_id} has negative captured bytes: {cap_val}")

                        if req_val is not None and cap_val is not None and req_val > 0 and cap_val > req_val:
                            is_valid = False
                            warnings.append(f"Manifest entry {m_id} captured ({cap_val}) exceeds requested ({req_val})")

                        # Cross-check disk manifest entries with in-memory regions if present
                        if self.regions and len(manifest_raw) != len(self.regions):
                            is_valid = False
                            warnings.append(
                                f"Manifest entry count mismatch: disk has {len(manifest_raw)}, memory has {len(self.regions)}"
                            )
                        elif self.regions:
                            for idx, (m_entry, r_obj) in enumerate(zip(manifest_raw, self.regions)):
                                if isinstance(m_entry, dict):
                                    if m_entry.get("region_id") != r_obj.region_id:
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} ID mismatch: disk '{m_entry.get('region_id')}' != memory '{r_obj.region_id}'")
                                    if m_entry.get("status") != r_obj.status:
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} status mismatch: disk '{m_entry.get('status')}' != memory '{r_obj.status}'")

                                    # Address checks
                                    m_s = m_entry.get("start_addr")
                                    if m_s is None and "start" in m_entry:
                                        try:
                                            m_s = int(str(m_entry["start"]), 0)
                                        except Exception:
                                            pass
                                    if m_s is not None and m_s != r_obj.start_addr:
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} start_addr mismatch: disk {m_s} != memory {r_obj.start_addr}")

                                    m_e = m_entry.get("end_addr")
                                    if m_e is None and "end" in m_entry:
                                        try:
                                            m_e = int(str(m_entry["end"]), 0)
                                        except Exception:
                                            pass
                                    if m_e is not None and m_e != r_obj.end_addr:
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} end_addr mismatch: disk {m_e} != memory {r_obj.end_addr}")

                                    if m_entry.get("size") is not None and m_entry.get("size") != r_obj.size:
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} size mismatch: disk {m_entry.get('size')} != memory {r_obj.size}")
                                    if m_entry.get("permissions") is not None and m_entry.get("permissions") != r_obj.permissions:
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} permissions mismatch: disk '{m_entry.get('permissions')}' != memory '{r_obj.permissions}'")
                                    if m_entry.get("category") is not None and m_entry.get("category") != r_obj.category:
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} category mismatch: disk '{m_entry.get('category')}' != memory '{r_obj.category}'")
                                    if m_entry.get("pathname") is not None and m_entry.get("pathname") != r_obj.pathname:
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} pathname mismatch: disk '{m_entry.get('pathname')}' != memory '{r_obj.pathname}'")
                                    if m_entry.get("requested") is not None and m_entry.get("requested") != r_obj.requested:
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} requested mismatch: disk {m_entry.get('requested')} != memory {r_obj.requested}")
                                    if m_entry.get("captured") is not None and m_entry.get("captured") != r_obj.captured:
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} captured mismatch: disk {m_entry.get('captured')} != memory {r_obj.captured}")
                                    if m_entry.get("filename") is not None and m_entry.get("filename") != (r_obj.filename or ""):
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} filename mismatch: disk '{m_entry.get('filename')}' != memory '{r_obj.filename}'")
                                    if "error" in m_entry and m_entry.get("error") != r_obj.error:
                                        is_valid = False
                                        warnings.append(f"Manifest region {idx} error mismatch: disk '{m_entry.get('error')}' != memory '{r_obj.error}'")
        except FileNotFoundError:
            is_valid = False
            warnings.append(f"Missing manifest.json in {real_out}")
        except OSError as e:
            is_valid = False
            warnings.append(f"manifest.json cannot be securely read or is a symbolic link in {real_out}: {e}")
        except Exception as e:
            is_valid = False
            warnings.append(f"manifest.json is malformed or invalid JSON: {e}")

        # 3. Validate maps.json exists and is valid JSON list
        maps_file = os.path.join(real_out, "maps.json")
        try:
            with _secure_open_read(maps_file) as f:
                maps_raw = json.load(f)
                if not isinstance(maps_raw, list):
                    is_valid = False
                    warnings.append("maps.json root is not a JSON list")
        except FileNotFoundError:
            is_valid = False
            warnings.append(f"Missing maps.json in {real_out}")
        except OSError as e:
            is_valid = False
            warnings.append(f"maps.json cannot be securely read or is a symbolic link in {real_out}: {e}")
        except Exception as e:
            is_valid = False
            warnings.append(f"maps.json is malformed or invalid JSON: {e}")

        # Check snapshot identity agreement between metadata and in-memory object
        if meta_raw and isinstance(meta_raw, dict):
            if meta_raw.get("snapshot_id") != self.snapshot_id:
                is_valid = False
                warnings.append(
                    f"Snapshot ID mismatch: metadata.json reports '{meta_raw.get('snapshot_id')}', but memory object has '{self.snapshot_id}'"
                )
            if meta_raw.get("pid") != self.pid:
                is_valid = False
                warnings.append(
                    f"PID mismatch: metadata.json reports {meta_raw.get('pid')}, but memory object has {self.pid}"
                )

        # 4. Validate regions, file paths, traversal, actual sizes, and statuses
        mem_dir = os.path.join(real_out, "memory")
        if os.path.islink(mem_dir):
            is_valid = False
            warnings.append(f"Memory directory is a symbolic link: {mem_dir}")

        seen_region_ids = set()
        for r in self.regions:
            # Check duplicate region_id in memory regions
            if not r.region_id:
                is_valid = False
                warnings.append("Memory region has empty region_id")
            elif r.region_id in seen_region_ids:
                is_valid = False
                warnings.append(f"Duplicate region_id '{r.region_id}' in memory regions")
            else:
                seen_region_ids.add(r.region_id)

            # Check address bounds and ranges
            if r.start_addr < 0 or r.end_addr < 0:
                is_valid = False
                warnings.append(f"Region {r.region_id} has negative address: start={r.start_addr}, end={r.end_addr}")
            elif r.start_addr >= r.end_addr:
                is_valid = False
                warnings.append(f"Region {r.region_id} has inverted/empty address range: start 0x{r.start_addr:x} >= end 0x{r.end_addr:x}")

            if r.size <= 0:
                is_valid = False
                warnings.append(f"Region {r.region_id} has non-positive size: {r.size}")
            elif r.start_addr < r.end_addr and r.size > (r.end_addr - r.start_addr):
                is_valid = False
                warnings.append(f"Region {r.region_id} size exceeds address range: size={r.size} > end-start={r.end_addr - r.start_addr}")

            if r.requested < 0:
                is_valid = False
                warnings.append(f"Region {r.region_id} has negative requested bytes: {r.requested}")
            if r.captured < 0:
                is_valid = False
                warnings.append(f"Region {r.region_id} has negative captured bytes: {r.captured}")
            if r.requested > 0 and r.captured > r.requested:
                is_valid = False
                warnings.append(f"Region {r.region_id} captured ({r.captured}) exceeds requested ({r.requested})")

            # Check path traversal
            if r.filename:
                norm_rel = os.path.normpath(r.filename)
                if os.path.isabs(norm_rel) or norm_rel.startswith("..") or (".." in norm_rel.split(os.path.sep)):
                    is_valid = False
                    warnings.append(f"Region {r.region_id} filename attempts path traversal: '{r.filename}' (escapes snapshot directory)")
                    continue

                full_bin = os.path.abspath(os.path.join(real_out, norm_rel))
                try:
                    common = os.path.commonpath([real_out, full_bin])
                    if common != real_out:
                        is_valid = False
                        warnings.append(f"Region {r.region_id} path escapes snapshot directory: '{r.filename}'")
                        continue
                except ValueError:
                    is_valid = False
                    warnings.append(f"Region {r.region_id} path drive mismatch: '{r.filename}'")
                    continue

                # Check if any parent component inside snapshot directory is a symlink
                parent_check = os.path.dirname(full_bin)
                while parent_check and parent_check != real_out:
                    if os.path.islink(parent_check):
                        is_valid = False
                        warnings.append(f"Region {r.region_id} parent directory is a symbolic link: '{parent_check}'")
                        break
                    parent_check = os.path.dirname(parent_check)

            # Check region file and sizes
            if r.status in ("COMPLETE", "PARTIAL") and r.captured > 0:
                if not r.filename:
                    is_valid = False
                    warnings.append(f"Region {r.region_id} status is {r.status} ({r.captured} bytes) but filename is missing.")
                else:
                    bin_path = os.path.join(real_out, r.filename)
                    open_flags = os.O_RDONLY
                    if hasattr(os, "O_NOFOLLOW"):
                        open_flags |= os.O_NOFOLLOW
                    if hasattr(os, "O_CLOEXEC"):
                        open_flags |= os.O_CLOEXEC
                    try:
                        fd = os.open(bin_path, open_flags)
                        try:
                            actual_sz = os.fstat(fd).st_size
                            if actual_sz != r.captured:
                                is_valid = False
                                warnings.append(
                                    f"Region {r.region_id} binary file corrupted/truncated: {r.filename} "
                                    f"(expected {r.captured} bytes, found {actual_sz} bytes)"
                                )
                        finally:
                            os.close(fd)
                    except FileNotFoundError:
                        is_valid = False
                        warnings.append(f"Region {r.region_id} binary file missing on disk: {r.filename}")
                    except OSError as e:
                        is_valid = False
                        warnings.append(f"Region {r.region_id} binary file cannot be securely read or is a symbolic link: {r.filename} ({e})")
            elif r.status == "FAILED":
                if r.captured != 0:
                    is_valid = False
                    warnings.append(f"Region {r.region_id} status is FAILED but reports captured={r.captured} != 0")

            # Region status and size consistency
            if r.status == "COMPLETE":
                if r.requested > 0 and r.captured != r.requested:
                    is_valid = False
                    warnings.append(
                        f"Region {r.region_id} status is COMPLETE but captured bytes ({r.captured}) != requested bytes ({r.requested})"
                    )
            elif r.status == "PARTIAL":
                if r.captured <= 0 or (r.requested > 0 and r.captured >= r.requested):
                    is_valid = False
                    warnings.append(
                        f"Region {r.region_id} status is PARTIAL but captured bytes ({r.captured}) is inconsistent with requested ({r.requested})"
                    )

        # 5. Manifest and metadata region counts agreement
        actual_captured_count = sum(1 for r in self.regions if r.status in ("COMPLETE", "PARTIAL") and r.captured > 0)
        if self.regions_captured != actual_captured_count:
            is_valid = False
            warnings.append(
                f"Region count mismatch: metadata reports regions_captured={self.regions_captured}, "
                f"but manifest contains {actual_captured_count} captured regions"
            )

        if self.regions_requested > 0 and len(self.regions) != self.regions_requested:
            is_valid = False
            warnings.append(
                f"Total region count mismatch: metadata reports regions_requested={self.regions_requested}, "
                f"but manifest contains {len(self.regions)} regions"
            )

        # 6. Requested/captured byte counts agreement
        actual_captured_bytes = sum(r.captured for r in self.regions)
        if self.bytes_captured != actual_captured_bytes:
            is_valid = False
            warnings.append(
                f"Captured bytes mismatch: metadata reports bytes_captured={self.bytes_captured}, "
                f"but sum of manifest regions is {actual_captured_bytes}"
            )

        actual_requested_bytes = sum(r.requested for r in self.regions)
        if self.bytes_requested > 0 and self.bytes_requested != actual_requested_bytes:
            is_valid = False
            warnings.append(
                f"Requested bytes mismatch: metadata reports bytes_requested={self.bytes_requested}, "
                f"but sum of manifest regions is {actual_requested_bytes}"
            )

        if not is_valid:
            self.validation_verdict = VERDICT_INVALID
            self.commit_state = STATE_INVALID
            if self.status == "COMPLETE":
                self.status = "PARTIAL"
        elif has_legacy_unverified:
            self.validation_verdict = VERDICT_UNVERIFIED
        else:
            self.validation_verdict = VERDICT_VALIDATED

        self.integrity_warnings = list(warnings)
        if hasattr(self, "provenance") and isinstance(self.provenance, dict):
            self.provenance["validation_verdict"] = self.validation_verdict
            self.provenance["integrity_warnings"] = list(warnings)
            if not is_valid:
                self.provenance["provenance_class"] = PROVENANCE_CLASS_IMPORTED_UNVERIFIED

        return is_valid, warnings

    @classmethod
    def load(cls, directory: str) -> "RawMemorySnapshot":
        """Load a persisted raw memory snapshot from a directory."""
        if os.path.islink(directory):
            raise ValueError(f"Snapshot directory '{directory}' is a symbolic link; symlinks are rejected")

        dir_path = os.path.abspath(directory)
        meta_path = os.path.join(dir_path, "metadata.json")
        manifest_path = os.path.join(dir_path, "manifest.json")
        maps_path = os.path.join(dir_path, "maps.json")
        modules_path = os.path.join(dir_path, "modules.json")

        try:
            with _secure_open_read(meta_path) as f:
                meta = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Missing metadata.json in {dir_path}")
        except OSError as e:
            raise OSError(f"Cannot securely read metadata.json in {dir_path} (symlink or unreadable): {e}") from e

        regions = []
        manifest_err = None
        try:
            with _secure_open_read(manifest_path) as f:
                manifest_data = json.load(f)
                if isinstance(manifest_data, list):
                    regions = [CapturedRegion.from_dict(r) for r in manifest_data]
                else:
                    manifest_err = "manifest.json root is not a list"
        except FileNotFoundError:
            pass
        except Exception as e:
            manifest_err = f"manifest.json is malformed: {e}"

        maps = []
        maps_err = None
        try:
            with _secure_open_read(maps_path) as f:
                maps_data = json.load(f)
                if isinstance(maps_data, list):
                    maps = maps_data
                else:
                    maps_err = "maps.json root is not a list"
        except FileNotFoundError:
            pass
        except Exception as e:
            maps_err = f"maps.json is malformed: {e}"

        modules = []
        modules_err = None
        try:
            with _secure_open_read(modules_path) as f:
                modules = json.load(f)
        except FileNotFoundError:
            if "modules" in meta:
                modules = meta["modules"]
        except Exception as e:
            modules_err = f"modules.json is malformed: {e}"

        snap = cls(
            snapshot_id=meta.get("snapshot_id", "UNKNOWN"),
            pid=meta.get("pid", 0),
            binary=meta.get("binary", ""),
            timestamp_ns=meta.get("timestamp_ns", 0),
            capture_mode=meta.get("capture_mode", "LOW_IMPACT"),
            backend=meta.get("backend", "process_vm_readv"),
            architecture=meta.get("architecture", "unknown"),
            endianness=meta.get("endianness", "UNKNOWN"),
            elf_class=meta.get("elf_class"),
            page_size=meta.get("page_size", 4096),
            status=meta.get("status", "COMPLETE"),
            timed_out=meta.get("timed_out", False),
            timeout_ms=meta.get("timeout_ms", 0),
            committed=meta.get("committed", True),
            commit_timestamp_ns=meta.get("commit_timestamp_ns", 0),
            integrity_warnings=list(meta.get("integrity_warnings", [])),
            mapping_race_detected=meta.get("mapping_race_detected", False),
            process_exited=meta.get("process_exited", False),
            process_starttime=meta.get("process_starttime", 0),
            regions_requested=meta.get("regions_requested", len(regions)),
            regions_captured=meta.get("regions", len(regions)),
            bytes_requested=meta.get("bytes_requested", 0),
            bytes_captured=meta.get("bytes_captured", 0),
            partial_reads=meta.get("partial_reads", 0),
            failed_reads=meta.get("failed_reads", 0),
            duration_us=meta.get("duration_us", 0.0),
            capture_start_ns=meta.get("capture_start_ns", 0),
            capture_end_ns=meta.get("capture_end_ns", 0),
            consistency=meta.get("consistency", {"level": NON_ATOMIC}),
            capture=meta.get("capture", {
                "backend": "process_vm_readv",
                "process_stop": False,
                "ptrace": False,
                "sigstop": False,
                "sigcont": False
            }),
            modules=modules,
            output_dir=dir_path,
            regions=regions,
            maps=maps,
        )

        is_valid, validation_warnings = snap.validate_integrity()
        if manifest_err:
            is_valid = False
            validation_warnings.append(f"Corrupted artifact: {manifest_err}")
        if maps_err:
            is_valid = False
            validation_warnings.append(f"Corrupted artifact: {maps_err}")
        if modules_err:
            is_valid = False
            validation_warnings.append(f"Corrupted artifact: {modules_err}")

        if validation_warnings:
            for w in validation_warnings:
                if w not in snap.integrity_warnings:
                    snap.integrity_warnings.append(w)
        if not is_valid:
            if snap.status == "COMPLETE":
                snap.status = "PARTIAL"
                snap.integrity_warnings.append("Snapshot status degraded from COMPLETE to PARTIAL due to integrity check failures.")
            snap.commit_state = STATE_INVALID
            snap.validation_verdict = VERDICT_INVALID

        return snap
