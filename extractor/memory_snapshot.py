"""Raw Memory Snapshot model and persistence for Phase 5.1.

Stores binary memory dumps and metadata decoupled from DWARF semantic interpretations:
- metadata.json: High-level snapshot summary, timings, consistency, and architecture
- manifest.json: Per-region metadata (start, end, permissions, captured size, status, file)
- maps.json: Complete /proc/<pid>/maps table at capture time
- memory/: Binary region dumps (region_000001.bin, ...)
"""

from dataclasses import asdict, dataclass, field
import fcntl
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from .snapshot_consistency import NON_ATOMIC, SnapshotConsistency

# Snapshot commit lifecycle states
STATE_CAPTURE_IN_PROGRESS = "CAPTURE_IN_PROGRESS"
STATE_COMMITTED = "COMMITTED"
STATE_INVALID = "INVALID"
STATE_INCOMPLETE = "INCOMPLETE"

# Validation verdicts
VERDICT_VALIDATED = "VALIDATED"
VERDICT_UNVERIFIED = "UNVERIFIED"
VERDICT_INVALID = "INVALID"


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

        lock_path = os.path.join(self.output_dir, ".collector.lock")
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            try:
                fcntl.lockf(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (IOError, OSError) as e:
                raise BlockingIOError(f"Output directory '{self.output_dir}' is locked by another writer: {e}")

            # Safe per-call unique suffix to prevent collisions across threads and processes
            unique_suffix = f"{os.getpid()}_{uuid.uuid4().hex[:8]}"

            # Invalidate any pre-existing metadata.json to ensure stale commits never certify partial writes
            meta_path = os.path.join(self.output_dir, "metadata.json")
            if os.path.exists(meta_path):
                try:
                    os.unlink(meta_path)
                except OSError:
                    pass

            # 1. manifest.json atomically
            manifest_path = os.path.join(self.output_dir, "manifest.json")
            manifest_tmp = os.path.join(self.output_dir, f"manifest.json.tmp.{unique_suffix}")
            with open(manifest_tmp, "w", encoding="utf-8") as f:
                json.dump([r.to_dict() for r in self.regions], f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(manifest_tmp, manifest_path)

            # 2. maps.json atomically
            maps_path = os.path.join(self.output_dir, "maps.json")
            maps_tmp = os.path.join(self.output_dir, f"maps.json.tmp.{unique_suffix}")
            with open(maps_tmp, "w", encoding="utf-8") as f:
                json.dump(self.maps, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(maps_tmp, maps_path)

            # 3. modules.json atomically
            modules_path = os.path.join(self.output_dir, "modules.json")
            modules_tmp = os.path.join(self.output_dir, f"modules.json.tmp.{unique_suffix}")
            mods_data = [m.to_dict() if hasattr(m, "to_dict") else m for m in self.modules]
            with open(modules_tmp, "w", encoding="utf-8") as f:
                json.dump(mods_data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(modules_tmp, modules_path)

            # 4. metadata.json atomically as the final commit barrier
            self.committed = True
            self.commit_state = STATE_COMMITTED
            if self.commit_timestamp_ns <= 0:
                self.commit_timestamp_ns = time.time_ns()
            meta_tmp = os.path.join(self.output_dir, f"metadata.json.tmp.{unique_suffix}")
            with open(meta_tmp, "w", encoding="utf-8") as f:
                json.dump(self.to_metadata(), f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(meta_tmp, meta_path)

            # Flush directory entries to disk for durability where supported
            try:
                dir_fd = os.open(self.output_dir, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass

            return self.output_dir
        finally:
            try:
                fcntl.lockf(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(lock_fd)

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

        real_out = os.path.abspath(self.output_dir)

        # 1. Validate metadata.json
        meta_file = os.path.join(real_out, "metadata.json")
        meta_raw = None
        if not os.path.exists(meta_file):
            is_valid = False
            warnings.append(f"Missing metadata.json in {real_out}")
        else:
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
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
        if not os.path.exists(manifest_file):
            is_valid = False
            warnings.append(f"Missing manifest.json in {real_out}")
        else:
            try:
                with open(manifest_file, "r", encoding="utf-8") as f:
                    manifest_raw = json.load(f)
                    if not isinstance(manifest_raw, list):
                        is_valid = False
                        warnings.append("manifest.json root is not a JSON list")
            except Exception as e:
                is_valid = False
                warnings.append(f"manifest.json is malformed or invalid JSON: {e}")

        # 3. Validate maps.json exists and is valid JSON list
        maps_file = os.path.join(real_out, "maps.json")
        if not os.path.exists(maps_file):
            is_valid = False
            warnings.append(f"Missing maps.json in {real_out}")
        else:
            try:
                with open(maps_file, "r", encoding="utf-8") as f:
                    maps_raw = json.load(f)
                    if not isinstance(maps_raw, list):
                        is_valid = False
                        warnings.append("maps.json root is not a JSON list")
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
        for r in self.regions:
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
                    if not os.path.exists(bin_path):
                        is_valid = False
                        warnings.append(f"Region {r.region_id} binary file missing on disk: {r.filename}")
                    elif os.path.islink(bin_path):
                        is_valid = False
                        warnings.append(f"Region {r.region_id} binary file is a symbolic link: {r.filename}")
                    else:
                        try:
                            actual_sz = os.path.getsize(bin_path)
                            if actual_sz != r.captured:
                                is_valid = False
                                warnings.append(
                                    f"Region {r.region_id} binary file corrupted/truncated: {r.filename} "
                                    f"(expected {r.captured} bytes, found {actual_sz} bytes)"
                                )
                        except OSError as e:
                            is_valid = False
                            warnings.append(f"Failed inspecting region file {bin_path}: {e}")
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
        elif has_legacy_unverified:
            self.validation_verdict = VERDICT_UNVERIFIED
        else:
            self.validation_verdict = VERDICT_VALIDATED

        return is_valid, warnings

    @classmethod
    def load(cls, directory: str) -> "RawMemorySnapshot":
        """Load a persisted raw memory snapshot from a directory."""
        dir_path = os.path.abspath(directory)
        meta_path = os.path.join(dir_path, "metadata.json")
        manifest_path = os.path.join(dir_path, "manifest.json")
        maps_path = os.path.join(dir_path, "maps.json")
        modules_path = os.path.join(dir_path, "modules.json")

        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Missing metadata.json in {dir_path}")

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        regions = []
        manifest_err = None
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
                    if isinstance(manifest_data, list):
                        regions = [CapturedRegion.from_dict(r) for r in manifest_data]
                    else:
                        manifest_err = "manifest.json root is not a list"
            except Exception as e:
                manifest_err = f"manifest.json is malformed: {e}"

        maps = []
        maps_err = None
        if os.path.exists(maps_path):
            try:
                with open(maps_path, "r", encoding="utf-8") as f:
                    maps_data = json.load(f)
                    if isinstance(maps_data, list):
                        maps = maps_data
                    else:
                        maps_err = "maps.json root is not a list"
            except Exception as e:
                maps_err = f"maps.json is malformed: {e}"

        modules = []
        modules_err = None
        if os.path.exists(modules_path):
            try:
                with open(modules_path, "r", encoding="utf-8") as f:
                    modules = json.load(f)
            except Exception as e:
                modules_err = f"modules.json is malformed: {e}"
        elif "modules" in meta:
            modules = meta["modules"]

        snap = cls(
            snapshot_id=meta["snapshot_id"],
            pid=meta["pid"],
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
