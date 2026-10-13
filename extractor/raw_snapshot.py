"""Raw Runtime Snapshot model representing physical process state captured in microseconds.

Stores raw memory regions, thread registers, and provenance without halting the process
for heavy semantic traversal.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
import struct
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass
class RawMemoryRegion:
    region_id: str
    start: int
    end: int
    size: int
    permissions: str
    category: str
    pathname: str
    data: Optional[bytes] = None
    captured_bytes: int = 0
    status: str = "COMPLETE"  # COMPLETE, PARTIAL, FAILED
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
            "captured_bytes": self.captured_bytes,
            "status": self.status,
            "error": self.error,
        }


@dataclass
class RawRuntimeSnapshot:
    """Artifact representing raw physical runtime process state captured at runtime."""
    snapshot_id: str
    pid: int
    executable: str
    executable_build_id: Optional[str]
    timestamp: str
    capture_duration_us: float
    thread_metadata: List[Dict[str, Any]] = field(default_factory=list)
    memory_regions: List[Dict[str, Any]] = field(default_factory=list)
    register_state: Dict[str, Any] = field(default_factory=dict)
    captured_ranges: List[Tuple[int, int]] = field(default_factory=list)
    raw_memory: Dict[str, Any] = field(default_factory=dict)
    capture_backend: str = "process_vm_readv"
    observation_metadata: Dict[str, Any] = field(default_factory=dict)
    completeness: str = "COMPLETE"
    provenance: Dict[str, Any] = field(default_factory=dict)

    # In-memory buffer mappings for fast offline reading: (start, end) -> bytes
    _buffers: Dict[Tuple[int, int], bytes] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.provenance:
            self.provenance = {
                "capture_backend": self.capture_backend,
                "pid": self.pid,
                "timestamp": self.timestamp,
                "capture_start": self.observation_metadata.get("capture_start"),
                "capture_end": self.observation_metadata.get("capture_end"),
                "duration": self.capture_duration_us / 1000.0,
                "thread_count": len(self.thread_metadata),
                "captured_region_count": len(self.memory_regions),
                "captured_bytes": sum(r.get("captured_bytes", 0) for r in self.memory_regions),
                "observation_point": self.observation_metadata.get("observation_point"),
                "executable_identity": {
                    "path": self.executable,
                    "build_id": self.executable_build_id
                }
            }
        self.completeness, self.provenance = self._enforce_canonical_quality_contract(
            completeness=self.completeness,
            provenance=self.provenance,
            memory_regions=self.memory_regions,
            thread_metadata=self.thread_metadata,
            observation_metadata=self.observation_metadata,
            captured_ranges=self.captured_ranges,
        )

    @property
    def latency_report(self):
        rep = self.observation_metadata.get("latency_report") or self.provenance.get("latency_report")
        if isinstance(rep, dict):
            from .capture_backend import CaptureLatencyReport
            return CaptureLatencyReport.from_dict(rep)
        return rep

    @property
    def stop_latency_us(self) -> float:
        rep = self.latency_report
        val = getattr(rep, "stop_latency_us", None) if rep else None
        return float(val) if val is not None else 0.0

    @property
    def memory_read_latency_us(self) -> float:
        rep = self.latency_report
        val = getattr(rep, "memory_capture_latency_us", None) if rep else None
        return float(val) if val is not None else 0.0

    @property
    def capture_latency_us(self) -> float:
        return self.memory_read_latency_us

    @property
    def resume_latency_us(self) -> float:
        rep = self.latency_report
        val = getattr(rep, "resume_latency_us", None) if rep else None
        return float(val) if val is not None else 0.0

    @property
    def total_capture_latency_us(self) -> float:
        rep = self.latency_report
        val = getattr(rep, "total_capture_latency_us", None) if rep else None
        return float(val) if val is not None else self.capture_duration_us

    @property
    def bytes_captured(self) -> int:
        return sum(r.get("captured_bytes", 0) for r in self.memory_regions)

    def register_buffer(self, start: int, data: bytes):
        end = start + len(data)
        self._buffers[(start, end)] = data

    def read_bytes(self, address: Any, size: int) -> Optional[bytes]:
        """Read arbitrary byte slice from registered memory buffers."""
        if isinstance(address, str):
            address = int(address, 16) if address.startswith("0x") else int(address)
        for (b_start, b_end), buf in self._buffers.items():
            if b_start <= address and (address + size) <= b_end:
                offset = address - b_start
                return buf[offset:offset + size]
        return None

    def read_ptr(self, address: int, ptr_size: int = 8, endianness: str = "little") -> Optional[int]:
        data = self.read_bytes(address, ptr_size)
        if not data or len(data) < ptr_size:
            return None
        fmt = "<Q" if (ptr_size == 8 and endianness == "little") else (
            ">Q" if (ptr_size == 8) else (
                "<I" if (ptr_size == 4 and endianness == "little") else ">I"
            )
        )
        return struct.unpack(fmt, data)[0]

    def read_int(self, address: int, size: int = 4, signed: bool = True, endianness: str = "little") -> Optional[int]:
        data = self.read_bytes(address, size)
        if not data or len(data) < size:
            return None
        byteorder = "little" if endianness == "little" else "big"
        return int.from_bytes(data, byteorder=byteorder, signed=signed)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "pid": self.pid,
            "executable": self.executable,
            "executable_build_id": self.executable_build_id,
            "timestamp": self.timestamp,
            "capture_duration_us": self.capture_duration_us,
            "thread_metadata": self.thread_metadata,
            "memory_regions": self.memory_regions,
            "register_state": self.register_state,
            "captured_ranges": [
                ["0x{:x}".format(r[0]), "0x{:x}".format(r[1])] for r in self.captured_ranges
            ],
            "raw_memory": self.raw_memory,
            "capture_backend": self.capture_backend,
            "observation_metadata": self.observation_metadata,
            "completeness": self.completeness,
            "provenance": self.provenance,
        }

    @classmethod
    def _enforce_canonical_quality_contract(
        cls,
        completeness: str,
        provenance: Dict[str, Any],
        memory_regions: List[Dict[str, Any]],
        thread_metadata: List[Dict[str, Any]],
        observation_metadata: Optional[Dict[str, Any]] = None,
        captured_ranges: Optional[List[Tuple[int, int]]] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """Define and enforce the monotonic capture quality contract across the system.

        Canonical quality states:
        - COMPLETE: Target identity verified, inferior confirmed stopped and all threads settled,
                    all requested memory regions captured, and map/thread metadata enumerated successfully.
        - PARTIAL:  Target identity verified and capture was safe, but some non-fatal regions,
                    thread metadata, or optional sections were missing or truncated, or map enumeration
                    failed during targeted capture with explicit usable ranges, or capture was non-atomic.
        - INVALID:  Process identity mismatch, PID reuse detected, target exited before capture,
                    stop could not be verified safely, or memory read could not be confirmed as belonging
                    to the intended process.
        - FAILED:   Fatal capture error, permission denied, 0 bytes read on an intended capture,
                    or map enumeration failed in FULL capture mode.

        Monotonicity guarantee:
        Downstream transformations may preserve or lower trust, never upgrade it without new validating evidence.
        """
        prov = dict(provenance or {})
        obs_meta = dict(observation_metadata or {})
        id_contract = prov.get("identity_contract", {}) or obs_meta.get("identity_contract", {}) or {}

        # 0. Malformed or unknown completeness values: never silently upgrade to COMPLETE
        valid_completeness = {"COMPLETE", "PARTIAL", "INVALID", "FAILED"}
        if completeness not in valid_completeness:
            original_comp = str(completeness)
            prov.setdefault("diagnostics", []).append({
                "code": "MALFORMED_QUALITY_VALUE",
                "message": f"Malformed or unknown completeness value '{original_comp}' conservatively clamped to PARTIAL.",
                "level": "WARNING"
            })
            prov["original_malformed_completeness"] = original_comp
            completeness = "PARTIAL"

        # 1. INVALID conditions (identity mismatch, PID reuse, unverified stop safety)
        if (
            id_contract.get("identity_mismatch_detected")
            or id_contract.get("validity") == "INVALID"
            or prov.get("capture_status") == "INVALID"
            or obs_meta.get("capture_status") == "INVALID"
            or completeness == "INVALID"
        ):
            return "INVALID", prov

        # 2. FAILED conditions (fatal capture errors, 0 bytes read, or full-mode map failure)
        bytes_req = prov.get("bytes_requested") or obs_meta.get("bytes_requested", 0)
        bytes_read = prov.get("bytes_read", prov.get("captured_bytes", 0))
        cap_mode = prov.get("capture_mode") or obs_meta.get("capture_mode")
        map_status = prov.get("map_enumeration", {}).get("status") or obs_meta.get("map_enumeration", {}).get("status")

        if (
            prov.get("capture_status") == "FAILED"
            or obs_meta.get("capture_status") == "FAILED"
            or id_contract.get("validity") == "FAILED"
            or completeness == "FAILED"
            or (bytes_req > 0 and bytes_read == 0)
            or (cap_mode == "FULL" and (map_status == "FAILED" or (map_status == "SUCCESS_EMPTY" and len(memory_regions) == 0)))
        ):
            return "FAILED", prov

        # 3. PARTIAL conditions (incomplete enumeration, partial reads, missing threads, non-atomic, budget exceeded)
        if completeness == "PARTIAL":
            return "PARTIAL", prov

        thread_enum = prov.get("thread_enumeration", {}) or obs_meta.get("thread_enumeration", {})
        thread_status = thread_enum.get("status")
        thread_synthetic = thread_enum.get("is_synthetic", False)

        has_failed_reg = any(r.get("status") in ("FAILED", "PARTIAL", "OMITTED") for r in memory_regions)
        has_byte_shortfall = (bytes_req > 0 and bytes_read < bytes_req)

        # Byte accounting invariant: requested == read + omitted + failed + unread
        bytes_omitted = prov.get("bytes_omitted", 0)
        bytes_failed = prov.get("bytes_failed", 0)
        bytes_unread = prov.get("bytes_unread", 0)
        has_accounting_mismatch = False
        if bytes_req > 0:
            bytes_accounted = bytes_read + bytes_omitted + bytes_failed + bytes_unread
            if bytes_accounted != bytes_req:
                has_accounting_mismatch = True
                prov.setdefault("diagnostics", []).append({
                    "code": "BYTE_ACCOUNTING_INVARIANT_VIOLATED",
                    "message": f"Requested bytes ({bytes_req}) does not match sum of read ({bytes_read}), omitted ({bytes_omitted}), failed ({bytes_failed}), and unread ({bytes_unread}).",
                    "level": "WARNING"
                })

        has_partial_maps = map_status in ("PARTIAL", "FAILED")
        has_partial_threads = (
            thread_status in ("PARTIAL", "FAILED", "SUCCESS_EMPTY")
            or thread_synthetic
            or any(t.get("is_synthetic") is True or t.get("verified_observation") is False for t in thread_metadata)
        )

        guarantees = obs_meta.get("lifecycle_guarantees", {})
        was_stopped = obs_meta.get("was_already_stopped", False)
        stop_unconfirmed = (not was_stopped and guarantees.get("process_stop_requested", False) and not guarantees.get("process_stop_confirmed", False))
        threads_unconfirmed = ((guarantees.get("process_stop_requested", False) or was_stopped) and not guarantees.get("all_threads_stopped", False) and guarantees.get("process_stop_confirmed", False))
        is_non_atomic = (obs_meta.get("consistency_classification") == "NON_ATOMIC" or prov.get("snapshot_consistency") == "NON_ATOMIC")
        stop_budget_exceeded = prov.get("stop_budget_exceeded", False) or any(d.get("code") == "STOP_BUDGET_EXCEEDED" for d in prov.get("diagnostics", []))

        if (
            has_failed_reg
            or has_byte_shortfall
            or has_accounting_mismatch
            or has_partial_maps
            or has_partial_threads
            or stop_unconfirmed
            or threads_unconfirmed
            or is_non_atomic
            or stop_budget_exceeded
        ):
            return "PARTIAL", prov

        # 4. Legacy snapshot conservative policy:
        # If provenance is missing or marked legacy, do not infer COMPLETE merely because memory regions exist.
        # Classify unverifiable quality conservatively as PARTIAL under legacy migration policy,
        # unless modern verifiable lifecycle guarantees exist.
        is_legacy = (not provenance) or prov.get("is_legacy", False)
        if is_legacy:
            prov["is_legacy"] = True
            prov["legacy_migration_policy"] = "CONSERVATIVE_UNVERIFIABLE_TO_PARTIAL"
            has_verifiable_guarantees = (
                guarantees.get("process_stop_confirmed") is True
                and guarantees.get("all_threads_stopped") is True
                and not has_failed_reg
            )
            if not has_verifiable_guarantees:
                prov.setdefault("diagnostics", []).append({
                    "code": "LEGACY_SNAPSHOT_UNVERIFIABLE",
                    "message": "Snapshot lacks modern verified lifecycle provenance; classified conservatively as PARTIAL under legacy migration policy.",
                    "level": "WARNING"
                })
                return "PARTIAL", prov

        return "COMPLETE", prov

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RawRuntimeSnapshot":
        ranges = []
        for r in data.get("captured_ranges", []):
            if isinstance(r, (list, tuple)) and len(r) >= 2:
                s = int(r[0], 16) if isinstance(r[0], str) and r[0].startswith("0x") else int(r[0])
                e = int(r[1], 16) if isinstance(r[1], str) and r[1].startswith("0x") else int(r[1])
                ranges.append((s, e))

        declared_comp = data.get("completeness", "COMPLETE")
        prov = data.get("provenance", {}) or {}
        obs_meta = data.get("observation_metadata", {}) or {}
        mem_regs = data.get("memory_regions", [])
        th_meta = data.get("thread_metadata", [])

        completeness, prov = cls._enforce_canonical_quality_contract(
            completeness=declared_comp,
            provenance=prov,
            memory_regions=mem_regs,
            thread_metadata=th_meta,
            observation_metadata=obs_meta,
            captured_ranges=ranges,
        )

        return cls(
            snapshot_id=data["snapshot_id"],
            pid=data.get("pid", 0),
            executable=data.get("executable", ""),
            executable_build_id=data.get("executable_build_id"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            capture_duration_us=float(data.get("capture_duration_us", 0.0)),
            thread_metadata=th_meta,
            memory_regions=mem_regs,
            register_state=data.get("register_state", {}),
            captured_ranges=ranges,
            raw_memory=data.get("raw_memory", {}),
            capture_backend=data.get("capture_backend", "unknown"),
            observation_metadata=obs_meta,
            completeness=completeness,
            provenance=prov,
        )

    def save(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        meta_path = os.path.join(output_dir, "snapshot_metadata.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

        mem_dir = os.path.join(output_dir, "memory")
        os.makedirs(mem_dir, exist_ok=True)
        for idx, ((start, end), buf) in enumerate(self._buffers.items(), 1):
            fn = f"range_{idx:05d}_0x{start:x}_0x{end:x}.bin"
            with open(os.path.join(mem_dir, fn), "wb") as f:
                f.write(buf)

    @classmethod
    def load(cls, output_dir: str) -> "RawRuntimeSnapshot":
        meta_path = os.path.join(output_dir, "snapshot_metadata.json")
        with open(meta_path, "r", encoding="utf-8") as f:
            snap = cls.from_dict(json.load(f))

        mem_dir = os.path.join(output_dir, "memory")
        if os.path.exists(mem_dir):
            for fn in os.listdir(mem_dir):
                if fn.startswith("range_") and fn.endswith(".bin"):
                    parts = fn[:-4].split("_")
                    if len(parts) >= 4:
                        start = int(parts[2], 16)
                        end = int(parts[3], 16)
                        with open(os.path.join(mem_dir, fn), "rb") as f:
                            snap.register_buffer(start, f.read())
        return snap
