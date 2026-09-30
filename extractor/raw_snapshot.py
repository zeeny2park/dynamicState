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
        return getattr(rep, "stop_latency_us", 0.0) if rep else 0.0

    @property
    def memory_read_latency_us(self) -> float:
        rep = self.latency_report
        return getattr(rep, "memory_capture_latency_us", 0.0) if rep else 0.0

    @property
    def capture_latency_us(self) -> float:
        return self.memory_read_latency_us

    @property
    def resume_latency_us(self) -> float:
        rep = self.latency_report
        return getattr(rep, "resume_latency_us", 0.0) if rep else 0.0

    @property
    def total_capture_latency_us(self) -> float:
        rep = self.latency_report
        return getattr(rep, "total_capture_latency_us", 0.0) if rep else self.capture_duration_us

    @property
    def bytes_captured(self) -> int:
        return sum(r.get("captured_bytes", 0) for r in self.memory_regions)

    def register_buffer(self, start: int, data: bytes):
        end = start + len(data)
        self._buffers[(start, end)] = data

    def read_bytes(self, address: int, size: int) -> Optional[bytes]:
        """Read arbitrary byte slice from registered memory buffers."""
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
    def from_dict(cls, data: Dict[str, Any]) -> "RawRuntimeSnapshot":
        ranges = []
        for r in data.get("captured_ranges", []):
            if isinstance(r, (list, tuple)) and len(r) >= 2:
                s = int(r[0], 16) if isinstance(r[0], str) and r[0].startswith("0x") else int(r[0])
                e = int(r[1], 16) if isinstance(r[1], str) and r[1].startswith("0x") else int(r[1])
                ranges.append((s, e))

        return cls(
            snapshot_id=data["snapshot_id"],
            pid=data.get("pid", 0),
            executable=data.get("executable", ""),
            executable_build_id=data.get("executable_build_id"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            capture_duration_us=float(data.get("capture_duration_us", 0.0)),
            thread_metadata=data.get("thread_metadata", []),
            memory_regions=data.get("memory_regions", []),
            register_state=data.get("register_state", {}),
            captured_ranges=ranges,
            raw_memory=data.get("raw_memory", {}),
            capture_backend=data.get("capture_backend", "unknown"),
            observation_metadata=data.get("observation_metadata", {}),
            completeness=data.get("completeness", "COMPLETE"),
            provenance=data.get("provenance", {}),
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
