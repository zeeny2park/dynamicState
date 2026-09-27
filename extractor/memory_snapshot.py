"""Raw Memory Snapshot model and persistence for Phase 5.1.

Stores binary memory dumps and metadata decoupled from DWARF semantic interpretations:
- metadata.json: High-level snapshot summary, timings, consistency, and architecture
- manifest.json: Per-region metadata (start, end, permissions, captured size, status, file)
- maps.json: Complete /proc/<pid>/maps table at capture time
- memory/: Binary region dumps (region_000001.bin, ...)
"""

from dataclasses import asdict, dataclass, field
import json
import os
import time
from typing import Any, Dict, List, Optional
from .snapshot_consistency import NON_ATOMIC, SnapshotConsistency


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
    architecture: str = "x86_64"
    endianness: str = "little"
    page_size: int = 4096
    status: str = "COMPLETE"            # "COMPLETE", "PARTIAL", "FAILED"
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
    output_dir: str = ""
    regions: List[CapturedRegion] = field(default_factory=list)
    maps: List[Dict[str, Any]] = field(default_factory=list)

    def to_metadata(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "pid": self.pid,
            "binary": self.binary,
            "timestamp_ns": self.timestamp_ns,
            "capture_mode": self.capture_mode,
            "backend": self.backend,
            "architecture": self.architecture,
            "endianness": self.endianness,
            "page_size": self.page_size,
            "status": self.status,
            "regions": self.regions_captured,
            "regions_requested": self.regions_requested,
            "bytes_requested": self.bytes_requested,
            "bytes_captured": self.bytes_captured,
            "partial_reads": self.partial_reads,
            "failed_reads": self.failed_reads,
            "duration_us": round(self.duration_us, 3),
            "capture_start_ns": self.capture_start_ns,
            "capture_end_ns": self.capture_end_ns,
            "consistency": self.consistency,
        }

    def to_dict(self) -> Dict[str, Any]:
        res = self.to_metadata()
        res["output_dir"] = self.output_dir
        res["manifest"] = [r.to_dict() for r in self.regions]
        return res

    def save(self, output_dir: Optional[str] = None) -> str:
        """Persist metadata, manifest, and maps to the output directory."""
        target_dir = output_dir or self.output_dir
        if not target_dir:
            raise ValueError("output_dir must be specified")
        self.output_dir = os.path.abspath(target_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "memory"), exist_ok=True)

        # 1. metadata.json
        meta_path = os.path.join(self.output_dir, "metadata.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(self.to_metadata(), f, indent=2)

        # 2. manifest.json
        manifest_path = os.path.join(self.output_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in self.regions], f, indent=2)

        # 3. maps.json
        maps_path = os.path.join(self.output_dir, "maps.json")
        with open(maps_path, "w", encoding="utf-8") as f:
            json.dump(self.maps, f, indent=2)

        return self.output_dir

    @classmethod
    def load(cls, directory: str) -> "RawMemorySnapshot":
        """Load a persisted raw memory snapshot from a directory."""
        dir_path = os.path.abspath(directory)
        meta_path = os.path.join(dir_path, "metadata.json")
        manifest_path = os.path.join(dir_path, "manifest.json")
        maps_path = os.path.join(dir_path, "maps.json")

        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Missing metadata.json in {dir_path}")

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        regions = []
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
                regions = [CapturedRegion.from_dict(r) for r in manifest_data]

        maps = []
        if os.path.exists(maps_path):
            with open(maps_path, "r", encoding="utf-8") as f:
                maps = json.load(f)

        return cls(
            snapshot_id=meta["snapshot_id"],
            pid=meta["pid"],
            binary=meta.get("binary", ""),
            timestamp_ns=meta.get("timestamp_ns", 0),
            capture_mode=meta.get("capture_mode", "LOW_IMPACT"),
            backend=meta.get("backend", "process_vm_readv"),
            architecture=meta.get("architecture", "x86_64"),
            endianness=meta.get("endianness", "little"),
            page_size=meta.get("page_size", 4096),
            status=meta.get("status", "COMPLETE"),
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
            output_dir=dir_path,
            regions=regions,
            maps=maps,
        )
