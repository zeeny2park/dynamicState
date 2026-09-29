"""UI-friendly Memory Snapshot Summary Model and Aggregator for dynamicState.

Provides an authoritative semantic summary answering:
- How is the process memory structured (Heap, Stack, Global, Executable, Shared Libs)?
- What semantic objects were discovered from this memory?
- How completely and safely was the snapshot captured (mapping races, partial reads, debug provenance)?
"""

from dataclasses import asdict, dataclass, field
import os
from typing import Any, Dict, List, Optional


@dataclass
class RegionItem:
    name: str
    category: str  # "heap", "stack", "global", "executable", "shared_library", "other"
    start_hex: str
    end_hex: str
    size_bytes: int
    permissions: str


@dataclass
class MemoryBreakdown:
    heap_bytes: int = 0
    stack_bytes: int = 0
    global_bytes: int = 0
    executable_bytes: int = 0
    shared_library_bytes: int = 0
    other_bytes: int = 0
    total_captured_bytes: int = 0


@dataclass
class SemanticObjectOverview:
    total_objects: int = 0
    heap_objects: int = 0
    global_objects: int = 0
    stack_objects: int = 0
    total_references: int = 0
    unavailable_fields: int = 0
    hierarchy_preview: List[Dict[str, Any]] = field(default_factory=list)
    footprint_bytes: Optional[int] = None
    footprint_status: str = "NOT_AVAILABLE"  # "ESTIMATED", "NOT_AVAILABLE"


@dataclass
class SnapshotQuality:
    completeness: str = "COMPLETE"  # "COMPLETE", "PARTIAL", "FAILED"
    completeness_pct: float = 100.0
    mapping_race_detected: bool = False
    partial_read_count: int = 0
    failed_read_count: int = 0
    architecture: str = "UNKNOWN"
    pointer_width: str = "UNKNOWN"  # "64-bit", "32-bit", "UNKNOWN"
    endianness: str = "UNKNOWN"      # "Little", "Big", "UNKNOWN"
    debug_image_status: str = "UNKNOWN"
    build_id_status: str = "UNKNOWN"
    build_id: Optional[str] = None
    module_count: int = 0


@dataclass
class MemorySnapshotSummary:
    snapshot_id: str
    status: str  # "COMPLETE", "PARTIAL", "FAILED"
    capture_mode: str  # "CONSISTENT", "LOW_IMPACT"
    captured_bytes: int
    duration_ms: Optional[float]
    region_count: int
    breakdown: MemoryBreakdown
    objects: SemanticObjectOverview
    quality: SnapshotQuality
    regions: List[Dict[str, Any]] = field(default_factory=list)
    captured_memory_status: str = "AVAILABLE"  # "AVAILABLE", "NOT_AVAILABLE"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def categorize_region(pathname: str, perms: str, is_main_binary: bool = False) -> str:
    """Categorize a memory mapping into standard semantic memory categories."""
    p_lower = (pathname or "").lower().strip()
    perms_str = perms or ""

    if "[heap]" in p_lower:
        return "heap"
    if "[stack]" in p_lower:
        return "stack"
    if ".so" in p_lower or "/lib/" in p_lower or "/usr/lib/" in p_lower:
        return "shared_library"
    if is_main_binary or (p_lower and not p_lower.startswith("[")):
        if "x" in perms_str:
            return "executable"
        if "w" in perms_str:
            return "global"
        return "global"
    if "x" in perms_str:
        return "executable"
    return "other"


def build_memory_snapshot_summary(
    snapshot_data: Dict[str, Any],
    raw_memory_snapshot: Optional[Any] = None,
    runtime_modules: Optional[List[Dict[str, Any]]] = None,
    debug_image_info: Optional[Dict[str, Any]] = None,
) -> MemorySnapshotSummary:
    """Construct an authoritative MemorySnapshotSummary from snapshot evidence."""
    snap_id = snapshot_data.get("snapshot_id") or "S_UNKNOWN"
    mode = snapshot_data.get("capture_mode") or ("LOW_IMPACT" if "regions" in snapshot_data or raw_memory_snapshot else "CONSISTENT")

    consistency = snapshot_data.get("consistency") or {}
    partial_reads = consistency.get("partial_reads") or []
    failed_reads = consistency.get("failed_reads") or []
    mapping_race = bool(consistency.get("mapping_race_detected", False))

    duration_us = consistency.get("duration_us")
    duration_ms = round(duration_us / 1000.0, 2) if duration_us is not None else None

    # 1. Process regions & memory breakdown
    raw_regions = []
    if raw_memory_snapshot and hasattr(raw_memory_snapshot, "regions"):
        for r in raw_memory_snapshot.regions:
            raw_regions.append({
                "start": r.start,
                "end": r.end,
                "size": r.size,
                "perms": getattr(r, "perms", "r--p"),
                "pathname": getattr(r, "pathname", getattr(r, "category", "")),
                "data_len": len(r.data) if hasattr(r, "data") else r.size,
            })
    elif "regions" in snapshot_data and isinstance(snapshot_data["regions"], list):
        raw_regions = snapshot_data["regions"]

    breakdown = MemoryBreakdown()
    region_items: List[Dict[str, Any]] = []

    main_binary_path = (snapshot_data.get("process") or {}).get("binary", "")

    for r in raw_regions:
        pathname = r.get("pathname") or r.get("name") or ""
        perms = r.get("perms") or "r--p"
        start = r.get("start", 0)
        end = r.get("end", 0)
        size = r.get("size") or (end - start if end > start else 0) or r.get("data_len", 0)

        is_main = bool(main_binary_path and pathname and os.path.basename(main_binary_path) in pathname)
        cat = categorize_region(pathname, perms, is_main_binary=is_main)

        if cat == "heap":
            breakdown.heap_bytes += size
        elif cat == "stack":
            breakdown.stack_bytes += size
        elif cat == "global":
            breakdown.global_bytes += size
        elif cat == "executable":
            breakdown.executable_bytes += size
        elif cat == "shared_library":
            breakdown.shared_library_bytes += size
        else:
            breakdown.other_bytes += size

        breakdown.total_captured_bytes += size

        region_items.append({
            "name": os.path.basename(pathname) if pathname else f"[{cat}]",
            "category": cat,
            "start_hex": hex(start) if isinstance(start, int) else str(start),
            "end_hex": hex(end) if isinstance(end, int) else str(end),
            "size_bytes": size,
            "permissions": perms,
        })

    persistent = snapshot_data.get("persistent") or {}
    objects_list = persistent.get("objects") or []

    # 2. Semantic Runtime Objects Analysis
    obj_overview = SemanticObjectOverview()
    obj_overview.total_objects = len(objects_list)

    if objects_list:
        # Separate semantic object footprint from physical captured memory
        est_footprint = 0
        for obj in objects_list:
            est_footprint += 32 + (len(obj.get("fields") or []) * 8)
        obj_overview.footprint_bytes = est_footprint
        obj_overview.footprint_status = "ESTIMATED"
    else:
        obj_overview.footprint_bytes = None
        obj_overview.footprint_status = "NOT_AVAILABLE"

    for obj in objects_list:
        st = (obj.get("storage") or "unknown").lower()
        if st == "heap":
            obj_overview.heap_objects += 1
        elif st == "global":
            obj_overview.global_objects += 1
        elif st == "stack":
            obj_overview.stack_objects += 1

        fields = obj.get("fields") or []
        for f in fields:
            if f.get("object_ref"):
                obj_overview.total_references += 1
            if f.get("value") in ("UNAVAILABLE", "UNKNOWN") or f.get("availability") == "UNAVAILABLE":
                obj_overview.unavailable_fields += 1

    # Build human-friendly hierarchy preview (top root objects with key fields)
    roots = persistent.get("roots") or []
    root_names = {r.get("name") for r in roots if r.get("name")}

    preview_objects = []
    # prioritize roots, then others up to 10
    sorted_objs = sorted(
        objects_list,
        key=lambda o: 0 if o.get("object_id") in root_names or o.get("storage") in ("global", "stack") else 1
    )

    for o in sorted_objs[:10]:
        preview_fields = []
        for f in (o.get("fields") or [])[:5]:
            preview_fields.append({
                "name": f.get("name"),
                "type": f.get("type"),
                "value": f.get("value"),
                "ref": f.get("object_ref"),
            })
        preview_objects.append({
            "object_id": o.get("object_id"),
            "type": o.get("type", "Unknown"),
            "storage": (o.get("storage") or "UNKNOWN").upper(),
            "field_count": len(o.get("fields") or []),
            "key_fields": preview_fields,
        })
    obj_overview.hierarchy_preview = preview_objects

    # 3. Snapshot Quality & Provenance
    quality = SnapshotQuality()
    quality.mapping_race_detected = mapping_race
    quality.partial_read_count = len(partial_reads)
    quality.failed_read_count = len(failed_reads)

    # Status: FAILED if failed reads dominate or zero bytes with error, PARTIAL if mapping race or partials
    if quality.failed_read_count > 0 or quality.partial_read_count > 0 or mapping_race:
        quality.completeness = "PARTIAL"
        total_attempts = len(raw_regions) or 1
        quality.completeness_pct = max(0.0, round(100.0 * (1.0 - (quality.failed_read_count + quality.partial_read_count) / total_attempts), 1))
    else:
        quality.completeness = "COMPLETE"
        quality.completeness_pct = 100.0

    # Architecture normalization
    provenance = snapshot_data.get("provenance") or {}
    rt_bin = provenance.get("runtime_binary") or {}
    dbg_img = provenance.get("debug_image") or (debug_image_info or {})

    # Strictly search for the authoritative main executable module; NEVER guess modules[0]
    main_mod = next((m for m in (runtime_modules or []) if m.get("is_main_executable")), None)

    arch_raw = (
        snapshot_data.get("architecture")
        or rt_bin.get("architecture")
        or (main_mod.get("architecture") if main_mod else None)
        or ""
    ).lower()

    if "aarch64" in arch_raw or "arm64" in arch_raw:
        quality.architecture = "AArch64"
    elif "x86_64" in arch_raw or "amd64" in arch_raw:
        quality.architecture = "x86_64"
    elif "arm" in arch_raw:
        quality.architecture = "ARM"
    elif "riscv" in arch_raw:
        quality.architecture = "RISC-V"
    elif arch_raw:
        quality.architecture = arch_raw.upper()
    else:
        quality.architecture = "UNKNOWN"

    # Pointer width from ELF class
    elf_class = (
        snapshot_data.get("elf_class")
        or rt_bin.get("elf_class")
        or (main_mod.get("elf_class") if main_mod else None)
        or ""
    )
    if elf_class == "ELF64":
        quality.pointer_width = "64-bit"
    elif elf_class == "ELF32":
        quality.pointer_width = "32-bit"
    else:
        quality.pointer_width = "UNKNOWN"

    # Endianness
    endian_raw = (
        snapshot_data.get("endianness")
        or rt_bin.get("endianness")
        or (main_mod.get("endianness") if main_mod else None)
        or ""
    ).lower()
    if endian_raw == "little":
        quality.endianness = "Little"
    elif endian_raw == "big":
        quality.endianness = "Big"
    else:
        quality.endianness = "UNKNOWN"

    # Debug image & build ID status
    build_id = rt_bin.get("build_id") or (main_mod.get("build_id") if main_mod else None)
    quality.build_id = build_id
    if build_id:
        quality.build_id_status = "MATCHED"
    else:
        quality.build_id_status = "UNAVAILABLE"

    if dbg_img.get("verified") or dbg_img.get("compatible"):
        quality.debug_image_status = "VERIFIED"
    elif dbg_img.get("status") in ("MISMATCH", "DEBUG_IMAGE_MISMATCH"):
        quality.debug_image_status = "MISMATCH"
    elif dbg_img.get("source") or dbg_img.get("path"):
        quality.debug_image_status = "LOADED"
    else:
        quality.debug_image_status = "NOT_AVAILABLE"

    quality.module_count = len(runtime_modules) if runtime_modules else (1 if main_binary_path else 0)

    overall_status = "COMPLETE" if quality.completeness == "COMPLETE" else "PARTIAL"
    captured_status = "AVAILABLE" if breakdown.total_captured_bytes > 0 else "NOT_AVAILABLE"

    return MemorySnapshotSummary(
        snapshot_id=snap_id,
        status=overall_status,
        capture_mode=mode,
        captured_bytes=breakdown.total_captured_bytes,
        duration_ms=duration_ms,
        region_count=len(region_items),
        breakdown=breakdown,
        objects=obj_overview,
        quality=quality,
        regions=region_items,
        captured_memory_status=captured_status,
    )
