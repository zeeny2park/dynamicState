"""Runtime module representation and address resolution for Phase 5.2.

Provides module-aware virtual address calculation using ELF PT_LOAD segments,
handling PIE, non-PIE, ASLR-enabled/disabled, and shared library modules.
"""

from dataclasses import asdict, dataclass, field
import os
from typing import Any, Dict, List, Optional, Tuple, Union

from .debug_image import BinaryIdentity, inspect_elf
from .memory_maps import MemoryRegion


class LoadBiasResolutionError(RuntimeError):
    """Raised when load bias cannot be deterministically computed from ELF and memory maps."""
    pass


@dataclass
class RuntimeModule:
    """Represents an executable binary or shared library mapped in process address space."""
    module_id: str
    path: str
    runtime_base: int
    runtime_end: int
    load_bias: Optional[int]
    build_id: Optional[str]
    architecture: str
    endianness: str
    elf_class: str
    is_main_executable: bool = False
    build_id_status: str = "NOT_AVAILABLE"      # "VERIFIED", "NOT_AVAILABLE", "MISMATCH", "UNREADABLE"
    load_bias_status: str = "RESOLVED"          # "RESOLVED", "UNRESOLVED"
    debuglink: Optional[Dict[str, Any]] = None  # {"filename": str, "crc": Optional[int]}
    elf_type: Optional[str] = None              # "ET_EXEC", "ET_DYN", etc.
    entry_point: Optional[int] = None
    pt_loads: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        load_bias_str = None
        if self.load_bias is not None:
            load_bias_str = "0x{:x}".format(self.load_bias) if self.load_bias >= 0 else "-0x{:x}".format(abs(self.load_bias))
        return {
            "module_id": self.module_id,
            "name": os.path.basename(self.path) if self.path else self.module_id,
            "path": self.path,
            "runtime_base": "0x{:x}".format(self.runtime_base),
            "runtime_end": "0x{:x}".format(self.runtime_end),
            "runtime_base_addr": self.runtime_base,
            "runtime_end_addr": self.runtime_end,
            "load_bias": load_bias_str,
            "load_bias_val": self.load_bias,
            "load_bias_status": self.load_bias_status,
            "build_id": self.build_id,
            "build_id_status": self.build_id_status,
            "architecture": self.architecture,
            "endianness": self.endianness,
            "elf_class": self.elf_class,
            "is_main_executable": self.is_main_executable,
            "debuglink": self.debuglink,
            "elf_type": self.elf_type,
            "entry_point": "0x{:x}".format(self.entry_point) if self.entry_point is not None else None,
            "pt_loads": self.pt_loads,
        }

    def contains_runtime_address(self, addr: int) -> bool:
        """Check if a runtime virtual address falls within this module's address range."""
        return self.runtime_base <= addr < self.runtime_end

    def contains_elf_address(self, elf_addr: int) -> bool:
        """Check if an ELF virtual address falls within this module's mapped range."""
        if self.load_bias_status != "RESOLVED" or self.load_bias is None:
            return False
        runtime_addr = elf_addr + self.load_bias
        return self.contains_runtime_address(runtime_addr)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuntimeModule":
        def parse_hex_or_int(val: Any) -> Optional[int]:
            if val is None:
                return None
            if isinstance(val, int):
                return val
            if isinstance(val, str):
                s = val.strip()
                if not s:
                    return None
                if s.startswith("-"):
                    return -int(s[1:], 16 if s[1:].startswith("0x") else 10)
                return int(s, 16 if s.startswith("0x") else 10)
            return int(val or 0)

        r_base = data.get("runtime_base_addr")
        if r_base is None:
            r_base = parse_hex_or_int(data.get("runtime_base", 0)) or 0

        r_end = data.get("runtime_end_addr")
        if r_end is None:
            r_end = parse_hex_or_int(data.get("runtime_end", 0)) or 0

        l_bias = data.get("load_bias_val")
        if l_bias is None and "load_bias" in data and data["load_bias"] is not None:
            l_bias = parse_hex_or_int(data.get("load_bias"))

        load_bias_status = data.get("load_bias_status")
        if not load_bias_status:
            load_bias_status = "RESOLVED" if l_bias is not None else "UNRESOLVED"

        ep_val = data.get("entry_point")
        entry_point = parse_hex_or_int(ep_val) if ep_val is not None else None

        return cls(
            module_id=data.get("module_id", "mod_unknown"),
            path=data.get("path", ""),
            runtime_base=r_base,
            runtime_end=r_end,
            load_bias=l_bias,
            build_id=data.get("build_id"),
            architecture=data.get("architecture", "x86_64"),
            endianness=data.get("endianness", "little"),
            elf_class=data.get("elf_class", "ELF64"),
            is_main_executable=data.get("is_main_executable", False),
            build_id_status=data.get("build_id_status", "NOT_AVAILABLE"),
            load_bias_status=load_bias_status,
            debuglink=data.get("debuglink"),
            elf_type=data.get("elf_type"),
            entry_point=entry_point,
            pt_loads=data.get("pt_loads", []),
        )


class ModuleAddressResolver:
    """Calculates load bias using ELF PT_LOAD segments and translates between runtime and ELF addresses."""

    @staticmethod
    def calculate_load_bias(
        runtime_mappings: List[Union[MemoryRegion, Dict[str, Any]]],
        elf_info: BinaryIdentity,
    ) -> int:
        """Calculate load bias = runtime_mapping_address - PT_LOAD.p_vaddr.

        Guarantees:
        - Non-PIE (ET_EXEC): Returns 0 because runtime mapping matches ELF virtual address.
        - PIE (ET_DYN) with/without ASLR: Returns delta between runtime base and ELF virtual address.
        - Shared Library (ET_DYN): Returns delta between runtime base and ELF virtual address.
        """
        if elf_info.elf_type == "ET_EXEC":
            return 0

        if not elf_info.pt_loads:
            raise LoadBiasResolutionError(
                f"No PT_LOAD segments found in ELF for '{elf_info.path}'. Cannot calculate load bias."
            )

        # Standard ELF loader convention: find PT_LOAD segment with lowest virtual address / offset 0
        sorted_pt_loads = sorted(elf_info.pt_loads, key=lambda pt: pt.get("p_vaddr", 0))
        first_pt_load = sorted_pt_loads[0]
        for pt in sorted_pt_loads:
            if pt.get("p_offset", 0) == 0:
                first_pt_load = pt
                break

        # Find matching runtime mapping by file offset
        target_offset = first_pt_load.get("p_offset", 0)
        matching_map = None

        def get_map_start(m: Any) -> int:
            if isinstance(m, MemoryRegion):
                return m.start
            return m.get("start_addr", int(m.get("start", "0"), 16) if isinstance(m.get("start"), str) else m.get("start", 0))

        def get_map_end(m: Any) -> int:
            if isinstance(m, MemoryRegion):
                return m.end
            return m.get("end_addr", int(m.get("end", "0"), 16) if isinstance(m.get("end"), str) else m.get("end", 0))

        def get_map_offset(m: Any) -> int:
            if isinstance(m, MemoryRegion):
                return m.offset
            raw = m.get("offset", 0)
            if isinstance(raw, str):
                return int(raw, 16 if raw.startswith("0x") else 10)
            return int(raw or 0)

        for m in sorted(runtime_mappings, key=get_map_start):
            m_off = get_map_offset(m)
            m_len = get_map_end(m) - get_map_start(m)
            if m_off <= target_offset < m_off + m_len:
                matching_map = m
                break

        if matching_map is None:
            if runtime_mappings:
                matching_map = min(runtime_mappings, key=get_map_start)
            else:
                raise LoadBiasResolutionError(
                    f"No runtime mappings found for module '{elf_info.path}'."
                )

        map_offset = get_map_offset(matching_map)
        runtime_vaddr = get_map_start(matching_map) + (target_offset - map_offset)
        elf_vaddr = first_pt_load.get("p_vaddr", 0)
        load_bias = runtime_vaddr - elf_vaddr
        return load_bias

    @staticmethod
    def resolve_runtime_address(module: RuntimeModule, elf_address: int) -> int:
        """Translate static ELF / DWARF symbol address to runtime memory address."""
        if module.load_bias_status != "RESOLVED" or module.load_bias is None:
            raise LoadBiasResolutionError(
                f"Cannot resolve runtime address: module '{module.module_id}' has UNRESOLVED load bias."
            )
        return elf_address + module.load_bias

    @staticmethod
    def resolve_elf_address(module: RuntimeModule, runtime_address: int) -> int:
        """Translate runtime memory address to static ELF / DWARF symbol address."""
        if module.load_bias_status != "RESOLVED" or module.load_bias is None:
            raise LoadBiasResolutionError(
                f"Cannot resolve ELF address: module '{module.module_id}' has UNRESOLVED load bias."
            )
        return runtime_address - module.load_bias

    @staticmethod
    def find_module_for_runtime_address(
        modules: List[RuntimeModule], runtime_address: int
    ) -> Optional[RuntimeModule]:
        """Find the RuntimeModule enclosing the given runtime memory address."""
        for mod in modules:
            if mod.runtime_base <= runtime_address < mod.runtime_end:
                return mod
        return None


def discover_modules(
    pid: int,
    regions: List[Union[MemoryRegion, Dict[str, Any]]],
    main_binary: Optional[str] = None,
) -> List[RuntimeModule]:
    """Discover runtime modules from process mappings and inspect their ELF identity."""
    # 1. Resolve canonical main binary path
    real_main = None
    if main_binary:
        clean_mb = main_binary[:-10].strip() if main_binary.endswith(" (deleted)") else main_binary
        real_main = os.path.realpath(clean_mb) if os.path.exists(clean_mb) else clean_mb
    elif pid > 0:
        exe_link = f"/proc/{pid}/exe"
        if os.path.islink(exe_link) or os.path.exists(exe_link):
            try:
                target = os.readlink(exe_link)
                if target.endswith(" (deleted)"):
                    target = target[:-10].strip()
                real_main = os.path.realpath(target) if os.path.exists(target) else target
            except Exception:
                pass

    # 2. Group mappings by real/canonical file pathname
    canonical_paths: Dict[str, str] = {}
    file_mappings: Dict[str, List[Any]] = {}

    def get_path(r: Any) -> str:
        if isinstance(r, MemoryRegion):
            return r.pathname or r.path
        return r.get("pathname", r.get("path", ""))

    def get_start(r: Any) -> int:
        if isinstance(r, MemoryRegion):
            return r.start
        return r.get("start_addr", int(r.get("start", "0"), 16) if isinstance(r.get("start"), str) else r.get("start", 0))

    def get_end(r: Any) -> int:
        if isinstance(r, MemoryRegion):
            return r.end
        return r.get("end_addr", int(r.get("end", "0"), 16) if isinstance(r.get("end"), str) else r.get("end", 0))

    for r in regions:
        p = get_path(r)
        if not p or p.startswith("[") or p == "(deleted)":
            continue
        is_deleted = p.endswith(" (deleted)")
        clean_p = p[:-10].strip() if is_deleted else p
        if not clean_p or clean_p.startswith("["):
            continue
        canon_p = os.path.realpath(clean_p) if os.path.exists(clean_p) else clean_p
        file_mappings.setdefault(canon_p, []).append(r)
        if canon_p not in canonical_paths:
            canonical_paths[canon_p] = clean_p

    modules: List[RuntimeModule] = []
    mod_idx = 1

    for canon_p, maps in file_mappings.items():
        if not maps:
            continue

        clean_p = canonical_paths.get(canon_p, canon_p)
        is_main = (
            (real_main is not None and (canon_p == real_main or clean_p == real_main or (real_main.endswith(" (deleted)") and canon_p == real_main[:-10].strip()))) or
            (main_binary is not None and (canon_p == main_binary or clean_p == main_binary))
        )

        # Check if file has executable mapping or shared library extension
        is_shlib = clean_p.endswith(".so") or ".so." in clean_p
        has_exec = any(
            (r.executable if isinstance(r, MemoryRegion) else "x" in r.get("permissions", ""))
            for r in maps
        )

        if not is_main and not is_shlib and not has_exec:
            # Skip non-code data files (e.g. font, locale, cache files)
            continue

        r_base = min(get_start(r) for r in maps)
        r_end = max(get_end(r) for r in maps)

        mod_id = "main" if is_main else f"mod_{mod_idx:04d}"
        if not is_main:
            mod_idx += 1

        # Attempt to inspect ELF on filesystem or via /proc/<pid>/exe
        elf_info: Optional[BinaryIdentity] = None
        build_id_status = "NOT_AVAILABLE"
        load_bias: Optional[int] = None
        load_bias_status = "UNRESOLVED"

        inspect_path = None
        if os.path.exists(clean_p):
            inspect_path = clean_p
        elif is_main and pid > 0:
            exe_link = f"/proc/{pid}/exe"
            if os.path.islink(exe_link) or os.path.exists(exe_link):
                inspect_path = exe_link

        if inspect_path:
            try:
                elf_info = inspect_elf(inspect_path)
                if elf_info.build_id:
                    build_id_status = "VERIFIED"
                else:
                    build_id_status = "NOT_AVAILABLE"

                # Calculate accurate load bias using PT_LOAD
                load_bias = ModuleAddressResolver.calculate_load_bias(maps, elf_info)
                load_bias_status = "RESOLVED"
            except Exception:
                build_id_status = "UNREADABLE"
                # Mark load bias as unresolved instead of silent fallback
                load_bias = None
                load_bias_status = "UNRESOLVED"
        else:
            build_id_status = "UNREADABLE"
            load_bias = None
            load_bias_status = "UNRESOLVED"

        modules.append(RuntimeModule(
            module_id=mod_id,
            path=clean_p,
            runtime_base=r_base,
            runtime_end=r_end,
            load_bias=load_bias,
            build_id=elf_info.build_id if elf_info else None,
            architecture=elf_info.architecture if elf_info else "unknown",
            endianness=elf_info.endianness if elf_info else "little",
            elf_class=elf_info.elf_class if elf_info else "ELF64",
            is_main_executable=is_main,
            build_id_status=build_id_status,
            load_bias_status=load_bias_status,
            debuglink=elf_info.debuglink if elf_info else None,
            elf_type=elf_info.elf_type if elf_info else None,
            entry_point=elf_info.entry_point if elf_info else None,
            pt_loads=elf_info.pt_loads if elf_info else [],
        ))

    # Ensure main executable is first in the list
    modules.sort(key=lambda m: (0 if m.is_main_executable else 1, m.runtime_base))
    return modules
