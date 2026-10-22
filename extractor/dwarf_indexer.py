"""High-performance DWARF Debug Information Indexer.

Parses DWARF compilation units, DIE hierarchies, type definitions, member offsets,
and global/static variable locations from ELF artifacts without running GDB or stopping
target processes.
"""

from dataclasses import dataclass, field
import os
import re
import subprocess
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from .debug_image import BinaryIdentity, inspect_elf


@dataclass
class DwarfMember:
    """Structure or class data member."""
    name: str
    type_offset: Optional[int]
    offset: int = 0
    byte_size: int = 0
    accessibility: str = "public"
    decl_file: Optional[str] = None
    decl_line: Optional[int] = None
    die_offset: Optional[int] = None


@dataclass
class DwarfBaseClass:
    """Inherited base class relationship."""
    type_offset: int
    offset: int = 0
    accessibility: str = "public"


@dataclass
class DwarfVariable:
    """Global, static, or local variable declaration/definition."""
    die_offset: int
    name: str
    linkage_name: Optional[str] = None
    type_offset: Optional[int] = None
    link_time_address: Optional[int] = None
    location_expr: Optional[str] = None
    location_list_offset: Optional[int] = None
    is_external: bool = False
    is_declaration: bool = False
    is_parameter: bool = False
    specification_offset: Optional[int] = None
    decl_file: Optional[str] = None
    decl_line: Optional[int] = None


@dataclass
class DwarfType:
    """Indexed DWARF type definition."""
    die_offset: int
    tag: str
    name: str
    byte_size: int = 0
    members: List[DwarfMember] = field(default_factory=list)
    base_classes: List[DwarfBaseClass] = field(default_factory=list)
    target_type_offset: Optional[int] = None  # Pointer, array element, typedef target, const/volatile target
    array_count: Optional[int] = None
    enum_values: Dict[int, str] = field(default_factory=dict)
    decl_file: Optional[str] = None
    decl_line: Optional[int] = None


@dataclass
class DwarfSubprogram:
    """Function or method subprogram declaration/definition."""
    die_offset: int
    name: str
    linkage_name: Optional[str] = None
    low_pc: Optional[int] = None
    high_pc: Optional[int] = None
    frame_base: Optional[str] = None
    decl_file: Optional[str] = None
    decl_line: Optional[int] = None
    is_external: bool = False
    is_declaration: bool = False
    specification_offset: Optional[int] = None
    has_frame_pointer: Optional[bool] = None
    frame_established_pc: Optional[int] = None
    frame_destroyed_pc: Optional[int] = None
    fp_offset_from_cfa: Optional[int] = None
    cfa_rules: List[Tuple[int, int, str, int, bool]] = field(default_factory=list)
    variables: List[DwarfVariable] = field(default_factory=list)
    has_unsupported_cfi: bool = False

    def get_variable(self, var_name: str) -> Optional[DwarfVariable]:
        for v in self.variables:
            if v.name == var_name:
                return v
        return None

    def get_cfa_rule_at(self, pc: int) -> Optional[Tuple[str, int, bool]]:
        """Return (cfa_reg, cfa_offset, fp_established) active at given link-time PC."""
        for start_pc, end_pc, reg, off, fp_est in self.cfa_rules:
            if start_pc <= pc < end_pc:
                return (reg, off, fp_est)
        if self.cfa_rules:
            if pc < self.cfa_rules[0][0]:
                _, _, reg, off, fp_est = self.cfa_rules[0]
                return (reg, off, fp_est)
            if pc >= self.cfa_rules[-1][0]:
                _, _, reg, off, fp_est = self.cfa_rules[-1]
                return (reg, off, fp_est)
        return None


@dataclass
class DwarfIndex:
    """Complete indexed DWARF symbol and type database for an ELF artifact."""
    artifact_path: str
    build_id: Optional[str] = None
    pointer_size: int = 8
    endianness: str = "little"
    elf_class: str = "ELF64"
    architecture: str = "x86_64"
    elf_type: str = "ET_DYN"
    pt_loads: List[Dict[str, Any]] = field(default_factory=list)

    types_by_die: Dict[int, DwarfType] = field(default_factory=dict)
    types_by_name: Dict[str, List[DwarfType]] = field(default_factory=dict)
    variables_by_name: Dict[str, List[DwarfVariable]] = field(default_factory=dict)
    variables: List[DwarfVariable] = field(default_factory=list)
    global_variables: List[DwarfVariable] = field(default_factory=list)
    static_variables: List[DwarfVariable] = field(default_factory=list)
    subprograms: List[DwarfSubprogram] = field(default_factory=list)
    subprograms_by_name: Dict[str, List[DwarfSubprogram]] = field(default_factory=dict)
    file_table: Dict[int, str] = field(default_factory=dict)

    def get_type_by_die(self, die_offset: int) -> Optional[DwarfType]:
        return self.types_by_die.get(die_offset)

    def resolve_canonical_type(self, type_offset: Optional[int]) -> Optional[DwarfType]:
        """Traverse typedef, const, volatile qualifiers to reach underlying canonical type."""
        curr = type_offset
        visited: Set[int] = set()
        while curr is not None and curr in self.types_by_die:
            if curr in visited:
                break
            visited.add(curr)
            t = self.types_by_die[curr]
            if t.tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"):
                if t.target_type_offset is not None:
                    curr = t.target_type_offset
                    continue
            return t
        return None

    def search_symbols(
        self,
        query: str = "",
        category: str = "all",
        limit: int = 50,
        smart_rank: bool = True,
        load_bias: int = 0,
        is_dyn: bool = True,
    ) -> List[Dict[str, Any]]:
        """Search indexed DWARF global/static variables and composite types with smart state ranking."""
        q = (query or "").strip().lower()
        cat = (category or "all").strip().lower()
        results: List[Dict[str, Any]] = []

        priority_keywords = (
            "state", "status", "mode", "err", "count", "retry", "queue", "pool",
            "buf", "mgr", "ctx", "session", "flag", "active", "seq", "config", "ctrl", "node", "heap"
        )

        def _score_name(name: str, is_struct_or_ptr: bool = False) -> float:
            score = 0.0
            nl = name.lower()
            if q:
                if nl == q:
                    score += 100.0
                elif nl.startswith(q):
                    score += 50.0
                elif q in nl:
                    score += 25.0
            if smart_rank:
                for kw in priority_keywords:
                    if kw in nl:
                        score += 10.0
                if is_struct_or_ptr:
                    score += 5.0
                if not nl.startswith("_"):
                    score += 3.0
            return score

        if cat in ("all", "variables", "globals", "statics"):
            seen_vars = set()
            for var in self.variables:
                if var.link_time_address is None or var.is_declaration or not var.name:
                    continue
                if var.name.startswith("__"):
                    continue
                if (var.name, var.link_time_address) in seen_vars:
                    continue
                seen_vars.add((var.name, var.link_time_address))

                t_name = self.get_type_name(var.type_offset)
                canon_t = self.resolve_canonical_type(var.type_offset)
                is_ptr = bool(canon_t and canon_t.tag == "DW_TAG_pointer_type")
                is_struct = bool(canon_t and canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"))

                # Check query against variable name, type name, or member names
                members_preview = []
                target_struct = canon_t
                if is_ptr and canon_t and canon_t.target_type_offset is not None:
                    target_struct = self.resolve_canonical_type(canon_t.target_type_offset)

                member_match = False
                if target_struct and target_struct.members:
                    for m in target_struct.members[:16]:
                        mt_name = self.get_type_name(m.type_offset)
                        if q and (q in m.name.lower() or q in mt_name.lower()):
                            member_match = True
                        members_preview.append({
                            "name": m.name,
                            "type_name": mt_name,
                            "offset": m.offset,
                            "size": m.byte_size or 4,
                            "expression": f"{var.name}->{m.name}" if is_ptr else f"{var.name}.{m.name}",
                        })

                if q and (q not in var.name.lower() and q not in t_name.lower() and not member_match):
                    continue

                runtime_addr = (load_bias + var.link_time_address) if is_dyn else var.link_time_address
                size = canon_t.byte_size if (canon_t and canon_t.byte_size) else 4
                score = _score_name(var.name, is_struct_or_ptr=(is_struct or is_ptr))
                if member_match:
                    score += 15.0

                results.append({
                    "kind": "global_variable" if var.is_external else "static_variable",
                    "name": var.name,
                    "type_name": t_name,
                    "size": size,
                    "is_pointer": is_ptr,
                    "is_struct": is_struct,
                    "link_time_address": f"0x{var.link_time_address:x}",
                    "runtime_address": f"0x{runtime_addr:x}",
                    "source_location": f"{var.decl_file}:{var.decl_line}" if var.decl_file else None,
                    "members": members_preview,
                    "score": score,
                })

        if cat in ("all", "types", "structs", "enums"):
            seen_types = set()
            for t in self.types_by_die.values():
                if not t.name or t.name.startswith("_") or t.name in seen_types:
                    continue
                if t.tag not in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_enumeration_type"):
                    continue
                seen_types.add(t.name)

                member_match = any(q in m.name.lower() for m in t.members) if q else False
                enum_match = any(q in ev.lower() for ev in t.enum_values.values()) if q else False
                if q and (q not in t.name.lower() and not member_match and not enum_match):
                    continue

                score = _score_name(t.name, is_struct_or_ptr=True) - 2.0
                entry: Dict[str, Any] = {
                    "kind": "enum_type" if t.tag == "DW_TAG_enumeration_type" else "struct_type",
                    "name": t.name,
                    "type_name": t.name,
                    "size": t.byte_size,
                    "source_location": f"{t.decl_file}:{t.decl_line}" if t.decl_file else None,
                    "score": score,
                }
                if t.tag == "DW_TAG_enumeration_type":
                    entry["enum_values"] = {str(k): v for k, v in list(t.enum_values.items())[:20]}
                else:
                    entry["members"] = [
                        {
                            "name": m.name,
                            "type_name": self.get_type_name(m.type_offset),
                            "offset": m.offset,
                            "size": m.byte_size or 4,
                        }
                        for m in t.members[:20]
                    ]
                results.append(entry)

        results.sort(key=lambda r: (r.get("score", 0.0), r.get("name", "")), reverse=True)
        return results[:max(1, limit)]

    def get_type_name(self, type_offset: Optional[int]) -> str:
        """Construct canonical human-readable type signature."""
        if type_offset is None:
            return "void"
        t = self.types_by_die.get(type_offset)
        if not t:
            return f"type_0x{type_offset:x}"

        if t.tag == "DW_TAG_pointer_type":
            target_name = self.get_type_name(t.target_type_offset)
            return f"{target_name}*"
        if t.tag in ("DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"):
            target_name = self.get_type_name(t.target_type_offset)
            return f"{target_name}&"
        if t.tag == "DW_TAG_const_type":
            target_name = self.get_type_name(t.target_type_offset)
            return f"const {target_name}"
        if t.tag == "DW_TAG_volatile_type":
            target_name = self.get_type_name(t.target_type_offset)
            return f"volatile {target_name}"
        if t.tag == "DW_TAG_array_type":
            elem_name = self.get_type_name(t.target_type_offset)
            count = t.array_count if t.array_count is not None else ""
            return f"{elem_name}[{count}]"
        if t.name:
            return t.name
        return f"type_0x{t.die_offset:x}"


_CFI_CACHE: Dict[Tuple[str, int, int, Optional[str]], Dict[int, Dict[str, Any]]] = {}
_CFI_ERROR: Dict[Tuple[str, int, int, Optional[str]], str] = {}


def _get_cfi_cache_key(path: str) -> Tuple[str, int, int, Optional[str]]:
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        return (abs_path, 0, 0, None)
    st = os.stat(abs_path)
    build_id = None
    try:
        from .debug_image import inspect_elf
        ident = inspect_elf(abs_path)
        build_id = ident.build_id
    except Exception:
        pass
    return (abs_path, st.st_mtime_ns, st.st_size, build_id)


def parse_cfi_table(artifact_path: str, arch: str = "x86_64") -> Dict[int, Dict[str, Any]]:
    """Parse .eh_frame / .debug_frame CFI rules using readelf to detect frame pointer presence, establishment PC, and rule intervals."""
    cache_key = _get_cfi_cache_key(artifact_path)
    if cache_key in _CFI_CACHE:
        return _CFI_CACHE[cache_key]

    cfi_map: Dict[int, Dict[str, Any]] = {}
    try:
        cmd = ["readelf", "--debug-dump=frames", cache_key[0]]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0:
            _CFI_ERROR[cache_key] = res.stderr.strip() or f"readelf exited with code {res.returncode}"
            return {}

        fp_reg_names = ("r29", "x29") if arch in ("aarch64", "arm64") else ("r6", "rbp")
        sp_reg_names = ("r31", "sp") if arch in ("aarch64", "arm64") else ("r7", "rsp")

        cie_re = re.compile(r"^\s*([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+CIE\b")
        fde_re = re.compile(r"FDE\s+cie=([0-9a-fA-F]+)\s+pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)")
        adv_re = re.compile(r"(?:DW_CFA_advance_loc\w*:\s+\d+\s+to\s+|DW_CFA_set_loc:\s+)([0-9a-fA-F]+)")
        def_cfa_re = re.compile(r"DW_CFA_def_cfa:\s+(\w+)\s+ofs\s+(\d+)")
        def_cfa_reg_re = re.compile(r"DW_CFA_def_cfa_register:\s+(\w+)")
        def_cfa_off_re = re.compile(r"DW_CFA_def_cfa_offset:\s+(\d+)")
        offset_fp_re = re.compile(r"DW_CFA_offset:\s+(?:r29|x29|r6|rbp)\b.*at cfa(-?\d+)")
        restore_fp_re = re.compile(r"DW_CFA_restore(?:_extended)?:\s+(?:r29|x29|r6|rbp|\b29\b|\b6\b)\b")

        cie_table: Dict[int, Dict[str, Any]] = {}
        curr_cie_offset: Optional[int] = None
        curr_fde: Optional[Dict[str, Any]] = None
        curr_pc: int = 0
        curr_cfa_reg: str = "sp"
        curr_cfa_off: int = 0 if arch in ("aarch64", "arm64") else 8
        fp_established: bool = False
        last_rule_pc: int = 0
        state_stack: List[Tuple[str, int, bool]] = []

        for line in res.stdout.splitlines():
            # Check CIE header
            m_cie = cie_re.match(line)
            if m_cie:
                if curr_fde is not None:
                    curr_fde["cfa_rules"].append((last_rule_pc, curr_fde["high_pc"], curr_cfa_reg, curr_cfa_off, fp_established))
                    curr_fde = None
                curr_cie_offset = int(m_cie.group(1), 16)
                cie_table[curr_cie_offset] = {
                    "cfa_reg": "sp",
                    "cfa_off": 0 if arch in ("aarch64", "arm64") else 8,
                }
                continue

            # Check FDE header
            m_fde = fde_re.search(line)
            if m_fde:
                if curr_fde is not None:
                    curr_fde["cfa_rules"].append((last_rule_pc, curr_fde["high_pc"], curr_cfa_reg, curr_cfa_off, fp_established))
                cie_off = int(m_fde.group(1), 16)
                low_pc = int(m_fde.group(2), 16)
                high_pc = int(m_fde.group(3), 16)
                curr_fde = {
                    "low_pc": low_pc,
                    "high_pc": high_pc,
                    "has_frame_pointer": False,
                    "frame_established_pc": None,
                    "frame_destroyed_pc": None,
                    "fp_offset_from_cfa": None,
                    "cfa_rules": [],
                    "has_unsupported_cfi": False,
                }
                cfi_map[low_pc] = curr_fde
                curr_pc = low_pc
                # Inherit CIE initial rule if present
                if cie_off in cie_table:
                    curr_cfa_reg = cie_table[cie_off]["cfa_reg"]
                    curr_cfa_off = cie_table[cie_off]["cfa_off"]
                else:
                    curr_cfa_reg = "sp"
                    curr_cfa_off = 0 if arch in ("aarch64", "arm64") else 8
                fp_established = False
                last_rule_pc = low_pc
                state_stack.clear()
                curr_cie_offset = None
                continue

            # If inside CIE, parse initial CFA definition
            if curr_cie_offset is not None:
                m_cfa = def_cfa_re.search(line)
                if m_cfa:
                    r = m_cfa.group(1).lower()
                    r_canon = "fp" if any(x in r for x in fp_reg_names) else ("sp" if any(x in r for x in sp_reg_names) else r)
                    cie_table[curr_cie_offset]["cfa_reg"] = r_canon
                    cie_table[curr_cie_offset]["cfa_off"] = int(m_cfa.group(2))
                m_cfa_r = def_cfa_reg_re.search(line)
                if m_cfa_r:
                    r = m_cfa_r.group(1).lower()
                    cie_table[curr_cie_offset]["cfa_reg"] = "fp" if any(x in r for x in fp_reg_names) else ("sp" if any(x in r for x in sp_reg_names) else r)
                m_cfa_o = def_cfa_off_re.search(line)
                if m_cfa_o:
                    cie_table[curr_cie_offset]["cfa_off"] = int(m_cfa_o.group(1))
                continue

            if curr_fde is None:
                continue

            # An FDE closes on encountering another CIE/FDE header (never on blank lines or nops)
            if re.match(r"^[0-9a-fA-F]{4,16}\s+[0-9a-fA-F]{4,16}\s+[0-9a-fA-F]{4,16}\s+(?:FDE|CIE)", line):
                curr_fde["cfa_rules"].append((last_rule_pc, curr_fde["high_pc"], curr_cfa_reg, curr_cfa_off, fp_established))
                curr_fde = None
                continue

            # Detect unsupported complex CFA expressions
            if "DW_CFA_def_cfa_expression" in line or "DW_CFA_expression" in line:
                curr_fde["has_unsupported_cfi"] = True

            m_adv = adv_re.search(line)
            if m_adv:
                new_pc = int(m_adv.group(1), 16)
                curr_fde["cfa_rules"].append((last_rule_pc, new_pc, curr_cfa_reg, curr_cfa_off, fp_established))
                last_rule_pc = new_pc
                curr_pc = new_pc

            if "DW_CFA_remember_state" in line:
                state_stack.append((curr_cfa_reg, curr_cfa_off, fp_established))
            if "DW_CFA_restore_state" in line and state_stack:
                curr_cfa_reg, curr_cfa_off, fp_established = state_stack.pop()

            m_cfa = def_cfa_re.search(line)
            if m_cfa:
                r = m_cfa.group(1).lower()
                curr_cfa_reg = "fp" if any(x in r for x in fp_reg_names) else ("sp" if any(x in r for x in sp_reg_names) else r)
                curr_cfa_off = int(m_cfa.group(2))

            m_cfa_r = def_cfa_reg_re.search(line)
            if m_cfa_r:
                r = m_cfa_r.group(1).lower()
                curr_cfa_reg = "fp" if any(x in r for x in fp_reg_names) else ("sp" if any(x in r for x in sp_reg_names) else r)

            m_cfa_o = def_cfa_off_re.search(line)
            if m_cfa_o:
                curr_cfa_off = int(m_cfa_o.group(1))

            m_off = offset_fp_re.search(line)
            if m_off:
                curr_fde["has_frame_pointer"] = True
                fp_established = True
                curr_fde["fp_offset_from_cfa"] = int(m_off.group(1))
                if curr_fde["frame_established_pc"] is None:
                    curr_fde["frame_established_pc"] = curr_pc

            if restore_fp_re.search(line):
                fp_established = False
                if curr_fde["frame_destroyed_pc"] is None:
                    curr_fde["frame_destroyed_pc"] = curr_pc

        if curr_fde is not None:
            curr_fde["cfa_rules"].append((last_rule_pc, curr_fde["high_pc"], curr_cfa_reg, curr_cfa_off, fp_established))

    except Exception as e:
        _CFI_ERROR[cache_key] = str(e)
        return {}

    _CFI_CACHE[cache_key] = cfi_map
    return cfi_map


def clear_cfi_cache() -> None:
    """Clear cached CFI tables (used in test teardown)."""
    _CFI_CACHE.clear()
    _CFI_ERROR.clear()


class DwarfIndexer:
    """Thread-safe indexer and cache manager for DWARF debug images."""

    _cache: Dict[Tuple[str, int, int, Optional[str]], DwarfIndex] = {}
    _lock = threading.Lock()

    @classmethod
    def get_index(cls, artifact_path: str) -> DwarfIndex:
        abs_path = os.path.abspath(artifact_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Debug artifact not found: {abs_path}")

        st = os.stat(abs_path)
        mtime = st.st_mtime_ns
        size = st.st_size

        # Inspect ELF header for build ID and architecture
        elf_info: BinaryIdentity = inspect_elf(abs_path)
        cache_key = (abs_path, mtime, size, elf_info.build_id)

        with cls._lock:
            if cache_key in cls._cache:
                return cls._cache[cache_key]

        index = cls._build_index(abs_path, elf_info)

        with cls._lock:
            cls._cache[cache_key] = index

        return index

    @classmethod
    def clear_cache(cls) -> None:
        """Clear cached DwarfIndex instances (used in test teardown)."""
        with cls._lock:
            cls._cache.clear()

    @classmethod
    def _clean_str(cls, val: str) -> str:
        if "): " in val:
            val = val.split("): ", 1)[1]
        val = val.strip()
        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            val = val[1:-1]
        return val

    @classmethod
    def _parse_offset(cls, val: str) -> Optional[int]:
        if "): " in val:
            val = val.split("): ", 1)[1]
        m = re.search(r"<0?x?([0-9a-fA-F]+)>", val)
        if m:
            return int(m.group(1), 16)
        m = re.search(r"0x([0-9a-fA-F]+)", val)
        if m:
            return int(m.group(1), 16)
        return None

    @classmethod
    def _parse_addr(cls, val: str) -> Optional[int]:
        if "): " in val:
            val = val.split("): ", 1)[1]
        m = re.search(r"DW_OP_addr:\s*([0-9a-fA-F]+)", val)
        if m:
            return int(m.group(1), 16)
        return None

    @classmethod
    def _parse_int(cls, val: str) -> int:
        if "): " in val:
            val = val.split("): ", 1)[1]
        m = re.search(r"DW_OP_plus_uconst\s*(\d+)", val)
        if m:
            return int(m.group(1))
        m = re.search(r"0x([0-9a-fA-F]+)", val)
        if m:
            return int(m.group(1), 16)
        m = re.match(r"^\s*(-?\d+)", val)
        if m:
            return int(m.group(1))
        return 0

    @classmethod
    def _parse_line_file_table(cls, path: str) -> Dict[int, str]:
        """Extract the File Name Table and Directory Table from .debug_line."""
        files: Dict[int, str] = {}
        dirs: Dict[int, str] = {}
        try:
            cmd = ["readelf", "--debug-dump=line", path]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                return files

            in_dir = False
            in_file = False
            for line in proc.stdout.splitlines():
                if "The Directory Table" in line:
                    in_dir = True
                    in_file = False
                    continue
                elif "The File Name Table" in line:
                    in_dir = False
                    in_file = True
                    continue
                elif line.startswith(" Line Number Statements") or line.startswith(" Opcodes:"):
                    in_dir = False
                    in_file = False
                    continue

                parts = line.strip().split()
                if in_dir and len(parts) >= 2 and parts[0].isdigit():
                    idx = int(parts[0])
                    name = line.split("):")[-1].strip() if "):" in line else parts[-1]
                    dirs[idx] = name
                elif in_file and len(parts) >= 3 and parts[0].isdigit():
                    idx = int(parts[0])
                    dir_idx = int(parts[1]) if parts[1].isdigit() else 0
                    name = line.split("):")[-1].strip() if "):" in line else parts[-1]
                    dir_name = dirs.get(dir_idx, "")
                    full_path = f"{dir_name}/{name}" if dir_name else name
                    files[idx] = full_path
        except Exception:
            pass
        return files

    @classmethod
    def _build_index(cls, path: str, elf_info: BinaryIdentity) -> DwarfIndex:
        pointer_size = 8 if elf_info.elf_class == "ELF64" else 4
        endianness = elf_info.endianness
        file_table = cls._parse_line_file_table(path)

        index = DwarfIndex(
            artifact_path=path,
            build_id=elf_info.build_id,
            pointer_size=pointer_size,
            endianness=endianness,
            elf_class=elf_info.elf_class,
            architecture=elf_info.architecture,
            elf_type=elf_info.elf_type or "ET_DYN",
            pt_loads=elf_info.pt_loads,
            file_table=file_table,
        )

        # Run readelf --debug-dump=info
        cmd = ["readelf", "--debug-dump=info", path]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
            raw_dwarf = proc.stdout
        except Exception as exc:
            # Fallback if readelf fails or is missing
            return index

        die_regex = re.compile(r"^\s*<(\d+)><([0-9a-fA-F]+)>:\s*Abbrev Number:\s*(\d+)(?:\s*\((DW_TAG_[a-zA-Z0-9_]+)\))?")
        attr_regex = re.compile(r"^\s*<([0-9a-fA-F]+)>\s*(DW_AT_[a-zA-Z0-9_]+)\s*:\s*(.*)$")

        dies: List[Dict[str, Any]] = []
        for line in raw_dwarf.splitlines():
            m_die = die_regex.match(line)
            if m_die:
                depth = int(m_die.group(1))
                offset = int(m_die.group(2), 16)
                tag = m_die.group(4) or ""
                dies.append({
                    "depth": depth,
                    "offset": offset,
                    "tag": tag,
                    "attrs": {}
                })
                continue

            m_attr = attr_regex.match(line)
            if m_attr and dies:
                attr_name = m_attr.group(2)
                attr_val = m_attr.group(3).strip()
                dies[-1]["attrs"][attr_name] = attr_val

        by_offset: Dict[int, Dict[str, Any]] = {d["offset"]: d for d in dies}

        # First pass: parse all types
        i = 0
        while i < len(dies):
            d = dies[i]
            tag = d["tag"]
            offset = d["offset"]
            attrs = d["attrs"]
            name = cls._clean_str(attrs.get("DW_AT_name", ""))
            byte_size = cls._parse_int(attrs.get("DW_AT_byte_size", "0"))

            if tag in (
                "DW_TAG_structure_type",
                "DW_TAG_class_type",
                "DW_TAG_union_type",
                "DW_TAG_base_type",
                "DW_TAG_pointer_type",
                "DW_TAG_reference_type",
                "DW_TAG_rvalue_reference_type",
                "DW_TAG_typedef",
                "DW_TAG_const_type",
                "DW_TAG_volatile_type",
                "DW_TAG_array_type",
                "DW_TAG_enumeration_type",
            ):
                target_type_offset = cls._parse_offset(attrs.get("DW_AT_type", ""))
                t_file_idx = cls._parse_int(attrs.get("DW_AT_decl_file", "0"))
                t_file = file_table.get(t_file_idx) or (cls._clean_str(attrs.get("DW_AT_decl_file", "")) if attrs.get("DW_AT_decl_file") else None)
                t_line = cls._parse_int(attrs.get("DW_AT_decl_line", "0")) or None

                d_type = DwarfType(
                    die_offset=offset,
                    tag=tag,
                    name=name,
                    byte_size=byte_size,
                    target_type_offset=target_type_offset,
                    decl_file=t_file,
                    decl_line=t_line,
                )

                # Process children if compound type
                if tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                    j = i + 1
                    while j < len(dies) and dies[j]["depth"] > d["depth"]:
                        child = dies[j]
                        if child["depth"] == d["depth"] + 1:
                            c_tag = child["tag"]
                            c_attrs = child["attrs"]
                            if c_tag == "DW_TAG_member":
                                m_name = cls._clean_str(c_attrs.get("DW_AT_name", ""))
                                m_loc = cls._parse_int(c_attrs.get("DW_AT_data_member_location", "0"))
                                m_type = cls._parse_offset(c_attrs.get("DW_AT_type", ""))
                                m_access_val = c_attrs.get("DW_AT_accessibility", "1")
                                m_access = "public" if "1" in m_access_val else ("protected" if "2" in m_access_val else "private")
                                m_file_idx = cls._parse_int(c_attrs.get("DW_AT_decl_file", "0"))
                                m_file = file_table.get(m_file_idx) or (cls._clean_str(c_attrs.get("DW_AT_decl_file", "")) if c_attrs.get("DW_AT_decl_file") else t_file)
                                m_line = cls._parse_int(c_attrs.get("DW_AT_decl_line", "0")) or None

                                d_type.members.append(DwarfMember(
                                    name=m_name,
                                    type_offset=m_type,
                                    offset=m_loc,
                                    accessibility=m_access,
                                    die_offset=child["offset"],
                                    decl_file=m_file,
                                    decl_line=m_line,
                                ))
                            elif c_tag == "DW_TAG_inheritance":
                                b_type = cls._parse_offset(c_attrs.get("DW_AT_type", ""))
                                b_loc = cls._parse_int(c_attrs.get("DW_AT_data_member_location", "0"))
                                b_access_val = c_attrs.get("DW_AT_accessibility", "1")
                                b_access = "public" if "1" in b_access_val else "protected"
                                if b_type is not None:
                                    d_type.base_classes.append(DwarfBaseClass(
                                        type_offset=b_type,
                                        offset=b_loc,
                                        accessibility=b_access,
                                    ))
                        j += 1

                elif tag == "DW_TAG_enumeration_type":
                    j = i + 1
                    while j < len(dies) and dies[j]["depth"] > d["depth"]:
                        child = dies[j]
                        if child["depth"] == d["depth"] + 1 and child["tag"] == "DW_TAG_enumerator":
                            c_name = cls._clean_str(child["attrs"].get("DW_AT_name", ""))
                            c_val = cls._parse_int(child["attrs"].get("DW_AT_const_value", "0"))
                            if c_name:
                                d_type.enum_values[c_val] = c_name
                        j += 1

                elif tag == "DW_TAG_array_type":
                    j = i + 1
                    while j < len(dies) and dies[j]["depth"] > d["depth"]:
                        child = dies[j]
                        if child["depth"] == d["depth"] + 1 and child["tag"] == "DW_TAG_subrange_type":
                            if "DW_AT_upper_bound" in child["attrs"]:
                                ub = cls._parse_int(child["attrs"]["DW_AT_upper_bound"])
                                d_type.array_count = ub + 1
                            elif "DW_AT_count" in child["attrs"]:
                                d_type.array_count = cls._parse_int(child["attrs"]["DW_AT_count"])
                        j += 1

                index.types_by_die[offset] = d_type
                if name:
                    index.types_by_name.setdefault(name, []).append(d_type)

            i += 1

        # Second pass: parse variables and subprograms
        cfi_table = parse_cfi_table(path, index.architecture)

        for die_idx, d in enumerate(dies):
            if d["tag"] == "DW_TAG_variable":
                attrs = d["attrs"]
                name = cls._clean_str(attrs.get("DW_AT_name", ""))
                linkage_name = cls._clean_str(attrs.get("DW_AT_linkage_name", ""))
                type_offset = cls._parse_offset(attrs.get("DW_AT_type", ""))
                loc_addr = cls._parse_addr(attrs.get("DW_AT_location", ""))
                is_ext = attrs.get("DW_AT_external") == "1"
                is_decl = attrs.get("DW_AT_declaration") == "1"
                spec_offset = cls._parse_offset(attrs.get("DW_AT_specification", ""))
                v_file_idx = cls._parse_int(attrs.get("DW_AT_decl_file", "0"))
                v_file = file_table.get(v_file_idx) or (cls._clean_str(attrs.get("DW_AT_decl_file", "")) if attrs.get("DW_AT_decl_file") else None)
                v_line = cls._parse_int(attrs.get("DW_AT_decl_line", "0")) or None

                # If this variable is an out-of-line definition referring to a specification
                if spec_offset and spec_offset in by_offset:
                    spec_die = by_offset[spec_offset]
                    if not name:
                        name = cls._clean_str(spec_die["attrs"].get("DW_AT_name", ""))
                    if not linkage_name:
                        linkage_name = cls._clean_str(spec_die["attrs"].get("DW_AT_linkage_name", ""))
                    if type_offset is None:
                        type_offset = cls._parse_offset(spec_die["attrs"].get("DW_AT_type", ""))
                    if not is_ext and spec_die["attrs"].get("DW_AT_external") == "1":
                        is_ext = True
                    if not v_file:
                        sf_idx = cls._parse_int(spec_die["attrs"].get("DW_AT_decl_file", "0"))
                        v_file = file_table.get(sf_idx) or (cls._clean_str(spec_die["attrs"].get("DW_AT_decl_file", "")) if spec_die["attrs"].get("DW_AT_decl_file") else None)
                    if not v_line:
                        v_line = cls._parse_int(spec_die["attrs"].get("DW_AT_decl_line", "0")) or None

                var = DwarfVariable(
                    die_offset=d["offset"],
                    name=name,
                    linkage_name=linkage_name if linkage_name else None,
                    type_offset=type_offset,
                    link_time_address=loc_addr,
                    is_external=is_ext,
                    is_declaration=is_decl,
                    specification_offset=spec_offset,
                    decl_file=v_file,
                    decl_line=v_line,
                )

                if name:
                    index.variables_by_name.setdefault(name, []).append(var)
                index.variables.append(var)

                # Classify into global vs static
                if loc_addr is not None and not is_decl and name:
                    if is_ext:
                        index.global_variables.append(var)
                    else:
                        index.static_variables.append(var)

            elif d["tag"] == "DW_TAG_subprogram":
                attrs = d["attrs"]
                name = cls._clean_str(attrs.get("DW_AT_name", ""))
                linkage_name = cls._clean_str(attrs.get("DW_AT_linkage_name", ""))
                low_pc = cls._parse_int(attrs.get("DW_AT_low_pc", "0")) or None
                high_pc_raw = cls._parse_int(attrs.get("DW_AT_high_pc", "0")) or None
                high_pc = (low_pc + high_pc_raw) if (low_pc is not None and high_pc_raw is not None and high_pc_raw < low_pc) else high_pc_raw
                frame_base_raw = attrs.get("DW_AT_frame_base", "")
                frame_base = None
                if frame_base_raw:
                    m_fb = re.search(r"\((DW_OP_[^)]+)\)", frame_base_raw)
                    frame_base = m_fb.group(1).strip() if m_fb else frame_base_raw.strip()
                is_ext = attrs.get("DW_AT_external") == "1"
                is_decl = attrs.get("DW_AT_declaration") == "1"
                spec_offset = cls._parse_offset(attrs.get("DW_AT_specification", ""))
                sp_file_idx = cls._parse_int(attrs.get("DW_AT_decl_file", "0"))
                sp_file = file_table.get(sp_file_idx) or (cls._clean_str(attrs.get("DW_AT_decl_file", "")) if attrs.get("DW_AT_decl_file") else None)
                sp_line = cls._parse_int(attrs.get("DW_AT_decl_line", "0")) or None

                if spec_offset and spec_offset in by_offset:
                    spec_die = by_offset[spec_offset]
                    if not name:
                        name = cls._clean_str(spec_die["attrs"].get("DW_AT_name", ""))
                    if not linkage_name:
                        linkage_name = cls._clean_str(spec_die["attrs"].get("DW_AT_linkage_name", ""))
                    if not sp_file:
                        sf_idx = cls._parse_int(spec_die["attrs"].get("DW_AT_decl_file", "0"))
                        sp_file = file_table.get(sf_idx)
                    if not sp_line:
                        sp_line = cls._parse_int(spec_die["attrs"].get("DW_AT_decl_line", "0")) or None

                if name:
                    subp_has_fp = None
                    subp_est_pc = None
                    subp_dest_pc = None
                    subp_fp_cfa_off = None
                    subp_cfa_rules = []
                    subp_unsupported_cfi = False
                    if low_pc is not None and low_pc in cfi_table:
                        cfi_info = cfi_table[low_pc]
                        subp_has_fp = cfi_info.get("has_frame_pointer")
                        subp_est_pc = cfi_info.get("frame_established_pc")
                        subp_dest_pc = cfi_info.get("frame_destroyed_pc")
                        subp_fp_cfa_off = cfi_info.get("fp_offset_from_cfa")
                        subp_cfa_rules = cfi_info.get("cfa_rules", [])
                        subp_unsupported_cfi = cfi_info.get("has_unsupported_cfi", False)

                    subp = DwarfSubprogram(
                        die_offset=d["offset"],
                        name=name,
                        linkage_name=linkage_name if linkage_name else None,
                        low_pc=low_pc,
                        high_pc=high_pc,
                        frame_base=frame_base,
                        decl_file=sp_file,
                        decl_line=sp_line,
                        is_external=is_ext,
                        is_declaration=is_decl,
                        specification_offset=spec_offset,
                        has_frame_pointer=subp_has_fp,
                        frame_established_pc=subp_est_pc,
                        frame_destroyed_pc=subp_dest_pc,
                        fp_offset_from_cfa=subp_fp_cfa_off,
                        cfa_rules=subp_cfa_rules,
                        has_unsupported_cfi=subp_unsupported_cfi,
                    )
                    # Extract parameters and local variables in subprogram subtree
                    j = die_idx + 1
                    while j < len(dies) and dies[j]["depth"] > d["depth"]:
                        child = dies[j]
                        c_tag = child["tag"]
                        if c_tag in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
                            c_attrs = child["attrs"]
                            c_name = cls._clean_str(c_attrs.get("DW_AT_name", ""))
                            c_type = cls._parse_offset(c_attrs.get("DW_AT_type", ""))
                            c_loc_raw = c_attrs.get("DW_AT_location", "")
                            c_loc_expr = None
                            c_loc_list = None
                            if c_loc_raw:
                                if "(location list)" in c_loc_raw:
                                    m_off = re.search(r"(?:^|:\s*|[\s(])(?:0x)?([0-9a-fA-F]+)\s+\(location list\)", c_loc_raw)
                                    if m_off:
                                        c_loc_list = int(m_off.group(1), 16)
                                else:
                                    m_expr = re.search(r"\((DW_OP_[^)]+)\)", c_loc_raw)
                                    c_loc_expr = m_expr.group(1).strip() if m_expr else c_loc_raw.strip()
                            c_file_idx = cls._parse_int(c_attrs.get("DW_AT_decl_file", "0"))
                            c_file = file_table.get(c_file_idx) or (cls._clean_str(c_attrs.get("DW_AT_decl_file", "")) if c_attrs.get("DW_AT_decl_file") else None)
                            c_line = cls._parse_int(c_attrs.get("DW_AT_decl_line", "0")) or None
                            if c_name:
                                subp.variables.append(DwarfVariable(
                                    die_offset=child["offset"],
                                    name=c_name,
                                    type_offset=c_type,
                                    location_expr=c_loc_expr,
                                    location_list_offset=c_loc_list,
                                    is_parameter=(c_tag == "DW_TAG_formal_parameter"),
                                    decl_file=c_file,
                                    decl_line=c_line,
                                ))
                        j += 1

                    index.subprograms.append(subp)
                    index.subprograms_by_name.setdefault(name, []).append(subp)
                    if linkage_name and linkage_name != name:
                        index.subprograms_by_name.setdefault(linkage_name, []).append(subp)

        # Infer byte size for compound types that missed DW_AT_byte_size
        for d_type in index.types_by_die.values():
            if d_type.byte_size == 0:
                if d_type.tag == "DW_TAG_pointer_type":
                    d_type.byte_size = pointer_size
                elif d_type.tag in ("DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"):
                    d_type.byte_size = pointer_size
                elif d_type.tag == "DW_TAG_array_type" and d_type.array_count and d_type.target_type_offset:
                    elem_t = index.resolve_canonical_type(d_type.target_type_offset)
                    if elem_t and elem_t.byte_size:
                        d_type.byte_size = d_type.array_count * elem_t.byte_size
                elif d_type.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and d_type.members:
                    # Estimate from last member
                    max_end = 0
                    for m in d_type.members:
                        m_t = index.resolve_canonical_type(m.type_offset)
                        m_sz = m.byte_size or (m_t.byte_size if m_t else pointer_size)
                        max_end = max(max_end, m.offset + m_sz)
                    d_type.byte_size = max_end

        return index
