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
    is_external: bool = False
    is_declaration: bool = False
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


class DwarfIndexer:
    """Thread-safe indexer and cache manager for DWARF debug images."""

    _cache: Dict[Tuple[str, float, int, Optional[str]], DwarfIndex] = {}
    _lock = threading.Lock()

    @classmethod
    def get_index(cls, artifact_path: str) -> DwarfIndex:
        abs_path = os.path.abspath(artifact_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Debug artifact not found: {abs_path}")

        st = os.stat(abs_path)
        mtime = st.st_mtime
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
    def _clean_str(cls, val: str) -> str:
        if "): " in val:
            val = val.split("): ", 1)[1]
        val = val.strip()
        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            val = val[1:-1]
        return val

    @classmethod
    def _parse_offset(cls, val: str) -> Optional[int]:
        m = re.search(r"<0?x?([0-9a-fA-F]+)>", val)
        if m:
            return int(m.group(1), 16)
        m = re.search(r"0x([0-9a-fA-F]+)", val)
        if m:
            return int(m.group(1), 16)
        return None

    @classmethod
    def _parse_addr(cls, val: str) -> Optional[int]:
        m = re.search(r"DW_OP_addr:\s*([0-9a-fA-F]+)", val)
        if m:
            return int(m.group(1), 16)
        return None

    @classmethod
    def _parse_int(cls, val: str) -> int:
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
    def _build_index(cls, path: str, elf_info: BinaryIdentity) -> DwarfIndex:
        pointer_size = 8 if elf_info.elf_class == "ELF64" else 4
        endianness = elf_info.endianness

        index = DwarfIndex(
            artifact_path=path,
            build_id=elf_info.build_id,
            pointer_size=pointer_size,
            endianness=endianness,
            elf_class=elf_info.elf_class,
            architecture=elf_info.architecture,
            elf_type=elf_info.elf_type or "ET_DYN",
            pt_loads=elf_info.pt_loads,
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
                d_type = DwarfType(
                    die_offset=offset,
                    tag=tag,
                    name=name,
                    byte_size=byte_size,
                    target_type_offset=target_type_offset,
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
                                d_type.members.append(DwarfMember(
                                    name=m_name,
                                    type_offset=m_type,
                                    offset=m_loc,
                                    accessibility=m_access,
                                    die_offset=child["offset"],
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

        # Second pass: parse variables
        for d in dies:
            if d["tag"] == "DW_TAG_variable":
                attrs = d["attrs"]
                name = cls._clean_str(attrs.get("DW_AT_name", ""))
                linkage_name = cls._clean_str(attrs.get("DW_AT_linkage_name", ""))
                type_offset = cls._parse_offset(attrs.get("DW_AT_type", ""))
                loc_addr = cls._parse_addr(attrs.get("DW_AT_location", ""))
                is_ext = attrs.get("DW_AT_external") == "1"
                is_decl = attrs.get("DW_AT_declaration") == "1"
                spec_offset = cls._parse_offset(attrs.get("DW_AT_specification", ""))

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

                var = DwarfVariable(
                    die_offset=d["offset"],
                    name=name,
                    linkage_name=linkage_name if linkage_name else None,
                    type_offset=type_offset,
                    link_time_address=loc_addr,
                    is_external=is_ext,
                    is_declaration=is_decl,
                    specification_offset=spec_offset,
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
