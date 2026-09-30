"""DWARF-aware C++ Object Decoder and Runtime State Resolver.

Reconstructs real C++ object graphs from RawRuntimeSnapshot memory buffers and DWARF debug info,
handling PIE/ASLR load bias, inheritance, pointer graphs, cyclic/shared structures,
and partial memory capture reporting without relying on GDB or synthetic fallbacks.
"""

from dataclasses import dataclass, field
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from .debug_image import inspect_elf
from .dwarf_indexer import DwarfIndex, DwarfIndexer, DwarfType, DwarfVariable
from .raw_snapshot import RawRuntimeSnapshot
from .typed_memory_reader import TypedMemoryReader


def _clean_type_name(t: Any) -> str:
    """Normalize C/C++ type names by removing redundant struct/class/enum keywords."""
    if not t:
        return "Unknown"
    s = str(t).strip()
    for prefix in ("struct ", "class ", "enum "):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return s.strip()


@dataclass
class ResolutionResult:
    """Result of DWARF-backed runtime state resolution."""
    status: str  # COMPLETE, PARTIAL, SYMBOL_MISMATCH, MEMORY_NOT_CAPTURED, UNRESOLVED, DECODE_ERROR
    roots: List[Dict[str, Any]] = field(default_factory=list)
    objects: List[Dict[str, Any]] = field(default_factory=list)
    references: List[Dict[str, Any]] = field(default_factory=list)
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)
    load_bias: int = 0
    pointer_size: int = 8
    endianness: str = "little"
    build_id: Optional[str] = None
    debug_image_path: Optional[str] = None


class CppObjectDecoder:
    """Decodes typed C++ memory objects using DWARF layout metadata and TypedMemoryReader."""

    def __init__(
        self,
        memory_reader: TypedMemoryReader,
        dwarf_index: DwarfIndex,
        load_bias: int = 0
    ):
        self.reader = memory_reader
        self.index = dwarf_index
        self.load_bias = load_bias
        self.pointer_size = dwarf_index.pointer_size
        self.endianness = dwarf_index.endianness

        # Stable identity mapping: (address, canonical_type) -> object_id
        self.visited: Dict[Tuple[int, str], str] = {}
        self.objects_by_id: Dict[str, Dict[str, Any]] = {}
        self.references: List[Dict[str, Any]] = []
        self.diagnostics: List[Dict[str, Any]] = []
        self._next_id: int = 1

    def _alloc_id(self) -> str:
        oid = f"obj_{self._next_id:04d}"
        self._next_id += 1
        return oid

    def decode_object(
        self,
        address: int,
        type_offset: Optional[int],
        path: str,
        storage: str = "global",
        custom_name: Optional[str] = None,
    ) -> str:
        """Decode a C++ object into the object graph, preserving identity and cycle safety."""
        canon_t = self.index.resolve_canonical_type(type_offset) if type_offset is not None else None
        type_sig = self.index.get_type_name(type_offset) if type_offset is not None else "Unknown"
        clean_name = _clean_type_name(canon_t.name if canon_t and canon_t.name else type_sig)

        # 1. Identity Check
        identity_key = (address, clean_name)
        if identity_key in self.visited:
            return self.visited[identity_key]

        obj_id = self._alloc_id()
        self.visited[identity_key] = obj_id

        byte_size = canon_t.byte_size if canon_t else self.pointer_size
        obj_dict: Dict[str, Any] = {
            "object_id": obj_id,
            "type": clean_name,
            "canonical_type": clean_name,
            "address": address,
            "hex_address": hex(address),
            "size": byte_size,
            "storage": storage,
            "fields": [],
            "provenance": {
                "source": "RAW_SNAPSHOT",
                "dwarf_type_die": hex(canon_t.die_offset) if canon_t else None,
                "memory_address": hex(address),
                "memory_range": [hex(address), hex(address + byte_size)],
                "build_id": self.index.build_id,
                "dwarf_type": clean_name,
                "synthetic": False,
            },
            "synthetic": False,
            "status": "COMPLETE",
        }
        self.objects_by_id[obj_id] = obj_dict

        if not canon_t:
            obj_dict["status"] = "PARTIAL"
            self.diagnostics.append({
                "code": "UNKNOWN_TYPE",
                "address": hex(address),
                "object": path,
                "recoverable": True,
            })
            return obj_id

        # 2. Decode based on DWARF tag
        if canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
            self._decode_compound_members(obj_dict, canon_t, address, path, storage)
        elif canon_t.tag == "DW_TAG_base_type":
            self._decode_primitive_object(obj_dict, canon_t, address, path)
        elif canon_t.tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"):
            self._decode_pointer_object(obj_dict, canon_t, address, path, storage)
        elif canon_t.tag == "DW_TAG_enumeration_type":
            self._decode_enum_object(obj_dict, canon_t, address, path)
        elif canon_t.tag == "DW_TAG_array_type":
            self._decode_array_object(obj_dict, canon_t, address, path, storage)
        else:
            obj_dict["status"] = "PARTIAL"
            self.diagnostics.append({
                "code": "UNSUPPORTED_TYPE",
                "type": canon_t.tag,
                "address": hex(address),
                "object": path,
                "recoverable": True,
            })

        return obj_id

    def _collect_all_members(self, dwarf_t: DwarfType, base_offset: int = 0) -> List[Tuple[Any, int]]:
        """Recursively collect base class members and current members with effective byte offsets."""
        all_members = []
        for base in dwarf_t.base_classes:
            b_t = self.index.resolve_canonical_type(base.type_offset)
            if b_t and b_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                all_members.extend(self._collect_all_members(b_t, base_offset + base.offset))

        for m in dwarf_t.members:
            all_members.append((m, base_offset + m.offset))
        return all_members

    def _decode_compound_members(
        self,
        obj_dict: Dict[str, Any],
        dwarf_t: DwarfType,
        base_address: int,
        parent_path: str,
        storage: str
    ):
        members = self._collect_all_members(dwarf_t)

        for member, m_rel_offset in members:
            m_addr = base_address + m_rel_offset
            m_type_die = member.type_offset
            m_type = self.index.resolve_canonical_type(m_type_die) if m_type_die else None
            m_type_name = self.index.get_type_name(m_type_die) if m_type_die else "Unknown"
            clean_m_type = _clean_type_name(m_type_name)
            m_path = f"{parent_path}.{member.name}"

            if not m_type:
                field_entry = {
                    "name": member.name,
                    "type": clean_m_type,
                    "value": None,
                    "status": "UNRESOLVED_TYPE",
                    "address": hex(m_addr),
                }
                obj_dict["fields"].append(field_entry)
                obj_dict["status"] = "PARTIAL"
                continue

            tag = m_type.tag

            # (A) Primitive Base Type
            if tag == "DW_TAG_base_type":
                sz = m_type.byte_size or 4
                if not self.reader.contains(m_addr, sz):
                    field_entry = {
                        "name": member.name,
                        "type": clean_m_type,
                        "value": None,
                        "status": "MEMORY_NOT_CAPTURED",
                        "address": hex(m_addr),
                        "provenance": {
                            "source": "RAW_SNAPSHOT",
                            "dwarf_type_die": hex(m_type.die_offset),
                            "memory_range": [hex(m_addr), hex(m_addr + sz)],
                            "status": "MEMORY_NOT_CAPTURED"
                        }
                    }
                    obj_dict["fields"].append(field_entry)
                    obj_dict["status"] = "PARTIAL"
                    self.diagnostics.append({
                        "code": "MEMORY_NOT_CAPTURED",
                        "address": hex(m_addr),
                        "size": sz,
                        "object": m_path,
                        "recoverable": True,
                    })
                else:
                    val = self._read_primitive_val(m_addr, m_type)
                    field_entry = {
                        "name": member.name,
                        "type": clean_m_type,
                        "value": val,
                        "status": "RESOLVED",
                        "address": hex(m_addr),
                        "provenance": {
                            "source": "RAW_SNAPSHOT",
                            "dwarf_type_die": hex(m_type.die_offset),
                            "member_die": hex(member.die_offset) if member.die_offset else None,
                            "memory_range": [hex(m_addr), hex(m_addr + sz)],
                            "build_id": self.index.build_id,
                            "status": "RESOLVED"
                        }
                    }
                    obj_dict["fields"].append(field_entry)

            # (B) Enumeration Type
            elif tag == "DW_TAG_enumeration_type":
                sz = m_type.byte_size or 4
                raw_int, st = self.reader.read_integer(m_addr, sz, signed=True)
                if st != "COMPLETE" or raw_int is None:
                    field_entry = {
                        "name": member.name,
                        "type": clean_m_type,
                        "value": None,
                        "status": "MEMORY_NOT_CAPTURED",
                        "address": hex(m_addr),
                    }
                    obj_dict["fields"].append(field_entry)
                    obj_dict["status"] = "PARTIAL"
                    self.diagnostics.append({
                        "code": "MEMORY_NOT_CAPTURED",
                        "address": hex(m_addr),
                        "size": sz,
                        "object": m_path,
                        "recoverable": True,
                    })
                else:
                    enum_name = m_type.enum_values.get(raw_int, str(raw_int))
                    field_entry = {
                        "name": member.name,
                        "type": clean_m_type,
                        "value": enum_name,
                        "raw_value": raw_int,
                        "status": "RESOLVED",
                        "address": hex(m_addr),
                        "provenance": {
                            "source": "RAW_SNAPSHOT",
                            "dwarf_type_die": hex(m_type.die_offset),
                            "member_die": hex(member.die_offset) if member.die_offset else None,
                            "memory_range": [hex(m_addr), hex(m_addr + sz)],
                            "status": "RESOLVED"
                        }
                    }
                    obj_dict["fields"].append(field_entry)

            # (C) Pointer / Reference Type
            elif tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type"):
                ptr_val, st = self.reader.read_pointer(m_addr)
                if st != "COMPLETE" or ptr_val is None:
                    field_entry = {
                        "name": member.name,
                        "type": clean_m_type,
                        "value": None,
                        "reference": None,
                        "object_ref": None,
                        "status": "MEMORY_NOT_CAPTURED",
                        "address": hex(m_addr),
                    }
                    obj_dict["fields"].append(field_entry)
                    obj_dict["status"] = "PARTIAL"
                    self.diagnostics.append({
                        "code": "MEMORY_NOT_CAPTURED",
                        "address": hex(m_addr),
                        "size": self.pointer_size,
                        "object": m_path,
                        "recoverable": True,
                    })
                elif ptr_val == 0:
                    field_entry = {
                        "name": member.name,
                        "type": clean_m_type,
                        "value": "0x0",
                        "reference": None,
                        "object_ref": None,
                        "status": "NULL_PTR",
                        "address": hex(m_addr),
                    }
                    obj_dict["fields"].append(field_entry)
                else:
                    target_t = self.index.resolve_canonical_type(m_type.target_type_offset) if m_type.target_type_offset else None
                    target_sz = target_t.byte_size if target_t and target_t.byte_size else 1

                    if not self.reader.contains(ptr_val, target_sz):
                        field_entry = {
                            "name": member.name,
                            "type": clean_m_type,
                            "value": hex(ptr_val),
                            "reference": None,
                            "object_ref": None,
                            "status": "OUTSIDE_CAPTURE",
                            "target_status": "OUTSIDE_CAPTURE",
                            "address": hex(m_addr),
                        }
                        obj_dict["fields"].append(field_entry)
                    else:
                        target_storage = "heap" if self.reader.is_heap(ptr_val) else ("stack" if self.reader.is_stack(ptr_val) else "global")
                        target_id = self.decode_object(
                            address=ptr_val,
                            type_offset=m_type.target_type_offset,
                            path=m_path,
                            storage=target_storage,
                        )
                        field_entry = {
                            "name": member.name,
                            "type": clean_m_type,
                            "value": hex(ptr_val),
                            "reference": target_id,
                            "object_ref": target_id,
                            "status": "RESOLVED",
                            "address": hex(m_addr),
                            "provenance": {
                                "source": "RAW_SNAPSHOT",
                                "dwarf_type_die": hex(m_type.die_offset),
                                "member_die": hex(member.die_offset) if member.die_offset else None,
                                "memory_range": [hex(m_addr), hex(m_addr + self.pointer_size)],
                                "status": "RESOLVED"
                            }
                        }
                        obj_dict["fields"].append(field_entry)
                        self.references.append({
                            "from_id": obj_dict["object_id"],
                            "to_id": target_id,
                            "field": member.name,
                            "type": "pointer",
                        })
                        if self.objects_by_id.get(target_id, {}).get("status") == "PARTIAL":
                            obj_dict["status"] = "PARTIAL"

            # (D) Embedded Structure / Class
            elif tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                sub_id = self.decode_object(
                    address=m_addr,
                    type_offset=member.type_offset,
                    path=m_path,
                    storage=storage,
                )
                field_entry = {
                    "name": member.name,
                    "type": clean_m_type,
                    "value": hex(m_addr),
                    "reference": sub_id,
                    "object_ref": sub_id,
                    "status": "RESOLVED",
                    "address": hex(m_addr),
                    "provenance": {
                        "source": "RAW_SNAPSHOT",
                        "dwarf_type_die": hex(m_type.die_offset),
                        "member_die": hex(member.die_offset) if member.die_offset else None,
                        "memory_range": [hex(m_addr), hex(m_addr + m_type.byte_size)],
                        "status": "RESOLVED"
                    }
                }
                obj_dict["fields"].append(field_entry)
                self.references.append({
                    "from_id": obj_dict["object_id"],
                    "to_id": sub_id,
                    "field": member.name,
                    "type": "embedded",
                })
                if self.objects_by_id.get(sub_id, {}).get("status") == "PARTIAL":
                    obj_dict["status"] = "PARTIAL"

            # (E) Array Type
            elif tag == "DW_TAG_array_type":
                elem_t = self.index.resolve_canonical_type(m_type.target_type_offset) if m_type.target_type_offset else None
                elem_sz = elem_t.byte_size if elem_t else 4
                count = m_type.array_count or 0
                arr_vals = []
                arr_st = "RESOLVED"
                for k in range(count):
                    e_addr = m_addr + k * elem_sz
                    if not self.reader.contains(e_addr, elem_sz):
                        arr_vals.append(None)
                        arr_st = "MEMORY_NOT_CAPTURED"
                        obj_dict["status"] = "PARTIAL"
                    else:
                        v = self._read_primitive_val(e_addr, elem_t) if elem_t else 0
                        arr_vals.append(v)

                field_entry = {
                    "name": member.name,
                    "type": clean_m_type,
                    "value": arr_vals,
                    "status": arr_st,
                    "address": hex(m_addr),
                    "provenance": {
                        "source": "RAW_SNAPSHOT",
                        "dwarf_type_die": hex(m_type.die_offset),
                        "member_die": hex(member.die_offset) if member.die_offset else None,
                        "memory_range": [hex(m_addr), hex(m_addr + count * elem_sz)],
                        "status": arr_st
                    }
                }
                obj_dict["fields"].append(field_entry)

            # (F) Fallback for unsupported complex types
            else:
                field_entry = {
                    "name": member.name,
                    "type": clean_m_type,
                    "value": None,
                    "status": "UNSUPPORTED_TYPE",
                    "address": hex(m_addr),
                }
                obj_dict["fields"].append(field_entry)
                obj_dict["status"] = "PARTIAL"
                self.diagnostics.append({
                    "code": "UNSUPPORTED_TYPE",
                    "type": clean_m_type,
                    "address": hex(m_addr),
                    "object": m_path,
                    "recoverable": True,
                })

    def _read_primitive_val(self, address: int, dwarf_t: DwarfType) -> Any:
        sz = dwarf_t.byte_size or 4
        fl = (dwarf_t.name or "").lower()
        if "float" in fl or "double" in fl:
            v, _ = self.reader.read_float(address, sz)
            return v
        if "bool" in fl:
            raw, _ = self.reader.read_integer(address, sz, signed=False)
            return bool(raw)
        signed = ("unsigned" not in fl and "char" not in fl) or ("signed char" in fl)
        v, _ = self.reader.read_integer(address, sz, signed=signed)
        return v

    def _decode_primitive_object(self, obj_dict: Dict[str, Any], dwarf_t: DwarfType, address: int, path: str):
        sz = dwarf_t.byte_size or 4
        if not self.reader.contains(address, sz):
            obj_dict["status"] = "PARTIAL"
            obj_dict["fields"].append({
                "name": "value",
                "type": obj_dict["type"],
                "value": None,
                "status": "MEMORY_NOT_CAPTURED",
                "address": hex(address),
            })
            self.diagnostics.append({
                "code": "MEMORY_NOT_CAPTURED",
                "address": hex(address),
                "size": sz,
                "object": path,
                "recoverable": True,
            })
        else:
            val = self._read_primitive_val(address, dwarf_t)
            obj_dict["fields"].append({
                "name": "value",
                "type": obj_dict["type"],
                "value": val,
                "status": "RESOLVED",
                "address": hex(address),
                "provenance": {
                    "source": "RAW_SNAPSHOT",
                    "dwarf_type_die": hex(dwarf_t.die_offset),
                    "memory_range": [hex(address), hex(address + sz)],
                    "status": "RESOLVED",
                }
            })

    def _decode_pointer_object(self, obj_dict: Dict[str, Any], dwarf_t: DwarfType, address: int, path: str, storage: str):
        ptr_val, st = self.reader.read_pointer(address)
        if st != "COMPLETE" or ptr_val is None:
            obj_dict["status"] = "PARTIAL"
            obj_dict["fields"].append({
                "name": "ptr",
                "type": obj_dict["type"],
                "value": None,
                "status": "MEMORY_NOT_CAPTURED",
                "address": hex(address),
            })
        elif ptr_val == 0:
            obj_dict["fields"].append({
                "name": "ptr",
                "type": obj_dict["type"],
                "value": "0x0",
                "status": "NULL_PTR",
                "address": hex(address),
            })
        else:
            target_t = self.index.resolve_canonical_type(dwarf_t.target_type_offset) if dwarf_t.target_type_offset else None
            target_sz = target_t.byte_size if target_t and target_t.byte_size else 1
            if not self.reader.contains(ptr_val, target_sz):
                obj_dict["fields"].append({
                    "name": "ptr",
                    "type": obj_dict["type"],
                    "value": hex(ptr_val),
                    "status": "OUTSIDE_CAPTURE",
                    "address": hex(address),
                })
            else:
                target_storage = "heap" if self.reader.is_heap(ptr_val) else "global"
                target_id = self.decode_object(
                    address=ptr_val,
                    type_offset=dwarf_t.target_type_offset,
                    path=f"{path}->deref",
                    storage=target_storage,
                )
                obj_dict["fields"].append({
                    "name": "ptr",
                    "type": obj_dict["type"],
                    "value": hex(ptr_val),
                    "reference": target_id,
                    "object_ref": target_id,
                    "status": "RESOLVED",
                    "address": hex(address),
                })
                self.references.append({
                    "from_id": obj_dict["object_id"],
                    "to_id": target_id,
                    "field": "ptr",
                    "type": "pointer",
                })

    def _decode_enum_object(self, obj_dict: Dict[str, Any], dwarf_t: DwarfType, address: int, path: str):
        sz = dwarf_t.byte_size or 4
        raw, st = self.reader.read_integer(address, sz, signed=True)
        if st != "COMPLETE" or raw is None:
            obj_dict["status"] = "PARTIAL"
            obj_dict["fields"].append({
                "name": "value",
                "type": obj_dict["type"],
                "value": None,
                "status": "MEMORY_NOT_CAPTURED",
                "address": hex(address),
            })
        else:
            name = dwarf_t.enum_values.get(raw, str(raw))
            obj_dict["fields"].append({
                "name": "value",
                "type": obj_dict["type"],
                "value": name,
                "raw_value": raw,
                "status": "RESOLVED",
                "address": hex(address),
            })

    def _decode_array_object(self, obj_dict: Dict[str, Any], dwarf_t: DwarfType, address: int, path: str, storage: str):
        elem_t = self.index.resolve_canonical_type(dwarf_t.target_type_offset) if dwarf_t.target_type_offset else None
        elem_sz = elem_t.byte_size if elem_t else 4
        count = dwarf_t.array_count or 0
        arr_vals = []
        for k in range(count):
            e_addr = address + k * elem_sz
            if not self.reader.contains(e_addr, elem_sz):
                arr_vals.append(None)
                obj_dict["status"] = "PARTIAL"
            else:
                arr_vals.append(self._read_primitive_val(e_addr, elem_t) if elem_t else 0)
        obj_dict["fields"].append({
            "name": "elements",
            "type": obj_dict["type"],
            "value": arr_vals,
            "status": "RESOLVED" if obj_dict["status"] == "COMPLETE" else "PARTIAL",
            "address": hex(address),
        })


class DwarfRuntimeResolver:
    """Orchestrates DWARF-backed runtime state resolution and PIE load bias."""

    def __init__(
        self,
        snapshot: RawRuntimeSnapshot,
        debug_image_path: str,
        allow_symbol_mismatch: bool = False
    ):
        self.snapshot = snapshot
        self.debug_image_path = os.path.abspath(debug_image_path)
        self.allow_symbol_mismatch = allow_symbol_mismatch

    def calculate_load_bias(self, debug_index: DwarfIndex) -> int:
        """Calculate runtime load bias: runtime_base_vaddr - first_pt_load_p_vaddr."""
        first_load_vaddr = 0
        if debug_index.pt_loads:
            first_load_vaddr = debug_index.pt_loads[0].get("p_vaddr", 0)

        target_name = os.path.basename(self.snapshot.executable) if self.snapshot.executable else ""

        # 1. Search full memory_maps from observation metadata if available
        maps_to_search = self.snapshot.observation_metadata.get("memory_maps") or []
        binary_entries = []
        for r in maps_to_search:
            pathname = r.get("pathname", "")
            cat = r.get("category", "")
            start = r.get("start")
            if isinstance(start, str):
                start = int(start, 16)
            if start is not None:
                if (target_name and (target_name in pathname or pathname == self.snapshot.executable)) or (cat == "binary"):
                    binary_entries.append(r)

        if binary_entries:
            binary_entries.sort(key=lambda item: item["start"] if isinstance(item["start"], int) else int(str(item["start"]), 16))
            b_start = binary_entries[0]["start"]
            runtime_base = b_start if isinstance(b_start, int) else int(str(b_start), 16)
            return runtime_base - first_load_vaddr

        # 2. Search snapshot.memory_regions
        binary_regions = []
        for r in self.snapshot.memory_regions:
            pathname = r.get("pathname", "")
            cat = r.get("category", "")
            start = r.get("start")
            if isinstance(start, str):
                start = int(start, 16)
            if start is not None:
                if (target_name and (target_name in pathname or pathname == self.snapshot.executable)) or (cat == "binary"):
                    binary_regions.append(r)

        if binary_regions:
            # Check if any region has offset == 0
            for r in binary_regions:
                off = r.get("offset")
                if off is not None:
                    off_val = off if isinstance(off, int) else int(str(off), 16)
                    if off_val == 0:
                        s_val = r["start"] if isinstance(r["start"], int) else int(str(r["start"]), 16)
                        return s_val - first_load_vaddr

            # If no offset 0, match with PT_LOAD segments
            for r in binary_regions:
                off = r.get("offset")
                s_val = r["start"] if isinstance(r["start"], int) else int(str(r["start"]), 16)
                if off is not None and debug_index.pt_loads:
                    off_val = off if isinstance(off, int) else int(str(off), 16)
                    for seg in debug_index.pt_loads:
                        p_off = seg.get("p_offset", 0)
                        if (p_off & ~0xfff) == (off_val & ~0xfff) or p_off == off_val:
                            return s_val - seg.get("p_vaddr", 0)

            # Fallback to lowest start
            binary_regions.sort(key=lambda item: item["start"] if isinstance(item["start"], int) else int(str(item["start"]), 16))
            s_val = binary_regions[0]["start"]
            runtime_base = s_val if isinstance(s_val, int) else int(str(s_val), 16)
            return runtime_base - first_load_vaddr

        return 0

    def resolve(self, target_variable: Optional[str] = None) -> ResolutionResult:
        """Execute full DWARF semantic reconstruction."""
        diagnostics = []

        if not os.path.exists(self.debug_image_path):
            return ResolutionResult(
                status="DECODE_ERROR",
                diagnostics=[{
                    "code": "MISSING_DEBUG_IMAGE",
                    "message": f"Debug image artifact not found: {self.debug_image_path}",
                    "recoverable": False
                }]
            )

        try:
            dwarf_index = DwarfIndexer.get_index(self.debug_image_path)
        except Exception as exc:
            return ResolutionResult(
                status="DECODE_ERROR",
                diagnostics=[{
                    "code": "DWARF_PARSE_ERROR",
                    "message": f"Failed to parse DWARF debug info: {exc}",
                    "recoverable": False
                }]
            )

        # 1. Build ID verification
        snap_bid = self.snapshot.executable_build_id
        dbg_bid = dwarf_index.build_id
        if snap_bid and dbg_bid and snap_bid.lower() != dbg_bid.lower():
            if not self.allow_symbol_mismatch:
                return ResolutionResult(
                    status="SYMBOL_MISMATCH",
                    build_id=dbg_bid,
                    diagnostics=[{
                        "code": "SYMBOL_MISMATCH",
                        "message": f"Snapshot executable build ID '{snap_bid}' does not match debug artifact build ID '{dbg_bid}'",
                        "expected_build_id": snap_bid,
                        "actual_build_id": dbg_bid,
                        "recoverable": False
                    }]
                )
            else:
                diagnostics.append({
                    "code": "SYMBOL_MISMATCH_IGNORED",
                    "message": f"Mismatch between snapshot '{snap_bid}' and debug '{dbg_bid}' permitted by allow_symbol_mismatch.",
                    "expected_build_id": snap_bid,
                    "actual_build_id": dbg_bid,
                    "recoverable": True
                })

        # 2. PIE / ASLR Load bias
        load_bias = self.calculate_load_bias(dwarf_index)

        # 3. Create TypedMemoryReader
        reader = TypedMemoryReader(
            snapshot=self.snapshot,
            pointer_size=dwarf_index.pointer_size,
            endianness=dwarf_index.endianness
        )

        # 4. Filter candidate variables
        candidate_vars: List[DwarfVariable] = []
        for v in dwarf_index.variables:
            if v.link_time_address is None or v.is_declaration:
                continue
            if not v.name or v.name.startswith("_") or "::" in v.name:
                continue
            if target_variable and v.name != target_variable:
                continue
            candidate_vars.append(v)

        # Sort candidate variables canonically by name
        candidate_vars.sort(key=lambda var: var.name)

        if not candidate_vars:
            return ResolutionResult(
                status="UNRESOLVED",
                load_bias=load_bias,
                pointer_size=dwarf_index.pointer_size,
                endianness=dwarf_index.endianness,
                build_id=dbg_bid,
                debug_image_path=self.debug_image_path,
                diagnostics=[{
                    "code": "NO_DWARF_ROOTS",
                    "message": "No global or static variables with link-time locations found in DWARF index.",
                    "recoverable": False
                }]
            )

        decoder = CppObjectDecoder(reader, dwarf_index, load_bias=load_bias)
        roots: List[Dict[str, Any]] = []

        for var in candidate_vars:
            runtime_addr = var.link_time_address + load_bias
            var_t = dwarf_index.resolve_canonical_type(var.type_offset) if var.type_offset else None
            type_name = dwarf_index.get_type_name(var.type_offset) if var.type_offset else "Unknown"
            clean_type = _clean_type_name(var_t.name if var_t and var_t.name else type_name)

            storage_kind = "global" if var.is_external else "file_static"
            obj_id = decoder.decode_object(
                address=runtime_addr,
                type_offset=var.type_offset,
                path=var.name,
                storage=storage_kind,
                custom_name=var.name,
            )

            root_entry = {
                "name": var.name,
                "kind": storage_kind,
                "address": runtime_addr,
                "type": clean_type,
                "type_die": hex(var.type_offset) if var.type_offset else None,
                "object_ref": obj_id,
                "resolution_status": "RESOLVED",
                "provenance": {
                    "source": "DWARF",
                    "die_offset": hex(var.die_offset),
                    "link_time_address": hex(var.link_time_address),
                    "runtime_address": hex(runtime_addr),
                    "load_bias": hex(load_bias),
                    "decl_file": var.decl_file,
                    "decl_line": var.decl_line,
                }
            }
            roots.append(root_entry)

        objects = list(decoder.objects_by_id.values())
        references = decoder.references
        diagnostics.extend(decoder.diagnostics)

        # Determine overall state status
        has_partial = any(o.get("status") == "PARTIAL" for o in objects)
        has_uncaptured = any(d.get("code") == "MEMORY_NOT_CAPTURED" for d in diagnostics)
        has_unsupported = any(d.get("code") == "UNSUPPORTED_TYPE" for d in diagnostics)

        if has_uncaptured or has_partial or has_unsupported:
            state_status = "PARTIAL"
        else:
            state_status = "COMPLETE"

        return ResolutionResult(
            status=state_status,
            roots=roots,
            objects=objects,
            references=references,
            diagnostics=diagnostics,
            load_bias=load_bias,
            pointer_size=dwarf_index.pointer_size,
            endianness=dwarf_index.endianness,
            build_id=dbg_bid,
            debug_image_path=self.debug_image_path,
        )
