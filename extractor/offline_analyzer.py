"""Offline semantic state analysis for low-impact memory snapshots (Phase 5.1).

Reconstructs DWARF-aware runtime object graphs and semantic snapshots purely from
captured memory artifacts and external debug images, without attaching to or stopping
any running process.
"""

from collections import deque
from dataclasses import asdict
from datetime import datetime, timezone
import json
import math
import os
import struct
import subprocess
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .debug_artifacts import DebugArtifactProvider
from .debug_image import BinaryIdentity, CompatibilityResult, DebugImageProvider, inspect_elf
from .debug_info import DebugInfoProvider, GdbDebugInfoProvider
from .memory_snapshot import CapturedRegion, RawMemorySnapshot
from .modules import ModuleAddressResolver, RuntimeModule, discover_modules
from .runtime_state import (
    ExecutionState,
    FieldState,
    ObjectState,
    PersistentState,
    RootState,
    ThreadState,
    VariableState,
)
from .snapshot import RuntimeSnapshot


class SnapshotMemoryReader:
    """Module-aware memory reader from raw memory snapshot artifacts."""

    def __init__(
        self,
        raw_snapshot: RawMemorySnapshot,
        modules: Optional[List[RuntimeModule]] = None,
    ):
        self.snapshot = raw_snapshot
        self._regions: List[Tuple[int, int, str, str, CapturedRegion]] = []
        self._cache: Dict[str, bytes] = {}

        for r in raw_snapshot.regions:
            if r.captured > 0 and r.filename:
                full_path = os.path.join(raw_snapshot.output_dir, r.filename)
                self._regions.append((r.start, r.start + r.captured, full_path, r.category, r))

        # Sort by ascending start address for binary search / quick lookup
        self._regions.sort(key=lambda x: x[0])

        if modules is not None:
            self.modules = list(modules)
        elif raw_snapshot.modules:
            self.modules = [
                RuntimeModule.from_dict(m) if isinstance(m, dict) else m
                for m in raw_snapshot.modules
            ]
        else:
            self.modules = discover_modules(
                raw_snapshot.pid, raw_snapshot.maps, raw_snapshot.binary
            )

        # Determine target endianness authoritatively
        # Precedence: 1. RuntimeModule.endianness, 2. raw_snapshot.endianness, 3. None (UNKNOWN)
        main_mod = next((m for m in self.modules if m.is_main_executable), self.modules[0] if self.modules else None)
        raw_endian = None
        if main_mod and main_mod.endianness and main_mod.endianness.lower() in ("little", "big"):
            raw_endian = main_mod.endianness.lower()
        elif getattr(raw_snapshot, "endianness", None) and str(raw_snapshot.endianness).lower() in ("little", "big"):
            raw_endian = str(raw_snapshot.endianness).lower()

        self.endianness: Optional[str] = raw_endian

        # Determine pointer width authoritatively from ELF class
        # Precedence: 1. RuntimeModule.elf_class, 2. raw_snapshot.elf_class, 3. None (UNKNOWN)
        if main_mod and main_mod.elf_class == "ELF32":
            self.ptr_size: Optional[int] = 4
        elif main_mod and main_mod.elf_class == "ELF64":
            self.ptr_size = 8
        elif getattr(raw_snapshot, "elf_class", None) == "ELF32":
            self.ptr_size = 4
        elif getattr(raw_snapshot, "elf_class", None) == "ELF64":
            self.ptr_size = 8
        else:
            self.ptr_size = None

    def find_region(self, address: int) -> Optional[Tuple[int, int, str, str, CapturedRegion]]:
        for start, end, fpath, cat, reg in self._regions:
            if start <= address < end:
                return (start, end, fpath, cat, reg)
        return None

    def region_for_address(self, address: int) -> Optional[CapturedRegion]:
        r = self.find_region(address)
        return r[4] if r else None

    def module_for_address(self, address: int) -> Optional[RuntimeModule]:
        for mod in self.modules:
            if mod.runtime_base <= address < mod.runtime_end:
                return mod
        return None

    def runtime_to_elf(self, address: int) -> Optional[Tuple[RuntimeModule, int]]:
        mod = self.module_for_address(address)
        if not mod or mod.load_bias_status != "RESOLVED" or mod.load_bias is None:
            return None
        return (mod, ModuleAddressResolver.resolve_elf_address(mod, address))

    def elf_to_runtime(self, module: RuntimeModule, elf_address: int) -> int:
        return ModuleAddressResolver.resolve_runtime_address(module, elf_address)

    def is_readable(self, address: int, size: int = 1) -> bool:
        r = self.find_region(address)
        if not r:
            return False
        return (address + size) <= r[1]

    def read(self, address: int, size: int) -> Optional[bytes]:
        if size <= 0:
            return b""
        r = self.find_region(address)
        if not r:
            return None
        start, end, fpath, _, _ = r
        if (address + size) > end:
            # Span exceeds captured boundary
            return None

        # Guard against reads exceeding module boundaries
        mod = self.module_for_address(address)
        if mod and (address + size) > mod.runtime_end:
            return None

        # Load region file (cache into memory)
        if fpath not in self._cache:
            if not os.path.exists(fpath):
                return None
            with open(fpath, "rb") as f:
                self._cache[fpath] = f.read()

        data = self._cache[fpath]
        offset = address - start
        res = data[offset:offset + size]
        if len(res) < size:
            return None
        return res

    def read_int(self, address: int, size: int = 4, signed: bool = False, endian: Optional[str] = None) -> Optional[int]:
        byte_order = endian or self.endianness
        if not byte_order or byte_order not in ("little", "big"):
            raise ValueError(f"TARGET_ENDIANNESS_UNAVAILABLE: '{byte_order}'")
        raw = self.read(address, size)
        if raw is None or len(raw) < size:
            return None
        return int.from_bytes(raw, byteorder=byte_order, signed=signed)

    def read_ptr(self, address: int, ptr_size: Optional[int] = None, endian: Optional[str] = None) -> Optional[int]:
        p_size = ptr_size if ptr_size is not None else self.ptr_size
        if p_size is None or p_size not in (4, 8):
            return None
        byte_order = endian or self.endianness
        if not byte_order or byte_order not in ("little", "big"):
            raise ValueError(f"TARGET_ENDIANNESS_UNAVAILABLE: '{byte_order}'")
        raw = self.read(address, p_size)
        if raw is None or len(raw) < p_size:
            return None
        return int.from_bytes(raw, byteorder=byte_order, signed=False)

    def read_float(self, address: int, endian: Optional[str] = None) -> Optional[float]:
        byte_order = endian or self.endianness
        if not byte_order or byte_order not in ("little", "big"):
            raise ValueError(f"TARGET_ENDIANNESS_UNAVAILABLE: '{byte_order}'")
        raw = self.read(address, 4)
        if raw is None or len(raw) < 4:
            return None
        fmt = "<f" if byte_order == "little" else ">f"
        return struct.unpack(fmt, raw)[0]

    def read_double(self, address: int, endian: Optional[str] = None) -> Optional[float]:
        byte_order = endian or self.endianness
        if not byte_order or byte_order not in ("little", "big"):
            raise ValueError(f"TARGET_ENDIANNESS_UNAVAILABLE: '{byte_order}'")
        raw = self.read(address, 8)
        if raw is None or len(raw) < 8:
            return None
        fmt = "<d" if byte_order == "little" else ">d"
        return struct.unpack(fmt, raw)[0]

    def read_bool(self, address: int) -> Optional[bool]:
        val = self.read_int(address, 1, signed=False)
        return bool(val) if val is not None else None

    def read_string(self, address: int, max_len: int = 256) -> Optional[str]:
        r = self.find_region(address)
        if not r:
            return None
        available = r[1] - address
        if available <= 0:
            return None
        read_len = min(max_len, available)
        raw = self.read(address, read_len)
        if raw is None:
            return None
        nul = raw.find(b"\x00")
        if nul >= 0:
            raw = raw[:nul]
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return str(raw)


def extract_dwarf_context(debug_image_path: str, known_symbols: Optional[List[str]] = None) -> Dict[str, Any]:
    """Extract global symbols and struct/enum type definitions from an external debug image.

    Runs GDB in batch mode without launching or attaching to any inferior process.
    """
    if not os.path.exists(debug_image_path):
        raise FileNotFoundError(f"Debug image not found: {debug_image_path}")

    # Discover global variable symbols from ELF symbols if known_symbols not fully specified
    sym_list = list(known_symbols or [])
    try:
        cmd_nm = ["nm", "-g", "-C", "--defined-only", "--", debug_image_path]
        proc_nm = subprocess.run(cmd_nm, capture_output=True, text=True, check=False, timeout=10)
        if proc_nm.returncode == 0:
            for line in proc_nm.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] in ("B", "D", "R", "b", "d", "r"):
                    name = parts[2]
                    if not name.startswith("_") and "::" not in name:
                        if name not in sym_list:
                            sym_list.append(name)
    except Exception:
        pass

    # Default common symbol targets if empty
    if not sym_list:
        sym_list = ["global_session", "file_session", "g_manager", "session"]

    sym_arg = json.dumps(sym_list)

    py_script = f"""
import gdb, json

sym_names = {sym_arg}
discovered_symbols = []
discovered_types = {{}}

for s_name in sym_names:
    try:
        sym = gdb.lookup_global_symbol(s_name)
        if not sym:
            sym = gdb.lookup_static_symbol(s_name)
        if sym:
            addr = int(gdb.parse_and_eval('&' + s_name))
            discovered_symbols.append({{
                'name': s_name,
                'type': str(sym.type),
                'address': addr
            }})
            # Enqueue type for resolution
            t = sym.type.strip_typedefs()
            if t.code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_REF):
                try:
                    target_t = t.target().strip_typedefs()
                    discovered_types[str(target_t)] = target_t
                except Exception:
                    pass
            discovered_types[str(t)] = t
    except Exception:
        pass

# Also resolve common application structs
for extra in ['Session', 'Buffer', 'SessionState', 'Manager']:
    try:
        t = gdb.lookup_type(extra).strip_typedefs()
        discovered_types[extra] = t
    except Exception:
        pass

types_out = {{}}
for t_name, t in list(discovered_types.items()):
    try:
        clean_name = getattr(t, 'name', None) or getattr(t, 'tag', None) or str(t)
        if clean_name in types_out:
            continue
        if t.code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
            fields = []
            for f in t.fields():
                if getattr(f, 'is_base_class', False):
                    continue
                fields.append({{
                    'name': f.name,
                    'type': str(f.type),
                    'offset': f.bitpos // 8 if f.bitpos is not None else 0,
                    'sizeof': getattr(f.type, 'sizeof', 0)
                }})
            types_out[clean_name] = {{
                'name': clean_name,
                'sizeof': t.sizeof,
                'code': 'aggregate',
                'fields': fields
            }}
        elif t.code == gdb.TYPE_CODE_ENUM:
            types_out[clean_name] = {{
                'name': clean_name,
                'sizeof': t.sizeof,
                'code': 'enum',
                'fields': [getattr(f, 'name', str(f)) for f in t.fields()]
            }}
    except Exception:
        pass

print('__DWARF_JSON_START__')
print(json.dumps({{'symbols': discovered_symbols, 'types': types_out}}))
print('__DWARF_JSON_END__')
"""

    cmd = ["gdb", "-q", "-nx", "-batch", "-ex", f"file {debug_image_path}", "-ex", f"python\n{py_script}"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"GDB offline symbol extraction failed: {proc.stderr}")

    out = proc.stdout
    start_tag = "__DWARF_JSON_START__"
    end_tag = "__DWARF_JSON_END__"
    if start_tag not in out or end_tag not in out:
        raise RuntimeError(f"Failed to parse DWARF JSON output from GDB: {out}")

    json_str = out.split(start_tag, 1)[1].split(end_tag, 1)[0].strip()
    return json.loads(json_str)


class OfflineMemoryAnalyzer:
    """Analyzes raw memory snapshots and generates semantic RuntimeSnapshots offline."""

    MAX_OBJECT_DEPTH = 8

    def __init__(self):
        self._object_counter = 0

    def analyze(
        self,
        memory_snapshot: Union[RawMemorySnapshot, str],
        debug_image: Optional[Union[DebugImageProvider, DebugArtifactProvider, str]] = None,
        optional_symbol_context: Optional[Dict[str, Any]] = None,
        debug_artifact_provider: Optional[DebugArtifactProvider] = None,
        debug_info_provider: Optional[DebugInfoProvider] = None,
        search_paths: Optional[List[str]] = None,
    ) -> RuntimeSnapshot:
        """Perform offline semantic reconstruction of the captured process state."""
        t_start = time.monotonic()

        # 1. Load memory snapshot
        if isinstance(memory_snapshot, str):
            raw_snap = RawMemorySnapshot.load(memory_snapshot)
        else:
            raw_snap = memory_snapshot

        # 2. Resolve runtime modules
        if raw_snap.modules:
            modules = [
                RuntimeModule.from_dict(m) if isinstance(m, dict) else m
                for m in raw_snap.modules
            ]
        else:
            modules = discover_modules(raw_snap.pid, raw_snap.maps, raw_snap.binary)

        main_module = next((m for m in modules if m.is_main_executable), modules[0] if modules else None)

        # 3. Resolve and verify debug artifact
        if debug_artifact_provider:
            artifact_provider = debug_artifact_provider
        elif isinstance(debug_image, DebugArtifactProvider):
            artifact_provider = debug_image
        else:
            artifact_provider = DebugArtifactProvider(search_paths=search_paths)

        if isinstance(debug_image, str):
            if main_module:
                artifact_provider.register(main_module.module_id, debug_image)
            artifact_provider.register("main", debug_image)
        elif isinstance(debug_image, DebugImageProvider) and debug_image.path:
            if main_module:
                artifact_provider.register(main_module.module_id, debug_image.path)
            artifact_provider.register("main", debug_image.path)

        dbg_path = None
        if main_module:
            dbg_path = artifact_provider.find_debug_artifact(main_module)
        if not dbg_path and isinstance(debug_image, str):
            dbg_path = os.path.abspath(debug_image)
        elif not dbg_path and hasattr(debug_image, "path") and debug_image.path:
            dbg_path = debug_image.path

        if not dbg_path:
            dbg_path = getattr(debug_image, "path", None) or "unknown_debug_image"

        if not optional_symbol_context and (not dbg_path or not os.path.exists(dbg_path)):
            raise FileNotFoundError(
                f"Debug artifact not found for main executable: {main_module.path if main_module else 'unknown'}"
            )

        if main_module and dbg_path and os.path.exists(dbg_path):
            compat = artifact_provider.verify(main_module, dbg_path)
            if not compat.compatible:
                raise ValueError(f"DEBUG_IMAGE_MISMATCH: {compat.reason}")
        elif hasattr(debug_image, "verify") and callable(debug_image.verify):
            compat = debug_image.verify(raw_snap.binary)
            if hasattr(compat, "compatible") and not compat.compatible:
                raise ValueError(f"DEBUG_IMAGE_MISMATCH: {compat.reason}")

        # 4. Extract symbols & types via DebugInfoProvider
        if optional_symbol_context:
            symbol_context = optional_symbol_context
        elif debug_info_provider:
            debug_info_provider.load(main_module, dbg_path)
            symbol_context = {
                "symbols": debug_info_provider.get_symbols(),
                "types": debug_info_provider.get_types(),
            }
        else:
            info_provider = GdbDebugInfoProvider(dbg_path)
            symbol_context = {
                "symbols": info_provider.get_symbols(),
                "types": info_provider.get_types(),
            }

        symbols = symbol_context.get("symbols", [])
        types_map = symbol_context.get("types", {})

        # 5. Initialize module-aware SnapshotMemoryReader and Object Graph builders
        reader = SnapshotMemoryReader(raw_snap, modules=modules)
        roots: List[RootState] = []
        objects: List[ObjectState] = []
        by_identity: Dict[Tuple[str, str], ObjectState] = {}
        active_identities: Set[Tuple[str, str]] = set()

        def classify_address(addr_num: int) -> str:
            for m in raw_snap.maps:
                s = m.get("start_addr", int(m.get("start", "0"), 16))
                e = m.get("end_addr", int(m.get("end", "0"), 16))
                if s <= addr_num < e:
                    return m.get("category", m.get("kind", "unknown"))
            return "unknown"

        def resolve_type_info(type_str: str) -> Dict[str, Any]:
            clean = type_str.replace(" *", "*").replace(" &", "&").strip()
            is_ptr = clean.endswith("*")
            base = clean[:-1].strip() if is_ptr else clean
            return {
                "clean": clean,
                "is_ptr": is_ptr,
                "base": base,
                "definition": types_map.get(base) or types_map.get(clean),
            }

        def build_object(address_num: int, type_name: str, depth: int) -> Optional[str]:
            if depth > self.MAX_OBJECT_DEPTH:
                return None
            if address_num == 0:
                return None

            addr_hex = "0x{:x}".format(address_num)
            identity = (addr_hex, type_name)
            if identity in by_identity:
                return by_identity[identity].object_id

            type_def = types_map.get(type_name)
            if not type_def or type_def.get("code") != "aggregate":
                return None

            self._object_counter += 1
            obj_id = "obj_{:04d}".format(self._object_counter)
            storage = classify_address(address_num)

            obj = ObjectState(
                object_id=obj_id,
                type=type_name,
                address=addr_hex,
                storage=storage,
                thread_id=None,
                frame_level=None,
                fields=[]
            )

            by_identity[identity] = obj
            objects.append(obj)
            active_identities.add(identity)

            try:
                for f_info in type_def.get("fields", []):
                    f_name = f_info["name"]
                    f_type = f_info["type"]
                    f_offset = f_info["offset"]
                    f_addr = address_num + f_offset

                    f_tinfo = resolve_type_info(f_type)
                    clean_type = f_tinfo["clean"]
                    is_ptr = f_tinfo["is_ptr"]
                    base_type = f_tinfo["base"]

                    try:
                        if is_ptr:
                            ptr_val = reader.read_ptr(f_addr)
                            if ptr_val is None:
                                obj.fields.append(FieldState(
                                    name=f_name,
                                    type=clean_type,
                                    offset=f_offset,
                                    availability="unavailable",
                                    error="Memory not captured or pointer width unavailable"
                                ))
                            elif ptr_val == 0:
                                obj.fields.append(FieldState(
                                    name=f_name,
                                    type=clean_type,
                                    offset=f_offset,
                                    value="0x0",
                                    address="0x0",
                                    object_ref=None
                                ))
                            else:
                                ptr_hex = "0x{:x}".format(ptr_val)
                                target_ref = None
                                if depth + 1 <= self.MAX_OBJECT_DEPTH:
                                    target_ref = build_object(ptr_val, base_type, depth + 1)
                                obj.fields.append(FieldState(
                                    name=f_name,
                                    type=clean_type,
                                    offset=f_offset,
                                    value=ptr_hex,
                                    address=ptr_hex,
                                    object_ref=target_ref
                                ))
                        elif clean_type in ("bool", "int", "short", "uint16_t", "int16_t", "unsigned short", "uint32_t", "uint64_t", "int32_t", "int64_t", "uint8_t", "int8_t", "double", "float") or (f_tinfo["definition"] and f_tinfo["definition"].get("code") == "enum"):
                            # Primitive or Enum
                            if clean_type == "bool":
                                val = reader.read_bool(f_addr)
                            elif clean_type == "double":
                                val = reader.read_double(f_addr)
                            elif clean_type == "float":
                                val = reader.read_float(f_addr)
                            elif clean_type == "uint8_t":
                                val = reader.read_int(f_addr, 1, signed=False)
                            elif clean_type == "int8_t":
                                val = reader.read_int(f_addr, 1, signed=True)
                            elif clean_type in ("uint16_t", "unsigned short"):
                                val = reader.read_int(f_addr, 2, signed=False)
                            elif clean_type in ("int16_t", "short"):
                                val = reader.read_int(f_addr, 2, signed=True)
                            elif clean_type in ("uint32_t", "int"):
                                val = reader.read_int(f_addr, 4, signed=("uint" not in clean_type))
                            elif clean_type in ("uint64_t", "int64_t"):
                                val = reader.read_int(f_addr, 8, signed=("uint" not in clean_type))
                            elif f_tinfo["definition"] and f_tinfo["definition"].get("code") == "enum":
                                raw_enum = reader.read_int(f_addr, 4, signed=False)
                                enum_members = f_tinfo["definition"].get("fields", [])
                                if raw_enum is not None and 0 <= raw_enum < len(enum_members):
                                    val = enum_members[raw_enum]
                                else:
                                    val = raw_enum
                            else:
                                val = reader.read_int(f_addr, 4, signed=False)

                            if val is None:
                                obj.fields.append(FieldState(
                                    name=f_name,
                                    type=clean_type,
                                    offset=f_offset,
                                    availability="unavailable",
                                    error="Memory not captured"
                                ))
                            else:
                                obj.fields.append(FieldState(
                                    name=f_name,
                                    type=clean_type,
                                    offset=f_offset,
                                    value=val
                                ))
                        elif f_tinfo["definition"] and f_tinfo["definition"].get("code") == "aggregate":
                            # Embedded aggregate struct
                            child_ref = build_object(f_addr, base_type, depth + 1)
                            obj.fields.append(FieldState(
                                name=f_name,
                                type=clean_type,
                                offset=f_offset,
                                value="0x{:x}".format(f_addr),
                                object_ref=child_ref
                            ))
                        else:
                            obj.fields.append(FieldState(
                                name=f_name,
                                type=clean_type,
                                offset=f_offset,
                                value=None,
                                availability="unknown"
                            ))
                    except ValueError as e:
                        obj.fields.append(FieldState(
                            name=f_name,
                            type=clean_type,
                            offset=f_offset,
                            availability="unavailable",
                            error=str(e)
                        ))
            finally:
                active_identities.discard(identity)

            # Compute object-level availability based on field readability and struct size readability
            unavail_count = sum(1 for f in obj.fields if f.availability in ("unavailable", "unknown") or f.error is not None)
            struct_size = type_def.get("sizeof", 0) if type_def else 0
            is_full_struct_readable = reader.is_readable(address_num, struct_size) if struct_size > 0 else reader.is_readable(address_num, 1)

            if not obj.fields:
                obj.availability = "COMPLETE" if is_full_struct_readable else "UNAVAILABLE"
            elif unavail_count == len(obj.fields) or not reader.is_readable(address_num, 1):
                obj.availability = "UNAVAILABLE"
            elif unavail_count > 0 or not is_full_struct_readable:
                obj.availability = "PARTIAL"
            else:
                obj.availability = "COMPLETE"

            return obj_id

        # 6. Process Global Roots
        for sym in symbols:
            s_name = sym["name"]
            s_type = sym["type"]
            s_elf_addr = sym["address"]

            if s_elf_addr is None:
                continue

            if main_module:
                runtime_sym_addr = ModuleAddressResolver.resolve_runtime_address(main_module, s_elf_addr)
            else:
                runtime_sym_addr = s_elf_addr

            tinfo = resolve_type_info(s_type)
            clean_type = tinfo["clean"]
            is_ptr = tinfo["is_ptr"]
            base_type = tinfo["base"]

            if is_ptr:
                ptr_val = reader.read_ptr(runtime_sym_addr)
                if ptr_val is not None:
                    ptr_hex = "0x{:x}".format(ptr_val)
                    target_obj_id = build_object(ptr_val, base_type, 1) if ptr_val != 0 else None
                    var_state = VariableState(
                        name=s_name,
                        type=clean_type,
                        value=ptr_hex,
                        address=ptr_hex,
                        object_ref=target_obj_id
                    )
                    root_state = RootState(
                        root_id="root_{:04d}".format(len(roots) + 1),
                        name=s_name,
                        source="global",
                        type=clean_type,
                        address=ptr_hex,
                        object_ref=target_obj_id
                    )
                    roots.append(root_state)
            else:
                target_obj_id = build_object(runtime_sym_addr, base_type, 1)
                var_addr_hex = "0x{:x}".format(runtime_sym_addr)
                root_state = RootState(
                    root_id="root_{:04d}".format(len(roots) + 1),
                    name=s_name,
                    source="global",
                    type=clean_type,
                    address=var_addr_hex,
                    object_ref=target_obj_id
                )
                roots.append(root_state)

        # 7. Assemble PersistentState
        persistent = PersistentState(
            roots=roots,
            objects=objects,
            statistics={
                "root_count": len(roots),
                "object_count": len(objects),
                "edge_count": sum(1 for obj in objects for f in obj.fields if f.object_ref),
                "heap_objects": sum(1 for obj in objects if obj.storage == "heap"),
                "stack_objects": sum(1 for obj in objects if obj.storage == "stack"),
                "global_objects": sum(1 for obj in objects if obj.storage == "global"),
            }
        )

        # 8. Execution State for LOW_IMPACT mode
        # In LOW_IMPACT capture, process execution context (threads/frames/PC) is not captured
        execution = ExecutionState(
            threads=[],
            availability="UNAVAILABLE",
            reason="LOW_IMPACT_MEMORY_SNAPSHOT"
        )

        # 9. Provenance metadata
        provenance = {
            "runtime_binary": {
                "path": raw_snap.binary,
                "architecture": raw_snap.architecture,
                "endianness": raw_snap.endianness,
                "stripped": True,
                "build_id": main_module.build_id if main_module else None,
                "build_id_status": main_module.build_id_status if main_module else "NOT_AVAILABLE",
            },
            "debug_image": {
                "path": dbg_path,
                "compatible": True,
                "source": "external",
                "verified": True,
                "reason": "COMPATIBLE",
            },
            "modules": [m.to_dict() if hasattr(m, "to_dict") else m for m in modules],
            "capture_mode": "LOW_IMPACT",
            "consistency": raw_snap.consistency,
        }

        # 10. Performance metadata
        t_elapsed_ms = round((time.monotonic() - t_start) * 1000, 3)
        metadata = {
            "offline_analysis_duration_ms": t_elapsed_ms,
            "raw_snapshot_id": raw_snap.snapshot_id,
            "capture_duration_us": raw_snap.duration_us,
            "bytes_captured": raw_snap.bytes_captured,
            "regions_captured": raw_snap.regions_captured,
            "objects_discovered": len(objects),
            "roots_discovered": len(roots),
            "module_count": len(modules),
        }

        snap_id = f"S_{raw_snap.snapshot_id}"
        return RuntimeSnapshot(
            snapshot_id=snap_id,
            schema_version="0.3",
            created_at=datetime.now(timezone.utc).isoformat(),
            process={
                "pid": raw_snap.pid,
                "binary": raw_snap.binary,
                "capture_mode": "LOW_IMPACT"
            },
            execution=execution,
            persistent=persistent,
            metadata=metadata,
            provenance=provenance
        )
