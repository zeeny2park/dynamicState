"""Symbol-path expressions: tokenizing, forgiving coercion, resolution to a target address/type, typed DWARF
decoding of target memory, and the self-repairing diagnostic for expressions that fail to resolve.

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import os
import re
import struct
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..cpp_decoder import CppContainerDecoder
from ..dwarf_indexer import DwarfIndex, DwarfIndexer
from ..target_adapter import TargetExecutionAdapter
from .process_memory import ZERO_STOP_NON_ATOMIC_CONSISTENCY, decode_value_from_bytes


# -------------------------------------------------------------------------
# Phase 32: Deep Symbol Path Expression Evaluator & Instant Diff
# -------------------------------------------------------------------------

def _tokenize_symbol_expression(expr: str) -> List[Tuple[str, Any]]:
    """Tokenizes a C/C++ symbol path expression into traversal operations.
        
        Supported forms:
        - `g_session.worker.state.counter`
        - `g_heap_state->value`
        - `(*g_heap_state).value` or `*g_heap_state`
        - `g_items[2].status` or `g_matrix[1][3]`
        """
    s = (expr or "").strip()
    if not s:
        raise ValueError("Empty symbol expression")

    # Count leading '*' dereferences e.g. `*g_ptr` or `(*g_ptr).field`
    leading_derefs = 0
    while True:
        s_strip = s.strip()
        if s_strip.startswith("(*") and ")" in s_strip:
            close_idx = s_strip.find(")")
            inner = s_strip[2:close_idx].strip()
            rest = s_strip[close_idx + 1:].strip()
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", inner):
                leading_derefs += 1
                s = inner + rest
                continue
        if s_strip.startswith("*"):
            leading_derefs += 1
            s = s_strip[1:].strip()
            continue
        break

    # Support optional shared library module qualifier e.g. `libhelper.so::g_sensor`
    mod_prefix = None
    if "::" in s:
        before_col, after_col = s.split("::", 1)
        if ".so" in before_col or "-" in before_col or "/" in before_col:
            mod_prefix = before_col.strip()
            s = after_col.strip()

    m_root = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)(.*)$", s)
    if not m_root:
        raise ValueError(f"Invalid root symbol in expression: '{expr}'")

    root_name = f"{mod_prefix}::{m_root.group(1)}" if mod_prefix else m_root.group(1)
    rem = m_root.group(2).strip()
    ops: List[Tuple[str, Any]] = [("ROOT", root_name)]
    for _ in range(leading_derefs):
        ops.append(("DEREF", None))

    while rem:
        if rem.startswith("->"):
            rem = rem[2:].strip()
            m_f = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)(.*)$", rem)
            if not m_f:
                raise ValueError(f"Expected member name after '->' in '{expr}'")
            ops.append(("DEREF_MEMBER", m_f.group(1)))
            rem = m_f.group(2).strip()
        elif rem.startswith("."):
            rem = rem[1:].strip()
            m_f = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)(.*)$", rem)
            if not m_f:
                raise ValueError(f"Expected member name after '.' in '{expr}'")
            ops.append(("MEMBER", m_f.group(1)))
            rem = m_f.group(2).strip()
        elif rem.startswith("["):
            m_idx = re.match(r"^\[\s*(\d+|0x[0-9a-fA-F]+)\s*\](.*)$", rem)
            if not m_idx:
                raise ValueError(f"Invalid array index in '{expr}'")
            idx_str = m_idx.group(1)
            idx_val = int(idx_str, 16) if idx_str.startswith("0x") else int(idx_str)
            ops.append(("INDEX", idx_val))
            rem = m_idx.group(2).strip()
        else:
            raise ValueError(f"Unexpected token '{rem}' in expression '{expr}'")

    return ops


def _decode_typed_memory(
    mgr,
    adapter: TargetExecutionAdapter,
    pid: int,
    idx: DwarfIndex,
    addr: int,
    type_offset: Optional[int],
    depth: int = 0,
    max_struct_depth: int = 3,
) -> Tuple[Any, str, Optional[str], str]:
    """Reads and decodes a DWARF type at runtime address `addr` (primitives, enums, arrays, structs)."""
    canon_t = idx.resolve_canonical_type(type_offset)
    t_name = idx.get_type_name(type_offset)
    endian = idx.endianness or "little"
    ptr_size = idx.pointer_size or 8

    if canon_t is None:
        raw, st, err = adapter.read_memory(pid, addr, 4)
        if st != "OBSERVED" or raw is None:
            return None, st, err, ""
        val, dec_err = decode_value_from_bytes(raw, t_name, endian=endian)
        return val, ("OBSERVED" if not dec_err else "DECODE_ERROR"), dec_err, raw.hex()

    byte_size = canon_t.byte_size or (ptr_size if canon_t.tag == "DW_TAG_pointer_type" else 4)
    byte_size = max(1, min(byte_size, 16384))
    raw, st, err = adapter.read_memory(pid, addr, byte_size)
    if st != "OBSERVED" or raw is None:
        return None, st, err, (raw.hex() if raw else "")

    raw_hex = raw.hex()

    # 1. Pointer type
    if canon_t.tag == "DW_TAG_pointer_type":
        fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")
        if len(raw) < ptr_size:
            return None, "PARTIAL", "Insufficient bytes for pointer", raw_hex
        ptr_val = struct.unpack(fmt, raw[:ptr_size])[0]
        return f"0x{ptr_val:x}", "OBSERVED", None, raw_hex

    # 2. Enumeration type
    if canon_t.tag == "DW_TAG_enumeration_type":
        int_type = "int32_t" if byte_size == 4 else ("int16_t" if byte_size == 2 else ("int8_t" if byte_size == 1 else "int64_t"))
        val, dec_err = decode_value_from_bytes(raw, int_type, endian=endian)
        if dec_err is not None:
            return None, "DECODE_ERROR", dec_err, raw_hex
        enum_label = canon_t.enum_values.get(val)
        if enum_label:
            return f"{enum_label} ({val})", "OBSERVED", None, raw_hex
        return val, "OBSERVED", None, raw_hex

    # 3. Array type
    if canon_t.tag == "DW_TAG_array_type":
        elem_t = idx.resolve_canonical_type(canon_t.target_type_offset)
        elem_name = idx.get_type_name(canon_t.target_type_offset).lower()
        if elem_name in ("char", "signed char", "unsigned char", "const char"):
            s_val = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            return s_val, "OBSERVED", None, raw_hex
        if elem_t and elem_t.byte_size and canon_t.array_count:
            arr_vals = []
            esize = elem_t.byte_size
            for i in range(min(canon_t.array_count, 16)):
                slice_bytes = raw[i * esize:(i + 1) * esize]
                if len(slice_bytes) < esize:
                    break
                v, _ = decode_value_from_bytes(slice_bytes, elem_t.name or elem_name, endian=endian)
                arr_vals.append(v)
            return arr_vals, "OBSERVED", None, raw_hex
        return raw_hex, "OBSERVED", None, raw_hex

    # 3.5 Phase 5: C++ STL Container Pretty-Decoding via Unified CppContainerDecoder
    stl_info = idx.classify_stl_type(type_offset)
    if stl_info is not None:
        def _live_read_fn(a: int, sz: int) -> Tuple[Optional[bytes], str]:
            r_bytes, r_st, _ = adapter.read_memory(pid, a, sz)
            return r_bytes, r_st

        def _live_elem_decoder(e_addr: int, e_type_off: Optional[int], e_depth: int) -> Any:
            e_val, e_st, e_err, _ = mgr._decode_typed_memory(
                adapter, pid, idx, e_addr, e_type_off, depth=e_depth, max_struct_depth=max_struct_depth
            )
            if e_st not in ("OBSERVED", "COMPLETE"):
                return {
                    "value": e_val,
                    "status": e_st,
                    "error": e_err,
                }
            return e_val

        c_data = CppContainerDecoder.decode_container(
            read_fn=_live_read_fn,
            address=addr,
            type_offset=type_offset,
            dwarf_index=idx,
            depth=depth,
            max_depth=max_struct_depth,
            decode_elem_fn=_live_elem_decoder,
        )
        if c_data:
            c_status = c_data.get("status", "COMPLETE")
            c_err = c_data.get("error")
            if c_status != "COMPLETE":
                return c_data.get("value"), c_status, c_err, raw_hex

            if c_data.get("container") == "std::string":
                return c_data.get("value"), "OBSERVED", None, raw_hex
            return c_data, "OBSERVED", None, raw_hex

    # 4. Structure / Class / Union type
    if canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
        if depth >= max_struct_depth or not canon_t.members:
            return f"<{t_name} @ 0x{addr:x}>", "OBSERVED", None, raw_hex
        fields_dict: Dict[str, Any] = {}
        struct_status = "OBSERVED"
        struct_err = None
        for mem in canon_t.members:
            if not mem.name:
                continue
            m_canon = idx.resolve_canonical_type(mem.type_offset)
            m_tname = idx.get_type_name(mem.type_offset)
            m_off = mem.offset
            m_size = mem.byte_size or (m_canon.byte_size if m_canon and m_canon.byte_size else (ptr_size if m_canon and m_canon.tag == "DW_TAG_pointer_type" else 4))
            if m_off + m_size <= len(raw):
                m_slice = raw[m_off:m_off + m_size]
                if m_canon and (m_canon.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") or idx.classify_stl_type(mem.type_offset) is not None) and depth + 1 < max_struct_depth:
                    sub_val, sub_st, sub_err, _ = mgr._decode_typed_memory(
                        adapter, pid, idx, addr + m_off, mem.type_offset, depth=depth + 1, max_struct_depth=max_struct_depth
                    )
                    fields_dict[mem.name] = sub_val
                    if sub_st not in ("OBSERVED", "COMPLETE"):
                        struct_status = "PARTIAL"
                        if not struct_err:
                            struct_err = f"Member '{mem.name}' decode status: {sub_st} ({sub_err})"
                elif m_canon and m_canon.tag == "DW_TAG_enumeration_type":
                    int_t = "int32_t" if m_size == 4 else ("int16_t" if m_size == 2 else ("int8_t" if m_size == 1 else "int64_t"))
                    ev_int, _ = decode_value_from_bytes(m_slice, int_t, endian=endian)
                    ev_lbl = m_canon.enum_values.get(ev_int)
                    fields_dict[mem.name] = f"{ev_lbl} ({ev_int})" if ev_lbl else ev_int
                elif m_canon and m_canon.tag == "DW_TAG_pointer_type":
                    fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")
                    if len(m_slice) >= ptr_size:
                        pval = struct.unpack(fmt, m_slice[:ptr_size])[0]
                        fields_dict[mem.name] = f"0x{pval:x}"
                elif m_canon and m_canon.tag == "DW_TAG_array_type":
                    elem_n = idx.get_type_name(m_canon.target_type_offset).lower()
                    if elem_n in ("char", "signed char", "unsigned char"):
                        fields_dict[mem.name] = m_slice.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    else:
                        fields_dict[mem.name] = m_slice.hex()
                else:
                    v, _ = decode_value_from_bytes(m_slice, m_canon.name if m_canon and m_canon.name else m_tname, endian=endian)
                    fields_dict[mem.name] = v
            else:
                struct_status = "PARTIAL"
                if not struct_err:
                    struct_err = f"Member '{mem.name}' memory truncated or not captured"
        return fields_dict, struct_status, struct_err, raw_hex

    # 5. Base / primitive type
    val, dec_err = decode_value_from_bytes(raw, canon_t.name or t_name, endian=endian)
    return val, ("OBSERVED" if not dec_err else "DECODE_ERROR"), dec_err, raw_hex


def evaluate_symbol_paths(
    mgr,
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    expressions: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    ssh_proxy_command: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
    max_pointer_depth: int = 8,
) -> Dict[str, Any]:
    """Evaluates high-level C/C++ symbol path expressions (including pointer dereferences and arrays)
        directly against live local or remote embedded target memory without suspending the process (zero-stop).
        Automatically inherits/heals `(pid, companion_elf_path)` from active context and auto-coerces
        forgiving C/C++ expressions (`.` <-> `->`, bare member names, and symbol typos).
        """
    ctx_info = mgr.resolve_target_context(
        pid=pid,
        companion_elf_path=companion_elf_path,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    pid = ctx_info["pid"]
    companion_elf_path = ctx_info["companion_elf_path"]
    expressions = mgr._coerce_str_list(expressions)

    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=ctx_info.get("remote_host"),
        ssh_user=ctx_info.get("ssh_user"),
        ssh_port=ctx_info.get("ssh_port", 22),
        ssh_key=ctx_info.get("ssh_key"),
        ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
        ssh_proxy_command=ssh_proxy_command,
        adapter=adapter,
    )

    primary_elf, extra_so_elfs = mgr._split_companion_elf_paths(companion_elf_path)
    if not primary_elf:
        raise ValueError("At least one valid companion ELF path is required")

    map_data = mgr._get_process_maps_and_load_bias(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    load_bias = map_data.get("base_address_int", 0)
    primary_idx = DwarfIndexer.get_index(primary_elf)

    # Build module contexts: [(mod_name, DwarfIndex, mod_load_bias, is_dyn)]
    module_contexts: List[Tuple[str, DwarfIndex, int, bool]] = [
        (os.path.basename(primary_elf), primary_idx, load_bias, (primary_idx.elf_type == "ET_DYN"))
    ]
    for mod_info in map_data.get("loaded_debug_modules", []):
        if not mod_info.get("is_main_executable") and mod_info.get("debug_image"):
            try:
                so_idx = DwarfIndexer.get_index(mod_info["debug_image"])
                module_contexts.append((
                    mod_info.get("module") or os.path.basename(mod_info["debug_image"]),
                    so_idx,
                    int(mod_info.get("load_bias_int", 0)),
                    (so_idx.elf_type == "ET_DYN"),
                ))
            except Exception:
                pass

    evaluated: List[Dict[str, Any]] = []
    t_start_ns = time.monotonic_ns()

    coercions_applied: List[Dict[str, Any]] = []
    for expr in expressions:
        expr_str = (expr or "").strip()
        if not expr_str:
            continue
        try:
            coerced_meta = mgr.coerce_and_resolve_expression(
                idx=primary_idx,
                raw_expr=expr_str,
                module_contexts=module_contexts,
            )
            effective_expr = coerced_meta["resolved_expression"]
            if coerced_meta["was_coerced"]:
                coercions_applied.append(coerced_meta)
            ops = coerced_meta.get("ops") or mgr._tokenize_symbol_expression(effective_expr)
            raw_root = ops[0][1]
            mod_filter = None
            root_name = raw_root
            if "::" in raw_root:
                mod_filter, root_name = raw_root.split("::", 1)

            matched_ctx = None
            root_var = None
            for mod_name, m_idx, m_bias, m_dyn in module_contexts:
                if mod_filter and mod_filter not in mod_name and os.path.basename(mod_filter) not in mod_name:
                    continue
                cands = [
                    v for v in m_idx.variables_by_name.get(root_name, [])
                    if v.link_time_address is not None and not v.is_declaration
                ]
                if cands:
                    matched_ctx = (mod_name, m_idx, m_bias, m_dyn)
                    root_var = cands[0]
                    break

            if not root_var or not matched_ctx:
                repair_diag = mgr.build_self_repairing_diagnostic(
                    error_status="SYMBOL_NOT_FOUND",
                    expression=expr_str,
                    raw_root=raw_root,
                    module_contexts=module_contexts,
                )
                evaluated.append({
                    "expression": expr_str,
                    "status": "SYMBOL_NOT_FOUND",
                    "error": f"Root variable '{raw_root}' not found in DWARF symbols across loaded modules",
                    "value": None,
                    "self_repair": repair_diag,
                })
                continue

            active_mod_name, idx, active_bias, is_dyn = matched_ctx
            ptr_size = idx.pointer_size or 8
            endian = idx.endianness or "little"
            ptr_fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")

            curr_addr = (active_bias + root_var.link_time_address) if is_dyn else root_var.link_time_address
            curr_type_off = root_var.type_offset
            pointer_chain: List[Dict[str, Any]] = [{
                "step": root_name,
                "address": f"0x{curr_addr:x}",
                "type_name": idx.get_type_name(curr_type_off),
            }]
            hop_count = 0
            abort_item = None

            for op_kind, op_arg in ops[1:]:
                canon_t = idx.resolve_canonical_type(curr_type_off)
                if canon_t is None:
                    abort_item = {
                        "expression": expr_str,
                        "status": "TYPE_RESOLUTION_ERROR",
                        "error": f"Cannot resolve DWARF type at address 0x{curr_addr:x}",
                        "pointer_chain": pointer_chain,
                        "value": None,
                    }
                    break

                if op_kind in ("DEREF", "DEREF_MEMBER"):
                    stl_curr = idx.classify_stl_type(curr_type_off)
                    is_smart_ptr = bool(stl_curr and stl_curr["stl_kind"] in ("std::unique_ptr", "std::shared_ptr", "std::weak_ptr"))
                    if canon_t.tag != "DW_TAG_pointer_type" and not is_smart_ptr:
                        abort_item = {
                            "expression": expr_str,
                            "status": "NOT_A_POINTER",
                            "error": f"Cannot dereference non-pointer type '{idx.get_type_name(curr_type_off)}'",
                            "pointer_chain": pointer_chain,
                            "value": None,
                        }
                        break
                    hop_count += 1
                    if hop_count > max_pointer_depth:
                        abort_item = {
                            "expression": expr_str,
                            "status": "MAX_POINTER_DEPTH_EXCEEDED",
                            "error": f"Pointer dereference depth exceeded limit ({max_pointer_depth})",
                            "pointer_chain": pointer_chain,
                            "value": None,
                        }
                        break

                    raw_ptr, p_st, p_err = target_adapter.read_memory(pid, curr_addr, ptr_size)
                    if p_st != "OBSERVED" or raw_ptr is None or len(raw_ptr) < ptr_size:
                        abort_item = {
                            "expression": expr_str,
                            "status": p_st if p_st != "OBSERVED" else "UNAVAILABLE",
                            "error": p_err or f"Failed reading pointer at 0x{curr_addr:x}",
                            "pointer_chain": pointer_chain,
                            "value": None,
                        }
                        break

                    target_addr = struct.unpack(ptr_fmt, raw_ptr[:ptr_size])[0]
                    if target_addr == 0:
                        repair_diag = mgr.build_self_repairing_diagnostic(
                            error_status="NULL_POINTER",
                            expression=expr_str,
                            raw_root=raw_root,
                            module_contexts=module_contexts,
                            pointer_chain=pointer_chain,
                            target_type_offset=canon_t.target_type_offset,
                            idx=idx,
                        )
                        abort_item = {
                            "expression": expr_str,
                            "status": "NULL_POINTER",
                            "error": f"Pointer at 0x{curr_addr:x} is NULL (0x0)",
                            "pointer_chain": pointer_chain,
                            "value": None,
                            "self_repair": repair_diag,
                        }
                        break

                    curr_addr = target_addr
                    curr_type_off = stl_curr["element_type_offset"] if is_smart_ptr else canon_t.target_type_offset
                    pointer_chain.append({
                        "step": f"*{pointer_chain[-1]['step']}",
                        "address": f"0x{curr_addr:x}",
                        "type_name": idx.get_type_name(curr_type_off),
                    })

                    if op_kind == "DEREF":
                        continue
                    # Fall through to member lookup on dereferenced struct
                    canon_t = idx.resolve_canonical_type(curr_type_off)

                if op_kind in ("MEMBER", "DEREF_MEMBER"):
                    member_name = op_arg
                    if not canon_t or canon_t.tag not in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                        abort_item = {
                            "expression": expr_str,
                            "status": "NOT_A_STRUCT",
                            "error": f"Type '{idx.get_type_name(curr_type_off)}' has no member '{member_name}'",
                            "pointer_chain": pointer_chain,
                            "value": None,
                        }
                        break
                    matched_mem = next((m for m in canon_t.members if m.name == member_name), None)
                    if matched_mem is None:
                        avail = [m.name for m in canon_t.members if m.name]
                        repair_diag = mgr.build_self_repairing_diagnostic(
                            error_status="MEMBER_NOT_FOUND",
                            expression=expr_str,
                            raw_root=raw_root,
                            module_contexts=module_contexts,
                            pointer_chain=pointer_chain,
                            struct_type=canon_t,
                            missing_member=member_name,
                            idx=idx,
                        )
                        abort_item = {
                            "expression": expr_str,
                            "status": "MEMBER_NOT_FOUND",
                            "error": f"Member '{member_name}' not found in '{canon_t.name}'. Available: {avail}",
                            "pointer_chain": pointer_chain,
                            "value": None,
                            "self_repair": repair_diag,
                        }
                        break
                    curr_addr = curr_addr + matched_mem.offset
                    curr_type_off = matched_mem.type_offset
                    pointer_chain.append({
                        "step": f".{member_name}",
                        "address": f"0x{curr_addr:x}",
                        "type_name": idx.get_type_name(curr_type_off),
                    })

                elif op_kind == "INDEX":
                    arr_idx = int(op_arg)
                    if not canon_t:
                        abort_item = {
                            "expression": expr_str,
                            "status": "TYPE_RESOLUTION_ERROR",
                            "error": f"Cannot index unknown type in '{expr_str}'",
                            "pointer_chain": pointer_chain,
                            "value": None,
                        }
                        break
                    stl_curr = idx.classify_stl_type(curr_type_off)
                    if stl_curr and stl_curr["stl_kind"] == "std::vector":
                        hop_count += 1
                        raw_vec, v_st, v_err = target_adapter.read_memory(pid, curr_addr, 2 * ptr_size)
                        if v_st != "OBSERVED" or not raw_vec or len(raw_vec) < 2 * ptr_size:
                            abort_item = {
                                "expression": expr_str,
                                "status": v_st if v_st != "OBSERVED" else "UNAVAILABLE",
                                "error": v_err or f"Failed reading std::vector header at 0x{curr_addr:x}",
                                "pointer_chain": pointer_chain,
                                "value": None,
                            }
                            break
                        start_ptr = struct.unpack(ptr_fmt, raw_vec[:ptr_size])[0]
                        finish_ptr = struct.unpack(ptr_fmt, raw_vec[ptr_size:2 * ptr_size])[0]
                        elem_sz = max(1, int(stl_curr.get("element_size") or 4))
                        vec_len = int((finish_ptr - start_ptr) // elem_sz) if (finish_ptr >= start_ptr and start_ptr > 0) else 0
                        if start_ptr == 0 or arr_idx < 0 or arr_idx >= vec_len:
                            abort_item = {
                                "expression": expr_str,
                                "status": "OUT_OF_BOUNDS",
                                "error": f"Index {arr_idx} out of bounds for std::vector (size={vec_len})",
                                "pointer_chain": pointer_chain,
                                "value": None,
                            }
                            break
                        curr_addr = start_ptr + (arr_idx * elem_sz)
                        curr_type_off = stl_curr.get("element_type_offset")
                    elif canon_t.tag == "DW_TAG_pointer_type":
                        hop_count += 1
                        raw_ptr, p_st, p_err = target_adapter.read_memory(pid, curr_addr, ptr_size)
                        if p_st != "OBSERVED" or not raw_ptr or len(raw_ptr) < ptr_size:
                            abort_item = {
                                "expression": expr_str,
                                "status": p_st if p_st != "OBSERVED" else "UNAVAILABLE",
                                "error": p_err or f"Failed reading array pointer at 0x{curr_addr:x}",
                                "pointer_chain": pointer_chain,
                                "value": None,
                            }
                            break
                        base_ptr = struct.unpack(ptr_fmt, raw_ptr[:ptr_size])[0]
                        if base_ptr == 0:
                            abort_item = {
                                "expression": expr_str,
                                "status": "NULL_POINTER",
                                "error": f"Array pointer at 0x{curr_addr:x} is NULL (0x0)",
                                "pointer_chain": pointer_chain,
                                "value": None,
                            }
                            break
                        elem_off = canon_t.target_type_offset
                        elem_canon = idx.resolve_canonical_type(elem_off)
                        pivoted = False
                        if elem_canon and elem_canon.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and elem_canon.members:
                            pool_arr_mem = mgr._find_primary_pool_array_member(idx, elem_canon)
                            if pool_arr_mem is not None:
                                mem_canon = idx.resolve_canonical_type(pool_arr_mem.type_offset)
                                mem_addr = base_ptr + pool_arr_mem.offset
                                if mem_canon and mem_canon.tag == "DW_TAG_array_type":
                                    e_off = mem_canon.target_type_offset
                                    e_can = idx.resolve_canonical_type(e_off)
                                    esz = e_can.byte_size if (e_can and e_can.byte_size) else 1
                                    curr_addr = mem_addr + (arr_idx * esz)
                                    curr_type_off = e_off
                                    pivoted = True
                                    pointer_chain.append({
                                        "step": f"->{pool_arr_mem.name}",
                                        "address": f"0x{mem_addr:x}",
                                        "type_name": idx.get_type_name(pool_arr_mem.type_offset),
                                    })
                        if not pivoted:
                            elem_sz = elem_canon.byte_size if (elem_canon and elem_canon.byte_size) else 4
                            curr_addr = base_ptr + (arr_idx * elem_sz)
                            curr_type_off = elem_off
                    elif canon_t.tag == "DW_TAG_array_type":
                        elem_off = canon_t.target_type_offset
                        elem_canon = idx.resolve_canonical_type(elem_off)
                        elem_sz = elem_canon.byte_size if (elem_canon and elem_canon.byte_size) else 1
                        curr_addr = curr_addr + (arr_idx * elem_sz)
                        curr_type_off = elem_off
                    else:
                        abort_item = {
                            "expression": expr_str,
                            "status": "NOT_INDEXABLE",
                            "error": f"Type '{idx.get_type_name(curr_type_off)}' does not support indexing",
                            "pointer_chain": pointer_chain,
                            "value": None,
                        }
                        break
                    pointer_chain.append({
                        "step": f"[{arr_idx}]",
                        "address": f"0x{curr_addr:x}",
                        "type_name": idx.get_type_name(curr_type_off),
                    })

            if abort_item is not None:
                evaluated.append(abort_item)
                continue

            final_canon = idx.resolve_canonical_type(curr_type_off)
            final_size = final_canon.byte_size if (final_canon and final_canon.byte_size) else (ptr_size if final_canon and final_canon.tag == "DW_TAG_pointer_type" else 4)
            val, st, err, raw_hex = mgr._decode_typed_memory(
                target_adapter, pid, idx, curr_addr, curr_type_off
            )
            evaluated.append({
                "expression": expr_str,
                "resolved_expression": effective_expr,
                "was_coerced": coerced_meta["was_coerced"],
                "coercion_reasons": coerced_meta["coercion_reasons"],
                "status": st,
                "error": err,
                "runtime_address": f"0x{curr_addr:x}",
                "runtime_address_int": curr_addr,
                "type_offset": curr_type_off,
                "type_name": idx.get_type_name(curr_type_off),
                "size": final_size,
                "value": val,
                "raw_hex": raw_hex,
                "module": active_mod_name,
                "pointer_chain": pointer_chain,
                "source_location": f"{root_var.decl_file}:{root_var.decl_line}" if root_var.decl_file else None,
            })
        except Exception as exc:
            evaluated.append({
                "expression": expr_str,
                "status": "EVALUATION_ERROR",
                "error": str(exc),
                "value": None,
            })

    elapsed_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "companion_elf": companion_elf_path,
        "auto_healed_pid": ctx_info.get("auto_healed_pid", False),
        "previous_pid": ctx_info.get("previous_pid"),
        "elf_auto_discovered": ctx_info.get("elf_auto_discovered", False),
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "load_bias": f"0x{load_bias:x}",
        "stop_duration_ms": 0.0,
        "capture_latency_us": elapsed_us,
        "consistency": dict(ZERO_STOP_NON_ATOMIC_CONSISTENCY),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "coercions_count": len(coercions_applied),
        "coercions": coercions_applied,
        "results": evaluated,
        "evaluated": evaluated,
    }


# -------------------------------------------------------------------------
# Phase 38 (Phase 8): LLM-Centric Memory Pool Scanner, Thread Ownership
# Reverse-Lookup, and Process X-Ray Blueprint
# -------------------------------------------------------------------------

def _resolve_expression_to_target(
    mgr,
    pid: int,
    companion_elf_path: str,
    expression: str,
    adapter: TargetExecutionAdapter,
    max_pointer_depth: int = 8,
) -> Dict[str, Any]:
    """Resolves a C/C++ symbol path expression to its runtime address, DWARF type offset,
        DwarfIndex, module name, and pointer chain without truncating large arrays."""
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    if not primary_elf:
        raise ValueError("At least one valid companion ELF path is required")

    map_data = mgr._get_process_maps_and_load_bias(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=adapter,
    )
    load_bias = map_data.get("base_address_int", 0)
    primary_idx = DwarfIndexer.get_index(primary_elf)

    module_contexts: List[Tuple[str, DwarfIndex, int, bool]] = [
        (os.path.basename(primary_elf), primary_idx, load_bias, (primary_idx.elf_type == "ET_DYN"))
    ]
    for mod_info in map_data.get("loaded_debug_modules", []):
        if not mod_info.get("is_main_executable") and mod_info.get("debug_image"):
            try:
                so_idx = DwarfIndexer.get_index(mod_info["debug_image"])
                module_contexts.append((
                    mod_info.get("module") or os.path.basename(mod_info["debug_image"]),
                    so_idx,
                    int(mod_info.get("load_bias_int", 0)),
                    (so_idx.elf_type == "ET_DYN"),
                ))
            except Exception:
                pass

    coerced_meta = mgr.coerce_and_resolve_expression(
        idx=primary_idx,
        raw_expr=expression,
        module_contexts=module_contexts,
    )
    effective_expression = coerced_meta["resolved_expression"]
    ops = coerced_meta.get("ops") or mgr._tokenize_symbol_expression(effective_expression)
    raw_root = ops[0][1]
    mod_filter = None
    root_name = raw_root
    if "::" in raw_root:
        mod_filter, root_name = raw_root.split("::", 1)

    matched_ctx = None
    root_var = None
    for mod_name, m_idx, m_bias, m_dyn in module_contexts:
        if mod_filter and mod_filter not in mod_name and os.path.basename(mod_filter) not in mod_name:
            continue
        cands = [
            v for v in m_idx.variables_by_name.get(root_name, [])
            if v.link_time_address is not None and not v.is_declaration
        ]
        if cands:
            matched_ctx = (mod_name, m_idx, m_bias, m_dyn)
            root_var = cands[0]
            break

    if not root_var or not matched_ctx:
        raise ValueError(f"Root variable '{raw_root}' not found in DWARF symbols across loaded modules")

    active_mod_name, idx, active_bias, is_dyn = matched_ctx
    ptr_size = idx.pointer_size or 8
    endian = idx.endianness or "little"
    ptr_fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")

    curr_addr = (active_bias + root_var.link_time_address) if is_dyn else root_var.link_time_address
    curr_type_off = root_var.type_offset
    pointer_chain: List[Dict[str, Any]] = [{
        "step": root_name,
        "address": f"0x{curr_addr:x}",
        "type_name": idx.get_type_name(curr_type_off),
    }]
    hop_count = 0

    for op_kind, op_arg in ops[1:]:
        canon_t = idx.resolve_canonical_type(curr_type_off)
        if canon_t is None:
            raise ValueError(f"Cannot resolve DWARF type at address 0x{curr_addr:x}")

        if op_kind in ("DEREF", "DEREF_MEMBER"):
            stl_curr = idx.classify_stl_type(curr_type_off)
            is_smart_ptr = bool(stl_curr and stl_curr["stl_kind"] in ("std::unique_ptr", "std::shared_ptr", "std::weak_ptr"))
            if canon_t.tag != "DW_TAG_pointer_type" and not is_smart_ptr:
                raise ValueError(f"Cannot dereference non-pointer type '{idx.get_type_name(curr_type_off)}'")
            hop_count += 1
            if hop_count > max_pointer_depth:
                raise ValueError(f"Pointer dereference depth exceeded limit ({max_pointer_depth})")
            raw_ptr, p_st, p_err = adapter.read_memory(pid, curr_addr, ptr_size)
            if p_st != "OBSERVED" or raw_ptr is None or len(raw_ptr) < ptr_size:
                raise RuntimeError(p_err or f"Failed reading pointer at 0x{curr_addr:x}")
            target_addr = struct.unpack(ptr_fmt, raw_ptr[:ptr_size])[0]
            if target_addr == 0:
                raise ValueError(f"Pointer at 0x{curr_addr:x} is NULL (0x0)")
            curr_addr = target_addr
            curr_type_off = stl_curr["element_type_offset"] if is_smart_ptr else canon_t.target_type_offset
            pointer_chain.append({
                "step": f"*{pointer_chain[-1]['step']}",
                "address": f"0x{curr_addr:x}",
                "type_name": idx.get_type_name(curr_type_off),
            })
            if op_kind == "DEREF":
                continue
            canon_t = idx.resolve_canonical_type(curr_type_off)

        if op_kind in ("MEMBER", "DEREF_MEMBER"):
            member_name = op_arg
            if not canon_t or canon_t.tag not in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                raise ValueError(f"Type '{idx.get_type_name(curr_type_off)}' has no member '{member_name}'")
            matched_mem = next((m for m in canon_t.members if m.name == member_name), None)
            if matched_mem is None:
                avail = [m.name for m in canon_t.members if m.name]
                raise ValueError(f"Member '{member_name}' not found in '{canon_t.name}'. Available: {avail}")
            curr_addr = curr_addr + matched_mem.offset
            curr_type_off = matched_mem.type_offset
            pointer_chain.append({
                "step": f".{member_name}",
                "address": f"0x{curr_addr:x}",
                "type_name": idx.get_type_name(curr_type_off),
            })

        elif op_kind == "INDEX":
            arr_idx = int(op_arg)
            stl_curr = idx.classify_stl_type(curr_type_off)
            if stl_curr and stl_curr["stl_kind"] == "std::vector":
                raw_vec, v_st, v_err = adapter.read_memory(pid, curr_addr, 2 * ptr_size)
                if v_st != "OBSERVED" or not raw_vec or len(raw_vec) < 2 * ptr_size:
                    raise RuntimeError(v_err or f"Failed reading std::vector header at 0x{curr_addr:x}")
                start_ptr = struct.unpack(ptr_fmt, raw_vec[:ptr_size])[0]
                finish_ptr = struct.unpack(ptr_fmt, raw_vec[ptr_size:2 * ptr_size])[0]
                elem_sz = max(1, int(stl_curr.get("element_size") or 4))
                vec_len = int((finish_ptr - start_ptr) // elem_sz) if (finish_ptr >= start_ptr and start_ptr > 0) else 0
                if start_ptr == 0 or arr_idx < 0 or arr_idx >= vec_len:
                    raise IndexError(f"Index {arr_idx} out of bounds for std::vector (size={vec_len})")
                curr_addr = start_ptr + (arr_idx * elem_sz)
                curr_type_off = stl_curr.get("element_type_offset")
            elif canon_t.tag == "DW_TAG_pointer_type":
                raw_ptr, p_st, p_err = adapter.read_memory(pid, curr_addr, ptr_size)
                if p_st != "OBSERVED" or not raw_ptr or len(raw_ptr) < ptr_size:
                    raise RuntimeError(p_err or f"Failed reading pointer at 0x{curr_addr:x}")
                base_ptr = struct.unpack(ptr_fmt, raw_ptr[:ptr_size])[0]
                if base_ptr == 0:
                    raise ValueError(f"Pointer at 0x{curr_addr:x} is NULL (0x0)")
                elem_off = canon_t.target_type_offset
                elem_canon = idx.resolve_canonical_type(elem_off)
                # Smart container-struct shorthand: if `gpMem` is `MemPool*` (a pool container struct
                # with a primary `buffers`/`slots`/`items` array/pointer member) and the user wrote
                # `gpMem[9]` meaning `gpMem->buffers[9]`, automatically pivot to the inner buffer array!
                pivoted = False
                if elem_canon and elem_canon.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and elem_canon.members:
                    pool_arr_mem = mgr._find_primary_pool_array_member(idx, elem_canon)
                    if pool_arr_mem is not None:
                        mem_canon = idx.resolve_canonical_type(pool_arr_mem.type_offset)
                        mem_stl = idx.classify_stl_type(pool_arr_mem.type_offset)
                        mem_addr = base_ptr + pool_arr_mem.offset
                        if mem_stl and mem_stl["stl_kind"] == "std::vector":
                            rv, vst, _ = adapter.read_memory(pid, mem_addr, 2 * ptr_size)
                            if vst == "OBSERVED" and rv and len(rv) >= 2 * ptr_size:
                                sp = struct.unpack(ptr_fmt, rv[:ptr_size])[0]
                                esz = max(1, int(mem_stl.get("element_size") or 4))
                                curr_addr = sp + (arr_idx * esz)
                                curr_type_off = mem_stl.get("element_type_offset")
                                pivoted = True
                        elif mem_canon and mem_canon.tag == "DW_TAG_array_type":
                            e_off = mem_canon.target_type_offset
                            e_can = idx.resolve_canonical_type(e_off)
                            esz = e_can.byte_size if (e_can and e_can.byte_size) else 1
                            curr_addr = mem_addr + (arr_idx * esz)
                            curr_type_off = e_off
                            pivoted = True
                        elif mem_canon and mem_canon.tag == "DW_TAG_pointer_type":
                            rp2, pst2, _ = adapter.read_memory(pid, mem_addr, ptr_size)
                            if pst2 == "OBSERVED" and rp2 and len(rp2) >= ptr_size:
                                bp2 = struct.unpack(ptr_fmt, rp2[:ptr_size])[0]
                                if bp2 > 0:
                                    e_off = mem_canon.target_type_offset
                                    e_can = idx.resolve_canonical_type(e_off)
                                    esz = e_can.byte_size if (e_can and e_can.byte_size) else 4
                                    curr_addr = bp2 + (arr_idx * esz)
                                    curr_type_off = e_off
                                    pivoted = True
                        if pivoted:
                            pointer_chain.append({
                                "step": f"->{pool_arr_mem.name}",
                                "address": f"0x{mem_addr:x}",
                                "type_name": idx.get_type_name(pool_arr_mem.type_offset),
                            })
                if not pivoted:
                    elem_sz = elem_canon.byte_size if (elem_canon and elem_canon.byte_size) else 4
                    curr_addr = base_ptr + (arr_idx * elem_sz)
                    curr_type_off = elem_off
            elif canon_t.tag == "DW_TAG_array_type":
                elem_off = canon_t.target_type_offset
                elem_canon = idx.resolve_canonical_type(elem_off)
                elem_sz = elem_canon.byte_size if (elem_canon and elem_canon.byte_size) else 1
                curr_addr = curr_addr + (arr_idx * elem_sz)
                curr_type_off = elem_off
            elif canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and canon_t.members:
                # Support indexing a pool struct directly e.g. `(*gpMem)[9]` or `g_pool[9]`
                pool_arr_mem = mgr._find_primary_pool_array_member(idx, canon_t)
                if pool_arr_mem is None:
                    raise ValueError(f"Struct '{canon_t.name}' has no indexable buffer/array member")
                mem_canon = idx.resolve_canonical_type(pool_arr_mem.type_offset)
                mem_addr = curr_addr + pool_arr_mem.offset
                if mem_canon and mem_canon.tag == "DW_TAG_array_type":
                    e_off = mem_canon.target_type_offset
                    e_can = idx.resolve_canonical_type(e_off)
                    esz = e_can.byte_size if (e_can and e_can.byte_size) else 1
                    curr_addr = mem_addr + (arr_idx * esz)
                    curr_type_off = e_off
                elif mem_canon and mem_canon.tag == "DW_TAG_pointer_type":
                    rp2, pst2, _ = adapter.read_memory(pid, mem_addr, ptr_size)
                    if pst2 != "OBSERVED" or not rp2 or len(rp2) < ptr_size:
                        raise RuntimeError(f"Failed reading buffer pointer '{pool_arr_mem.name}' at 0x{mem_addr:x}")
                    bp2 = struct.unpack(ptr_fmt, rp2[:ptr_size])[0]
                    if bp2 == 0:
                        raise ValueError(f"Buffer pointer '{pool_arr_mem.name}' is NULL (0x0)")
                    e_off = mem_canon.target_type_offset
                    e_can = idx.resolve_canonical_type(e_off)
                    esz = e_can.byte_size if (e_can and e_can.byte_size) else 4
                    curr_addr = bp2 + (arr_idx * esz)
                    curr_type_off = e_off
                else:
                    raise ValueError(f"Type '{idx.get_type_name(curr_type_off)}' does not support indexing")
            else:
                raise ValueError(f"Type '{idx.get_type_name(curr_type_off)}' does not support indexing")

            pointer_chain.append({
                "step": f"[{arr_idx}]",
                "address": f"0x{curr_addr:x}",
                "type_name": idx.get_type_name(curr_type_off),
            })

    return {
        "address": curr_addr,
        "type_offset": curr_type_off,
        "canonical_type": idx.resolve_canonical_type(curr_type_off),
        "type_name": idx.get_type_name(curr_type_off),
        "idx": idx,
        "module_name": active_mod_name,
        "load_bias": active_bias,
        "is_dyn": is_dyn,
        "module_contexts": module_contexts,
        "pointer_chain": pointer_chain,
        "root_var": root_var,
        "mappings": map_data.get("mappings", []),
        "coerced_meta": coerced_meta,
        "resolved_expression": effective_expression,
    }


def _find_primary_pool_array_member(idx: DwarfIndex, struct_t: Any) -> Optional[Any]:
    """Finds the primary buffer/slot array, vector, or pointer member inside a pool/manager struct."""
    if not struct_t or not getattr(struct_t, "members", None):
        return None
    pool_member_keywords = (
        "buffers", "buffer", "slots", "slot", "items", "item", "blocks", "block",
        "entries", "entry", "nodes", "node", "elements", "pool", "chunks", "pages", "packets"
    )
    candidates = []
    for mem in struct_t.members:
        if not mem.name:
            continue
        m_canon = idx.resolve_canonical_type(mem.type_offset)
        m_stl = idx.classify_stl_type(mem.type_offset)
        m_low = mem.name.lower()
        kw_score = 100 if m_low in pool_member_keywords else (50 if any(k in m_low for k in pool_member_keywords) else 0)
        if m_stl and m_stl["stl_kind"] == "std::vector":
            candidates.append((kw_score + 40, mem))
        elif m_canon and m_canon.tag == "DW_TAG_array_type":
            elem_name = idx.get_type_name(m_canon.target_type_offset).lower()
            # Skip plain char[] name/label buffers unless it's the only array and named buffer
            if elem_name in ("char", "const char") and kw_score == 0:
                continue
            elem_c = idx.resolve_canonical_type(m_canon.target_type_offset)
            is_struct_elem = 30 if (elem_c and elem_c.tag in ("DW_TAG_structure_type", "DW_TAG_class_type")) else 0
            candidates.append((kw_score + 30 + is_struct_elem + min(20, m_canon.array_count or 0), mem))
        elif m_canon and m_canon.tag == "DW_TAG_pointer_type" and kw_score > 0:
            elem_c = idx.resolve_canonical_type(m_canon.target_type_offset)
            if elem_c and elem_c.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                candidates.append((kw_score + 25, mem))

    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def _reconstruct_expression_from_ops(ops: List[Tuple[str, Any]]) -> str:
    """Rebuilds a canonical C/C++ expression string from tokenized `(op_kind, op_arg)` operations."""
    if not ops:
        return ""
    root_name = str(ops[0][1])
    idx_pos = 1
    deref_count = 0
    while idx_pos < len(ops) and ops[idx_pos][0] == "DEREF":
        deref_count += 1
        idx_pos += 1
    if deref_count > 0:
        if idx_pos < len(ops):
            expr_out = "(" + ("*" * deref_count) + root_name + ")"
        else:
            expr_out = ("*" * deref_count) + root_name
    else:
        expr_out = root_name

    for op_kind, op_arg in ops[idx_pos:]:
        if op_kind == "DEREF":
            expr_out = f"(*({expr_out}))"
        elif op_kind == "DEREF_MEMBER":
            expr_out = f"{expr_out}->{op_arg}"
        elif op_kind == "MEMBER":
            expr_out = f"{expr_out}.{op_arg}"
        elif op_kind == "INDEX":
            expr_out = f"{expr_out}[{op_arg}]"
    return expr_out


def coerce_and_resolve_expression(
    mgr,
    idx: DwarfIndex,
    raw_expr: str,
    module_contexts: Optional[List[Tuple[str, DwarfIndex, int, bool]]] = None,
) -> Dict[str, Any]:
    """Forgiving C/C++ Expression Auto-Coercer:
        1. Bare Member / Sub-Array Promotion: If the root token is not a global symbol, searches global
           structs and pointers-to-structs for a matching member name (e.g., `buffers[2].seq` -> `gpMem->buffers[2].seq`,
           `prod_tail` -> `g_dpdk_rx_ring.prod_tail`).
        2. Fuzzy Root Symbol Typo Coercion: If the root token has a minor typo or omitted middle token
           (e.g., `g_pol_storage.active_buffers` -> `g_pool_storage.active_buffers`,
           `g_rx_ring.prod_tail` -> `g_dpdk_rx_ring.prod_tail`), coerces to the closest DWARF global variable.
        3. DWARF Type-Guided `.` <-> `->` Coercion: Automatically converts `.` on a `DW_TAG_pointer_type`
           to `->` (e.g., `gpMem.buffers[2].seq` -> `gpMem->buffers[2].seq`) and `->` on a value struct
           to `.` (e.g., `g_pool_storage->active_buffers` -> `g_pool_storage.active_buffers`).
        4. Container-Struct Shorthand & Member Typo Coercion: Converts `gpMem[2].seq` -> `gpMem->buffers[2].seq`
           and fixes minor struct field typos.
        """
    import difflib

    expr_clean = (raw_expr or "").strip()
    if not expr_clean:
        return {
            "original_expression": raw_expr,
            "resolved_expression": "",
            "was_coerced": False,
            "coercion_reasons": [],
            "ops": [],
        }

    try:
        ops = list(mgr._tokenize_symbol_expression(expr_clean))
    except Exception:
        return {
            "original_expression": raw_expr,
            "resolved_expression": expr_clean,
            "was_coerced": False,
            "coercion_reasons": [],
            "ops": None,
        }

    contexts = module_contexts or [(os.path.basename(getattr(idx, "elf_path", None) or getattr(idx, "binary_path", None) or "main"), idx, 0, (idx.elf_type == "ET_DYN"))]
    coercion_reasons: List[str] = []

    raw_root = str(ops[0][1])
    mod_filter = None
    root_name = raw_root
    if "::" in raw_root:
        mod_filter, root_name = raw_root.split("::", 1)

    def _find_exact_root(r_name: str):
        for mod_name, m_idx, m_bias, m_dyn in contexts:
            if mod_filter and mod_filter not in mod_name and os.path.basename(mod_filter) not in mod_name:
                continue
            cands = [
                v for v in m_idx.variables_by_name.get(r_name, [])
                if v.link_time_address is not None and not v.is_declaration
            ]
            if cands:
                return (mod_name, m_idx, m_bias, m_dyn), cands[0]
        return None, None

    matched_ctx, root_var = _find_exact_root(root_name)

    # Rule 1: If root_name is not an exact global symbol, try (1A) Bare Member Promotion, then (1B) Fuzzy Symbol Typo
    if root_var is None:
        # 1A: Search global pointer-to-structs and value structs for a member named `root_name`
        member_matches: List[Tuple[int, Any, DwarfIndex, Tuple[str, DwarfIndex, int, bool], str]] = []
        for mod_name, m_idx, m_bias, m_dyn in contexts:
            if mod_filter and mod_filter not in mod_name and os.path.basename(mod_filter) not in mod_name:
                continue
            for v in m_idx.variables:
                if not v.name or v.link_time_address is None or v.is_declaration:
                    continue
                v_canon = m_idx.resolve_canonical_type(v.type_offset)
                if not v_canon:
                    continue
                v_low = v.name.lower()
                name_bonus = 15 if v_low.startswith(("gp", "g_")) else 0
                if v_canon.tag == "DW_TAG_pointer_type":
                    t_canon = m_idx.resolve_canonical_type(v_canon.target_type_offset)
                    if t_canon and t_canon.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                        if any(m.name == root_name for m in (t_canon.members or [])):
                            member_matches.append((100 + name_bonus, v, m_idx, (mod_name, m_idx, m_bias, m_dyn), "DEREF_MEMBER"))
                elif v_canon.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                    if any(m.name == root_name for m in (v_canon.members or [])):
                        member_matches.append((85 + name_bonus, v, m_idx, (mod_name, m_idx, m_bias, m_dyn), "MEMBER"))

        if member_matches:
            member_matches.sort(key=lambda x: x[0], reverse=True)
            _, best_v, best_idx, best_ctx, access_op = member_matches[0]
            new_root = f"{mod_filter}::{best_v.name}" if mod_filter else best_v.name
            # Rebuild ops: [("ROOT", new_root), (access_op, root_name), ...ops[1:]]
            ops = [("ROOT", new_root), (access_op, root_name)] + ops[1:]
            matched_ctx = best_ctx
            root_var = best_v
            op_sym = "->" if access_op == "DEREF_MEMBER" else "."
            coercion_reasons.append(f"bare_member_promoted:{root_name}->{new_root}{op_sym}{root_name}")
        else:
            # 1B: Fuzzy global variable typo resolution (ignoring trivial 'g'/'gp'/'s' prefixes for token overlap)
            def _meaningful_tokens(s_val: str) -> List[str]:
                s_spaced = re.sub(r"([a-z0-9])([A-Z])", r"_", s_val).lower()
                toks = [t for t in re.split(r"[^a-z0-9]+", s_spaced) if t]
                return [t for t in toks if t not in ("g", "gp", "s", "st", "the", "my", "nonexistent", "symbol", "unknown")]

            q_toks = _meaningful_tokens(root_name)
            best_fuzzy = None
            best_score = 0.0
            for mod_name, m_idx, m_bias, m_dyn in contexts:
                if mod_filter and mod_filter not in mod_name and os.path.basename(mod_filter) not in mod_name:
                    continue
                for v in m_idx.variables:
                    if not v.name or v.link_time_address is None or v.is_declaration:
                        continue
                    c_toks = _meaningful_tokens(v.name)
                    seq_ratio = difflib.SequenceMatcher(None, root_name.lower(), v.name.lower()).ratio()
                    shared = [qt for qt in q_toks if any(qt == ct or (len(qt) >= 4 and len(ct) >= 4 and difflib.SequenceMatcher(None, qt, ct).ratio() >= 0.8) for ct in c_toks)]
                    tok_cov = (len(shared) / float(len(q_toks))) if q_toks else 0.0
                    # Require either high character similarity (>= 0.74) with at least 1 meaningful shared/fuzzy token,
                    # or complete meaningful token coverage (e.g. g_rx_ring -> g_dpdk_rx_ring)
                    if (seq_ratio >= 0.74 and (tok_cov >= 0.5 or not q_toks)) or (len(q_toks) >= 2 and tok_cov >= 0.99 and seq_ratio >= 0.60):
                        comb = seq_ratio * 0.65 + tok_cov * 0.35
                        if comb > best_score:
                            best_score = comb
                            best_fuzzy = (v, (mod_name, m_idx, m_bias, m_dyn))

            if best_fuzzy is not None:
                best_v, best_ctx = best_fuzzy
                new_root = f"{mod_filter}::{best_v.name}" if mod_filter else best_v.name
                ops[0] = ("ROOT", new_root)
                matched_ctx = best_ctx
                root_var = best_v
                coercion_reasons.append(f"root_symbol_typo:{root_name}->{best_v.name}")

    # Rule 2: Walk operator chain with DWARF types to coerce `.` <-> `->`, container indexing, and member typos
    if root_var is not None and matched_ctx is not None:
        _, active_idx, _, _ = matched_ctx
        curr_type_off = root_var.type_offset
        new_ops: List[Tuple[str, Any]] = [ops[0]]

        for step_i, (op_kind, op_arg) in enumerate(ops[1:], start=1):
            canon_t = active_idx.resolve_canonical_type(curr_type_off)
            if canon_t is None:
                new_ops.append((op_kind, op_arg))
                continue

            stl_curr = active_idx.classify_stl_type(curr_type_off)
            is_smart_ptr = bool(stl_curr and stl_curr["stl_kind"] in ("std::unique_ptr", "std::shared_ptr", "std::weak_ptr"))
            is_ptr = bool(canon_t.tag == "DW_TAG_pointer_type" or is_smart_ptr)

            if op_kind == "DEREF":
                new_ops.append((op_kind, op_arg))
                if is_ptr:
                    curr_type_off = stl_curr["element_type_offset"] if is_smart_ptr else canon_t.target_type_offset
                continue

            if op_kind in ("MEMBER", "DEREF_MEMBER"):
                # Check if `.` was used on a pointer to struct/class -> coerce to `->` (`DEREF_MEMBER`)
                if op_kind == "MEMBER" and is_ptr:
                    target_off = stl_curr["element_type_offset"] if is_smart_ptr else canon_t.target_type_offset
                    target_canon = active_idx.resolve_canonical_type(target_off)
                    if target_canon and target_canon.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                        op_kind = "DEREF_MEMBER"
                        coercion_reasons.append(f"dot_to_arrow:.{op_arg}->->{op_arg}")
                        curr_type_off = target_off
                        canon_t = target_canon
                # Check if `->` was used on a non-pointer struct/class -> coerce to `.` (`MEMBER`)
                elif op_kind == "DEREF_MEMBER" and not is_ptr and canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                    op_kind = "MEMBER"
                    coercion_reasons.append(f"arrow_to_dot:->{op_arg}->.{op_arg}")
                elif op_kind == "DEREF_MEMBER" and is_ptr:
                    target_off = stl_curr["element_type_offset"] if is_smart_ptr else canon_t.target_type_offset
                    curr_type_off = target_off
                    canon_t = active_idx.resolve_canonical_type(curr_type_off)

                # Validate member name or coerce minor typo on struct field
                member_name = str(op_arg)
                if canon_t and canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
                    matched_mem = next((m for m in (canon_t.members or []) if m.name == member_name), None)
                    if matched_mem is None and canon_t.members:
                        best_m = None
                        best_m_ratio = 0.0
                        for cand_m in canon_t.members:
                            if not cand_m.name:
                                continue
                            r = difflib.SequenceMatcher(None, member_name.lower(), cand_m.name.lower()).ratio()
                            if r >= 0.74 and r > best_m_ratio:
                                best_m_ratio = r
                                best_m = cand_m
                        if best_m is not None:
                            coercion_reasons.append(f"member_typo:{member_name}->{best_m.name}")
                            member_name = best_m.name
                            matched_mem = best_m
                    if matched_mem is not None:
                        curr_type_off = matched_mem.type_offset

                new_ops.append((op_kind, member_name))

            elif op_kind == "INDEX":
                arr_idx = int(op_arg)
                if stl_curr and stl_curr["stl_kind"] == "std::vector":
                    curr_type_off = stl_curr.get("element_type_offset")
                    new_ops.append((op_kind, arr_idx))
                elif is_ptr:
                    elem_off = stl_curr["element_type_offset"] if is_smart_ptr else canon_t.target_type_offset
                    elem_canon = active_idx.resolve_canonical_type(elem_off)
                    pivoted = False
                    if elem_canon and elem_canon.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and elem_canon.members:
                        pool_arr_mem = mgr._find_primary_pool_array_member(active_idx, elem_canon)
                        if pool_arr_mem is not None:
                            mem_canon = active_idx.resolve_canonical_type(pool_arr_mem.type_offset)
                            if mem_canon and mem_canon.tag in ("DW_TAG_array_type", "DW_TAG_pointer_type"):
                                new_ops.append(("DEREF_MEMBER", pool_arr_mem.name))
                                new_ops.append(("INDEX", arr_idx))
                                curr_type_off = mem_canon.target_type_offset
                                coercion_reasons.append(f"container_index_pivot:[{arr_idx}]->->{pool_arr_mem.name}[{arr_idx}]")
                                pivoted = True
                    if not pivoted:
                        new_ops.append((op_kind, arr_idx))
                        curr_type_off = elem_off
                elif canon_t.tag == "DW_TAG_array_type":
                    new_ops.append((op_kind, arr_idx))
                    curr_type_off = canon_t.target_type_offset
                elif canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and canon_t.members:
                    pool_arr_mem = mgr._find_primary_pool_array_member(active_idx, canon_t)
                    if pool_arr_mem is not None:
                        mem_canon = active_idx.resolve_canonical_type(pool_arr_mem.type_offset)
                        if mem_canon and mem_canon.tag in ("DW_TAG_array_type", "DW_TAG_pointer_type"):
                            new_ops.append(("MEMBER", pool_arr_mem.name))
                            new_ops.append(("INDEX", arr_idx))
                            curr_type_off = mem_canon.target_type_offset
                            coercion_reasons.append(f"struct_index_pivot:[{arr_idx}]->.{pool_arr_mem.name}[{arr_idx}]")
                            continue
                    new_ops.append((op_kind, arr_idx))
                else:
                    new_ops.append((op_kind, arr_idx))

        ops = new_ops

    resolved_expr = mgr._reconstruct_expression_from_ops(ops) if coercion_reasons else expr_clean
    return {
        "original_expression": raw_expr,
        "resolved_expression": resolved_expr,
        "was_coerced": bool(coercion_reasons and resolved_expr != expr_clean),
        "coercion_reasons": coercion_reasons,
        "ops": ops,
    }


# -------------------------------------------------------------------------
# Phase 49 (Phase 19): Self-Repairing Error Diagnostics, LLM Token-Budgeted
# Smart Compactor & Anomaly-First Pagination, and 1-Call Multi-Tool Batch
# Macro Executor (`runtime_batch_execute`)
# -------------------------------------------------------------------------

def build_self_repairing_diagnostic(
    mgr,
    error_status: str,
    expression: str,
    raw_root: str = "",
    module_contexts: Optional[List[Tuple[str, DwarfIndex, int, bool]]] = None,
    pointer_chain: Optional[List[Dict[str, Any]]] = None,
    struct_type: Optional[Any] = None,
    missing_member: Optional[str] = None,
    target_type_offset: Optional[int] = None,
    idx: Optional[DwarfIndex] = None,
) -> Dict[str, Any]:
    """Constructs actionable self-repairing diagnostics when an expression evaluation fails
        (`SYMBOL_NOT_FOUND`, `MEMBER_NOT_FOUND`, `NULL_POINTER`), providing closest DWARF symbols,
        available struct members with byte offsets, alternative non-null globals of the same struct
        type, and a ready-to-call MCP recovery payload.
        """
    import difflib

    contexts = module_contexts or []
    if error_status == "SYMBOL_NOT_FOUND":
        scored_globals: List[Tuple[float, Dict[str, Any]]] = []
        q_low = (raw_root or expression or "").lower()
        for mod_name, m_idx, m_bias, m_dyn in contexts:
            for v in m_idx.variables:
                if not v.name or v.link_time_address is None or v.is_declaration:
                    continue
                rt_addr = (m_bias + v.link_time_address) if m_dyn else v.link_time_address
                t_name = m_idx.get_type_name(v.type_offset)
                sim = difflib.SequenceMatcher(None, q_low, v.name.lower()).ratio()
                # Boost state/pool/ring/worker globals so the fallback list is always high-signal
                kw_boost = 0.25 if any(k in v.name.lower() for k in ("pool", "mem", "ring", "worker", "session", "state", "ctx")) else 0.0
                scored_globals.append((
                    sim + kw_boost,
                    {
                        "name": v.name,
                        "type_name": t_name,
                        "module": mod_name,
                        "runtime_address": f"0x{rt_addr:x}",
                        "similarity": round(sim, 3),
                    },
                ))
        scored_globals.sort(key=lambda x: x[0], reverse=True)
        closest = [item[1] for item in scored_globals[:6]]
        rec_exprs = [c["name"] for c in closest[:3]]
        return {
            "error_status": error_status,
            "failed_expression": expression,
            "closest_symbols": closest,
            "self_repair_hint": (
                f"Symbol '{raw_root}' was not found. Top available DWARF globals in this binary: "
                + ", ".join(f"{c['name']} ({c['type_name']})" for c in closest[:4])
            ),
            "suggested_mcp_call": {
                "tool": "runtime_eval_memory_path",
                "arguments": {"expressions": rec_exprs},
            },
        }

    if error_status == "MEMBER_NOT_FOUND" and struct_type is not None:
        avail_members: List[Dict[str, Any]] = []
        scored_mems: List[Tuple[float, str]] = []
        m_low = (missing_member or "").lower()
        for m in (getattr(struct_type, "members", None) or []):
            if not m.name:
                continue
            m_tname = idx.get_type_name(m.type_offset) if idx else "unknown"
            avail_members.append({
                "name": m.name,
                "type_name": m_tname,
                "offset": m.offset,
                "byte_size": m.byte_size,
            })
            sim = difflib.SequenceMatcher(None, m_low, m.name.lower()).ratio()
            scored_mems.append((sim, m.name))
        scored_mems.sort(key=lambda x: x[0], reverse=True)
        closest_m = [x[1] for x in scored_mems[:3]]
        base_prefix = expression.rsplit(".", 1)[0].rsplit("->", 1)[0] if ("." in expression or "->" in expression) else raw_root
        sep = "->" if "->" in expression else "."
        rec_exprs = [f"{base_prefix}{sep}{cm}" for cm in closest_m[:2]]
        return {
            "error_status": error_status,
            "failed_expression": expression,
            "struct_name": getattr(struct_type, "name", None),
            "missing_member": missing_member,
            "available_members": avail_members,
            "closest_members": closest_m,
            "self_repair_hint": (
                f"Struct '{getattr(struct_type, 'name', '')}' does not have member '{missing_member}'. "
                f"Available members: {[m['name'] for m in avail_members]}"
            ),
            "suggested_mcp_call": {
                "tool": "runtime_eval_memory_path",
                "arguments": {"expressions": rec_exprs},
            },
        }

    if error_status == "NULL_POINTER":
        broken_step = pointer_chain[-1] if pointer_chain else {"step": raw_root}
        alt_globals: List[Dict[str, Any]] = []
        if idx is not None and target_type_offset is not None:
            target_canon = idx.resolve_canonical_type(target_type_offset)
            target_struct_name = getattr(target_canon, "name", None) if target_canon else None
            for mod_name, m_idx, m_bias, m_dyn in contexts:
                for v in m_idx.variables:
                    if not v.name or v.name == raw_root or v.link_time_address is None or v.is_declaration:
                        continue
                    v_can = m_idx.resolve_canonical_type(v.type_offset)
                    if v_can and target_struct_name and getattr(v_can, "name", None) == target_struct_name:
                        rt_addr = (m_bias + v.link_time_address) if m_dyn else v.link_time_address
                        alt_globals.append({
                            "name": v.name,
                            "type_name": m_idx.get_type_name(v.type_offset),
                            "runtime_address": f"0x{rt_addr:x}",
                        })
        return {
            "error_status": error_status,
            "failed_expression": expression,
            "null_break_step": broken_step.get("step"),
            "null_pointer_address": broken_step.get("address"),
            "alternative_same_type_globals": alt_globals[:5],
            "self_repair_hint": (
                f"Pointer hop '{broken_step.get('step')}' at {broken_step.get('address')} is currently NULL (0x0)."
                + (f" Alternative value/struct globals of the same type: {[a['name'] for a in alt_globals]}" if alt_globals else "")
            ),
            "suggested_mcp_call": {
                "tool": "runtime_eval_memory_path",
                "arguments": {"expressions": [a["name"] for a in alt_globals[:2]] or [raw_root]},
            },
        }

    return {
        "error_status": error_status,
        "failed_expression": expression,
        "self_repair_hint": "Use `runtime_get_xray_blueprint` or `runtime_ask` to inspect valid symbols.",
    }
