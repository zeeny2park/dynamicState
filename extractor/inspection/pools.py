"""Memory pool / array scanner, symbol owner and thread lookup, the process x-ray blueprint and linked-structure
traversal.

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import re
import struct
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from ..dwarf_indexer import DwarfIndex, DwarfIndexer
from ..target_adapter import TargetExecutionAdapter
from .process_memory import ZERO_STOP_NON_ATOMIC_CONSISTENCY, decode_value_from_bytes


def scan_memory_pool_or_array(
    mgr,
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    base_expression: str = "*gpMem",
    count: Optional[int] = None,
    status_field: Optional[str] = None,
    include_fields: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Scans an entire memory pool or array (static array `T[N]`, dynamic pointer `T*`,
        pool container struct `*gpMem` / `gpMem`, or `std::vector<T>`) in a single zero-stop
        batch read and returns slot-by-slot allocation status, bitmap, and visual map chart.
        """
    t_start_ns = time.monotonic_ns()
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
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )

    resolved = mgr._resolve_expression_to_target(
        pid=pid,
        companion_elf_path=companion_elf_path,
        expression=base_expression,
        adapter=target_adapter,
    )
    idx: DwarfIndex = resolved["idx"]
    curr_addr: int = resolved["address"]
    curr_type_off: Optional[int] = resolved["type_offset"]
    canon_t = resolved["canonical_type"]
    ptr_size = idx.pointer_size or 8
    endian = idx.endianness or "little"
    ptr_fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")

    # If the user passed `gpMem` (a pointer to a pool container struct `MemPool*`),
    # dereference it once so we can inspect the `MemPool` struct or array target.
    if canon_t and canon_t.tag == "DW_TAG_pointer_type":
        pointee_t = idx.resolve_canonical_type(canon_t.target_type_offset)
        if pointee_t and pointee_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
            # Check if pointee_t is a container struct holding an inner buffers/slots array
            inner_arr_mem = mgr._find_primary_pool_array_member(idx, pointee_t)
            if inner_arr_mem is not None:
                raw_ptr, pst, perr = target_adapter.read_memory(pid, curr_addr, ptr_size)
                if pst != "OBSERVED" or not raw_ptr or len(raw_ptr) < ptr_size:
                    raise RuntimeError(perr or f"Failed reading pool pointer '{base_expression}' at 0x{curr_addr:x}")
                deref_addr = struct.unpack(ptr_fmt, raw_ptr[:ptr_size])[0]
                if deref_addr == 0:
                    raise ValueError(f"Pool pointer '{base_expression}' is NULL (0x0)")
                curr_addr = deref_addr
                curr_type_off = canon_t.target_type_offset
                canon_t = pointee_t

    pool_metadata: Dict[str, Any] = {}
    inferred_count: Optional[int] = None
    resolved_array_expr = base_expression

    # If curr_type is a pool container struct (e.g. `*gpMem` -> `struct MemPool`),
    # extract its scalar metadata fields (like `num_buffers`, `capacity`, `used_count`)
    # and pivot to its primary buffer array/pointer/vector member!
    if canon_t and canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
        inner_arr_mem = mgr._find_primary_pool_array_member(idx, canon_t)
        if inner_arr_mem is not None:
            # Read scalar metadata fields from parent pool struct
            struct_sz = max(1, min(canon_t.byte_size or 64, 4096))
            raw_parent, p_st, _ = target_adapter.read_memory(pid, curr_addr, struct_sz)
            count_keywords = (
                "num_buffers", "total_buffers", "buffer_count", "num_slots", "total_slots",
                "slot_count", "max_buffers", "max_slots", "capacity", "count", "num_items", "total"
            )
            if p_st == "OBSERVED" and raw_parent:
                for m in canon_t.members:
                    if not m.name or m.name == inner_arr_mem.name:
                        continue
                    mc = idx.resolve_canonical_type(m.type_offset)
                    if mc and mc.tag in ("DW_TAG_base_type", "DW_TAG_enumeration_type"):
                        msz = m.byte_size or (mc.byte_size if mc.byte_size else 4)
                        if m.offset + msz <= len(raw_parent):
                            mv, merr = decode_value_from_bytes(
                                raw_parent[m.offset:m.offset + msz],
                                mc.name or idx.get_type_name(m.type_offset),
                                endian=endian,
                            )
                            if merr is None:
                                pool_metadata[m.name] = mv
                                if inferred_count is None and isinstance(mv, int) and 1 <= mv <= 4096:
                                    if m.name.lower() in count_keywords or any(k in m.name.lower() for k in count_keywords):
                                        inferred_count = int(mv)

            curr_addr = curr_addr + inner_arr_mem.offset
            curr_type_off = inner_arr_mem.type_offset
            canon_t = idx.resolve_canonical_type(curr_type_off)
            sep = "->" if (not base_expression.startswith("*") and resolved["canonical_type"] and resolved["canonical_type"].tag == "DW_TAG_pointer_type") else "."
            clean_base = base_expression[1:].strip() if (base_expression.startswith("*") and sep == ".") else base_expression
            resolved_array_expr = f"{clean_base}->{inner_arr_mem.name}" if base_expression.startswith("*") else f"{base_expression}{sep}{inner_arr_mem.name}"

    # Now determine array_base_addr, elem_type_off, and total_slots
    stl_info = idx.classify_stl_type(curr_type_off)
    array_base_addr = curr_addr
    elem_type_off: Optional[int] = None
    total_slots = count or inferred_count or 0

    if stl_info and stl_info["stl_kind"] == "std::vector":
        raw_vec, vst, verr = target_adapter.read_memory(pid, curr_addr, 3 * ptr_size)
        if vst != "OBSERVED" or not raw_vec or len(raw_vec) < 2 * ptr_size:
            raise RuntimeError(verr or f"Failed reading std::vector header at 0x{curr_addr:x}")
        start_ptr = struct.unpack(ptr_fmt, raw_vec[:ptr_size])[0]
        finish_ptr = struct.unpack(ptr_fmt, raw_vec[ptr_size:2 * ptr_size])[0]
        elem_sz = max(1, int(stl_info.get("element_size") or 4))
        vec_count = int((finish_ptr - start_ptr) // elem_sz) if (finish_ptr >= start_ptr and start_ptr > 0) else 0
        array_base_addr = start_ptr
        elem_type_off = stl_info.get("element_type_offset")
        if not total_slots:
            total_slots = vec_count
    elif canon_t and canon_t.tag == "DW_TAG_array_type":
        array_base_addr = curr_addr
        elem_type_off = canon_t.target_type_offset
        if not total_slots:
            total_slots = canon_t.array_count or 16
    elif canon_t and canon_t.tag == "DW_TAG_pointer_type":
        raw_ptr, pst, perr = target_adapter.read_memory(pid, curr_addr, ptr_size)
        if pst != "OBSERVED" or not raw_ptr or len(raw_ptr) < ptr_size:
            raise RuntimeError(perr or f"Failed reading array pointer at 0x{curr_addr:x}")
        array_base_addr = struct.unpack(ptr_fmt, raw_ptr[:ptr_size])[0]
        if array_base_addr == 0:
            raise ValueError(f"Buffer array pointer '{resolved_array_expr}' at 0x{curr_addr:x} is NULL (0x0)")
        elem_type_off = canon_t.target_type_offset
        if not total_slots:
            total_slots = 32
    elif canon_t and canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
        # User dereferenced a pointer to the first element of a buffer array e.g. `*gpMem` where `gpMem` is `Buffer*`
        array_base_addr = curr_addr
        elem_type_off = curr_type_off
        if not total_slots:
            total_slots = 32
    else:
        raise ValueError(f"Expression '{base_expression}' (type '{idx.get_type_name(curr_type_off)}') is not a scannable pool or array")

    total_slots = max(1, min(int(total_slots), 4096))
    elem_canon = idx.resolve_canonical_type(elem_type_off)
    elem_type_name = idx.get_type_name(elem_type_off)
    elem_size = (
        elem_canon.byte_size
        if (elem_canon and elem_canon.byte_size and elem_canon.byte_size > 0)
        else (ptr_size if (elem_canon and elem_canon.tag == "DW_TAG_pointer_type") else 4)
    )

    total_bytes = min(total_slots * elem_size, 4 * 1024 * 1024)
    effective_slots = max(1, total_bytes // elem_size)
    raw_pool_bytes, read_st, read_err = target_adapter.read_memory(pid, array_base_addr, effective_slots * elem_size)
    if read_st != "OBSERVED" or raw_pool_bytes is None:
        raise RuntimeError(read_err or f"Failed reading pool memory at 0x{array_base_addr:x} ({effective_slots * elem_size} bytes)")

    include_set = set(include_fields) if include_fields else None
    status_field_clean = (status_field or "").strip() or None

    slots: List[Dict[str, Any]] = []
    allocated_indices: List[int] = []
    free_indices: List[int] = []
    bitmap_chars: List[str] = []

    status_priority_names = (
        "in_use", "used", "is_used", "allocated", "is_allocated", "active", "busy", "occupied",
        "state", "status", "flags", "ref_count", "refcnt", "use_count", "owner_tid", "tid", "thread_id"
    )
    owner_field_names = ("owner_tid", "tid", "thread_id", "owner", "worker_id", "holder_tid", "task_id")

    for s_idx in range(effective_slots):
        slot_addr = array_base_addr + (s_idx * elem_size)
        slot_slice = raw_pool_bytes[s_idx * elem_size : (s_idx + 1) * elem_size]
        if len(slot_slice) < elem_size:
            break

        slot_fields: Dict[str, Any] = {}
        is_allocated = False
        status_basis = "non_zero_bytes"
        owner_hint: Optional[Any] = None

        if elem_canon and elem_canon.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type") and elem_canon.members:
            for mem in elem_canon.members:
                if not mem.name:
                    continue
                if include_set is not None and mem.name not in include_set and mem.name != status_field_clean and mem.name.lower() not in status_priority_names and mem.name.lower() not in owner_field_names:
                    continue
                m_canon = idx.resolve_canonical_type(mem.type_offset)
                m_tname = idx.get_type_name(mem.type_offset)
                m_off = mem.offset
                m_sz = mem.byte_size or (m_canon.byte_size if m_canon and m_canon.byte_size else (ptr_size if m_canon and m_canon.tag == "DW_TAG_pointer_type" else 4))
                if m_off + m_sz > len(slot_slice):
                    continue
                m_bytes = slot_slice[m_off : m_off + m_sz]
                if m_canon and m_canon.tag == "DW_TAG_pointer_type":
                    pval = struct.unpack(ptr_fmt, m_bytes[:ptr_size])[0] if len(m_bytes) >= ptr_size else 0
                    slot_fields[mem.name] = f"0x{pval:x}"
                elif m_canon and m_canon.tag == "DW_TAG_enumeration_type":
                    int_t = "int32_t" if m_sz == 4 else ("int16_t" if m_sz == 2 else ("int8_t" if m_sz == 1 else "int64_t"))
                    ev_int, _ = decode_value_from_bytes(m_bytes, int_t, endian=endian)
                    ev_lbl = m_canon.enum_values.get(ev_int)
                    slot_fields[mem.name] = f"{ev_lbl} ({ev_int})" if ev_lbl else ev_int
                elif m_canon and m_canon.tag == "DW_TAG_array_type":
                    en = idx.get_type_name(m_canon.target_type_offset).lower()
                    if en in ("char", "signed char", "unsigned char", "const char"):
                        slot_fields[mem.name] = m_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    else:
                        slot_fields[mem.name] = m_bytes[:16].hex()
                else:
                    v, _ = decode_value_from_bytes(m_bytes, (m_canon.name if m_canon and m_canon.name else m_tname), endian=endian)
                    slot_fields[mem.name] = v

            # Determine owner_hint if present
            for ofn in owner_field_names:
                for k, v in slot_fields.items():
                    if k.lower() == ofn and v not in (None, 0, "0x0", ""):
                        owner_hint = v
                        break
                if owner_hint is not None:
                    break

            # Determine allocation status
            def _is_val_active(v: Any) -> bool:
                if v is None or v is False or v == 0 or v == "0x0" or v == "":
                    return False
                if isinstance(v, str):
                    vu = v.strip().upper()
                    if vu.startswith(("FREE", "IDLE", "UNUSED", "EMPTY", "NONE")) or vu.endswith("(0)"):
                        return False
                return True

            if status_field_clean and status_field_clean in slot_fields:
                is_allocated = _is_val_active(slot_fields[status_field_clean])
                status_basis = f"field:{status_field_clean}"
            else:
                matched_status_key = None
                for pname in status_priority_names:
                    for k in slot_fields:
                        if k.lower() == pname:
                            matched_status_key = k
                            break
                    if matched_status_key:
                        break
                if matched_status_key is not None:
                    is_allocated = _is_val_active(slot_fields[matched_status_key])
                    status_basis = f"field:{matched_status_key}"
                else:
                    is_allocated = any(b != 0 for b in slot_slice)
                    status_basis = "non_zero_slot_bytes"
        else:
            val, _ = decode_value_from_bytes(slot_slice, (elem_canon.name if elem_canon and elem_canon.name else elem_type_name), endian=endian)
            slot_fields["value"] = val
            is_allocated = bool(val not in (None, 0, False, "0x0", ""))
            status_basis = "element_value"

        if is_allocated:
            allocated_indices.append(s_idx)
            bitmap_chars.append("1")
        else:
            free_indices.append(s_idx)
            bitmap_chars.append("0")

        slots.append({
            "index": s_idx,
            "expression": f"{resolved_array_expr}[{s_idx}]",
            "runtime_address": f"0x{slot_addr:x}",
            "runtime_address_int": slot_addr,
            "size": elem_size,
            "status": "IN_USE" if is_allocated else "FREE",
            "is_allocated": is_allocated,
            "owner_hint": owner_hint,
            "fields": slot_fields,
        })

    # Build visual ASCII / Unicode block map chart (16 slots per row)
    row_width = 16
    chart_lines = [
        f"Memory Pool Map: {resolved_array_expr} ({len(allocated_indices)}/{effective_slots} IN_USE, {round(len(allocated_indices) * 100.0 / max(1, effective_slots), 1)}%)",
        "Legend: [■] = IN_USE (할당/사용 중)   [·] = FREE (비어 있음)",
    ]
    for r_start in range(0, effective_slots, row_width):
        r_end = min(effective_slots - 1, r_start + row_width - 1)
        row_cells = []
        for idx_cell in range(r_start, r_end + 1):
            row_cells.append("■" if bitmap_chars[idx_cell] == "1" else "·")
        chart_lines.append(f"[{r_start:03d}..{r_end:03d}]  " + " ".join(row_cells))

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    decl_loc = f"{elem_canon.decl_file}:{elem_canon.decl_line}" if (elem_canon and elem_canon.decl_file) else None

    coerced_meta = resolved.get("coerced_meta") or {}
    return {
        "pid": pid,
        "companion_elf": companion_elf_path,
        "auto_healed_pid": ctx_info.get("auto_healed_pid", False),
        "previous_pid": ctx_info.get("previous_pid"),
        "elf_auto_discovered": ctx_info.get("elf_auto_discovered", False),
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "base_expression": base_expression,
        "was_coerced": bool(coerced_meta.get("was_coerced")),
        "coercion_reasons": coerced_meta.get("coercion_reasons") or [],
        "resolved_array_expression": resolved_array_expr,
        "array_base_address": f"0x{array_base_addr:x}",
        "element_type": elem_type_name,
        "element_size": elem_size,
        "element_decl_location": decl_loc,
        "status_detection_basis": status_basis,
        "pool_metadata": pool_metadata,
        "pool_summary": {
            "total_slots": effective_slots,
            "allocated_count": len(allocated_indices),
            "free_count": len(free_indices),
            "utilization_pct": round((len(allocated_indices) * 100.0) / max(1, effective_slots), 2),
            "allocated_indices": allocated_indices,
            "free_indices": free_indices,
        },
        "allocation_bitmap": "".join(bitmap_chars),
        "ascii_map_chart": "\n".join(chart_lines),
        "slots": slots,
        "llm_next_step_hint": (
            f"To find which thread owns a specific IN_USE slot (e.g. index {allocated_indices[0] if allocated_indices else 0}), "
            f"call `runtime_find_symbol_owners` with target_expression='{resolved_array_expr}[{allocated_indices[0] if allocated_indices else 0}]'."
        ),
        "consistency": dict(ZERO_STOP_NON_ATOMIC_CONSISTENCY),
    }


def find_symbol_owners_and_threads(
    mgr,
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    target_expression: str = "",
    stack_scan_bytes: int = 65536,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Identifies which thread(s) or global worker contexts are currently using or referencing
        a target C/C++ symbol/slot (e.g. `gpMem->buffers[9]` or `gpMem[9]`) without stopping the target.

        Executes a 3-stage non-intrusive reverse-lookup pipeline:
        1. Direct Struct Owner Field Check (`owner_tid`, `tid`, `thread_id`, `worker_id` inside target object).
        2. Global Worker/Thread Context Table Scan (scans DWARF global structs/arrays for pointers to the target slot or matching slot index).
        3. Active Thread Stack Memory Pointer Scan (scans active stack memory of each thread in `/proc/<pid>/task/<tid>` for pointer addresses to the target slot or its inner data buffer).
        """
    t_start_ns = time.monotonic_ns()
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
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )

    resolved = mgr._resolve_expression_to_target(
        pid=pid,
        companion_elf_path=companion_elf_path,
        expression=target_expression,
        adapter=target_adapter,
    )
    idx: DwarfIndex = resolved["idx"]
    target_addr: int = resolved["address"]
    target_type_off: Optional[int] = resolved["type_offset"]
    canon_t = resolved["canonical_type"]
    ptr_size = idx.pointer_size or 8
    endian = idx.endianness or "little"
    ptr_fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")

    target_size = (
        canon_t.byte_size
        if (canon_t and canon_t.byte_size and canon_t.byte_size > 0)
        else (ptr_size if (canon_t and canon_t.tag == "DW_TAG_pointer_type") else 4)
    )
    target_end = target_addr + max(1, target_size)

    # Decode target object value & extract any inner pointers (e.g. `data_ptr`)
    target_val, _, _, target_raw_hex = mgr._decode_typed_memory(
        target_adapter, pid, idx, target_addr, target_type_off
    )

    # Extract index if expression ended with `[idx]`
    m_idx = re.search(r"\[\s*(\d+)\s*\]\s*$", target_expression.strip())
    target_slot_index: Optional[int] = int(m_idx.group(1)) if m_idx else None

    # Collect candidate pointer addresses that refer to this buffer/object:
    # - Start address of the slot struct itself (`target_addr`)
    # - Any non-null pointer fields inside the slot struct (e.g. `buf.data` / `buf.payload`)
    target_addresses: Dict[int, str] = {target_addr: f"&({target_expression})"}
    if isinstance(target_val, dict):
        for fk, fv in target_val.items():
            if isinstance(fv, str) and fv.startswith("0x"):
                try:
                    p_int = int(fv, 16)
                    if p_int >= 0x10000:
                        target_addresses[p_int] = f"({target_expression}).{fk}"
                except ValueError:
                    pass

    # Fetch active OS threads from /proc/<pid>/task
    threads = target_adapter.get_threads(pid)
    threads_by_tid: Dict[int, Dict[str, Any]] = {int(t["tid"]): t for t in threads if "tid" in t}
    matched_threads_map: Dict[int, Dict[str, Any]] = {}
    global_references: List[Dict[str, Any]] = []

    def _record_thread_match(
        tid_val: int,
        evidence_kind: str,
        confidence: str,
        detail: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        t_info = threads_by_tid.get(tid_val, {"tid": tid_val, "name": "unknown", "state": "UNKNOWN"})
        entry = matched_threads_map.get(tid_val)
        if entry is None:
            entry = {
                "tid": tid_val,
                "thread_name": t_info.get("name", "unknown"),
                "thread_state": t_info.get("state", "UNKNOWN"),
                "confidence": confidence,
                "evidence": [],
            }
            matched_threads_map[tid_val] = entry
        elif confidence == "HIGH" and entry["confidence"] != "HIGH":
            entry["confidence"] = "HIGH"
        ev_item = {
            "evidence_kind": evidence_kind,
            "confidence": confidence,
            "detail": detail,
        }
        if extra:
            ev_item.update(extra)
        entry["evidence"].append(ev_item)

    # ---------------------------------------------------------------------
    # Stage 1: Check direct owner/thread fields inside the target struct
    # ---------------------------------------------------------------------
    owner_tid_fields = ("owner_tid", "tid", "thread_id", "holder_tid", "locked_by_tid", "client_tid")
    worker_idx_fields = ("worker_id", "owner_worker", "thread_index", "worker_idx", "owner_id", "owner")
    candidate_worker_indices: Set[int] = set()

    if isinstance(target_val, dict):
        for fk, fv in target_val.items():
            f_low = fk.lower()
            if isinstance(fv, int) and fv > 0 and not isinstance(fv, bool):
                if f_low in owner_tid_fields or "tid" in f_low:
                    if fv in threads_by_tid:
                        _record_thread_match(
                            fv,
                            evidence_kind="STRUCT_OWNER_TID_FIELD",
                            confidence="HIGH",
                            detail=f"Target field '{fk}' directly stores active thread TID {fv} ({threads_by_tid[fv].get('name', 'unknown')})",
                            extra={"field": fk, "value": fv},
                        )
                    else:
                        # Record even if TID is not in current /proc task list (e.g. exited or logical ID)
                        _record_thread_match(
                            fv,
                            evidence_kind="STRUCT_OWNER_TID_FIELD",
                            confidence="MEDIUM",
                            detail=f"Target field '{fk}' stores TID/owner value {fv}",
                            extra={"field": fk, "value": fv},
                        )
                elif f_low in worker_idx_fields or "worker" in f_low or "owner" in f_low:
                    if fv in threads_by_tid:
                        _record_thread_match(
                            fv,
                            evidence_kind="STRUCT_OWNER_FIELD_MATCHES_TID",
                            confidence="HIGH",
                            detail=f"Target field '{fk}' matches active thread TID {fv}",
                            extra={"field": fk, "value": fv},
                        )
                    elif 0 <= fv < len(threads):
                        candidate_worker_indices.add(fv)

    # ---------------------------------------------------------------------
    # Stage 2: Scan DWARF global/static worker/thread/context tables for
    # pointers to `target_addresses` or references to `target_slot_index`
    # ---------------------------------------------------------------------
    root_var_name = resolved["root_var"].name if resolved.get("root_var") else ""
    addr_patterns: Dict[bytes, Tuple[int, str]] = {}
    for a_int, a_label in target_addresses.items():
        if a_int > 0:
            addr_patterns[struct.pack(ptr_fmt, a_int)] = (a_int, a_label)

    for mod_name, m_idx, m_bias, m_dyn in resolved["module_contexts"]:
        for var in m_idx.variables:
            if var.link_time_address is None or var.is_declaration or not var.name or var.name.startswith("__"):
                continue
            v_canon = m_idx.resolve_canonical_type(var.type_offset)
            if not v_canon:
                continue
            v_rt_addr = (m_bias + var.link_time_address) if m_dyn else var.link_time_address
            v_sz = v_canon.byte_size or 0
            if v_sz <= 0 or v_sz > 262144:
                continue
            # Avoid scanning the exact target slot itself
            if v_rt_addr == target_addr:
                continue

            # Check arrays of worker/thread/context structs or standalone structs/pointers
            is_worker_like = any(
                kw in var.name.lower() or kw in m_idx.get_type_name(var.type_offset).lower()
                for kw in ("worker", "thread", "task", "ctx", "context", "session", "client", "channel", "slot", "holder")
            )
            if not is_worker_like and v_canon.tag not in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_array_type", "DW_TAG_pointer_type"):
                continue

            raw_v, vst, _ = target_adapter.read_memory(pid, v_rt_addr, min(v_sz, 65536))
            if vst != "OBSERVED" or not raw_v:
                continue

            # Search for any target pointer pattern inside this global variable
            for pat_bytes, (pat_addr, pat_label) in addr_patterns.items():
                pos = raw_v.find(pat_bytes)
                while pos != -1:
                    found_at = v_rt_addr + pos
                    # Ignore if found_at is inside the target slot itself
                    if not (target_addr <= found_at < target_end):
                        ref_desc = var.name
                        matched_tid_in_struct = None
                        if v_canon.tag == "DW_TAG_array_type":
                            elem_c = m_idx.resolve_canonical_type(v_canon.target_type_offset)
                            esz = elem_c.byte_size if (elem_c and elem_c.byte_size) else ptr_size
                            elem_idx = pos // max(1, esz)
                            elem_off = pos % max(1, esz)
                            ref_desc = f"{var.name}[{elem_idx}]"
                            if elem_c and elem_c.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                                for m in elem_c.members:
                                    if m.offset == elem_off and m.name:
                                        ref_desc = f"{var.name}[{elem_idx}].{m.name}"
                                    # Also check if this array element has a `tid` / `thread_id` field!
                                    if m.name and ("tid" in m.name.lower() or "thread" in m.name.lower()):
                                        mc = m_idx.resolve_canonical_type(m.type_offset)
                                        msz = m.byte_size or (mc.byte_size if mc and mc.byte_size else 4)
                                        m_start = elem_idx * esz + m.offset
                                        if m_start + msz <= len(raw_v) and msz in (4, 8):
                                            tv, terr = decode_value_from_bytes(raw_v[m_start:m_start + msz], "int32_t" if msz == 4 else "int64_t", endian=endian)
                                            if terr is None and isinstance(tv, int) and tv in threads_by_tid:
                                                matched_tid_in_struct = tv
                        elif v_canon.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                            for m in v_canon.members:
                                if m.offset == pos and m.name:
                                    ref_desc = f"{var.name}.{m.name}"
                                if m.name and ("tid" in m.name.lower() or "thread" in m.name.lower()):
                                    mc = m_idx.resolve_canonical_type(m.type_offset)
                                    msz = m.byte_size or (mc.byte_size if mc and mc.byte_size else 4)
                                    if m.offset + msz <= len(raw_v) and msz in (4, 8):
                                        tv, terr = decode_value_from_bytes(raw_v[m.offset:m.offset + msz], "int32_t" if msz == 4 else "int64_t", endian=endian)
                                        if terr is None and isinstance(tv, int) and tv in threads_by_tid:
                                            matched_tid_in_struct = tv

                        global_references.append({
                            "symbol": ref_desc,
                            "module": mod_name,
                            "reference_address": f"0x{found_at:x}",
                            "points_to": f"0x{pat_addr:x} ({pat_label})",
                            "associated_tid": matched_tid_in_struct,
                        })
                        if matched_tid_in_struct is not None:
                            _record_thread_match(
                                matched_tid_in_struct,
                                evidence_kind="GLOBAL_WORKER_TABLE_POINTER",
                                confidence="HIGH",
                                detail=f"Global struct '{ref_desc}' holds pointer to {pat_label} (0x{pat_addr:x}) and is bound to TID {matched_tid_in_struct}",
                                extra={"symbol": ref_desc, "points_to": f"0x{pat_addr:x}"},
                            )
                    pos = raw_v.find(pat_bytes, pos + ptr_size)

            # Also check if a worker struct array stores `target_slot_index` (e.g. `current_slot == 9` or `buf_idx == 9`) + `tid`
            if target_slot_index is not None and is_worker_like and v_canon.tag == "DW_TAG_array_type":
                elem_c = m_idx.resolve_canonical_type(v_canon.target_type_offset)
                esz = elem_c.byte_size if (elem_c and elem_c.byte_size) else 0
                if elem_c and elem_c.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and esz > 0:
                    arr_cnt = min(v_canon.array_count or 64, len(raw_v) // esz)
                    for e_i in range(arr_cnt):
                        e_slice = raw_v[e_i * esz : (e_i + 1) * esz]
                        found_tid = None
                        found_slot_field = None
                        for m in elem_c.members:
                            if not m.name:
                                continue
                            mc = m_idx.resolve_canonical_type(m.type_offset)
                            msz = m.byte_size or (mc.byte_size if mc and mc.byte_size else 4)
                            if m.offset + msz <= len(e_slice) and msz in (4, 8):
                                iv, ierr = decode_value_from_bytes(e_slice[m.offset:m.offset + msz], "int32_t" if msz == 4 else "int64_t", endian=endian)
                                if ierr is None and isinstance(iv, int):
                                    if ("tid" in m.name.lower() or "thread" in m.name.lower()) and iv in threads_by_tid:
                                        found_tid = iv
                                    elif any(k in m.name.lower() for k in ("idx", "index", "slot", "buf")) and iv == target_slot_index:
                                        found_slot_field = m.name
                        if found_tid is not None and found_slot_field is not None:
                            _record_thread_match(
                                found_tid,
                                evidence_kind="GLOBAL_WORKER_SLOT_INDEX_MATCH",
                                confidence="HIGH",
                                detail=f"Worker entry '{var.name}[{e_i}].{found_slot_field}' == {target_slot_index} (bound to TID {found_tid})",
                                extra={"symbol": f"{var.name}[{e_i}].{found_slot_field}", "slot_index": target_slot_index},
                            )

    # ---------------------------------------------------------------------
    # Stage 3: Scan active thread stack memory for pointers to target slot
    # ---------------------------------------------------------------------
    clamped_stack_scan = max(4096, min(int(stack_scan_bytes), 262144))
    scanned_stack_ranges: Set[Tuple[int, int]] = set()

    for t in threads:
        tid_val = int(t["tid"])
        s_info = t.get("stack_info") or {}
        if s_info.get("status") != "AVAILABLE":
            continue
        s_start = int(s_info.get("start_int") or 0)
        s_end = int(s_info.get("end_int") or 0)
        sp_int = int(s_info.get("sp_int") or 0)
        tcb_int = int(s_info.get("tcb_address_int") or 0)
        if s_start <= 0 or s_end <= s_start:
            continue

        stack_ceiling = (tcb_int - 64) if (s_start < tcb_int <= s_end) else s_end
        if sp_int > 0 and s_start <= sp_int < stack_ceiling:
            scan_from = max(s_start, (sp_int & ~0x7) - 4096)
            scan_to = min(stack_ceiling, scan_from + clamped_stack_scan)
        else:
            scan_to = stack_ceiling
            scan_from = max(s_start, scan_to - clamped_stack_scan)

        if scan_to <= scan_from:
            continue
        scanned_stack_ranges.add((s_start, s_end))
        raw_stack, sst, _ = target_adapter.read_memory(pid, scan_from, scan_to - scan_from)
        if sst != "OBSERVED" or not raw_stack:
            continue

        for pat_bytes, (pat_addr, pat_label) in addr_patterns.items():
            pos = raw_stack.find(pat_bytes)
            if pos != -1:
                stack_ref_addr = scan_from + pos
                _record_thread_match(
                    tid_val,
                    evidence_kind="THREAD_STACK_POINTER_REFERENCE",
                    confidence="HIGH",
                    detail=f"Thread {tid_val} ({t.get('name', 'unknown')}) holds pointer to {pat_label} (0x{pat_addr:x}) on its stack at 0x{stack_ref_addr:x}",
                    extra={
                        "stack_reference_address": f"0x{stack_ref_addr:x}",
                        "points_to": f"0x{pat_addr:x}",
                        "points_to_label": pat_label,
                    },
                )

    # Fallback for pthreads whose stack VMA was not tagged with `syscall` sp (e.g. running on CPU):
    # Scan writable anonymous guard-bounded stack mappings in /proc/<pid>/maps
    mappings = resolved.get("mappings", [])
    for m_i, m in enumerate(mappings):
        if m.get("category") != "anonymous" or not m.get("is_readable") or not m.get("is_writable"):
            continue
        s_start = int(m["start_int"])
        s_end = int(m["end_int"])
        if (s_start, s_end) in scanned_stack_ranges:
            continue
        # Pthread stacks are typically preceded by a `---p` guard mapping and between 64KB and 16MB
        has_guard = (m_i > 0 and mappings[m_i - 1].get("permissions", "").startswith("---"))
        if not has_guard or not (65536 <= (s_end - s_start) <= 16 * 1024 * 1024):
            continue

        scan_from = max(s_start, s_end - clamped_stack_scan)
        raw_stack, sst, _ = target_adapter.read_memory(pid, scan_from, s_end - scan_from)
        if sst != "OBSERVED" or not raw_stack:
            continue

        for pat_bytes, (pat_addr, pat_label) in addr_patterns.items():
            pos = raw_stack.find(pat_bytes)
            if pos != -1:
                stack_ref_addr = scan_from + pos
                # Try to identify which pthread owns this stack by looking for TID in the top 8KB (glibc TCB `struct pthread`)
                inferred_tid = None
                tcb_slice = raw_stack[max(0, len(raw_stack) - 8192):]
                for cand_tid in threads_by_tid:
                    if cand_tid == pid:
                        continue
                    tid_pair = struct.pack("<ii" if endian == "little" else ">ii", cand_tid, pid)
                    if tid_pair in tcb_slice or struct.pack("<i" if endian == "little" else ">i", cand_tid) in tcb_slice:
                        inferred_tid = cand_tid
                        break
                if inferred_tid is not None:
                    _record_thread_match(
                        inferred_tid,
                        evidence_kind="PTHREAD_STACK_POINTER_REFERENCE",
                        confidence="HIGH",
                        detail=f"Thread {inferred_tid} ({threads_by_tid[inferred_tid].get('name', 'unknown')}) holds pointer to {pat_label} (0x{pat_addr:x}) in pthread stack at 0x{stack_ref_addr:x}",
                        extra={
                            "stack_reference_address": f"0x{stack_ref_addr:x}",
                            "points_to": f"0x{pat_addr:x}",
                            "points_to_label": pat_label,
                        },
                    )

    matched_threads = sorted(
        matched_threads_map.values(),
        key=lambda x: (0 if x["confidence"] == "HIGH" else 1, x["tid"]),
    )
    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    decl_loc = f"{canon_t.decl_file}:{canon_t.decl_line}" if (canon_t and canon_t.decl_file) else None

    coerced_meta = resolved.get("coerced_meta") or {}
    return {
        "pid": pid,
        "companion_elf": companion_elf_path,
        "auto_healed_pid": ctx_info.get("auto_healed_pid", False),
        "previous_pid": ctx_info.get("previous_pid"),
        "elf_auto_discovered": ctx_info.get("elf_auto_discovered", False),
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "target_expression": target_expression,
        "resolved_expression": resolved.get("resolved_expression") or target_expression,
        "was_coerced": bool(coerced_meta.get("was_coerced")),
        "coercion_reasons": coerced_meta.get("coercion_reasons") or [],
        "target_runtime_address": f"0x{target_addr:x}",
        "target_size": target_size,
        "target_type": idx.get_type_name(target_type_off),
        "target_decl_location": decl_loc,
        "target_value": target_val,
        "searched_pointer_targets": {f"0x{k:x}": v for k, v in target_addresses.items()},
        "matched_threads_count": len(matched_threads),
        "matched_threads": matched_threads,
        "global_references": global_references,
        "active_threads_checked": len(threads),
        "llm_next_step_hint": (
            f"Found {len(matched_threads)} thread(s) referencing '{target_expression}': "
            + ", ".join(f"TID {m['tid']} ({m['thread_name']})" for m in matched_threads)
            + f". Search the C/C++ codebase for thread entry functions matching '{matched_threads[0]['thread_name']}' or references to '{root_var_name}'."
            if matched_threads
            else f"No active thread stack or owner field currently holds '{target_expression}' (0x{target_addr:x}). The buffer may be free, or its pointer is held only in a volatile CPU register."
        ),
    }


def get_process_xray_blueprint(
    mgr,
    pid: int,
    companion_elf_path: str,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Generates a 1-call Process X-Ray Blueprint for an LLM coding agent:
        categorizes DWARF global/static roots into Memory Pools/Buffers, Thread/Worker Contexts,
        State Machines/Flags, Counters/Metrics, and STL Containers, and provides ready-to-run
        MCP tool call templates.
        """
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    if not primary_elf:
        raise ValueError("Valid companion ELF path is required")

    map_data = mgr._get_process_maps_and_load_bias(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    threads = target_adapter.get_threads(pid)
    idx = DwarfIndexer.get_index(primary_elf)
    load_bias = map_data.get("base_address_int", 0)
    is_dyn = (idx.elf_type == "ET_DYN")

    pools_and_buffers: List[Dict[str, Any]] = []
    worker_contexts: List[Dict[str, Any]] = []
    state_machines: List[Dict[str, Any]] = []
    counters_metrics: List[Dict[str, Any]] = []
    stl_containers: List[Dict[str, Any]] = []

    seen = set()
    for var in idx.variables:
        if var.link_time_address is None or var.is_declaration or not var.name or var.name.startswith("__"):
            continue
        if (var.name, var.link_time_address) in seen:
            continue
        seen.add((var.name, var.link_time_address))

        rt_addr = (load_bias + var.link_time_address) if is_dyn else var.link_time_address
        t_name = idx.get_type_name(var.type_offset)
        canon_t = idx.resolve_canonical_type(var.type_offset)
        stl_info = idx.classify_stl_type(var.type_offset)
        nl = var.name.lower()
        tl = t_name.lower()

        item_summary = {
            "name": var.name,
            "type_name": t_name,
            "runtime_address": f"0x{rt_addr:x}",
            "decl_location": f"{var.decl_file}:{var.decl_line}" if var.decl_file else None,
        }

        if stl_info is not None:
            stl_containers.append({**item_summary, "stl_kind": stl_info["stl_kind"]})

        # Check if pool/buffer struct or array
        is_pool = any(k in nl or k in tl for k in ("pool", "mem", "buf", "slab", "arena", "ring", "slot", "queue"))
        if not is_pool and canon_t:
            if canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and mgr._find_primary_pool_array_member(idx, canon_t) is not None:
                is_pool = True
            elif canon_t.tag == "DW_TAG_pointer_type":
                pt = idx.resolve_canonical_type(canon_t.target_type_offset)
                if pt and pt.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and mgr._find_primary_pool_array_member(idx, pt) is not None:
                    is_pool = True

        if is_pool:
            expr_hint = f"*{var.name}" if (canon_t and canon_t.tag == "DW_TAG_pointer_type") else var.name
            pools_and_buffers.append({**item_summary, "recommended_pool_expression": expr_hint})
        elif any(k in nl or k in tl for k in ("worker", "thread", "task", "ctx", "session", "mgr", "manager", "client")):
            worker_contexts.append(item_summary)
        elif any(k in nl or k in tl for k in ("state", "status", "mode", "flag", "phase", "err", "active", "health")):
            state_machines.append(item_summary)
        elif any(k in nl or k in tl for k in ("count", "cnt", "num", "seq", "total", "retry", "metric", "stat")):
            counters_metrics.append(item_summary)

    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "load_bias": f"0x{load_bias:x}",
        "loaded_debug_modules": map_data.get("loaded_debug_modules", []),
        "threads_count": len(threads),
        "threads": [{"tid": t["tid"], "name": t["name"], "state": t["state"], "sp": (t.get("stack_info") or {}).get("sp")} for t in threads],
        "categories": {
            "memory_pools_and_buffers": pools_and_buffers[:25],
            "thread_and_worker_contexts": worker_contexts[:25],
            "state_machines_and_flags": state_machines[:25],
            "counters_and_metrics": counters_metrics[:25],
            "stl_containers": stl_containers[:25],
        },
        "recommended_mcp_calls": {
            "scan_pool": (
                f"runtime_scan_memory_pool(pid={pid}, companion_elf='{companion_elf_path}', base_expression='{pools_and_buffers[0]['recommended_pool_expression']}')"
                if pools_and_buffers else None
            ),
            "find_owner": (
                f"runtime_find_symbol_owners(pid={pid}, companion_elf='{companion_elf_path}', target_expression='{pools_and_buffers[0]['name']}[0]')"
                if pools_and_buffers else None
            ),
        },
    }


def traverse_linked_structure(
    mgr,
    pid: int,
    companion_elf_path: str,
    head_expression: str,
    next_field: str = "next",
    max_depth: int = 64,
    include_fields: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Walks a non-contiguous pointer chain / linked list / tree (`node->next`) in zero-stop mode.
        Automatically detects pointer cycles (infinite loops) and corrupted/unmapped links (dangling pointers).
        """
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    t_start_ns = time.monotonic_ns()
    head_expr = (head_expression or "").strip()
    if not head_expr:
        raise ValueError("head_expression is required")

    eval_res = mgr.evaluate_symbol_paths(
        pid=pid,
        companion_elf_path=companion_elf_path,
        expressions=[head_expr],
        adapter=target_adapter,
    )
    items = eval_res.get("results", [])
    if not items or items[0].get("status") not in ("OBSERVED", "NULL_POINTER"):
        err_msg = items[0].get("error") if items else "Failed to evaluate head_expression"
        raise ValueError(f"Cannot evaluate head_expression '{head_expr}': {err_msg}")

    head_item = items[0]
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    idx = DwarfIndexer.get_index(primary_elf)
    ptr_size = idx.pointer_size or 8
    endian = idx.endianness or "little"
    ptr_fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")

    # Resolve readable VMA ranges for dangling pointer validation
    map_data = mgr._get_process_maps_and_load_bias(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    readable_ranges: List[Tuple[int, int]] = []
    for m in map_data.get("mappings", []):
        perms = m.get("permissions", "")
        ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
        me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
        if ("r" in perms or m.get("is_readable")) and ms > 0 and me > ms:
            readable_ranges.append((ms, me))

    def _is_readable_addr(addr: int, size: int = 8) -> bool:
        if not readable_ranges:
            return addr > 0x1000
        for rs, re_end in readable_ranges:
            if rs <= addr and (addr + size) <= re_end:
                return True
        return False

    # Determine starting node runtime address and DWARF struct type
    head_type_off = head_item.get("type_offset")
    canon_head = idx.resolve_canonical_type(head_type_off)
    curr_node_addr = 0
    node_struct_type: Any = None

    if head_item.get("status") == "NULL_POINTER":
        curr_node_addr = 0
    elif canon_head and canon_head.tag == "DW_TAG_pointer_type":
        val_str = str(head_item.get("value") or "0x0")
        curr_node_addr = int(val_str, 16) if val_str.startswith("0x") else int(val_str or 0)
        node_struct_type = idx.resolve_canonical_type(canon_head.target_type_offset)
    elif canon_head and canon_head.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
        curr_node_addr = int(head_item.get("runtime_address_int") or int(head_item.get("runtime_address", "0x0"), 16))
        node_struct_type = canon_head
    else:
        raise ValueError(f"head_expression '{head_expr}' does not resolve to a struct or struct pointer (type: {head_item.get('type_name')})")

    if node_struct_type is None or node_struct_type.tag not in ("DW_TAG_structure_type", "DW_TAG_class_type"):
        raise ValueError(f"Could not resolve target struct definition for '{head_expr}'")

    # Locate `next_field` offset inside `node_struct_type` (supports nested e.g. `link.next` or auto-detection)
    next_parts = [p.strip() for p in (next_field or "next").split(".") if p.strip()]
    next_offset: Optional[int] = None
    resolved_next_field = next_field

    curr_t = node_struct_type
    accum_off = 0
    for p_idx, part_name in enumerate(next_parts):
        found_m = next((m for m in curr_t.members if m.name == part_name), None)
        if not found_m:
            accum_off = -1
            break
        accum_off += found_m.offset
        if p_idx == len(next_parts) - 1:
            next_offset = accum_off
        else:
            sub_t = idx.resolve_canonical_type(found_m.type_offset)
            if not sub_t or sub_t.tag not in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                accum_off = -1
                break
            curr_t = sub_t

    if next_offset is None:
        # Auto-detect pointer member named next / p_next / right / link
        for m in node_struct_type.members:
            mc = idx.resolve_canonical_type(m.type_offset)
            if mc and mc.tag == "DW_TAG_pointer_type":
                if m.name in ("next", "p_next", "next_node", "flink", "right", "prev"):
                    next_offset = m.offset
                    resolved_next_field = m.name
                    break
        if next_offset is None:
            for m in node_struct_type.members:
                mc = idx.resolve_canonical_type(m.type_offset)
                if mc and mc.tag == "DW_TAG_pointer_type":
                    next_offset = m.offset
                    resolved_next_field = m.name
                    break

    if next_offset is None:
        raise ValueError(f"Struct '{node_struct_type.name}' has no pointer member matching '{next_field}'")

    node_size = max(ptr_size, min(node_struct_type.byte_size or 64, 4096))
    clamped_max_depth = max(1, min(int(max_depth), 1024))
    inc_set = set(include_fields) if include_fields else None

    nodes: List[Dict[str, Any]] = []
    visited_addr_to_idx: Dict[int, int] = {}
    cycle_detected = False
    cycle_target_address: Optional[str] = None
    cycle_target_index: Optional[int] = None
    corrupted_link_detected = False
    corrupted_address: Optional[str] = None
    termination_reason = "NULL_TERMINATED"

    step = 0
    while curr_node_addr != 0:
        if curr_node_addr in visited_addr_to_idx:
            cycle_detected = True
            cycle_target_address = f"0x{curr_node_addr:x}"
            cycle_target_index = visited_addr_to_idx[curr_node_addr]
            termination_reason = "CYCLE_DETECTED"
            break

        if step >= clamped_max_depth:
            termination_reason = "MAX_DEPTH_REACHED"
            break

        if not _is_readable_addr(curr_node_addr, node_size):
            corrupted_link_detected = True
            corrupted_address = f"0x{curr_node_addr:x}"
            termination_reason = "CORRUPTED_LINK_UNMAPPED"
            break

        raw_node, st, _ = target_adapter.read_memory(pid, curr_node_addr, node_size)
        if st != "OBSERVED" or not raw_node or len(raw_node) < next_offset + ptr_size:
            corrupted_link_detected = True
            corrupted_address = f"0x{curr_node_addr:x}"
            termination_reason = "CORRUPTED_LINK_UNREADABLE"
            break

        visited_addr_to_idx[curr_node_addr] = step

        # Decode scalar/pointer/string members of the node
        node_fields: Dict[str, Any] = {}
        for m in node_struct_type.members:
            if not m.name:
                continue
            if inc_set and m.name not in inc_set and m.name != resolved_next_field:
                continue
            mc = idx.resolve_canonical_type(m.type_offset)
            mt_name = idx.get_type_name(m.type_offset)
            msz = m.byte_size or (mc.byte_size if mc and mc.byte_size else (ptr_size if mc and mc.tag == "DW_TAG_pointer_type" else 4))
            if m.offset + msz <= len(raw_node):
                m_slice = raw_node[m.offset:m.offset + msz]
                if mc and mc.tag == "DW_TAG_pointer_type":
                    if len(m_slice) >= ptr_size:
                        pval = struct.unpack(ptr_fmt, m_slice[:ptr_size])[0]
                        node_fields[m.name] = f"0x{pval:x}"
                elif mc and mc.tag == "DW_TAG_array_type":
                    en = idx.get_type_name(mc.target_type_offset).lower()
                    if en in ("char", "signed char", "unsigned char"):
                        node_fields[m.name] = m_slice.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                elif mc and mc.tag in ("DW_TAG_base_type", "DW_TAG_enumeration_type"):
                    v_dec, derr = decode_value_from_bytes(m_slice, mc.name or mt_name, endian=endian)
                    if derr is None:
                        node_fields[m.name] = v_dec

        next_ptr_val = struct.unpack(ptr_fmt, raw_node[next_offset:next_offset + ptr_size])[0]
        nodes.append({
            "index": step,
            "address": f"0x{curr_node_addr:x}",
            "address_int": curr_node_addr,
            "next_address": f"0x{next_ptr_val:x}",
            "fields": node_fields,
        })

        curr_node_addr = next_ptr_val
        step += 1

    chain_parts = [f"[#{n['index']} @ {n['address']}]" for n in nodes[:16]]
    if len(nodes) > 16:
        chain_parts.append(f"... (+{len(nodes) - 16} nodes)")
    if cycle_detected:
        chain_parts.append(f"🔄 CYCLE -> #{cycle_target_index} ({cycle_target_address})")
    elif corrupted_link_detected:
        chain_parts.append(f"💥 CORRUPTED -> {corrupted_address}")
    elif termination_reason == "NULL_TERMINATED":
        chain_parts.append("NULL (0x0)")

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "head_expression": head_expr,
        "node_type": node_struct_type.name,
        "node_size": node_size,
        "next_field": resolved_next_field,
        "next_field_offset": next_offset,
        "nodes_count": len(nodes),
        "termination_reason": termination_reason,
        "cycle_detected": cycle_detected,
        "cycle_target_index": cycle_target_index,
        "cycle_target_address": cycle_target_address,
        "corrupted_link_detected": corrupted_link_detected,
        "corrupted_address": corrupted_address,
        "ascii_chain_summary": " ➔ ".join(chain_parts),
        "nodes": nodes,
        "llm_next_step_hint": (
            f"CRITICAL: Pointer cycle detected at node #{len(nodes) - 1} pointing back to node #{cycle_target_index} ({cycle_target_address}). Any thread iterating '{head_expr}' will spin in an infinite loop!"
            if cycle_detected
            else (
                f"CRITICAL: Corrupted/dangling link pointer {corrupted_address} detected at node #{len(nodes) - 1} in '{head_expr}'!"
                if corrupted_link_detected
                else f"Successfully traversed {len(nodes)} node(s) in '{head_expr}' ({termination_reason}) without stopping the target."
            )
        ),
    }
