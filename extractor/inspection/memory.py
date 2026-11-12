"""Memory integrity audit (allocator pointer classification), code-pointer resolution and the heap object scanner.

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import os
import struct
import subprocess
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from ..allocator_inspector import PointerClassification, classify_pointer_integrity, detect_allocator
from ..dwarf_indexer import DwarfIndex, DwarfIndexer
from ..target_abi import detect_target_abi
from ..target_adapter import TargetExecutionAdapter
from .process_memory import decode_value_from_bytes


def audit_memory_integrity(
    mgr,
    pid: int,
    companion_elf_path: str,
    target_expressions: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Automated DWARF-guided memory corruption & pointer integrity auditor (zero-stop).
        Detects:
        1. `DANGLING_OR_UNMAPPED_POINTER`: Non-null pointers pointing outside valid `/proc/<pid>/maps` VMAs.
        2. `CORRUPTED_BOOL_VALUE`: `bool` / `_Bool` fields containing raw byte values other than `0` or `1`.
        3. `INVALID_ENUM_VALUE`: `enum` fields holding values outside defined DWARF enumerators.
        4. `POOL_COUNTER_DRIFT`: Memory pool header active count mismatch vs actual allocated slots.
        5. `ORPHANED_THREAD_OWNER_TID`: Struct or mutex `owner_tid` referencing a dead/non-existent thread.
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
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    if not primary_elf:
        raise ValueError("Valid companion ELF path is required")

    map_data = mgr._get_process_maps_and_load_bias(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    load_bias = map_data.get("base_address_int", 0)
    idx = DwarfIndexer.get_index(primary_elf)
    is_dyn = (idx.elf_type == "ET_DYN")
    ptr_size = idx.pointer_size or 8
    endian = idx.endianness or "little"
    ptr_fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")

    mappings = map_data.get("mappings", [])
    # IMP-015: ptmalloc chunk interpretation only on supported (arch, libc) targets
    alloc_detection = detect_allocator(
        maps=mappings, target_abi=detect_target_abi(target_adapter, pid, probe_version=False)
    )
    alloc_inspector = alloc_detection.inspector

    readable_vmas: List[Tuple[int, int]] = []
    for m in mappings:
        perms = m.get("permissions", "")
        ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
        me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
        if ("r" in perms or m.get("is_readable")) and ms > 0 and me > ms:
            readable_vmas.append((ms, me))

    def _is_valid_ptr(p_addr: int) -> bool:
        if p_addr == 0:
            return True
        if not readable_vmas:
            return p_addr >= 0x1000
        return any(vs <= p_addr < ve for vs, ve in readable_vmas)

    threads = target_adapter.get_threads(pid)
    active_tids: Set[int] = {int(t["tid"]) for t in threads}

    # Select expressions to audit
    exprs = list(target_expressions or [])
    if not exprs:
        for var in idx.variables:
            if var.link_time_address is None or var.is_declaration or not var.name or var.name.startswith("__"):
                continue
            canon_t = idx.resolve_canonical_type(var.type_offset)
            if canon_t and canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                exprs.append(var.name)
            elif canon_t and canon_t.tag == "DW_TAG_pointer_type":
                pt = idx.resolve_canonical_type(canon_t.target_type_offset)
                if pt and pt.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                    exprs.append(f"*{var.name}")
                else:
                    exprs.append(var.name)
            if len(exprs) >= 20:
                break

    anomalies: List[Dict[str, Any]] = []
    checked_count = 0

    def _audit_struct_bytes(base_expr: str, base_addr: int, struct_t: Any, raw_bytes: bytes, depth: int = 0) -> None:
        if depth > 2:
            return
        for m in struct_t.members:
            if not m.name:
                continue
            mc = idx.resolve_canonical_type(m.type_offset)
            if not mc:
                continue
            msz = m.byte_size or (mc.byte_size if mc.byte_size else (ptr_size if mc.tag == "DW_TAG_pointer_type" else 4))
            if m.offset + msz > len(raw_bytes):
                continue
            m_slice = raw_bytes[m.offset:m.offset + msz]
            m_expr = f"{base_expr}.{m.name}" if not base_expr.startswith("*") else f"{base_expr[1:]}->{m.name}"
            m_addr = base_addr + m.offset

            # 1. Pointer validity check
            if mc.tag == "DW_TAG_pointer_type" and len(m_slice) >= ptr_size:
                pval = struct.unpack(ptr_fmt, m_slice[:ptr_size])[0]
                if pval != 0:
                    def _mem_reader(a: int, sz: int) -> Optional[bytes]:
                        b, st, _ = target_adapter.read_memory(pid, a, sz)
                        return b if st == "OBSERVED" else None

                    p_res = classify_pointer_integrity(
                        address=pval,
                        maps=mappings,
                        inspector=alloc_inspector,
                        memory_reader=_mem_reader,
                    )
                    if p_res.classification == PointerClassification.OUT_OF_RANGE:
                        anomalies.append({
                            "anomaly_kind": "DANGLING_OR_UNMAPPED_POINTER",
                            "severity": "HIGH",
                            "expression": m_expr,
                            "runtime_address": f"0x{m_addr:x}",
                            "observed_value": f"0x{pval:x}",
                            "expected_constraint": "NULL (0x0) or address within mapped readable VMA",
                            "pointer_classification": p_res.classification.value,
                            "detail": f"Pointer field '{m_expr}' holds unmapped/invalid address 0x{pval:x}: {p_res.reason}",
                        })
                    elif p_res.classification == PointerClassification.FREED_CHUNK:
                        anomalies.append({
                            "anomaly_kind": "USE_AFTER_FREE_POINTER",
                            "severity": "HIGH",
                            "expression": m_expr,
                            "runtime_address": f"0x{m_addr:x}",
                            "observed_value": f"0x{pval:x}",
                            "expected_constraint": "Active allocated object (not freed chunk)",
                            "pointer_classification": p_res.classification.value,
                            "detail": f"Pointer field '{m_expr}' (0x{pval:x}) references freed heap chunk: {p_res.reason}",
                        })

            # 2. Corrupted bool check
            elif mc.tag == "DW_TAG_base_type" and (mc.name or "").lower() in ("bool", "_bool") and len(m_slice) >= 1:
                bval = m_slice[0]
                if bval not in (0, 1):
                    anomalies.append({
                        "anomaly_kind": "CORRUPTED_BOOL_VALUE",
                        "severity": "HIGH",
                        "expression": m_expr,
                        "runtime_address": f"0x{m_addr:x}",
                        "observed_value": bval,
                        "expected_constraint": "0 (false) or 1 (true)",
                        "detail": f"Boolean field '{m_expr}' contains corrupted byte 0x{bval:02x} ({bval}), indicating memory overwrite/overflow",
                    })

            # 3. Invalid enum value check
            elif mc.tag == "DW_TAG_enumeration_type" and mc.enum_values:
                int_t = "int32_t" if msz == 4 else ("int16_t" if msz == 2 else ("int8_t" if msz == 1 else "int64_t"))
                eval_int, e_err = decode_value_from_bytes(m_slice, int_t, endian=endian)
                if e_err is None and eval_int not in mc.enum_values:
                    anomalies.append({
                        "anomaly_kind": "INVALID_ENUM_VALUE",
                        "severity": "MEDIUM",
                        "expression": m_expr,
                        "runtime_address": f"0x{m_addr:x}",
                        "observed_value": eval_int,
                        "expected_constraint": f"One of {dict(list(mc.enum_values.items())[:8])}",
                        "detail": f"Enum field '{m_expr}' has out-of-domain value {eval_int} not defined in '{mc.name}'",
                    })

            # 4. Orphaned thread owner TID check
            elif mc.tag == "DW_TAG_base_type" and any(k in m.name.lower() for k in ("owner_tid", "holder_tid")) and msz == 4:
                tid_val, t_err = decode_value_from_bytes(m_slice, "int32_t", endian=endian)
                if t_err is None and isinstance(tid_val, int) and tid_val > 0 and active_tids and tid_val not in active_tids:
                    anomalies.append({
                        "anomaly_kind": "ORPHANED_THREAD_OWNER_TID",
                        "severity": "HIGH",
                        "expression": m_expr,
                        "runtime_address": f"0x{m_addr:x}",
                        "observed_value": tid_val,
                        "expected_constraint": f"Active thread TID in {sorted(active_tids)} or 0",
                        "detail": f"Field '{m_expr}' references non-existent/dead thread TID {tid_val}",
                    })

            # 5. Recurse into nested structs
            elif mc.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                _audit_struct_bytes(m_expr, m_addr, mc, m_slice, depth + 1)

    read_errors: List[str] = []
    observed_count = 0
    if not mappings:
        read_errors.append(f"Process memory mappings (/proc/{pid}/maps) could not be read.")

    eval_res = mgr.evaluate_symbol_paths(
        pid=pid,
        companion_elf_path=companion_elf_path,
        expressions=exprs,
        adapter=target_adapter,
    )

    for item in eval_res.get("results", []):
        ex = item.get("expression", "")
        checked_count += 1
        if item.get("status") != "OBSERVED":
            read_errors.append(f"Failed to read symbol '{ex}': {item.get('error') or item.get('status')}")
            continue
        observed_count += 1
        rt_addr_str = item.get("runtime_address", "0x0")
        rt_addr = int(rt_addr_str, 16) if rt_addr_str.startswith("0x") else 0
        t_off = item.get("type_offset")
        canon_t = idx.resolve_canonical_type(t_off)
        if not canon_t:
            continue

        if canon_t.tag == "DW_TAG_pointer_type":
            val_str = str(item.get("value") or "0x0")
            pval = int(val_str, 16) if val_str.startswith("0x") else 0
            if pval != 0:
                def _mem_reader(a: int, sz: int) -> Optional[bytes]:
                    b, st, _ = target_adapter.read_memory(pid, a, sz)
                    return b if st == "OBSERVED" else None

                p_res = classify_pointer_integrity(
                    address=pval,
                    maps=mappings,
                    inspector=alloc_inspector,
                    memory_reader=_mem_reader,
                )
                if p_res.classification == PointerClassification.OUT_OF_RANGE:
                    anomalies.append({
                        "anomaly_kind": "DANGLING_OR_UNMAPPED_POINTER",
                        "severity": "HIGH",
                        "expression": ex,
                        "runtime_address": rt_addr_str,
                        "observed_value": val_str,
                        "expected_constraint": "NULL (0x0) or address within mapped readable VMA",
                        "pointer_classification": p_res.classification.value,
                        "detail": f"Pointer '{ex}' points to unmapped/invalid address {val_str}: {p_res.reason}",
                    })
                elif p_res.classification == PointerClassification.FREED_CHUNK:
                    anomalies.append({
                        "anomaly_kind": "USE_AFTER_FREE_POINTER",
                        "severity": "HIGH",
                        "expression": ex,
                        "runtime_address": rt_addr_str,
                        "observed_value": val_str,
                        "expected_constraint": "Active allocated object (not freed chunk)",
                        "pointer_classification": p_res.classification.value,
                        "detail": f"Pointer '{ex}' ({val_str}) references freed heap chunk: {p_res.reason}",
                    })
        elif canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and rt_addr > 0:
            bsize = max(1, min(canon_t.byte_size or 64, 16384))
            try:
                raw_s, sst, s_err = target_adapter.read_memory(pid, rt_addr, bsize)
            except Exception as s_exc:
                raw_s, sst, s_err = None, "READ_ERROR", f"{type(s_exc).__name__}: {s_exc}"
            if sst != "OBSERVED" or not raw_s:
                read_errors.append(f"Failed to read struct '{ex}' at 0x{rt_addr:x}: {s_err or sst}")
            if sst == "OBSERVED" and raw_s:
                _audit_struct_bytes(ex, rt_addr, canon_t, raw_s, depth=0)

                # Check if this struct is a memory pool with an array member + active counter
                pool_arr_m = mgr._find_primary_pool_array_member(idx, canon_t)
                if pool_arr_m is not None:
                    try:
                        pool_scan = mgr.scan_memory_pool_or_array(
                            pid=pid,
                            companion_elf_path=companion_elf_path,
                            base_expression=ex,
                            adapter=target_adapter,
                        )
                        actual_alloc = pool_scan["pool_summary"]["allocated_count"]
                        meta = pool_scan.get("pool_metadata") or {}
                        for mk, mv in meta.items():
                            if any(w in mk.lower() for w in ("active", "used", "alloc")) and isinstance(mv, int):
                                if mv != actual_alloc:
                                    anomalies.append({
                                        "anomaly_kind": "POOL_COUNTER_DRIFT",
                                        "severity": "MEDIUM",
                                        "expression": f"{ex}.{mk}",
                                        "runtime_address": rt_addr_str,
                                        "observed_value": mv,
                                        "expected_constraint": f"Matches actual allocated slot count ({actual_alloc})",
                                        "detail": f"Pool header counter '{mk}' reports {mv}, but {actual_alloc} slot(s) are marked IN_USE in '{pool_scan['resolved_array_expression']}'",
                                    })
                        # Also audit individual allocated slots in the pool
                        elem_t = idx.resolve_canonical_type(
                            idx.resolve_canonical_type(pool_arr_m.type_offset).target_type_offset  # type: ignore[union-attr]
                        )
                        if elem_t and elem_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                            for s_item in pool_scan.get("slots", []):
                                s_addr = int(s_item["runtime_address_int"])
                                s_sz = int(s_item["size"])
                                s_raw, s_st, _ = target_adapter.read_memory(pid, s_addr, s_sz)
                                if s_st == "OBSERVED" and s_raw:
                                    _audit_struct_bytes(s_item["expression"], s_addr, elem_t, s_raw, depth=1)
                    except Exception as pool_exc:
                        read_errors.append(f"Failed to scan memory pool '{ex}': {type(pool_exc).__name__}: {pool_exc}")

    if anomalies:
        audit_health_status = "ANOMALIES_DETECTED"
    elif not mappings or (exprs and observed_count == 0) or (read_errors and observed_count == 0):
        audit_health_status = "INCONCLUSIVE"
    else:
        # an observation status of this scan, not a verdict (verdicts come from diagnose())
        audit_health_status = "NO_ANOMALY_FOUND"

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "health_status": audit_health_status,
        "limitations": read_errors,
        "allocator": alloc_detection.allocator_type.value,
        "allocator_confidence": alloc_detection.confidence,
        "allocator_support_status": alloc_detection.support_status,
        "allocator_basis": alloc_detection.basis,
        "checked_symbols_count": checked_count,
        "observed_symbols_count": observed_count,
        "anomalies_count": len(anomalies),
        "anomalies": anomalies,
        "llm_next_step_hint": (
            f"Detected {len(anomalies)} memory integrity anomaly(ies): "
            + "; ".join(f"[{a['anomaly_kind']}] {a['expression']} = {a['observed_value']}" for a in anomalies[:5])
            if anomalies
            else (
                f"Memory integrity audit inconclusive: {observed_count}/{checked_count} symbol(s) observed ({'; '.join(read_errors[:3])})."
                if audit_health_status == "INCONCLUSIVE"
                else f"All {observed_count} audited symbol(s) and memory pool slots passed DWARF pointer/enum/boolean/owner integrity checks."
            )
        ),
    }


def resolve_code_pointers(
    mgr,
    pid: int,
    companion_elf_path: str,
    expressions: List[str],
    vtable_slots: int = 6,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Resolves function pointers, callback struct fields, or C++ polymorphic object `_vptr` / `vtable`
        entries to exact C/C++ function names and DWARF source `file:line` locations (zero-stop).
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
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    if not primary_elf:
        raise ValueError("Valid companion ELF path is required")

    map_data = mgr._get_process_maps_and_load_bias(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    load_bias = map_data.get("base_address_int", 0)
    primary_idx = DwarfIndexer.get_index(primary_elf)
    ptr_size = primary_idx.pointer_size or 8
    endian = primary_idx.endianness or "little"
    ptr_fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")

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

    def _resolve_pc(rt_pc: int) -> Optional[Dict[str, Any]]:
        if rt_pc <= 0:
            return None
        for mod_name, m_idx, m_bias, m_dyn in module_contexts:
            lt_pc = (rt_pc - m_bias) if m_dyn else rt_pc
            if lt_pc <= 0:
                continue
            res = m_idx.resolve_code_address(lt_pc)
            if res is not None:
                return {"runtime_address": f"0x{rt_pc:x}", "module": mod_name, **res}
        return None

    results: List[Dict[str, Any]] = []
    for expr in expressions:
        ex_s = (expr or "").strip()
        if not ex_s:
            continue

        # Case 1: Raw hex instruction/function address
        if ex_s.startswith("0x") or ex_s.startswith("0X"):
            try:
                pc_val = int(ex_s, 16)
                sym = _resolve_pc(pc_val)
                results.append({
                    "expression": ex_s,
                    "kind": "RAW_CODE_ADDRESS",
                    "resolved": sym,
                })
                continue
            except ValueError:
                pass

        # Case 2: Symbol expression (function pointer, struct with callbacks, or C++ object with _vptr)
        eval_out = mgr.evaluate_symbol_paths(
            pid=pid,
            companion_elf_path=companion_elf_path,
            expressions=[ex_s],
            adapter=target_adapter,
        ).get("results", [])

        if not eval_out or eval_out[0].get("status") != "OBSERVED":
            results.append({
                "expression": ex_s,
                "kind": "UNRESOLVED",
                "error": eval_out[0].get("error") if eval_out else "Evaluation failed",
            })
            continue

        item = eval_out[0]
        val = item.get("value")
        rt_addr_str = item.get("runtime_address", "0x0")
        rt_addr = int(rt_addr_str, 16) if rt_addr_str.startswith("0x") else 0

        if isinstance(val, str) and val.startswith("0x"):
            ptr_val = int(val, 16)
            sym = _resolve_pc(ptr_val)
            if sym is not None:
                results.append({
                    "expression": ex_s,
                    "kind": "FUNCTION_POINTER",
                    "pointer_storage_address": rt_addr_str,
                    "target_code_address": val,
                    "resolved": sym,
                })
                continue

        # Check if it's a struct containing function pointer fields OR a C++ polymorphic object with `_vptr` at offset 0
        resolved_members: Dict[str, Any] = {}
        vtable_entries: List[Dict[str, Any]] = []

        if isinstance(val, dict):
            for mk, mv in val.items():
                if isinstance(mv, str) and mv.startswith("0x") and mv != "0x0":
                    try:
                        m_ptr = int(mv, 16)
                        if mk.startswith("_vptr"):
                            # Read vtable slots!
                            raw_vt, vt_st, _ = target_adapter.read_memory(pid, m_ptr, ptr_size * max(1, min(vtable_slots, 16)))
                            if vt_st == "OBSERVED" and raw_vt:
                                for s_i in range(len(raw_vt) // ptr_size):
                                    fn_ptr = struct.unpack_from(ptr_fmt, raw_vt, s_i * ptr_size)[0]
                                    fn_sym = _resolve_pc(fn_ptr)
                                    if not fn_sym:
                                        break
                                    vtable_entries.append({
                                        "slot_index": s_i,
                                        "vtable_entry_address": f"0x{m_ptr + s_i * ptr_size:x}",
                                        **fn_sym,
                                    })
                        else:
                            m_sym = _resolve_pc(m_ptr)
                            if m_sym is not None:
                                resolved_members[mk] = m_sym
                    except ValueError:
                        pass

        # Even if DWARF didn't expose `_vptr` in `val` dict, inspect the first pointer at `rt_addr` for a C++ vtable
        if not vtable_entries and rt_addr > 0:
            raw_first, fst, _ = target_adapter.read_memory(pid, rt_addr, ptr_size)
            if fst == "OBSERVED" and raw_first and len(raw_first) >= ptr_size:
                cand_vptr = struct.unpack(ptr_fmt, raw_first[:ptr_size])[0]
                if cand_vptr > 0x1000:
                    raw_vt, vt_st, _ = target_adapter.read_memory(pid, cand_vptr, ptr_size * max(1, min(vtable_slots, 16)))
                    if vt_st == "OBSERVED" and raw_vt:
                        for s_i in range(len(raw_vt) // ptr_size):
                            fn_ptr = struct.unpack_from(ptr_fmt, raw_vt, s_i * ptr_size)[0]
                            fn_sym = _resolve_pc(fn_ptr)
                            if not fn_sym:
                                break
                            vtable_entries.append({
                                "slot_index": s_i,
                                "vtable_entry_address": f"0x{cand_vptr + s_i * ptr_size:x}",
                                **fn_sym,
                            })

        results.append({
            "expression": ex_s,
            "kind": "POLYMORPHIC_VTABLE" if vtable_entries else ("STRUCT_CALLBACKS" if resolved_members else "VALUE"),
            "runtime_address": rt_addr_str,
            "vtable_entries": vtable_entries,
            "resolved_function_members": resolved_members,
        })

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "results": results,
    }


def scan_heap_objects(
    mgr,
    pid: int,
    companion_elf_path: str,
    class_filter: Optional[str] = None,
    max_scan_bytes: int = 524288,
    max_objects: int = 64,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Zero-stop C++ polymorphic `vtable` (`_ZTV*`) heap & data segment object census + leak detector (zero-stop).
        1. Discovers all C++ `vtable for <ClassName>` symbols in the ELF binary and computes their relocated runtime `_vptr` addresses.
        2. Scans `[heap]` (and `.data`/`.bss`) for matching `_vptr` headers to locate live polymorphic objects and decodes their DWARF fields.
        3. Checks whether each `[heap]` object is referenced by any global pointer, thread stack, or other heap object; flags unreferenced heap objects as `is_leaked_candidate = True`.
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
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    if not primary_elf:
        raise ValueError("Valid companion ELF path is required")

    map_data = mgr._get_process_maps_and_load_bias(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    load_bias = map_data.get("base_address_int", 0)
    idx = DwarfIndexer.get_index(primary_elf)
    is_dyn = (idx.elf_type == "ET_DYN")
    ptr_size = idx.pointer_size or 8
    endian = idx.endianness or "little"
    ptr_fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")

    # 1. Extract `vtable for <ClassName>` from nm -C -n
    vtable_map: Dict[int, str] = {}
    flt = (class_filter or "").strip().lower()
    try:
        proc = subprocess.run(
            ["nm", "-C", "-n", primary_elf],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if "vtable for " not in line:
                    continue
                parts = line.strip().split(None, 2)
                if len(parts) < 3:
                    continue
                try:
                    lt_vt = int(parts[0], 16)
                except ValueError:
                    continue
                cls_name = parts[2].split("vtable for ", 1)[1].strip()
                if any(skip in cls_name for skip in ("__cxxabiv1", "std::", "type_info")):
                    continue
                if flt and flt not in cls_name.lower():
                    continue
                rt_vt = (load_bias + lt_vt) if is_dyn else lt_vt
                # In Itanium C++ ABI, object _vptr points to vtable + 2 * ptr_size (+16 on 64-bit)
                vtable_map[rt_vt + 2 * ptr_size] = cls_name
                vtable_map[rt_vt] = cls_name
    except Exception:
        pass

    # Collect readable writable data/heap segments and thread stack segments
    all_mappings = map_data.get("mappings", [])
    heap_vmas: List[Tuple[int, int]] = []
    data_vmas: List[Tuple[int, int]] = []
    main_base = os.path.basename(primary_elf)

    for m in all_mappings:
        perms = m.get("permissions", "")
        if "r" not in perms or "w" not in perms:
            continue
        ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
        me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
        pname = m.get("pathname") or ""
        cat = m.get("category") or ""
        if pname == "[heap]" or cat == "heap":
            heap_vmas.append((ms, me))
        elif main_base in pname:
            data_vmas.append((ms, me))

    clamped_max_scan = max(16384, min(int(max_scan_bytes), 2 * 1024 * 1024))

    # Read data segments & thread stacks first so we can both scan and check incoming pointers
    reference_buffers: List[Tuple[str, int, bytes]] = []
    for ds, de in data_vmas:
        sz = min(de - ds, 262144)
        raw_d, st_d, _ = target_adapter.read_memory(pid, ds, sz)
        if st_d == "OBSERVED" and raw_d:
            reference_buffers.append(("global_data", ds, raw_d))

    exec_ranges: List[Tuple[int, int]] = []
    for m in all_mappings:
        if "x" in (m.get("permissions") or "") and main_base in (m.get("pathname") or ""):
            ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
            me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
            exec_ranges.append((ms, me))

    def _trim_dead_stack(base_a: int, buf: bytes, known_sp: int) -> Tuple[int, bytes]:
        if known_sp > base_a or not exec_ranges:
            return base_a, buf
        nw = len(buf) // ptr_size
        for w_idx in range(nw):
            w_val = struct.unpack_from(ptr_fmt, buf, w_idx * ptr_size)[0]
            if any(es <= w_val < ee for es, ee in exec_ranges):
                active_off = max(0, w_idx * ptr_size - 128)
                return base_a + active_off, buf[active_off:]
        return base_a, buf

    for t in target_adapter.get_threads(pid):
        s_info = t.get("stack_info") or {}
        ss = int(s_info.get("start_int") or 0)
        se = int(s_info.get("end_int") or 0)
        sp_i = int(s_info.get("sp_int") or 0)
        if se > ss > 0:
            from_a = sp_i if (sp_i > 0 and ss <= sp_i < se) else max(ss, se - 32768)
            raw_s, st_s, _ = target_adapter.read_memory(pid, from_a, se - from_a)
            if st_s == "OBSERVED" and raw_s:
                trim_a, trim_s = _trim_dead_stack(from_a, raw_s, sp_i)
                reference_buffers.append((f"stack:TID_{t['tid']}", trim_a, trim_s))

    # Also include pthread anonymous guard-bounded stacks
    for m_i, m in enumerate(all_mappings):
        perms = m.get("permissions", "")
        if m.get("category") != "anonymous" or "r" not in perms or "w" not in perms:
            continue
        ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
        me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
        has_guard = (m_i > 0 and all_mappings[m_i - 1].get("permissions", "").startswith("---"))
        if has_guard and (65536 <= (me - ms) <= 16 * 1024 * 1024):
            from_a = max(ms, me - 32768)
            raw_s, st_s, _ = target_adapter.read_memory(pid, from_a, me - from_a)
            if st_s == "OBSERVED" and raw_s:
                reference_buffers.append(("pthread_stack", from_a, raw_s))

    heap_buffers: List[Tuple[int, bytes]] = []
    scanned_heap_bytes = 0
    for hs, he in heap_vmas:
        if scanned_heap_bytes >= clamped_max_scan:
            break
        to_read = min(he - hs, clamped_max_scan - scanned_heap_bytes)
        raw_h, st_h, _ = target_adapter.read_memory(pid, hs, to_read)
        if st_h == "OBSERVED" and raw_h:
            heap_buffers.append((hs, raw_h))
            scanned_heap_bytes += len(raw_h)

    discovered_objects: List[Dict[str, Any]] = []
    class_histogram: Dict[str, Dict[str, int]] = {}

    def _scan_region_for_vtables(region_kind: str, base_addr: int, buf: bytes) -> None:
        if not vtable_map:
            return
        n_words = len(buf) // ptr_size
        for w_i in range(n_words):
            if len(discovered_objects) >= max_objects:
                break
            word_val = struct.unpack_from(ptr_fmt, buf, w_i * ptr_size)[0]
            cls_name = vtable_map.get(word_val)
            if not cls_name:
                continue
            obj_addr = base_addr + w_i * ptr_size
            d_type = idx.resolve_type_by_name(cls_name)
            obj_size = d_type.byte_size if (d_type and d_type.byte_size) else (2 * ptr_size)

            decoded_val = None
            if d_type is not None:
                decoded_val, _, _, _ = mgr._decode_typed_memory(
                    adapter=target_adapter,
                    pid=pid,
                    idx=idx,
                    addr=obj_addr,
                    type_offset=d_type.die_offset,
                    depth=0,
                    max_struct_depth=2,
                )

            # Check if `obj_addr` is referenced anywhere in globals, thread stacks, or other heap locations
            pat = struct.pack(ptr_fmt, obj_addr)
            ref_sources: List[str] = []
            for ref_label, ref_base, ref_buf in reference_buffers:
                pos = ref_buf.find(pat)
                if pos != -1 and (ref_base + pos) != obj_addr:
                    ref_sources.append(f"{ref_label}@0x{ref_base + pos:x}")
            for h_base, h_buf in heap_buffers:
                pos = h_buf.find(pat)
                while pos != -1:
                    ref_at = h_base + pos
                    if not (obj_addr <= ref_at < obj_addr + max(8, obj_size)):
                        ref_sources.append(f"heap@0x{ref_at:x}")
                        break
                    pos = h_buf.find(pat, pos + ptr_size)

            is_heap = (region_kind == "heap")
            is_leaked = is_heap and (len(ref_sources) == 0)

            hist = class_histogram.setdefault(cls_name, {"total": 0, "on_heap": 0, "on_global": 0, "leaked_candidates": 0})
            hist["total"] += 1
            if is_heap:
                hist["on_heap"] += 1
            else:
                hist["on_global"] += 1
            if is_leaked:
                hist["leaked_candidates"] += 1

            discovered_objects.append({
                "class_name": cls_name,
                "address": f"0x{obj_addr:x}",
                "address_int": obj_addr,
                "byte_size": obj_size,
                "region": region_kind,
                "vptr_target": f"0x{word_val:x}",
                "is_referenced": len(ref_sources) > 0,
                "referenced_by": ref_sources[:5],
                "is_leaked_candidate": is_leaked,
                "fields": decoded_val,
            })

    for hs, h_buf in heap_buffers:
        _scan_region_for_vtables("heap", hs, h_buf)
    for ref_label, ds, d_buf in reference_buffers:
        if ref_label == "global_data":
            _scan_region_for_vtables("global_data", ds, d_buf)

    leaked_cnt = sum(1 for o in discovered_objects if o.get("is_leaked_candidate"))
    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "scanned_heap_bytes": scanned_heap_bytes,
        "known_polymorphic_classes": sorted(set(vtable_map.values())),
        "total_objects_found": len(discovered_objects),
        "leaked_candidates_count": leaked_cnt,
        "class_histogram": class_histogram,
        "objects": discovered_objects,
        "llm_next_step_hint": (
            f"Detected {leaked_cnt} unreachable/leaked C++ heap object(s) out of {len(discovered_objects)} live polymorphic instance(s)!"
            if leaked_cnt > 0
            else f"Scanned {scanned_heap_bytes} heap bytes and found {len(discovered_objects)} live C++ polymorphic object(s) with 0 unreachable leaks."
        ),
    }
