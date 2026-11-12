"""Thread-local storage: thread-pointer / TCB discovery (x86_64 and aarch64 glibc), TLS variable decoding, and the
concurrent-read consistency verifier.

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import json
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from ..dwarf_indexer import DwarfIndexer
from ..target_abi import (
    FEATURE_TCB_SCAN,
    SUPPORT_NOT_SUPPORTED_ON_TARGET,
    TargetABI,
    check_support,
    detect_target_abi,
)
from ..target_adapter import TargetExecutionAdapter


def _tls_first_block_offset_aarch64(tls_align: Optional[int]) -> int:
    """aarch64 glibc (TLS variant I): the executable's static TLS block starts `roundup(16, p_align)` bytes
        above the thread pointer (TLS_TCB_SIZE == 16: the two-word `tcbhead_t` {dtv, private})."""
    align = max(1, int(tls_align or 1))
    return (16 + align - 1) // align * align


def _discover_thread_pointers_aarch64(
    mgr,
    pid: int,
    target_adapter: TargetExecutionAdapter,
    all_mappings: List[Dict[str, Any]],
    target_tids: set,
    tls_align: Optional[int] = None,
) -> Dict[int, int]:
    """aarch64/glibc thread pointers (TPIDR_EL0) without stopping or tracing any thread.

        aarch64 glibc uses TLS variant I: `tp` points at `tcbhead_t {void *dtv; void *private;}` and the
        `struct pthread` lies *before* it (`pthread_self() == tp - sizeof(struct pthread)`), the static TLS
        blocks after it.  `struct pthread` and the static TLS are allocated at the top of a pthread-created
        thread's stack mapping and in the initial TLS mapping (anonymous, or `[heap]` for static executables)
        for the main thread.  Neither `sizeof(struct pthread)` nor the offset of `tid` inside it is stable across
        glibc versions, so the layout is derived from invariants instead of a version table:

        1. the thread's own TID (an int32) is located in the stack-top / initial-TLS window;
        2. the thread pointer is the 16-byte aligned address T above it whose first word is the `dtv`
           pointer into readable memory, and whose `dtv[1].val` (the first static TLS block, 16 bytes per
           dtv slot, dtv[0] = generation) is a TLS block above T inside the same mapping; when the executable's
           PT_TLS alignment is known `dtv[1].val` must equal exactly T + roundup(16, p_align);
        3. every thread of one process shares the same T - &tid distance; threads that disagree with the
           majority are discarded.

        Returns {tid: thread pointer}; threads that cannot be validated are simply absent.
        """
    import bisect
    readable: List[Tuple[int, int]] = []
    for m in all_mappings:
        perms = m.get("permissions") or m.get("perms") or ""
        if "r" not in perms:
            continue
        ms = int(m["start_int"]) if m.get("start_int") is not None else int(str(m.get("start", "0")), 16)
        me = int(m["end_int"]) if m.get("end_int") is not None else int(str(m.get("end", "0")), 16)
        readable.append((ms, me))
    readable.sort()
    starts = [r[0] for r in readable]

    def containing(addr: int) -> Optional[Tuple[int, int]]:
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0 and readable[i][0] <= addr < readable[i][1]:
            return readable[i]
        return None

    dtv_cache: Dict[int, Optional[int]] = {}

    def dtv_first_block(dtv_addr: int) -> Optional[int]:
        """dtv[1].val if `dtv_addr` looks like a glibc dtv: dtv[-1].counter (slot count) and dtv[0].counter
            (generation) are small integers; each slot is 16 bytes (`{void *val; void *to_free;}`)."""
        if dtv_addr not in dtv_cache:
            val = None
            raw, st, _ = target_adapter.read_memory(pid, dtv_addr - 16, 48)
            if st == "OBSERVED" and raw and len(raw) >= 40:
                n_slots = struct.unpack_from("<Q", raw, 0)[0]
                generation = struct.unpack_from("<Q", raw, 16)[0]
                if 1 <= n_slots <= 0x100000 and generation < (1 << 32):
                    val = struct.unpack_from("<Q", raw, 32)[0]
            dtv_cache[dtv_addr] = val
        return dtv_cache[dtv_addr]

    first_off = mgr._tls_first_block_offset_aarch64(tls_align) if tls_align else None

    def find_tp(raw: bytes, win_base: int, tid_idx: int) -> Optional[int]:
        lo = (win_base + tid_idx + 0x40 + 15) & ~15
        hi = min(win_base + tid_idx + 0x4000, win_base + len(raw) - 16)
        for t_addr in range(lo, hi + 1, 16):
            idx = t_addr - win_base
            dtv = struct.unpack_from("<Q", raw, idx)[0]
            if dtv < 0x10000 or dtv % 8 or containing(dtv) is None:
                continue
            block = dtv_first_block(dtv)
            if block is None:
                continue
            if first_off is not None:
                if block != t_addr + first_off:
                    continue
            else:
                region = containing(t_addr)
                if not (t_addr + 16 <= block < (region[1] if region else 0)) or block % 8:
                    continue
            return t_addr
        return None

    windows: List[Tuple[int, int]] = []
    for m in all_mappings:
        perms = m.get("permissions") or m.get("perms") or ""
        if "r" not in perms or "w" not in perms:
            continue
        path = (m.get("pathname") or m.get("path") or "").strip()
        if path and not path.startswith("[stack") and path != "[heap]":
            continue
        ms = int(m["start_int"]) if m.get("start_int") is not None else int(str(m.get("start", "0")), 16)
        me = int(m["end_int"]) if m.get("end_int") is not None else int(str(m.get("end", "0")), 16)
        size = me - ms
        if size < 4096:
            continue
        if size <= (1 << 20):
            windows.append((ms, size))
        else:
            windows.append((me - (256 << 10), 256 << 10))
            if path == "[heap]":
                windows.append((ms, 64 << 10))

    patterns = {tid: struct.pack("<i", tid) for tid in target_tids}
    candidates: Dict[int, set] = {tid: set() for tid in target_tids}  # tid -> {(tp, tp - &tid)}
    for win_base, win_len in windows:
        if all(candidates.values()):
            break
        raw, st, _ = target_adapter.read_memory(pid, win_base, win_len)
        if st != "OBSERVED" or not raw or len(raw) < 64:
            continue
        for tid, pat in patterns.items():
            pos = raw.find(pat)
            while pos != -1:
                if (win_base + pos) % 4 == 0:
                    t_addr = find_tp(raw, win_base, pos)
                    if t_addr is not None:
                        candidates[tid].add((t_addr, t_addr - (win_base + pos)))
                pos = raw.find(pat, pos + 1)

    # A stray copy of a TID in the window can pair with a wrong thread pointer; the real
    # `tp - &struct pthread.tid` distance is the same in every thread of the process, so vote on it.
    votes: Dict[int, int] = {}
    for cands in candidates.values():
        for dist in {d for _tp, d in cands}:
            votes[dist] = votes.get(dist, 0) + 1
    if not votes:
        return {}
    best = max(votes, key=lambda d: (votes[d], -d))
    result: Dict[int, int] = {}
    for tid, cands in candidates.items():
        tps = {tp for tp, d in cands if d == best}
        if len(tps) == 1:
            result[tid] = tps.pop()
    return result


def _discover_thread_tcb_addresses(
    mgr,
    pid: int,
    target_adapter: TargetExecutionAdapter,
    all_mappings: List[Dict[str, Any]],
    threads: List[Dict[str, Any]],
    ptr_size: int = 8,
    endian: str = "<",
    target_abi: Optional[TargetABI] = None,
    tls_align: Optional[int] = None,
) -> Dict[int, int]:
    """Discovers each thread's glibc TCB (`struct pthread *` / `fs_base`) in zero-stop mode.

        aarch64/glibc dispatches to `_discover_thread_pointers_aarch64` (thread pointer == TPIDR_EL0); the
        description below is the x86_64 algorithm.
        
        Uses the deterministic glibc `tcbhead_t` self-pointer invariant:
        - `*(uint64_t *)(tcb_addr + 0x00) == tcb_addr` (`header.tcb`)
        - `*(uint64_t *)(tcb_addr + 2 * ptr_size) == tcb_addr` (`header.self`)
        combined with the embedded `pid_t tid` (`int32_t`) field inside `struct pthread` (`[tcb_addr + 0x40, tcb_addr + 0x600)`).
        """
    tcb_by_tid: Dict[int, int] = {}
    # IMP-015: tcbhead_t self-pointer + struct pthread tid offsets are the glibc x86_64 layout.
    # On any other target return nothing (callers report the support decision) instead of garbage.
    if target_abi is None:
        target_abi = detect_target_abi(target_adapter, pid, probe_version=False)
    if not check_support(target_abi, FEATURE_TCB_SCAN).supported:
        return tcb_by_tid
    target_tids = {int(t["tid"]) for t in threads if "tid" in t}
    if not target_tids:
        return tcb_by_tid
    if target_abi.architecture == "aarch64":
        return mgr._discover_thread_pointers_aarch64(
            pid, target_adapter, all_mappings, target_tids, tls_align=tls_align,
        )

    ptr_fmt = endian + ("Q" if ptr_size == 8 else "I")
    candidate_tcbs: List[Tuple[int, bytes]] = []
    seen_tcb_addrs = set()

    # Scan candidate regions in writable anonymous VMAs (thread stack tops + ld.so TCB allocations)
    for m in all_mappings:
        perms = m.get("permissions") or m.get("perms") or ""
        if "r" not in perms or "w" not in perms:
            continue
        path = (m.get("pathname") or m.get("path") or "").strip()
        if path and not path.startswith("[stack"):
            continue
        vma_start = int(m["start_int"]) if m.get("start_int") is not None else int(str(m.get("start", "0")), 16)
        vma_end = int(m["end_int"]) if m.get("end_int") is not None else int(str(m.get("end", "0")), 16)
        vma_size = vma_end - vma_start
        if vma_size < 4096:
            continue

        scan_windows: List[Tuple[int, int]] = []
        # 1. Top 24KB of VMA (where pthread_create places struct pthread + TCB above stack)
        top_start = max(vma_start, vma_end - 24576)
        scan_windows.append((top_start, vma_end - top_start))
        # 2. If small anonymous VMA (<= 512KB), also scan bottom 32KB (where ld.so places main thread TCB)
        if vma_size <= 524288 and top_start > vma_start:
            bot_len = min(32768, top_start - vma_start)
            scan_windows.append((vma_start, bot_len))

        for win_base, win_len in scan_windows:
            if win_len < 64:
                continue
            raw, r_st, _ = target_adapter.read_memory(pid, win_base, win_len)
            if r_st != "OBSERVED" or not raw or len(raw) < 64:
                continue
            limit = len(raw) - 3 * ptr_size
            for off in range(0, limit, ptr_size):
                cand_addr = win_base + off
                if cand_addr in seen_tcb_addrs:
                    continue
                try:
                    w0 = struct.unpack_from(ptr_fmt, raw, off)[0]
                    if w0 != cand_addr:
                        continue
                    w2 = struct.unpack_from(ptr_fmt, raw, off + 2 * ptr_size)[0]
                    if w2 != cand_addr:
                        continue
                except Exception:
                    continue
                seen_tcb_addrs.add(cand_addr)
                tcb_struct_bytes = raw[off : off + 1536]
                if len(tcb_struct_bytes) < 1024:
                    extra, ex_st, _ = target_adapter.read_memory(pid, cand_addr, 1536)
                    if ex_st == "OBSERVED" and extra:
                        tcb_struct_bytes = extra
                candidate_tcbs.append((cand_addr, tcb_struct_bytes))

    # Match candidate TCBs to thread TIDs
    unmatched_tcbs: List[int] = []
    for cand_addr, tcb_bytes in candidate_tcbs:
        matched_tid: Optional[int] = None
        if len(tcb_bytes) >= 0x2d4:
            val_2d0 = struct.unpack_from(endian + "i", tcb_bytes, 0x2d0)[0]
            if val_2d0 in target_tids and val_2d0 not in tcb_by_tid:
                matched_tid = val_2d0
        if matched_tid is None:
            for off in range(0x40, min(len(tcb_bytes) - 4, 0x580), 4):
                val = struct.unpack_from(endian + "i", tcb_bytes, off)[0]
                if val in target_tids and val not in tcb_by_tid:
                    matched_tid = val
                    break
        if matched_tid is not None:
            tcb_by_tid[matched_tid] = cand_addr
        else:
            unmatched_tcbs.append(cand_addr)

    remaining_tids = [t_id for t_id in target_tids if t_id not in tcb_by_tid]
    if len(remaining_tids) == 1 and len(unmatched_tcbs) == 1:
        tcb_by_tid[remaining_tids[0]] = unmatched_tcbs[0]

    return tcb_by_tid


def inspect_thread_local_storage(
    mgr,
    pid: int,
    companion_elf_path: str,
    tid: Optional[int] = None,
    variable_names: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Zero-Stop Per-Thread TLS (`__thread` / `thread_local`) Variable Decoder."""
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
    idx = DwarfIndexer.get_index(primary_elf)
    target_abi = detect_target_abi(target_adapter, pid)
    tcb_support = check_support(target_abi, FEATURE_TCB_SCAN)
    ptr_size = idx.pointer_size
    endian = "<" if idx.endianness == "little" else ">"

    pt_tls = idx.pt_tls
    if pt_tls is None and not target_adapter.is_remote():
        try:
            from ..debug_image import inspect_elf
            rt_ident = inspect_elf(f"/proc/{pid}/exe")
            pt_tls = rt_ident.pt_tls
        except Exception:
            pt_tls = None

    seen_tls_names = set()
    tls_vars = []
    name_filter = {n.strip() for n in (variable_names or []) if n and n.strip()}
    for v in idx.tls_variables:
        if not v.name or v.tls_offset is None:
            continue
        if name_filter and v.name not in name_filter and not any(f in v.name for f in name_filter):
            continue
        if (v.name, v.tls_offset) in seen_tls_names:
            continue
        seen_tls_names.add((v.name, v.tls_offset))
        tls_vars.append(v)

    tls_vars.sort(key=lambda v: (v.tls_offset or 0, v.name))

    if pt_tls and pt_tls.get("p_memsz", 0) > 0:
        tls_memsz = int(pt_tls["p_memsz"])
        tls_align = max(1, int(pt_tls.get("p_align", 8)))
        aligned_tls_memsz = (tls_memsz + tls_align - 1) & ~(tls_align - 1)
    else:
        max_end = 0
        for v in tls_vars:
            canon_t = idx.resolve_canonical_type(v.type_offset)
            v_sz = canon_t.byte_size if (canon_t and canon_t.byte_size) else 8
            max_end = max(max_end, int(v.tls_offset or 0) + v_sz)
        tls_memsz = max_end
        tls_align = 8
        aligned_tls_memsz = (tls_memsz + tls_align - 1) & ~(tls_align - 1)

    map_data = mgr._get_process_maps_and_load_bias(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    all_mappings = map_data.get("mappings", [])
    threads = target_adapter.get_threads(pid)
    if tid is not None:
        threads = [t for t in threads if int(t["tid"]) == int(tid)]

    tcb_by_tid = mgr._discover_thread_tcb_addresses(
        pid=pid,
        target_adapter=target_adapter,
        all_mappings=all_mappings,
        threads=threads,
        ptr_size=ptr_size,
        endian=endian,
        target_abi=target_abi,
        tls_align=(tls_align if (pt_tls and pt_tls.get("p_memsz", 0) > 0) else None),
    )
    is_aarch64_tls = target_abi.architecture == "aarch64"
    tcb_status, tcb_message, tcb_ok = tcb_support.status, tcb_support.message, tcb_support.supported
    if tcb_ok and is_aarch64_tls and threads and not tcb_by_tid:
        # aarch64 discovery is invariant-validated: nothing validated means the layout is not the glibc one
        # we can verify, so report the explicit unsupported status instead of guessing addresses.
        tcb_status = SUPPORT_NOT_SUPPORTED_ON_TARGET
        tcb_message = (
            "tcb_scan: not supported on this target (aarch64/glibc thread pointer could not be validated: "
            "no thread produced a dtv-consistent TCB)"
        )
        tcb_ok = False

    thread_reports: List[Dict[str, Any]] = []
    values_by_var: Dict[str, List[Any]] = {v.name: [] for v in tls_vars}

    for t in threads:
        t_tid = int(t["tid"])
        t_name = t.get("name", f"tid-{t_tid}")
        tcb_addr = tcb_by_tid.get(t_tid)
        if is_aarch64_tls:
            # TLS variant I: the executable's block sits above the thread pointer
            tls_block_base = (
                tcb_addr + mgr._tls_first_block_offset_aarch64(tls_align)
                if (tcb_addr is not None and aligned_tls_memsz > 0) else None
            )
        else:
            tls_block_base = (tcb_addr - aligned_tls_memsz) if (tcb_addr is not None and aligned_tls_memsz > 0) else None

        decoded_vars: List[Dict[str, Any]] = []
        if tls_block_base is not None:
            for v in tls_vars:
                var_addr = tls_block_base + int(v.tls_offset or 0)
                v_val, v_st, _, _ = mgr._decode_typed_memory(
                    adapter=target_adapter,
                    pid=pid,
                    idx=idx,
                    addr=var_addr,
                    type_offset=v.type_offset,
                    depth=0,
                    max_struct_depth=2,
                )
                if v_st == "OBSERVED":
                    values_by_var[v.name].append(v_val)
                decoded_vars.append({
                    "name": v.name,
                    "type_name": idx.get_type_name(v.type_offset),
                    "tls_offset": f"0x{int(v.tls_offset or 0):x}",
                    "tls_offset_int": int(v.tls_offset or 0),
                    "runtime_address": f"0x{var_addr:x}",
                    "status": v_st,
                    "value": v_val,
                    "source_location": f"{v.decl_file}:{v.decl_line}" if v.decl_file else None,
                })

        thread_reports.append({
            "tid": t_tid,
            "name": t_name,
            "state": t.get("state", "S"),
            "tcb_address": f"0x{tcb_addr:x}" if tcb_addr is not None else None,
            "tls_block_base": f"0x{tls_block_base:x}" if tls_block_base is not None else None,
            "tls_variables_count": len(decoded_vars),
            "tls_variables": decoded_vars,
        })

    variable_summaries: List[Dict[str, Any]] = []
    for v in tls_vars:
        obs_vals = values_by_var.get(v.name, [])
        unique_serialized = {json.dumps(x, sort_keys=True, default=str) for x in obs_vals}
        variable_summaries.append({
            "name": v.name,
            "type_name": idx.get_type_name(v.type_offset),
            "tls_offset": f"0x{int(v.tls_offset or 0):x}",
            "source_location": f"{v.decl_file}:{v.decl_line}" if v.decl_file else None,
            "threads_observed": len(obs_vals),
            "unique_values_count": len(unique_serialized),
            "has_per_thread_divergence": len(unique_serialized) > 1,
        })

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "pt_tls_geometry": {
            "tls_memsz": tls_memsz,
            "tls_align": tls_align,
            "aligned_tls_memsz": aligned_tls_memsz,
        },
        "target_abi": target_abi.to_dict(),
        "tcb_scan_status": tcb_status,
        "tcb_scan_status_reason": tcb_message,
        "tls_variables_discovered": len(tls_vars),
        "variable_summaries": variable_summaries,
        "threads_count": len(thread_reports),
        "tcb_resolved_count": len(tcb_by_tid),
        "threads": thread_reports,
        "llm_next_step_hint": (
            f"TLS decoding {tcb_message}; no per-thread TLS values were produced."
            if not tcb_ok else
            f"Decoded {len(tls_vars)} TLS (`__thread` / `thread_local`) variable(s) across "
            f"{len(tcb_by_tid)}/{len(thread_reports)} thread TCB(s) in zero-stop mode."
        ),
    }


def verify_concurrent_read_consistency(
    mgr,
    pid: int,
    companion_elf_path: str,
    expressions: Optional[List[str]] = None,
    retries: int = 3,
    inter_read_delay_ms: int = 4,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Optimistic Seqlock Double-Read Concurrency Verifier (`zero-stop` stop time)."""
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
    idx = DwarfIndexer.get_index(primary_elf)
    map_data = mgr._get_process_maps_and_load_bias(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    load_bias = map_data.get("base_address_int", 0)
    is_dyn = (idx.elf_type == "ET_DYN")

    target_exprs: List[str] = []
    if expressions:
        for e in expressions:
            if e and e.strip() and e.strip() not in target_exprs:
                target_exprs.append(e.strip())
    else:
        seen_v = set()
        for v in idx.variables:
            if v.link_time_address is None or v.is_declaration or not v.name or v.name.startswith("__"):
                continue
            if v.name in seen_v:
                continue
            seen_v.add(v.name)
            target_exprs.append(v.name)
            if len(target_exprs) >= 12:
                break

    max_retries = max(1, min(int(retries), 10))
    delay_sec = max(0.0, min(float(inter_read_delay_ms), 200.0)) / 1000.0

    symbol_reports: List[Dict[str, Any]] = []
    atomic_count = 0
    recovered_count = 0
    mutating_count = 0

    for expr in target_exprs:
        var_candidates = [v for v in idx.variables_by_name.get(expr, []) if v.link_time_address is not None and not v.is_declaration]
        check_addr: Optional[int] = None
        check_size: int = 8
        check_type_off: Optional[int] = None
        type_name: str = "unknown"
        deref_note: Optional[str] = None

        if var_candidates:
            v = var_candidates[0]
            check_addr = (load_bias + v.link_time_address) if is_dyn else v.link_time_address
            check_type_off = v.type_offset
            canon_t = idx.resolve_canonical_type(v.type_offset)
            type_name = idx.get_type_name(v.type_offset)
            check_size = canon_t.byte_size if (canon_t and canon_t.byte_size and canon_t.byte_size > 0) else idx.pointer_size

            if canon_t and canon_t.tag == "DW_TAG_pointer_type" and canon_t.target_type_offset is not None:
                target_t = idx.resolve_canonical_type(canon_t.target_type_offset)
                if target_t and target_t.byte_size and target_t.byte_size > 0:
                    ptr_bytes, p_st, _ = target_adapter.read_memory(pid, check_addr, idx.pointer_size)
                    if p_st == "OBSERVED" and ptr_bytes and len(ptr_bytes) == idx.pointer_size:
                        ptr_fmt = ("<" if idx.endianness == "little" else ">") + ("Q" if idx.pointer_size == 8 else "I")
                        deref_addr = struct.unpack(ptr_fmt, ptr_bytes)[0]
                        if deref_addr > 0x1000:
                            check_addr = deref_addr
                            check_size = min(target_t.byte_size, 4096)
                            check_type_off = canon_t.target_type_offset
                            deref_note = f"Dereferenced pointer {expr} -> 0x{deref_addr:x} ({idx.get_type_name(check_type_off)})"
        else:
            ev = mgr.evaluate_expression(
                pid=pid,
                companion_elf_path=companion_elf_path,
                expression=expr,
                adapter=target_adapter,
            )
            rt_hex = ev.get("runtime_address")
            if rt_hex and isinstance(rt_hex, str) and rt_hex.startswith("0x"):
                check_addr = int(rt_hex, 16)
                check_size = max(1, int(ev.get("byte_size") or 8))
                type_name = ev.get("type_name", "unknown")

        if check_addr is None or check_addr <= 0:
            continue

        check_size = max(1, min(check_size, 4096))
        attempts_log: List[Dict[str, Any]] = []
        consistency_status = "CONCURRENTLY_MUTATING"
        final_val: Any = None
        mutating_fields: List[str] = []

        for attempt_idx in range(1, max_retries + 1):
            raw_1, st_1, _ = target_adapter.read_memory(pid, check_addr, check_size)
            val_1, _, _, _ = mgr._decode_typed_memory(
                adapter=target_adapter,
                pid=pid,
                idx=idx,
                addr=check_addr,
                type_offset=check_type_off,
                depth=0,
                max_struct_depth=2,
            )
            if delay_sec > 0:
                time.sleep(delay_sec)
            raw_2, st_2, _ = target_adapter.read_memory(pid, check_addr, check_size)
            val_2, _, _, _ = mgr._decode_typed_memory(
                adapter=target_adapter,
                pid=pid,
                idx=idx,
                addr=check_addr,
                type_offset=check_type_off,
                depth=0,
                max_struct_depth=2,
            )

            bytes_matched = (st_1 == "OBSERVED" and st_2 == "OBSERVED" and raw_1 is not None and raw_2 is not None and raw_1 == raw_2)
            changed_byte_offsets = []
            if raw_1 and raw_2 and len(raw_1) == len(raw_2) and not bytes_matched:
                changed_byte_offsets = [i for i in range(len(raw_1)) if raw_1[i] != raw_2[i]]
            if isinstance(val_1, dict) and isinstance(val_2, dict):
                for k in val_1:
                    if k in val_2 and val_1[k] != val_2[k] and k not in mutating_fields:
                        mutating_fields.append(k)
            elif val_1 != val_2 and "value" not in mutating_fields:
                mutating_fields.append("value")

            attempts_log.append({
                "attempt": attempt_idx,
                "bytes_matched": bytes_matched,
                "changed_bytes_count": len(changed_byte_offsets),
                "read_1_value": val_1,
                "read_2_value": val_2,
            })

            final_val = val_2
            if bytes_matched:
                consistency_status = "ATOMIC_CONSISTENT" if attempt_idx == 1 else "TORN_READ_RECOVERED"
                break

        if consistency_status == "ATOMIC_CONSISTENT":
            atomic_count += 1
        elif consistency_status == "TORN_READ_RECOVERED":
            recovered_count += 1
        else:
            mutating_count += 1

        symbol_reports.append({
            "expression": expr,
            "type_name": type_name,
            "checked_address": f"0x{check_addr:x}",
            "checked_byte_size": check_size,
            "dereference_note": deref_note,
            "consistency_status": consistency_status,
            "attempts_used": len(attempts_log),
            "mutating_fields": mutating_fields,
            "verified_value": final_val,
            "attempts": attempts_log,
        })

    overall_status = (
        "ACTIVE_CONCURRENT_MUTATIONS_DETECTED"
        if mutating_count > 0
        else ("TORN_READS_RECOVERED_CLEANLY" if recovered_count > 0 else "ALL_ATOMIC_CONSISTENT")
    )

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "overall_consistency_status": overall_status,
        "symbols_checked_count": len(symbol_reports),
        "atomic_consistent_count": atomic_count,
        "torn_read_recovered_count": recovered_count,
        "concurrently_mutating_count": mutating_count,
        "symbols": symbol_reports,
        "llm_next_step_hint": (
            f"Seqlock Concurrency Verification: {overall_status} "
            f"({atomic_count} atomic consistent, {recovered_count} torn-read recovered, {mutating_count} concurrently mutating in zero-stop mode)."
        ),
    }
