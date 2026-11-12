"""Shared-memory IPC inspection, IPC pipeline tracing and DPDK lcore / ring inspection.

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import os
import time
from typing import Any, Dict, List, Optional, Tuple

from ..dwarf_indexer import DwarfIndexer
from ..target_adapter import TargetExecutionAdapter


def inspect_shared_memory_ipc(
    mgr,
    pid: int,
    companion_elf_path: str,
    cast_type: Optional[str] = None,
    address: Optional[str] = None,
    shm_name: Optional[str] = None,
    discover_peer_processes: bool = True,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Inspects POSIX shared memory (`/dev/shm/*`, `SYSV`, shared `mmap`) or overlays a DWARF struct type
        (`cast_type`) onto any arbitrary runtime address, and discovers peer processes sharing the same IPC mapping.
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
    idx = DwarfIndexer.get_index(primary_elf)

    # Find shared memory / IPC VMA mappings in target process
    shared_mappings: List[Dict[str, Any]] = []
    for m in map_data.get("mappings", []):
        perms = m.get("permissions", "")
        pathname = m.get("pathname") or ""
        is_shared_flag = ("s" in perms.lower())
        is_shm_path = any(k in pathname for k in ("/dev/shm", "shm", "memfd", "SYSV"))
        if is_shared_flag or is_shm_path:
            if shm_name and shm_name not in pathname:
                continue
            ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
            me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
            shared_mappings.append({
                "start": m.get("start"),
                "start_int": ms,
                "end": m.get("end"),
                "end_int": me,
                "size": int(m.get("size") or (me - ms)),
                "permissions": perms,
                "pathname": pathname,
            })

    # Determine target address to cast/decode
    target_addr = 0
    matched_mapping = None
    if address:
        addr_s = address.strip()
        target_addr = int(addr_s, 16) if addr_s.startswith("0x") else int(addr_s)
        for sm in shared_mappings:
            if sm["start_int"] <= target_addr < sm["end_int"]:
                matched_mapping = sm
                break
    elif shared_mappings:
        matched_mapping = shared_mappings[0]
        target_addr = matched_mapping["start_int"]

    decoded_overlay = None
    resolved_type_name = None
    if cast_type and target_addr > 0:
        d_type = idx.resolve_type_by_name(cast_type)
        if d_type is None:
            raise ValueError(f"DWARF type '{cast_type}' not found in '{primary_elf}'")
        resolved_type_name = d_type.name
        val, st, err, raw_hex = mgr._decode_typed_memory(
            adapter=target_adapter,
            pid=pid,
            idx=idx,
            addr=target_addr,
            type_offset=d_type.die_offset,
            depth=0,
            max_struct_depth=3,
        )
        decoded_overlay = {
            "cast_type": resolved_type_name,
            "address": f"0x{target_addr:x}",
            "byte_size": d_type.byte_size,
            "status": st,
            "error": err,
            "value": val,
        }

    # Discover peer processes on the host sharing any of the non-empty shared_mappings pathnames
    peer_processes: List[Dict[str, Any]] = []
    shm_paths = {sm["pathname"] for sm in shared_mappings if sm.get("pathname") and not sm["pathname"].startswith("[")}
    if discover_peer_processes and shm_paths and not target_adapter.is_remote():
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            other_pid = int(entry)
            if other_pid == pid:
                continue
            try:
                with open(f"/proc/{other_pid}/maps", "r", encoding="utf-8", errors="replace") as mf:
                    maps_txt = mf.read()
                for sp in shm_paths:
                    if sp in maps_txt:
                        comm_name = f"pid_{other_pid}"
                        try:
                            with open(f"/proc/{other_pid}/comm", "r", encoding="utf-8") as cf:
                                comm_name = cf.read().strip()
                        except Exception:
                            pass
                        peer_processes.append({
                            "peer_pid": other_pid,
                            "peer_name": comm_name,
                            "shared_pathname": sp,
                        })
            except Exception:
                continue

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "shared_mappings_count": len(shared_mappings),
        "shared_mappings": shared_mappings,
        "decoded_overlay": decoded_overlay,
        "peer_processes_count": len(peer_processes),
        "peer_processes": peer_processes,
        "llm_next_step_hint": (
            f"Decoded '{resolved_type_name}' at 0x{target_addr:x} and found {len(peer_processes)} peer process(es) sharing IPC memory."
            if decoded_overlay
            else f"Found {len(shared_mappings)} shared memory mapping(s) and {len(peer_processes)} peer process(es)."
        ),
    }


# -------------------------------------------------------------------------
# Phase 42 (Phase 12): Multi-Process IPC Pipeline Bottleneck Tracer
#                      & DWARF/vtable Heap Object Census / Leak Scanner
# -------------------------------------------------------------------------

def trace_ipc_pipeline(
    mgr,
    pid: int,
    companion_elf_path: str,
    cast_type: Optional[str] = None,
    address: Optional[str] = None,
    shm_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Cross-process shared memory (`shm` / `MAP_SHARED`) & IPC FD pipeline bottleneck analyzer (zero-stop).
        1. Auto-detects or overlays `cast_type` onto shared memory regions.
        2. Computes producer vs consumer sequence lag (`pending_backlog`, `backlog_utilization_pct`).
        3. Maps peer processes sharing the same SHM or pipe/socket inodes and inspects their thread states.
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

    idx = DwarfIndexer.get_index(primary_elf)

    # Auto-infer `cast_type` if not explicitly passed by looking for Shm/Ring/Ipc struct types in DWARF
    effective_cast = (cast_type or "").strip() or None
    if not effective_cast:
        for t in idx.types_by_die.values():
            if t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and t.name and t.members:
                tn_low = t.name.lower()
                if any(k in tn_low for k in ("shm", "ipc", "ring", "channel", "shared")):
                    effective_cast = t.name
                    break

    shm_base = mgr.inspect_shared_memory_ipc(
        pid=pid,
        companion_elf_path=companion_elf_path,
        cast_type=effective_cast,
        address=address,
        shm_name=shm_name,
        discover_peer_processes=True,
        adapter=target_adapter,
    )

    # Analyze producer/consumer sequence counters inside decoded_overlay
    overlay = shm_base.get("decoded_overlay")
    ov_val = overlay.get("value") if isinstance(overlay, dict) else None

    producer_seq: Optional[int] = None
    consumer_seq: Optional[int] = None
    capacity: Optional[int] = None
    lock_owner_pid: Optional[int] = None

    if isinstance(ov_val, dict):
        for k, v in ov_val.items():
            if not isinstance(v, int):
                continue
            kl = k.lower()
            if any(w in kl for w in ("producer", "write_seq", "write_idx", "tx_seq", "head", "enqueued")):
                producer_seq = v
            elif any(w in kl for w in ("consumer", "read_seq", "read_idx", "rx_seq", "tail", "dequeued")):
                consumer_seq = v
            elif any(w in kl for w in ("cap", "max", "total", "slots", "size")):
                capacity = v
            elif any(w in kl for w in ("owner_pid", "writer_pid", "lock_owner", "holder_pid")):
                lock_owner_pid = v

    pending_backlog = 0
    utilization_pct = 0.0
    if producer_seq is not None and consumer_seq is not None:
        pending_backlog = max(0, producer_seq - consumer_seq)
        if capacity and capacity > 0:
            utilization_pct = round(min(100.0, (pending_backlog / float(capacity)) * 100.0), 2)

    # Enrich peer processes with live state from /proc/<peer_pid>/stat
    peers = list(shm_base.get("peer_processes", []))
    for p in peers:
        p_pid = int(p["peer_pid"])
        p_state = "S"
        if not target_adapter.is_remote():
            try:
                with open(f"/proc/{p_pid}/stat", "r", encoding="utf-8") as sf:
                    st_txt = sf.read()
                rpar = st_txt.rfind(")")
                if rpar != -1:
                    after = st_txt[rpar + 1:].strip().split()
                    if after:
                        p_state = after[0]
            except Exception:
                pass
        p["peer_state"] = p_state

    # Also scan /proc/<pid>/fd for pipe/socket inodes if local
    ipc_fds: List[Dict[str, Any]] = []
    if not target_adapter.is_remote():
        fd_dir = f"/proc/{pid}/fd"
        if os.path.isdir(fd_dir):
            try:
                for fd_name in sorted(os.listdir(fd_dir))[:32]:
                    if not fd_name.isdigit():
                        continue
                    link_target = os.readlink(os.path.join(fd_dir, fd_name))
                    if any(k in link_target for k in ("socket:", "pipe:", "anon_inode:", "/dev/shm")):
                        ipc_fds.append({"fd": int(fd_name), "target": link_target})
            except Exception:
                pass

    pipeline_health = "HEALTHY_PIPELINE"
    bottleneck_diagnosis = "No cross-process backlog or stall detected."
    if utilization_pct >= 80.0:
        pipeline_health = "PIPELINE_STALLED_OR_FULL"
        peer_desc = f"peer PID {peers[0]['peer_pid']} ({peers[0]['peer_name']})" if peers else "consumer process"
        bottleneck_diagnosis = (
            f"Shared ring buffer is {utilization_pct}% full (backlog={pending_backlog}/{capacity}, "
            f"producer_seq={producer_seq}, consumer_seq={consumer_seq}). Inspect {peer_desc} for consumer stall."
        )
    elif pending_backlog > 0:
        pipeline_health = "CONSUMER_LAGGING"
        bottleneck_diagnosis = (
            f"Consumer is lagging behind producer by {pending_backlog} item(s) "
            f"(producer_seq={producer_seq}, consumer_seq={consumer_seq})."
        )

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "pipeline_health": pipeline_health,
        "bottleneck_diagnosis": bottleneck_diagnosis,
        "metrics": {
            "producer_seq": producer_seq,
            "consumer_seq": consumer_seq,
            "pending_backlog": pending_backlog,
            "capacity": capacity,
            "backlog_utilization_pct": utilization_pct,
            "lock_owner_pid": lock_owner_pid,
        },
        "shared_mappings": shm_base.get("shared_mappings", []),
        "decoded_overlay": overlay,
        "peer_processes": peers,
        "ipc_fds": ipc_fds,
        "llm_next_step_hint": (
            f"[{pipeline_health}] {bottleneck_diagnosis}"
            + (f" Connected peer process: PID {peers[0]['peer_pid']} ({peers[0]['peer_name']})." if peers else "")
        ),
    }


def inspect_dpdk_lcores_and_rings(
    mgr,
    pid: int,
    companion_elf_path: str,
    sample_window_ms: int = 40,
    ring_expressions: Optional[List[str]] = None,
    spinlock_expressions: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Zero-Stop DPDK Isolated-Core (`isolcpus`) Dedicated Lcore, PMD Poll-Loop, Lockless Ring (`rte_ring`)
        & User-Space Spinlock (`rte_spinlock_t`) Inspector (`zero-stop` stop time).
        
        Engineered specifically for DPDK / high-performance user-space poll-mode threads where:
        - Threads run 100% in user space (`state == 'R'`, `/proc/<pid>/task/<tid>/syscall == 'running'`, `kstkesp == 0`).
        - Threads are pinned to isolated CPU cores (`pthread_setaffinity_np`, `isolcpus`, `nohz_full`).
        - Per-lcore state is stored in ELF TLS (`RTE_DEFINE_PER_LCORE` -> `per_lcore_*` / `__thread`).
        - Packet buffers and rings reside in `hugetlbfs` mappings or lockless `rte_ring` structures.
        """
    from ..target_adapter import _get_kernel_isolated_cpus
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
    all_mappings = map_data.get("mappings", [])

    hugepage_mappings = [
        {
            "start": m.get("start"),
            "end": m.get("end"),
            "size": m.get("size"),
            "permissions": m.get("permissions"),
            "pathname": m.get("pathname"),
        }
        for m in all_mappings
        if m.get("is_hugepage") or any(k in (m.get("pathname") or "").lower() for k in ("huge", "rtemap", "hugetlb"))
    ]

    # Auto-discover candidate lockless rings, spinlocks, and progress counters from DWARF
    cand_rings: List[str] = list(ring_expressions or [])
    cand_spinlocks: List[str] = list(spinlock_expressions or [])
    cand_counters: List[str] = []

    for v in idx.variables:
        if v.link_time_address is None or v.is_declaration or not v.name or v.name.startswith("__"):
            continue
        nl = v.name.lower()
        canon_t = idx.resolve_canonical_type(v.type_offset)
        t_name = idx.get_type_name(v.type_offset).lower()

        # Check if struct or pointer to struct has ring-like or spinlock-like members
        struct_t = canon_t
        expr_name = v.name
        if canon_t and canon_t.tag == "DW_TAG_pointer_type" and canon_t.target_type_offset is not None:
            struct_t = idx.resolve_canonical_type(canon_t.target_type_offset)
            expr_name = f"*{v.name}"

        if struct_t and struct_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
            mem_names = {m.name.lower() for m in struct_t.members if m.name}
            if (
                ("prod" in mem_names and "cons" in mem_names)
                or ("prod_head" in mem_names and "prod_tail" in mem_names)
                or ("producer_seq" in mem_names and "consumer_seq" in mem_names)
                or "rte_ring" in t_name
            ):
                if expr_name not in cand_rings:
                    cand_rings.append(expr_name)
            elif ("locked" in mem_names and len(mem_names) <= 4) or "spinlock" in t_name or "spinlock" in nl:
                if expr_name not in cand_spinlocks:
                    cand_spinlocks.append(expr_name)

        if canon_t and canon_t.tag == "DW_TAG_base_type":
            if any(k in nl for k in ("pkt", "rx", "tx", "burst", "loop", "cycle", "count", "seq", "tick", "heartbeat")):
                if v.name not in cand_counters:
                    cand_counters.append(v.name)

    # Snapshot T0: threads, TLS variables, callstacks, rings, spinlocks, and global counters
    threads_t0 = {int(t["tid"]): t for t in target_adapter.get_threads(pid)}
    tls_t0 = mgr.inspect_thread_local_storage(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    tls_by_tid_t0: Dict[int, Dict[str, Any]] = {}
    for th_tls in tls_t0.get("threads", []):
        tls_by_tid_t0[int(th_tls["tid"])] = {
            "tcb_address": th_tls.get("tcb_address"),
            "tls_block_base": th_tls.get("tls_block_base"),
            "vars": {v["name"]: v["value"] for v in th_tls.get("tls_variables", [])},
        }

    eval_exprs = cand_rings + cand_spinlocks + cand_counters[:12]
    vals_t0: Dict[str, Any] = {}
    if eval_exprs:
        ev0 = mgr.evaluate_symbol_paths(
            pid=pid,
            companion_elf_path=companion_elf_path,
            expressions=eval_exprs,
            adapter=target_adapter,
        )
        for r in ev0.get("results", []):
            vals_t0[r["expression"]] = r

    clamped_win_ms = max(10, min(int(sample_window_ms), 500))
    time.sleep(clamped_win_ms / 1000.0)

    # Snapshot T1 after micro-window
    threads_t1 = {int(t["tid"]): t for t in target_adapter.get_threads(pid)}
    tls_t1 = mgr.inspect_thread_local_storage(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    tls_by_tid_t1: Dict[int, Dict[str, Any]] = {}
    for th_tls in tls_t1.get("threads", []):
        tls_by_tid_t1[int(th_tls["tid"])] = {
            "tcb_address": th_tls.get("tcb_address"),
            "tls_block_base": th_tls.get("tls_block_base"),
            "vars": {v["name"]: v["value"] for v in th_tls.get("tls_variables", [])},
        }

    vals_t1: Dict[str, Any] = {}
    if eval_exprs:
        ev1 = mgr.evaluate_symbol_paths(
            pid=pid,
            companion_elf_path=companion_elf_path,
            expressions=eval_exprs,
            adapter=target_adapter,
        )
        for r in ev1.get("results", []):
            vals_t1[r["expression"]] = r

    callstack_res = mgr.inspect_thread_callstacks_and_locks(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    cs_by_tid = {int(t["tid"]): t for t in callstack_res.get("threads", [])}
    locals_res = mgr.inspect_thread_locals_and_frame_vars(
        pid=pid,
        companion_elf_path=companion_elf_path,
        max_frames=4,
        adapter=target_adapter,
    )
    locals_by_tid = {int(t["tid"]): t for t in locals_res.get("threads", [])}

    # Compute global counter delta sum
    global_progress_delta = 0
    global_counter_deltas: Dict[str, int] = {}
    for c_expr in cand_counters[:12]:
        v0 = (vals_t0.get(c_expr) or {}).get("value")
        v1 = (vals_t1.get(c_expr) or {}).get("value")
        if isinstance(v0, int) and isinstance(v1, int):
            d_val = v1 - v0
            global_counter_deltas[c_expr] = d_val
            if d_val != 0:
                global_progress_delta += abs(d_val)

    # 1. Analyze Lockless Rings (`rte_ring`)
    ring_reports: List[Dict[str, Any]] = []
    any_ring_stall = False
    for r_expr in cand_rings:
        r0 = (vals_t0.get(r_expr) or {}).get("value")
        r1 = (vals_t1.get(r_expr) or {}).get("value")
        rt_addr = (vals_t1.get(r_expr) or {}).get("runtime_address")
        t_name = (vals_t1.get(r_expr) or {}).get("type_name")
        if not isinstance(r1, dict):
            continue

        def _extract_ring_state(d: Dict[str, Any]) -> Tuple[int, int, int, int, int, int]:
            if isinstance(d.get("prod"), dict) and isinstance(d.get("cons"), dict):
                ph = int(d["prod"].get("head", 0))
                pt = int(d["prod"].get("tail", 0))
                ch = int(d["cons"].get("head", 0))
                ct = int(d["cons"].get("tail", 0))
            elif "prod_head" in d or "prod_tail" in d:
                ph = int(d.get("prod_head", 0))
                pt = int(d.get("prod_tail", 0))
                ch = int(d.get("cons_head", 0))
                ct = int(d.get("cons_tail", 0))
            else:
                ph = int(d.get("producer_seq", 0))
                pt = ph
                ch = int(d.get("consumer_seq", 0))
                ct = ch
            cap = int(d.get("capacity") or d.get("size") or 1024)
            msk = int(d.get("mask") or (cap - 1 if cap > 0 else 0xffffffff))
            return ph, pt, ch, ct, cap, msk

        ph0, pt0, ch0, ct0, cap0, msk0 = _extract_ring_state(r0 if isinstance(r0, dict) else r1)
        ph1, pt1, ch1, ct1, cap1, msk1 = _extract_ring_state(r1)
        inflight = (pt1 - ch1) & msk1 if pt1 >= ch1 else max(0, pt1 - ch1)
        enq_delta = max(0, pt1 - pt0)
        deq_delta = max(0, ct1 - ct0)
        throughput_delta = enq_delta + deq_delta
        global_progress_delta += throughput_delta

        if ph1 != pt1 and pt1 == pt0 and ph1 == ph0:
            ring_status = "STUCK_PROD_INFLIGHT_RESERVATION"
            any_ring_stall = True
        elif ch1 != ct1 and ct1 == ct0 and ch1 == ch0:
            ring_status = "STUCK_CONS_INFLIGHT_RESERVATION"
            any_ring_stall = True
        elif cap1 > 0 and inflight >= cap1:
            ring_status = "RING_FULL_BACKPRESSURE"
        elif throughput_delta > 0:
            ring_status = "HEALTHY_FLOWING"
        else:
            ring_status = "IDLE_EMPTY"

        ring_reports.append({
            "expression": r_expr,
            "type_name": t_name,
            "runtime_address": rt_addr,
            "capacity": cap1,
            "mask": f"0x{msk1:x}",
            "prod_head": ph1,
            "prod_tail": pt1,
            "cons_head": ch1,
            "cons_tail": ct1,
            "inflight_entries": inflight,
            "utilization_pct": round((inflight * 100.0) / max(1, cap1), 2),
            "enqueued_delta": enq_delta,
            "dequeued_delta": deq_delta,
            "throughput_delta": throughput_delta,
            "ring_status": ring_status,
        })

    # 2. Analyze User-Space Spinlocks (`rte_spinlock_t`)
    spinlock_reports: List[Dict[str, Any]] = []
    any_spinlock_stuck = False
    for s_expr in cand_spinlocks:
        s0 = (vals_t0.get(s_expr) or {}).get("value")
        s1 = (vals_t1.get(s_expr) or {}).get("value")
        rt_addr = (vals_t1.get(s_expr) or {}).get("runtime_address")
        lk0 = int(s0.get("locked", 0)) if isinstance(s0, dict) else (int(s0) if isinstance(s0, int) else 0)
        lk1 = int(s1.get("locked", 0)) if isinstance(s1, dict) else (int(s1) if isinstance(s1, int) else 0)
        if lk0 != 0 and lk1 != 0:
            sp_status = "CONTENDED_OR_STUCK_LOCKED"
            any_spinlock_stuck = True
        elif lk0 != 0 or lk1 != 0:
            sp_status = "TRANSIENT_LOCK"
        else:
            sp_status = "UNLOCKED"
        spinlock_reports.append({
            "expression": s_expr,
            "runtime_address": rt_addr,
            "locked_before": lk0,
            "locked_after": lk1,
            "spinlock_status": sp_status,
        })

    # 3. Analyze Per-Lcore Dedicated Threads
    lcore_reports: List[Dict[str, Any]] = []
    dedicated_count = 0
    any_lcore_deadloop = False
    any_os_jitter = False

    for tid_val, t1 in sorted(threads_t1.items()):
        t0 = threads_t0.get(tid_val, t1)
        t_name = t1.get("name", f"tid-{tid_val}")
        t_state = t1.get("state", "S")
        cpu_before = t0.get("cpu_id")
        cpu_after = t1.get("cpu_id")
        cpu_migrated = (cpu_before is not None and cpu_after is not None and cpu_before != cpu_after)
        is_pinned = bool(t1.get("is_single_core_pinned"))
        is_isolated = bool(t1.get("is_kernel_isolated_core"))
        utime_d = max(0, int(t1.get("utime_ticks", 0)) - int(t0.get("utime_ticks", 0)))
        stime_d = max(0, int(t1.get("stime_ticks", 0)) - int(t0.get("stime_ticks", 0)))
        vol_cs_d = max(0, int(t1.get("voluntary_ctxt_switches", 0)) - int(t0.get("voluntary_ctxt_switches", 0)))
        nonvol_cs_d = max(0, int(t1.get("nonvoluntary_ctxt_switches", 0)) - int(t0.get("nonvoluntary_ctxt_switches", 0)))

        tls0_vars = (tls_by_tid_t0.get(tid_val) or {}).get("vars") or {}
        tls1_vars = (tls_by_tid_t1.get(tid_val) or {}).get("vars") or {}
        tls_deltas: Dict[str, int] = {}
        lcore_progress_delta = 0
        lcore_id_val: Optional[int] = None

        for k_var, v1_val in tls1_vars.items():
            if "lcore_id" in k_var.lower() or "slot_id" in k_var.lower() or "core_id" in k_var.lower():
                if isinstance(v1_val, int):
                    lcore_id_val = v1_val
            v0_val = tls0_vars.get(k_var)
            if isinstance(v0_val, int) and isinstance(v1_val, int):
                dv = v1_val - v0_val
                tls_deltas[k_var] = dv
                if "id" not in k_var.lower() and dv != 0:
                    lcore_progress_delta += abs(dv)

        is_dpdk_named = any(k in t_name.lower() for k in ("lcore", "pmd", "dpdk", "rte", "poll", "rx", "tx"))
        is_dedicated_pmd = bool(
            (t_state == "R" or t1.get("is_running_user_space"))
            and (is_pinned or is_isolated or is_dpdk_named or (lcore_id_val is not None and lcore_id_val >= 0))
        )
        if is_dedicated_pmd:
            dedicated_count += 1
            lcore_role = "DPDK_PMD_DEDICATED_LCORE"
        elif tid_val == pid:
            lcore_role = "CONTROL_OR_MAIN_LCORE"
        else:
            lcore_role = "HOUSEKEEPING_WORKER"

        cs_info = cs_by_tid.get(tid_val) or {}
        frames = cs_info.get("callstack") or []
        top_fn = frames[0]["function_name"] if frames else None
        top_src = frames[0].get("source_location") if frames else None
        loc_info = locals_by_tid.get(tid_val) or {}
        frame_locals = loc_info.get("frames") or []

        has_tls_progress_vars = any("id" not in k.lower() for k in tls_deltas)
        effective_progress = lcore_progress_delta if has_tls_progress_vars else global_progress_delta
        jitter_detected = bool(is_dedicated_pmd and (nonvol_cs_d > 0 or cpu_migrated))

        if is_dedicated_pmd:
            if effective_progress == 0 or (top_fn and any(k in top_fn.lower() for k in ("deadloop", "stuck", "spin_lock"))):
                pmd_status = "LCORE_STUCK_DEADLOOP"
                any_lcore_deadloop = True
            elif jitter_detected:
                pmd_status = "PMD_POLLING_WITH_OS_JITTER"
                any_os_jitter = True
            else:
                pmd_status = "PMD_POLLING_HEALTHY"
        else:
            pmd_status = "SLEEPING_OR_CONTROL_THREAD"

        lcore_reports.append({
            "tid": tid_val,
            "name": t_name,
            "state": t_state,
            "lcore_role": lcore_role,
            "lcore_id": lcore_id_val,
            "cpu_id": cpu_after,
            "cpu_id_before": cpu_before,
            "cpu_migrated": cpu_migrated,
            "cpus_allowed_list": t1.get("cpus_allowed_list", ""),
            "pinned_cpus": t1.get("pinned_cpus", []),
            "is_single_core_pinned": is_pinned,
            "is_kernel_isolated_core": is_isolated,
            "sched_policy": t1.get("sched_policy", "SCHED_OTHER"),
            "rt_priority": t1.get("rt_priority", 0),
            "utime_delta_ticks": utime_d,
            "stime_delta_ticks": stime_d,
            "voluntary_ctxt_switches_delta": vol_cs_d,
            "nonvoluntary_ctxt_switches_delta": nonvol_cs_d,
            "isolation_jitter_detected": jitter_detected,
            "tcb_address": (tls_by_tid_t1.get(tid_val) or {}).get("tcb_address") or (t1.get("stack_info") or {}).get("tcb_address"),
            "per_lcore_tls": tls1_vars,
            "per_lcore_tls_deltas": tls_deltas,
            "progress_delta": effective_progress,
            "pmd_health_status": pmd_status,
            "top_function": top_fn,
            "top_source_location": top_src,
            "active_callstack": frames,
            "decoded_stack_frames": frame_locals,
        })

    if any_lcore_deadloop or any_ring_stall:
        overall_status = "LCORE_DEADLOOP_OR_RING_STALL_DETECTED"
    elif any_os_jitter or any_spinlock_stuck:
        overall_status = "OS_JITTER_OR_SPINLOCK_CONTENTION"
    else:
        overall_status = "HEALTHY_ZERO_JITTER_PMD"

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "sample_window_ms": clamped_win_ms,
        "kernel_isolated_cpus": _get_kernel_isolated_cpus(),
        "hugepage_mappings_count": len(hugepage_mappings),
        "hugepage_mappings": hugepage_mappings,
        "lcore_threads_count": len(lcore_reports),
        "dedicated_pmd_lcores_count": dedicated_count,
        "overall_dpdk_status": overall_status,
        "lcores": lcore_reports,
        "lockless_rings_count": len(ring_reports),
        "lockless_rings": ring_reports,
        "spinlocks_count": len(spinlock_reports),
        "spinlocks": spinlock_reports,
        "global_counter_deltas": global_counter_deltas,
        "llm_next_step_hint": (
            f"DPDK Isolated-Core & PMD Audit: {overall_status} across {dedicated_count} dedicated PMD lcore(s) "
            f"and {len(ring_reports)} lockless ring(s) in zero-stop mode."
        ),
    }
