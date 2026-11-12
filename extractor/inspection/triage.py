"""Scans that combine the inspectors: auto-triage, the symptom investigator, the dependency graph and source/state
correlation.  Their overall verdict and health score come from diagnostic_verdict_aggregator (IMP-017); nothing
here invents a verdict.

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from ..diagnostic_verdict_aggregator import VERDICT_INCONCLUSIVE, health_score_for, verdict_for_scan
from ..dwarf_indexer import DwarfIndexer
from ..target_adapter import TargetExecutionAdapter


def auto_triage_incident(
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
    """1-Call Composite Zero-Stop Incident Auto-Triage & Root-Cause Correlator.
        Executes in a single pass without stopping the target:
        1. Process X-Ray Blueprint discovery
        2. Memory & Pointer Integrity Audit (`audit_memory_integrity`)
        3. Thread Callstacks, Mutex Contention & Deadlock Check (`inspect_thread_callstacks_and_locks`)
        4. Memory Pool Utilization & Allocated Slot Ownership Sweep (`scan_memory_pool_or_array`)
        5. Linked List / Queue Pointer Chain Cycle Sweep (`traverse_linked_structure`)
        Synthesizes ranked root-cause `findings` and `source_remediation_targets`.
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

    limitations: List[str] = []
    try:
        blueprint = mgr.get_process_xray_blueprint(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )
    except Exception as bp_exc:
        limitations.append(f"get_process_xray_blueprint failed: {type(bp_exc).__name__}: {bp_exc}")
        blueprint = {"categories": {}}

    try:
        audit_res = mgr.audit_memory_integrity(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )
        for lim in (audit_res.get("limitations") or []):
            if lim not in limitations:
                limitations.append(lim)
        if audit_res.get("health_status") == "INCONCLUSIVE" and not audit_res.get("limitations"):
            limitations.append("audit_memory_integrity returned INCONCLUSIVE")
    except Exception as au_exc:
        err_msg = f"audit_memory_integrity failed: {type(au_exc).__name__}: {au_exc}"
        limitations.append(err_msg)
        audit_res = {"health_status": "INCONCLUSIVE", "anomalies": [], "limitations": [err_msg]}

    try:
        callstack_res = mgr.inspect_thread_callstacks_and_locks(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )
        for lim in (callstack_res.get("limitations") or []):
            if lim not in limitations:
                limitations.append(lim)
        if callstack_res.get("status") == "INCONCLUSIVE" and not callstack_res.get("limitations"):
            limitations.append("inspect_thread_callstacks_and_locks returned INCONCLUSIVE")
    except Exception as cs_exc:
        err_msg = f"inspect_thread_callstacks_and_locks failed: {type(cs_exc).__name__}: {cs_exc}"
        limitations.append(err_msg)
        callstack_res = {"status": "INCONCLUSIVE", "threads": [], "locks": [], "deadlock_detected": False, "limitations": [err_msg]}

    findings: List[Dict[str, Any]] = []
    source_targets: List[str] = []

    # 1. Check Deadlocks & Mutex Contention
    if callstack_res.get("deadlock_detected"):
        for cyc in callstack_res.get("deadlock_cycles", []):
            desc = " -> ".join(f"TID {e['waiter_tid']} ({e['waiter_name']}) waits on {e['lock_name']} held by TID {e['owner_tid']}" for e in cyc)
            findings.append({
                "severity": "CRITICAL",
                "category": "DEADLOCK",
                "title": "Circular Mutex Deadlock Detected",
                "summary": desc,
                "recommended_action": "Inspect lock acquisition order in the involved thread functions.",
            })
    for lk in callstack_res.get("locks", []):
        if lk.get("is_locked") and lk.get("owner_tid"):
            owner_th = next((t for t in callstack_res.get("threads", []) if t["tid"] == lk["owner_tid"]), None)
            # IMP-011: CFI stacks start with the (source-less) libc wait frames: take the first frame with a source line
            top_loc = next((f.get("source_location") for f in ((owner_th or {}).get("callstack") or [])
                            if f.get("source_location")), None)
            if top_loc and top_loc not in source_targets:
                source_targets.append(top_loc)
            findings.append({
                "severity": "HIGH" if lk.get("waiting_tids") else "MEDIUM",
                "category": "MUTEX_LOCK_HELD",
                "title": f"Mutex '{lk['name']}' Held by TID {lk['owner_tid']} ({lk.get('owner_thread_name')})",
                "summary": f"Mutex {lk['name']} ({lk['runtime_address']}) is locked by TID {lk['owner_tid']}" + (f" with waiting threads {lk['waiting_tids']}" if lk.get("waiting_tids") else ""),
                "source_location": top_loc,
                "recommended_action": f"Check why TID {lk['owner_tid']} ({lk.get('owner_thread_name')}) is holding '{lk['name']}' without releasing it.",
            })

    # 2. Check Memory Corruption & Pointer Integrity Anomalies
    for anom in audit_res.get("anomalies", []):
        findings.append({
            "severity": "CRITICAL" if anom["anomaly_kind"] in ("DANGLING_OR_UNMAPPED_POINTER", "CORRUPTED_BOOL_VALUE") else "HIGH",
            "category": "MEMORY_CORRUPTION",
            "title": f"{anom['anomaly_kind']} on '{anom['expression']}'",
            "summary": anom["detail"],
            "recommended_action": f"Inspect writes to '{anom['expression']}' ({anom['runtime_address']}) and adjacent struct fields for buffer overflow or use-after-free.",
        })

    # 3. Sweep Discovered Memory Pools
    pool_reports: List[Dict[str, Any]] = []
    pools_meta = blueprint.get("categories", {}).get("memory_pools_and_buffers", [])
    for pm in pools_meta[:3]:
        expr = pm.get("recommended_pool_expression") or pm.get("name")
        if not expr:
            continue
        try:
            p_scan = mgr.scan_memory_pool_or_array(
                pid=pid,
                companion_elf_path=companion_elf_path,
                base_expression=expr,
                adapter=target_adapter,
            )
            pool_reports.append(p_scan)
            util = p_scan["pool_summary"]["utilization_pct"]
            if util >= 75.0:
                findings.append({
                    "severity": "HIGH" if util >= 90.0 else "MEDIUM",
                    "category": "MEMORY_POOL_PRESSURE",
                    "title": f"High Memory Pool Utilization on '{p_scan['resolved_array_expression']}' ({util}%)",
                    "summary": f"{p_scan['pool_summary']['allocated_count']}/{p_scan['pool_summary']['total_slots']} slots allocated.",
                    "recommended_action": "Run `runtime_find_symbol_owners` on allocated slot indices to identify leaking threads.",
                })
        except Exception as pool_exc:
            limitations.append(f"scan_memory_pool_or_array('{expr}') failed: {type(pool_exc).__name__}: {pool_exc}")

    # 4. Sweep Discovered Linked-List Head Pointers for Cycles or Dangling Links
    linked_list_reports: List[Dict[str, Any]] = []
    try:
        primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
        idx = DwarfIndexer.get_index(primary_elf)
        for var in idx.variables:
            if var.link_time_address is None or var.is_declaration or not var.name or var.name.startswith("__"):
                continue
            canon_t = idx.resolve_canonical_type(var.type_offset)
            if canon_t and canon_t.tag == "DW_TAG_pointer_type":
                target_t = idx.resolve_canonical_type(canon_t.target_type_offset)
                if target_t and target_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                    has_next = any(m.name in ("next", "p_next", "next_node") for m in target_t.members)
                    if has_next:
                        try:
                            ll_res = mgr.traverse_linked_structure(
                                pid=pid,
                                companion_elf_path=companion_elf_path,
                                head_expression=var.name,
                                max_depth=64,
                                adapter=target_adapter,
                            )
                            linked_list_reports.append(ll_res)
                            if ll_res.get("cycle_detected"):
                                findings.append({
                                    "severity": "CRITICAL",
                                    "category": "LINKED_LIST_CYCLE",
                                    "title": f"Infinite Pointer Cycle in Linked List '{var.name}'",
                                    "summary": ll_res["llm_next_step_hint"],
                                    "recommended_action": f"Fix list insertion/removal logic on '{var.name}' where node points back to index #{ll_res['cycle_target_index']}.",
                                })
                            elif ll_res.get("corrupted_link_detected"):
                                findings.append({
                                    "severity": "CRITICAL",
                                    "category": "LINKED_LIST_CORRUPTION",
                                    "title": f"Corrupted Pointer Link in Linked List '{var.name}'",
                                    "summary": ll_res["llm_next_step_hint"],
                                    "recommended_action": f"Inspect node link mutation on '{var.name}' (unmapped address {ll_res.get('corrupted_address')}).",
                                })
                        except Exception as ll_exc:
                            limitations.append(f"traverse_linked_structure('{var.name}') failed: {type(ll_exc).__name__}: {ll_exc}")
    except Exception as idx_exc:
        limitations.append(f"DWARF linked-list sweep failed: {type(idx_exc).__name__}: {idx_exc}")

    # IMP-017: this is a finding SCAN; it decides no verdict of its own.  Its status is the one verdict
    # vocabulary via the aggregator's explicit scan mapping (a scan never certifies health; a collection
    # failure without findings is INCONCLUSIVE; a scan finding is at most PROBABLE_FAULT).
    sev_Order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_Order.get(f.get("severity", "LOW"), 3))
    overall_status = verdict_for_scan(findings)
    score = health_score_for(overall_status, findings)
    severity_counts = {k: sum(1 for f in findings if f.get("severity") == k) for k in sev_Order}

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "collection_mode": "ZERO_STOP",
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "overall_status": overall_status,
        "verdict": overall_status,
        "health_score": score,
        "severity_counts": severity_counts,
        "limitations": limitations,
        "findings_count": len(findings),
        "findings": findings,
        "source_remediation_targets": source_targets,
        "memory_audit": audit_res,
        "callstacks_and_locks": callstack_res,
        "memory_pools": pool_reports,
        "linked_lists": linked_list_reports,
        "llm_next_step_hint": (
            f"Auto-Triage found {len(findings)} issue(s) (Status: {overall_status}). Top finding: [{findings[0]['severity']}] {findings[0]['title']} — {findings[0]['summary']}"
            if findings
            else (
                f"Auto-Triage inconclusive due to collection failure(s): {'; '.join(limitations[:3])}"
                if limitations
                else "Auto-Triage found no issue in the audited symbols, pools, locks and linked lists. A scan does "
                     "not certify the process healthy: run diagnose for a verdict."
            )
        ),
    }


# -------------------------------------------------------------------------
# Phase 43 (Phase 13): Autonomous Symptom Investigator, Cross-Entity
#                      Dependency Graph Synthesizer, and Source-to-Runtime
#                      Inline Correlator
# -------------------------------------------------------------------------

def build_dependency_graph(
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
    """Synthesizes a directed cross-entity dependency & causal graph across:
        `[Process] ➔ [Thread] ➔ [Mutex Lock / Stack Frame] ➔ [Memory Pool Slot / Heap Object] ➔ [Shared Memory Peer]`
        without stopping the target, and identifies `root_blocker_nodes` and `causal_chains`.
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

    blueprint = mgr.get_process_xray_blueprint(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    callstacks = mgr.inspect_thread_callstacks_and_locks(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    ipc_res = mgr.trace_ipc_pipeline(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    def _add_node(node_id: str, kind: str, label: str, status: str = "NORMAL", meta: Optional[Dict[str, Any]] = None) -> None:
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "kind": kind,
                "label": label,
                "status": status,
                "metadata": meta or {},
            }
        else:
            if status in ("CRITICAL", "BLOCKED", "CONTENDED") and nodes[node_id]["status"] == "NORMAL":
                nodes[node_id]["status"] = status
            if meta:
                nodes[node_id]["metadata"].update(meta)

    def _add_edge(src: str, dst: str, relation: str, detail: str = "") -> None:
        for e in edges:
            if e["from"] == src and e["to"] == dst and e["relation"] == relation:
                return
        edges.append({
            "from": src,
            "to": dst,
            "relation": relation,
            "detail": detail,
        })

    # 1. Process Node
    proc_node_id = f"PROC:{pid}"
    _add_node(
        proc_node_id,
        kind="PROCESS",
        label=f"PID {pid} ({os.path.basename(primary_elf)})",
        status="NORMAL",
        meta={"pid": pid, "load_bias": blueprint.get("load_bias")},
    )

    # 2. Thread & Lock Nodes
    threads_by_tid: Dict[int, Dict[str, Any]] = {}
    for t in callstacks.get("threads", []):
        tid_val = int(t["tid"])
        threads_by_tid[tid_val] = t
        t_node_id = f"THREAD:{tid_val}"
        top_frame = t["callstack"][0] if t.get("callstack") else None
        wait_lock = t.get("waiting_on_lock")
        t_status = "BLOCKED" if wait_lock else "NORMAL"
        _add_node(
            t_node_id,
            kind="THREAD",
            label=f"TID {tid_val} ({t.get('name', 'thread')})",
            status=t_status,
            meta={
                "tid": tid_val,
                "name": t.get("name"),
                "state": t.get("state"),
                "syscall": t.get("syscall"),
                "top_function": top_frame.get("function_name") if top_frame else None,
                "source_location": next((f.get("source_location") for f in (t.get("callstack") or [])
                                         if f.get("source_location")), None),
            },
        )
        _add_edge(proc_node_id, t_node_id, "HAS_THREAD")

    for lk in callstacks.get("locks", []):
        lk_name = lk["name"]
        lk_node_id = f"LOCK:{lk_name}"
        is_contended = bool(lk.get("waiting_tids"))
        _add_node(
            lk_node_id,
            kind="MUTEX_LOCK",
            label=f"Mutex {lk_name} ({lk.get('runtime_address')})",
            status="CONTENDED" if is_contended else ("LOCKED" if lk.get("is_locked") else "NORMAL"),
            meta=lk,
        )
        owner_tid = lk.get("owner_tid")
        if owner_tid:
            owner_id = f"THREAD:{owner_tid}"
            _add_node(owner_id, kind="THREAD", label=f"TID {owner_tid} ({lk.get('owner_thread_name') or 'thread'})")
            _add_edge(
                lk_node_id,
                owner_id,
                "HELD_BY_THREAD",
                detail=f"Mutex {lk_name} is held by TID {owner_tid}",
            )
        for w_tid in (lk.get("waiting_tids") or []):
            waiter_id = f"THREAD:{w_tid}"
            _add_node(waiter_id, kind="THREAD", label=f"TID {w_tid}", status="BLOCKED")
            _add_edge(
                waiter_id,
                lk_node_id,
                "WAITS_ON_LOCK",
                detail=f"TID {w_tid} blocked in futex waiting for {lk_name}",
            )

    # 3. Memory Pool & Occupied Buffer Slot Ownership Edges
    pools_meta = blueprint.get("categories", {}).get("memory_pools_and_buffers", [])
    for pm in pools_meta[:2]:
        expr = pm.get("recommended_pool_expression") or pm.get("name")
        if not expr:
            continue
        try:
            p_scan = mgr.scan_memory_pool_or_array(
                pid=pid,
                companion_elf_path=companion_elf_path,
                base_expression=expr,
                adapter=target_adapter,
            )
            arr_expr = p_scan["resolved_array_expression"]
            pool_id = f"POOL:{arr_expr}"
            util_pct = p_scan["pool_summary"]["utilization_pct"]
            _add_node(
                pool_id,
                kind="MEMORY_POOL",
                label=f"Pool {arr_expr} ({p_scan['pool_summary']['allocated_count']}/{p_scan['pool_summary']['total_slots']} IN_USE, {util_pct}%)",
                status="CONTENDED" if util_pct >= 75.0 else "NORMAL",
                meta=p_scan["pool_summary"],
            )
            _add_edge(proc_node_id, pool_id, "OWNS_POOL")

            # Inspect up to 4 allocated slots to link slots -> owner threads
            for alloc_idx in p_scan["pool_summary"].get("allocated_indices", [])[:4]:
                slot_expr = f"{arr_expr}[{alloc_idx}]"
                slot_node_id = f"SLOT:{slot_expr}"
                owner_res = mgr.find_symbol_owners_and_threads(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    target_expression=slot_expr,
                    adapter=target_adapter,
                )
                _add_node(
                    slot_node_id,
                    kind="BUFFER_SLOT",
                    label=f"{slot_expr} ({owner_res.get('target_runtime_address')})",
                    status="IN_USE",
                    meta={
                        "expression": slot_expr,
                        "runtime_address": owner_res.get("target_runtime_address"),
                    },
                )
                _add_edge(pool_id, slot_node_id, "HAS_ALLOCATED_SLOT")
                for mt in owner_res.get("matched_threads", []):
                    mt_tid = int(mt["tid"])
                    t_node_id = f"THREAD:{mt_tid}"
                    _add_node(t_node_id, kind="THREAD", label=f"TID {mt_tid} ({mt.get('thread_name', 'thread')})")
                    ev_kind = (mt.get("evidence") or [{}])[0].get("evidence_kind", "REFERENCES_SLOT")
                    _add_edge(
                        t_node_id,
                        slot_node_id,
                        "OCCUPIES_SLOT",
                        detail=f"TID {mt_tid} ({mt.get('thread_name')}) holds {slot_expr} via {ev_kind}",
                    )
        except Exception:
            pass

    # 4. Shared Memory IPC & Peer Process Edges
    for shm in ipc_res.get("shared_mappings", []):
        shm_path = shm.get("pathname") or shm.get("start")
        shm_id = f"SHM:{shm_path}"
        p_health = ipc_res.get("pipeline_health", "HEALTHY_PIPELINE")
        _add_node(
            shm_id,
            kind="SHARED_MEMORY",
            label=f"SHM {shm_path} ({p_health})",
            status="CONTENDED" if p_health != "HEALTHY_PIPELINE" else "NORMAL",
            meta=ipc_res.get("metrics") or {},
        )
        _add_edge(proc_node_id, shm_id, "MAPS_SHM", detail=ipc_res.get("bottleneck_diagnosis", ""))
        for peer in ipc_res.get("peer_processes", []):
            if peer.get("shared_pathname") == shm_path or not peer.get("shared_pathname"):
                peer_id = f"PEER_PROC:{peer['peer_pid']}"
                _add_node(
                    peer_id,
                    kind="PEER_PROCESS",
                    label=f"Peer PID {peer['peer_pid']} ({peer.get('peer_name', 'peer')})",
                    status="NORMAL",
                    meta=peer,
                )
                _add_edge(shm_id, peer_id, "SHARED_WITH_PEER")

    # Synthesize Root Blocker Nodes & Human/LLM-Readable Causal Chains
    root_blocker_nodes: List[Dict[str, Any]] = []
    causal_chains: List[Dict[str, Any]] = []

    # Pattern 1: Thread A waits on Lock L held by Thread B (which may also occupy a Buffer Slot)
    for e_wait in edges:
        if e_wait["relation"] != "WAITS_ON_LOCK":
            continue
        waiter_id = e_wait["from"]
        lock_id = e_wait["to"]
        holder_edges = [e for e in edges if e["from"] == lock_id and e["relation"] == "HELD_BY_THREAD"]
        for eh in holder_edges:
            holder_id = eh["to"]
            holder_node = nodes.get(holder_id, {})
            waiter_node = nodes.get(waiter_id, {})
            lock_node = nodes.get(lock_id, {})
            held_slots = [e["to"] for e in edges if e["from"] == holder_id and e["relation"] == "OCCUPIES_SLOT"]

            chain_steps = [
                f"{waiter_node.get('label', waiter_id)} is BLOCKED waiting on {lock_node.get('label', lock_id)}",
                f"{lock_node.get('label', lock_id)} is currently HELD by {holder_node.get('label', holder_id)} at {holder_node.get('metadata', {}).get('source_location') or holder_node.get('metadata', {}).get('top_function') or 'active frame'}",
            ]
            if held_slots:
                chain_steps.append(f"{holder_node.get('label', holder_id)} simultaneously occupies {', '.join(held_slots)}")

            causal_chains.append({
                "chain_type": "LOCK_CONTENTION_CHAIN",
                "root_blocker_id": holder_id,
                "root_blocker_label": holder_node.get("label", holder_id),
                "source_location": holder_node.get("metadata", {}).get("source_location"),
                "impacted_entities": [waiter_id, lock_id] + held_slots,
                "steps": chain_steps,
                "ascii_flow": f"[{waiter_node.get('label', waiter_id)}] ──(waits)──▶ [{lock_node.get('label', lock_id)}] ──(held by)──▶ [{holder_node.get('label', holder_id)}]"
                + (f" ──(occupies)──▶ [{', '.join(held_slots)}]" if held_slots else ""),
            })
            if not any(r["id"] == holder_id for r in root_blocker_nodes):
                root_blocker_nodes.append(holder_node)

    # Pattern 2: Thread occupies buffer slots even when no mutex is contended
    for e_slot in edges:
        if e_slot["relation"] != "OCCUPIES_SLOT":
            continue
        holder_id = e_slot["from"]
        slot_id = e_slot["to"]
        holder_node = nodes.get(holder_id, {})
        slot_node = nodes.get(slot_id, {})
        if not any(c.get("root_blocker_id") == holder_id for c in causal_chains):
            causal_chains.append({
                "chain_type": "RESOURCE_HOLD_CHAIN",
                "root_blocker_id": holder_id,
                "root_blocker_label": holder_node.get("label", holder_id),
                "source_location": holder_node.get("metadata", {}).get("source_location"),
                "impacted_entities": [slot_id],
                "steps": [
                    f"{holder_node.get('label', holder_id)} occupies {slot_node.get('label', slot_id)}",
                ],
                "ascii_flow": f"[{holder_node.get('label', holder_id)}] ──(occupies)──▶ [{slot_node.get('label', slot_id)}]",
            })

    # Pattern 3: Shared Memory IPC Backlog Chain
    if ipc_res.get("pipeline_health") not in (None, "HEALTHY_PIPELINE"):
        peers = ipc_res.get("peer_processes") or []
        peer_label = f"PID {peers[0]['peer_pid']} ({peers[0]['peer_name']})" if peers else "Consumer Process"
        causal_chains.append({
            "chain_type": "IPC_BACKLOG_CHAIN",
            "root_blocker_id": f"PEER_PROC:{peers[0]['peer_pid']}" if peers else proc_node_id,
            "root_blocker_label": peer_label,
            "source_location": None,
            "impacted_entities": [proc_node_id],
            "steps": [ipc_res.get("bottleneck_diagnosis", "")],
            "ascii_flow": f"[PID {pid}] ──(SHM backlog {ipc_res.get('metrics', {}).get('pending_backlog', 0)})──▶ [{peer_label}]",
        })

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "nodes_count": len(nodes),
        "edges_count": len(edges),
        "nodes": list(nodes.values()),
        "edges": edges,
        "root_blocker_nodes": root_blocker_nodes,
        "causal_chains": causal_chains,
        "llm_next_step_hint": (
            f"Synthesized {len(causal_chains)} causal chain(s) across {len(nodes)} runtime entities. "
            + (f"Top root blocker: {causal_chains[0]['ascii_flow']}" if causal_chains else "No blocking dependency chains detected.")
        ),
    }


def correlate_source_and_state(
    mgr,
    pid: int,
    companion_elf_path: str,
    source_location: Optional[str] = None,
    tid: Optional[int] = None,
    context_lines: int = 8,
    source_search_dirs: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Correlates DWARF `file:line` source locations and active stack frames with real C/C++
        source code files on disk, overlaying live runtime values of parameters, local variables,
        and referenced global symbols inline (`annotated_lines`) without stopping the target.
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
    elf_dir = os.path.dirname(os.path.abspath(primary_elf))
    search_dirs = list(source_search_dirs or []) + [elf_dir, os.getcwd(), "/tmp"]

    # Decode active thread frame locals/parameters so we can overlay them onto source lines
    frame_locals_res = mgr.inspect_thread_locals_and_frame_vars(
        pid=pid,
        companion_elf_path=companion_elf_path,
        tid=tid,
        max_frames=6,
        adapter=target_adapter,
    )

    # Collect target (file, line, function_name, live_vars_dict) tuples to annotate
    targets_to_annotate: List[Dict[str, Any]] = []

    if source_location and ":" in source_location:
        f_part, l_part = source_location.rsplit(":", 1)
        try:
            line_no = int(l_part.strip())
        except ValueError:
            line_no = 1
        live_map: Dict[str, Any] = {}
        matched_fn = None
        for th in frame_locals_res.get("threads", []):
            for fr in th.get("frames", []):
                fr_loc = fr.get("source_location") or ""
                if os.path.basename(f_part) in fr_loc:
                    matched_fn = fr.get("function_name")
                    for p in fr.get("parameters", []):
                        live_map[p["name"]] = p["value"]
                    for l in fr.get("locals", []):
                        live_map[l["name"]] = l["value"]
        targets_to_annotate.append({
            "file_hint": f_part.strip(),
            "target_line": line_no,
            "function_name": matched_fn,
            "tid": tid,
            "live_variables": live_map,
        })
    else:
        for th in frame_locals_res.get("threads", []):
            for fr in th.get("frames", [])[:2]:
                fr_loc = fr.get("source_location")
                if not fr_loc or ":" not in fr_loc:
                    continue
                f_part, l_part = fr_loc.rsplit(":", 1)
                try:
                    line_no = int(l_part.strip())
                except ValueError:
                    continue
                live_map = {}
                for p in fr.get("parameters", []):
                    live_map[p["name"]] = p["value"]
                for l in fr.get("locals", []):
                    live_map[l["name"]] = l["value"]
                targets_to_annotate.append({
                    "file_hint": f_part.strip(),
                    "target_line": line_no,
                    "function_name": fr.get("function_name"),
                    "tid": th.get("tid"),
                    "thread_name": th.get("name"),
                    "live_variables": live_map,
                })

    # Also add top global variables to a global lookup table so references in source lines get annotated
    global_var_names = {
        v.name for v in idx.variables
        if v.name and not v.name.startswith("__") and v.link_time_address is not None
    }

    def _locate_source_file(file_hint: str) -> Optional[str]:
        if os.path.isabs(file_hint) and os.path.isfile(file_hint):
            return file_hint
        base_name = os.path.basename(file_hint)
        for d in search_dirs:
            cand1 = os.path.join(d, file_hint)
            if os.path.isfile(cand1):
                return cand1
            cand2 = os.path.join(d, base_name)
            if os.path.isfile(cand2):
                return cand2
        return None

    snippets: List[Dict[str, Any]] = []
    clamped_ctx = max(3, min(int(context_lines), 25))

    for tgt in targets_to_annotate[:4]:
        resolved_path = _locate_source_file(tgt["file_hint"])
        t_line = int(tgt["target_line"])
        live_vars = dict(tgt.get("live_variables") or {})

        if resolved_path and os.path.isfile(resolved_path):
            try:
                with open(resolved_path, "r", encoding="utf-8", errors="replace") as sf:
                    all_lines = sf.read().splitlines()
            except Exception:
                all_lines = []
        else:
            all_lines = []

        annotated_lines: List[Dict[str, Any]] = []
        if all_lines:
            start_ln = max(1, t_line - clamped_ctx // 2)
            end_ln = min(len(all_lines), t_line + clamped_ctx)
            window_text = "\n".join(all_lines[start_ln - 1 : end_ln])

            # Check if any DWARF global variable appears in this source window
            referenced_globals = [g for g in global_var_names if re.search(rf"\b{re.escape(g)}\b", window_text)]
            if referenced_globals:
                try:
                    g_eval = mgr.evaluate_symbol_paths(
                        pid=pid,
                        companion_elf_path=companion_elf_path,
                        expressions=referenced_globals[:6],
                        adapter=target_adapter,
                    )
                    for r in g_eval.get("results", []):
                        if r.get("status") == "OBSERVED" and r.get("expression"):
                            live_vars[r["expression"]] = r.get("value")
                except Exception:
                    pass

            for ln_no in range(start_ln, end_ln + 1):
                code_str = all_lines[ln_no - 1]
                inline_hits: Dict[str, Any] = {}
                for v_name, v_val in live_vars.items():
                    if re.search(rf"\b{re.escape(v_name)}\b", code_str):
                        inline_hits[v_name] = v_val
                annotated_lines.append({
                    "line_number": ln_no,
                    "is_target_line": (ln_no == t_line),
                    "code": code_str,
                    "live_annotations": inline_hits,
                    "formatted": (
                        f"{'▶' if ln_no == t_line else ' '} {ln_no:4d} | {code_str}"
                        + (f"   // [LIVE] " + ", ".join(f"{k}={json.dumps(v, ensure_ascii=False)}" for k, v in inline_hits.items()) if inline_hits else "")
                    ),
                })

        snippets.append({
            "file_hint": tgt["file_hint"],
            "resolved_source_path": resolved_path,
            "target_line": t_line,
            "function_name": tgt.get("function_name"),
            "tid": tgt.get("tid"),
            "thread_name": tgt.get("thread_name"),
            "live_variables": live_vars,
            "annotated_lines": annotated_lines,
            "annotated_code_block": "\n".join(l["formatted"] for l in annotated_lines) if annotated_lines else None,
        })

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "snippets_count": len(snippets),
        "snippets": snippets,
        "llm_next_step_hint": (
            f"Correlated {len(snippets)} active source location(s) with inline live runtime variable values."
            if snippets
            else "No source locations with debug line info were found on active frames."
        ),
    }


def investigate_symptom(
    mgr,
    pid: int,
    companion_elf_path: str,
    symptom_query: str = "왜 멈췄지? 전체적인 문제를 종합 분석해줘",
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Autonomous Symptom-Driven Multi-Stage Root-Cause Investigator (zero-stop; the target is not suspended).
        Accepts a simple, high-level user symptom question (e.g. '왜 멈췄지?', '버벅거려', '메모리가 새는 것 같아',
        '왜 응답이 없지?') and automatically orchestrates:
        1. Symptom Classification (`HANG_OR_DEADLOCK`, `MEMORY_LEAK_OR_EXHAUSTION`, `MEMORY_CORRUPTION`, `IPC_BOTTLENECK`, `GENERAL_ANOMALY`)
        2. One-Call Incident Auto-Triage (`auto_triage_incident`)
        3. Cross-Entity Causal Dependency Graph (`build_dependency_graph`)
        4. Heap Polymorphic Leak Census (`scan_heap_objects`) when memory/leak/general symptoms are present
        5. Source-to-Runtime Inline Code Correlation (`correlate_source_and_state`) on the root blocker frame
        Synthesizes a unified `root_cause_hypothesis`, `causal_chain`, `confidence_score`, and `remediation_plan`.
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
    q_low = (symptom_query or "").lower()

    # 1. Classify user's natural-language symptom intent
    if any(k in q_low for k in ("멈췄", "멈춤", "응답", "락", "데드락", "블록", "hang", "stuck", "freeze", "deadlock", "wait")):
        classified_symptom = "HANG_OR_DEADLOCK"
    elif any(k in q_low for k in ("누수", "새는", "메모리 부족", "고갈", "힙", "leak", "oom", "exhaust")):
        classified_symptom = "MEMORY_LEAK_OR_EXHAUSTION"
    elif any(k in q_low for k in ("깨졌", "오염", "크래시", "세그폴트", "유효하지", "corrupt", "crash", "dangling", "overflow")):
        classified_symptom = "MEMORY_CORRUPTION"
    elif any(k in q_low for k in ("느려", "지연", "밀려", "파이프라인", "큐", "프로듀서", "컨슈머", "slow", "lag", "ipc", "drop")):
        classified_symptom = "PIPELINE_OR_PERF_BOTTLENECK"
    else:
        classified_symptom = "COMPREHENSIVE_SYMPTOM_CHECK"

    # 2. Run composite triage + dependency graph + source correlation + heap scan
    legacy_sweep_errors: List[Dict[str, Any]] = []
    try:
        triage = mgr.auto_triage_incident(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )
    except Exception as exc:
        legacy_sweep_errors.append({"stage": "auto_triage_incident", "error_type": type(exc).__name__, "error": str(exc)})
        triage = {"overall_status": "INCONCLUSIVE", "health_score": None, "findings": [], "limitations": [f"{type(exc).__name__}: {exc}"], "source_remediation_targets": []}
    try:
        dep_graph = mgr.build_dependency_graph(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )
    except Exception as exc:
        legacy_sweep_errors.append({"stage": "build_dependency_graph", "error_type": type(exc).__name__, "error": str(exc)})
        dep_graph = {"causal_chains": [], "nodes_count": 0, "edges_count": 0, "nodes": [], "edges": [], "root_blocker_nodes": []}
    try:
        heap_report = mgr.scan_heap_objects(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )
    except Exception as exc:
        legacy_sweep_errors.append({"stage": "scan_heap_objects", "error_type": type(exc).__name__, "error": str(exc)})
        heap_report = {"leaked_candidates_count": 0, "total_objects_found": 0, "objects": [], "class_histogram": {}}

    # Merge heap leak findings into triage findings if any leaked objects were discovered
    findings = list(triage.get("findings") or [])
    if heap_report.get("leaked_candidates_count", 0) > 0:
        leaked_objs = [o for o in heap_report.get("objects", []) if o.get("is_leaked_candidate")]
        sample_leak = leaked_objs[0]
        findings.append({
            "severity": "HIGH",
            "category": "HEAP_MEMORY_LEAK",
            "title": f"Unreferenced C++ Heap Object Leak ({heap_report['leaked_candidates_count']} instance(s) of {sample_leak['class_name']})",
            "summary": f"Heap object {sample_leak['class_name']} @ {sample_leak['address']} has no incoming pointer from globals, thread stacks, or heap.",
            "recommended_action": f"Verify destructor / smart-pointer lifecycle for dynamically allocated `{sample_leak['class_name']}` instances.",
        })

    # Run statistical hotspot profiler when slowness/CPU/comprehensive symptoms are queried
    hotspot_report = None
    if classified_symptom in ("PIPELINE_OR_PERF_BOTTLENECK", "COMPREHENSIVE_SYMPTOM_CHECK", "HANG_OR_DEADLOCK"):
        try:
            hotspot_report = mgr.sample_statistical_hotspots(
                pid=pid,
                companion_elf_path=companion_elf_path,
                samples_count=4,
                interval_ms=25,
                adapter=target_adapter,
            )
            top_hs = (hotspot_report.get("hotspot_functions") or [None])[0]
            if top_hs and top_hs.get("inclusive_pct", 0) >= 75.0 and not findings:
                findings.append({
                    "severity": "HIGH",
                    "category": "CPU_HOTSPOT_LOOP",
                    "title": f"High Callstack Residency in `{top_hs['function_name']}()` ({top_hs['inclusive_pct']}%)",
                    "summary": f"Function `{top_hs['function_name']}` ({top_hs.get('source_location')}) appeared in {top_hs['inclusive_pct']}% of statistical samples across {top_hs.get('threads')}.",
                    "source_location": top_hs.get("source_location"),
                    "recommended_action": f"Inspect loop termination condition and sleep/yield intervals inside `{top_hs['function_name']}()`.",
                })
        except Exception as hs_exc:
            legacy_sweep_errors.append({"stage": "sample_statistical_hotspots", "error_type": type(hs_exc).__name__, "error": str(hs_exc)})
            hotspot_report = None

    # Correlate source code with runtime variables at top remediation target or active thread frame
    top_source_loc = (triage.get("source_remediation_targets") or [None])[0]
    try:
        source_corr = mgr.correlate_source_and_state(
            pid=pid,
            companion_elf_path=companion_elf_path,
            source_location=top_source_loc,
            adapter=target_adapter,
        )
    except Exception as exc:
        legacy_sweep_errors.append({"stage": "correlate_source_and_state", "error_type": type(exc).__name__, "error": str(exc)})
        source_corr = {"snippets": []}

    # Synthesize primary root-cause hypothesis and step-by-step causal narrative
    causal_chains = dep_graph.get("causal_chains") or []
    if findings or causal_chains:
        top_f = findings[0] if findings else None
        top_chain = causal_chains[0] if causal_chains else None
        if top_chain and top_f:
            hypothesis = f"[{top_f['category']}] {top_f['title']} — {top_chain['ascii_flow']}"
        elif top_f:
            hypothesis = f"[{top_f['category']}] {top_f['title']}: {top_f['summary']}"
        else:
            hypothesis = f"[{top_chain['chain_type']}] {top_chain['ascii_flow']}"
        confidence_score = 0.94 if (top_f and top_f.get("severity") == "CRITICAL") else 0.88
    elif legacy_sweep_errors or triage.get("overall_status") == "INCONCLUSIVE" or triage.get("limitations"):
        lim_parts = [f"{e.get('stage')}: {e.get('error')}" for e in legacy_sweep_errors] + list(triage.get("limitations") or [])
        hypothesis = f"Diagnostic inspection inconclusive due to collection failure(s): {'; '.join(lim_parts[:3])}"
        confidence_score = 0.20
    else:
        hypothesis = "No critical lock contention, memory corruption, or unreferenced heap leak detected in current zero-stop snapshot."
        confidence_score = 0.80

    remediation_steps: List[str] = []
    for f in findings[:4]:
        if f.get("recommended_action") and f["recommended_action"] not in remediation_steps:
            remediation_steps.append(f["recommended_action"])

    # IMP-017: the verification step and the verdict are diagnose() (the retired adaptive engine used to run
    # here).  The scans above are context; they decide nothing.
    diagnosis: Optional[Dict[str, Any]] = None
    diagnosis_error_details: List[Dict[str, Any]] = []
    exec_status = "COMPLETED"
    fail_category: Optional[str] = None
    stop_reason = "SUFFICIENT_EVIDENCE"
    try:
        from .. import expert_diagnostic_engine as _ede
        diagnosis = _ede.diagnose(pid, debug_image=companion_elf_path or None, symptom=symptom_query,
                                  adapter=target_adapter, corpus_dir=mgr.corpus_dir).to_dict()
        if not diagnosis.get("checks_run"):
            exec_status = "INCONCLUSIVE"
        stop_reason = str(diagnosis.get("stop_reason") or stop_reason)
    except Exception as diag_exc:  # noqa: BLE001 - never swallowed: reported and capped below
        exec_status = "FAILED"
        fail_category = type(diag_exc).__name__
        stop_reason = "DIAGNOSIS_EXCEPTION"
        diagnosis_error_details.append({"stage": "diagnose", "error_type": type(diag_exc).__name__,
                                        "error": str(diag_exc)})
        confidence_score = min(confidence_score, 0.35)
    checks = list((diagnosis or {}).get("checks_run") or [])
    actual_obs_cnt = len(checks)
    succ_obs_cnt = sum(1 for c in checks if c.get("status") in ("PASS", "FAIL"))
    fail_obs_cnt = sum(1 for c in checks if c.get("status") == "ERROR")
    abs_obs_cnt = actual_obs_cnt - succ_obs_cnt - fail_obs_cnt
    consumed_budget = dict((diagnosis or {}).get("collection_impact") or {})

    all_symp_limitations = list(triage.get("limitations") or []) + [
        f"{e.get('stage')}: {e.get('error')}" for e in legacy_sweep_errors
    ]
    if diagnosis is not None:
        eff_overall_status = str(diagnosis.get("verdict") or VERDICT_INCONCLUSIVE)
        confidence_score = float(diagnosis.get("confidence") or 0.0)
        if diagnosis.get("findings"):
            top = diagnosis["findings"][0]
            hypothesis = (f"[{top.get('category')}] {top.get('description')}"
                          + (f" (subjects: {', '.join(map(str, (top.get('subjects') or [])[:4]))})"
                             if top.get("subjects") else ""))
    else:
        eff_overall_status = verdict_for_scan(findings)
    if eff_overall_status == VERDICT_INCONCLUSIVE:
        confidence_score = min(confidence_score, 0.20)
        if stop_reason == "SUFFICIENT_EVIDENCE":
            stop_reason = "NO_USEFUL_SAFE_OBSERVATION_REMAINS"
    eff_health_score = health_score_for(eff_overall_status, (diagnosis or {}).get("findings") or findings)

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "symptom_query": symptom_query,
        "execution_status": exec_status,
        "overall_status": eff_overall_status,
        "failure_category": fail_category,
        "stop_reason": stop_reason,
        "limitations": all_symp_limitations,
        "verdict": eff_overall_status,
        "diagnostic_error_details": diagnosis_error_details,
        "collection_error_details": list(legacy_sweep_errors),
        "actual_observation_count": actual_obs_cnt,
        "successful_observation_count": succ_obs_cnt,
        "failed_observation_count": fail_obs_cnt,
        "abstained_observation_count": abs_obs_cnt,
        "consumed_execution_budget": consumed_budget,
        "diagnosis_succeeded": diagnosis is not None,
        "legacy_findings": list(findings),
        "diagnosis": diagnosis,
        "classified_symptom": classified_symptom,
        "root_cause_hypothesis": hypothesis,
        "confidence_score": confidence_score,
        "health_score": eff_health_score,
        "findings_count": len(findings),
        "findings": findings,
        "causal_chains": causal_chains,
        "dependency_graph": {
            "nodes_count": dep_graph.get("nodes_count", 0),
            "edges_count": dep_graph.get("edges_count", 0),
            "nodes": dep_graph.get("nodes", []),
            "edges": dep_graph.get("edges", []),
            "root_blocker_nodes": dep_graph.get("root_blocker_nodes", []),
        },
        "annotated_source_snippets": source_corr.get("snippets", []),
        "heap_leak_summary": {
            "total_objects_found": heap_report.get("total_objects_found", 0),
            "leaked_candidates_count": heap_report.get("leaked_candidates_count", 0),
            "class_histogram": heap_report.get("class_histogram", {}),
        },
        "statistical_hotspots": hotspot_report,
        "remediation_steps": remediation_steps,
        "llm_next_step_hint": (
            f"Symptom Investigation ({classified_symptom}) complete with confidence {int(confidence_score * 100)}%: {hypothesis}"
        ),
    }
