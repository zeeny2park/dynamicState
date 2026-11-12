"""Agent-facing composition: natural-language runtime questions, LLM token-budget summaries, the smart compact query
and the batch macro executor.

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import json
import re
import time
from typing import Any, Dict, List, Optional

from ..target_adapter import TargetExecutionAdapter


def _coerce_steps_list(val: Any, max_steps: int = 32) -> List[Dict[str, Any]]:
    """Safely coerces batch macro steps from JSON string, single dict, or list of dicts."""
    if val is None:
        return []
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return []
        try:
            parsed = json.loads(s)
            if isinstance(parsed, dict):
                return [parsed]
            if isinstance(parsed, list):
                val = parsed
            else:
                return [{"action": "ask", "question": s}]
        except Exception:
            return [{"action": "ask", "question": s}]
    if isinstance(val, dict):
        return [val]
    if isinstance(val, (list, tuple)):
        out: List[Dict[str, Any]] = []
        for item in val[:max_steps]:
            if isinstance(item, dict):
                out.append(item)
            elif isinstance(item, str) and item.strip():
                out.append({"action": "eval", "expression": item.strip()})
            else:
                out.append({
                    "action": "malformed_step",
                    "raw_item": item,
                    "error": f"Invalid step format: expected dictionary or expression string, got {type(item).__name__}",
                })
        return out
    return []


def ask_runtime_question(
    mgr,
    question: str,
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    process_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Universal 1-Call Intent Gateway (`runtime_ask`) in zero-stop mode.
        Accepts any C/C++ expression (even with `.` vs `->` mistakes, omitted root globals, or typos)
        OR any natural-language diagnostic question in Korean/English, automatically resolves/heals
        the active `(pid, companion_elf)` context, routes to the optimal zero-stop engine, and returns
        a unified response.
        """
    t_start_ns = time.monotonic_ns()
    ctx_info = mgr.resolve_target_context(
        pid=pid,
        companion_elf_path=companion_elf_path,
        process_name=process_name,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    eff_pid = ctx_info["pid"]
    eff_elf = ctx_info["companion_elf_path"]
    q_str = (question or "").strip()
    q_low = q_str.lower()

    # Extract candidate C/C++ expression tokens from question if present
    expr_candidates: List[str] = []
    # Check if the entire question is a single C/C++ expression
    if re.match(r"^[\*\(\)\w:\.\->\[\]]+$", q_str) and not q_str.isdigit():
        expr_candidates.append(q_str)
    else:
        for m in re.finditer(r"(\*?[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|->)[A-Za-z_][A-Za-z0-9_]*|\[\d+\])+)", q_str):
            tok = m.group(1)
            if tok not in expr_candidates:
                expr_candidates.append(tok)

    routed_tool = ""
    routed_result: Dict[str, Any] = {}

    # Route 1: DPDK / Lcore / PMD / rte_ring / rte_spinlock intent
    if any(k in q_low for k in ("dpdk", "lcore", "pmd", "rte_ring", "isolcpu", "spinlock", "폴링 코어")):
        routed_tool = "runtime_inspect_dpdk_lcores_and_rings"
        routed_result = mgr.inspect_dpdk_lcores_and_rings(
            pid=eff_pid,
            companion_elf_path=eff_elf,
            remote_host=ctx_info.get("remote_host"),
            ssh_user=ctx_info.get("ssh_user"),
            ssh_port=ctx_info.get("ssh_port", 22),
            ssh_key=ctx_info.get("ssh_key"),
            ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
            adapter=adapter,
        )
    # Route 2: Thread-Local Storage (`__thread` / `thread_local`) intent
    elif any(k in q_low for k in ("tls", "thread_local", "__thread", "스레드 로컬")):
        routed_tool = "runtime_inspect_thread_local_storage"
        routed_result = mgr.inspect_thread_local_storage(
            pid=eff_pid,
            companion_elf_path=eff_elf,
            remote_host=ctx_info.get("remote_host"),
            ssh_user=ctx_info.get("ssh_user"),
            ssh_port=ctx_info.get("ssh_port", 22),
            ssh_key=ctx_info.get("ssh_key"),
            ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
            adapter=adapter,
        )
    # Route 3: Thread Ownership / Who holds buffer slot intent
    elif any(k in q_low for k in ("누가", "owner", "소유", "잡고", "홀딩", "holding", "using")) and (
        expr_candidates or re.search(r"(\d+)\s*번", q_str) or "buffer" in q_low or "버퍼" in q_low
    ):
        routed_tool = "runtime_find_symbol_owners"
        target_expr = expr_candidates[0] if expr_candidates else "buffers[0]"
        if not expr_candidates:
            m_num = re.search(r"(\d+)", q_str)
            if m_num:
                target_expr = f"buffers[{m_num.group(1)}]"
        routed_result = mgr.find_symbol_owners_and_threads(
            pid=eff_pid,
            companion_elf_path=eff_elf,
            target_expression=target_expr,
            remote_host=ctx_info.get("remote_host"),
            ssh_user=ctx_info.get("ssh_user"),
            ssh_port=ctx_info.get("ssh_port", 22),
            ssh_key=ctx_info.get("ssh_key"),
            ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
            adapter=adapter,
        )
    # Route 4: Memory Pool / Slot Bitmap Scan intent
    elif any(k in q_low for k in ("메모리 풀", "버퍼 풀", "memory pool", "slot map", "할당 현황", "bitmap")):
        routed_tool = "runtime_scan_memory_pool"
        base_expr = expr_candidates[0] if expr_candidates else "*gpMem"
        routed_result = mgr.scan_memory_pool_or_array(
            pid=eff_pid,
            companion_elf_path=eff_elf,
            base_expression=base_expr,
            remote_host=ctx_info.get("remote_host"),
            ssh_user=ctx_info.get("ssh_user"),
            ssh_port=ctx_info.get("ssh_port", 22),
            ssh_key=ctx_info.get("ssh_key"),
            ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
            adapter=adapter,
        )
    # Route 5: Direct or Forgiving C/C++ Expression Evaluation
    elif expr_candidates:
        routed_tool = "runtime_eval_memory_path"
        routed_result = mgr.evaluate_symbol_paths(
            pid=eff_pid,
            companion_elf_path=eff_elf,
            expressions=expr_candidates,
            remote_host=ctx_info.get("remote_host"),
            ssh_user=ctx_info.get("ssh_user"),
            ssh_port=ctx_info.get("ssh_port", 22),
            ssh_key=ctx_info.get("ssh_key"),
            ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
            adapter=adapter,
        )
    # Route 6: Autonomous Symptom Investigation
    else:
        routed_tool = "runtime_investigate_symptom"
        routed_result = mgr.investigate_symptom(
            pid=eff_pid,
            companion_elf_path=eff_elf,
            symptom_query=q_str or "왜 멈췄지? 전체 상태 종합 진단",
            remote_host=ctx_info.get("remote_host"),
            ssh_user=ctx_info.get("ssh_user"),
            ssh_port=ctx_info.get("ssh_port", 22),
            ssh_key=ctx_info.get("ssh_key"),
            ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
            adapter=adapter,
        )

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    out: Dict[str, Any] = {
        **routed_result,
        "question": q_str,
        "routed_tool": routed_tool,
        "pid": eff_pid,
        "companion_elf": eff_elf,
        "auto_healed_pid": ctx_info.get("auto_healed_pid", False),
        "previous_pid": ctx_info.get("previous_pid"),
        "elf_auto_discovered": ctx_info.get("elf_auto_discovered", False),
        "elf_discovery_source": ctx_info.get("elf_discovery_source"),
        "active_context": ctx_info,
        "stop_duration_ms": 0.0,
        "gateway_latency_us": latency_us,
        "result": routed_result,
    }
    return out


def summarize_for_llm_budget(
    mgr,
    data: Dict[str, Any],
    max_tokens: int = 1200,
    drop_zero_or_free: bool = True,
    cursor_offset: int = 0,
    page_size: int = 16,
) -> Dict[str, Any]:
    """LLM Context-Window Budgeter & Anomaly-First Smart Compactor.
        1. Strips repetitive `FREE` slots or all-zero/NULL struct fields (`drop_zero_or_free=True`)
           while preserving 100% of `IN_USE`, anomalous, or non-zero items first.
        2. Applies deterministic cursor pagination (`cursor_offset`, `page_size`) to large collections
           (`slots`, `results`, `threads`, `objects`, `nodes`) and returns `pagination.next_cursor_offset`.
        3. Reports `original_estimated_tokens`, `compacted_estimated_tokens`, and `token_reduction_pct`.
        """
    raw_json_str = json.dumps(data, ensure_ascii=False, default=str)
    orig_tokens = max(1, len(raw_json_str) // 4)
    clamped_offset = max(0, int(cursor_offset or 0))
    clamped_page = max(1, min(int(page_size or 16), 200))

    compacted: Dict[str, Any] = {}
    for k, v in data.items():
        # Omit redundant verbose ASCII chart or duplicate alias keys when compacting for LLM token budget
        if k in ("ascii_map_chart", "allocation_bitmap", "evaluated", "raw_hex") and orig_tokens > max_tokens:
            continue
        compacted[k] = v

    omitted_zero_or_free_count = 0
    pagination_meta: Optional[Dict[str, Any]] = None

    # Case 1: Memory Pool Scanner output (`slots`)
    if isinstance(data.get("slots"), list):
        all_slots = data["slots"]
        if drop_zero_or_free:
            active_slots = [s for s in all_slots if s.get("is_allocated") or s.get("status") == "IN_USE"]
            free_slots = [s for s in all_slots if not (s.get("is_allocated") or s.get("status") == "IN_USE")]
            omitted_zero_or_free_count += len(free_slots)
            target_list = active_slots
        else:
            target_list = all_slots

        total_filtered = len(target_list)
        sliced = target_list[clamped_offset:clamped_offset + clamped_page]
        # Strip zero fields inside each slot if drop_zero_or_free is True
        cleaned_slots = []
        for s in sliced:
            s_copy = dict(s)
            if drop_zero_or_free and isinstance(s_copy.get("fields"), dict):
                s_copy["fields"] = {
                    fk: fv for fk, fv in s_copy["fields"].items()
                    if fv not in (0, "0x0", "", None) or fk in ("in_use", "owner_tid", "seq")
                }
            cleaned_slots.append(s_copy)

        compacted["slots"] = cleaned_slots
        compacted["collapsed_free_slots_count"] = omitted_zero_or_free_count
        has_more = (clamped_offset + clamped_page) < total_filtered
        pagination_meta = {
            "collection": "slots",
            "total_raw_items": len(all_slots),
            "total_active_items": total_filtered,
            "omitted_free_or_zero_items": omitted_zero_or_free_count,
            "cursor_offset": clamped_offset,
            "page_size": clamped_page,
            "returned_items": len(cleaned_slots),
            "has_more": has_more,
            "next_cursor_offset": (clamped_offset + clamped_page) if has_more else None,
        }

    # Case 2: Symbol Evaluation output (`results`)
    elif isinstance(data.get("results"), list):
        cleaned_results = []
        for r in data["results"]:
            r_copy = {rk: rv for rk, rv in r.items() if rk != "raw_hex"}
            val = r_copy.get("value")
            if drop_zero_or_free and isinstance(val, dict):
                non_zero_dict = {}
                zero_keys = []
                for fk, fv in val.items():
                    if fv in (0, 0.0, "0x0", "", None, False) or (isinstance(fv, list) and all(x == 0 for x in fv)):
                        zero_keys.append(fk)
                    else:
                        non_zero_dict[fk] = fv
                if zero_keys:
                    omitted_zero_or_free_count += len(zero_keys)
                    non_zero_dict["_omitted_zero_fields_count"] = len(zero_keys)
                    r_copy["value"] = non_zero_dict
            elif drop_zero_or_free and isinstance(val, list) and len(val) > clamped_page:
                non_zero_items = [
                    {"index": idx_i, "value": item_v}
                    for idx_i, item_v in enumerate(val)
                    if item_v not in (0, 0.0, "0x0", "", None)
                ]
                omitted_zero_or_free_count += (len(val) - len(non_zero_items))
                r_copy["value"] = non_zero_items[clamped_offset:clamped_offset + clamped_page]
                r_copy["array_compaction"] = {
                    "total_elements": len(val),
                    "non_zero_elements": len(non_zero_items),
                    "omitted_zero_elements": len(val) - len(non_zero_items),
                }
            cleaned_results.append(r_copy)
        compacted["results"] = cleaned_results
        if "evaluated" in compacted:
            compacted["evaluated"] = cleaned_results

    compacted_json_str = json.dumps(compacted, ensure_ascii=False, default=str)
    comp_tokens = max(1, len(compacted_json_str) // 4)
    reduction_pct = round(max(0.0, (1.0 - (comp_tokens / float(orig_tokens))) * 100.0), 1)

    compacted["token_budget_meta"] = {
        "max_tokens_requested": max_tokens,
        "original_estimated_tokens": orig_tokens,
        "compacted_estimated_tokens": comp_tokens,
        "token_reduction_pct": reduction_pct,
        "drop_zero_or_free": drop_zero_or_free,
        "omitted_zero_or_free_count": omitted_zero_or_free_count,
        "anomaly_first_preserved": True,
        "pagination": pagination_meta,
    }
    return compacted


def smart_compact_query(
    mgr,
    query_or_expression: str = "*gpMem",
    mode: str = "auto",
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    max_tokens: int = 800,
    drop_zero_or_free: bool = True,
    cursor_offset: int = 0,
    page_size: int = 16,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Executes a zero-stop query or expression evaluation and automatically applies
        `summarize_for_llm_budget` (anomaly-first noise filtering + cursor pagination).
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
    eff_pid = ctx_info["pid"]
    eff_elf = ctx_info["companion_elf_path"]
    q_clean = (query_or_expression or "*gpMem").strip()

    if mode == "pool" or (mode == "auto" and (q_clean.startswith("*") or "pool" in q_clean.lower() or q_clean.endswith("buffers"))):
        raw_res = mgr.scan_memory_pool_or_array(
            pid=eff_pid,
            companion_elf_path=eff_elf,
            base_expression=q_clean,
            remote_host=ctx_info.get("remote_host"),
            ssh_user=ctx_info.get("ssh_user"),
            ssh_port=ctx_info.get("ssh_port", 22),
            ssh_key=ctx_info.get("ssh_key"),
            ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
            adapter=adapter,
        )
    elif mode == "eval":
        raw_res = mgr.evaluate_symbol_paths(
            pid=eff_pid,
            companion_elf_path=eff_elf,
            expressions=[x.strip() for x in q_clean.split(",") if x.strip()],
            remote_host=ctx_info.get("remote_host"),
            ssh_user=ctx_info.get("ssh_user"),
            ssh_port=ctx_info.get("ssh_port", 22),
            ssh_key=ctx_info.get("ssh_key"),
            ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
            adapter=adapter,
        )
    else:
        raw_res = mgr.ask_runtime_question(
            question=q_clean,
            pid=eff_pid,
            companion_elf_path=eff_elf,
            remote_host=ctx_info.get("remote_host"),
            ssh_user=ctx_info.get("ssh_user"),
            ssh_port=ctx_info.get("ssh_port", 22),
            ssh_key=ctx_info.get("ssh_key"),
            ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
            adapter=adapter,
        )

    return mgr.summarize_for_llm_budget(
        data=raw_res,
        max_tokens=max_tokens,
        drop_zero_or_free=drop_zero_or_free,
        cursor_offset=cursor_offset,
        page_size=page_size,
    )


def execute_batch_macro(
    mgr,
    steps: List[Dict[str, Any]],
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    process_name: Optional[str] = None,
    compact: bool = True,
    max_tokens_per_step: int = 800,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """1-Call Multi-Tool Composite Batch Macro Executor (`runtime_batch_execute`) in zero-stop mode.
        Executes multiple heterogeneous diagnostic steps (`eval`, `scan_pool`, `find_owners`, `tls`,
        `dpdk_lcores`, `verify_consistency`, `triage`, `ask`) in a single round-trip while sharing
        the bound target context, ASLR load-bias cache, and DWARF index.
        """
    t_start_ns = time.monotonic_ns()
    ctx_info = mgr.resolve_target_context(
        pid=pid,
        companion_elf_path=companion_elf_path,
        process_name=process_name,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    eff_pid = ctx_info["pid"]
    eff_elf = ctx_info["companion_elf_path"]

    step_results: List[Dict[str, Any]] = []
    cross_step_highlights: List[str] = []
    succeeded_count = 0
    failed_count = 0

    normalized_steps = mgr._coerce_steps_list(steps, max_steps=32)
    for idx_s, step in enumerate(normalized_steps):
        step_id = str(step.get("step_id") or f"step_{idx_s + 1}")
        action = str(step.get("action") or step.get("tool") or "ask").strip().lower()
        step_t0 = time.monotonic_ns()
        try:
            if action == "malformed_step":
                raise ValueError(step.get("error") or "Malformed step input: expected dictionary")
            elif action in ("eval", "runtime_eval_memory_path", "evaluate_symbol_paths"):
                exprs = step.get("expressions") or ([step["expression"]] if step.get("expression") else ["*gpMem"])
                if isinstance(exprs, str):
                    exprs = [x.strip() for x in exprs.split(",") if x.strip()]
                raw_out = mgr.evaluate_symbol_paths(
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    expressions=exprs,
                    adapter=adapter,
                )
            elif action in ("scan_pool", "pool", "runtime_scan_memory_pool", "scan_memory_pool_or_array"):
                base_e = str(step.get("base_expression") or step.get("expression") or "*gpMem")
                raw_out = mgr.scan_memory_pool_or_array(
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    base_expression=base_e,
                    count=step.get("count"),
                    adapter=adapter,
                )
                p_sum = raw_out.get("pool_summary") or {}
                cross_step_highlights.append(
                    f"[{step_id}:scan_pool] {raw_out.get('resolved_array_expression')}: {p_sum.get('allocated_count')}/{p_sum.get('total_slots')} IN_USE ({p_sum.get('utilization_pct')}%)"
                )
            elif action in ("find_owners", "owners", "runtime_find_symbol_owners", "find_symbol_owners_and_threads"):
                t_expr = str(step.get("target_expression") or step.get("expression") or "buffers[0]")
                raw_out = mgr.find_symbol_owners_and_threads(
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    target_expression=t_expr,
                    adapter=adapter,
                )
                m_ths = raw_out.get("matched_threads") or []
                cross_step_highlights.append(
                    f"[{step_id}:find_owners] {raw_out.get('resolved_expression')}: {len(m_ths)} owner thread(s) ({[t['thread_name'] for t in m_ths]})"
                )
            elif action in ("tls", "runtime_inspect_thread_local_storage", "inspect_thread_local_storage"):
                raw_out = mgr.inspect_thread_local_storage(
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    tid=step.get("tid"),
                    variable_names=step.get("variable_names"),
                    adapter=adapter,
                )
            elif action in ("dpdk", "dpdk_lcores", "runtime_inspect_dpdk_lcores_and_rings", "inspect_dpdk_lcores_and_rings"):
                raw_out = mgr.inspect_dpdk_lcores_and_rings(
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    sample_window_ms=int(step.get("sample_window_ms") or 30),
                    adapter=adapter,
                )
            elif action in ("triage", "auto_triage", "runtime_auto_triage_incident", "auto_triage_incident"):
                raw_out = mgr.auto_triage_incident(
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    adapter=adapter,
                )
            elif action in ("callstack", "callstacks", "locks", "runtime_inspect_thread_callstack_and_locks", "inspect_thread_callstack_and_locks", "inspect_thread_callstacks_and_locks"):
                raw_out = mgr.inspect_thread_callstacks_and_locks(
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    adapter=adapter,
                )
            elif action in ("diff", "capture_diff", "capture_and_diff", "runtime_capture_and_diff"):
                raw_out = mgr.capture_and_diff_expressions(
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    expressions=step.get("expressions"),
                    wait_ms=int(step.get("wait_ms") or 200),
                    adapter=adapter,
                )
            elif action in ("heap", "scan_heap", "runtime_scan_heap_objects", "scan_heap_objects"):
                raw_out = mgr.scan_heap_objects(
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    class_filter=step.get("class_filter"),
                    adapter=adapter,
                )
            elif action in ("verify_consistency", "runtime_verify_concurrent_read_consistency", "verify_concurrent_read_consistency"):
                raw_out = mgr.verify_concurrent_read_consistency(
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    expressions=step.get("expressions") or ["gpRegistry.magic"],
                    retries=int(step.get("retries") or 3),
                    inter_read_delay_ms=int(step.get("inter_read_delay_ms") or 5),
                    adapter=adapter,
                )
            elif action in ("ask", "question", "ask_runtime_question", "runtime_ask"):
                q_txt = str(step.get("question") or step.get("expression") or "프로세스 상태 요약")
                raw_out = mgr.ask_runtime_question(
                    question=q_txt,
                    pid=eff_pid,
                    companion_elf_path=eff_elf,
                    adapter=adapter,
                )
            else:
                raise ValueError(f"Unsupported batch action '{action}'. Supported actions: eval, scan_pool, find_owners, tls, dpdk, triage, callstack, diff, heap, verify_consistency, ask.")

            final_out = (
                mgr.summarize_for_llm_budget(
                    data=raw_out,
                    max_tokens=max_tokens_per_step,
                    drop_zero_or_free=bool(step.get("drop_zero_or_free", True)),
                    cursor_offset=int(step.get("cursor_offset") or 0),
                    page_size=int(step.get("page_size") or 16),
                )
                if compact
                else raw_out
            )
            # Check if step produced a structured failure dictionary without raising
            is_step_failed = False
            step_failure_msg = None
            if isinstance(raw_out, dict):
                if raw_out.get("success") is False:
                    is_step_failed = True
                    step_failure_msg = raw_out.get("error") or raw_out.get("error_message") or "Step execution returned failure"
                elif raw_out.get("status") in ("FAILED", "ERROR") and "results" not in raw_out:
                    is_step_failed = True
                    step_failure_msg = raw_out.get("error") or f"Step returned status {raw_out.get('status')}"

            if is_step_failed:
                failed_count += 1
                step_results.append({
                    "step_id": step_id,
                    "action": action,
                    "success": False,
                    "error": step_failure_msg,
                    "elapsed_us": round((time.monotonic_ns() - step_t0) / 1000.0, 2),
                    "output": final_out,
                })
            else:
                succeeded_count += 1
                step_results.append({
                    "step_id": step_id,
                    "action": action,
                    "success": True,
                    "elapsed_us": round((time.monotonic_ns() - step_t0) / 1000.0, 2),
                    "output": final_out,
                })
        except Exception as step_exc:
            failed_count += 1
            step_results.append({
                "step_id": step_id,
                "action": action,
                "success": False,
                "error": str(step_exc),
                "elapsed_us": round((time.monotonic_ns() - step_t0) / 1000.0, 2),
            })

    total_latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    total_steps = len(normalized_steps)
    overall_success = (failed_count == 0)
    is_partial = (succeeded_count > 0 and failed_count > 0)

    res: Dict[str, Any] = {
        "success": overall_success,
        "partial_success": is_partial,
        "pid": eff_pid,
        "companion_elf": eff_elf,
        "auto_healed_pid": ctx_info.get("auto_healed_pid", False),
        "elf_auto_discovered": ctx_info.get("elf_auto_discovered", False),
        "stop_duration_ms": 0.0,
        "batch_latency_us": total_latency_us,
        "compact_mode": compact,
        "steps_requested": total_steps,
        "steps_succeeded": succeeded_count,
        "steps_failed": failed_count,
        "cross_step_highlights": cross_step_highlights,
        "step_results": step_results,
        "llm_next_step_hint": (
            f"Executed {succeeded_count}/{total_steps} batch diagnostic step(s) in {total_latency_us}us without stopping the target."
        ),
    }
    if failed_count > 0:
        if is_partial:
            res["error_code"] = "PARTIAL_BATCH_FAILURE"
            res["error"] = f"{failed_count} of {total_steps} batch step(s) failed"
            res["recovery_hint"] = "Review failed steps in 'step_results' to diagnose individual action failures."
        else:
            res["error_code"] = "ALL_STEPS_FAILED"
            res["error"] = f"All {failed_count} batch step(s) failed"
            res["recovery_hint"] = "Check target process liveness and parameters for all batch steps."
    return res
