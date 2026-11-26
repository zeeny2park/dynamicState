"""Autonomous Playbook Loop Runner, Coding-Agent Handoff Brief Generator,
CI Standard Exit Codes, and Multi-Run Snapshot Diff Engine.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from .diagnostic_playbooks import select_playbook
from .tracking_ledger import (
    GLOBAL_TRACKING_LEDGER,
    TrackingLedgerStore,
    enrich_tool_response,
    make_target_key,
)


# Standard CI Exit Codes
EXIT_HEALTHY = 0
EXIT_FAULT = 2
EXIT_DEGRADED = 3
EXIT_INCONCLUSIVE = 4
EXIT_BLOCKED = 5

_SEVERITY_RANK: Dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "WARNING": 2,
    "MEDIUM": 2,
    "HIGH": 3,
    "ERROR": 3,
    "CRITICAL": 4,
}


def verdict_to_exit_code(
    verdict: Optional[str],
    *,
    predicate_status: Optional[str] = None,
    fail_on: Optional[List[str]] = None,
) -> int:
    """Map diagnostic verdict / loop status to a deterministic CI exit code.

    Precedence & invariants:
      1. BLOCKED / ERROR / FAILED -> 5 (always distinguishable from INCONCLUSIVE)
      2. FAULT / DEFECT_CONFIRMED / CONFIRMED / CRITICAL -> 2
      3. DEGRADED / WARNING -> 3
      4. EXHAUSTED / PIVOT_REQUIRED -> 4 (never returns 0 even if last tool said HEALTHY)
      5. HEALTHY -> 0 ONLY when predicate_status is MET or omitted (standalone diagnose);
         if predicate_status is OPEN (incomplete loop), returns 4 (INCONCLUSIVE).
      6. INCONCLUSIVE / UNKNOWN / empty -> 4

    If `fail_on` is provided (e.g. ['fault', 'degraded']), returns 0 unless the
    classified bucket is in `fail_on` ('exhausted' is accepted as an alias for 'inconclusive').
    """
    v = str(verdict or "").strip().upper()
    ps = str(predicate_status or "").strip().upper()

    if ps == "BLOCKED" or v in ("BLOCKED", "ERROR", "FAILED"):
        bucket, code = "blocked", EXIT_BLOCKED
    elif v in ("FAULT", "DEFECT_CONFIRMED", "CONFIRMED", "CRITICAL"):
        bucket, code = "fault", EXIT_FAULT
    elif v in ("DEGRADED", "WARNING"):
        bucket, code = "degraded", EXIT_DEGRADED
    elif ps in ("EXHAUSTED", "PIVOT_REQUIRED"):
        bucket, code = "inconclusive", EXIT_INCONCLUSIVE
    elif v == "HEALTHY" and ps in ("", "MET"):
        bucket, code = "healthy", EXIT_HEALTHY
    else:
        bucket, code = "inconclusive", EXIT_INCONCLUSIVE

    if fail_on:
        allowed = {str(x).strip().lower() for x in fail_on if str(x).strip()}
        if "exhausted" in allowed:
            allowed.add("inconclusive")
        if bucket not in allowed:
            return EXIT_HEALTHY
    return code


def compact_payload(payload: Dict[str, Any], *, max_items: int = 8) -> Dict[str, Any]:
    """Return a token-bounded compact view of a tool payload without dropping tracking metadata."""
    if not isinstance(payload, dict):
        return {}
    out: Dict[str, Any] = {}
    keep_full = {
        "success", "verdict", "status", "error", "error_code", "message",
        "tracking_context", "delta_from_last_call", "code_anchors",
        "next_drilldown", "recovery_actions", "suppressed_repeat_actions",
        "agent_summary", "selected_playbook", "loop_state", "timing",
        "exit_predicate_evaluation", "hypothesis_status", "partial_evidence_preserved",
    }
    for k, v in payload.items():
        if k in keep_full:
            out[k] = v
        elif isinstance(v, list):
            if len(v) > max_items:
                out[k] = v[:max_items]
                out[f"{k}_truncated_from"] = len(v)
            else:
                out[k] = v
        elif isinstance(v, dict) and len(v) > max_items * 2:
            keys = list(v.keys())[: max_items * 2]
            out[k] = {kk: v[kk] for kk in keys}
            out[f"{k}_truncated_from"] = len(v)
        else:
            out[k] = v
    return out


def render_handoff_markdown(loop_result: Dict[str, Any], lang: str = "en") -> str:
    """Render a concise, token-efficient Markdown handoff brief for coding agents."""
    ko = lang == "ko"
    pb_id = loop_result.get("playbook_id") or "unknown"
    verdict = loop_result.get("verdict") or "INCONCLUSIVE"
    status = loop_result.get("final_status") or "OPEN"
    pid = loop_result.get("pid")
    pred = loop_result.get("exit_predicate") or ""
    anchors = loop_result.get("code_anchors") or []
    dlog = loop_result.get("decision_log") or []
    deltas = loop_result.get("key_deltas") or []
    max_it_label = str(loop_result.get("max_iterations")) if loop_result.get("max_iterations") is not None else "unbounded"

    lines: List[str] = [
        f"# DynamicState Investigation Handoff (`pid={pid}`)" if not ko else f"# DynamicState 진단 핸드오프 (`pid={pid}`)",
        "",
        f"- **Playbook**: `{pb_id}`",
        f"- **Verdict / Loop Status**: `{verdict}` / `{status}` ({loop_result.get('iterations_run', 0)}/{max_it_label} iterations, {loop_result.get('elapsed_s', 0.0)}s)",
        f"- **Hypothesis Status**: `{loop_result.get('hypothesis_status', 'UNVALIDATED')}`",
        f"- **Exit Predicate**: {pred}",
        "",
    ]

    if anchors:
        lines.append("## Code Anchors (`file:line`)" if not ko else "## 소스 코드 앵커 (`file:line`)")
        for a in anchors[:10]:
            loc = f"`{a['file']}:{a['line']}`" if a.get("file") and a.get("line") else f"`{a.get('file') or a.get('function') or a.get('symbol') or a.get('variable_path')}`"
            extra = [x for x in (a.get("function"), a.get("variable_path"), a.get("symbol"), a.get("note")) if x]
            lines.append(f"- {loc}" + (f" — {' | '.join(str(x) for x in extra[:3])}" if extra else ""))
        lines.append("")

    if deltas:
        lines.append("## Observed Deltas" if not ko else "## 관측된 변화량(Delta)")
        for d in deltas[:6]:
            lines.append(f"- {d}")
        lines.append("")

    if dlog:
        lines.append("## Decision Log" if not ko else "## 결정 로그")
        lines.append("| Iter | Tool | Moved | Hypothesis | Status | Note |")
        lines.append("| :---: | :--- | :---: | :--- | :--- | :--- |")
        for row in dlog:
            lines.append(
                f"| {row.get('iter')} | `{row.get('tool')}` | {'YES' if row.get('evidence_moved') else 'no'} | "
                f"`{row.get('hypothesis_status', 'INCONCLUSIVE')}` | `{row.get('predicate_status')}` | {row.get('note', '')} |"
            )
        lines.append("")

    next_act = loop_result.get("next_recommended_action")
    if next_act:
        lines.append("## Next Recommended Action" if not ko else "## 다음 권장 조치")
        lines.append(f"- {next_act}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def run_playbook_loop(
    *,
    pid: int,
    symptom: str,
    executor: Callable[[str, Dict[str, Any]], Dict[str, Any]],
    companion_elf: Optional[str] = None,
    max_iterations: Optional[int] = None,
    time_budget_s: Optional[float] = None,
    lang: str = "en",
    remote_target: Optional[Dict[str, Any]] = None,
    ledger_store: Optional[TrackingLedgerStore] = None,
    on_iteration: Optional[Callable[[Dict[str, Any]], None]] = None,
    clock: Optional[Callable[[], float]] = None,
) -> Dict[str, Any]:
    """Execute a problem-specific playbook autonomously on the server/CLI side.

    Budget & completeness semantics:
    - `max_iterations=None` (default): no arbitrary iteration cap; runs through all playbook steps,
      applicable pivots, and source correlation until the exit predicate is MET, BLOCKED, or all
      planned/pivot actions are exhausted. Explicit user `max_iterations` is honored without clamping.
    - `time_budget_s=None` (default): no premature default time cap. When explicitly configured,
      distinguishes total investigation elapsed time from individual tool execution duration; a
      single slow tool's output is always recorded and preserved before stopping for budget exhaustion.
    - Individual tool exceptions are isolated and recorded without losing prior or subsequent evidence.
    """
    now_fn = clock or time.monotonic
    t0 = float(now_fn())
    store = ledger_store or GLOBAL_TRACKING_LEDGER
    tkey = make_target_key(int(pid), remote_target)
    ledger = store.get_or_create(tkey)

    pb = select_playbook(symptom=symptom, lang=lang)
    explicit_max_it: Optional[int] = max(1, int(max_iterations)) if max_iterations is not None else None
    explicit_time_budget: Optional[float] = float(time_budget_s) if time_budget_s is not None else None
    ledger.activate_playbook(pb, max_iterations=explicit_max_it)

    rm_args = (
        {k: v for k, v in remote_target.items() if v is not None}
        if isinstance(remote_target, dict) else {}
    )
    base_args: Dict[str, Any] = {"pid": int(pid), **rm_args}
    if companion_elf:
        base_args["companion_elf"] = str(companion_elf)

    steps = list(pb.get("steps") or [])
    pivots = list(pb.get("pivot_rules") or [])
    step_idx = 0
    pivot_idx = 0
    step_summaries: List[Dict[str, Any]] = []
    tool_errors: List[Dict[str, Any]] = []
    key_deltas: List[str] = []
    last_verdict = "INCONCLUSIVE"
    pivots_taken = 0
    limit_reason: Optional[str] = None
    budget_exceeded_during_tool = False
    longest_tool_s = 0.0
    longest_tool_name: Optional[str] = None

    while True:
        if explicit_max_it is not None and ledger.iteration >= explicit_max_it:
            if ledger.predicate_status not in ("MET", "BLOCKED"):
                ledger.predicate_status = "EXHAUSTED"
                limit_reason = "explicit_iteration_limit_reached"
            break

        elapsed_before = float(now_fn()) - t0
        if explicit_time_budget is not None and elapsed_before >= explicit_time_budget:
            if ledger.predicate_status not in ("MET", "BLOCKED"):
                ledger.predicate_status = "EXHAUSTED"
                limit_reason = "explicit_time_budget_exhausted"
            break

        ls = ledger.loop_state()
        if ls["predicate_status"] in ("MET", "BLOCKED", "EXHAUSTED"):
            break

        # Choose next tool: pivot if PIVOT_REQUIRED and unused pivot remains, else next planned step
        tool_name: Optional[str] = None
        call_args: Dict[str, Any] = dict(base_args)
        if ls["predicate_status"] == "PIVOT_REQUIRED" and pivot_idx < len(pivots):
            tool_name = str(pivots[pivot_idx].get("pivot_to_tool") or "")
            pivot_idx += 1
            pivots_taken += 1
            if tool_name == "runtime_capture_and_diff":
                call_args["wait_ms"] = 2000
            elif tool_name == "runtime_watch_until_condition":
                call_args["timeout_ms"] = 5000
        elif step_idx < len(steps):
            tool_name = str(steps[step_idx].get("tool") or "")
            step_idx += 1
        elif pivot_idx < len(pivots):
            tool_name = str(pivots[pivot_idx].get("pivot_to_tool") or "")
            pivot_idx += 1
            pivots_taken += 1
        else:
            # All planned steps and pivots completed without satisfying exit predicate
            if companion_elf and "runtime_correlate_source_and_state" not in {c["tool"] for c in ledger.calls}:
                tool_name = "runtime_correlate_source_and_state"
            else:
                if ledger.predicate_status not in ("MET", "BLOCKED"):
                    ledger.predicate_status = "EXHAUSTED"
                    limit_reason = "playbook_steps_exhausted"
                break

        if not tool_name:
            break

        if tool_name == "runtime_diagnose_process":
            call_args = {"pid": int(pid), **rm_args}
            if companion_elf:
                call_args["debug_image"] = str(companion_elf)
            if symptom:
                call_args["symptom"] = symptom
        elif tool_name == "runtime_symbol_search":
            call_args = {**base_args, "query": symptom.split()[0] if symptom.strip() else "state", "limit": 20}

        t_tool_start = float(now_fn())
        tool_exc: Optional[str] = None
        try:
            raw_res = executor(tool_name, call_args)
            if not isinstance(raw_res, dict):
                raw_res = {"success": False, "error": f"non-dict response from {tool_name}"}
        except Exception as exc:  # noqa: BLE001
            tool_exc = f"{type(exc).__name__}: {exc}"
            raw_res = {"success": False, "error": str(exc), "error_code": type(exc).__name__}
            tool_errors.append({"iteration": ledger.iteration + 1, "tool": tool_name, "error": tool_exc})

        t_tool_end = float(now_fn())
        tool_dur_s = round(max(0.0, t_tool_end - t_tool_start), 3)
        if tool_dur_s >= longest_tool_s:
            longest_tool_s = tool_dur_s
            longest_tool_name = tool_name

        # Always record and preserve the tool's evidence even if it exceeded the nominal budget
        enriched = enrich_tool_response(
            tool_name,
            dict(raw_res),
            pid=int(pid),
            companion_elf=companion_elf,
            args=call_args,
            remote_target=remote_target,
            ledger_store=store,
            now=t_tool_end,
        )

        if enriched.get("verdict"):
            last_verdict = str(enriched["verdict"]).upper()
        if isinstance(enriched.get("delta_from_last_call"), dict) and enriched["delta_from_last_call"].get("summary"):
            key_deltas.append(f"{tool_name}: {enriched['delta_from_last_call']['summary']}")

        cur_ls = ledger.loop_state()
        elapsed_after = t_tool_end - t0
        exceeded_here = bool(explicit_time_budget is not None and elapsed_after >= explicit_time_budget)
        if exceeded_here:
            budget_exceeded_during_tool = True
            if cur_ls["predicate_status"] not in ("MET", "BLOCKED"):
                ledger.predicate_status = "EXHAUSTED"
                limit_reason = "explicit_time_budget_exhausted_during_tool"
                ledger.exit_predicate_evaluation = {
                    **ledger.exit_predicate_evaluation,
                    "satisfied": False,
                    "status": "EXHAUSTED",
                    "reason": (
                        f"Explicit time budget ({explicit_time_budget}s) exceeded during {tool_name} "
                        f"({tool_dur_s}s); partial evidence preserved."
                    ),
                }
                store.save(tkey)
                cur_ls = ledger.loop_state()

        row = {
            "iteration": cur_ls["iteration"],
            "tool": tool_name,
            "duration_s": tool_dur_s,
            "success": bool(enriched.get("success", True)),
            "error": tool_exc,
            "hypothesis_status": cur_ls["hypothesis_status"],
            "predicate_status": cur_ls["predicate_status"],
            "new_anchors": len(enriched.get("code_anchors") or []),
            "verdict": enriched.get("verdict"),
        }
        step_summaries.append(row)
        if on_iteration is not None:
            try:
                on_iteration(row)
            except Exception:
                pass

        if cur_ls["predicate_status"] in ("MET", "BLOCKED", "EXHAUSTED"):
            break

    store.save(tkey)
    final_ls = ledger.loop_state()
    elapsed_s = round(max(0.0, float(now_fn()) - t0), 3)
    next_act = None
    if final_ls["predicate_status"] == "BLOCKED":
        next_act = "Resolve OS permission / ptrace_scope or verify target PID is alive before retrying."
    elif final_ls["predicate_status"] == "MET":
        next_act = "Inspect the extracted code_anchors (file:line) in your repository and implement/verify the fix."
    elif final_ls.get("next_planned_step"):
        ns = final_ls["next_planned_step"]
        next_act = f"Continue with {ns.get('tool')} ({ns.get('cli_hint')})"

    result: Dict[str, Any] = {
        "success": final_ls["predicate_status"] != "BLOCKED",
        "pid": int(pid),
        "symptom": symptom,
        "playbook_id": pb["playbook_id"],
        "playbook_title": pb["title"],
        "exit_predicate": pb["exit_predicate"],
        "final_status": final_ls["predicate_status"],
        "hypothesis_status": final_ls["hypothesis_status"],
        "exit_predicate_evaluation": final_ls["exit_predicate_evaluation"],
        "verdict": last_verdict,
        "exit_code": verdict_to_exit_code(last_verdict, predicate_status=final_ls["predicate_status"]),
        "iterations_run": final_ls["iteration"],
        "max_iterations": explicit_max_it,
        "pivots_taken": pivots_taken,
        "limit_reason": limit_reason,
        "partial_evidence_preserved": bool(ledger.calls or ledger.code_anchors or ledger.evidence_provenance),
        "elapsed_s": elapsed_s,
        "timing": {
            "total_elapsed_s": elapsed_s,
            "time_budget_s": explicit_time_budget,
            "longest_tool_s": longest_tool_s,
            "longest_tool_name": longest_tool_name,
            "budget_exceeded_during_tool": budget_exceeded_during_tool,
        },
        "tool_errors": tool_errors,
        "code_anchors": list(ledger.code_anchors[:12]),
        "key_deltas": key_deltas,
        "decision_log": list(final_ls.get("decision_log") or []),
        "step_summaries": step_summaries,
        "next_recommended_action": next_act,
    }
    result["handoff_markdown"] = render_handoff_markdown(result, lang=lang)
    return result


def diff_diagnostic_runs(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two saved diagnostic JSON snapshots objectively without invented metric thresholds.

    - Explicitly marks missing metrics as `status: "unknown"` (never silently omitted).
    - Tracks finding severity changes on persistent findings.
    - Classifies `regressed=True` only on objective verdict worsening, new non-INFO fault/warning
      findings, or finding severity escalation (never on INFO/non-fault observations alone).
    """
    b = before if isinstance(before, dict) else {}
    a = after if isinstance(after, dict) else {}

    v_before = str(b.get("verdict") or "UNKNOWN").upper()
    v_after = str(a.get("verdict") or "UNKNOWN").upper()

    def _profile_metrics(doc: Dict[str, Any]) -> Dict[str, Optional[float]]:
        ps = ((doc.get("process_profile") or {}).get("summary") or {}) if isinstance(doc.get("process_profile"), dict) else {}
        if not ps and isinstance(doc.get("agent_summary"), dict):
            ps = doc["agent_summary"].get("state_snapshot") or {}
        return {
            "rss_kb": ps.get("rss_kb"),
            "open_fds": ps.get("open_fds"),
            "thread_count": ps.get("thread_count"),
        }

    m_before = _profile_metrics(b)
    m_after = _profile_metrics(a)
    metric_deltas: Dict[str, Any] = {}
    for k in ("rss_kb", "open_fds", "thread_count"):
        vb, va = m_before.get(k), m_after.get(k)
        if isinstance(vb, (int, float)) and isinstance(va, (int, float)):
            metric_deltas[k] = {"status": "measured", "before": vb, "after": va, "delta": round(va - vb, 2)}
        else:
            metric_deltas[k] = {"status": "unknown", "before": vb, "after": va, "delta": None}

    def _findings_map(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for f in (doc.get("findings") or []):
            if not isinstance(f, dict):
                continue
            key = str(f.get("recipe_id") or f.get("category") or f.get("title") or "").strip()
            if not key:
                continue
            sev = str(f.get("severity") or f.get("finding_severity") or "UNKNOWN").strip().upper()
            non_fault = bool(f.get("non_fault")) or sev == "INFO"
            out[key] = {
                "key": key,
                "summary": str(f.get("summary") or f.get("title") or key),
                "severity": sev,
                "non_fault": non_fault,
            }
        return out

    f_before = _findings_map(b)
    f_after = _findings_map(a)
    new_findings = [f_after[k] for k in sorted(set(f_after) - set(f_before))]
    resolved_findings = [f_before[k] for k in sorted(set(f_before) - set(f_after))]
    persistent_keys = sorted(set(f_before) & set(f_after))

    severity_changes: List[Dict[str, Any]] = []
    for k in persistent_keys:
        sb = f_before[k]["severity"]
        sa = f_after[k]["severity"]
        if sb != sa:
            rb = _SEVERITY_RANK.get(sb)
            ra = _SEVERITY_RANK.get(sa)
            escalated = bool(rb is not None and ra is not None and ra > rb)
            severity_changes.append({
                "key": k,
                "before_severity": sb,
                "after_severity": sa,
                "escalated": escalated,
            })

    verdict_rank = {
        "HEALTHY": 0,
        "INCONCLUSIVE": 1,
        "UNKNOWN": 1,
        "DEGRADED": 2,
        "WARNING": 2,
        "FAULT": 3,
        "DEFECT_CONFIRMED": 3,
        "CRITICAL": 4,
    }
    verdict_worsened = (
        v_before in ("HEALTHY", "DEGRADED", "WARNING")
        and v_after in ("DEGRADED", "WARNING", "FAULT", "DEFECT_CONFIRMED", "CRITICAL")
        and verdict_rank.get(v_after, 0) > verdict_rank.get(v_before, 0)
    )
    has_severe_new_finding = any(
        (not nf["non_fault"]) and (_SEVERITY_RANK.get(nf["severity"], 2) >= 2)
        for nf in new_findings
    )
    has_severity_escalation = any(sc["escalated"] for sc in severity_changes)
    regressed = bool(verdict_worsened or has_severe_new_finding or has_severity_escalation)

    return {
        "success": True,
        "verdict_before": v_before,
        "verdict_after": v_after,
        "verdict_changed": v_before != v_after,
        "verdict_worsened": verdict_worsened,
        "regressed": regressed,
        "metric_deltas": metric_deltas,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "persistent_findings": persistent_keys,
        "severity_changes": severity_changes,
        "summary": (
            f"Verdict {v_before} -> {v_after}; "
            f"+{len(new_findings)} new / -{len(resolved_findings)} resolved finding(s), "
            f"{len(severity_changes)} severity change(s)"
            + (" [REGRESSION]" if regressed else "")
        ),
    }
