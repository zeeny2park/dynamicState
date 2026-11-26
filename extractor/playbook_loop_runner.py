"""Autonomous Playbook Loop Runner, Coding-Agent Handoff Brief Generator,
CI Standard Exit Codes, and Multi-Run Snapshot Diff Engine.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

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


def verdict_to_exit_code(
    verdict: Optional[str],
    *,
    predicate_status: Optional[str] = None,
    fail_on: Optional[List[str]] = None,
) -> int:
    """Map diagnostic verdict / loop status to a deterministic CI exit code.

    Standard mapping:
      - HEALTHY / CONTRADICTED -> 0
      - FAULT / DEFECT_CONFIRMED / SUPPORTED -> 2
      - DEGRADED / WARNING -> 3
      - INCONCLUSIVE / EXHAUSTED -> 4
      - BLOCKED / ERROR -> 5

    If `fail_on` is provided (e.g. ['fault', 'degraded']), returns 0 unless the
    classified severity bucket is in `fail_on`.
    """
    v = str(verdict or "").strip().upper()
    ps = str(predicate_status or "").strip().upper()

    if ps == "BLOCKED" or v in ("BLOCKED", "ERROR", "FAILED"):
        bucket, code = "blocked", EXIT_BLOCKED
    elif v in ("FAULT", "DEFECT_CONFIRMED", "CONFIRMED", "CRITICAL"):
        bucket, code = "fault", EXIT_FAULT
    elif v in ("DEGRADED", "WARNING"):
        bucket, code = "degraded", EXIT_DEGRADED
    elif v == "HEALTHY":
        bucket, code = "healthy", EXIT_HEALTHY
    elif ps == "EXHAUSTED" or v in ("INCONCLUSIVE", "UNKNOWN", ""):
        bucket, code = "inconclusive", EXIT_INCONCLUSIVE
    else:
        bucket, code = "inconclusive", EXIT_INCONCLUSIVE

    if fail_on:
        allowed = {str(x).strip().lower() for x in fail_on if str(x).strip()}
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
        "agent_summary", "selected_playbook", "loop_state",
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

    lines: List[str] = [
        f"# DynamicState Investigation Handoff (`pid={pid}`)" if not ko else f"# DynamicState 진단 핸드오프 (`pid={pid}`)",
        "",
        f"- **Playbook**: `{pb_id}`",
        f"- **Verdict / Loop Status**: `{verdict}` / `{status}` ({loop_result.get('iterations_run', 0)}/{loop_result.get('max_iterations', 0)} iterations, {loop_result.get('elapsed_s', 0.0)}s)",
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
        lines.append("| Iter | Tool | Moved | Status | Note |")
        lines.append("| :---: | :--- | :---: | :--- | :--- |")
        for row in dlog:
            lines.append(
                f"| {row.get('iter')} | `{row.get('tool')}` | {'YES' if row.get('evidence_moved') else 'no'} | `{row.get('predicate_status')}` | {row.get('note', '')} |"
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
    max_iterations: int = 4,
    time_budget_s: float = 20.0,
    lang: str = "en",
    remote_target: Optional[Dict[str, Any]] = None,
    ledger_store: Optional[TrackingLedgerStore] = None,
    on_iteration: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Execute a problem-specific playbook autonomously on the server/CLI side.

    Runs read-only playbook steps sequentially, tracks progress in `TargetTrackingLedger`,
    automatically pivots on `PIVOT_REQUIRED` (2 consecutive plateaus), and stops cleanly
    on `MET`, `BLOCKED`, `EXHAUSTED`, or `time_budget_s`.
    """
    t0 = time.monotonic()
    store = ledger_store or GLOBAL_TRACKING_LEDGER
    tkey = make_target_key(int(pid), remote_target)
    ledger = store.get_or_create(tkey)

    pb = select_playbook(symptom=symptom, lang=lang)
    max_it = max(1, min(int(max_iterations), 10))
    ledger.activate_playbook(pb, max_iterations=max_it)

    rm_args = (
        {k: v for k, v in remote_target.items() if v is not None}
        if isinstance(remote_target, dict) else {}
    )
    base_args: Dict[str, Any] = {"pid": int(pid), **rm_args}
    if companion_elf:
        base_args["companion_elf"] = str(companion_elf)

    steps = list(pb.get("steps") or [])
    step_idx = 0
    step_summaries: List[Dict[str, Any]] = []
    key_deltas: List[str] = []
    last_verdict = "INCONCLUSIVE"
    pivots_taken = 0

    for _ in range(max_it):
        if time.monotonic() - t0 >= float(time_budget_s):
            ledger.predicate_status = "EXHAUSTED"
            break

        ls = ledger.loop_state()
        if ls["predicate_status"] in ("MET", "BLOCKED", "EXHAUSTED"):
            break

        # Choose next tool: pivot if PIVOT_REQUIRED, else next planned playbook step
        tool_name: Optional[str] = None
        call_args: Dict[str, Any] = dict(base_args)
        if ls["predicate_status"] == "PIVOT_REQUIRED" and ls.get("pivot_recommendation"):
            tool_name = str(ls["pivot_recommendation"].get("pivot_to_tool") or "")
            pivots_taken += 1
            if tool_name == "runtime_capture_and_diff":
                call_args["wait_ms"] = 2000
            elif tool_name == "runtime_watch_until_condition":
                call_args["timeout_ms"] = 5000
        elif step_idx < len(steps):
            tool_name = str(steps[step_idx].get("tool") or "")
            step_idx += 1
        else:
            # All planned steps ran; if still OPEN, try source correlation or break
            if companion_elf and "runtime_correlate_source_and_state" not in {c["tool"] for c in ledger.calls}:
                tool_name = "runtime_correlate_source_and_state"
            else:
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

        try:
            raw_res = executor(tool_name, call_args)
            if not isinstance(raw_res, dict):
                raw_res = {"success": False, "error": f"non-dict response from {tool_name}"}
        except Exception as exc:  # noqa: BLE001
            raw_res = {"success": False, "error": str(exc), "error_code": type(exc).__name__}

        enriched = enrich_tool_response(
            tool_name,
            dict(raw_res),
            pid=int(pid),
            companion_elf=companion_elf,
            args=call_args,
            remote_target=remote_target,
            ledger_store=store,
        )

        if enriched.get("verdict"):
            last_verdict = str(enriched["verdict"]).upper()
        if isinstance(enriched.get("delta_from_last_call"), dict) and enriched["delta_from_last_call"].get("summary"):
            key_deltas.append(f"{tool_name}: {enriched['delta_from_last_call']['summary']}")

        cur_ls = ledger.loop_state()
        row = {
            "iteration": cur_ls["iteration"],
            "tool": tool_name,
            "success": bool(enriched.get("success", True)),
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

    final_ls = ledger.loop_state()
    elapsed_s = round(time.monotonic() - t0, 2)
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
        "verdict": last_verdict,
        "exit_code": verdict_to_exit_code(last_verdict, predicate_status=final_ls["predicate_status"]),
        "iterations_run": final_ls["iteration"],
        "max_iterations": max_it,
        "pivots_taken": pivots_taken,
        "elapsed_s": elapsed_s,
        "code_anchors": list(ledger.code_anchors[:12]),
        "key_deltas": key_deltas,
        "decision_log": list(final_ls.get("decision_log") or []),
        "step_summaries": step_summaries,
        "next_recommended_action": next_act,
    }
    result["handoff_markdown"] = render_handoff_markdown(result, lang=lang)
    return result


def diff_diagnostic_runs(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two saved diagnostic JSON snapshots (e.g. yesterday's build vs today's build)."""
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
            metric_deltas[k] = {"before": vb, "after": va, "delta": round(va - vb, 2)}

    def _finding_keys(doc: Dict[str, Any]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for f in (doc.get("findings") or []):
            if isinstance(f, dict):
                key = str(f.get("recipe_id") or f.get("category") or f.get("title") or "")
                if key:
                    out[key] = str(f.get("summary") or f.get("title") or key)
        return out

    f_before = _finding_keys(b)
    f_after = _finding_keys(a)
    new_findings = [{"key": k, "summary": f_after[k]} for k in sorted(set(f_after) - set(f_before))]
    resolved_findings = [{"key": k, "summary": f_before[k]} for k in sorted(set(f_before) - set(f_after))]
    persistent_findings = sorted(set(f_before) & set(f_after))

    regressed = bool(
        new_findings
        or (v_before == "HEALTHY" and v_after in ("FAULT", "DEFECT_CONFIRMED", "DEGRADED"))
        or (metric_deltas.get("rss_kb", {}).get("delta", 0) > 10240)
    )
    return {
        "success": True,
        "verdict_before": v_before,
        "verdict_after": v_after,
        "verdict_changed": v_before != v_after,
        "regressed": regressed,
        "metric_deltas": metric_deltas,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "persistent_findings": persistent_findings,
        "summary": (
            f"Verdict {v_before} -> {v_after}; "
            f"+{len(new_findings)} new / -{len(resolved_findings)} resolved finding(s)"
            + (" [REGRESSION]" if regressed else "")
        ),
    }
