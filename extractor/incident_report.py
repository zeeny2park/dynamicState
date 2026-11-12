"""Incident report export built on the one diagnosis entry point (IMP-017).

``export_incident_report`` (CLI ``export-report``, MCP ``runtime_export_incident_report`` without an
investigation id, web ``/api/watch/export-report`` and the workspace chat) used to run its own triage and decide
its own verdict and health score.  It now runs :func:`extractor.expert_diagnostic_engine.diagnose` once and
renders that result: the verdict is the aggregator's (``diagnostic_verdict_aggregator.ALL_OVERALL_VERDICTS``),
the findings and the "what could not be examined" list are diagnose's, the body is the human summary
(:mod:`extractor.human_report`) and the HTML/JSON are the expert engine's report.  An optional hypothesis is
verified separately and shown in its own section; it never replaces the verdict.

IMP-001 guarantees are inherited from ``diagnose``: a collection failure is INCONCLUSIVE (never HEALTHY), a
fault needs a finding, and an unattributed finding is not confirmed.
"""

from __future__ import annotations

import html
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .collection_impact import impact_summary_lines
from .diagnostic_verdict_aggregator import (
    FAULT_VERDICTS,
    VERDICT_INCONCLUSIVE,
    health_score_for,
)
from .verdict_engine import sanitize_report_output_path

DEFAULT_TITLE = "dynamicState Zero-Stop Runtime Incident Report"
DEFAULT_TITLE_KO = "dynamicState 무정지 런타임 인시던트 보고서"

_LABELS = {
    "en": {"summary": "Plain-language summary", "detail": "Detailed report (sections A-I)",
           "verdict": "Verdict", "diag_summary": "Diagnosis summary", "no_summary": "No summary was produced."},
    "ko": {"summary": "쉬운 말 요약", "detail": "상세 보고서 (A-I 항목)",
           "verdict": "판정", "diag_summary": "진단 요약", "no_summary": "요약이 만들어지지 않았습니다."},
}

_HTML_CSS = """
.ds-summary { max-width: 860px; margin: 24px auto; padding: 16px 24px; border: 1px solid #cbd5e1; border-radius: 8px;
  background: #ffffff; color: #0f172a; font: 15px/1.6 -apple-system, "Segoe UI", "Noto Sans KR", sans-serif; }
.ds-summary h1, .ds-summary h2, .ds-summary h3 { line-height: 1.3; }
.ds-summary code, .ds-summary pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
.ds-summary code { background: #f1f5f9; padding: 1px 4px; border-radius: 3px; }
.ds-summary pre { background: #f1f5f9; padding: 12px; border-radius: 6px; overflow-x: auto; }
.ds-summary pre code { background: none; padding: 0; }
.ds-verdict { font-weight: 600; }
.ds-detail-title { max-width: 860px; margin: 16px auto; }
@media (prefers-color-scheme: dark) {
  .ds-summary { background: #0f172a; color: #e2e8f0; border-color: #334155; }
  .ds-summary code, .ds-summary pre { background: #1e293b; }
}
"""


def _summary_section(lang: str, verdict: str, summary_md: str) -> str:
    from .human_report import markdown_to_html
    lb = _LABELS[lang]
    body = markdown_to_html(summary_md, heading_offset=1) if summary_md else f"<p>{html.escape(lb['no_summary'])}</p>"
    return (f'<style>{_HTML_CSS}</style>\n<section class="ds-summary" lang="{lang}" id="human-summary">\n'
            f'<h2>{html.escape(lb["summary"])}</h2>\n'
            f'<p class="ds-verdict">{html.escape(lb["verdict"])}: <code>{html.escape(verdict)}</code></p>\n'
            f'{body}\n</section>\n<h2 class="ds-detail-title">{html.escape(lb["detail"])}</h2>\n')


def _limitation_text(nc: Dict[str, Any]) -> str:
    return f"{nc.get('kind')}: {nc.get('item')}: {nc.get('reason')}"


def _inconclusive_result(pid: Any, debug_image: Optional[str], kind: str, item: str, reason: str) -> Dict[str, Any]:
    return {
        "verdict": VERDICT_INCONCLUSIVE, "confidence": 0.0, "summary": f"No conclusion was reached: {reason}",
        "findings": [], "checks_run": [], "collection_impact": {},
        "not_covered": [{"kind": kind, "item": item, "reason": reason}],
        "target": {"pid": pid, "debug_image": debug_image}, "report": None, "report_path": None,
        "investigation_id": None, "state": "NOT_RUN",
    }


def _finding_row(f: Dict[str, Any], remediation: List[str]) -> Dict[str, Any]:
    details = f.get("subject_details") or []
    loc = next((d.get("name") for d in details if d.get("kind") == "source_location"), None)
    subjects = [str(s) for s in (f.get("subjects") or [])]
    return {
        **f,
        "title": f"{f.get('category')}" + (f" ({', '.join(subjects[:3])})" if subjects else ""),
        "summary": f.get("description"),
        "source_location": loc,
        "recommended_action": remediation[0] if remediation else None,
    }


def _demote_headings(md: str) -> List[str]:
    out = []
    for line in md.splitlines():
        if line.startswith("#"):
            line = "##" + line  # human summary "# x" -> "### x" under the report's own sections
        out.append(line)
    return out


def _html_fallback(title: str, verdict: str, summary_md: str, lang: str = "en", human_md: str = "") -> str:
    return (
        f"<!DOCTYPE html>\n<html lang=\"{lang}\"><head><meta charset=\"utf-8\"><title>" + html.escape(title)
        + "</title></head><body>"
        f"<h1>{html.escape(title)}</h1>\n{_summary_section(lang, verdict, human_md)}"
        f"<pre>{html.escape(summary_md)}</pre></body></html>\n"
    )


def _write(path_in: Optional[str], content: str, file_type: str, forbid_same_as: Optional[str] = None):
    if not path_in or not str(path_in).strip():
        return None, None
    if forbid_same_as and os.path.abspath(str(path_in).strip()) == forbid_same_as:
        err = f"Refusing to overwrite primary output path '{forbid_same_as}' with HTML report."
        print(f"WARNING: {err}", file=sys.stderr)
        return None, err
    san, err = sanitize_report_output_path(path_in, file_type=file_type)
    if err or not san:
        err = err or f"Refusing to write {file_type} to protected system path: {path_in}"
        print(f"WARNING: {err}", file=sys.stderr)
        return None, err
    try:
        os.makedirs(os.path.dirname(san), exist_ok=True)
        with open(san, "w", encoding="utf-8") as fh:
            fh.write(content)
        return san, None
    except OSError as exc:
        return None, f"Failed to write {file_type} to {san}: {exc}"


def export_incident_report(
    title: str = DEFAULT_TITLE,
    hypothesis: Optional[str] = None,
    assertions: Optional[List[str]] = None,
    output_path: Optional[str] = None,
    report_html_path: Optional[str] = None,
    template_path: Optional[str] = None,
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    process_name: Optional[str] = None,
    build_id: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Any = None,
    corpus_dir: Optional[str] = None,
    engine: Any = None,
    symptom: Optional[str] = None,
    time_limit_s: Optional[float] = None,
    hypothesis_verifier: Optional[Callable[..., Dict[str, Any]]] = None,
    pre_limitations: Optional[List[str]] = None,
    language: str = "en",
) -> Dict[str, Any]:
    """Diagnose ``pid`` once with ``diagnose()`` and render the incident report (Markdown, HTML, JSON)."""
    t0 = time.monotonic_ns()
    if language not in ("en", "ko"):
        raise ValueError(f"language must be 'en' or 'ko', got {language!r}")
    if title == DEFAULT_TITLE and language == "ko":
        title = DEFAULT_TITLE_KO
    if pid is not None and (isinstance(pid, bool) or int(pid) <= 0):
        return {
            "success": False, "pid": pid, "overall_status": VERDICT_INCONCLUSIVE, "verdict": VERDICT_INCONCLUSIVE,
            "health_score": None, "limitations": [f"Invalid target PID {pid}."],
            "error": f"Target process PID {pid} is invalid.",
        }
    limitations: List[str] = list(pre_limitations or [])

    # 1. the diagnosis (the only verdict)
    if not pid:
        res = _inconclusive_result(pid, companion_elf_path, "no_target", "pid",
                                   "no target process was given or bound, so nothing was examined")
        summary_md = ""
    else:
        try:
            from .expert_diagnostic_engine import diagnose
            from .human_report import render_human_report
            kw: Dict[str, Any] = {"engine": engine} if engine is not None else {"corpus_dir": corpus_dir}
            if adapter is not None:
                kw["adapter"] = adapter
            elif remote_host:
                kw["target"] = {"remote_host": remote_host, "ssh_user": ssh_user, "ssh_port": ssh_port,
                                "ssh_key": ssh_key, "ssh_proxy_jump": ssh_proxy_jump}
            r = diagnose(int(pid), debug_image=companion_elf_path or None, symptom=symptom,
                         time_limit_s=time_limit_s, include_report=True, **kw)
            res = r.to_dict()
            summary_md = render_human_report(res, res.get("report"), lang=language)
        except Exception as exc:  # noqa: BLE001 - a crash in the diagnosis is a collection failure, not a report
            res = _inconclusive_result(pid, companion_elf_path, "unexpected_error", "diagnose",
                                       f"{type(exc).__name__}: {exc}")
            summary_md = ""
    for nc in res.get("not_covered") or []:
        txt = _limitation_text(nc)
        if txt not in limitations:
            limitations.append(txt)

    verdict = str(res.get("verdict") or VERDICT_INCONCLUSIVE)
    report = res.get("report") if isinstance(res.get("report"), dict) else None
    sec_a = (report or {}).get("section_a_executive_summary") or {}
    sec_i = (report or {}).get("section_i_final_conclusions") or {}
    remediation_checklist: List[str] = []
    for item in list(sec_i.get("safe_remediation_suggestions") or []) + list(sec_a.get("recommended_next_actions") or []):
        if item and item not in remediation_checklist:
            remediation_checklist.append(str(item))
    if pre_limitations and verdict not in FAULT_VERDICTS:
        verdict = VERDICT_INCONCLUSIVE  # the target itself could not be resolved
    findings = [_finding_row(f, remediation_checklist) for f in (res.get("findings") or []) if isinstance(f, dict)]
    if verdict == VERDICT_INCONCLUSIVE:
        remediation_checklist = [
            "Investigation inconclusive: the collection failed or parts of the target could not be examined "
            f"({'; '.join(limitations[:3])}). Verify target process accessibility and read permissions, then re-run."
        ] + [x for x in remediation_checklist if "within expected parameters" not in x]
    elif not remediation_checklist:
        remediation_checklist.append("No fault was found by the checks that ran; see 'What could not be examined'.")
    health_score = health_score_for(verdict, findings)

    # 2. optional hypothesis verification (its own section; never the verdict)
    hyp_res: Optional[Dict[str, Any]] = None
    if (hypothesis or assertions) and hypothesis_verifier is not None and pid:
        try:
            hyp_res = hypothesis_verifier(hypothesis=hypothesis or "Runtime State Verification",
                                          assertions=assertions or [], pid=pid,
                                          companion_elf_path=companion_elf_path, adapter=adapter)
        except Exception as exc:  # noqa: BLE001
            limitations.append(f"verify_runtime_hypothesis failed: {type(exc).__name__}: {exc}")

    impact = res.get("collection_impact") or {}
    stop_ms = float(impact.get("measured_stop_ms") or 0.0)
    collection_mode = str(impact.get("capture_mode") or ("STOPPED" if stop_ms > 0.0 else "ZERO_STOP"))
    target = res.get("target") or {}
    eff_pid = target.get("pid") or pid
    eff_elf = target.get("debug_image") or companion_elf_path
    now_iso = datetime.now(timezone.utc).isoformat()
    status_line = (f"- **Overall Status**: `{verdict}` (Health Score: `{health_score}/100`)" if health_score is not None
                   else f"- **Overall Status**: `{verdict}` (Health Score: `N/A — {'Inconclusive' if verdict == VERDICT_INCONCLUSIVE else 'not scored'}`)")
    md = [
        f"# {title}", "",
        "## 1. Target Identity & Zero-Stop Telemetry",
        f"- **PID**: `{eff_pid}` (`{target.get('process_name') or process_name or 'target'}`)",
        f"- **Companion ELF**: `{eff_elf}`",
        f"- **Build ID**: `{build_id or 'N/A'}`",
        f"- **Investigation**: `{res.get('investigation_id') or 'N/A'}`",
        f"- **Collection Mode**: `{collection_mode}`",
        f"- **Process Stop Duration**: `{stop_ms:.2f}ms` (Measured)",
        *impact_summary_lines(impact),
        status_line,
        f"- **Generated At**: `{now_iso}`", "",
        "## 2. Root-Cause Findings",
    ]
    if findings:
        md.append("| Severity | Category | Status | Subjects | Description |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in findings:
            md.append(f"| **{f.get('severity')}** | `{f.get('category')}` | {f.get('status')} | "
                      f"{', '.join('`%s`' % s for s in (f.get('subjects') or [])[:6]) or '-'} | {f.get('description') or '-'} |")
    elif verdict == VERDICT_INCONCLUSIVE:
        md.append("- Diagnostic inspection inconclusive: collection failed or target memory was unreadable.")
        for lim in limitations[:12]:
            md.append(f"  - Limitation: `{lim}`")
    else:
        md.append("- No fault was found by the checks that ran.")
    if summary_md:
        md += ["", f"### {_LABELS[language]['diag_summary']}", ""] + _demote_headings(summary_md)
    if hyp_res is not None:
        md += ["", f"## 3. Hypothesis Verification (`{hyp_res.get('verdict')}` · Confidence "
                   f"`{round(float(hyp_res.get('confidence_score') or 0.0) * 100, 1)}%`)",
               f"- **Hypothesis**: {hyp_res.get('hypothesis')}",
               "- This verifies the stated assertions only; it does not change the diagnosis verdict above.", "",
               "| Assertion | Resolved Expression | Observed Value | Expected | Passed |",
               "| :--- | :--- | :--- | :--- | :--- |"]
        for ar in hyp_res.get("assertion_results", []):
            md.append(f"| `{ar.get('assertion')}` | `{ar.get('resolved_expression')}` | `{ar.get('observed_value')}` | "
                      f"`{ar.get('expected')}` | **{'PASS' if ar.get('passed') else 'FAIL'}** |")
    md += ["", "## 4. Checks Run"]
    for c in (res.get("checks_run") or [])[:30]:
        md.append(f"- `{c.get('recipe_id')}`: {c.get('status')}")
    md += ["", "## 5. Remediation Checklist"]
    md += [f"{i}. [ ] {step}" for i, step in enumerate(remediation_checklist, start=1)]
    report_markdown = "\n".join(md) + "\n"

    report_html: Optional[str] = None
    if template_path and os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as tf:
            report_html = tf.read().replace("{{VERDICT}}", verdict)
    elif report is not None:
        try:
            from .diagnostic_report import DiagnosticReport
            report_html = DiagnosticReport.from_dict(report).to_html().replace(
                "<body>", f"<body>\n<h1>{html.escape(title)}</h1>\n"
                          f"{_summary_section(language, verdict, summary_md)}", 1)
            report_html = report_html.replace("<html>", f'<html lang="{language}">', 1)
        except Exception:  # noqa: BLE001 - fall back to the plain rendering below
            report_html = None
    if report_html is None:
        report_html = _html_fallback(title, verdict, report_markdown, language, summary_md)
    report_json = json.dumps(res, default=str)

    saved_path, save_error = _write(output_path, report_markdown, "incident report")
    saved_html_path, save_html_error = _write(report_html_path, report_html, "HTML report", forbid_same_as=saved_path)
    latency_us = round((time.monotonic_ns() - t0) / 1000.0, 2)
    if verdict == VERDICT_INCONCLUSIVE:
        hint = (f"Incident report for PID {eff_pid} is INCONCLUSIVE ({len(limitations)} limitation(s): "
                f"{'; '.join(limitations[:2])})")
    else:
        from .human_report import conclusion_sentence
        hint = f"Incident report for PID {eff_pid}: verdict {verdict}. {conclusion_sentence(summary_md)}".rstrip()
        hint = hint.rstrip(".")
    hint += f" and saved to {saved_path}." if saved_path else "."
    out_res = {k: v for k, v in res.items() if k != "report"}
    return {
        "success": True,
        "pid": eff_pid,
        "companion_elf": eff_elf,
        "build_id": build_id,
        "investigation_id": res.get("investigation_id"),
        "collection_mode": collection_mode,
        "stop_duration_ms": stop_ms,
        "target_stop_duration_ms": stop_ms,
        "collection_impact": impact,
        "report_latency_us": latency_us,
        "observation_latency_us": latency_us,
        "title": title,
        "language": language,
        "verdict": verdict,
        "overall_status": verdict,
        "health_score": health_score,
        "limitations": limitations,
        "not_covered": list(res.get("not_covered") or []),
        "findings_count": len(findings),
        "findings": findings,
        "diagnosis": out_res,
        "human_summary": summary_md,
        "hypothesis_verification": hyp_res,
        "remediation_checklist": remediation_checklist,
        "report_markdown": report_markdown,
        "report_html": report_html,
        "report_json": report_json,
        "report_path": res.get("report_path"),
        "saved_path": saved_path,
        "save_error": save_error,
        "saved_html_path": saved_html_path,
        "save_html_error": save_html_error,
        "llm_next_step_hint": hint,
    }


__all__ = ["export_incident_report", "DEFAULT_TITLE"]
