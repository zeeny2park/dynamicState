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
from dataclasses import asdict
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .human_report import ko_text
from .diagnostic_verdict_aggregator import (
    FAULT_VERDICTS,
    VERDICT_HEALTHY,
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


# Fixed wording of the incident-report-only parts, (en, ko) per key like ``human_report.T``.  The common outline
# itself (conclusion, findings, next steps, scope, method, reference) comes from ``human_report.compose``.
_MD: Dict[str, Any] = {
    "hyp": ("- **Hypothesis**: {x}", "- **가설**: {x}"),
    "hyp_result": ("- **Result**: {v}", "- **결과**: {v}"),
    "hyp_note": ("- This verifies the stated assertions only; it does not change the diagnosis verdict above.",
                 "- 이 검증은 명시한 단언만 확인하며, 위의 진단 판정을 바꾸지 않습니다."),
    "hyp_th": ("| Assertion | Resolved Expression | Observed Value | Expected | Result |",
               "| 단언 | 해석된 식 | 관측값 | 기대값 | 결과 |"),
    "pass": ("passed", "통과"), "fail": ("failed", "실패"),
    "appendix": ("Detailed records, by report part (English)", "보고서 부분별 상세 기록 (영문)"),
    "ap_verdict": ("Conclusion: how the verdict was derived", "결론: 판정 근거"),
    "ap_finding": ("Finding {i}", "발견 {i}"),
    "ap_check": ("Check {x}", "검사 {x}"),
    "ap_scope": ("Scope: check totals and limitations", "검사 범위: 검사 집계와 제한 사항"),
    "ap_method": ("Method: target, collection and plan", "진단 방법: 대상, 수집, 계획"),
    "ap_repro": ("Reproducibility", "재현 정보"),
    "ap_other": ("Other detailed records", "그 밖의 상세 기록"),
}


# The JSON ``remediation_checklist`` of a result without a finding-specific step (not shown in the report body).
_REM: Dict[str, Any] = {
    "incon": ("Investigation inconclusive: the collection failed or parts of the target could not be examined "
              "({lims}). Verify target process accessibility and read permissions, then re-run.",
              "조사가 판단 불가로 끝났습니다: 수집에 실패했거나 대상의 일부를 확인하지 못했습니다 ({lims}). "
              "대상 프로세스에 접근할 수 있는지와 읽기 권한을 확인한 뒤 다시 실행하세요."),
    "healthy": ("No remediation needed within the checked scope: every baseline check ran to completion and found nothing.",
                "점검한 범위 안에서는 조치가 필요 없습니다: 기본 검사가 모두 끝까지 실행되었고 아무것도 발견하지 못했습니다."),
    "notchecked": ("Not checked (outside the healthy scope): {x}.", "점검하지 못함 (정상 판정 범위 밖): {x}."),
    "none": ("No fault was found by the checks that ran; see 'What could not be examined'.",
             "실행된 검사에서는 결함이 발견되지 않았습니다. '확인하지 못한 것'을 참고하세요."),
}


def _generated_at() -> str:
    """Local time of the report with the timezone stated once (``2026-11-13 17:42:05 KST (UTC+09:00)``)."""
    now = datetime.now().astimezone()
    off = now.strftime("%z")
    off = f"{off[:3]}:{off[3:]}" if off else ""
    tz = now.tzname() or ""
    if off in ("+00:00", "-00:00"):
        return f"{now:%Y-%m-%d %H:%M:%S} UTC"
    return f"{now:%Y-%m-%d %H:%M:%S} {tz} (UTC{off})".replace("  ", " ")


def _hypothesis_lines(hyp_res: Optional[Dict[str, Any]], li: int) -> List[str]:
    """The optional hypothesis verification the caller asked for (its own part; never the verdict)."""
    if hyp_res is None:
        return []
    out = [_MD["hyp"][li].format(x=hyp_res.get("hypothesis")),
           _MD["hyp_result"][li].format(v=f"`{hyp_res.get('verdict')}`"),
           _MD["hyp_note"][li], "", _MD["hyp_th"][li], "| :--- | :--- | :--- | :--- | :--- |"]
    for ar in hyp_res.get("assertion_results", []):
        out.append(f"| `{ar.get('assertion')}` | `{ar.get('resolved_expression')}` | `{ar.get('observed_value')}` | "
                   f"`{ar.get('expected')}` | **{_MD['pass' if ar.get('passed') else 'fail'][li]}** |")
    return out


def _reproducibility_section(repro: Any, language: str) -> List[str]:
    """The reproducibility section (``extractor.reproducibility``) as Markdown lines without its heading;
    ``human_report.compose`` places it as "Reproducibility / 재현 정보" after "How the diagnosis was done" and before
    "Reference", in the Markdown and the HTML report alike.  Empty: the section is left out."""
    if repro is None:
        return []
    from .reproducibility import outline_markdown
    return outline_markdown(repro, language)


_SECTION_NAMES = {
    "A": "A. Executive Summary", "B": "B. Target and Investigation Context", "C": "C. Diagnostic Strategy",
    "C_excluded": "C. Diagnostic Strategy (excluded recipes)", "D": "D. Detailed Inspection Results",
    "D_totals": "D. Detailed Inspection Results (totals)", "D_links": "D. Checks behind this finding",
    "E": "E. Findings and Root Cause Analysis", "F": "F. Competing Hypotheses", "F_head": "F. Competing Hypotheses (ranking)",
    "G": "G. Evidence & Provenance Index", "G_head": "G. Evidence & Provenance Index (totals)",
    "H": "H. Limitations and Unverified Areas", "I": "I. Final Conclusions and Recommendations",
    "meta": "Report identity", "collection_impact": "Collection impact (measured)", "J": "J. Reproducibility",
}


def _detail_appendix_markdown(parts: Dict[str, Any], comp: Dict[str, Any], li: int, repro: Any = None) -> List[str]:
    """Opt-in Markdown appendix of the detailed records, organised by report part (not as one A-I sequence); each
    record is titled with the name of the A-I section it comes from."""
    from .diagnostic_report import detail_record_markdown
    from .human_report import check_label
    rec = parts.get("records") or {}
    out = [f"## {_MD['appendix'][li]}", ""]

    def block(title: str, groups: Any) -> None:
        items = [(k, v) for g in (groups or []) if isinstance(g, dict) for k, v in g.items() if v]
        if not items:
            return
        out.extend([f"### {title}", ""])
        for k, v in items:
            out.extend(detail_record_markdown(_SECTION_NAMES.get(k, k), v))
    block(_MD["ap_verdict"][li], rec.get("verdict"))
    for i, r in sorted((rec.get("findings") or {}).items()):
        block(_MD["ap_finding"][li].format(i=i), [r])
    for rid, r in (rec.get("checks") or {}).items():
        block(_MD["ap_check"][li].format(x=check_label(rid, li)), [r])
    block(_MD["ap_scope"][li], rec.get("scope"))
    block(_MD["ap_method"][li], rec.get("method"))
    if repro is not None:
        block(_MD["ap_repro"][li], [{"J": repro.to_dict()}])
    block(_MD["ap_other"][li], rec.get("other"))
    return out


# The page itself adds nothing: background, type and colours come from the shared theme the body inlines
# (report_visuals.theme_style), light or dark by the OS setting or a .dark class on <html>.


def _page(title: str, lang: str, body: str) -> str:
    return ("<!DOCTYPE html>\n<html lang=\"" + lang + "\"><head>\n<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>{html.escape(title)}</title>\n</head>\n<body>\n{body}\n</body>\n</html>\n")


def _limitation_text(nc: Dict[str, Any]) -> str:
    return f"{nc.get('kind')}: {nc.get('item')}: {nc.get('reason')}"


def _ko_limitation(text: str, li: int) -> str:
    """A limitation line ``kind: item: reason`` for the Korean report: the engine's reason is translated, the rest kept."""
    if not li:
        return text
    parts = str(text).split(": ", 2)
    return ": ".join(parts[:2] + [ko_text(parts[2], li)]) if len(parts) == 3 else ko_text(text, li)


def _inconclusive_result(pid: Any, debug_image: Optional[str], kind: str, item: str, reason: str) -> Dict[str, Any]:
    return {
        "verdict": VERDICT_INCONCLUSIVE, "confidence": 0.0, "summary": f"No conclusion was reached: {reason}",
        "findings": [], "checks_run": [], "collection_impact": {},
        "not_covered": [{"kind": kind, "item": item, "reason": reason}],
        "target": {"pid": pid, "debug_image": debug_image}, "report": None, "report_path": None,
        "investigation_id": None, "state": "NOT_RUN",
    }


def result_from_session(session: Any) -> Dict[str, Any]:
    """A ``DiagnoseResult``-shaped dict (``res``) for an investigation that already ran (``investigation_id`` entry).

    The adapter that lets a stored session go through the same report generator as a fresh ``diagnose()``: the
    ``DiagnosticReport`` is the session's own, findings / checks / not-covered rows are derived from it the way
    ``diagnose()`` derives them, and the verdict is the report's (no healthy-scope or INFO re-evaluation is applied,
    exactly as the former session-export path did not apply one).
    """
    from .diagnostic_methodology import CheckStatus
    from .expert_diagnostic_engine import _diagnose_check_row, _finding_subjects
    report = session.build_diagnostic_report().to_dict()
    sec_a, sec_b, sec_e = (report.get(k) or {} for k in (
        "section_a_executive_summary", "section_b_target_context", "section_e_findings_and_root_cause"))
    findings: List[Dict[str, Any]] = []
    for rec in list(sec_e.get("confirmed_root_causes") or []) + list(sec_e.get("probable_causes") or []):
        rules = list(rec.get("applicable_diagnostic_rules") or [])
        details = _finding_subjects(session, rules)
        findings.append({
            "category": rec.get("affected_entity"), "severity": rec.get("severity"),
            "status": rec.get("classification"), "description": rec.get("problem_description"),
            "subjects": [d["name"] for d in details], "subject_details": details, "recipe_ids": rules,
            "evidence_ids": list(rec.get("supporting_evidence_ids") or []),
            "observed": [c.technical_interpretation for c in session.checks
                         if c.recipe_id in rules and c.status == CheckStatus.FAIL and c.technical_interpretation],
        })
    from .static_location_candidates import attach_location_candidates   # same as diagnose(): statically derived
    attach_location_candidates(findings, session.companion_elf, report=report)
    executed =[c for c in session.checks if c.status not in (CheckStatus.NOT_EXECUTED, CheckStatus.SKIPPED)]
    not_covered = []
    for c in session.checks:
        if c.status in (CheckStatus.PASS, CheckStatus.FAIL):
            continue
        why = "; ".join(list(c.limitations or []) + list(c.missing_evidence or [])) or (c.error_details or "") \
            or (c.technical_interpretation or "")
        not_covered.append({"kind": f"check_{str(c.status).lower()}", "item": c.recipe_id, "reason": why or str(c.status)})
    concl = getattr(session, "conclusion", None)
    for lim in (list(getattr(concl, "diagnostic_limitations", []) or [])
                + list(getattr(concl, "missing_evidence_and_unknowns", []) or [])
                + list(sec_b.get("environmental_limitations") or []) + list(sec_b.get("collection_failures") or [])):
        not_covered.append({"kind": "limitation", "item": "engine", "reason": str(lim)})
    metrics = getattr(getattr(session, "budget_tracker", None), "metrics", None)
    stop_ms = float(sec_b.get("target_stop_duration_ms") or 0.0)
    target: Dict[str, Any] = {"pid": session.pid, "process_name": sec_b.get("target_process_name"),
                              "debug_image": session.companion_elf, "abi": None}
    if not sec_b.get("target_abi"):
        # Nothing was recorded at diagnosis time (older session): re-read now, labelled as such in the report; if the
        # process is gone the ABI stays unknown.
        try:
            from .target_abi import detect_target_abi
            redetected = detect_target_abi(session.adapter, session.pid, probe_version=False)
            if redetected.status == "DETECTED":   # target process gone / unreadable: everything stays unknown
                target["abi"] = redetected.to_dict()
                target["abi_source"] = "export_time_detection"
        except Exception:  # noqa: BLE001
            pass
    return {
        "verdict": str(sec_a.get("overall_result") or VERDICT_INCONCLUSIVE),
        "confidence": float(getattr(concl, "confidence", 0.0) or 0.0),
        "confidence_basis": str(getattr(concl, "confidence_basis", "") or ""),
        "summary": str(sec_a.get("verdict_rationale") or ""),
        "findings": findings, "checks_run": [_diagnose_check_row(c) for c in executed], "not_covered": not_covered,
        "collection_impact": {
            "capture_mode": sec_b.get("collection_mode"), "measured_stop_ms": stop_ms, "zero_stop": stop_ms == 0.0,
            "bytes_read": int(getattr(metrics, "bytes_read", 0) or 0),
            "wall_clock_ms": float(getattr(metrics, "wall_clock_elapsed_ms", 0.0) or 0.0),
            "samples_collected": int(getattr(metrics, "samples_collected", 0) or 0) if metrics is not None else None,
            "budget_exhausted": bool(getattr(metrics, "is_budget_exhausted", False)),
        },
        "report": json.loads(json.dumps(report, default=str)), "report_path": None,
        "investigation_id": session.investigation_id, "target": target, "state": session.state,
        "stop_reason": getattr(concl, "stop_reason", None), "healthy_scope": {},
    }


def session_report_extras(session: Any, report: Dict[str, Any]) -> Dict[str, Any]:
    """Session-only keys that ``AdaptiveInvestigationSession.export_report("json")`` adds next to the DiagnosticReport
    dict; kept in the JSON of an ``investigation_id`` export (no second report generation: ``report`` is the one built)."""
    sec_d = report.get("section_d_detailed_inspection_results") or {}
    concl = getattr(session, "conclusion", None)
    ta = getattr(session, "target_assessment", None)
    return {
        "report_13_points": {
            "1_problem_description": session.raw_problem_statement,
            "2_target_information": report.get("section_b_target_context", {}),
            "3_initial_classification": report.get("section_c_diagnostic_strategy", {}),
            "4_investigation_scope": {"targeted_recipes": [st.recipe_id for st in session.plan.steps] if session.plan else []},
            "5_executed_diagnostic_procedures": [c for c in sec_d.get("checks", [])
                                                 if c.get("status") not in ("NOT_EXECUTED", "SKIPPED")],
            "6_actual_observations": [r.to_dict() for r in session.collected_evidence_records],
            "7_confirmed_findings": [h.to_dict() for h in session.active_hypotheses if h.status == "CONFIRMED"],
            "7_findings_detail": report.get("section_e_findings_and_root_cause", {}),
            "8_probable_causes": [h.problem_statement for h in session.active_hypotheses
                                  if h.status in ("CONFIRMED", "LIKELY")],
            "9_rejected_hypotheses": [h.to_dict() for h in session.rejected_hypotheses],
            "10_unresolved_hypotheses": [h.to_dict() for h in session.active_hypotheses
                                         if h.status in ("PROPOSED", "LIKELY", "INCONCLUSIVE")],
            "11_evidence_to_source_mapping": [c for c in [ev.get("correlation") for ev in session.collected_evidence] if c],
            "12_missing_evidence": ta.limitations if ta else [],
            "13_recommended_next_actions": concl.recommended_remediations if concl else [],
        },
        "investigation_id": session.investigation_id,
        "target_pid": session.pid,
        "problem_statement": session.raw_problem_statement,
        "status": session.state,
        "conclusion": asdict(concl) if concl else None,
        "plan": session.plan.to_dict() if session.plan else None,
        "active_hypotheses": [h.to_dict() for h in session.active_hypotheses],
        "rejected_hypotheses": [h.to_dict() for h in session.rejected_hypotheses],
        "timeline": session.timeline,
        "diagnostic_limitations": ta.limitations if ta else [],
    }


def _safe_extras(session: Any, report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(json.dumps(session_report_extras(session, report), default=str))
    except Exception:  # noqa: BLE001 - an addition to the JSON; the report itself is already built
        return None


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
    """Plain page used only when the structured page could not be built: the Markdown report, escaped."""
    from .human_report import markdown_to_html
    from .report_visuals import theme_style
    return _page(title, lang, theme_style(lang) + f'<main class="ds-fallback card" lang="{lang}" data-verdict="{html.escape(verdict)}">'
                 + '<div class="card-content">' + markdown_to_html(summary_md) + "</div></main>")


def _compose_markdown(title: str, comp: Dict[str, Any], appendix: List[str]) -> str:
    """The incident report in Markdown: title, then the common outline, then (opt-in) the detail appendix."""
    from .human_report import sections_markdown
    lines = [f"# {title}", ""] + sections_markdown(comp) + appendix
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


def _compose_html(title: str, comp: Dict[str, Any], res: Dict[str, Any], report: Optional[Dict[str, Any]],
                  language: str, parts: Dict[str, Any]) -> str:
    """The incident report in HTML: the same outline, each part with its picture/check list and its own collapsed
    detailed records."""
    from .report_visuals import build_visual_summary
    body = build_visual_summary(res, report, language, title=title, comp=comp, details=parts)
    return _page(title, language, body)


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
        parent = os.path.dirname(san)
        if parent:
            os.makedirs(parent, mode=0o700, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW          # a symlink at the output path is refused, never followed
        fd = os.open(san, flags, 0o600)      # a newly created report file is owner-only
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
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
    session: Any = None,
    report_json_path: Optional[str] = None,
    markdown_detail: bool = False,
    result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Render the incident report (Markdown, HTML, JSON) of one diagnosis.

    The diagnosis is either a fresh ``diagnose()`` of ``pid`` or, with ``session`` (an investigation that already ran,
    the ``investigation_id`` entry), that session adapted by :func:`result_from_session`.  Both end as a
    ``DiagnosticReport`` and are rendered by the one code path below.

    The Markdown and the HTML follow the same outline (``human_report.compose``), with the reproducibility section
    (``extractor.reproducibility``) in its place.  The detailed (A-I) records are attached to the part of the HTML
    report they explain (``report_detail.partition``); the Markdown points to them, and ``markdown_detail=True``
    appends them to the Markdown as well, organised by report part.

    ``result`` is a ``DiagnoseResult`` dict of a diagnosis that already ran, with its inline ``report``
    (``diagnose(..., include_report=True)``): it is rendered as is, so a caller that showed that result (the web UI's
    diagnosis job) gets the report of exactly the same verdict, findings and checks."""
    t0 = time.monotonic_ns()
    if language not in ("en", "ko"):
        raise ValueError(f"language must be 'en' or 'ko', got {language!r}")
    if title == DEFAULT_TITLE and language == "ko":
        title = DEFAULT_TITLE_KO
    if session is not None and not pid:
        pid = session.pid
    if result is not None and not pid:
        pid = (result.get("target") or {}).get("pid")
    if pid is not None and (isinstance(pid, bool) or int(pid) <= 0):
        return {
            "success": False, "pid": pid, "overall_status": VERDICT_INCONCLUSIVE, "verdict": VERDICT_INCONCLUSIVE,
            "health_score": None, "limitations": [f"Invalid target PID {pid}."],
            "error": f"Target process PID {pid} is invalid.",
        }
    limitations: List[str] = list(pre_limitations or [])
    li = 1 if language == "ko" else 0

    # 1. the diagnosis (the only verdict)
    if result is not None:
        from .human_report import render_human_report
        res = json.loads(json.dumps(result, default=str))
        summary_md = render_human_report(res, res.get("report"), lang=language)
        companion_elf_path = companion_elf_path or (res.get("target") or {}).get("debug_image")
    elif session is not None:
        try:
            from .human_report import render_human_report
            res = result_from_session(session)
            summary_md = render_human_report(res, res.get("report"), lang=language)
        except Exception as exc:  # noqa: BLE001
            res = _inconclusive_result(pid, companion_elf_path, "unexpected_error", "session report",
                                       f"{type(exc).__name__}: {exc}")
            summary_md = ""
        companion_elf_path = companion_elf_path or session.companion_elf
    elif not pid:
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
    from .diagnostic_report import DiagnosticReport
    from .reproducibility import build_reproducibility, detail_html as repro_detail_html
    report_obj: Optional[DiagnosticReport] = None
    if report is not None:
        try:
            report_obj = DiagnosticReport.from_dict(report)  # the standard model: every entry ends here
        except Exception:  # noqa: BLE001 - rendered from the dicts by the fallback below
            report_obj = None
    repro = build_reproducibility(report or {}, res)
    if report_obj is not None:
        report_obj.section_j_reproducibility = repro
    res["reproducibility"] = repro.to_dict()
    if report is not None:
        report["section_j_reproducibility"] = res["reproducibility"]
    sec_a = (report or {}).get("section_a_executive_summary") or {}
    sec_b_build_id = ((report or {}).get("section_b_target_context") or {}).get("build_id")
    sec_i = (report or {}).get("section_i_final_conclusions") or {}
    remediation_checklist: List[str] = []
    for item in list(sec_i.get("safe_remediation_suggestions") or []) + list(sec_a.get("recommended_next_actions") or []):
        if item and item not in remediation_checklist:
            remediation_checklist.append(str(item))
    if pre_limitations and verdict not in FAULT_VERDICTS:
        verdict = VERDICT_INCONCLUSIVE  # the target itself could not be resolved
    findings = [_finding_row(f, remediation_checklist) for f in (res.get("findings") or []) if isinstance(f, dict)]
    # ``remediation_checklist`` is kept in the JSON result; the reader-facing "what to do next" is built from the
    # findings (human_report), because the engine's checklist is generic for most categories
    if verdict == VERDICT_INCONCLUSIVE:
        remediation_checklist = [
            _REM["incon"][li].format(lims="; ".join(_ko_limitation(x, li) for x in limitations[:3]))
        ] + [x for x in remediation_checklist if "within expected parameters" not in x]
    elif verdict == VERDICT_HEALTHY:
        from .healthy_verdict import display_label
        not_checked = [display_label(x, bool(li)) for x in (res.get("healthy_scope") or {}).get("not_checked") or []]
        remediation_checklist = [_REM["healthy"][li]] + (
            [_REM["notchecked"][li].format(x="; ".join(not_checked))] if not_checked else [])
    elif not remediation_checklist:
        remediation_checklist.append(_REM["none"][li])
    health_score = health_score_for(verdict, findings)   # JSON only: a fixed deduction per severity, not a measurement

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

    # 3. one composition of the common outline, rendered as Markdown and as HTML
    from .human_report import compose
    view = dict(res, verdict=verdict)
    if not view.get("target"):
        view["target"] = {"pid": eff_pid, "process_name": process_name, "debug_image": eff_elf}
    elif process_name and not target.get("process_name"):
        view["target"] = dict(target, process_name=process_name)
    comp = compose(view, report, language, pointers=True,
                   method_extra={"build_id": build_id or sec_b_build_id, "generated": _generated_at()},
                   extra_sections={"hypothesis": _hypothesis_lines(hyp_res, li),
                                   "reproducibility": _reproducibility_section(repro, language)},
                   repro=res["reproducibility"])
    from .report_detail import partition
    parts = partition(view, report, comp["rows"])
    parts["reproducibility"] = repro_detail_html(repro, language)
    appendix = _detail_appendix_markdown(parts, comp, li, repro) if markdown_detail else []
    report_markdown = _compose_markdown(title, comp, appendix)

    report_html: Optional[str] = None
    if template_path and os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as tf:
            report_html = tf.read().replace("{{VERDICT}}", verdict)
    else:
        try:
            report_html = _compose_html(title, comp, view, report, language, parts)
        except Exception:  # noqa: BLE001 - fall back to the plain rendering below
            report_html = None
    if report_html is None:
        report_html = _html_fallback(title, verdict, report_markdown, language, summary_md)
    report_json = json.dumps(res, default=str)

    saved_path, save_error = _write(output_path, report_markdown, "incident report")
    saved_html_path, save_html_error = _write(report_html_path, report_html, "HTML report", forbid_same_as=saved_path)
    extras = _safe_extras(session, report) if session is not None and report is not None else None
    json_doc = {**report, **{k: v for k, v in extras.items() if k not in report}} if (report is not None and extras) \
        else (report if report is not None else res)
    saved_json_path, save_json_error = _write(
        report_json_path, json.dumps(json_doc, indent=2, default=str), "JSON report", forbid_same_as=saved_path)
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
        "build_id": build_id or sec_b_build_id,
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
        "healthy_scope": res.get("healthy_scope") or {},
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
        "reproducibility": repro.to_dict(),
        # the two reader-facing parts of the report body, as data (report language): the causes considered per
        # finding and the time-ordered course of the diagnosis (extractor.report_story)
        "competing_causes": comp.get("competing") or [],
        "investigation_timeline": comp.get("timeline") or {},
        "session_report_extras": extras,
        "report_path": res.get("report_path"),
        "saved_path": saved_path,
        "save_error": save_error,
        "saved_html_path": saved_html_path,
        "save_html_error": save_html_error,
        "saved_json_path": saved_json_path,
        "save_json_error": save_json_error,
        "llm_next_step_hint": hint,
    }


__all__ = ["export_incident_report", "DEFAULT_TITLE"]
