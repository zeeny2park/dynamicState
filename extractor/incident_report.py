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


# Fixed wording of the Markdown incident report, (en, ko) per key like ``human_report.T``.  Engine-produced text that
# is quoted in it (finding descriptions, limitations, remediation steps) goes through ``human_report.ko_text``.
_MD: Dict[str, Any] = {
    "h1": ("## 1. Target Identity & Zero-Stop Telemetry", "## 1. 대상 정보와 무중단 수집 측정"),
    "pid": ("- **PID**: `{pid}` (`{name}`)", "- **PID**: `{pid}` (`{name}`)"),
    "elf": ("- **Companion ELF**: `{x}`", "- **동반 ELF**: `{x}`"),
    "build": ("- **Build ID**: `{x}`", "- **빌드 ID**: `{x}`"),
    "inv": ("- **Investigation**: `{x}`", "- **조사 ID**: `{x}`"),
    "mode": ("- **Collection Mode**: `{x}`", "- **수집 방식**: `{x}`"),
    "stop": ("- **Process Stop Duration**: `{ms}ms` (Measured)", "- **프로세스 정지 시간**: `{ms}ms` (측정값)"),
    "status": ("- **Overall Status**: `{v}` (Health Score: `{s}/100`)", "- **종합 상태**: `{v}` (건강 점수: `{s}/100`)"),
    "status_na": ("- **Overall Status**: `{v}` (Health Score: `N/A — {why}`)", "- **종합 상태**: `{v}` (건강 점수: `해당 없음 — {why}`)"),
    "why_incon": ("Inconclusive", "판단 불가"), "why_unscored": ("not scored", "점수 없음"),
    "gen": ("- **Generated At**: `{x}`", "- **생성 시각**: `{x}`"),
    "h2": ("## 2. Root-Cause Findings", "## 2. 근본 원인 발견"),
    "th": ("| Severity | Category | Status | Subjects | Description |", "| 심각도 | 범주 | 상태 | 대상 | 설명 |"),
    "incon": ("- Diagnostic inspection inconclusive: collection failed or target memory was unreadable.",
              "- 진단 점검이 판단 불가로 끝났습니다: 수집에 실패했거나 대상 메모리를 읽을 수 없었습니다."),
    "lim": ("  - Limitation: `{x}`", "  - 제한 사항: `{x}`"),
    "healthy": ("- Healthy within the checked scope: every baseline check ran to completion and found nothing.",
                "- 점검한 범위 안에서는 정상입니다: 기본 검사가 모두 끝까지 실행되었고 아무것도 발견하지 못했습니다."),
    "checked": ("  - Checked: {what} (`{rid}`)", "  - 점검함: {what} (`{rid}`)"),
    "notchecked": ("  - Not checked: {x}", "  - 점검하지 못함: {x}"),
    "nofault": ("- No fault was found by the checks that ran.", "- 실행된 검사에서는 결함이 발견되지 않았습니다."),
    "h3": ("## 3. Hypothesis Verification (`{v}` · Confidence `{c}%`)", "## 3. 가설 검증 (`{v}` · 신뢰도 `{c}%`)"),
    "hyp": ("- **Hypothesis**: {x}", "- **가설**: {x}"),
    "hyp_note": ("- This verifies the stated assertions only; it does not change the diagnosis verdict above.",
                 "- 이 검증은 명시한 단언만 확인하며, 위의 진단 판정을 바꾸지 않습니다."),
    "hyp_th": ("| Assertion | Resolved Expression | Observed Value | Expected | Passed |",
               "| 단언 | 해석된 식 | 관측값 | 기대값 | 통과 |"),
    "pass": ("PASS", "통과"), "fail": ("FAIL", "실패"),
    "h4": ("## 4. Checks Run", "## 4. 실행한 검사"),
    "h5": ("## 5. Remediation Checklist", "## 5. 조치 체크리스트"),
    "h_detail": ("## Appendix: Detailed report (sections A-I)", "## 부록: 상세 보고서 (A-I 항목, 영문 원문)"),
    "rem_incon": ("Investigation inconclusive: the collection failed or parts of the target could not be examined "
                  "({lims}). Verify target process accessibility and read permissions, then re-run.",
                  "조사가 판단 불가로 끝났습니다: 수집에 실패했거나 대상의 일부를 확인하지 못했습니다 ({lims}). "
                  "대상 프로세스에 접근할 수 있는지와 읽기 권한을 확인한 뒤 다시 실행하세요."),
    "rem_healthy": ("No remediation needed within the checked scope: every baseline check ran to completion and found nothing.",
                    "점검한 범위 안에서는 조치가 필요 없습니다: 기본 검사가 모두 끝까지 실행되었고 아무것도 발견하지 못했습니다."),
    "rem_notchecked": ("Not checked (outside the healthy scope): {x}.", "점검하지 못함 (정상 판정 범위 밖): {x}."),
    "rem_none": ("No fault was found by the checks that ran; see 'What could not be examined'.",
                 "실행된 검사에서는 결함이 발견되지 않았습니다. '확인하지 못한 것'을 참고하세요."),
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
            f'{body}\n</section>\n')


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
    executed = [c for c in session.checks if c.status not in (CheckStatus.NOT_EXECUTED, CheckStatus.SKIPPED)]
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
    try:
        from .target_abi import detect_target_abi
        target["abi"] = detect_target_abi(session.adapter, session.pid, probe_version=False).to_dict()
    except Exception:  # noqa: BLE001 - the process may be gone; the ABI is then recorded as unknown
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
    session: Any = None,
    report_json_path: Optional[str] = None,
    markdown_detail: bool = False,
) -> Dict[str, Any]:
    """Render the incident report (Markdown, HTML, JSON) of one diagnosis.

    The diagnosis is either a fresh ``diagnose()`` of ``pid`` or, with ``session`` (an investigation that already ran,
    the ``investigation_id`` entry), that session adapted by :func:`result_from_session`.  Both end as a
    ``DiagnosticReport`` and are rendered by the one code path below."""
    t0 = time.monotonic_ns()
    if language not in ("en", "ko"):
        raise ValueError(f"language must be 'en' or 'ko', got {language!r}")
    if title == DEFAULT_TITLE and language == "ko":
        title = DEFAULT_TITLE_KO
    if session is not None and not pid:
        pid = session.pid
    if pid is not None and (isinstance(pid, bool) or int(pid) <= 0):
        return {
            "success": False, "pid": pid, "overall_status": VERDICT_INCONCLUSIVE, "verdict": VERDICT_INCONCLUSIVE,
            "health_score": None, "limitations": [f"Invalid target PID {pid}."],
            "error": f"Target process PID {pid} is invalid.",
        }
    limitations: List[str] = list(pre_limitations or [])
    li = 1 if language == "ko" else 0

    # 1. the diagnosis (the only verdict)
    if session is not None:
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
    from .reproducibility import build_reproducibility, render_html as repro_html, render_markdown as repro_md
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
    if verdict == VERDICT_INCONCLUSIVE:
        remediation_checklist = [
            _MD["rem_incon"][li].format(lims="; ".join(_ko_limitation(x, li) for x in limitations[:3]))
        ] + [x for x in remediation_checklist if "within expected parameters" not in x]
    elif verdict == VERDICT_HEALTHY:
        # HEALTHY rule (extractor.healthy_verdict): the claim is limited to the baseline scope; say what was not checked
        from .healthy_verdict import display_label
        not_checked = [display_label(x, bool(li)) for x in (res.get("healthy_scope") or {}).get("not_checked") or []]
        remediation_checklist = [
            _MD["rem_healthy"][li]
        ] + ([_MD["rem_notchecked"][li].format(x="; ".join(not_checked))] if not_checked else [])
    elif not remediation_checklist:
        remediation_checklist.append(_MD["rem_none"][li])
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
    na = _MD["why_incon" if verdict == VERDICT_INCONCLUSIVE else "why_unscored"][li]
    status_line = (_MD["status"][li].format(v=verdict, s=health_score) if health_score is not None
                   else _MD["status_na"][li].format(v=verdict, why=na))
    md = [
        f"# {title}", "",
        _MD["h1"][li],
        _MD["pid"][li].format(pid=eff_pid, name=target.get('process_name') or process_name or 'target'),
        _MD["elf"][li].format(x=eff_elf),
        _MD["build"][li].format(x=build_id or sec_b_build_id or 'N/A'),
        _MD["inv"][li].format(x=res.get('investigation_id') or 'N/A'),
        _MD["mode"][li].format(x=collection_mode),
        _MD["stop"][li].format(ms=f"{stop_ms:.2f}"),
        *impact_summary_lines(impact, language),
        status_line,
        _MD["gen"][li].format(x=now_iso), "",
        _MD["h2"][li],
    ]
    if findings:
        md.append(_MD["th"][li])
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in findings:
            md.append(f"| **{f.get('severity')}** | `{f.get('category')}` | {f.get('status')} | "
                      f"{', '.join('`%s`' % s for s in (f.get('subjects') or [])[:6]) or '-'} | "
                      f"{ko_text(f.get('description') or '-', li)} |")
    elif verdict == VERDICT_INCONCLUSIVE:
        md.append(_MD["incon"][li])
        for lim in limitations[:12]:
            md.append(_MD["lim"][li].format(x=_ko_limitation(lim, li)))
    elif verdict == VERDICT_HEALTHY:
        from .healthy_verdict import display_label, display_what
        scope = res.get("healthy_scope") or {}
        md.append(_MD["healthy"][li])
        for c in scope.get("checked") or []:
            md.append(_MD["checked"][li].format(what=display_what(c, bool(li)), rid=c.get('recipe_id')))
        for x in scope.get("not_checked") or []:
            md.append(_MD["notchecked"][li].format(x=display_label(x, bool(li))))
    else:
        md.append(_MD["nofault"][li])
    if summary_md:
        md += ["", f"### {_LABELS[language]['diag_summary']}", ""] + _demote_headings(summary_md)
    if hyp_res is not None:
        md += ["", _MD["h3"][li].format(v=hyp_res.get('verdict'),
                                        c=round(float(hyp_res.get('confidence_score') or 0.0) * 100, 1)),
               _MD["hyp"][li].format(x=hyp_res.get('hypothesis')),
               _MD["hyp_note"][li], "",
               _MD["hyp_th"][li],
               "| :--- | :--- | :--- | :--- | :--- |"]
        for ar in hyp_res.get("assertion_results", []):
            md.append(f"| `{ar.get('assertion')}` | `{ar.get('resolved_expression')}` | `{ar.get('observed_value')}` | "
                      f"`{ar.get('expected')}` | **{_MD['pass' if ar.get('passed') else 'fail'][li]}** |")
    md += ["", _MD["h4"][li]]
    for c in (res.get("checks_run") or [])[:30]:
        md.append(f"- `{c.get('recipe_id')}`: {c.get('status')}")
    md += ["", _MD["h5"][li]]
    md += [f"{i}. [ ] {ko_text(step, li)}" for i, step in enumerate(remediation_checklist, start=1)]
    md += [""] + repro_md(repro, language, heading="## 6.")
    if markdown_detail and report_obj is not None:
        # the same A-I sections the HTML report carries in its collapsed block; the reproducibility section is above
        from dataclasses import replace
        md += ["", _MD["h_detail"][li], ""] + _demote_headings(
            replace(report_obj, section_j_reproducibility=None).to_markdown(language))
    report_markdown = "\n".join(md) + "\n"

    report_html: Optional[str] = None
    if template_path and os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as tf:
            report_html = tf.read().replace("{{VERDICT}}", verdict)
    elif report_obj is not None:
        try:
            from .report_visuals import build_visual_summary, wrap_detail
            from dataclasses import replace
            base_html = wrap_detail(replace(report_obj, section_j_reproducibility=None).to_html(language), _LABELS[language]["detail"])
            try:
                visual = build_visual_summary(res, report, language, title=title, summary_md=summary_md)
            except Exception:  # noqa: BLE001 - the pictures are an addition; the report must still be written
                visual = f"<h1>{html.escape(title)}</h1>"
            report_html = base_html.replace(
                "<body>", f"<body>\n{visual}\n{_summary_section(language, verdict, summary_md)}\n{repro_html(repro, language)}", 1)
            report_html = report_html.replace("<html>", f'<html lang="{language}">', 1)
            report_html = report_html.replace(
                "<head>", '<head>\n<meta name="viewport" content="width=device-width, initial-scale=1">', 1)
        except Exception:  # noqa: BLE001 - fall back to the plain rendering below
            report_html = None
    if report_html is None:
        report_html = _html_fallback(title, verdict, report_markdown, language, summary_md)
    report_json = json.dumps(res, default=str)

    saved_path, save_error = _write(output_path, report_markdown, "incident report")
    saved_html_path, save_html_error = _write(report_html_path, report_html, "HTML report", forbid_same_as=saved_path)
    saved_json_path, save_json_error = _write(
        report_json_path, json.dumps(report if report is not None else res, indent=2, default=str), "JSON report",
        forbid_same_as=saved_path)
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
