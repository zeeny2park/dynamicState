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


def _reproducibility_section(res: Dict[str, Any], report: Optional[Dict[str, Any]], language: str) -> List[str]:
    """RESERVED SLOT for the reproducibility section (``extractor/reproducibility.py``, added separately).

    Return its Markdown lines here; ``human_report.compose`` places them as the "Reproducibility / 재현 정보"
    section after "How the diagnosis was done" and before "Reference", in the Markdown and the HTML report alike.
    Empty: the section is left out."""
    return []


def _detail_appendix_markdown(parts: Dict[str, Any], comp: Dict[str, Any], li: int) -> List[str]:
    """Opt-in Markdown appendix of the detailed records, organised by report part (not as one A-I sequence)."""
    from .diagnostic_report import detail_record_markdown
    from .human_report import check_label
    rec = parts.get("records") or {}
    out = [f"## {_MD['appendix'][li]}", ""]

    def block(title: str, records: Any) -> None:
        items = [r for r in (records or []) if r]
        if not items:
            return
        out.extend([f"### {title}", ""])
        for r in items:
            out.extend(detail_record_markdown(", ".join(sorted(r.keys())) if isinstance(r, dict) else "-", r))
    block(_MD["ap_verdict"][li], rec.get("verdict"))
    for i, r in sorted((rec.get("findings") or {}).items()):
        block(_MD["ap_finding"][li].format(i=i), [{k: v} for k, v in r.items() if v])
    for rid, r in (rec.get("checks") or {}).items():
        block(_MD["ap_check"][li].format(x=check_label(rid, li)), [{k: v} for k, v in r.items() if v])
    block(_MD["ap_scope"][li], rec.get("scope"))
    block(_MD["ap_method"][li], rec.get("method"))
    block(_MD["ap_other"][li], [x for x in (rec.get("other") or []) if any(v for v in x.values())])
    return out


_PAGE_CSS = """
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; padding: 16px; background: #f1f5f9; color: #0f172a; }
@media (prefers-color-scheme: dark) { body { background: #020617; color: #e2e8f0; } }
"""


def _page(title: str, lang: str, body: str) -> str:
    return ("<!DOCTYPE html>\n<html lang=\"" + lang + "\"><head>\n<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>{html.escape(title)}</title>\n<style>{_PAGE_CSS}</style>\n</head>\n<body>\n{body}\n</body>\n</html>\n")


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
    return _page(title, lang, f'<main class="ds-fallback" lang="{lang}" data-verdict="{html.escape(verdict)}">'
                 + markdown_to_html(summary_md) + "</main>")


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
    markdown_detail: bool = False,
) -> Dict[str, Any]:
    """Diagnose ``pid`` once with ``diagnose()`` and render the incident report (Markdown, HTML, JSON).

    The Markdown and the HTML follow the same outline (``human_report.compose``).  The detailed (A-I) records are
    attached to the part of the HTML report they explain (``report_detail.partition``); the Markdown points to them,
    and ``markdown_detail=True`` appends them to the Markdown as well, organised by report part."""
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
    li = 1 if language == "ko" else 0

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
                   method_extra={"build_id": build_id, "generated": _generated_at()},
                   extra_sections={"hypothesis": _hypothesis_lines(hyp_res, li),
                                   "reproducibility": _reproducibility_section(view, report, language)})
    from .report_detail import partition
    parts = partition(view, report, comp["rows"])
    appendix = _detail_appendix_markdown(parts, comp, li) if markdown_detail else []
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
        "report_path": res.get("report_path"),
        "saved_path": saved_path,
        "save_error": save_error,
        "saved_html_path": saved_html_path,
        "save_html_error": save_html_error,
        "llm_next_step_hint": hint,
    }


__all__ = ["export_incident_report", "DEFAULT_TITLE"]
