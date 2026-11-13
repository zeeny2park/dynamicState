"""The web UI's view of one finished diagnosis, built on the server from the report code.

The browser renders a ``DiagnoseResult`` without re-implementing any of the report's wording, labels or pictures:
everything that is words or a picture comes from here, and every piece is produced by the same functions that
write the incident report (``human_report.compose``, ``report_visuals``), so the final screen and the report say
the same thing.  The ``verdict`` event of ``/api/diagnose/{job_id}/events`` carries ``view = {"ko": ..., "en": ...}``
(see ``docs/ui-redesign/UI_EVENTS.md``); the replay files under ``replay/`` are made with the same function.

Read-only use of the report modules; nothing here decides anything about the diagnosis.
"""
from __future__ import annotations

import html
import re
from typing import Any, Dict, List, Optional

VIEW_VERSION = 1
LANGS = ("ko", "en")

# verdict -> one of the four status tones (the same mapping as the report's hero card)
VERDICT_TONE = {"CONFIRMED_FAULT": "fail", "FAULT": "fail", "PROBABLE_FAULT": "warn", "DEGRADED": "warn",
                "HEALTHY": "pass"}

_E = html.escape
_CK_RE = re.compile(r'<details class="dsv-ck dsv-s-(\w+)" data-status="\w+" id="check-([^"]+)"><summary>(.*?)</summary>'
                    r'(<dl>.*?</dl>)', re.S)
_SPAN = r'<span class="{cls}">(.*?)</span>'


def _span(cls: str, s: str) -> str:
    m = re.search(_SPAN.format(cls=re.escape(cls)), s, re.S)
    return m.group(1) if m else ""


def _strip_tags(s: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", s))


def _finding_body(card: str) -> str:
    """The report's finding card without its own frame and heading: the UI draws the frame and the heading
    (whose badge changes while the diagnosis runs); everything inside is the report's."""
    body = re.sub(r'^<section class="dsv-card[^"]*" id="finding-\d+"><span id="dsv-finding-\d+"></span>', "", card)
    body = re.sub(r'^<div class="dsv-fhead">.*?</div>', "", body, flags=re.S)
    return re.sub(r"</section>$", "", body)


def build_view(result: Dict[str, Any], lang: str, report: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Everything the UI shows for a finished diagnosis, in one language, as plain data and report HTML fragments."""
    from extractor import human_report as hr
    from extractor import report_visuals as rv
    from extractor.diagnostic_recipes import CAPABILITY_DESCRIPTIONS

    if lang not in LANGS:
        raise ValueError(f"lang must be one of {LANGS}")
    res = dict(result or {})
    report = report if isinstance(report, dict) else (res.get("report") if isinstance(res.get("report"), dict) else None)
    comp = hr.compose(res, report, lang)
    lx = rv._Lx(lang)
    i = lx.i
    verdict = comp["verdict"]
    vkey = verdict if f"v_{verdict}" in hr.T else "INCONCLUSIVE"
    findings = [f for f in (res.get("findings") or []) if isinstance(f, dict)]
    rows = comp["rows"]
    counts = comp["counts"]

    # ---- checks: one entry per recipe, taken from the report's own check list
    checklist = rv._checklist(lx, res, report, findings, comp, {})
    from_report = {}
    for st, rid, summary, dl in _CK_RE.findall(checklist):
        from_report[html.unescape(rid)] = {"name": _strip_tags(_span("dsv-ck-name", summary)),
                                           "domain": _strip_tags(_span("dsv-chip", summary)),
                                           "line": _strip_tags(_span("dsv-ck-line", summary)), "detail_html": dl}
    checks = []
    for r in rows:
        rid = r["rid"]
        raw = r.get("raw_status") or ""
        kind = ("not_in_mode" if raw == "NOT_IN_MODE" else "not_planned" if raw == "NOT_PLANNED"
                else "not_executed" if r["status"] == "SKIPPED" else "run")
        item = {"rid": rid, "status": r["status"], "raw_status": raw, "kind": kind,
                "anchor": f"check-{rid}-detail", **from_report.get(rid, {"name": rid, "domain": "", "line": "",
                                                                         "detail_html": ""})}
        if isinstance(r.get("dur"), (int, float)) and kind == "run":
            item["ms"] = round(float(r["dur"]) * 1000)
        if kind == "not_in_mode":
            cap = r.get("mode_cap") or ""
            item["capability"] = cap
            item["capability_label"] = CAPABILITY_DESCRIPTIONS.get(cap, (cap, cap))[i]
        item["findings"] = [n for n, f in enumerate(findings, 1) if rid in [str(x) for x in f.get("recipe_ids") or []]]
        checks.append(item)

    # ---- findings: the report's card body (picture, facts, why, evidence) under the UI's own heading
    fviews = []
    for n, (f, block) in enumerate(zip(findings, comp["blocks"]), 1):
        status = str(f.get("status") or "")
        sev = str(f.get("severity") or "").upper()
        if sev == "INFO" and status in ("CONFIRMED_ROOT_CAUSE", "PROBABLE_CAUSE"):
            word, tone = hr.T["k_fstatus_i"][i], "skip"
        elif status == "CONFIRMED_ROOT_CAUSE":
            word, tone = hr.T["k_fstatus_c"][i], "fail"
        else:
            word, tone = (hr.T["k_fstatus_p"][i] if status == "PROBABLE_CAUSE" else status), "warn"
        card = rv._finding_card(lx, n, f, report, block, "")
        fviews.append({"n": n, "category": str(f.get("category")), "status": status, "severity": sev,
                       "severity_word": hr.T[f"sev_{sev}"][i] if f"sev_{sev}" in hr.T else sev,
                       "status_word": word, "tone": tone, "heading_html": hr._inline_html(block["heading"]),
                       "recipe_ids": [str(x) for x in f.get("recipe_ids") or []],
                       "body_html": _finding_body(card), "anchor": f"finding-{n}-detail"})

    impact = res.get("collection_impact") if isinstance(res.get("collection_impact"), dict) else {}
    tiles: Dict[str, Any] = {"checks": {"value": counts["run"], "counts": counts}}
    if isinstance(impact.get("measured_stop_ms"), (int, float)):
        stop = float(impact["measured_stop_ms"])
        tiles["stop"] = {"value": hr.fmt_ms(stop, i),
                         "note": lx.t("zero_stop") if stop == 0 and impact.get("zero_stop") else ""}
    if isinstance(impact.get("bytes_read"), (int, float)):
        tiles["bytes"] = {"value": hr.fmt_bytes(impact["bytes_read"]), "note": str(impact.get("impact_transport") or "")}
    if isinstance(res.get("duration_s"), (int, float)):
        tiles["duration"] = {"value": hr.fmt_ms(float(res["duration_s"]) * 1000, i)}

    next_lines = next((s["lines"] for s in comp["sections"] if s["key"] == "next"), [])
    return {
        "version": VIEW_VERSION, "lang": lang, "verdict": verdict, "tone": VERDICT_TONE.get(verdict, "skip"),
        "verdict_word": hr.T[f"v_{vkey}"][i], "verdict_meaning": hr.T[f"vm_{vkey}"][i],
        "conclusion_html": hr._inline_html(comp["conclusion"]),
        "symptom_html": [hr._inline_html(x) for x in comp.get("symptom_note") or [] if x],
        "scope_html": " ".join(hr._inline_html(x) for x in comp.get("scope_head") or [] if x),
        "tiles": tiles, "checks": checks, "findings": fviews,
        "not_examined_html": rv._md_html(comp.get("not_examined") or []) if comp.get("not_examined") else "",
        "next_html": rv._md_html(next_lines) if next_lines else "",
        "picture_css": rv._CSS + rv._interaction_css(),
    }


def build_views(result: Dict[str, Any], report: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """``{"ko": view, "en": view}`` for the ``verdict`` event (the UI switches language without a round trip)."""
    return {lang: build_view(result, lang, report) for lang in LANGS}


def plan_labels(recipe_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Name and domain of each check in both languages, for the ``plan`` event (the UI has no label table)."""
    from extractor import report_visuals as rv
    out: Dict[str, Dict[str, Any]] = {}
    for rid in recipe_ids:
        meta = rv._recipe_meta(rid)
        dom = meta[0] if meta else "OTHER"
        out[rid] = {"name": {"en": meta[1] if meta else rid, "ko": meta[2] if meta else rid},
                    "domain": dom, "domain_label": {"en": rv._L["dom_" + dom][0], "ko": rv._L["dom_" + dom][1]}}
    return out


def category_labels(category: str) -> Dict[str, str]:
    """A finding category in words, both languages, for ``finding_provisional``."""
    from extractor.human_report import CATEGORY_LABEL
    from extractor.report_registry import category_label
    reg = category_label(category) or CATEGORY_LABEL.get(category)
    return {"en": reg[0], "ko": reg[1]} if reg else {"en": category, "ko": category}
