"""Which detailed (A-I) record belongs to which part of the incident report.

The detailed report of a diagnosis (``DiagnosticReport.to_dict()``, sections A-I) used to be appended to the HTML
report as one collapsed block.  ``partition`` assigns every record to the one part of the report it explains, so the
reader opens the detail of the part they are reading:

=========================================  ==============================================================
report part                                detailed records shown there
=========================================  ==============================================================
conclusion (verdict)                       A executive summary, F ranking head, I final conclusions
finding *n*                                E finding records, F hypotheses and G evidence records of that
                                           finding (matched by evidence id, then category / recipe id)
check row (one recipe)                     D check records of that recipe, the G evidence records attached
                                           to those checks, F hypotheses decided by that recipe (refuted
                                           alternatives), the C exclusion reason of a recipe not run
scope (check totals, what was not judged)  D totals, H limitations
method (how it was done, cost)             report ids, B target context, C strategy, G totals and the G
                                           records no finding or check refers to (collection reads)
other details                              whatever matches none of the above
=========================================  ==============================================================

A record is rendered in exactly one place; another part that refers to it links to its anchor
(``diagnostic_report.detail_anchor``).  The rendered fragments are English, like the detailed report.
"""

from __future__ import annotations

import html
from typing import Any, Dict, List, Optional, Tuple

from . import diagnostic_report as dr

E = html.escape


def _ids(xs: Any) -> List[str]:
    return [str(x) for x in (xs or []) if x]


def _e_records(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    sec = report.get("section_e_findings_and_root_cause") or {}
    out: List[Dict[str, Any]] = []
    for key in ("confirmed_root_causes", "probable_causes", "anomalies", "observed_symptoms", "derived_evidence"):
        out += [r for r in (sec.get(key) or []) if isinstance(r, dict)]
    return out


def _link(kind: str, ident: Any, text: str) -> str:
    return f'<a href="#{dr.detail_anchor(kind, ident)}">{E(text)}</a>'


def partition(res: Dict[str, Any], report: Optional[Dict[str, Any]], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Assign the detailed records to the report parts; returns the rendered HTML fragments and the record lists.

    Keys: ``verdict``, ``scope``, ``method``, ``other`` (HTML strings), ``findings`` (finding number -> HTML),
    ``checks`` (recipe id -> HTML), ``records`` (the same assignment as raw records, for the Markdown appendix and
    for tests)."""
    out: Dict[str, Any] = {"verdict": "", "scope": "", "method": "", "other": "", "findings": {}, "checks": {},
                           "records": {"verdict": [], "scope": [], "method": [], "other": [], "findings": {}, "checks": {}}}
    if not isinstance(report, dict):
        return out
    rec = out["records"]
    findings = [f for f in (res.get("findings") or []) if isinstance(f, dict)]
    row_ids = [r["rid"] for r in rows]
    a = report.get("section_a_executive_summary") or {}
    f_sec = report.get("section_f_competing_hypotheses") or {}
    g_sec = report.get("section_g_evidence_and_provenance") or {}
    d_sec = report.get("section_d_detailed_inspection_results") or {}
    c_sec = report.get("section_c_diagnostic_strategy") or {}

    # ---- findings: E records, F hypotheses, G evidence
    f_ev = {i: set(_ids(f.get("evidence_ids"))) for i, f in enumerate(findings, 1)}
    f_rid = {i: set(_ids(f.get("recipe_ids"))) for i, f in enumerate(findings, 1)}
    f_cat = {i: str(f.get("category")) for i, f in enumerate(findings, 1)}
    e_of: Dict[int, List[Dict[str, Any]]] = {i: [] for i in f_ev}
    other_e: List[Dict[str, Any]] = []
    for r in _e_records(report):
        ev = set(_ids(r.get("supporting_evidence_ids")))
        hit = next((i for i in f_ev if ev & f_ev[i]), None)
        if hit is None:
            rules = set(_ids(r.get("applicable_diagnostic_rules")))
            hit = next((i for i in f_rid if rules and rules & f_rid[i]), None)
        (e_of[hit] if hit is not None else other_e).append(r)
    hyp_of: Dict[int, List[Dict[str, Any]]] = {i: [] for i in f_ev}
    hyp_row: Dict[str, List[Dict[str, Any]]] = {}
    other_h: List[Dict[str, Any]] = []
    for h in [h for h in (f_sec.get("hypotheses") or []) if isinstance(h, dict)]:
        supp = set(_ids(h.get("supporting_evidence_ids")))
        hit = next((i for i in f_ev if supp & f_ev[i]), None)
        if hit is None and str(h.get("status")) not in ("REFUTED", "CONTRADICTED"):
            hit = next((i for i in f_cat if str(h.get("category") or h.get("problem_category")) == f_cat[i]), None)
        if hit is not None:
            hyp_of[hit].append(h)
            continue
        cand = [str(e.get("recipe_id")) for e in (h.get("contradicting_evidence") or []) if isinstance(e, dict)]
        cand += _ids(h.get("applicable_diagnostic_rules"))
        rid = next((x for x in cand if x in row_ids), None)
        if rid:
            hyp_row.setdefault(rid, []).append(h)
        else:
            other_h.append(h)
    for i in f_ev:   # evidence named by the finding's own records belongs to the finding too
        for r in e_of[i] + hyp_of[i]:
            f_ev[i] |= set(_ids(r.get("supporting_evidence_ids")))
    ev_home: Dict[str, Tuple[str, Any]] = {}
    checks_by_rid: Dict[str, List[Dict[str, Any]]] = {}
    other_d: List[Dict[str, Any]] = []
    rid_of_check: Dict[str, str] = {}
    for c in [c for c in (d_sec.get("checks") or []) if isinstance(c, dict)]:
        rid = str(c.get("recipe_id") or "")
        if rid in row_ids:
            checks_by_rid.setdefault(rid, []).append(c)
            rid_of_check[str(c.get("check_id"))] = rid
        else:
            other_d.append(c)
    ev_of: Dict[int, List[Dict[str, Any]]] = {i: [] for i in f_ev}
    ev_row: Dict[str, List[Dict[str, Any]]] = {}
    ev_method: List[Dict[str, Any]] = []
    for ev in [e for e in (g_sec.get("evidence_records") or []) if isinstance(e, dict)]:
        eid = str(ev.get("evidence_id"))
        hit = next((i for i in f_ev if eid in f_ev[i]), None)
        if hit is not None:
            ev_of[hit].append(ev)
            ev_home[eid] = ("finding", hit)
            continue
        rid = next((rid_of_check[c] for c in _ids(ev.get("associated_checks")) if c in rid_of_check), None)
        if rid is None:
            rid = next((r for r, cs in checks_by_rid.items()
                        if any(eid in _ids(c.get("supporting_evidence_ids")) for c in cs)), None)
        if rid is not None:
            ev_row.setdefault(rid, []).append(ev)
            ev_home[eid] = ("check", rid)
        else:
            ev_method.append(ev)
            ev_home[eid] = ("method", None)

    excluded = [x for x in (c_sec.get("recipes_excluded") or []) if isinstance(x, dict)]
    excl_row = {str(x.get("recipe_id")): x for x in excluded if str(x.get("recipe_id")) in row_ids}
    excl_rest = [x for x in excluded if str(x.get("recipe_id")) not in excl_row]

    # ---- render: findings
    for i, f in enumerate(findings, 1):
        parts = []
        if e_of[i]:
            parts.append("<h4>E. Finding records</h4>" + dr.detail_findings_html(e_of[i]))
        if hyp_of[i]:
            parts.append("<h4>F. Hypotheses about this finding</h4>" + dr.detail_hypotheses_html(hyp_of[i]))
        if ev_of[i]:
            parts.append("<h4>G. Evidence records</h4>" + dr.detail_evidence_html(ev_of[i]))
        produced = [r for r in _ids(f.get("recipe_ids")) if r in checks_by_rid]
        if produced:
            parts.append("<p><strong>Checks behind this finding (D):</strong> " + ", ".join(
                f'<a href="#check-{E(r)}">{E(r)}</a>' for r in produced) + "</p>")
        out["findings"][i] = "\n".join(parts)
        rec["findings"][i] = {"E": e_of[i], "F": hyp_of[i], "G": ev_of[i], "D_links": produced}

    # ---- render: check rows
    linked_f: Dict[str, List[int]] = {}
    for i, f in enumerate(findings, 1):
        for r in _ids(f.get("recipe_ids")):
            linked_f.setdefault(r, []).append(i)
    for rid in row_ids:
        parts = []
        cs = checks_by_rid.get(rid) or []
        if cs:
            parts.append(dr.detail_checks_html(cs))
        if ev_row.get(rid):
            parts.append("<h4>G. Evidence records of this check</h4>" + dr.detail_evidence_html(ev_row[rid]))
        moved = [e for c in cs for e in _ids(c.get("supporting_evidence_ids")) if ev_home.get(e, ("", None))[0] == "finding"]
        if moved:
            parts.append("<p>Evidence shown with the finding it supports: "
                         + ", ".join(_link("ev", e, e) for e in dict.fromkeys(moved)) + "</p>")
        if hyp_row.get(rid):
            parts.append("<h4>F. Hypotheses decided by this check</h4>" + dr.detail_hypotheses_html(hyp_row[rid]))
        if rid in excl_row:
            parts.append("<h4>C. Why this check was not run</h4>" + dr.detail_excluded_html([excl_row[rid]]))
        if linked_f.get(rid):
            parts.append("<p>Finding records: " + ", ".join(f'<a href="#finding-{i}-detail">finding {i}</a>'
                                                              for i in linked_f[rid]) + "</p>")
        if parts:
            out["checks"][rid] = "\n".join(parts)
        rec["checks"][rid] = {"D": cs, "G": ev_row.get(rid) or [], "F": hyp_row.get(rid) or [],
                              "C": [excl_row[rid]] if rid in excl_row else []}

    # ---- render: verdict, scope, method, other
    i_sec = report.get("section_i_final_conclusions") or {}
    out["verdict"] = "\n".join(x for x in (dr.detail_section_a_html(a), dr.detail_section_f_header_html(f_sec),
                                           dr.detail_section_i_html(i_sec, str(a.get("verdict_rationale") or ""))) if x)
    rec["verdict"] = [{"A": a}, {"F_head": {k: v for k, v in f_sec.items() if k != "hypotheses"}}, {"I": i_sec}]
    h_sec = report.get("section_h_limitations_and_unverified") or {}
    out["scope"] = "\n".join(x for x in (dr.detail_section_d_summary_html(d_sec), dr.detail_section_h_html(h_sec)) if x)
    rec["scope"] = [{"D_totals": {k: v for k, v in d_sec.items() if k != "checks"}}, {"H": h_sec}]
    method = [dr.detail_meta_html(report), dr.detail_section_b_html(report.get("section_b_target_context") or {}),
              dr.detail_section_c_html(c_sec, include_excluded=False)]
    if excl_rest:
        method.append("<p><strong>Excluded Recipes (no check row):</strong></p>" + dr.detail_excluded_html(excl_rest))
    method.append(dr.detail_section_g_header_html(g_sec))
    if ev_method:
        method.append("<h4>G. Collection records not tied to a finding or check</h4>" + dr.detail_evidence_html(ev_method))
    impact = res.get("collection_impact") if isinstance(res.get("collection_impact"), dict) else {}
    if impact:
        method.append("<h4>Collection impact (measured)</h4><pre class=\"dsd-pre\">"
                      + E("\n".join(f"{k}: {v}" for k, v in impact.items())) + "</pre>")
    out["method"] = "\n".join(x for x in method if x)
    rec["method"] = [{"meta": {k: report.get(k) for k in ("report_id", "investigation_id", "schema_version",
                                                          "generated_at", "report_completeness")}},
                     {"B": report.get("section_b_target_context")},
                     {"C": {k: v for k, v in c_sec.items() if k != "recipes_excluded"}, "C_excluded": excl_rest},
                     {"G_head": {k: v for k, v in g_sec.items() if k != "evidence_records"}, "G": ev_method},
                     {"collection_impact": impact}]
    other = []
    if other_e:
        other.append("<h4>E. Finding records not tied to a reported finding</h4>" + dr.detail_findings_html(other_e))
    if other_h:
        other.append("<h4>F. Other hypotheses</h4>" + dr.detail_hypotheses_html(other_h))
    if other_d:
        other.append("<h4>D. Checks without a check-list row</h4>" + dr.detail_checks_html(other_d))
    out["other"] = "\n".join(other)
    rec["other"] = [{"E": other_e}, {"F": other_h}, {"D": other_d}]
    return out
