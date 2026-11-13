"""Make the UI's replay files from saved ``DiagnoseResult`` fixtures.

A replay is the event sequence the server would stream for that diagnosis (``docs/ui-redesign/API_CONTRACT.md``):
target -> classified -> plan -> check_start/check_done per check in executed order (a finding_provisional right
after the first failing check that supports it) -> verified -> verdict.  The page plays it with ``?replay=<name>``.

    python3 -m extractor.web.ui.replay_gen            # rewrites extractor/web/ui/replay/*.json (+ report pages)

The fixtures predate the engine's ``unsupported_in_mode`` entry; ``normalise`` moves the checks that need a
capability a zero-stop diagnosis does not have out of ``checks_run`` into that entry, as the engine now does.
"""
from __future__ import annotations

import gzip
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from .view import build_views, category_labels, plan_labels

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
OUT = os.path.join(HERE, "replay")

# name -> (fixture, request shown in the form, what it demonstrates)
REPLAYS: Dict[str, Tuple[str, Dict[str, Any], str]] = {
    "deadlock": ("tests/fixtures/ko_report/deadlock_circular.json.gz",
                 {"symptom": "서비스가 응답하지 않음"}, "confirmed fault with a picture"),
    "healthy": ("tests/fixtures/ko_report/ok_idle_server.json.gz", {}, "healthy within the checked scope"),
    "inconclusive": ("tests/fixtures/ko_report/request_threads.json.gz",
                     {"symptom": "요청 처리가 느려짐"}, "could not decide (budget ran out)"),
    "degraded": ("tests/fixtures/ko_report/lock_convoy.json.gz",
                 {"symptom": "처리량이 떨어짐"}, "degraded, not a fault"),
}


def _capability_recipes() -> Dict[str, str]:
    from extractor import diagnostic_recipes as dr
    return {rid: r.requires_capabilities[0] for rid, r in dr._RECIPES.items() if r.requires_capabilities}


def normalise(res: Dict[str, Any]) -> Dict[str, Any]:
    """The fixture as today's engine would report it (checks needing a missing capability: unsupported_in_mode)."""
    from extractor.diagnostic_recipes import CAPABILITY_DESCRIPTIONS
    caps = _capability_recipes()
    res = json.loads(json.dumps(res))
    res["checks_run"] = [c for c in res.get("checks_run") or [] if c.get("recipe_id") not in caps]
    nc: List[Dict[str, Any]] = []
    moved: Dict[str, List[str]] = {}
    for n in res.get("not_covered") or []:
        kind = str(n.get("kind") or "")
        if kind.startswith("check_") and n.get("item") in caps:
            moved.setdefault(caps[n["item"]], []).append(n["item"])
            continue
        if kind == "recipes_not_planned":
            keep = []
            for rid in str(n.get("item") or "").split(","):
                (moved.setdefault(caps[rid], []).append(rid) if rid in caps else keep.append(rid))
            if not keep:
                continue
            n = dict(n, item=",".join(keep))
        nc.append(n)
    for cap, ids in moved.items():
        nc.append({"kind": "unsupported_in_mode", "item": ",".join(dict.fromkeys(ids)), "capability": cap,
                   "reason": "not supported in this mode: needs " + CAPABILITY_DESCRIPTIONS.get(cap, (cap, cap))[0]})
    res["not_covered"] = nc
    if isinstance(res.get("report"), dict):
        sec = res["report"].get("section_d_detailed_inspection_results")
        if isinstance(sec, dict) and isinstance(sec.get("checks"), list):
            sec["checks"] = [c for c in sec["checks"] if c.get("recipe_id") not in caps]
    return res


def events_from_result(res: Dict[str, Any], request: Optional[Dict[str, Any]] = None, *,
                       report_url: Optional[str] = None) -> List[Dict[str, Any]]:
    """The event sequence of one finished diagnosis, with ``seq`` and ``t`` (ms since start, compressed)."""
    request = request or {}
    views = build_views(res, res.get("report"))
    ko = {c["rid"]: c for c in views["ko"]["checks"]}
    en = {c["rid"]: c for c in views["en"]["checks"]}
    ev: List[Dict[str, Any]] = []
    t = 0

    def push(e: Dict[str, Any], dt: int) -> None:
        """Append one event in the server's wire shape (API_CONTRACT.md: envelope, contract field names) with the
        fields the contract adds for the UI; ``t`` (ms) is the replay clock."""
        nonlocal t
        t += dt
        data = {k: v for k, v in e.items() if k != "type"}
        if "rid" in data:
            data["recipe_id"] = data.pop("rid")
        if e["type"] == "plan":
            data["steps"] = [{"recipe_id": c["rid"], "name": c["name"]["en"], "label": c["name"], "domain": c["domain"],
                              "domain_label": c["domain_label"]} for c in data.pop("checks")]
            data["total_steps"] = len(data["steps"])
            for key in ("not_planned", "not_in_mode"):
                data[key] = [dict({k: v for k, v in c.items() if k != "rid"}, recipe_id=c["rid"]) for c in data[key]]
        if e["type"] == "check_done":
            data["summary"] = data["line"]["en"]
        if e["type"] == "finding_provisional":
            data["key"] = data.get("category")
            data["category_label"] = data.pop("label")
        ts = "2026-11-13T00:00:%06.3fZ" % (t / 1000.0) if t < 60000 else "2026-11-13T00:%02d:%06.3fZ" % (t // 60000, (t % 60000) / 1000.0)
        ev.append({"seq": len(ev) + 1, "ts": ts, "t": t, "type": e["type"], "data": data})

    tg = res.get("target") or {}
    abi = tg.get("abi") or {}
    impact = res.get("collection_impact") or {}
    push({"type": "target", "pid": tg.get("pid"), "process_name": tg.get("process_name"),
          "architecture": abi.get("architecture"), "libc": abi.get("libc"), "libc_version": abi.get("libc_version"),
          "debug_image": tg.get("debug_image"), "debug_info": bool(tg.get("debug_image")),
          "transport": tg.get("transport") or impact.get("impact_transport") or "local",
          "build_id": tg.get("build_id"), "build_id_match": tg.get("build_id_match"),
          "zero_stop": bool(impact.get("zero_stop")), "stop_ms": impact.get("measured_stop_ms")}, 300)
    run = [c for c in res.get("checks_run") or [] if c.get("recipe_id")]
    first_dom = (plan_labels([run[0]["recipe_id"]])[run[0]["recipe_id"]] if run else None)
    push({"type": "classified", "symptom": request.get("symptom"),
          "category_label": first_dom["domain_label"] if (first_dom and request.get("symptom")) else None,
          "hypotheses": len({str(c.get("recipe_id")) for c in run})}, 300)
    rows = views["en"]["checks"]
    labels = plan_labels([c["rid"] for c in rows])
    plan = {"type": "plan", "checks": [], "not_planned": [], "not_in_mode": [], "budget_s": 20}
    for c in run:
        rid = c["recipe_id"]
        plan["checks"].append(dict(rid=rid, **labels.get(rid) or plan_labels([rid])[rid]))
    for c in rows:
        if c["kind"] == "not_executed":       # planned, never reached: pending until the verdict says "not run"
            plan["checks"].append(dict(rid=c["rid"], **labels[c["rid"]]))
        elif c["kind"] == "not_planned":
            plan["not_planned"].append(dict(rid=c["rid"], **labels[c["rid"]]))
        elif c["kind"] == "not_in_mode":
            plan["not_in_mode"].append(dict(rid=c["rid"], capability=c["capability"],
                                            capability_label={"en": en[c["rid"]]["capability_label"],
                                                              "ko": ko[c["rid"]]["capability_label"]},
                                            **labels[c["rid"]]))
    push(plan, 300)
    findings = [f for f in res.get("findings") or [] if isinstance(f, dict)]
    announced = set()
    bytes_total = float(impact.get("bytes_read") or 0)
    for k, c in enumerate(run, 1):
        rid = c["recipe_id"]
        ms = round(float(c.get("duration_s") or 0) * 1000)
        push({"type": "check_start", "rid": rid}, 80)
        st = str(c.get("status") or "").upper()
        push({"type": "check_done", "rid": rid, "status": st, "duration_ms": ms,
              "line": {"ko": (ko.get(rid) or {}).get("line", ""), "en": (en.get(rid) or {}).get("line", "")},
              "bytes_read": round(bytes_total * k / len(run))}, max(60, min(ms, 600)))
        if st == "FAIL":
            for n, f in enumerate(findings, 1):
                if n not in announced and rid in [str(x) for x in f.get("recipe_ids") or []]:
                    announced.add(n)
                    push({"type": "finding_provisional", "n": n, "category": f.get("category"),
                          "label": category_labels(str(f.get("category"))), "severity": f.get("severity"),
                          "recipe_ids": [str(x) for x in f.get("recipe_ids") or []]}, 10)
    for n, f in enumerate(findings, 1):     # a finding no failing check announced appears at verification
        if n not in announced:
            push({"type": "finding_provisional", "n": n, "category": f.get("category"),
                  "label": category_labels(str(f.get("category"))), "severity": f.get("severity"),
                  "recipe_ids": [str(x) for x in f.get("recipe_ids") or []]}, 10)
    push({"type": "verified", "findings": [{"n": n, "status": f.get("status")} for n, f in enumerate(findings, 1)]},
         500)
    result = {k: v for k, v in res.items() if k != "report"}
    from extractor.human_report import render_human_report
    push({"type": "verdict", "result": result, "view": views,
          "human_summary": {lang: render_human_report(res, res.get("report"), lang=lang) for lang in ("ko", "en")},
          "report_url": report_url}, 500)
    return ev


def report_html(res: Dict[str, Any], lang: str) -> str:
    """The incident report page of the result, by the one report path (``export_incident_report(result=...)``, as
    the server's report endpoint renders a finished job): theme, outline, reproducibility section, detail per part."""
    from extractor.incident_report import export_incident_report
    out = export_incident_report(result=res, language=lang)
    if not out.get("success") or not out.get("report_html"):
        raise RuntimeError(f"report failed: {out.get('error')}")
    return out["report_html"]


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    index = []
    for name, (path, request, what) in REPLAYS.items():
        with gzip.open(os.path.join(REPO, path), "rt", encoding="utf-8") as fh:
            res = normalise(json.load(fh))
        for lang in ("ko", "en"):
            with open(os.path.join(OUT, f"{name}.report.{lang}.html"), "w", encoding="utf-8") as fh:
                fh.write(report_html(res, lang))
        tg = res.get("target") or {}
        doc = {"name": name, "about": what, "source": path,
               "request": dict(request, target=str(tg.get("pid") or ""), mode="local"),
               "report": {"html": f"replay/{name}.report.{{lang}}.html"},
               "events": events_from_result(res, request, report_url=f"replay/{name}.report.{{lang}}.html")}
        with open(os.path.join(OUT, f"{name}.json"), "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, separators=(",", ":"))
        views = next(e["data"]["view"] for e in doc["events"] if e["type"] == "verdict")
        index.append({"name": name, "about": what, "verdict": res.get("verdict"),
                      "verdict_word": {k: v["verdict_word"] for k, v in views.items()},
                      "process_name": tg.get("process_name"), "pid": tg.get("pid")})
    with open(os.path.join(OUT, "index.json"), "w", encoding="utf-8") as fh:
        json.dump(index, fh, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
