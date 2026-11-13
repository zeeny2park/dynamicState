"""The "Additional observation" section that "Add to report" puts into one job's report (HTML, Markdown, JSON; ko/en).

The section is the user's observation after the diagnosis (``extractor.web.explore.WatchSession.snapshot``): it is
placed after "What to do next" and changes nothing else in the report -- not the verdict, not the findings, not the
checks.  Removing the section gives back the report without it, byte for byte (``tests/test_web_explore_report.py``).
The HTML is static markup (inline SVG sparklines, the pool grid as cells): no script, every target value escaped.
"""
from __future__ import annotations

import html
import json
import re
from typing import Any, Dict, List, Tuple

from extractor.web.ui.explore_fragments import clock

E = html.escape
HTML_ID = "obs-report"
MARK_BEGIN = "<!-- ds:additional-observation -->"
MARK_END = "<!-- /ds:additional-observation -->"
MD_BEGIN = "<!-- ds:additional-observation -->"

W: Dict[str, Tuple[str, str]] = {
    "title": ("Additional observation", "추가 관찰"),
    "desc": ("added by the user after the diagnosis · does not change the verdict", "진단 뒤에 사용자가 추가 · 판정에 영향 없음"),
    "line": ("{a} – {b} · {n} samples · every {i} s · target stop 0 ms · no writes · {how}",
             "{a} – {b} · 표본 {n}회 · {i}초 간격 · 대상 정지 0 ms · 쓰기 없음 · {how}"),
    "how_local": ("process_vm_readv", "process_vm_readv"), "how_ssh": ("over SSH", "SSH로 읽음"),
    "tracked": ("Tracked values", "추적한 값"), "name": ("name", "이름"), "type": ("type", "형식"), "now": ("last value", "마지막 값"),
    "spark": ("last 30", "최근 30회"), "changes": ("changes", "변화"), "last": ("last change", "마지막 변화"),
    "unchanged": ("unchanged", "변화 없음"),
    "pool": ("Pool", "풀"), "pool_line": ("{e} · {n} × {t} ({s} B) · status field {f} · {per} element(s) per cell",
                                          "{e} · {n} × {t} ({s} B) · 상태 필드 {f} · 칸 하나 = 원소 {per}개"),
    "pool_trunc": ("the array has {total} elements; only the first {n} are read (per-sample read budget)",
                   "배열은 원소 {total}개이고 앞의 {n}개만 읽음 (표본 읽기 한도)"),
    "other": ("other", "그 밖"),
    "cmp": ("Compare", "비교"), "cmp_line": ("frozen at sample #{a} ({ta}) → #{b} ({tb}) · changed {c} · same {s}",
                                           "고정: 표본 #{a} ({ta}) → #{b} ({tb}) · 바뀜 {c} · 그대로 {s}"),
    "cells": ("cells whose state changed", "상태가 바뀐 칸"), "count_of": ("{x} count", "{x} 개수"),
    "stopped": ("Observation ended: {m}", "관찰 끝: {m}"),
}


def _t(lang: str, k: str, **kw: Any) -> str:
    s = W[k][1 if lang == "ko" else 0]
    return s.format(**kw) if kw else s


def _pool_line(lang: str, p: Dict[str, Any]) -> str:
    line = _t(lang, "pool_line", e=p["expr"], n=p["count"], t=_v(p.get("elem_type")), s=p.get("elem_size"), f=_v(p.get("field")),
              per=p.get("per_cell", 1))
    if int(p.get("total") or 0) > int(p["count"]):
        line += " · " + _t(lang, "pool_trunc", total=p["total"], n=p["count"])
    return line


def _v(x: Any) -> str:
    if isinstance(x, float):
        return f"{x:g}"
    return "—" if x is None else str(x)


def spark_svg(series: List[Any], gone: bool = False) -> str:
    a = list(series or [])[-30:]
    n, W_, H = len(a), 110, 22
    if not n:
        return '<svg class="spark flat" viewBox="0 0 110 22" aria-hidden="true"></svg>'
    num = all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in a)
    flat = all(v == a[0] for v in a)
    cls = "spark" + (" gone" if gone else " flat" if flat else "")
    step = W_ / 29 if n > 1 else 0
    x0 = W_ - step * (n - 1)
    if num and not flat:
        mn, mx = min(a), max(a)
        pts = [f"{x0 + i * step:.1f},{H - 2 - (H - 4) * (v - mn) / (mx - mn):.1f}" for i, v in enumerate(a)]
        lx, ly = pts[-1].split(",")
        return (f'<svg class="{cls}" viewBox="0 0 {W_} {H}" aria-hidden="true"><polygon class="ar" points="{x0:.1f},{H} {" ".join(pts)} {W_},{H}"/>'
                f'<polyline class="ln" points="{" ".join(pts)}"/><circle class="pt" r="2" cx="{lx}" cy="{ly}"/></svg>')
    tk = "".join(f'<line class="tk" x1="{x0 + i * step:.1f}" x2="{x0 + i * step:.1f}" y1="4" y2="{H - 4}"/>' for i in range(1, n) if a[i] != a[i - 1])
    return (f'<svg class="{cls}" viewBox="0 0 {W_} {H}" aria-hidden="true"><line class="base" x1="0" x2="{W_}" y1="{H / 2:g}" y2="{H / 2:g}"/>'
            f'{tk}<circle class="pt" r="2" cx="{W_}" cy="{H / 2:g}"/></svg>')


def _rows(obs: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for it in obs.get("items") or []:
        if it.get("fields") is not None:
            out.append({"name": it["label"], "type": it.get("type"), "value": None, "spark": it.get("spark"), "changes": it.get("changes"),
                        "last": it.get("last_change"), "sub": False})
            for f in it["fields"]:
                out.append({"name": f["name"], "type": "", "value": f.get("value"), "spark": f.get("spark"), "changes": f.get("changes"),
                            "last": f.get("last_change"), "sub": True})
        else:
            out.append({"name": it["label"], "type": it.get("type"), "value": it.get("value"), "spark": it.get("spark"),
                        "changes": it.get("changes"), "last": it.get("last_change"), "sub": False})
    return out


def section_html(obs: Dict[str, Any], lang: str) -> str:
    gone = obs.get("reason") == "target_exited"
    how = _t(lang, "how_ssh" if obs.get("transport") == "ssh" else "how_local")
    body = [f'<p class="impact">{E(_t(lang, "line", a=clock(obs.get("first_t")), b=clock(obs.get("last_t")), n=obs.get("samples", 0), i=_v(obs.get("interval_s")), how=how))}</p>']
    if obs.get("state") == "stopped" and obs.get("reason_detail"):
        body.append(f'<p class="impact">{E(_t(lang, "stopped", m=obs["reason_detail"]))}</p>')
    rows = _rows(obs)
    if rows:
        sub = ' class="sub"'
        tr = "".join(
            f'<tr{sub if r["sub"] else ""}><td class="mono">{E(_v(r["name"]))}</td><td class="mono">{E(_v(r["type"] or ""))}</td>'
            f'<td class="mono num">{E(_v(r["value"])) if r["value"] is not None else ""}</td><td>{spark_svg(r["spark"] or [], gone)}</td>'
            f'<td class="num">{E(_v(r["changes"]))}</td><td class="mono">{E(clock(r["last"]) if r["last"] else _t(lang, "unchanged"))}</td></tr>'
            for r in rows)
        body.append(f'<h3>{E(_t(lang, "tracked"))}</h3><div class="scroll-x"><table class="table"><thead><tr><th>{E(_t(lang, "name"))}</th>'
                    f'<th>{E(_t(lang, "type"))}</th><th class="num">{E(_t(lang, "now"))}</th><th>{E(_t(lang, "spark"))}</th>'
                    f'<th class="num">{E(_t(lang, "changes"))}</th><th>{E(_t(lang, "last"))}</th></tr></thead><tbody>{tr}</tbody></table></div>')
    p = obs.get("pool")
    if p and p.get("cells"):
        cells = str(p["cells"])
        size = "" if len(cells) > 1024 else " pool-md" if len(cells) > 256 else " pool-sm"
        grid = "".join(f'<i class="pc s{int(c)}"></i>' for c in cells if c.isdigit())
        legend = "".join(f'<li><i class="pc s{int(x["cls"])}"></i>{E(_v(x["name"]) if x.get("name") is not None else _t(lang, "other"))} <b>{int(x["count"])}</b></li>'
                         for x in p.get("legend") or [])
        body.append(f'<h3>{E(_t(lang, "pool"))}</h3><p class="impact">{E(_pool_line(lang, p))}</p>'
                    f'<div class="pool{size}" style="--cols:64"><div class="rl"></div><div class="cells">{grid}</div></div><ul class="pool-legend">{legend}</ul>')
    c = obs.get("compare")
    if c:
        items = [(x["name"], x["before"], x["now"], x.get("diff")) for x in c.get("changed") or []]
        if c.get("pool"):
            items += [(_t(lang, "count_of", x=_v(x["name"]) if x.get("name") is not None else _t(lang, "other")), x["before"], x["now"], x["diff"])
                      for x in c["pool"].get("counts") or []]
            items.append((_t(lang, "cells"), "", f'{c["pool"]["cells_changed"]} / {c["pool"]["cells"]}', None))
        def diff(d: Any) -> str:
            return '<span class="d">' + ("+" if d > 0 else "") + E(_v(d)) + "</span>" if d is not None else ""
        lis = "".join(f'<li><span class="nm">{E(_v(n))}</span><span class="was">{E(_v(a))}</span><span aria-hidden="true">→</span>'
                      f'<span class="now">{E(_v(b))}</span>{diff(d)}</li>' for n, a, b, d in items)
        body.append(f'<h3>{E(_t(lang, "cmp"))}</h3><p class="impact">{E(_t(lang, "cmp_line", a=c["from_seq"], ta=clock(c.get("from_t")), b=c["to_seq"], tb=clock(c.get("to_t")), c=len(c.get("changed") or []), s=c.get("same", 0)))}</p>'
                    f'<ul class="cmp">{lis}</ul>')
    return (f'{MARK_BEGIN}<section class="card" id="{HTML_ID}"><div class="card-header"><h2 class="card-title">{E(_t(lang, "title"))}</h2>'
            f'<span class="card-description">{E(_t(lang, "desc"))}</span></div><div class="card-content">{"".join(body)}</div></section>{MARK_END}')


def _md_cell(x: Any) -> str:
    return "`" + str(_v(x)).replace("`", "'").replace("|", "\\|").replace("\n", " ") + "`"


def section_md(obs: Dict[str, Any], lang: str) -> str:
    how = _t(lang, "how_ssh" if obs.get("transport") == "ssh" else "how_local")
    out = [MD_BEGIN, f"## {_t(lang, 'title')}", "", f"_{_t(lang, 'desc')}_", "",
           _t(lang, "line", a=clock(obs.get("first_t")), b=clock(obs.get("last_t")), n=obs.get("samples", 0), i=_v(obs.get("interval_s")), how=how), ""]
    rows = _rows(obs)
    if rows:
        out += [f"### {_t(lang, 'tracked')}", "", f"| {_t(lang, 'name')} | {_t(lang, 'type')} | {_t(lang, 'now')} | {_t(lang, 'changes')} | {_t(lang, 'last')} |",
                "|---|---|---|---|---|"]
        for r in rows:
            out.append(f"| {('↳ ' if r['sub'] else '') + _md_cell(r['name'])} | {_md_cell(r['type'] or '')} | {_md_cell(r['value']) if r['value'] is not None else ''} | "
                       f"{_v(r['changes'])} | {clock(r['last']) if r['last'] else _t(lang, 'unchanged')} |")
        out.append("")
    p = obs.get("pool")
    if p:
        out += [f"### {_t(lang, 'pool')}", "", _pool_line(lang, p), ""]
        out += [f"- {_md_cell(x['name']) if x.get('name') is not None else _t(lang, 'other')}: {x['count']}" for x in p.get("legend") or []]
        out.append("")
    c = obs.get("compare")
    if c:
        out += [f"### {_t(lang, 'cmp')}", "", _t(lang, "cmp_line", a=c["from_seq"], ta=clock(c.get("from_t")), b=c["to_seq"], tb=clock(c.get("to_t")),
                                                 c=len(c.get("changed") or []), s=c.get("same", 0)), ""]
        out += [f"- {_md_cell(x['name'])}: {_md_cell(x['before'])} → {_md_cell(x['now'])}" + (f" ({'+' if x['diff'] > 0 else ''}{_v(x['diff'])})" if x.get("diff") is not None else "")
                for x in c.get("changed") or []]
        out.append("")
    out.append(MD_BEGIN.replace("ds:", "/ds:"))
    return "\n".join(out) + "\n"


_NEXT_MD = re.compile(r"^## (?:\d+\. )?(?:What to do next|다음에 할 일)\s*$")


def add_to_report(rep: Dict[str, str], obs: Dict[str, Any], lang: str) -> Dict[str, str]:
    """The report with the section inserted after "What to do next" (nothing else changes)."""
    out = dict(rep)
    h = rep.get("html") or ""
    sec = section_html(obs, lang)
    anchor = '<section class="card" id="sec-method">'
    out["html"] = h.replace(anchor, sec + anchor, 1) if anchor in h else h.replace("</main>", sec + "</main>", 1)
    if 'href="#sec-method"' in out["html"]:
        out["html"] = out["html"].replace('<a href="#sec-method">', f'<a href="#{HTML_ID}">{E(_t(lang, "title"))}</a><a href="#sec-method">', 1)
    lines = (rep.get("md") or "").split("\n")
    idx = next((i for i, ln in enumerate(lines) if _NEXT_MD.match(ln)), None)
    ins = next((j for j in range(idx + 1, len(lines)) if lines[j].startswith("## ")), len(lines)) if idx is not None else len(lines)
    lines[ins:ins] = section_md(obs, lang).rstrip("\n").split("\n")
    out["md"] = "\n".join(lines)
    try:
        doc = json.loads(rep.get("json") or "{}")
        doc["additional_observation"] = {"note": W["desc"][0], **obs}
        out["json"] = json.dumps(doc, ensure_ascii=False, indent=2, default=str)
    except ValueError:
        pass
    return out


def strip_from_report(rep: Dict[str, str]) -> Dict[str, str]:
    """The inverse of ``add_to_report`` (used by the test that the rest of the report is unchanged)."""
    out = dict(rep)
    out["html"] = re.sub(re.escape(MARK_BEGIN) + ".*?" + re.escape(MARK_END), "", rep.get("html") or "", flags=re.S)
    out["html"] = re.sub(r'<a href="#' + HTML_ID + r'">[^<]*</a>', "", out["html"], count=1)
    md_end = MD_BEGIN.replace("ds:", "/ds:")
    out["md"] = re.sub(re.escape(MD_BEGIN) + ".*?" + re.escape(md_end) + "\n", "", rep.get("md") or "", flags=re.S)
    try:
        doc = json.loads(rep.get("json") or "{}")
        doc.pop("additional_observation", None)
        out["json"] = json.dumps(doc, ensure_ascii=False, indent=2, default=str)
    except ValueError:
        pass
    return out
