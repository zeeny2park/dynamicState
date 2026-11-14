"""The two reader-facing parts that tell how a diagnosis reached its verdict: the competing causes it considered
(per finding) and the time-ordered course of the investigation.

Both used to exist only inside the collapsed English detail records (section F and the engine timeline).  This
module builds them as plain data from what the report layer already has (the result, its inline report, the check
rows of ``human_report``), then renders that data three ways from one place: Markdown lines (the Markdown report),
an HTML fragment (the HTML report and the web UI view) and the data itself (result JSON).

Rendering only.  Nothing here decides anything about the diagnosis: outcomes are the verdicts the competing-hypothesis
candidates already carry (``CompetingHypothesis.status``, bound to the verified ``ExpertHypothesis`` through
``verdict_source``), the evidence is the check that ran, the times are the ones the engine recorded.  Reader-facing
output carries outcome words only, never a confidence figure.
"""

from __future__ import annotations

import html
import re
from typing import Any, Dict, List, Optional, Tuple

E = html.escape

# ------------------------------------------------------------------------------------------------ wording
_L: Dict[str, Tuple[str, str]] = {
    "cc_head": ("Other causes considered", "검토한 다른 원인"),
    "cc_cols": ("Cause|Outcome|What decided it", "원인|결과|결정 근거"),
    "cc_same": ("Same causes were considered as for finding {n}.", "발견 {n}과 같은 원인들을 검토했습니다."),
    "cc_more": ("{n} more causes", "원인 {n}개 더 보기"),
    "cc_note": ("Each cause is a different explanation of the same symptom; the outcome is what the checks that "
                "belong to it showed.", "각 원인은 같은 증상의 다른 설명이고, 결과는 그 원인에 딸린 검사가 보인 것입니다."),
    "o_supported": ("supported", "지지됨"), "o_ruled_out": ("ruled out", "배제됨"), "o_undecided": ("undecided", "판단 불가"),
    "ev_not_run": ("the related check was not run", "관련 검사가 실행되지 않음"),
    "ev_ran_undecided": ("the related check ran but could not decide ({why})", "관련 검사는 실행됐으나 결론을 내지 못함 ({why})"),
    "ev_ran_undecided_nw": ("the related check ran but could not decide", "관련 검사는 실행됐으나 결론을 내지 못함"),
    "ev_clean": ("no sign of it", "이 원인의 징후 없음"),
    "ev_found": ("problem found", "이상 발견"),
    "tl_head": ("Course of the diagnosis", "진행 순서"),
    "tl_note": ("In time order: how the symptom was read, the checks that ran (offset from the first check, duration), what "
                "they showed, the verdict.", "시간 순서입니다: 증상 해석, 실행한 검사(첫 검사로부터의 시각, 걸린 시간), 관찰한 것, 결론."),
    "tl_total": ("The whole diagnosis took {x}.", "진단 전체에 {x} 걸렸습니다."),
    "tl_symptom": ("Read the symptom: looking at {cat} first, {n} checks planned.",
                   "증상 해석: {cat}을(를) 먼저 확인하도록 검사 {n}개를 계획"),
    "tl_symptom_broad": ("Read the symptom: not specific, so a broad plan of {n} checks.",
                         "증상 해석: 구체적이지 않아 검사 {n}개의 넓은 계획"),
    "tl_nosymptom": ("No symptom given: {n} baseline checks planned.", "증상 없음: 기본 검사 {n}개를 계획"),
    "tl_obs": ("Observed: {x}", "관찰: {x}"),
    "tl_window": ("observed over {win}, {n} samples", "관측 구간 {win}, 표본 {n}회"),
    "tl_window_nn": ("observed over {win}", "관측 구간 {win}"),
    "tl_shared": ("same samples as the check before", "앞 검사와 같은 표본 사용"),
    "tl_group": ("{n} checks without a finding ({parts})", "이상을 찾지 못한 검사 {n}개 ({parts})"),
    "tl_part": ("{n} {w}", "{w} {n}개"),
    "tl_names_more": ("and {n} more (all are listed under Checks)", "외 {n}개 (모두 '검사'에 있음)"),
    "tl_undec_mark": ("{x} (could not judge)", "{x} (판단 불가)"),
    "tl_verdict": ("Verdict: {x}", "결론: {x}"),
    "tl_more": ("Show the {n} checks", "검사 {n}개 펼치기"),
    "tl_start": ("start", "시작"),
    "st_FAIL": ("problem found", "이상 발견"), "st_PASS": ("passed", "통과"), "st_INCONCLUSIVE": ("could not judge", "판단 불가"),
    "no_cat": ("the broad set of problems", "넓은 범위의 문제"),
}

# the candidate causes the competing-hypothesis model proposes, in plain words (English title -> Korean)
CAUSE_KO: Dict[str, str] = {
    "Unmanaged Heap Allocation Expansion": "해제되지 않는 힙 할당이 계속 늘어남",
    "Long-Lived Object Accumulation in Containers / Caches": "컨테이너·캐시에 오래 사는 객체가 쌓임",
    "Allocation and Deallocation Counter Imbalance": "할당 횟수가 해제 횟수보다 계속 많음",
    "Transient Initialization or Cache Warm-up Plateau": "초기화·캐시 워밍업 중의 일시적 증가",
    "Allocator Arena Fragmentation and Retention": "할당자가 조각난 메모리를 돌려주지 않음",
    "Dangling Pointer Dereference (Use-After-Free)": "해제된 메모리를 가리키는 포인터 사용",
    "Out-of-Bounds Heap Buffer Write": "힙 버퍼 범위를 넘어선 쓰기",
    "Duplicate Memory Release (Double Free)": "같은 메모리를 두 번 해제",
    "Unmapped / Wild Pointer Dereference": "매핑되지 않은 주소(엉뚱한 포인터) 접근",
    "Mutual Wait Cycle (Classic AB-BA or Multi-Thread Deadlock)": "스레드들이 서로 락을 기다리는 순환 교착",
    "Severe Lock Contention / Long-Holding Critical Section": "락을 오래 쥐고 있어 생기는 심한 경합",
    "Asymmetric Futex Wait Starvation or Missing Wakeup": "깨우기 신호가 빠져 한쪽이 계속 기다림",
    "Slow Forward Progress / Heavy Compute Loop Without Lock Deadlock": "락 문제 없이 계산이 느리게 진행됨",
    "Progressive Heap or Resource Exhaustion Leading to Crash": "힙·자원이 점점 고갈되어 종료됨",
    "Latent Heap Metadata or Use-After-Free Corruption Crash": "숨은 힙 메타데이터 손상으로 종료됨",
    "Concurrency Deadlock or Shared-State Race Triggering Failure": "교착 또는 공유 상태 경합이 실패를 일으킴",
    "Candidate Unbounded Memory Growth or Retention": "메모리가 한없이 늘거나 유지됨",
    "Candidate Memory Integrity or Allocator Metadata Violation": "메모리 무결성 또는 할당자 메타데이터 위반",
    "Candidate Thread Deadlock or Lock Contention": "스레드 교착 또는 락 경합",
}

_SUPPORTED = {"CONFIRMED", "LIKELY", "SUPPORTED", "OBSERVED", "CONFIRMED_ROOT_CAUSE", "PROBABLE_CAUSE"}
_RULED_OUT = {"REFUTED", "CONTRADICTED"}
_OUTCOME_ORDER = ("supported", "ruled_out", "undecided")
_OUTCOME_TONE = {"supported": "tone-warn", "ruled_out": "tone-pass", "undecided": "tone-skip"}
MAX_CAUSE_ROWS = 5            # shown at once; the rest sits behind a disclosure
MAX_GROUP_NAMES = 6           # a folded group names this many checks in the Markdown; the HTML lists them all
MAX_TIMELINE_STEPS = 8        # more steps than this: runs of clean checks collapse into one line


def _t(lang: str, key: str, **kw: Any) -> str:
    return _L[key][1 if lang == "ko" else 0].format(**kw)


def outcome_of(status: Any) -> str:
    s = str(status or "").upper()
    return "supported" if s in _SUPPORTED else "ruled_out" if s in _RULED_OUT else "undecided"


def _short(text: str, n: int = 110) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip().replace("|", "/")
    if len(text) <= n:
        return text
    cut = text[:n - 1].rstrip()
    return cut + ("`" if cut.count("`") % 2 else "") + "…"


_ENGLISH_RUN = re.compile(r"\b[A-Za-z]{3,}\s+[A-Za-z]{3,}\b")


def _untranslated(text: str) -> bool:
    """True when ``text`` (the report language's rendering of an engine sentence) still holds English prose: two
    plain English words in a row outside code spans and identifiers."""
    plain = re.sub(r"`[^`]*`|\S*[_./(>*\[]\S*", " ", text)
    return bool(_ENGLISH_RUN.search(plain))


def _check_text(lang: str, row: Dict[str, Any], otherwise: str = "") -> str:
    """One check as 'name: what it showed' (the engine's interpretation in the report language); without an
    interpretation, 'name: <otherwise>' (just the name when ``otherwise`` is empty)."""
    from .human_report import check_name, ko_text
    i = 1 if lang == "ko" else 0
    name = check_name(row["rid"], i, row.get("name"))
    interp = str(row.get("interp") or "")
    if interp and interp != "Check executed" and row.get("status") in ("FAIL", "PASS"):
        shown = ko_text(interp, i)
        if lang == "en" or not _untranslated(shown):    # an engine sentence the Korean table does not know stays out
            return f"{name}: {_short(shown)}"
    return f"{name}: {otherwise}" if otherwise else name


# ------------------------------------------------------------------------------------------------ competing causes
def _finding_domains(f: Dict[str, Any]) -> set:
    from .human_report import recipe_meta
    out = set()
    for rid in f.get("recipe_ids") or []:
        meta = recipe_meta(str(rid))
        if meta:
            out.add(meta[0])
    return out


def _belongs(cand: Dict[str, Any], f: Dict[str, Any], doms: set) -> bool:
    """A candidate cause is a candidate for a finding when it names the finding's category (or the category of the
    verified hypothesis it is bound to), shares one of the finding's checks, or lies in the domain of those checks."""
    cat = str(f.get("category") or "")
    vs = cand.get("verdict_source") if isinstance(cand.get("verdict_source"), dict) else {}
    if cat and cat in (str(cand.get("category") or ""), str(vs.get("category") or "")):
        return True
    if set(str(x) for x in cand.get("applicable_diagnostic_rules") or []) & set(str(x) for x in f.get("recipe_ids") or []):
        return True
    return bool(doms) and str(cand.get("domain") or "") in doms


def _cause_row(lang: str, cand: Dict[str, Any], by_rid: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    from .human_report import ko_text
    i = 1 if lang == "ko" else 0
    title = str(cand.get("title") or cand.get("hypothesis_id") or "")
    out = outcome_of(cand.get("status"))
    rows = [by_rid[str(r)] for r in cand.get("applicable_diagnostic_rules") or [] if str(r) in by_rid]
    ran = [r for r in rows if r.get("planned", True) and r["status"] in ("FAIL", "PASS", "INCONCLUSIVE")]
    pick: Optional[Dict[str, Any]] = None
    if out == "supported":
        pick = next((r for r in ran if r["status"] == "FAIL"), None)
    elif out == "ruled_out":
        pick = next((r for r in ran if r["status"] == "PASS"), None)
    if pick is not None:
        evidence = _check_text(lang, pick, _t(lang, "ev_clean") if out == "ruled_out" else _t(lang, "ev_found"))
        rid = pick["rid"]
    else:
        rid = None
        obs = (cand.get("supporting_observations") if out == "supported" else cand.get("contradicting_observations")) or []
        if out != "undecided" and obs and (lang == "en" or not _untranslated(ko_text(str(obs[0]), i))):
            evidence = _short(ko_text(str(obs[0]), i))
        elif out != "undecided" and ran:
            evidence = _check_text(lang, ran[0])
        elif ran:
            from .human_report import _Ctx, _undecided_reason
            why = _undecided_reason(_Ctx(lang), ran[0], {})
            evidence = _t(lang, "ev_ran_undecided", why=_short(why, 80)) if why else _t(lang, "ev_ran_undecided_nw")
        else:
            evidence = _t(lang, "ev_not_run")
    return {"id": str(cand.get("hypothesis_id") or ""), "cause": CAUSE_KO.get(title, title) if lang == "ko" else title,
            "title": title, "outcome": out, "outcome_word": _t(lang, "o_" + out), "evidence": evidence,
            "recipe_id": rid, "status": str(cand.get("status") or "")}


def competing_causes(lang: str, res: Dict[str, Any], report: Optional[Dict[str, Any]],
                     rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per finding, the candidate causes considered (>1 only): ``[{finding, category, same_as, causes}]`` in finding
    order.  A finding whose causes are the same set as an earlier finding's carries ``same_as`` and no list."""
    sec = (report or {}).get("section_f_competing_hypotheses") if isinstance(report, dict) else None
    cands = [c for c in ((sec or {}).get("competing_candidates") or []) if isinstance(c, dict)]
    findings = [f for f in (res.get("findings") or []) if isinstance(f, dict)]
    if not cands or not findings:
        return []
    by_rid = {r["rid"]: r for r in rows}
    out: List[Dict[str, Any]] = []
    seen: Dict[Tuple[str, ...], int] = {}
    for n, f in enumerate(findings, 1):
        doms = _finding_domains(f)
        mine = [c for c in cands if _belongs(c, f, doms)]
        if len(mine) < 2:
            continue
        key = tuple(sorted(str(c.get("hypothesis_id")) for c in mine))
        if key in seen:
            out.append({"finding": n, "category": str(f.get("category")), "same_as": seen[key], "causes": []})
            continue
        seen[key] = n
        causes = [_cause_row(lang, c, by_rid) for c in mine]
        causes.sort(key=lambda c: _OUTCOME_ORDER.index(c["outcome"]))
        out.append({"finding": n, "category": str(f.get("category")), "same_as": None, "causes": causes})
    return out


def competing_markdown(lang: str, item: Optional[Dict[str, Any]]) -> List[str]:
    """The block of one finding as Markdown lines (a small table); [] when there is none."""
    if not item:
        return []
    head = f"**{_t(lang, 'cc_head')}**"
    if item.get("same_as"):
        return [head, "", _t(lang, "cc_same", n=item["same_as"])]
    cols = _t(lang, "cc_cols").split("|")
    lines = [head, "", _t(lang, "cc_note"), "", "| " + " | ".join(cols) + " |", "|---|---|---|"]
    for c in item["causes"]:
        lines.append(f"| {c['cause'].replace('|', '/')} | **{c['outcome_word']}** | {c['evidence'].replace('|', '/')} |")
    return lines


def _cause_tr(c: Dict[str, Any]) -> str:
    return (f'<tr data-outcome="{E(c["outcome"])}"><td>{E(c["cause"])}</td>'
            f'<td><span class="badge badge-tone {_OUTCOME_TONE[c["outcome"]]}">{E(c["outcome_word"])}</span></td>'
            f'<td>{_ih(c["evidence"])}</td></tr>')


def competing_html(lang: str, item: Optional[Dict[str, Any]], finding_no: int) -> str:
    """The block of one finding as an HTML fragment (theme classes only); the rows beyond ``MAX_CAUSE_ROWS`` are
    behind a disclosure."""
    if not item:
        return ""
    head = f'<h4 class="dsv-sub">{E(_t(lang, "cc_head"))}</h4>'
    if item.get("same_as"):
        return (f'<div class="dsv-causes" id="finding-{finding_no}-causes">{head}'
                f'<p class="dsv-note">{E(_t(lang, "cc_same", n=item["same_as"]))}</p></div>')
    cols = "".join(f"<th>{E(x)}</th>" for x in _t(lang, "cc_cols").split("|"))
    causes = item["causes"]
    shown, rest = causes[:MAX_CAUSE_ROWS], causes[MAX_CAUSE_ROWS:]
    body = "".join(_cause_tr(c) for c in shown)
    more = ""
    if rest:
        more = (f'<details class="collapsible collapsible-plain dsv-more"><summary>{E(_t(lang, "cc_more", n=len(rest)))}</summary>'
                f'<table class="dsv-tbl dsv-cause-tbl"><tbody>{"".join(_cause_tr(c) for c in rest)}</tbody></table></details>')
    return (f'<div class="dsv-causes" id="finding-{finding_no}-causes">{head}'
            f'<p class="dsv-note">{E(_t(lang, "cc_note"))}</p>'
            f'<table class="dsv-tbl dsv-cause-tbl"><thead><tr>{cols}</tr></thead><tbody>{body}</tbody></table>{more}</div>')


# ------------------------------------------------------------------------------------------------ timeline
def _fmt_s(seconds: float, lang: str) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.1f}초" if lang == "ko" else f"{seconds:.1f} s"


def _fmt_off(seconds: float, lang: str) -> str:
    return "+" + _fmt_s(seconds, lang)


def _window_of(obs: Any) -> Optional[Dict[str, Any]]:
    """The observation window a sampling check recorded: seconds and sample count (None when it did not sample)."""
    if not isinstance(obs, dict):
        return None
    li = obs.get("leak_investigation") if isinstance(obs.get("leak_investigation"), dict) else {}
    ts = obs.get("thread_sampling") if isinstance(obs.get("thread_sampling"), dict) else {}
    mt = obs.get("memory_trend") if isinstance(obs.get("memory_trend"), dict) else {}
    for secs, n in ((li.get("window_s"), li.get("walks") or len(li.get("heap_walks") or []) or None),
                    (ts.get("window_sec"), ts.get("samples_collected")),
                    (mt.get("window_s"), mt.get("samples"))):
        if isinstance(secs, (int, float)) and not isinstance(secs, bool) and secs > 0:
            return {"seconds": round(float(secs), 3), "samples": int(n) if isinstance(n, (int, float)) else None}
    return None


def _check_records(report: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    from .human_report import _checks
    return {str(c.get("recipe_id")): c for c in _checks(report) if c.get("recipe_id")}


def build_timeline(lang: str, res: Dict[str, Any], report: Optional[Dict[str, Any]], rows: List[Dict[str, Any]],
                   renders: List[Dict[str, Any]], verdict_text: str, verdict: str) -> Dict[str, Any]:
    """The investigation as ordered steps: symptom reading, each check that ran, what the findings observed, the
    verdict.  ``t`` is the offset in seconds from the start of the first check (None when the engine recorded no
    times), ``dur`` the check's own duration.  When there are more than ``MAX_TIMELINE_STEPS`` steps, consecutive
    clean checks fold into one ``group`` step that keeps its items."""
    from .human_report import _Ctx, _cat_label, _one_line, check_label, check_name, _undecided_reason
    ctx = _Ctx(lang)
    i = ctx.i
    recs = _check_records(report)
    ran = [r for r in rows if r.get("planned", True) and r["status"] in ("FAIL", "PASS", "INCONCLUSIVE")]
    starts = {r["rid"]: recs[r["rid"]].get("monotonic_start") for r in ran if r["rid"] in recs}
    timed = bool(ran) and all(isinstance(starts.get(r["rid"]), (int, float)) for r in ran)
    if timed:
        ran.sort(key=lambda r: starts[r["rid"]])
        t0 = float(starts[ran[0]["rid"]])
    reasons: Dict[str, List[str]] = {}
    steps: List[Dict[str, Any]] = []

    si = res.get("symptom_interpretation") if isinstance(res.get("symptom_interpretation"), dict) else {}
    planned = sum(1 for r in rows if r.get("planned", True))
    if si:
        cat = str(si.get("primary_category") or "")
        if si.get("understood", True) and not si.get("broad_plan") and cat:
            text = _t(lang, "tl_symptom", cat=_cat_label(ctx, cat), n=planned)
        else:
            text = _t(lang, "tl_symptom_broad", n=planned)
    else:
        text = _t(lang, "tl_nosymptom", n=planned)
    steps.append({"kind": "symptom", "t": 0.0 if timed else None, "dur": None, "text": text, "status": None})

    seen_windows: List[Tuple[float, Optional[int]]] = []
    end = 0.0
    for r in ran:
        rec = recs.get(r["rid"], {})
        dur = r.get("dur")
        dur = float(dur) if isinstance(dur, (int, float)) and not isinstance(dur, bool) else None
        line = _check_text(lang, r)
        if r["status"] == "INCONCLUSIVE":
            why = _undecided_reason(ctx, r, reasons)
            line = f"{line}: {_short(why, 90)}" if why else line
        step: Dict[str, Any] = {"kind": "check", "rid": r["rid"], "status": r["status"], "dur": dur, "text": line,
                                "label": check_label(r["rid"], i, r.get("name")), "name": check_name(r["rid"], i, r.get("name")), "window": None,
                                "t": round(float(starts[r["rid"]]) - t0, 3) if timed else None}
        win = _window_of(rec.get("actual_observations"))
        if win:
            key = (win["seconds"], win["samples"])
            win["shared"] = key in seen_windows
            seen_windows.append(key)
            step["window"] = win
        if timed:
            end = max(end, (step["t"] or 0.0) + (dur or 0.0))
        steps.append(step)
    for f, rend in zip([f for f in (res.get("findings") or []) if isinstance(f, dict)], renders):
        try:
            one = _one_line(ctx, f, rend)
        except Exception:  # noqa: BLE001 - a missing sentence never prevents the report
            continue
        steps.append({"kind": "observation", "t": round(end, 3) if timed else None, "dur": None,
                      "text": _t(lang, "tl_obs", x=_short(one, 160)), "status": "FAIL"})
    steps.append({"kind": "verdict", "t": round(end, 3) if timed else None, "dur": None,
                  "text": _t(lang, "tl_verdict", x=verdict_text), "status": None, "verdict": verdict})

    folded = False
    if len(steps) > MAX_TIMELINE_STEPS:
        folded_steps: List[Dict[str, Any]] = []
        run: List[Dict[str, Any]] = []

        def flush() -> None:
            if len(run) >= 2:
                last = run[-1]
                counts = [(st, sum(1 for x in run if x["status"] == st)) for st in ("PASS", "INCONCLUSIVE")]
                parts = ", ".join(_t(lang, "tl_part", n=n, w=_t(lang, "st_" + st)) for st, n in counts if n)
                undecided = any(x["status"] == "INCONCLUSIVE" for x in run)
                folded_steps.append({"kind": "group", "status": "INCONCLUSIVE" if undecided else "PASS",
                                     "t": run[0]["t"], "dur": None, "items": list(run),
                                     "text": _t(lang, "tl_group", n=len(run), parts=parts),
                                     "names": [_t(lang, "tl_undec_mark", x=x["name"]) if x["status"] == "INCONCLUSIVE"
                                               else x["name"] for x in run],
                                     "end": (round(last["t"] + (last["dur"] or 0.0), 3) if last["t"] is not None else None)})
            else:
                folded_steps.extend(run)
            run.clear()
        for s in steps:
            if s["kind"] == "check" and s["status"] in ("PASS", "INCONCLUSIVE"):
                run.append(s)
                continue
            flush()
            folded_steps.append(s)
        flush()
        folded = any(s["kind"] == "group" for s in folded_steps)
        steps = folded_steps
    total = res.get("duration_s")
    return {"steps": steps, "timed": timed, "folded": folded,
            "total_s": float(total) if isinstance(total, (int, float)) and not isinstance(total, bool) and total > 0 else None}


def _window_text(lang: str, win: Dict[str, Any]) -> str:
    w = _fmt_s(win["seconds"], lang)
    s = _t(lang, "tl_window", win=w, n=win["samples"]) if win.get("samples") else _t(lang, "tl_window_nn", win=w)
    return s + (f", {_t(lang, 'tl_shared')}" if win.get("shared") else "")


def _step_line(lang: str, s: Dict[str, Any]) -> str:
    """One step as a Markdown list item."""
    when = f"`{_fmt_off(s['t'], lang)}` " if s.get("t") is not None else ""
    if s["kind"] == "group":
        if s.get("t") is not None and s.get("end") is not None and _fmt_off(s["t"], lang) != _fmt_off(s["end"], lang):
            when = f"`{_fmt_off(s['t'], lang)} ~ {_fmt_off(s['end'], lang)}` "
        shown = s["names"][:MAX_GROUP_NAMES]
        more = ", " + _t(lang, "tl_names_more", n=len(s["names"]) - len(shown)) if len(s["names"]) > len(shown) else ""
        return f"- {when}{s['text']}: " + ", ".join(shown) + more
    st = f"**{_t(lang, 'st_' + s['status'])}** " if s["kind"] == "check" else ""
    tail = []
    if s.get("dur") is not None:
        tail.append(_fmt_s(s["dur"], lang))
    if s.get("window"):
        tail.append(_window_text(lang, s["window"]))
    return f"- {when}{st}{s['text']}" + (f" ({'; '.join(tail)})" if tail else "")


def timeline_markdown(lang: str, tl: Optional[Dict[str, Any]]) -> List[str]:
    if not tl or not tl.get("steps"):
        return []
    out = [f"### {_t(lang, 'tl_head')}", "", _t(lang, "tl_note"), ""]
    out += [_step_line(lang, s) for s in tl["steps"]]
    if tl.get("total_s"):
        out += ["", _t(lang, "tl_total", x=_fmt_s(tl["total_s"], lang))]
    return out


def _ih(text: str) -> str:
    from .human_report import _inline_html
    return _inline_html(text)


def _li(lang: str, s: Dict[str, Any], inner_group: str = "") -> str:
    when = _fmt_off(s["t"], lang) if s.get("t") is not None else ""
    if s["kind"] == "group":
        end = (f"~ {_fmt_off(s['end'], lang)}" if s.get("end") is not None and s.get("t") is not None
               and _fmt_off(s["t"], lang) != _fmt_off(s["end"], lang) else "")
        items = "".join(_li(lang, x) for x in s["items"])
        return (f'<li class="dsv-tl-group" data-kind="group"><span class="dsv-tl-t">{E(when)}</span>'
                + ('<span class="dsv-tl-ic tone-warn" aria-hidden="true">?</span>'
                   if s.get("status") == "INCONCLUSIVE" else
                   '<span class="dsv-tl-ic tone-pass" aria-hidden="true">✔</span>')
                + f'<div class="dsv-tl-b">'
                f'<details class="collapsible collapsible-plain"><summary>{E(s["text"])} <small>{E(end)}</small></summary>'
                f'<ol class="dsv-tl dsv-tl-in">{items}</ol></details></div></li>')
    icon = {"FAIL": ("✖", "FAIL", "tone-fail"), "PASS": ("✔", "PASS", "tone-pass"),
            "INCONCLUSIVE": ("?", "INCONCLUSIVE", "tone-warn")}.get(s.get("status") or "")
    mark = (f'<span class="dsv-tl-ic {icon[2]}" aria-hidden="true">{icon[0]}</span>' if icon
            else '<span class="dsv-tl-dot" aria-hidden="true"></span>')
    tail = []
    if s.get("dur") is not None:
        tail.append(_fmt_s(s["dur"], lang))
    if s.get("window"):
        tail.append(_window_text(lang, s["window"]))
    return (f'<li data-kind="{E(s["kind"])}"{(" data-tone=" + chr(34) + s["status"] + chr(34)) if s.get("status") else ""}>'
            f'<span class="dsv-tl-t">{E(when)}</span>{mark}<div class="dsv-tl-b">{_ih(s["text"])}'
            + (f' <small>({E("; ".join(tail))})</small>' if tail else "") + "</div></li>")


def timeline_html(lang: str, tl: Optional[Dict[str, Any]]) -> str:
    """The timeline as an HTML fragment (an ordered list; clean-check runs are collapsed in their own disclosure)."""
    if not tl or not tl.get("steps"):
        return ""
    total = f'<p class="dsv-note">{E(_t(lang, "tl_total", x=_fmt_s(tl["total_s"], lang)))}</p>' if tl.get("total_s") else ""
    return (f'<div class="dsv-timeline" id="dsv-timeline"><h3 class="ckhead">{E(_t(lang, "tl_head"))}</h3>'
            f'<p class="dsv-note">{E(_t(lang, "tl_note"))}</p>'
            f'<ol class="dsv-tl">{"".join(_li(lang, s) for s in tl["steps"])}</ol>{total}</div>')
