"""The detail fragments of the job-bound read routes (``extractor/web/explore.py``), ko and en, built on the server.

Each ``*_fragment(lang, data)`` returns inert HTML: every string that comes from the target (thread and symbol names,
values read from its memory, paths) is escaped, there is no script, no event-handler attribute and no URL.  Buttons
declare what they do with ``data-act``; the UI's one click handler acts on them.  ``both(fn, data)`` gives
``{"ko": ..., "en": ...}`` so the UI switches language without a round trip.
"""
from __future__ import annotations

import html
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from extractor.web.ui.explore_view import Lx, key, row_btn, slot

E = html.escape
LANGS = ("ko", "en")

# (en, ko)
F: Dict[str, Tuple[str, str]] = {
    "stack_h": ("Call stack", "호출 스택"), "locals_h": ("Locals", "지역 변수"), "locks_h": ("Locks", "락"),
    "no_locals": ("This frame has no locals.", "이 프레임에는 지역 변수가 없습니다."),
    "no_locals_sym": ("No locals: {m} has symbols only.", "지역 변수 없음: {m} 은(는) 심볼만 있습니다."),
    "no_locals_dbg": ("No locals: without debug info the frame layout is unknown.", "지역 변수 없음: 디버그 정보가 없어 프레임 배치를 모릅니다."),
    "no_locals_est": ("No locals: this frame was estimated, its frame base is not known.",
                      "지역 변수 없음: 추정한 프레임이라 프레임 기준 주소를 모릅니다."),
    "holds": ("holds ", "잡고 있음 "), "waits": ("waits for ", "기다림 "), "owner": (" (owner {x})", " (소유자 {x})"),
    "read_stack": ("read {t} · stack once, no thread stopped (registers via /proc/pid/task/tid/syscall, stack via process_vm_readv) · {c}",
                   "읽음 {t} · 스택 1회, 스레드 정지 없음 (레지스터는 /proc/pid/task/tid/syscall, 스택은 process_vm_readv) · {c}"),
    "read_once": ("read {t} · {c}", "읽음 {t} · {c}"),
    "cost": ("{r} reads, {b}, {ms} ms, target stop 0 ms", "읽기 {r}회, {b}, {ms} ms, 대상 정지 0 ms"),
    "cost0": ("no target memory read, target stop 0 ms", "대상 메모리 읽기 없음, 대상 정지 0 ms"),
    "est": ("estimated", "추정"),
    "grp_note": ("Locals may differ per member; open a member to read it.", "구성원마다 지역 변수 값은 다를 수 있습니다. 구성원을 눌러 개별로 읽으세요."),
    "members_h": ("Members {n}", "구성원 {n}"), "members_more": ("{n} more (50 at a time)", "{n}개 더 (50개씩)"),
    "members_note": ("list from /proc/pid/task (by name) · stacks read on open", "목록은 /proc/pid/task (이름으로) · 스택은 누를 때 읽음"),
    "tid_filter": ("filter by tid", "tid로 거르기"),
    "lk_owner": ("owner", "소유자"), "lk_waiter": ("waiter", "대기"), "lk_thread": ("thread", "스레드"),
    "lk_at": ("stopped at", "멈춘 곳"), "lk_top": ("top frame", "맨 위 프레임"),
    "lk_words": ("{n} @ {a} · __lock = {w}{x} · __owner = {o}", "{n} @ {a} · __lock = {w}{x} · __owner = {o}"),
    "lk_locked_w": ("  (locked, has waiters)", "  (잠김, 대기자 있음)"), "lk_watch": ("Watch owner", "소유자 추적"),
    "m_start": ("start", "시작"), "m_end": ("end", "끝"), "m_perm": ("perm", "권한"), "m_size": ("size", "크기"),
    "m_kind": ("kind · path", "종류 · 경로"), "m_read": ("Read", "범위 읽기"),
    "m_more": ("{n} more mappings not shown", "그 밖의 매핑 {n}개는 보이지 않음"),
    "r_line": ("{a} … {b} · {n} B · read once {t} (one read, no stop) · {c}",
               "{a} … {b} · {n} B · 한 번 읽음 {t} (읽기 1회, 대상 정지 없음) · {c}"),
    "r_typed_h": ("Typed decode (DWARF{heap})", "형식 해석 (DWARF{heap})"), "r_heap": (" + glibc heap layout", " + glibc 힙 배치"),
    "r_raw_h": ("Raw decode (no type information)", "원시 해석 (형식 정보 없음)"),
    "r_partial": ("Only part of the range could be read: {e}", "범위의 일부만 읽을 수 있었습니다: {e}"),
    "r_unmapped": ("Nothing could be read at this address: {e}", "이 주소에서는 아무것도 읽을 수 없었습니다: {e}"),
    "r_hdr": ("chunk header", "청크 헤더"), "r_buf": ("buffer (usable)", "버퍼 (사용 가능 영역)"),
    "r_over": ("written past the end", "버퍼 끝을 넘은 쓰기"), "r_victim": ("next chunk's header", "다음 청크 헤더"),
    "r_in_var": ("{n} + {o} ({t})", "{n} + {o} ({t})"),
    "r_ptr": ("pointer candidate", "포인터 후보"), "r_text": ("as text", "문자로"),
    "r_prev": ("← previous {n} B", "← 이전 {n} B"), "r_next": ("next {n} B →", "다음 {n} B →"),
    "f_fd": ("fd", "fd"), "f_kind": ("kind", "종류"), "f_target": ("target", "대상"),
    "f_more": ("{n} more not shown", "{n}개 더 있음 (보이지 않음)"),
    "mod_name": ("module", "모듈"), "mo_base": ("base", "기준 주소"), "mo_debug": ("debug info", "디버그 정보"),
    "dbg_dwarf": ("DWARF", "DWARF"), "dbg_symbols": ("symbols only", "심볼만"), "dbg_none2": ("none", "없음"),
    "dbg_unknown": ("unknown", "모름"),
    "v_name": ("name", "이름"), "v_type": ("type", "형식"), "v_size": ("size", "크기"), "v_where": ("where", "위치"),
    "v_show": ("Show value", "값 보기"), "v_track": ("Add to watch", "추적에 추가"), "v_pool": ("View as pool", "풀로 보기"),
    "v_pool_cap": ("first {n} of {total} elements (the per-sample read budget does not cover more)",
                   "원소 {total}개 중 앞의 {n}개 (표본 읽기 한도 때문에 더는 못 봅니다)"),
    "v_static": ("static", "정적"), "v_global": ("global", "전역"),
    "v_none": ("This executable has no globals or statics with that name.", "이 실행 파일에는 그런 이름의 전역·정적 변수가 없습니다."),
    "val_h": ("Value", "값"), "val_read": ("read {t} · {s} B once · {c}", "읽음 {t} · {s} B 1회 · {c}"),
    "val_follow": ("follow →", "따라가기 →"),
    "val_fail": ("Could not read {e}: {m}", "{e} 을(를) 읽지 못했습니다: {m}"),
    "val_more": ("… {n} more elements", "… {n}개 더"),
    "err_TARGET_EXITED": ("The target is gone: {m}. Values read before stay on screen.",
                          "대상이 종료되었습니다: {m}. 앞서 읽은 값은 그대로 남습니다."),
    "err_RATE_LIMITED": ("Too many reads in a short time; try again in a moment.", "짧은 시간에 읽기가 너무 많습니다. 잠시 뒤 다시 시도하세요."),
    "err_NO_DEBUG_INFO": ("No debug information for this target: {m}.", "이 대상에는 디버그 정보가 없습니다: {m}."),
    "err_NOT_FOUND": ("Not found: {m}.", "찾을 수 없습니다: {m}."), "err_INVALID_PARAM": ("Check the input: {m}.", "입력을 확인하세요: {m}."),
    "err_UNSUPPORTED_REMOTE": ("Not available for a remote target: {m}.", "원격 대상에서는 볼 수 없습니다: {m}."),
    "err_BUDGET": ("Over the observation's read budget: {m}.", "관찰의 읽기 한도를 넘습니다: {m}."),
    "err_generic": ("The read failed: {m}.", "읽기에 실패했습니다: {m}."),
    "ch_lbl": ("Related", "관련 정보"), "ch_thread": ("thread", "스레드"), "ch_lock": ("lock", "락"), "ch_range": ("range", "범위"),
    "ch_watch": ("watch", "추적"), "ch_value": ("value", "값"), "ch_mem": ("memory", "주변 메모리"), "ch_profile": ("profile", "프로필"),
    "ch_around": ("memory around {x}", "{x} 주변 메모리"),
}


def t(lang: str, k: str, **kw: Any) -> str:
    s = F[k][1 if lang == "ko" else 0]
    return s.format(**kw) if kw else s


def clock(iso: Optional[str]) -> str:
    """HH:MM:SS of an ISO timestamp in this host's local time."""
    try:
        return datetime.fromisoformat(str(iso)).astimezone().strftime("%H:%M:%S")
    except (TypeError, ValueError):
        return "—"


def _bytes(n: Any) -> str:
    from extractor.human_report import fmt_bytes
    return fmt_bytes(int(n or 0))


def cost_text(lang: str, c: Optional[Dict[str, Any]]) -> str:
    c = c or {}
    if not c.get("reads") and not c.get("bytes"):
        return t(lang, "cost0")
    return t(lang, "cost", r=c.get("reads", 0), b=_bytes(c.get("bytes")), ms=c.get("ms", 0))


def error_fragment(lang: str, code: str, message: str) -> str:
    k = f"err_{code}" if f"err_{code}" in F else "err_generic"
    tone = "warn" if code in ("RATE_LIMITED", "NO_DEBUG_INFO", "UNSUPPORTED_REMOTE", "NOT_FOUND", "INVALID_PARAM", "BUDGET") else "fail"
    return f'<div class="alert alert-tone tone-{tone}" role="alert">{E(t(lang, k, m=message))}</div>'


def both(fn: Callable[..., str], *a: Any, **kw: Any) -> Dict[str, str]:
    return {lang: fn(lang, *a, **kw) for lang in LANGS}


def val(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return f"{v:g}"
    return str(v)


def _note(lang: str, d: Dict[str, Any], k: str = "read_once") -> str:
    return f'<p class="dt-note">{E(t(lang, k, t=clock((d.get("cost") or {}).get("at")), c=cost_text(lang, d.get("cost"))))}</p>'


# ------------------------------------------------------------------------------------------------ threads
def thread_fragment(lang: str, d: Dict[str, Any]) -> str:
    """A thread's stack (frames are buttons), one hidden locals panel per frame (the UI shows the selected one) and the
    locks it holds or waits for (buttons that open the lock row)."""
    tid = int(d["tid"])
    k = key("th", tid)
    stack, panels = [], []
    for f in d.get("frames") or []:
        i = int(f["i"])
        loc = f.get("loc") or f.get("module") or ""
        fn = str(f.get("fn") or "?")
        est = f' <span class="dt-note">({E(t(lang, "est"))})</span>' if f.get("estimated") else ""
        stack.append(f'<li class="{"est" if f.get("estimated") else ""}"><button type="button" data-act="frame" data-k="{k}" data-i="{i}" '
                     f'data-fn="{E(fn)}" aria-current="false"><span class="i">#{i}</span><span class="fn">{E(fn)}{est}</span>'
                     f'<span class="loc">{E(str(loc))}</span></button></li>')
        vs = list(f.get("params") or []) + list(f.get("locals") or [])
        if vs:
            body = '<dl class="locals">' + "".join(
                f'<dt>{E(str(p.get("name") or "?"))}</dt><dd class="ty">{E(str(p.get("type_name") or ""))}</dd>'
                f'<dd>{E(val(p.get("value"))) if p.get("value") is not None else "—"}</dd>' for p in vs) + "</dl>"
        elif not d.get("has_dwarf"):
            body = f'<p class="dt-note">{E(t(lang, "no_locals_dbg"))}</p>'
        elif f.get("estimated"):
            body = f'<p class="dt-note">{E(t(lang, "no_locals_est"))}</p>'
        elif f.get("loc"):
            body = f'<p class="dt-note">{E(t(lang, "no_locals"))}</p>'
        else:
            body = f'<p class="dt-note">{E(t(lang, "no_locals_sym", m=str(f.get("module") or "?")))}</p>'
        panels.append(f'<div class="fr-loc" data-fr="{i}" hidden><h4 style="margin-top:0">{E(t(lang, "locals_h"))} · '
                      f'<span class="mono">#{i} {E(fn)}</span></h4>{body}</div>')
    locks = ""
    if d.get("holds") or d.get("waits"):
        li = []
        for h in d.get("holds") or []:
            n = str(h.get("name") or h.get("address") or "?")
            li.append(f'<li>{E(t(lang, "holds"))}<button type="button" class="btn btn-ghost btn-sm" data-act="goto-lock" '
                      f'data-name="{E(key(n))}"><code>{E(n)}</code></button></li>')
        w = d.get("waits")
        if w:
            n = str(w.get("name") or w.get("address") or "?")
            own = f'{w.get("owner_name") or ""} {w.get("owner_tid") or ""}'.strip()
            li.append(f'<li>{E(t(lang, "waits"))}<button type="button" class="btn btn-ghost btn-sm" data-act="goto-lock" '
                      f'data-name="{E(key(n))}"><code>{E(n)}</code></button>{E(t(lang, "owner", x=own)) if own else ""}</li>')
        locks = f'<h4>{E(t(lang, "locks_h"))}</h4><ul class="ul">{"".join(li)}</ul>'
    return (f'<div class="split"><div><h4 style="margin-top:0">{E(t(lang, "stack_h"))}</h4><ol class="stack" aria-label="{E(t(lang, "stack_h"))}">'
            f'{"".join(stack)}</ol></div><div>{"".join(panels)}{locks}</div></div>{_note(lang, d, "read_stack")}')


def members_fragment(lang: str, d: Dict[str, Any], limit: int, flt: str = "") -> str:
    """The members of a thread group as a grid of rows (each opens its own stack in place), ``limit`` at a time."""
    name = str(d.get("name") or "")
    mem = [m for m in d.get("members") or [] if not flt or flt in str(m["tid"])]
    shown = mem[:limit]
    cells = "".join(row_btn(key("th", m["tid"]), f'<span class="n">{int(m["tid"])}</span><span class="st">{E(str(m.get("state") or ""))}</span>')
                    for m in shown)
    opened = "".join(slot(key("th", m["tid"])) for m in shown)
    more = len(mem) - len(shown)
    out = (f'<p class="dt-note">{E(t(lang, "grp_note"))}</p><h4>{E(t(lang, "members_h", n=len(d.get("members") or [])))}</h4>'
           f'<div class="search"><input class="input mono addr" id="mf-{E(key(name))}" data-act="mfilter" data-name="{E(name)}" '
           f'value="{E(flt)}" placeholder="{E(t(lang, "tid_filter"))}" aria-label="tid" autocomplete="off"></div>'
           f'<div class="mem-grid">{cells}</div>{opened}<div class="dt-actions">')
    if more > 0:
        out += f'<button type="button" class="btn btn-outline btn-sm" data-act="more" data-name="{E(name)}">{E(t(lang, "members_more", n=more))}</button>'
    return out + f'<span class="dt-note">{E(t(lang, "members_note"))}</span></div>'


def lock_fragment(lang: str, d: Dict[str, Any]) -> str:
    def who(w: Optional[Dict[str, Any]], role: str) -> str:
        if not w:
            return ""
        tid = int(w.get("tid") or 0)
        at = " · ".join(x for x in (str(w.get("at") or ""), str(w.get("loc") or "")) if x)
        return (f'<tr><td>{E(t(lang, role))}</td><td><button type="button" class="lnk" data-act="goto-thread" data-tid="{tid}">'
                f'{E(str(w.get("name") or "?"))} {tid}</button></td><td class="mono">{E(at)}</td><td class="mono">{E(str(w.get("top") or ""))}</td></tr>')
    rows = who(d.get("owner"), "lk_owner") + "".join(who(w, "lk_waiter") for w in d.get("waiters") or [])
    words = t(lang, "lk_words", n=str(d.get("name")), a=str(d.get("addr") or "?"), w=val(d.get("lock_word")),
              x=t(lang, "lk_locked_w") if d.get("lock_word") == 2 else "", o=val(d.get("owner_tid") or 0))
    btn = ""
    if d.get("owner_expr"):
        btn = (f'<div class="dt-actions"><button type="button" class="btn btn-outline btn-sm" data-act="track" '
               f'data-expr="{E(d["owner_expr"])}">{E(t(lang, "lk_watch"))}</button></div>')
    return (f'<div class="scroll-x"><table class="table compact"><thead><tr><th></th><th>{E(t(lang, "lk_thread"))}</th>'
            f'<th>{E(t(lang, "lk_at"))}</th><th>{E(t(lang, "lk_top"))}</th></tr></thead><tbody>{rows}</tbody></table></div>'
            f'<p class="dt-note mono">{E(words)}</p>{btn}{_note(lang, d)}')


# ------------------------------------------------------------------------------------------------ memory
_KIND_CLASS = {"heap": 1, "stack": 2, "anonymous": 3, "code": 4, "file": 5, "data": 5}


def maps_fragment(lang: str, d: Dict[str, Any], limit: int = 120) -> str:
    maps = d.get("maps") or []
    rows = []
    for m in maps[:limit]:
        btn = (f'<button type="button" class="btn btn-outline btn-sm" data-act="map-read" data-addr="{E(str(m.get("start")))}">'
               f'{E(t(lang, "m_read"))}</button>') if m.get("readable") else ""
        path = (" · " + E(str(m.get("path")))) if m.get("path") else ""
        rows.append(f'<tr><td class="mono">{E(str(m.get("start")))}</td><td class="mono">{E(str(m.get("end")))}</td>'
                    f'<td class="mono">{E(str(m.get("perm") or ""))}</td><td class="num">{E(_bytes(m.get("size")))}</td>'
                    f'<td><span class="legend" style="display:inline"><i class="m{_KIND_CLASS.get(str(m.get("kind")), 0)}"></i></span>'
                    f'<span class="mono">{E(str(m.get("kind") or ""))}{path}</span></td><td>{btn}</td></tr>')
    if len(maps) > limit:
        rows.append(f'<tr><td colspan="6" class="dt-note">{E(t(lang, "m_more", n=len(maps) - limit))}</td></tr>')
    return (f'<div class="scroll-x"><table class="table compact"><thead><tr><th>{E(t(lang, "m_start"))}</th><th>{E(t(lang, "m_end"))}</th>'
            f'<th>{E(t(lang, "m_perm"))}</th><th class="num">{E(t(lang, "m_size"))}</th><th>{E(t(lang, "m_kind"))}</th><th></th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>{_note(lang, d)}')


_MARK_LABEL = {"b-hdr": "r_hdr", "b-buf": "r_buf", "b-over": "r_over"}


def range_fragment(lang: str, d: Dict[str, Any]) -> str:
    """Hex + ASCII of one read, with the heap layout the diagnosis found marked, then a typed or a raw decode."""
    addr, n = int(d["addr"]), int(d["len"])
    b = bytes.fromhex(d.get("bytes") or "")
    marks = d.get("marks") or []

    def cls(a: int) -> str:
        for m in marks:
            if m["from"] <= a < m["to"]:
                return m["cls"]
        return ""

    rows = []
    for off in range(0, len(b), 16):
        cells = []
        for j in range(off, min(off + 16, len(b))):
            c = cls(addr + j)
            cells.append(f'<span class="{c}">{b[j]:02x}</span>' if c else f"<span>{b[j]:02x}</span>")
        text = "".join(chr(x) if 32 <= x < 127 else "." for x in b[off:off + 16])
        tags = " · ".join(t(lang, m["label"]) for m in marks if addr + off <= m["from"] < addr + off + 16 and m.get("label") in F)
        rows.append(f'<div class="r"><span class="o">0x{addr + off:x}</span><span class="bs">{"".join(cells)}</span>'
                    f'<span class="as">{E(text)}</span><span class="tag">{E(tags)}</span></div>')
    out = ""
    st = d.get("status")
    if st == "PARTIAL":
        out += f'<div class="alert alert-tone tone-warn" role="status">{E(t(lang, "r_partial", e=str(d.get("error") or "")))}</div>'
    elif st != "OBSERVED":
        out += f'<div class="alert alert-tone tone-fail" role="alert">{E(t(lang, "r_unmapped", e=str(d.get("error") or st or "")))}</div>'
    out += (f'<p class="dt-note">{E(t(lang, "r_line", a=f"0x{addr:x}", b=f"0x{addr + n:x}", n=n, t=clock((d.get("cost") or {}).get("at")), c=cost_text(lang, d.get("cost"))))}</p>')
    if rows:
        out += f'<div class="hex" role="table" aria-label="memory range">{"".join(rows)}</div>'
    used = []
    for m in marks:
        if m["cls"] in _MARK_LABEL and m["cls"] not in used:
            used.append(m["cls"])
    if used:
        out += '<div class="legend">' + "".join(f'<span><i class="{c}"></i>{E(t(lang, _MARK_LABEL[c]))}</span>' for c in used) + "</div>"
    dec = d.get("decode") or {}
    typed = dec.get("typed")
    trs = []
    if typed:
        trs.append(f'<tr><td class="mono">0x{addr:x}</td><td class="mono">{E(str(typed.get("name")))}</td>'
                   f'<td>{E(t(lang, "r_in_var", n=str(typed.get("name")), o=typed.get("offset", 0), t=str(typed.get("type") or "")))}</td></tr>')
    for m in marks:
        if m.get("note"):
            hot = ' class="hot"' if m["cls"] == "b-over" else ""
            bad = ' style="color:var(--destructive)"' if m["cls"] == "b-over" else ""
            trs.append(f'<tr{hot}><td class="mono">0x{m["from"]:x}</td><td class="mono">{E(t(lang, m["label"]))}</td><td{bad}>{E(str(m["note"]))}</td></tr>')
    if trs:
        out += (f'<h4>{E(t(lang, "r_typed_h", heap=t(lang, "r_heap") if marks else ""))}</h4><div class="scroll-x"><table class="table compact">'
                f'<tbody>{"".join(trs)}</tbody></table></div>')
    raw = dec.get("raw") or []
    if raw and not trs:
        rr = []
        for r in raw:
            ptr = f' · {t(lang, "r_ptr")}' if r.get("ptr") else ""
            rr.append(f'<tr><td class="mono">+{int(r["off"])}</td><td class="mono">u64 0x{int(r["u64"]):x}{E(ptr)}</td>'
                      f'<td class="mono">u32 {int(r["u32"][0])}, {int(r["u32"][1])}</td></tr>')
        out += (f'<h4>{E(t(lang, "r_raw_h"))}</h4><div class="scroll-x"><table class="table compact"><tbody>{"".join(rr)}'
                f'<tr><td class="mono">{E(t(lang, "r_text"))}</td><td class="mono" colspan="2">{E(str(dec.get("text") or ""))}</td></tr></tbody></table></div>')
    return out + (f'<div class="dt-actions"><button type="button" class="btn btn-ghost btn-sm" data-act="range-step" data-addr="0x{max(1, addr - n):x}" data-len="{n}">'
                  f'{E(t(lang, "r_prev", n=n))}</button><button type="button" class="btn btn-ghost btn-sm" data-act="range-step" '
                  f'data-addr="0x{addr + n:x}" data-len="{n}">{E(t(lang, "r_next", n=n))}</button></div>')


def files_fragment(lang: str, d: Dict[str, Any]) -> str:
    rows = "".join(f'<tr><td class="mono">{int(f["fd"])}</td><td>{E(str(f.get("kind")))}</td><td class="mono">{E(str(f.get("target")))}</td></tr>'
                   for f in d.get("fds") or [])
    more = int(d.get("total") or 0) - len(d.get("fds") or [])
    return (f'<div class="scroll-x"><table class="table compact"><thead><tr><th>{E(t(lang, "f_fd"))}</th><th>{E(t(lang, "f_kind"))}</th>'
            f'<th>{E(t(lang, "f_target"))}</th></tr></thead><tbody>{rows}</tbody></table></div>'
            + (f'<p class="dt-note">{E(t(lang, "f_more", n=more))}</p>' if more > 0 else "") + _note(lang, d))


def modules_fragment(lang: str, d: Dict[str, Any]) -> str:
    dbg = {"dwarf": "dbg_dwarf", "symbols": "dbg_symbols", "none": "dbg_none2"}
    rows = "".join(f'<tr><td class="mono">{E(str(m.get("name")))}</td><td class="mono">{E(str(m.get("base")))}</td>'
                   f'<td>{E(t(lang, dbg.get(str(m.get("debug")), "dbg_unknown")))}</td></tr>' for m in d.get("modules") or [])
    return (f'<div class="scroll-x"><table class="table compact"><thead><tr><th>{E(t(lang, "mod_name"))}</th><th>{E(t(lang, "mo_base"))}</th>'
            f'<th>{E(t(lang, "mo_debug"))}</th></tr></thead><tbody>{rows}</tbody></table></div>{_note(lang, d)}')


# ------------------------------------------------------------------------------------------------ variables
def vars_fragment(lang: str, d: Dict[str, Any]) -> str:
    vs = d.get("vars") or []
    if not vs:
        return f'<p class="dt-note">{E(t(lang, "v_none"))}</p>'
    rows = []
    for v in vs:
        name = str(v.get("name"))
        k = key("var", name)
        acts = f'<button type="button" class="btn btn-outline btn-sm" data-act="tog" data-key="{E(k)}" aria-expanded="false">{E(t(lang, "v_show"))}</button> '
        if v.get("pool"):
            p = v["pool"]
            acts += (f'<button type="button" class="btn btn-outline btn-sm" data-act="pool-go" data-expr="{E(str(p["expr"]))}" '
                     f'data-count="{int(p["count"])}" data-field="{E(str(p["field"]))}">{E(t(lang, "v_pool"))}</button>')
            if int(p.get("total") or p["count"]) > int(p["count"]):
                acts += ' <span class="dt-note">' + E(t(lang, "v_pool_cap", n=f"{int(p['count']):,}", total=f"{int(p['total']):,}")) + "</span>"
        else:
            acts += f'<button type="button" class="btn btn-ghost btn-sm" data-act="track" data-expr="{E(name)}">{E(t(lang, "v_track"))}</button>'
        where = (t(lang, "v_static") if v.get("kind") == "static_variable" else t(lang, "v_global")) + " · " + str(v.get("decl") or "")
        rows.append(f'<tr><td class="mono">{E(name)}</td><td class="mono">{E(str(v.get("type") or ""))}</td><td class="num">{E(str(v.get("size") or ""))}</td>'
                    f'<td class="mono nw">{E(where)}</td><td class="nw">{acts}</td></tr>')
    slots = "".join(slot(key("var", str(v.get("name")))) for v in vs)
    return (f'<div class="scroll-x"><table class="table compact"><thead><tr><th>{E(t(lang, "v_name"))}</th><th>{E(t(lang, "v_type"))}</th>'
            f'<th class="num">{E(t(lang, "v_size"))}</th><th>{E(t(lang, "v_where"))}</th><th></th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>{slots}')


_HEXPTR = re.compile(r"^0x[0-9a-fA-F]{4,16}$")


def _follow(lang: str, expr: str, x: Any) -> str:
    if isinstance(x, str) and _HEXPTR.match(x) and int(x, 16) >= 0x10000:
        return f'   <button type="button" data-act="follow" data-expr="{E(expr)}" data-addr="{E(x)}">{E(t(lang, "val_follow"))}</button>'
    return ""


def _value_lines(lang: str, expr: str, v: Any, depth: int = 0) -> List[str]:
    pad = "  " * (depth + 1)
    out = []
    if isinstance(v, dict):
        for k, x in list(v.items())[:64]:
            sub = f"{expr}.{k}"
            if isinstance(x, (dict, list)) and depth < 2:
                out.append(f"{pad}{E(str(k))} = {{")
                out += _value_lines(lang, sub, x, depth + 1)
                out.append(f"{pad}}}")
            else:
                out.append(f"{pad}{E(str(k))} = {E(val(x))}{_follow(lang, sub, x)}")
    elif isinstance(v, list):
        for i, x in enumerate(v[:32]):
            out.append(f"{pad}[{i}] = {E(val(x)) if not isinstance(x, (dict, list)) else E(str(x)[:120])}")
        if len(v) > 32:
            out.append(f"{pad}{E(t(lang, 'val_more', n=len(v) - 32))}")
    return out


def value_fragment(lang: str, d: Dict[str, Any]) -> str:
    expr = str(d.get("expr"))
    if d.get("status") != "OBSERVED":
        return error_fragment(lang, "READ_FAILED", t(lang, "val_fail", e=expr, m=str(d.get("error") or d.get("status"))))
    v = d.get("value")
    ty = str(d.get("type") or "")
    if isinstance(v, (dict, list)):
        body = f"{E(expr)} = ({E(ty)}) {{\n" + "\n".join(_value_lines(lang, expr, v)) + "\n}"
    else:
        body = f"{E(expr)} = {E(val(v))}"
        if d.get("pointer"):
            body += _follow(lang, expr, v)
        body += f'   <span class="c">{E(ty)}</span>'
    note = t(lang, "val_read", t=clock((d.get("cost") or {}).get("at")), s=d.get("size") or "?", c=cost_text(lang, d.get("cost")))
    return (f'<div><h4>{E(t(lang, "val_h"))} · <span class="mono">{E(expr)}</span> @ {E(str(d.get("addr") or "?"))}</h4>'
            f'<pre class="valbox">{body}</pre><div class="dt-actions" style="margin-top:6px"><span class="dt-note">{E(note)}</span>'
            f'<button type="button" class="btn btn-outline btn-sm" data-act="track" data-expr="{E(expr)}">{E(t(lang, "v_track"))}</button></div></div>')


# ------------------------------------------------------------------------------------------------ chips
def _chip(lang: str, kind: str, label: str, attrs: str, hidden: bool) -> str:
    return (f'<button type="button" class="btn btn-outline btn-sm"{" hidden" if hidden else ""} {attrs}>'
            f'<span class="kind">{E(t(lang, kind))}</span> {E(label)}</button>')


def chips_html(lang: str, chips: List[Dict[str, Any]], fid: str) -> str:
    """The "Related" line of one finding: at most four chips, the rest behind a +N button that opens them in place."""
    if not chips:
        return ""
    parts = []
    for i, c in enumerate(chips):
        attrs = " ".join(f'data-{k}="{E(str(v))}"' for k, v in c["attrs"].items())
        parts.append(_chip(lang, c["kind"], c["label"] if not c.get("label_key") else t(lang, c["label_key"], x=c["label"]),
                           f'data-act="{c["act"]}" data-from="{E(fid)}" {attrs}', i >= 4))
    more = (f'<button type="button" class="btn btn-ghost btn-sm" data-act="chips-more" data-id="{E(fid)}">+{len(chips) - 4}</button>'
            if len(chips) > 4 else "")
    return f'<div class="related"><span class="lbl">{E(t(lang, "ch_lbl"))}</span>{"".join(parts)}{more}</div>'


_CK_CHIPS = (("CONCURRENCY", (("threads", "r_threads"), ("locks", "r_locks"))), ("MEMORY", (("memory", "r_memory"),)),
             ("ABNORMAL_STATE", (("files", "r_files"), ("threads", "r_threads"))))


def check_chips_html(lang: str, domain: str) -> str:
    """The chips of an opened check row: the profile rows of that check's area (no read)."""
    lx = Lx(lang)
    d = str(domain or "").upper()
    rows = next((v for k, v in _CK_CHIPS if k in d), None)
    if not rows:
        return ""
    btns = "".join(_chip(lang, "ch_profile", lx.t(label), f'data-act="goto" data-from="checks" data-keys="pf:{r}" data-focus="pf:{r}"', False)
                   for r, label in rows)
    return f'<div class="related"><span class="lbl">{E(t(lang, "ch_lbl"))}</span>{btns}</div>'
