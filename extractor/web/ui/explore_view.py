"""Words and markup of process exploration in the web UI, ko and en, built on the server.

* ``profile_card(prof, lang)``: the Process profile card of a finished diagnosis (four figures, six rows, each with
  what it was observed from, and one "not observed" line), from ``process_profile.build_process_profile``.  Rows open
  in place; what opens is drawn here from the diagnosis's own data, and the places where a live read goes are marked
  ``<!--slot:KEY-->`` (the UI fills them with the fragments below).
* ``*_fragment(data, lang)``: the detail fragments of the job-bound read routes (``extractor/web/explore.py``).

Every string that comes from the target (thread and symbol names, values read from its memory, paths) is escaped
here; fragments contain no script, no event-handler attribute and no URL.  Interaction is declared with ``data-act``
attributes that the UI's single click handler understands.
"""
from __future__ import annotations

import html
import re
from typing import Any, Dict, List, Optional, Tuple

E = html.escape
LANGS = ("ko", "en")

# (en, ko)
W: Dict[str, Tuple[str, str]] = {
    "hint": ("Rows open in place", "줄을 누르면 그 자리에서 펼쳐집니다"),
    "f_threads": ("threads", "스레드"), "f_rss": ("RSS", "RSS"), "f_heap": ("heap", "힙"), "f_fds": ("open files", "열린 파일"),
    "r_threads": ("Threads", "스레드"), "r_memory": ("Memory", "메모리"), "r_locks": ("Locks", "락"),
    "r_files": ("Files", "파일·자원"), "r_modules": ("Modules", "모듈"), "r_vars": ("Variables", "변수"),
    "src_threads": ("thread samples", "스레드 표본"), "src_threads_n": ("{n} thread samples", "스레드 표본 {n}회"),
    "src_memory": ("/proc/pid/status · maps", "/proc/pid/status · maps"),
    "src_locks": ("mutex values + thread samples", "뮤텍스 값 + 스레드 표본"), "src_files": ("/proc/pid/fd", "/proc/pid/fd"),
    "src_modules": ("/proc/pid/maps · ELF", "/proc/pid/maps · ELF"), "src_vars": ("DWARF .debug_info", "DWARF .debug_info"),
    "t_line": ("{n} · {states} · {blocked}", "{n}개 · {states} · {blocked}"),
    "t_blocked": ("{n} blocked on a lock", "락에 막힌 스레드 {n}개"), "t_blocked_0": ("none blocked", "막힌 스레드 없음"),
    "t_none": ("no thread data", "스레드 데이터 없음"),
    "m_line_rss": ("RSS {x}", "RSS {x}"), "m_line_change": ("{d} over {w}", "{w} 동안 {d}"),
    "m_line_heap": ("heap {x}", "힙 {x}"), "m_line_chunks": ("{n} heap chunks", "힙 청크 {n}개"),
    "m_line_vsz": ("address space {x}", "주소 공간 {x}"), "m_none": ("no memory figures", "메모리 수치 없음"),
    "l_line": ("{n} mutexes · {owned} held · {waiting} waited on", "뮤텍스 {n}개 · 소유 {owned} · 대기 {waiting}"),
    "l_none": ("no lock held or waited on ({n} samples)", "기다린 락 없음 (표본 {n}회)"),
    "l_unknown": ("not sampled", "표본 없음"),
    "fi_line": ("{n} open", "{n}개"), "fi_trend": ("{a} → {b} over {w}", "{w} 동안 {a} → {b}"),
    "fi_none": ("not read", "읽지 않음"),
    "mo_line": ("{n} · debug info: {d}", "{n}개 · 디버그 정보: {d}"),
    "mo_none": ("not recorded", "기록 없음"),
    "v_line": ("search globals and statics by name · values are read once on request",
               "전역·정적 변수를 이름으로 찾기 · 값은 누를 때 한 번 읽음"),
    "v_line_nodebug": ("no debug information: read by address only", "디버그 정보 없음: 주소로만 읽기"),
    "dbg_exe": ("the executable (DWARF)", "실행 파일 (DWARF)"), "dbg_none": ("none (symbols only)", "없음 (심볼만)"),
    "unseen": ("Not observed: per-thread CPU trends, per-peer socket traffic, per-thread memory, in-kernel wait causes "
               "(not available from zero-stop reads).",
               "관측하지 않음: 스레드별 CPU 추세, 소켓 상대방별 트래픽, 스레드별 메모리, 커널 안의 대기 원인 (무정지 읽기로 얻지 않음)."),
    "unseen_more": (" Also not established in this diagnosis: {x}.", " 이번 진단에서 확인하지 못한 것도 있음: {x}."),
    # thread rows
    "th_note": ("State column: {n} samples ({legend}). A row reads that thread's stack once.",
                "상태 열은 표본 {n}회의 상태({legend}). 행을 누르면 그 스레드의 스택을 한 번 읽습니다."),
    "th_legend": ("R running, S sleeping, D disk wait", "R 실행, S 대기, D 디스크 대기"),
    "th_grouped": ("{n} threads grouped by (name, top location). A group shares one stack, shown once.",
                   "{n}개를 (이름, 맨 위 위치)로 묶었습니다. 같은 묶음은 같은 스택이므로 스택을 한 번만 보입니다."),
    "th_more": ("{g} more groups ({n} threads) were not sampled in detail", "나머지 {g}개 묶음({n}개 스레드)은 자세히 표본하지 않았습니다"),
    "th_wait_lock": ("lock {x} wait", "락 {x} 대기"), "cpu": ("CPU {p}%", "CPU {p}%"),
    "finding_n": ("finding {n}", "발견 {n}"),
    # memory rows
    "space_h": ("Address space (resident and mapped, by kind)", "주소 공간 구성 (종류별)"),
    "maps_k": ("Mappings", "매핑 목록"), "maps_v": ("address, permissions, size, kind · read once on open",
                                                 "주소, 권한, 크기, 종류 · 열 때 한 번 읽음"),
    "range_k": ("Read a range", "범위 읽기"),
    "range_v": ("type an address or pick a mapping or variable: that range is read once (max 4 KiB)",
                "주소를 입력하거나 매핑·변수에서 고르면 그 범위만 한 번 읽습니다 (최대 4 KiB)"),
    # locks
    "lk_v": ("owner {o} · waiters {n}", "소유자 {o} · 대기 {n}"), "lk_unowned": ("unowned", "소유자 없음"),
    # files and modules
    "files_k": ("Open files", "열린 파일 목록"), "files_v": ("number, kind, target · read once on open", "번호 · 종류 · 대상 · 열 때 한 번 읽음"),
    "mods_k": ("Load addresses", "적재 주소"), "mods_v": ("base address and debug information of each module · read once on open",
                                                       "모듈마다 기준 주소와 디버그 정보 · 열 때 한 번 읽음"),
    "mod_role": ("role", "역할"), "mod_name": ("module", "모듈"), "mod_path": ("path", "경로"),
    # variables
    "var_ph": ("global/static name (substring)", "전역·정적 변수 이름 (일부만 써도 됨)"),
    "var_aria": ("variable search", "변수 검색"),
    "var_note": ("searched in the executable's DWARF · no target read", "실행 파일의 DWARF에서 찾음 · 대상을 읽지 않음"),
}


class Lx:
    def __init__(self, lang: str):
        self.lang = "ko" if lang == "ko" else "en"
        self.i = 1 if self.lang == "ko" else 0

    def t(self, key: str, **kw: Any) -> str:
        s = W[key][self.i]
        return s.format(**kw) if kw else s


_KEY_RE = re.compile(r"[^A-Za-z0-9_.:\-]")


def key(*parts: Any) -> str:
    """A row key: only characters that are safe inside an attribute and an HTML comment."""
    return ":".join(_KEY_RE.sub("_", str(p))[:96] for p in parts)


def slot(k: str) -> str:
    return f"<!--slot:{key(k)}-->"


def row_btn(k: str, inner: str, extra: str = "") -> str:
    """A row that opens its detail in place (the check rows' pattern); the chevron is drawn by CSS from aria-expanded."""
    return (f'<button type="button" class="row-btn" data-act="tog" data-key="{E(key(k))}" aria-expanded="false"{extra}>'
            f'{inner}<span class="chev" aria-hidden="true"></span></button>')


def sub_row(lx: "Lx", k: str, label_key: str, value_key: str) -> str:
    inner = f'<span class="k">{E(lx.t(label_key))}</span><span class="v">{E(lx.t(value_key))}</span>'
    return f"<li>{row_btn(k, inner)}{slot(k)}</li>"


# ------------------------------------------------------------------------------------------------ the profile card
def _size(kb: Any) -> str:
    from extractor.human_report import fmt_bytes
    return fmt_bytes(float(kb) * 1024)


def _secs(x: Any, lx: Lx) -> str:
    v = float(x)
    return f"{v:.1f}초" if lx.i else f"{v:.1f} s"


def _states_text(lx: Lx, states: Dict[str, int]) -> str:
    from extractor import profile_render as pr
    from extractor.process_profile import THREAD_STATES
    plx = pr.Lx(lx.lang)
    return " · ".join(f"{pr.state_word(plx, k)} {states[k]}" for k in THREAD_STATES if k in states)


def _threads_row(lx: Lx, prof: Dict[str, Any], hot_tids: Dict[int, int]) -> Tuple[str, str, str]:
    th = prof.get("threads")
    if not th:
        return lx.t("t_none"), lx.t("src_threads"), ""
    st = th.get("states") or {}
    blocked = st.get("lock", 0)
    line = lx.t("t_line", n=th["count"]["v"], states=_states_text(lx, st) or "—",
                blocked=lx.t("t_blocked", n=blocked) if blocked else lx.t("t_blocked_0"))
    samp = (th.get("sampling") or {}).get("samples")
    src = lx.t("src_threads_n", n=samp) if samp else lx.t("src_threads")
    rows = []
    groups = 0
    for gi, r in enumerate(th.get("rows") or []):
        fn = r.get("function") or ""
        where = fn + (" · " + r["location"] if r.get("location") else "")
        w = r.get("waits_on") or {}
        if w.get("kind") == "lock":
            where += " · " + lx.t("th_wait_lock", x=w.get("name") or "?")
        cpu = r.get("cpu_share")
        cpu_s = lx.t("cpu", p=round(cpu * 100)) if isinstance(cpu, (int, float)) else ""
        if (r.get("count") or 1) > 1:
            groups += 1
            tids = r.get("tids") or []
            inner = (f'<span class="w">{E(str(r.get("name") or "?"))} × {int(r["count"])}</span>'
                     f'<span class="v mono">{E(where)}</span><span class="src">{E(_state_word(lx, r.get("state")))}</span>')
            k = key("grp", gi)
            extra = f' data-tid="{int(tids[0])}" data-name="{E(str(r.get("name") or ""))}"' if tids else ""
            rows.append(f"<li>{row_btn(k, inner, extra)}{slot(k)}</li>")
        else:
            tid = int(r.get("tid") or (r.get("tids") or [0])[0])
            hot = f'<span class="badge badge-outline">{E(lx.t("finding_n", n=hot_tids[tid]))}</span>' if tid in hot_tids else ""
            inner = (f'<span class="w">{E(str(r.get("name") or "?"))}</span><span class="n">{tid}</span>'
                     f'<span class="st">{E(" ".join(str(r.get("samples") or "")[:8]))}</span>'
                     f'<span class="v mono">{E(where)}</span>{hot}<span class="src">{E(cpu_s)}</span>')
            k = key("th", tid)
            rows.append(f"<li>{row_btn(k, inner)}{slot(k)}</li>")
    out = ""
    if groups:
        out += f'<p class="dt-note">{E(lx.t("th_grouped", n=th["count"]["v"]))}</p>'
    out += '<ul class="rows">' + "".join(rows) + "</ul>"
    om = th.get("omitted")
    if om:
        out += f'<p class="dt-note">{E(lx.t("th_more", g=om.get("groups"), n=om.get("threads")))}</p>'
    if samp:
        out += f'<p class="dt-note">{E(lx.t("th_note", n=samp, legend=lx.t("th_legend")))}</p>'
    return line, src, out


def _state_word(lx: Lx, st: Any) -> str:
    from extractor import profile_render as pr
    return pr.state_word(pr.Lx(lx.lang), str(st or "unknown"))


_CAT_CLASS = {"heap": 1, "thread_stacks": 2, "anon": 3, "main_stack": 4, "libs": 5, "exe": 0, "other": 0}


def _memory_row(lx: Lx, prof: Dict[str, Any]) -> Tuple[str, str, str]:
    from extractor import profile_render as pr
    mem = prof.get("memory") or {}
    bits = []
    rss = mem.get("rss")
    if rss:
        s = lx.t("m_line_rss", x=_size(rss["v"]))
        b = rss.get("basis") or {}
        if "series" in rss and b.get("window_s"):
            ch = rss.get("change_kb") or 0
            s += ", " + lx.t("m_line_change", d=("+" if ch >= 0 else "−") + _size(abs(ch)), w=_secs(b["window_s"], lx))
        bits.append(s)
    heap = mem.get("heap") or {}
    if heap.get("mapping_kb"):
        bits.append(lx.t("m_line_heap", x=_size(heap["mapping_kb"]["v"])))
    ig = mem.get("integrity") or {}
    if ig.get("chunks") is not None:
        bits.append(lx.t("m_line_chunks", n=ig["chunks"]))
    asp = mem.get("address_space")
    if asp:
        bits.append(lx.t("m_line_vsz", x=_size(asp["total_kb"])))
    line = " · ".join(bits) or lx.t("m_none")
    plx = pr.Lx(lx.lang)
    out = ""
    if asp and asp.get("categories"):
        cats = asp["categories"]
        tot = sum(c["kb"] for c in cats) or 1
        out += (f'<h4 style="margin-top:0">{E(lx.t("space_h"))}</h4><div class="progress-stack addr-bar" aria-hidden="true">'
                + "".join(f'<i class="m{_CAT_CLASS.get(c["key"], 0)}" style="width:{100.0 * c["kb"] / tot:.1f}%"></i>' for c in cats)
                + '</div><div class="legend">'
                + "".join(f'<span><i class="m{_CAT_CLASS.get(c["key"], 0)}"></i>{E(pr.category_label(plx, c))} {E(_size(c["kb"]))}</span>' for c in cats)
                + "</div>")
    ml = pr.memory_lines(plx, mem) if mem else []
    if ml:
        out += '<ul class="ul">' + "".join(f"<li>{_md(x)}</li>" for x in ml) + "</ul>"
    out += '<ul class="rows">' + sub_row(lx, "maps", "maps_k", "maps_v") + sub_row(lx, "range", "range_k", "range_v") + "</ul>"
    return line, lx.t("src_memory"), out


def _md(s: str) -> str:
    from extractor.human_report import _inline_html
    return _inline_html(s)


def _locks_row(lx: Lx, prof: Dict[str, Any]) -> Tuple[str, str, str]:
    lk = prof.get("locks")
    if not lk:
        return lx.t("l_unknown"), lx.t("src_locks"), ""
    items = lk.get("items") or []
    if not items:
        return lx.t("l_none", n=lk.get("samples") or 0), lx.t("src_locks"), f'<p class="dt-note">{E(lx.t("l_none", n=lk.get("samples") or 0))}</p>'
    owned = sum(1 for it in items if it.get("owner"))
    waiting = sum(1 for it in items if it.get("waiter_count"))
    line = lx.t("l_line", n=len(items), owned=owned, waiting=waiting)
    rows = []
    for it in items:
        name = str(it.get("name") or it.get("address") or "?")
        ow = it.get("owner") or {}
        o = (f'{ow.get("name") or ""} {ow.get("tid") or ""}'.strip()) if ow else lx.t("lk_unowned")
        inner = (f'<span class="w">{E(name)}</span><span class="v">{E(lx.t("lk_v", o=o, n=it.get("waiter_count") or 0))}</span>'
                 f'<span class="src mono">{E(str(it.get("type") or ""))} · {E(str(it.get("address") or ""))}</span>')
        k = key("lk", name)
        rows.append(f"<li>{row_btn(k, inner)}{slot(k)}</li>")
    return line, lx.t("src_locks"), '<ul class="rows">' + "".join(rows) + "</ul>"


def _files_row(lx: Lx, prof: Dict[str, Any]) -> Tuple[str, str, str]:
    from extractor import profile_render as pr
    rs = prof.get("resources") or {}
    f = rs.get("fds")
    if not f:
        line = lx.t("fi_none")
    else:
        line = lx.t("fi_line", n=f["v"])
        ser = f.get("series") or []
        w = (f.get("basis") or {}).get("window_s")
        if len(ser) >= 2 and w:
            line += " · " + lx.t("fi_trend", a=ser[0], b=ser[-1], w=_secs(w, lx))
    out = ""
    lines = pr.resources_text(pr.Lx(lx.lang), rs) if rs else []
    if lines:
        out += '<ul class="ul">' + "".join(f"<li>{_md(x)}</li>" for x in lines) + "</ul>"
    out += '<ul class="rows">' + sub_row(lx, "files", "files_k", "files_v") + "</ul>"
    return line, lx.t("src_files"), out


def _modules_row(lx: Lx, prof: Dict[str, Any], dwarf: Optional[bool]) -> Tuple[str, str, str]:
    from extractor import profile_render as pr
    mo = prof.get("modules")
    if not mo:
        line = lx.t("mo_none")
        out = ""
    else:
        n = len(mo.get("items") or []) + int(mo.get("omitted") or 0)
        line = lx.t("mo_line", n=n, d=lx.t("dbg_exe") if dwarf is not False else lx.t("dbg_none"))
        plx = pr.Lx(lx.lang)
        out = ('<div class="scroll-x"><table class="table compact"><thead><tr>'
               f'<th>{E(lx.t("mod_role"))}</th><th>{E(lx.t("mod_name"))}</th><th>{E(lx.t("mod_path"))}</th></tr></thead><tbody>'
               + "".join(f'<tr><td>{E(plx.t("mo_" + m["role"]))}</td><td class="mono">{E(str(m.get("name") or ""))}</td>'
                         f'<td class="mono">{E(str(m.get("path") or ""))}</td></tr>' for m in mo.get("items") or [])
               + "</tbody></table></div>")
    out += '<ul class="rows">' + sub_row(lx, "mods", "mods_k", "mods_v") + "</ul>"
    return line, lx.t("src_modules"), out


def _vars_row(lx: Lx, prof: Dict[str, Any], dwarf: Optional[bool]) -> Tuple[str, str, str]:
    line = lx.t("v_line_nodebug") if dwarf is False else lx.t("v_line")
    out = (f'<div class="search"><input class="input mono" id="var-q" data-act="q" type="search" autocomplete="off" spellcheck="false" '
           f'placeholder="{E(lx.t("var_ph"))}" aria-label="{E(lx.t("var_aria"))}"><span class="dt-note">{E(lx.t("var_note"))}</span></div>'
           f'{slot("vars")}')
    return line, lx.t("src_vars"), out


def profile_card(prof: Dict[str, Any], lang: str, dwarf: Optional[bool] = None, hot_tids: Optional[Dict[int, int]] = None) -> Dict[str, Any]:
    """The Process profile card as data for the UI: figures, rows (each with its detail markup), the closing line."""
    from extractor import profile_render as pr
    lx = Lx(lang)
    plx = pr.Lx(lang)
    if not prof or not prof.get("available"):
        return {"available": False}
    s = prof.get("summary") or {}
    figs = []
    if s.get("threads") is not None:
        figs.append({"v": str(s["threads"]), "k": lx.t("f_threads")})
    if s.get("rss_kb") is not None:
        figs.append({"v": _size(s["rss_kb"]), "k": lx.t("f_rss")})
    if s.get("heap_kb") is not None:
        figs.append({"v": _size(s["heap_kb"]), "k": lx.t("f_heap")})
    if s.get("fds") is not None:
        figs.append({"v": str(s["fds"]), "k": lx.t("f_fds")})
    rows = []
    for k, label, fn in (("threads", "r_threads", lambda: _threads_row(lx, prof, hot_tids or {})),
                         ("memory", "r_memory", lambda: _memory_row(lx, prof)),
                         ("locks", "r_locks", lambda: _locks_row(lx, prof)),
                         ("files", "r_files", lambda: _files_row(lx, prof)),
                         ("modules", "r_modules", lambda: _modules_row(lx, prof, dwarf)),
                         ("vars", "r_vars", lambda: _vars_row(lx, prof, dwarf))):
        line, src, detail = fn()
        rows.append({"key": k, "label": lx.t(label), "line": line, "src": src, "detail_html": detail})
    no = [t for t in (pr.not_observed_text(plx, it) for it in prof.get("not_observed") or []) if t]
    unseen = lx.t("unseen") + (lx.t("unseen_more", x="; ".join(no)) if no else "")
    return {"available": True, "window": pr.window_text(plx, prof), "hint": lx.t("hint"), "figures": figs, "rows": rows,
            "unseen": unseen}
