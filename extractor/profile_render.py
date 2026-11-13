"""Words and pictures of the process profile (``process_profile.build_process_profile``), in one place.

The incident report's Markdown (``human_report.compose``), its HTML (``report_visuals``) and the live UI (``web.ui.view``)
all show the profile through this module, from the one model, in the same order and with the same words.
``profile_lines`` is the compact Markdown; ``profile_html`` the card body (a three-line summary, the full profile in a
Collapsible below it).  Nothing here reads a target or decides anything.
"""
from __future__ import annotations

import html
from typing import Any, Dict, List, Optional, Tuple

from .process_profile import THREAD_STATES

E = html.escape

# (en, ko).  Identifiers (thread, lock, function, file:line, system call) are put in code spans by the callers.
W: Dict[str, Tuple[str, str]] = {
    "title": ("Process profile", "프로세스 프로필"),
    "glance": ("At a glance: {x}", "한눈에: {x}"),
    "g_threads": ("{n} threads", "스레드 {n}개"), "g_threads_1": ("{n} thread", "스레드 {n}개"), "g_rss": ("RSS {x}", "RSS {x}"), "g_heap": ("heap {x}", "힙 {x}"),
    "g_fds": ("{n} open files", "열린 파일 {n}개"), "g_fds_1": ("{n} open file", "열린 파일 {n}개"),
    "window": ("Observation window {s} s, {n} samples", "관측 구간 {s}초, 표본 {n}회"),
    "window_n": ("{n} samples", "표본 {n}회"),
    "caveat_short": ("values seen in that window, not permanent properties", "이 구간에서 본 값이며 고정된 성질이 아님"),
    "caveat": ("These are what this diagnosis saw in that window, not permanent properties of the process.",
               "이 값은 이 진단이 그 구간에서 본 것이며 프로세스의 고정된 성질이 아닙니다."),
    "open": ("Show the process profile", "프로세스 프로필 보기"),
    "none": ("The diagnosis left no data to profile this process.", "이 진단에는 프로세스를 설명할 데이터가 남지 않았습니다."),
    "pending": ("Filled in when the verdict arrives.", "판정이 나오면 채워집니다."),
    "pending_t": ("{n} threads seen so far.", "지금까지 확인한 스레드 {n}개."),
    # how a figure was observed
    "b_read": ("single read", "한 번 읽음"), "b_derived": ("derived", "계산한 값"),
    "b_series": ("{n} samples over {w} s", "{w}초 동안 표본 {n}회"), "b_series_n": ("{n} samples", "표본 {n}회"),
    # sections
    "s_runtime": ("Runtime", "실행 환경"), "s_threads": ("Threads", "스레드"), "s_memory": ("Memory", "메모리"),
    "s_locks": ("Locks", "락"), "s_resources": ("Files and resources", "파일과 자원"), "s_modules": ("Modules", "모듈"),
    "s_not": ("Not observed", "관측하지 못한 것"),
    # runtime
    "r_uptime": ("running for {x} (derived)", "가동 {x} (계산한 값)"), "r_libc": ("C library {x}", "C 라이브러리 {x}"),
    "r_cpus": ("allowed CPUs {x}", "허용 CPU {x}"),
    # threads
    "t_count": ("{n} threads (last read)", "{n}개 (마지막으로 읽음)"),
    "t_count_1": ("{n} thread (last read)", "{n}개 (마지막으로 읽음)"),
    "t_trend": ("over the window the count went {a} -> {b} ({basis}): {w}", "구간 동안 {a} → {b}개 ({basis}): {w}"),
    "t_trend_flat": ("count unchanged at {a} over the window ({basis})", "구간 동안 {a}개로 변화 없음 ({basis})"),
    "tr_growing": ("growing", "늘어남"), "tr_shrinking": ("shrinking", "줄어듦"), "tr_stable": ("stable", "안정"),
    "tr_fluctuating": ("fluctuating", "오르내림"),
    "t_states": ("by state: {x}", "상태별: {x}"),
    "t_more": ("{g} more groups ({n} threads) not listed", "나머지 {g}개 묶음({n}개 스레드)은 적지 않았습니다"),
    "t_head": ("Thread", "스레드"), "t_state": ("State", "상태"), "t_samples": ("State per sample", "샘플별 상태"),
    "t_cpu": ("On CPU", "CPU 사용"), "t_where": ("Where / waiting on", "머문 위치 · 대기 대상"),
    "t_runnable": ("ready to run in {p}% of samples", "샘플의 {p}%에서 실행 가능 상태"),
    "t_oncpu": ("on CPU {p}%", "CPU {p}% 사용"),
    "t_lock": ("lock {x}", "락 {x}"), "t_owner": ("held by {x}", "소유 {x}"), "t_call": ("in {x}", "{x} 호출 중"),
    "t_group": ("{n} threads", "{n}개"),
    "st_lock": ("waiting on a lock", "락 대기"), "st_running": ("running", "실행 중"),
    "st_runnable": ("ready, waiting for a CPU", "실행 대기"), "st_disk": ("uninterruptible wait", "중단 불가 대기"),
    "st_waiting": ("waiting in a system call", "시스템 호출에서 대기"), "st_sleeping": ("sleeping", "잠자는 중"),
    "st_stopped": ("stopped", "정지"), "st_zombie": ("zombie", "좀비"), "st_unknown": ("unknown", "알 수 없음"),
    "t_chart": ("Thread count over the window", "관측 구간의 스레드 수"),
    "t_chart_x": ("sample", "샘플"), "t_chart_y": ("threads", "스레드"),
    # memory
    "m_rss": ("RSS {x}", "RSS {x}"), "m_rss_basis": ("{basis}", "{basis}"),
    "m_rss_flat": ("unchanged", "변화 없음"), "m_rss_up": ("{x} more than at the first read", "처음 읽은 값보다 {x} 늘어남"),
    "m_rss_down": ("{x} less than at the first read", "처음 읽은 값보다 {x} 줄어듦"),
    "m_peak": ("peak {x}", "최대 {x}"), "m_split": ("anonymous {a}, file-backed {f}", "익명 {a}, 파일 {f}"),
    "m_vsize": ("address space {x}", "가상 크기 {x}"),
    "m_heap_map": ("main heap (brk) mapping {x}", "주 힙(brk) 매핑 {x}"), "m_alloc": ("allocator: {x}", "할당자: {x}"),
    "al_glibc_ptmalloc": ("glibc ptmalloc", "glibc ptmalloc"),
    "m_walk_full": ("heap walk: {u} in use, {f} free in {c} free chunks (largest free chunk {l}), {basis}",
                    "힙 순회: 사용 중 {u}, 여유 {f}(여유 덩어리 {c}개, 가장 큰 것 {l}), {basis}"),
    "m_walk_use": ("heap walk: {u} in use{n}, {basis}", "힙 순회: 사용 중 {u}{n}, {basis}"),
    "m_walk_n": (" ({n} blocks)", "(블록 {n}개)"),
    "m_classes": ("growing size classes: {x}", "늘어나는 크기 등급: {x}"),
    "m_class": ("{c} B blocks x {n}", "{c} B 블록 {n}개"),
    "m_integ": ("integrity check: heap walk {w}, {c} chunks, {d} damaged; {k} thread stacks checked{u}",
                "무결성 점검: 힙 순회 {w}, 덩어리 {c}개, 손상 {d}건, 스레드 스택 {k}개 확인{u}"),
    "m_integ_nc": ("integrity check: heap {s}", "무결성 점검: 힙 {s}"),
    "m_integ_u": (" (most used {x})", "(가장 많이 쓴 스택 {x})"),
    "w_OK": ("completed", "정상 완료"), "w_PARTIAL": ("partial", "일부만 완료"),
    "m_space": ("Address space by category (total {x})", "범주별 주소 공간 (전체 {x})"),
    "c_heap": ("main heap (brk)", "주 힙(brk)"), "c_thread_stacks": ("thread stacks ({n})", "스레드 스택({n}개)"),
    "c_anon": ("other anonymous mappings", "그 밖의 익명 매핑"), "c_main_stack": ("main thread stack", "주 스레드 스택"),
    "c_libs": ("shared libraries", "공유 라이브러리"), "c_exe": ("executable", "실행 파일"),
    "c_other": ("other mappings", "그 밖의 매핑"),
    "m_chart": ("Resident memory (RSS) over the diagnosis", "진단 동안의 상주 메모리(RSS)"),
    "m_chart_x": ("read", "읽은 순서"), "m_chart_y": ("RSS", "RSS"),
    # locks
    "l_none": ("No lock was held or waited on in any of the {n} samples.", "표본 {n}회 모두에서 잠겨 있거나 대기 중인 락이 없었습니다."),
    "l_line": ("{lock}: held by {owner}{waiters}; seen in {s} of {n} samples{at}",
               "{lock}: 소유 {owner}{waiters}, 표본 {n}회 중 {s}회에서 관측{at}"),
    "l_waiters": (", waited on by {x}", ", 대기 {x}"), "l_at": ("; owner at {x}", ", 소유자 위치 {x}"),
    "l_nobody": ("no owner seen", "소유자 확인 안 됨"), "l_changed": (" (the owner changed)", "(소유자가 바뀜)"),
    "l_more": ("{n} more locks not listed", "나머지 락 {n}개는 적지 않았습니다"),
    # resources
    "f_open": ("{n} open files", "열린 파일 {n}개"), "f_open_1": ("{n} open file", "열린 파일 {n}개"), "f_limit": ("limit {x}", "한도 {x}"),
    "f_kinds": ("by type: {x}", "종류별: {x}"), "f_new": ("{n} new during the window", "구간 동안 새로 {n}개"),
    "f_threadlimit": ("thread limit (nproc) {n}", "스레드 수 한도(nproc) {n}"),
    "f_series": ("{basis}", "{basis}"),
    # modules
    "mo_executable": ("executable", "실행 파일"), "mo_loader": ("dynamic loader", "동적 로더"), "mo_libc": ("C library", "C 라이브러리"),
    "mo_library": ("shared library", "공유 라이브러리"),
    "mo_more": ("{n} more not listed", "나머지 {n}개는 적지 않았습니다"),
    # not observed
    "n_heap_walk_no_growth": ("heap in-use / free split: no heap walk ran, because memory showed no growth trend",
                              "힙의 사용·여유 내역: 메모리가 늘어나는 추세가 없어 힙 순회를 하지 않았습니다"),
    "n_heap_walk_not_asked": ("heap in-use / free split: no heap walk ran in this diagnosis",
                              "힙의 사용·여유 내역: 이번 진단에서는 힙 순회를 하지 않았습니다"),
    "n_heap_free_walk_without_free": ("heap free size: the heap walk measured only what is in use",
                                      "힙의 여유 크기: 힙 순회가 사용 중인 크기만 측정했습니다"),
    "n_size_classes_not_in_data": ("whole-heap size-class distribution: the diagnosis did not tally it",
                                   "힙 전체의 크기 등급별 분포: 이 진단은 집계하지 않았습니다"),
    "n_address_space_no_status": ("address space by category: the process status was not read",
                                  "범주별 주소 공간: 프로세스 상태 값을 읽지 못했습니다"),
    "n_locks_not_sampled": ("locks: no lock-wait samples were taken", "락: 락 대기 표본을 얻지 못했습니다"),
    "n_fds_not_run": ("open files: the file-descriptor check did not run", "열린 파일: 파일 기술자 검사가 실행되지 않았습니다"),
    "n_threads_not_sampled": ("threads: no thread data was collected", "스레드: 스레드 데이터를 모으지 못했습니다"),
    "n_load_addresses_not_recorded": ("module load addresses: this diagnosis did not record them",
                                      "모듈의 적재 주소: 이 진단은 기록하지 않았습니다"),
    "n_stacks_not_unwound": ("call stacks: none were obtained", "호출 스택: 얻지 못했습니다"),
    "n_thread_detail_partial": ("thread table: only {d} of {l} threads were sampled over the window; the others have one read",
                                "스레드 표: {l}개 중 {d}개만 구간 동안 표본으로 관측했고 나머지는 한 번 읽은 값입니다"),
    "n_profile_no_report": ("the profile: the result carries no detailed report", "프로필: 결과에 상세 보고서가 없습니다"),
}


class Lx:
    def __init__(self, lang: str):
        self.lang = "ko" if lang == "ko" else "en"
        self.i = 1 if self.lang == "ko" else 0

    def t(self, key: str, **kw: Any) -> str:
        s = W[key][self.i]
        return s.format(**kw) if kw else s


def _c(x: Any) -> str:
    return "`" + str(x).replace("`", "'") + "`"


def _size(kb: Any) -> str:
    from .human_report import fmt_bytes
    return fmt_bytes(float(kb) * 1024)


def _bytes(b: Any) -> str:
    from .human_report import fmt_bytes
    return fmt_bytes(b)


def _secs(x: Any, lx: Lx) -> str:
    v = float(x)
    if v < 60:
        return (f"{v:.1f}초" if lx.i else f"{v:.1f} s")
    m, s = divmod(int(round(v)), 60)
    if m < 60:
        return f"{m}분 {s}초" if lx.i else f"{m} min {s} s"
    h, m = divmod(m, 60)
    if h < 48:
        return f"{h}시간 {m}분" if lx.i else f"{h} h {m} min"
    d, h = divmod(h, 24)
    return f"{d}일 {h}시간" if lx.i else f"{d} d {h} h"


def basis_text(lx: Lx, b: Optional[Dict[str, Any]]) -> str:
    b = b or {}
    k = b.get("kind")
    if k == "series":
        if b.get("window_s") is not None:
            return lx.t("b_series", n=b["samples"], w=f"{b['window_s']:g}")
        return lx.t("b_series_n", n=b["samples"])
    if k == "derived":
        return lx.t("b_derived")
    return lx.t("b_read")


def window_text(lx: Lx, prof: Dict[str, Any]) -> str:
    w = prof.get("window") or {}
    if w.get("seconds") is not None and w.get("samples"):
        return lx.t("window", s=f"{w['seconds']:.1f}", n=w["samples"])
    if w.get("samples"):
        return lx.t("window_n", n=w["samples"])
    return ""


def glance_text(lx: Lx, prof: Dict[str, Any]) -> str:
    s = prof.get("summary") or {}
    parts = []
    if s.get("threads") is not None:
        parts.append(lx.t("g_threads_1" if s["threads"] == 1 else "g_threads", n=s["threads"]))
    if s.get("rss_kb") is not None:
        parts.append(lx.t("g_rss", x=_size(s["rss_kb"])))
    if s.get("heap_kb") is not None:
        parts.append(lx.t("g_heap", x=_size(s["heap_kb"])))
    if s.get("fds") is not None:
        parts.append(lx.t("g_fds_1" if s["fds"] == 1 else "g_fds", n=s["fds"]))
    return " · ".join(parts)


def state_word(lx: Lx, st: str) -> str:
    return lx.t("st_" + st if ("st_" + st) in W else "st_unknown")


# ------------------------------------------------------------------------------------------------ phrases (Markdown text)
def runtime_text(lx: Lx, sec: Dict[str, Any]) -> str:
    out = []
    for it in sec.get("items") or []:
        k, v = it["key"], it["v"]
        if k == "uptime":
            out.append(lx.t("r_uptime", x=_secs(v, lx)))
        elif k == "libc_version":
            out.append(lx.t("r_libc", x=_c(v)))
        elif k == "cpus_allowed":
            out.append(lx.t("r_cpus", x=_c(v)))
    return " · ".join(out)


def thread_count_text(lx: Lx, sec: Dict[str, Any]) -> str:
    parts = [lx.t("t_count_1" if sec["count"]["v"] == 1 else "t_count", n=sec["count"]["v"])]
    ser = sec.get("series")
    if ser:
        v = ser["v"]
        basis = basis_text(lx, ser["basis"])
        if v[0] == v[-1] and min(v) == max(v):
            parts.append(lx.t("t_trend_flat", a=v[0], basis=basis))
        else:
            tr = sec.get("trend") or ("growing" if v[-1] > v[0] else "shrinking" if v[-1] < v[0] else "fluctuating")
            parts.append(lx.t("t_trend", a=v[0], b=v[-1], basis=basis, w=lx.t("tr_" + tr if ("tr_" + tr) in W else "tr_fluctuating")))
    st = sec.get("states") or {}
    if st:
        parts.append(lx.t("t_states", x=", ".join(f"{state_word(lx, k)} {st[k]}" for k in THREAD_STATES if k in st)))
    return "; ".join(parts)


def thread_label(lx: Lx, row: Dict[str, Any]) -> str:
    name = _c(row["name"]) if row.get("name") else (f"tid {row['tid']}" if "tid" in row else "")
    if row.get("count", 1) > 1:
        return f"{name} ×{row['count']}"
    return f"{name} (tid {row['tid']})" if row.get("name") and "tid" in row else name


def thread_where(lx: Lx, row: Dict[str, Any]) -> List[str]:
    out = []
    if row.get("function"):
        out.append(_c(row["function"]) + (" " + _c(row["location"]) if row.get("location") else ""))
    w = row.get("waits_on")
    if w and w["kind"] == "lock":
        s = lx.t("t_lock", x=_c(w["name"]))
        if w.get("owner_name") or w.get("owner_tid") is not None:
            s += ", " + lx.t("t_owner", x=_c(w.get("owner_name") or f"tid {w['owner_tid']}"))
        out.append(s)
    elif w:
        out.append(lx.t("t_call", x=_c(w["name"])))
    return out


def thread_line(lx: Lx, row: Dict[str, Any]) -> str:
    bits = [state_word(lx, row["state"])] + thread_where(lx, row)
    cpu = row.get("cpu_share")
    if cpu is not None and cpu >= 0.01:
        bits.append(lx.t("t_oncpu", p=round(cpu * 100)))
    elif row.get("runnable_fraction") is not None and row["runnable_fraction"] >= 0.05:
        bits.append(lx.t("t_runnable", p=round(row["runnable_fraction"] * 100)))
    return f"{thread_label(lx, row)}: " + ", ".join(bits)


def memory_lines(lx: Lx, mem: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    rss = mem.get("rss")
    if rss:
        ch = rss.get("change_kb")
        inner = [basis_text(lx, rss["basis"])]
        if "series" in rss:
            inner[0] += ", " + (lx.t("m_rss_flat") if not ch else lx.t("m_rss_up", x=_size(ch)) if ch > 0
                                else lx.t("m_rss_down", x=_size(-ch)))
        if rss.get("peak_kb") and rss["peak_kb"] != rss["v"]:
            inner.append(lx.t("m_peak", x=_size(rss["peak_kb"])))
        if rss.get("anon_kb") is not None:
            inner.append(lx.t("m_split", a=_size(rss["anon_kb"]), f=_size(rss["file_kb"])))
        line = lx.t("m_rss", x=_size(rss["v"])) + " (" + "; ".join(inner) + ")"
        asp = mem.get("address_space")
        if asp:
            line += ", " + lx.t("m_vsize", x=_size(asp["total_kb"]))
        out.append(line)
    heap = mem.get("heap") or {}
    hb = []
    if heap.get("mapping_kb"):
        hb.append(lx.t("m_heap_map", x=_size(heap["mapping_kb"]["v"])))
    if heap.get("allocator"):
        hb.append(lx.t("m_alloc", x=lx.t("al_" + heap["allocator"])))
    walk = heap.get("walk")
    if walk:
        basis = basis_text(lx, walk["basis"])
        if "free_kb" in walk:
            hb.append(lx.t("m_walk_full", u=_size(walk["in_use_kb"]), f=_size(walk["free_kb"]), c=walk.get("free_chunks", "?"),
                           l=_bytes(walk.get("largest_free_b") or 0), basis=basis))
        else:
            n = lx.t("m_walk_n", n=walk["in_use_count"]) if walk.get("in_use_count") else ""
            hb.append(lx.t("m_walk_use", u=_size(walk["in_use_kb"]), n=n, basis=basis))
    if heap.get("growing_classes"):
        hb.append(lx.t("m_classes", x=", ".join(lx.t("m_class", c=c["chunk_b"], n=c["blocks"]) for c in heap["growing_classes"])))
    ig = mem.get("integrity")
    if ig:
        if ig.get("chunks") is not None:
            u = lx.t("m_integ_u", x=_size(ig["stack_max_used_kb"])) if ig.get("stack_max_used_kb") else ""
            hb.append(lx.t("m_integ", w=lx.t("w_" + str(ig.get("walk_status"))) if ("w_" + str(ig.get("walk_status"))) in W else str(ig.get("walk_status")),
                           c=ig["chunks"], d=ig.get("defects", 0), k=ig.get("stacks_checked") or 0, u=u))
        else:
            hb.append(lx.t("m_integ_nc", s=str(ig.get("heap_status"))))
    if hb:
        out.append("; ".join(hb))
    return out


def category_label(lx: Lx, cat: Dict[str, Any]) -> str:
    return lx.t("c_" + cat["key"], n=cat.get("count", "")) if ("c_" + cat["key"]) in W else cat["key"]


def space_line(lx: Lx, asp: Dict[str, Any]) -> str:
    return lx.t("m_space", x=_size(asp["total_kb"])) + ": " + ", ".join(
        f"{category_label(lx, c)} {_size(c['kb'])}" for c in asp["categories"])


def lock_line(lx: Lx, it: Dict[str, Any], n_default: int) -> str:
    owner = (_c(it["owner"]["name"]) if it["owner"].get("name") else f"tid {it['owner']['tid']}") if it.get("owner") else lx.t("l_nobody")
    if it.get("owner_changed"):
        owner += lx.t("l_changed")
    wt = ""
    if it.get("waiters"):
        wt = lx.t("l_waiters", x=", ".join(_c(w["name"]) if w.get("name") else f"tid {w['tid']}" for w in it["waiters"]))
    at = lx.t("l_at", x=_c(it["owner_at"]["location"])) if it.get("owner_at") else ""
    return lx.t("l_line", lock=_c(it["name"] or it.get("address")), owner=owner, waiters=wt, s=it["seen_samples"],
                n=it.get("of_samples") or n_default, at=at)


def resources_text(lx: Lx, sec: Dict[str, Any]) -> List[str]:
    out = []
    f = sec.get("fds")
    if f:
        bits = [lx.t("f_open_1" if f["v"] == 1 else "f_open", n=f["v"]) + " (" + basis_text(lx, f["basis"]) + ")"]
        if f.get("limit"):
            bits.append(lx.t("f_limit", x=f"{f['limit']:,}"))
        if f.get("by_kind"):
            bits.append(lx.t("f_kinds", x=", ".join(f"{_c(k)} {v}" for k, v in f["by_kind"].items())))
        if f.get("new_targets"):
            bits.append(lx.t("f_new", n=f["new_targets"]))
        out.append(", ".join(bits))
    t = sec.get("thread_limit")
    if t:
        out.append(lx.t("f_threadlimit", n=f"{t['nproc']:,}"))
    return out


def module_text(lx: Lx, mod: Dict[str, Any]) -> str:
    return f"{lx.t('mo_' + mod['role'])} {_c(mod['name'])}"


def not_observed_text(lx: Lx, it: Dict[str, Any]) -> str:
    key = f"n_{it['key']}_{it['reason']}"
    if key not in W:
        key = f"n_{it['key']}"
    if key not in W:
        return ""
    return lx.t(key, d=it.get("detailed", ""), l=it.get("listed", ""))


# ------------------------------------------------------------------------------------------------ Markdown
MAX_MD_THREAD_LINES = 3


def profile_lines(prof: Dict[str, Any], lang: str) -> List[str]:
    """The compact Markdown of the profile (bullets only; ``[]`` when the diagnosis left nothing to profile)."""
    if not prof or not prof.get("available"):
        return []
    lx = Lx(lang)
    out: List[str] = []
    g = glance_text(lx, prof)
    w = window_text(lx, prof)
    if g:
        out.append("- " + lx.t("glance", x=g) + (f" ({w}; {lx.t('caveat_short')})" if w else ""))
    if prof.get("runtime"):
        out.append(f"- {lx.t('s_runtime')}: " + runtime_text(lx, prof["runtime"]))
    th = prof.get("threads")
    if th:
        out.append(f"- {lx.t('s_threads')}: " + thread_count_text(lx, th))
        rows = th["rows"]
        for r in rows[:MAX_MD_THREAD_LINES]:
            out.append("  - " + thread_line(lx, r))
        rest_g = len(rows) - MAX_MD_THREAD_LINES
        if rest_g > 0 or th.get("omitted"):
            n = sum(r.get("count", 1) for r in rows[MAX_MD_THREAD_LINES:]) + ((th.get("omitted") or {}).get("threads") or 0)
            gcount = max(rest_g, 0) + ((th.get("omitted") or {}).get("groups") or 0)
            out.append("  - " + lx.t("t_more", g=gcount, n=n))
    mem = prof.get("memory")
    if mem:
        ml = memory_lines(lx, mem)
        if ml:
            out.append(f"- {lx.t('s_memory')}: " + ml[0])
            out += ["  - " + x for x in ml[1:]]
        if mem.get("address_space"):
            out.append("  - " + space_line(lx, mem["address_space"]))
    lk = prof.get("locks")
    if lk:
        if lk["items"]:
            out.append(f"- {lx.t('s_locks')}:")
            out += ["  - " + lock_line(lx, it, lk["samples"]) for it in lk["items"]]
            if lk.get("omitted"):
                out.append("  - " + lx.t("l_more", n=lk["omitted"]))
        else:
            out.append(f"- {lx.t('s_locks')}: " + lx.t("l_none", n=lk["samples"]))
    rs = prof.get("resources")
    if rs:
        out.append(f"- {lx.t('s_resources')}: " + "; ".join(resources_text(lx, rs)))
    mo = prof.get("modules")
    if mo:
        out.append(f"- {lx.t('s_modules')}: " + ", ".join(module_text(lx, m) for m in mo["items"])
                   + (", " + lx.t("mo_more", n=mo["omitted"]) if mo.get("omitted") else ""))
    no = [t for t in (not_observed_text(lx, it) for it in prof.get("not_observed") or []) if t]
    if no:
        out.append(f"- {lx.t('s_not')}: " + "; ".join(no))
    # nested bullets are flattened by the report's Markdown converter only when they stay one level deep
    return out


# ------------------------------------------------------------------------------------------------ HTML
def _md(s: str) -> str:
    from .human_report import _inline_html
    return _inline_html(s)


def _thread_table(lx: Lx, th: Dict[str, Any]) -> str:
    body = []
    for r in th["rows"]:
        cells = "".join(f'<i class="dsv-st-{E(s)}" title="{E(state_word(lx, r["state"]))}">{E(s)}</i>' for s in (r.get("samples") or "")[:40])
        cpu = r.get("cpu_share")
        run = r.get("runnable_fraction")
        meter = ""
        if cpu is not None:
            meter = f'<span class="dsv-meter"><i style="width:{max(0.0, min(100.0, cpu * 100)):.0f}%"></i></span> {cpu * 100:.0f}%'
            if run is not None and run >= 0.05:
                meter += f'<br><span class="dsv-note">{E(lx.t("t_runnable", p=round(run * 100)))}</span>'
        name = _md(thread_label(lx, r))
        hot = ' class="dsv-hot"' if r["state"] == "lock" else ""
        body.append(f'<tr{hot}><td>{name}</td><td>{E(state_word(lx, r["state"]))}<br><span class="dsv-smp">{cells}</span></td>'
                    f'<td>{meter}</td><td>{"<br>".join(_md(x) for x in thread_where(lx, r))}</td></tr>')
    more = ""
    if th.get("omitted"):
        more = f'<p class="dsv-note">{E(lx.t("t_more", g=th["omitted"]["groups"], n=th["omitted"]["threads"]))}</p>'
    used = sorted({s for r in th["rows"] for s in (r.get("samples") or "")})
    legend = ""
    return (f'<div class="dsv-scroll"><table class="dsv-tbl"><thead><tr><th>{E(lx.t("t_head"))}</th><th>{E(lx.t("t_state"))} · {E(lx.t("t_samples"))}</th>'
            f'<th>{E(lx.t("t_cpu"))}</th><th>{E(lx.t("t_where"))}</th></tr></thead><tbody>{"".join(body)}</tbody></table></div>{more}{legend}')


def _chart(lx: Lx, ys: List[float], title_key: str, x_key: str, y_key: str, unit: str = "") -> str:
    from .report_visuals import series_chart
    ys = [float(y) for y in ys]
    idx = list(range(len(ys)))
    if len(ys) > 12:                      # a small picture: at most 12 evenly chosen points
        idx = [round(i * (len(ys) - 1) / 11) for i in range(12)]
    return series_chart([float(i) for i in idx], [ys[i] for i in idx], lx.t(title_key), lx.t(x_key), lx.t(y_key), None, unit,
                        x_fmt="{:.0f}")


def profile_html(prof: Dict[str, Any], lang: str, uid: str = "profile") -> str:
    """The card body: the three-line summary, then the whole profile in a Collapsible.  ``""`` when nothing to show."""
    if not prof or not prof.get("available"):
        return ""
    from .report_visuals import share_bars
    lx = Lx(lang)
    summary = [f'<p class="profile-glance"><strong>{E(glance_text(lx, prof))}</strong></p>']
    w = window_text(lx, prof)
    if w:
        summary.append(f'<p class="dsv-note">{E(w)}. {E(lx.t("caveat"))}</p>')
    no = [t for t in (not_observed_text(lx, it) for it in prof.get("not_observed") or []) if t]
    parts: List[str] = []

    def block(title_key: str, inner: str) -> None:
        if inner:
            parts.append(f'<h3>{E(lx.t(title_key))}</h3>{inner}')

    def bullets(items: List[str]) -> str:
        return '<ul class="dsv-facts">' + "".join(f"<li>{_md(x)}</li>" for x in items) + "</ul>" if items else ""

    if prof.get("runtime"):
        block("s_runtime", f"<p>{_md(runtime_text(lx, prof['runtime']))}</p>")
    th = prof.get("threads")
    if th:
        inner = f"<p>{_md(thread_count_text(lx, th))}</p>"
        ser = (th.get("series") or {}).get("v") or []
        if len(ser) >= 2 and min(ser) != max(ser):
            inner += _chart(lx, ser, "t_chart", "t_chart_x", "t_chart_y")
        inner += _thread_table(lx, th)
        block("s_threads", inner)
    mem = prof.get("memory")
    if mem:
        ml = memory_lines(lx, mem)
        inner = bullets(ml)
        rss = mem.get("rss") or {}
        if len(rss.get("series") or []) >= 2:
            inner += _chart(lx, rss["series"], "m_chart", "m_chart_x", "m_chart_y", " KB")
        asp = mem.get("address_space")
        if asp:
            items = [(category_label(lx, c), c["kb"] / 1024.0) for c in asp["categories"]]
            inner += f'<h4>{E(lx.t("m_space", x=_size(asp["total_kb"])))}</h4>' + share_bars(
                items, words=True, fmt=lambda v: _size(v * 1024))
        block("s_memory", inner)
    lk = prof.get("locks")
    if lk:
        if lk["items"]:
            items = [lock_line(lx, it, lk["samples"]) for it in lk["items"]]
            if lk.get("omitted"):
                items.append(lx.t("l_more", n=lk["omitted"]))
            block("s_locks", bullets(items))
        else:
            block("s_locks", f"<p>{E(lx.t('l_none', n=lk['samples']))}</p>")
    if prof.get("resources"):
        block("s_resources", bullets(resources_text(lx, prof["resources"])))
    mo = prof.get("modules")
    if mo:
        items = [module_text(lx, m) + " · " + _c(m["path"]) for m in mo["items"]]
        if mo.get("omitted"):
            items.append(lx.t("mo_more", n=mo["omitted"]))
        block("s_modules", bullets(items))
    if no:
        block("s_not", bullets(no))
    detail = (f'<details class="collapsible" id="{E(uid)}-detail"><summary>{E(lx.t("open"))}</summary>'
              f'<div class="in">{"".join(parts)}</div></details>')
    return "".join(summary) + detail
