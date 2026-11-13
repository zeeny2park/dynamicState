"""The process profile: what a diagnosis learned about the process itself, built only from data it already collected.

``build_process_profile(result, report)`` reads the result and the full report of one diagnosis (the ``actual_observations``
of the checks, ``section_b_target_context``, ``target.abi``, ``collection_impact``) and returns language-neutral data.
It performs no read of the target and takes no part in any verdict.  Words, labels and pictures are made elsewhere
(``human_report`` for Markdown, ``report_visuals`` for HTML, ``web.ui.view`` for the live UI) from this one dict, so
all three say the same thing in the same order.

Rules of the model
* A section exists only when the diagnosis observed something for it; no empty or guessed value is ever put in.
  What is missing is listed in ``not_observed`` with a reason code.
* Every figure says how it was observed in ``basis``:
    ``{"kind": "read"}``                          one read at one moment,
    ``{"kind": "series", "samples": n, "window_s": w}``  n reads over a window of w seconds (w may be None),
    ``{"kind": "derived"}``                       computed from other observed figures.
* Sizes are in kB (1024 bytes) unless a ``unit`` says otherwise; times in seconds.

Order of the sections: ``SECTIONS``.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple

PROFILE_VERSION = 1
SECTIONS = ("runtime", "threads", "memory", "locks", "resources", "modules")
MAX_THREAD_ROWS = 10          # rows of the thread table; the rest is counted ("N more")
MAX_LOCKS = 8
MAX_MODULES = 8
_USER_HZ = 100                # /proc start times are in clock ticks; 100 on every Linux ABI this tool targets

# thread state classes, in the order a reader should meet them
THREAD_STATES = ("lock", "running", "runnable", "disk", "waiting", "sleeping", "stopped", "zombie", "unknown")
_SLEEP_CALLS = frozenset({"nanosleep", "clock_nanosleep", "pause", "restart_syscall"})
_RANK = {s: i for i, s in enumerate(THREAD_STATES)}


# ------------------------------------------------------------------------------------------------ basis helpers
def _read() -> Dict[str, Any]:
    return {"kind": "read"}


def _series(n: int, window_s: Optional[float] = None) -> Dict[str, Any]:
    return {"kind": "series", "samples": int(n), "window_s": None if window_s is None else round(float(window_s), 2)}


def _derived() -> Dict[str, Any]:
    return {"kind": "derived"}


def _num(x: Any) -> Optional[float]:
    if isinstance(x, bool):
        return None
    if isinstance(x, (int, float)):
        return float(x)
    return None


def _kb(x: Any) -> Optional[int]:
    """A /proc status value in kB: a number or a "92 kB" string."""
    if isinstance(x, (int, float)) and not isinstance(x, bool):
        return int(x)
    m = re.match(r"^\s*(\d+)\s*kB\s*$", str(x or ""))
    return int(m.group(1)) if m else None


# ------------------------------------------------------------------------------------------------ the evidence
class _Evidence:
    """The observations of one report, looked up by key across its checks."""

    def __init__(self, result: Dict[str, Any], report: Optional[Dict[str, Any]]):
        self.result = result
        self.report = report if isinstance(report, dict) else {}
        sec = self.report.get("section_d_detailed_inspection_results") or {}
        self.checks = [c for c in (sec.get("checks") or []) if isinstance(c, dict)]
        self.sec_b = self.report.get("section_b_target_context") or {}
        self.impact = result.get("collection_impact") if isinstance(result.get("collection_impact"), dict) else {}
        self.target = result.get("target") if isinstance(result.get("target"), dict) else {}
        self.obs: List[Dict[str, Any]] = [c["actual_observations"] for c in self.checks
                                          if isinstance(c.get("actual_observations"), dict)]
        self.ran = {str(c.get("recipe_id")): str(c.get("status")) for c in self.checks}

    def first(self, key: str, ok=None) -> Any:
        """The first non-empty value of ``key`` in report order (``ok``: optional predicate on the value)."""
        for o in self.obs:
            v = o.get(key)
            if v in (None, "", [], {}):
                continue
            if ok is None or ok(v):
                return v
        return None

    def last(self, key: str, ok=None) -> Any:
        """The last non-empty value of ``key``: the checks run one after another, so this is the latest read."""
        for o in reversed(self.obs):
            v = o.get(key)
            if v in (None, "", [], {}):
                continue
            if ok is None or ok(v):
                return v
        return None

    def longest(self, key: str) -> Optional[List[Any]]:
        best = None
        for o in self.obs:
            v = o.get(key)
            if isinstance(v, list) and v and (best is None or len(v) > len(best)):
                best = v
        return best

    def has_check(self, recipe: str) -> bool:
        return ("RECIPE_" + recipe) in self.ran and self.ran["RECIPE_" + recipe] not in ("SKIPPED", "NOT_PLANNED", "NOT_IN_MODE")


def _is_dict(v: Any) -> bool:
    return isinstance(v, dict)


# ------------------------------------------------------------------------------------------------ threads
def _classify(letters: str, cpu: Optional[float], runnable: Optional[float], syscall: Optional[str],
              lock: Optional[str]) -> str:
    if lock:
        return "lock"
    if cpu is not None and cpu >= 0.2:
        return "running"
    if runnable is not None and runnable >= 0.2:
        return "runnable"
    if not letters:
        return "unknown"
    top = max(set(letters), key=letters.count).upper()
    if top == "R":
        return "running"
    if top == "D":
        return "disk"
    if top in ("T", "Z", "X"):
        return "stopped" if top == "T" else "zombie"
    if top in ("S", "I"):
        if syscall and syscall not in _SLEEP_CALLS:
            return "waiting"
        return "sleeping"
    return "unknown"


def _user_frame(callstack: Any) -> Tuple[Optional[str], Optional[str]]:
    """The top frame of a stack that has a source line (the process's own code), as (function, file:line)."""
    for fr in callstack or []:
        if isinstance(fr, dict) and fr.get("source_location") and fr.get("function_name"):
            return str(fr["function_name"]), str(fr["source_location"])
    return None, None


def _threads_section(ev: _Evidence) -> Optional[Dict[str, Any]]:
    snap = ev.last("threads", lambda v: isinstance(v, list) and v and isinstance(v[0], dict))
    summ = ev.first("thread_summary", lambda v: isinstance(v, list) and v and isinstance(v[0], dict))
    if not snap and not summ:
        return None
    sampling = ev.first("thread_sampling", _is_dict) or {}
    window = _num(sampling.get("window_sec"))
    n_samples = int(sampling.get("samples_collected") or 0)
    by_tid: Dict[int, Dict[str, Any]] = {}
    for r in snap or []:
        if isinstance(r, dict) and isinstance(r.get("tid"), int):
            by_tid[r["tid"]] = {"snap": r}
    for r in summ or []:
        if isinstance(r, dict) and isinstance(r.get("tid"), int):
            by_tid.setdefault(r["tid"], {})["sum"] = r
    cs = ev.first("callstacks_info", _is_dict) or {}
    for r in cs.get("threads") or []:
        if isinstance(r, dict) and isinstance(r.get("tid"), int):
            by_tid.setdefault(r["tid"], {})["stack"] = r
    names = {tid: str((v.get("sum") or v.get("snap") or v.get("stack") or {}).get("name") or "") for tid, v in by_tid.items()}

    rows: List[Dict[str, Any]] = []
    for tid, v in by_tid.items():
        s, sn, st = v.get("sum") or {}, v.get("snap") or {}, v.get("stack") or {}
        letters = "".join(str(x)[:1].upper() for x in (s.get("states") or []))[:40] or str(sn.get("state") or "")[:1].upper()
        windowed = bool(s.get("states"))
        syscall = s.get("syscall") or st.get("syscall")
        lock = s.get("waiting_on_lock") or ((st.get("waiting_on_lock") or {}).get("lock_name")
                                            if isinstance(st.get("waiting_on_lock"), dict) else None)
        owner_tid, owner_name = s.get("lock_owner_tid"), s.get("lock_owner_name")
        if isinstance(st.get("waiting_on_lock"), dict) and owner_tid is None:
            owner_tid = st["waiting_on_lock"].get("held_by_tid")
            owner_name = st["waiting_on_lock"].get("held_by_thread_name")
        cpu, runnable = _num(s.get("cpu_share")), _num(s.get("runnable_fraction"))
        fn, loc = s.get("top_function"), s.get("top_source_location")
        if not (fn and loc):
            fn2, loc2 = _user_frame(st.get("callstack"))
            fn, loc = (fn or fn2), (loc or loc2)
        row: Dict[str, Any] = {
            "tid": tid, "name": names.get(tid) or None, "state": _classify(letters, cpu, runnable, syscall, lock),
            "samples": letters, "basis": _series(len(s.get("states") or []), s.get("window_sec") or window) if windowed else _read(),
        }
        if cpu is not None:
            row["cpu_share"] = round(cpu, 3)
        if runnable is not None:
            row["runnable_fraction"] = round(runnable, 3)
        if fn:
            row["function"] = str(fn)
        if loc:
            row["location"] = str(loc)
        if s.get("top_source_text") and s.get("top_source_line_exact"):
            row["source"] = str(s["top_source_text"]).strip()
        if lock:
            row["waits_on"] = {"kind": "lock", "name": str(lock), "owner_tid": owner_tid,
                               "owner_name": owner_name or (names.get(owner_tid) if isinstance(owner_tid, int) else None)}
        elif syscall:
            row["waits_on"] = {"kind": "syscall", "name": str(syscall)}
        rows.append(row)
    rows.sort(key=lambda r: (_RANK.get(r["state"], 99), r["tid"]))

    # same name and same state (and the same lock, when waiting on one): one line with a count.  The line shows the
    # place and wait of a thread that was sampled over the window, when the group has one.
    groups: List[Dict[str, Any]] = []
    index: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for r in rows:
        w = r.get("waits_on") or {}
        key = (r.get("name"), r["state"], w.get("name") if w.get("kind") == "lock" else None)
        g = index.get(key)
        if g is None:
            g = dict(r, count=1, tids=[r["tid"]])
            index[key] = g
            groups.append(g)
        else:
            g["count"] += 1
            g["tids"].append(r["tid"])
            if g["basis"]["kind"] != "series" and r["basis"]["kind"] == "series":
                keep = {k: g[k] for k in ("count", "tids")}
                g.clear()
                g.update(r)
                g.update(keep)
            for k in ("cpu_share", "runnable_fraction"):
                if r.get(k) is not None and (g.get(k) is None or r[k] > g[k]):
                    g[k] = r[k]
    for g in groups:
        g["tids"] = g["tids"][:6]
        if g["count"] > 1:
            g.pop("tid", None)
    groups.sort(key=lambda g: (_RANK.get(g["state"], 99), -g["count"], g.get("tid") or g["tids"][0]))
    shown = groups[:MAX_THREAD_ROWS]
    hidden = groups[MAX_THREAD_ROWS:]
    state_counts: Dict[str, int] = {}
    for r in rows:
        state_counts[r["state"]] = state_counts.get(r["state"], 0) + 1

    out: Dict[str, Any] = {"rows": shown, "states": {k: state_counts[k] for k in THREAD_STATES if k in state_counts},
                           "omitted": {"groups": len(hidden), "threads": sum(g["count"] for g in hidden)} if hidden else None,
                           "detailed": sum(1 for r in rows if r["basis"]["kind"] == "series"), "listed": len(rows)}
    series = ev.first("thread_count_series", lambda v: isinstance(v, list) and v)
    count = _num(ev.last("thread_count")) or (len(rows) or None)
    if not count:
        return None
    # the count is the latest read; the series and its trend are the sampled window (earlier in the diagnosis)
    out["count"] = {"v": int(count), "basis": _read()}
    if series and len([x for x in series if _num(x) is not None]) >= 2:
        ser = [int(x) for x in series if _num(x) is not None]
        out["series"] = {"v": ser, "basis": _series(len(ser), window)}
        out["trend"] = str(ev.first("thread_count_trend") or "") or None
    if n_samples and window is not None:
        out["sampling"] = {"samples": n_samples, "window_s": round(window, 2)}
    return out


# ------------------------------------------------------------------------------------------------ memory
def _memory_section(ev: _Evidence) -> Optional[Dict[str, Any]]:
    out: Dict[str, Any] = {}
    hist = ev.longest("rss_history_kb")
    wall = _num(ev.impact.get("wall_clock_ms"))
    st = ev.last("status_fields", _is_dict) or {}
    rss_now = _kb(st.get("VmRSS")) or (int(hist[-1]) if hist else None) or _num(ev.first("rss_kb")) or _num(ev.first("current_rss_kb"))
    if hist and len(hist) >= 2:
        series = [int(x) for x in hist if _num(x) is not None]
        out["rss"] = {"v": series[-1], "unit": "kB", "basis": _series(len(series), wall / 1000.0 if wall else None),
                      "series": series, "change_kb": series[-1] - series[0]}
    elif rss_now:
        out["rss"] = {"v": int(rss_now), "unit": "kB", "basis": _read()}
    if "rss" in out:
        rss = out["rss"]
        if _kb(st.get("VmHWM")):
            rss["peak_kb"] = _kb(st.get("VmHWM"))
        if _kb(st.get("RssAnon")) is not None and _kb(st.get("RssFile")) is not None:
            rss["anon_kb"], rss["file_kb"] = _kb(st.get("RssAnon")), _kb(st.get("RssFile"))
            rss["split_basis"] = _read()
    # heap
    heap_kb = _num(ev.first("heap_kb"))
    alloc_kb = _num(ev.first("allocator_heap_kb"))
    heap: Dict[str, Any] = {}
    if heap_kb is not None:
        heap["mapping_kb"] = {"v": int(heap_kb), "unit": "kB", "basis": _read()}
    caps = [str(c) for c in (ev.sec_b.get("target_capabilities") or [])]
    if "ALLOCATOR_GLIBC_PTMALLOC" in caps:
        heap["allocator"] = "glibc_ptmalloc"
    ret = ev.first("heap_retention", lambda v: isinstance(v, dict) and isinstance(v.get("totals"), dict))
    li = ev.first("leak_investigation", lambda v: isinstance(v, dict) and v.get("heap_walks"))
    if ret and ret.get("walk_status") in ("OK", "PARTIAL"):
        t = ret["totals"]
        heap["walk"] = {"basis": _read(), "arenas": len(ret.get("arenas") or []),
                        "total_kb": round((t.get("system_mem") or 0) / 1024), "in_use_kb": round((t.get("in_use_bytes") or 0) / 1024),
                        "free_kb": round((t.get("free_bytes") or 0) / 1024), "free_chunks": t.get("free_chunks"),
                        "largest_free_b": t.get("largest_free")}
    elif li:
        walks = [w for w in li["heap_walks"] if isinstance(w, dict) and w.get("status", "OK") == "OK" and "in_use_bytes" in w]
        if walks:
            heap["walk"] = {"basis": _series(len(walks), li.get("window_s")),
                            "in_use_kb": round(walks[-1]["in_use_bytes"] / 1024), "in_use_count": walks[-1].get("in_use_count"),
                            "in_use_series_kb": [round(w["in_use_bytes"] / 1024) for w in walks]}
    elif alloc_kb is not None:
        heap["walk"] = {"basis": _read(), "in_use_kb": int(alloc_kb)}
    if li:
        classes = []
        for g in (li.get("unreachable_growth") or []) + (li.get("held_growth") or []):
            if isinstance(g, dict) and g.get("chunk_size") and g.get("blocks_now"):
                classes.append({"chunk_b": int(g["chunk_size"]), "blocks": int(g["blocks_now"]),
                                "blocks_delta": g.get("blocks_delta")})
        if classes:
            heap["growing_classes"] = sorted(classes, key=lambda c: -c["blocks"] * c["chunk_b"])[:3]
    if heap:
        out["heap"] = heap
    # integrity
    mi = ev.first("memory_integrity", _is_dict) or {}
    hp = mi.get("heap") if isinstance(mi.get("heap"), dict) else {}
    if hp.get("status"):
        chk = hp.get("checked") if isinstance(hp.get("checked"), dict) else {}
        stacks = mi.get("stacks") if isinstance(mi.get("stacks"), dict) else {}
        used = [t.get("used_bytes") for t in stacks.get("threads") or [] if isinstance(t, dict) and _num(t.get("used_bytes")) is not None]
        out["integrity"] = {"basis": _read(), "mode": mi.get("mode"), "heap_status": hp.get("status"), "walk_status": hp.get("walk_status"),
                            "chunks": chk.get("chunks"), "defects": len(hp.get("defects") or []),
                            "stacks_checked": stacks.get("threads_checked"),
                            "stack_max_used_kb": round(max(used) / 1024) if used else None}
    # address space by category
    stacks_kb = None
    snap = ev.last("threads", lambda v: isinstance(v, list) and v and isinstance(v[0], dict)) or []
    pid = ev.target.get("pid") or ev.sec_b.get("pid")
    # the main thread's stack is VmStk, counted on its own line
    sizes = [(t.get("stack_info") or {}).get("size") for t in snap if isinstance(t, dict) and t.get("tid") != pid]
    sizes = [s for s in sizes if _num(s)]
    if sizes:
        stacks_kb = round(sum(sizes) / 1024)
    vsize, vdata, vstk = _kb(st.get("VmSize")), _kb(st.get("VmData")), _kb(st.get("VmStk"))
    vexe, vlib = _kb(st.get("VmExe")), _kb(st.get("VmLib"))
    if vsize and vdata is not None:
        cats: List[Dict[str, Any]] = []
        hk = int(heap_kb or 0)
        data_rest = max(0, vdata - hk - (stacks_kb or 0))
        if heap_kb is not None:
            cats.append({"key": "heap", "kb": hk, "basis": _read()})
        if stacks_kb:
            cats.append({"key": "thread_stacks", "kb": stacks_kb, "count": len(sizes), "basis": _derived()})
        cats.append({"key": "anon", "kb": data_rest if heap_kb is not None else max(0, vdata - (stacks_kb or 0)),
                     "basis": _derived()})
        if vstk:
            cats.append({"key": "main_stack", "kb": vstk, "basis": _read()})
        if vlib:
            cats.append({"key": "libs", "kb": vlib, "basis": _read()})
        if vexe:
            cats.append({"key": "exe", "kb": vexe, "basis": _read()})
        rest = vsize - sum(c["kb"] for c in cats)
        if rest > 0:
            cats.append({"key": "other", "kb": rest, "basis": _derived()})
        out["address_space"] = {"total_kb": vsize, "basis": _read(), "categories": [c for c in cats if c["kb"] > 0]}
    return out or None


# ------------------------------------------------------------------------------------------------ locks
def _locks_section(ev: _Evidence, names: Dict[int, str]) -> Optional[Dict[str, Any]]:
    samples = ev.first("lock_wait_samples", lambda v: isinstance(v, list) and v and isinstance(v[0], dict))
    cont = ev.first("lock_contention", _is_dict) or {}
    sampling = ev.first("thread_sampling", _is_dict) or {}
    if samples is None and not cont:
        return None
    n = len(samples) if samples else int(cont.get("samples") or 0)
    window = _num(sampling.get("window_sec")) or _num(cont.get("window_s"))
    agg: Dict[str, Dict[str, Any]] = {}
    for smp in samples or []:
        for lk in smp.get("locks") or []:
            if not isinstance(lk, dict):
                continue
            key = str(lk.get("lock") or lk.get("address"))
            a = agg.setdefault(key, {"name": str(lk.get("lock") or ""), "address": lk.get("address"), "type": lk.get("type"),
                                     "seen": 0, "max_waiters": 0, "owners": [], "waiters": []})
            a["seen"] += 1
            w = list(lk.get("waiter_tids") or [])
            a["max_waiters"] = max(a["max_waiters"], len(w))
            if lk.get("owner_tid") is not None and lk["owner_tid"] not in a["owners"]:
                a["owners"].append(lk["owner_tid"])
            for t in w:
                if t not in a["waiters"]:
                    a["waiters"].append(t)
    where = {str(m.get("lock_name")): m for m in cont.get("mutexes") or [] if isinstance(m, dict)}
    items = []
    for key, a in agg.items():
        item: Dict[str, Any] = {"name": a["name"] or None, "address": a["address"], "type": a["type"],
                                "seen_samples": a["seen"], "of_samples": n, "max_waiters": a["max_waiters"],
                                "owner": ({"tid": a["owners"][0], "name": names.get(a["owners"][0])} if a["owners"] else None),
                                "owner_changed": len(a["owners"]) > 1,
                                "waiters": [{"tid": t, "name": names.get(t)} for t in a["waiters"][:4]],
                                "waiter_count": len(a["waiters"]), "basis": _series(n, window)}
        w = where.get(a["name"]) or {}
        ow = (w.get("owner_where") or [None])[0]
        if isinstance(ow, dict) and ow.get("source_location"):
            item["owner_at"] = {"function": ow.get("function_name"), "location": ow.get("source_location")}
        items.append(item)
    items.sort(key=lambda x: (-x["waiter_count"], -x["seen_samples"], str(x["name"])))
    return {"samples": n, "window_s": None if window is None else round(window, 2), "basis": _series(n, window),
            "items": items[:MAX_LOCKS], "omitted": max(0, len(items) - MAX_LOCKS)}


# ------------------------------------------------------------------------------------------------ resources
def _resources_section(ev: _Evidence) -> Optional[Dict[str, Any]]:
    fd = ev.first("fd_usage", _is_dict)
    tg = ev.first("thread_growth", _is_dict) or {}
    out: Dict[str, Any] = {}
    if fd and isinstance(fd.get("samples"), list) and fd["samples"]:
        opens = [s["open_fds"] for s in fd["samples"] if isinstance(s, dict) and _num(s.get("open_fds")) is not None]
        if opens:
            span = _num(fd["samples"][-1].get("t_s"))
            f: Dict[str, Any] = {"v": int(opens[-1]), "basis": _series(len(opens), span), "series": [int(x) for x in opens]}
            if _num(fd.get("fd_limit")):
                f["limit"] = int(fd["fd_limit"])
            kinds = fd.get("open_fds_by_kind")
            if isinstance(kinds, dict) and kinds:
                f["by_kind"] = {str(k): int(v) for k, v in sorted(kinds.items(), key=lambda kv: -kv[1]) if _num(v)}
            f["new_targets"] = len(fd.get("new_fd_targets") or [])
            out["fds"] = f
    if _num(tg.get("rlimit_nproc")):
        out["thread_limit"] = {"nproc": int(tg["rlimit_nproc"]), "system_max": int(tg["threads_max"]) if _num(tg.get("threads_max")) else None,
                               "basis": _read()}
    return out or None


# ------------------------------------------------------------------------------------------------ modules
def _modules_section(ev: _Evidence) -> Optional[Dict[str, Any]]:
    exe = ev.sec_b.get("binary_path") or (ev.first("executable") if isinstance(ev.first("executable"), str) else None)
    abi = ev.target.get("abi") if isinstance(ev.target.get("abi"), dict) else (ev.sec_b.get("target_abi") or {})
    seen: Dict[str, Dict[str, Any]] = {}

    def add(role: str, path: Any, name: Any = None) -> None:
        if not path:
            return
        path = str(path)
        if path not in seen:
            seen[path] = {"role": role, "path": path, "name": str(name or os.path.basename(path))}

    add("executable", exe)
    if isinstance(abi, dict):
        add("loader", abi.get("interpreter"))
        add("libc", abi.get("libc_path"))
    cs = ev.first("callstacks_info", _is_dict) or {}
    for t in cs.get("threads") or []:
        for fr in (t.get("callstack") or []) if isinstance(t, dict) else []:
            if isinstance(fr, dict) and fr.get("module_path"):
                add("library" if fr["module_path"] != exe else "executable", fr["module_path"], fr.get("module"))
    if not seen:
        return None
    mods = list(seen.values())
    return {"items": mods[:MAX_MODULES], "omitted": max(0, len(mods) - MAX_MODULES), "basis": _read(),
            "load_addresses": False, "source": "stacks" if cs.get("threads") else "abi"}


# ------------------------------------------------------------------------------------------------ runtime
def _runtime_section(ev: _Evidence) -> Optional[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    # uptime: the process start (clock ticks since boot) against the monotonic clock of the first memory sample
    start = _num(ev.first("start_time", lambda v: _num(v) is not None or str(v).isdigit()) or 0) or (
        float(ev.first("start_time")) if str(ev.first("start_time") or "").isdigit() else None)
    t0 = _num((ev.first("mapping_growth", _is_dict) or {}).get("t0"))
    if start and t0 and not ev.first("is_remote"):
        up = t0 - start / _USER_HZ
        if 0 <= up < 10 * 365 * 86400:
            items.append({"key": "uptime", "v": round(up, 1), "unit": "s", "basis": _derived()})
    cs = ev.first("callstacks_info", _is_dict) or {}
    abi = ev.target.get("abi") if isinstance(ev.target.get("abi"), dict) else {}
    ver = (cs.get("target_abi") or {}).get("libc_version") or abi.get("libc_version")
    libc = (cs.get("target_abi") or {}).get("libc") or abi.get("libc")
    if ver and libc:
        items.append({"key": "libc_version", "v": f"{libc} {ver}", "basis": _read()})
    snap = ev.last("threads", lambda v: isinstance(v, list) and v and isinstance(v[0], dict)) or []
    cpus = {str(t.get("cpus_allowed_list")) for t in snap if isinstance(t, dict) and t.get("cpus_allowed_list")}
    if len(cpus) == 1:
        items.append({"key": "cpus_allowed", "v": next(iter(cpus)), "basis": _read()})
    return {"items": items} if items else None


# ------------------------------------------------------------------------------------------------ the profile
def build_process_profile(result: Dict[str, Any], report: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The profile of one finished diagnosis.  ``report`` defaults to ``result["report"]``.

    Returns ``{"version", "available", "window", "summary", <sections>, "not_observed"}``; a section key is present only
    when the diagnosis observed something for it.  ``available`` is False when the diagnosis left nothing to profile.
    """
    res = result if isinstance(result, dict) else {}
    rep = report if isinstance(report, dict) else (res.get("report") if isinstance(res.get("report"), dict) else None)
    ev = _Evidence(res, rep)
    prof: Dict[str, Any] = {"version": PROFILE_VERSION, "available": False}
    if not ev.obs:
        prof["not_observed"] = [{"key": "profile", "reason": "no_report"}]
        return prof
    secs: Dict[str, Any] = {}
    for key, fn in (("threads", _threads_section), ("memory", _memory_section), ("resources", _resources_section),
                    ("modules", _modules_section), ("runtime", _runtime_section)):
        try:
            v = fn(ev)
        except Exception:  # noqa: BLE001 - a broken section must never stop the report; it is then "not observed"
            v = None
        if v:
            secs[key] = v
    names: Dict[int, str] = {}
    for r in (ev.first("thread_summary", lambda v: isinstance(v, list)) or []) + (ev.last("threads", lambda v: isinstance(v, list)) or []):
        if isinstance(r, dict) and isinstance(r.get("tid"), int) and r.get("name"):
            names.setdefault(r["tid"], str(r["name"]))
    try:
        lk = _locks_section(ev, names)
    except Exception:  # noqa: BLE001
        lk = None
    if lk is not None:
        secs["locks"] = lk
    for k in SECTIONS:
        if k in secs:
            prof[k] = secs[k]
    window_s = _num(ev.sec_b.get("observation_duration_sec"))
    samples = ev.impact.get("samples_collected")
    if window_s or samples:
        prof["window"] = {"seconds": window_s, "samples": int(samples) if _num(samples) else None}
    summary: Dict[str, Any] = {}
    th = secs.get("threads") or {}
    if th.get("count"):
        summary["threads"] = th["count"]["v"]
    mem = secs.get("memory") or {}
    if mem.get("rss"):
        summary["rss_kb"] = mem["rss"]["v"]
    heap = mem.get("heap") or {}
    if (heap.get("walk") or {}).get("in_use_kb") is not None:
        summary["heap_kb"] = heap["walk"]["in_use_kb"]
        summary["heap_kind"] = "in_use"
    elif (heap.get("mapping_kb") or {}).get("v") is not None:
        summary["heap_kb"] = heap["mapping_kb"]["v"]
        summary["heap_kind"] = "mapping"
    if (secs.get("resources") or {}).get("fds"):
        summary["fds"] = secs["resources"]["fds"]["v"]
    prof["summary"] = summary
    prof["not_observed"] = _not_observed(ev, secs)
    prof["available"] = bool(secs)
    return prof


def _not_observed(ev: _Evidence, secs: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    mem = secs.get("memory") or {}
    heap = mem.get("heap") or {}
    walk = heap.get("walk") or {}
    li = ev.first("leak_investigation", _is_dict) or {}
    if "free_kb" not in walk:
        if walk:
            out.append({"key": "heap_free", "reason": "walk_without_free"})
        else:
            reason = "no_growth" if li.get("status") == "NOT_RUN" else "not_asked"
            out.append({"key": "heap_walk", "reason": reason})
    if walk:
        out.append({"key": "size_classes", "reason": "not_in_data"})
    if "address_space" not in mem:
        out.append({"key": "address_space", "reason": "no_status"})
    if "locks" not in secs:
        out.append({"key": "locks", "reason": "not_sampled"})
    if "resources" not in secs or "fds" not in (secs.get("resources") or {}):
        out.append({"key": "fds", "reason": "not_run"})
    if "threads" not in secs:
        out.append({"key": "threads", "reason": "not_sampled"})
    mods = secs.get("modules") or {}
    if mods:
        out.append({"key": "load_addresses", "reason": "not_recorded"})
    cs = ev.first("callstacks_info", _is_dict) or {}
    if secs.get("threads") and not cs.get("threads"):
        out.append({"key": "stacks", "reason": "not_unwound"})
    th = secs.get("threads") or {}
    if th and th.get("detailed", 0) < th.get("listed", 0):
        out.append({"key": "thread_detail_partial", "reason": "sampled_subset", "detailed": th["detailed"], "listed": th["listed"]})
    return out
