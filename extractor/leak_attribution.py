"""IMP-008: who leaks - multi-observation memory trend, heap-walk census and growth attribution.

One investigation observes the target's memory several times within a single run, without stopping it:

1. Cheap trend (always, part of the baseline): /proc-only samples (VmRSS, [heap] size, anonymous
   writable mapping total).  The samples ride the thread sampler's existing window (one sample per
   thread sample, taken in the provider's inspect hook - no second sleep); when that window is not
   available (remote target, standalone provider) a short window of its own is used.
2. Escalation to heap walks ONLY when the cheap trend shows growth or the run asks about memory (a
   memory symptom, a memory recipe planned for the symptom, or a targeted memory recipe).  Each walk
   is an IMP-007 walk + reverse reachability map (zero-stop reads through the adapter, budgeted), run
   ``walks`` times spaced over the session's observation window.
3. Census per walk: in-use chunk count and bytes (mmapped chunks included) -> ``live_allocations_count``
   / ``allocator_heap_kb``; every in-use chunk is attributed to its owner: the root of its first
   (shortest, BFS) referrer, with a normalised path (array indices -> ``[*]``, runs of the same step
   -> ``(->next)*``) so that a growing linked list or array aggregates under its owning variable; chunks
   with no referrer at all are counted per size class ("unreachable").
4. Verdict (strict): a leak needs in-use heap growing across >= 3 walks (no drop beyond a small churn
   tolerance) AND attribution: a growing set of unreachable blocks (``LEAK_UNREACHABLE``, a leak by
   definition) or a growing set owned by a global/static variable (``UNBOUNDED_GROWTH_OWNED``: still
   referenced, so leak vs intended accumulation is undecidable from memory alone - reported as
   unbounded growth under that owner, never as a confirmed leak).  Growth held only by thread stacks /
   locals (working sets), untyped data, RSS growth without in-use growth, shrinking or flat in-use heap
   -> no leak (at most "growth observed, not established as a leak").
"""

import re
import struct
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

INV_NOT_RUN = "NOT_RUN"
INV_COMPLETED = "COMPLETED"
INV_UNSUPPORTED = "UNSUPPORTED"
INV_LIMITED = "LIMITED"            # budget / target exit / failed walks: fewer than the minimum walks

V_LEAK_UNREACHABLE = "LEAK_UNREACHABLE"
V_GROWTH_OWNED = "UNBOUNDED_GROWTH_OWNED"
V_NOT_ESTABLISHED = "GROWTH_NOT_ESTABLISHED"
V_NO_GROWTH = "NO_GROWTH"
V_SHRANK = "IN_USE_SHRANK"
V_NO_TREND = "NO_GROWTH_TREND"        # cheap trend only, no walk needed
V_INSUFFICIENT = "INSUFFICIENT_OBSERVATIONS"
V_UNSUPPORTED = "LEAK_OWNER_UNSUPPORTED"
LEAK_VERDICTS = (V_LEAK_UNREACHABLE, V_GROWTH_OWNED)

OWNED_KINDS = ("global", "static")
HELD_KINDS = ("local", "stack_conservative")

_WALK_STATUS_UNSUPPORTED = ("UNSUPPORTED_ALLOCATOR", "UNSUPPORTED_GLIBC_VERSION", "INCONCLUSIVE_ABI_UNDETECTED",
                            "ARENA_NOT_FOUND")


@dataclass
class MemoryObservationConfig:
    interval_s: float = 0.05            # session observation_interval (lower bound of the walk spacing)
    window_s: float = 1.0               # session observation_duration (span of the walk series)
    walks: int = 4
    min_walks: int = 3
    min_walk_spacing_s: float = 0.1
    own_sample_interval_s: float = 0.2  # cheap trend without a thread-sampler window
    trend_min_growth_kb: int = 128
    trend_step_tolerance_kb: int = 16
    min_inuse_growth_bytes: int = 64 * 1024
    min_class_growth_bytes: int = 32 * 1024
    min_class_growth_blocks: int = 2
    churn_tolerance_bytes: int = 16 * 1024
    churn_tolerance_fraction: float = 0.005
    wall_fraction: float = 0.6          # share of the remaining session wall clock the walks may use
    bytes_fraction: float = 0.75        # share of the remaining session byte budget the walks may use
    target_recipe: Optional[str] = None

    @classmethod
    def from_session(cls, interval: Optional[float], duration: Optional[float], thresholds: Optional[Dict[str, Any]],
                     target_recipe: Optional[str] = None) -> "MemoryObservationConfig":
        c = cls(interval_s=float(interval or 0.05), window_s=float(duration or 1.0), target_recipe=target_recipe)
        t = thresholds or {}
        try:
            if t.get("leak_walk_count") is not None:
                c.walks = max(c.min_walks, int(t["leak_walk_count"]))
            if t.get("leak_window_sec") is not None:
                c.window_s = max(0.2, float(t["leak_window_sec"]))
        except (TypeError, ValueError):
            pass
        return c


# --------------------------------------------------------------------------------------------- cheap samples
def _kb(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return int(v)
    try:
        return int(str(v).strip().split()[0])
    except (ValueError, IndexError):
        return None


def proc_memory_sample(adapter: Any, pid: int) -> Optional[Dict[str, Any]]:
    """/proc-only memory sample: VmRSS, [heap] size, total anonymous writable mappings (kB)."""
    t = time.monotonic()
    try:
        st = adapter.get_process_status(pid) or {}
        maps = adapter.get_proc_maps(pid) or []
    except Exception:  # noqa: BLE001
        return None
    rss = _kb(st.get("VmRSS"))
    if rss is None:
        return None
    heap = 0
    anon = 0
    for m in maps:
        size = int(m.get("size") or 0)
        p = m.get("pathname") or ""
        perms = m.get("permissions") or ""
        if p == "[heap]":
            heap += size
        if "w" in perms and (not p or p == "[heap]"):
            anon += size
    return {"t": t, "rss_kb": rss, "heap_vma_kb": heap // 1024, "anon_rw_kb": anon // 1024}


def _state(provider: Any) -> Dict[str, Any]:
    st = getattr(provider, "_imp008_state", None)
    if st is None:
        st = {"cosamples": {}, "investigations": {}}
        provider._imp008_state = st
    return st


def cosampling_inspect(provider: Any, pid: int, inner: Callable[[], Any]) -> Callable[[], Any]:
    """Wrap the thread sampler's per-sample inspect hook: one /proc memory sample per thread sample."""
    def _f():
        s = proc_memory_sample(provider.adapter, pid)
        if s is not None:
            s["source"] = "thread_sampling_window"
            _state(provider)["cosamples"].setdefault(int(pid), []).append(s)
        return inner()
    return _f


def cheap_trend(samples: Sequence[Dict[str, Any]], cfg: MemoryObservationConfig) -> Dict[str, Any]:
    ss = sorted(samples, key=lambda s: s["t"])
    out: Dict[str, Any] = {"samples": len(ss), "window_s": round(ss[-1]["t"] - ss[0]["t"], 3) if ss else 0.0,
                           "rss_kb_series": [s["rss_kb"] for s in ss],
                           "anon_rw_kb_series": [s["anon_rw_kb"] for s in ss],
                           "heap_vma_kb_series": [s["heap_vma_kb"] for s in ss],
                           "indicates_growth": False, "established": len(ss) >= 3}

    def grows(series: List[int]) -> bool:
        if len(series) < 3:
            return False
        steps_ok = all(b - a >= -cfg.trend_step_tolerance_kb for a, b in zip(series, series[1:]))
        return steps_ok and series[-1] - series[0] >= cfg.trend_min_growth_kb

    if ss:
        out["rss_growth_kb"] = ss[-1]["rss_kb"] - ss[0]["rss_kb"]
        out["anon_rw_growth_kb"] = ss[-1]["anon_rw_kb"] - ss[0]["anon_rw_kb"]
        out["indicates_growth"] = grows(out["rss_kb_series"]) or grows(out["anon_rw_kb_series"])
    return out


# --------------------------------------------------------------------------------------------- census
_IDX_RE = re.compile(r"\[\d+\]")
_OFF_RE = re.compile(r"\[\+0x[0-9a-fA-F]+\]")


def _ntok(tok: str) -> str:
    return _OFF_RE.sub("[+*]", _IDX_RE.sub("[*]", tok or ""))


def _combine(p: str, last: str, rep: int, tok: str) -> Tuple[str, str, int]:
    if not tok:
        return p, last, rep
    if tok == last:
        if rep:
            return p, last, 1
        return p[:-len(last)] + "(" + last + ")*", last, 1
    return p + tok, tok, 0


class _NormPaths:
    """Normalised path per reachability node (computed once, nodes are created parent-first)."""

    def __init__(self, an: Any) -> None:
        n = len(an.node_suffix)
        self.p: List[str] = [""] * n
        self.last: List[str] = [""] * n
        self.rep = bytearray(n)
        for i in range(n):
            par = an.node_parent[i]
            tok = _ntok(an.node_suffix[i])
            if par < 0:
                self.p[i], self.last[i], self.rep[i] = tok, tok, 0
            else:
                self.p[i], self.last[i], self.rep[i] = _combine(self.p[par], self.last[par], self.rep[par], tok)

    def path(self, node: int, suffix: str) -> str:
        if node < 0:
            return _ntok(suffix)
        return _combine(self.p[node], self.last[node], self.rep[node], _ntok(suffix))[0]


def _owner_of(an: Any, norm: _NormPaths, node: int, suffix: str, root: int) -> Tuple[str, str, str, Optional[str], str]:
    """(key, kind, label, root variable name or None, path)."""
    roots = an.roots
    r = roots[root] if 0 <= root < len(roots) else None
    guard = 0
    # an untyped word inside a reached block: the owner is the root of the block that holds the word
    while r is not None and r.kind == "heap_conservative" and node >= 0 and guard < 64:
        par = an.node_parent[node]
        if par < 0:
            break
        node, suffix = par, ""
        r = roots[an.node_root[par]]
        guard += 1
    if r is None or r.kind == "heap_conservative":
        return "untyped", "heap_conservative", "untyped reference inside a reachable block", None, ""
    if r.kind in OWNED_KINDS:
        return "var:%s:%s" % (r.module or "", r.name), r.kind, "%s variable %s" % (r.kind, r.name), r.name, \
            norm.path(node, suffix)
    if r.kind == "local":
        return ("local:%s:%s:%s" % (r.tid, r.function, r.name), "local",
                "local %s of %s in thread %s" % (r.name, r.function, r.thread), None, norm.path(node, suffix))
    if r.kind == "stack_conservative":
        return "stack:%s" % r.tid, r.kind, "stack of thread %s" % r.thread, None, ""
    return "data:%s" % r.name, r.kind, "%s (%s, no variable name)" % (r.name, r.kind), None, ""


def census(analysis: Any) -> Dict[str, Any]:
    """Per-walk census of in-use chunks: totals, owners (with normalised paths), unreachable size classes."""
    from .heap_walker import ST_IN_USE, ST_MMAPPED
    an = analysis.analyzer
    walk = analysis.walk
    ct = walk.chunks
    out: Dict[str, Any] = {"status": analysis.status, "message": analysis.message, "in_use_count": 0,
                           "in_use_bytes": 0, "mmapped_count": 0, "mmapped_bytes": 0, "owners": {},
                           "unreachable": {}}
    if an is None:
        return out
    norm = _NormPaths(an)
    owners: Dict[str, Dict[str, Any]] = {}
    unreach: Dict[int, Dict[str, Any]] = {}
    for ci in range(len(ct)):
        st = ct.states[ci]
        if st != ST_IN_USE and st != ST_MMAPPED:
            continue
        sz = int(ct.sizes[ci])
        out["in_use_count"] += 1
        out["in_use_bytes"] += sz
        if st == ST_MMAPPED:
            out["mmapped_count"] += 1
            out["mmapped_bytes"] += sz
        lst = an.refs.get(ci)
        if not lst:
            if an.reach[ci]:
                key, kind, label, rname, path = "untracked", "untracked", "reached (referrer not recorded)", None, ""
            else:
                u = unreach.get(sz)
                if u is None:
                    u = unreach[sz] = {"count": 0, "bytes": 0, "mmapped": st == ST_MMAPPED, "arenas": Counter(),
                                       "usable_size": ct.usable_size(ci), "example": "0x%x" % (ct.addrs[ci] + 16)}
                u["count"] += 1
                u["bytes"] += sz
                u["arenas"][int(ct.arena[ci])] += 1
                continue
        else:
            node, suffix, root, _slot, _interior = lst[0]
            key, kind, label, rname, path = _owner_of(an, norm, node, suffix, root)
        o = owners.get(key)
        if o is None:
            o = owners[key] = {"kind": kind, "label": label, "root": rname, "count": 0, "bytes": 0, "paths": Counter(),
                               "arenas": Counter()}
        o["count"] += 1
        o["arenas"][int(ct.arena[ci])] += 1
        o["bytes"] += sz
        if path:
            o["paths"][path] += 1
    out["owners"] = owners
    out["unreachable"] = unreach
    return out


# --------------------------------------------------------------------------------------------- corroboration
def _request2chunk(req: int) -> int:
    return max(32, (req + 8 + 15) & ~15)


_TYPE_SIZE_CACHE: Dict[int, Dict[int, List[str]]] = {}


def candidate_types(analysis: Any, chunk_size: int) -> List[str]:
    """Named struct/class types of the main executable whose single-object allocation lands in this size class."""
    an = analysis.analyzer
    if an is None or not an.modules:
        return []
    idx = an.modules[0][1]
    table = _TYPE_SIZE_CACHE.get(id(idx))
    if table is None:
        table = {}
        for t in getattr(idx, "types_by_die", {}).values():
            if t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") and t.name and int(t.byte_size or 0) > 0:
                lst = table.setdefault(_request2chunk(int(t.byte_size)), [])
                label = ("struct " if t.tag == "DW_TAG_structure_type" else "class ") + t.name
                if label not in lst:
                    lst.append(label)
        _TYPE_SIZE_CACHE[id(idx)] = table
    return list(table.get(int(chunk_size), []))


def arena_threads(analysis: Any, threads: Sequence[Dict[str, Any]], pid: int,
                  max_region: int = 128 * 1024) -> Dict[int, Dict[str, Any]]:
    """Arena index -> the thread attached to it, when that is unambiguous.

    Evidence: glibc keeps ``thread_arena`` and ``tcache`` in each thread's TLS, which for threads created
    by pthread_create sits at the top of the thread's stack mapping (above the live stack).  A thread is
    named for arena A only when its stack-top region holds both A's address and the address of A's
    tcache_perthread_struct, it is the only such thread, and A's ``attached_threads`` counter is 1.  The
    main arena is named for the main thread when ``attached_threads`` is 1 and no other thread refers to it.
    """
    out: Dict[int, Dict[str, Any]] = {}
    an = analysis.analyzer
    walk = analysis.walk
    walker = getattr(an, "walker", None)
    layout = getattr(walker, "_layout", None)
    if an is None or layout is None or "attached_threads" not in layout.ms:
        return out
    arenas = []
    for info in walk.arenas:
        try:
            addr = int(str(info["address"]), 16)
        except (KeyError, TypeError, ValueError):
            continue
        ab = walker._arena_bytes(addr, layout)
        attached = struct.unpack_from("<Q", ab, layout.ms["attached_threads"])[0] if ab else None
        tc = [int(str(t["address"]), 16) for t in walk.tcache_structs if t.get("arena_index") == info["index"]]
        arenas.append((int(info["index"]), addr, attached, tc))
    from .heap_walker import _map_bounds
    regions = []
    known_stacks = set()
    unresolved = []
    for t in threads:
        si = t.get("stack_info") or {}
        s, e = int(si.get("start_int") or 0), int(si.get("end_int") or 0)
        if int(t.get("tid") or 0) == int(pid):
            continue
        if not (e > s > 0):
            unresolved.append(t)
            continue
        known_stacks.add(e)
        sp = int(si.get("sp_int") or 0)
        frm = max(s, e - max_region, (sp & ~7) if s <= sp < e else s)
        regions.append((t, frm, e))
    if unresolved:
        # A running thread exposes no stack pointer: its stack is an anonymous mapping right above a PROT_NONE
        # guard, and the thread descriptor at its top holds the TID (same matching as the conservative roots).
        ordered = sorted(walk.mappings, key=lambda mm: _map_bounds(mm)[0])
        cands = []
        for prev, cur in zip(ordered, ordered[1:]):
            ps, pe = _map_bounds(prev)
            cs, ce = _map_bounds(cur)
            if pe == cs and (prev.get("permissions") or "").startswith("---") and not cur.get("pathname") \
                    and "w" in (cur.get("permissions") or "") and ce not in known_stacks:
                cands.append((cs, ce))
        tops = an.reader.read_ranges([(max(s, e - max_region), e - max(s, e - max_region)) for s, e in cands]) \
            if cands else []
        for (s, e), data in zip(cands, tops):
            if not data:
                continue
            for t in list(unresolved):
                if struct.pack("<i", int(t.get("tid") or 0)) in data[-65536:]:
                    regions.append((t, e - len(data), e))
                    unresolved.remove(t)
                    break
    datas = an.reader.read_ranges([(s, e - s) for _, s, e in regions]) if regions else []
    hits: Dict[int, List[Dict[str, Any]]] = {}
    for (t, _s, _e), data in zip(regions, datas):
        if not data:
            continue
        for ai, addr, _att, tc in arenas:
            if struct.pack("<Q", addr) in data and (ai == 0 or any(struct.pack("<Q", x) in data for x in tc)):
                hits.setdefault(ai, []).append(t)
    main_tid = int(pid)
    main_name = next((t.get("name") for t in threads if int(t.get("tid") or 0) == main_tid), None)
    for ai, addr, attached, _tc in arenas:
        ts = hits.get(ai, [])
        if ai == 0:
            if attached == 1 and not ts and not unresolved:
                out[ai] = {"tid": main_tid, "name": main_name, "evidence": "main arena, attached_threads=1, "
                                                                          "no other thread refers to it"}
            continue
        if attached == 1 and len(ts) == 1:
            out[ai] = {"tid": ts[0].get("tid"), "name": ts[0].get("name"),
                       "evidence": "arena %d: attached_threads=1; the thread's TLS holds the arena and its "
                                   "tcache pointers" % ai}
        elif ts:
            out[ai] = {"ambiguous": True, "candidates": [x.get("name") for x in ts], "attached_threads": attached}
    return out


# --------------------------------------------------------------------------------------------- verdict
def _monotonic(series: List[int], tol: int = 0) -> bool:
    return all(b - a >= -tol for a, b in zip(series, series[1:]))


def judge(walks: List[Dict[str, Any]], cfg: MemoryObservationConfig) -> Dict[str, Any]:
    """Strict leak verdict over consecutive walk censuses (pure function)."""
    ok = [w for w in walks if w.get("owners") is not None and w.get("ok")]
    res: Dict[str, Any] = {"walks": len(ok), "facts": [], "limitations": [], "growth_owners": [],
                           "unreachable_growth": [], "held_growth": []}
    if len(ok) < cfg.min_walks:
        res["verdict"] = V_INSUFFICIENT
        res["limitations"].append("only %d usable heap walk(s); %d are needed to establish a trend"
                                  % (len(ok), cfg.min_walks))
        return res
    inuse = [w["in_use_bytes"] for w in ok]
    counts = [w["in_use_count"] for w in ok]
    dt = max(1e-6, ok[-1]["t"] - ok[0]["t"])
    res.update(in_use_bytes_series=inuse, in_use_count_series=counts, window_s=round(dt, 3),
               mmapped_bytes_series=[w["mmapped_bytes"] for w in ok],
               in_use_growth_bytes=inuse[-1] - inuse[0], in_use_growth_blocks=counts[-1] - counts[0],
               rate_kb_per_s=round((inuse[-1] - inuse[0]) / 1024.0 / dt, 1))
    tol = max(cfg.churn_tolerance_bytes, int(cfg.churn_tolerance_fraction * max(inuse)))
    drops = [(i, a - b) for i, (a, b) in enumerate(zip(inuse, inuse[1:])) if a - b > tol]
    res["in_use_monotonic_growth"] = False
    if drops:
        i, d = max(drops, key=lambda x: x[1])
        res["verdict"] = V_SHRANK
        res["facts"].append("in-use heap fell by %d KB between observations %d and %d (%s KB series): memory is "
                            "released (transient or periodic use), not a leak"
                            % (d // 1024, i + 1, i + 2, [x // 1024 for x in inuse]))
        return res
    if inuse[-1] - inuse[0] < cfg.min_inuse_growth_bytes:
        res["verdict"] = V_NO_GROWTH
        res["facts"].append("in-use heap stable across %d walks over %.2f s (%+d KB, %+d blocks)"
                            % (len(ok), dt, (inuse[-1] - inuse[0]) // 1024, counts[-1] - counts[0]))
        return res
    res["in_use_monotonic_growth"] = True

    def series_of(get) -> List[int]:
        return [get(w) for w in ok]

    keys = set()
    for w in ok:
        keys.update(w["owners"].keys())
    for k in sorted(keys):
        cnt = series_of(lambda w: w["owners"].get(k, {}).get("count", 0))
        byt = series_of(lambda w: w["owners"].get(k, {}).get("bytes", 0))
        if not (_monotonic(cnt) and byt[-1] - byt[0] >= cfg.min_class_growth_bytes
                and cnt[-1] - cnt[0] >= cfg.min_class_growth_blocks):
            continue
        last = ok[-1]["owners"][k]
        first_paths = ok[0]["owners"].get(k, {}).get("paths", Counter())
        pdelta = Counter({p: c - first_paths.get(p, 0) for p, c in last["paths"].items()})
        top = [p for p, d in pdelta.most_common(3) if d > 0]
        row = {"blocks_delta": cnt[-1] - cnt[0], "bytes_delta": byt[-1] - byt[0], "count_series": cnt,
               "rate_kb_per_s": round((byt[-1] - byt[0]) / 1024.0 / dt, 1), "owner_kind": last["kind"]}
        if last["kind"] in OWNED_KINDS and last.get("root"):
            ar = last.get("arenas") or Counter()
            row.update(variable=last["root"], variable_path=top[0] if top else last["root"],
                       growing_paths={p: pdelta[p] for p in top},
                       arena_index=(ar.most_common(1)[0][0] if ar else None),
                       mmapped=bool(ar) and ar.most_common(1)[0][0] == -1)
            res["growth_owners"].append(row)
            res["facts"].append(
                "unbounded growth under %s: +%d blocks / +%d KB in use over %.2f s (%.1f KB/s), still referenced "
                "from %s variable %s" % (row["variable_path"], row["blocks_delta"], row["bytes_delta"] // 1024, dt,
                                         row["rate_kb_per_s"], last["kind"], last["root"]))
        else:
            row["holder"] = last["label"]
            res["held_growth"].append(row)
    sizes = set()
    for w in ok:
        sizes.update(w["unreachable"].keys())
    for sz in sorted(sizes):
        cnt = series_of(lambda w: w["unreachable"].get(sz, {}).get("count", 0))
        if not (_monotonic(cnt) and cnt[-1] - cnt[0] >= cfg.min_class_growth_blocks
                and (cnt[-1] - cnt[0]) * sz >= cfg.min_class_growth_bytes):
            continue
        u = ok[-1]["unreachable"][sz]
        row = {"chunk_size": sz, "usable_size": u["usable_size"], "blocks_now": cnt[-1],
               "blocks_delta": cnt[-1] - cnt[0], "bytes_delta": (cnt[-1] - cnt[0]) * sz, "count_series": cnt,
               "mmapped": u["mmapped"], "rate_blocks_per_s": round((cnt[-1] - cnt[0]) / dt, 1),
               "arena_index": (u["arenas"].most_common(1)[0][0] if u["arenas"] else None),
               "owner": "unknown: no reference remains", "example_block": u["example"]}
        res["unreachable_growth"].append(row)
    res["unreachable_growth"].sort(key=lambda r: -r["bytes_delta"])
    res["held_growth"].sort(key=lambda r: -r["bytes_delta"])
    if res["unreachable_growth"]:
        res["verdict"] = V_LEAK_UNREACHABLE
    elif res["growth_owners"]:
        res["verdict"] = V_GROWTH_OWNED
    else:
        res["verdict"] = V_NOT_ESTABLISHED
        held = "; ".join("%s +%d KB" % (h["holder"], h["bytes_delta"] // 1024) for h in res["held_growth"][:3])
        res["limitations"].append(
            "growth observed, not established as a leak: in-use heap +%d KB over %.2f s, but the growth is %s"
            % ((inuse[-1] - inuse[0]) // 1024, dt,
               ("held by %s (a working set of running code or untyped data, not an owner that outlives it)" % held)
               if held else "not attributable to a growing owner or to unreachable blocks"))
    return res


def _unreachable_fact(row: Dict[str, Any], dt: float) -> str:
    s = ("%d in-use blocks of size class %d B (usable %d B) with no reachable path, +%d (+%d KB) over %.2f s; "
         "owner unknown: no reference remains" % (row["blocks_now"], row["chunk_size"], row["usable_size"],
                                                   row["blocks_delta"], row["bytes_delta"] // 1024, dt))
    if row.get("mmapped"):
        s += "; mmapped blocks (no arena)"
    if row.get("allocating_thread_name"):
        s += "; allocated in arena %s, whose only attached thread is %s (tid %s)" % (
            row.get("arena_index"), row["allocating_thread_name"], row.get("allocating_thread_tid"))
    elif row.get("arena_index") is not None and not row.get("mmapped"):
        s += "; allocated in arena %s" % row["arena_index"]
    if row.get("candidate_type"):
        s += "; the only DWARF type of the executable that fits this size class is %s" % row["candidate_type"]
    return s


# --------------------------------------------------------------------------------------------- walk series
def _remaining(budget: Any) -> Tuple[float, int]:
    if budget is None:
        return 30.0, 1 << 34
    try:
        wall = (float(budget.limits.max_wall_clock_ms) - float(budget.elapsed_ms)) / 1000.0
        byt = int(budget.limits.max_bytes_read) - int(budget.metrics.bytes_read)
        return max(0.0, wall), max(0, byt)
    except Exception:  # noqa: BLE001
        return 30.0, 1 << 34


def _walk_limits() -> Any:
    from .reachability import ReachabilityLimits
    # running threads expose no stack pointer: scan the top 1 MB of their stack, not the whole mapping (8 MB
    # by default) on every walk
    return ReachabilityLimits(max_stack_without_sp_bytes=1024 * 1024)


def run_walk_series(adapter: Any, pid: int, companion_elf: Optional[str], cfg: MemoryObservationConfig,
                    budget: Any = None, sleep: Callable[[float], None] = time.sleep) -> Dict[str, Any]:
    """``cfg.walks`` heap walks + reachability spaced over the observation window, within a share of the
    session's remaining budget.  Returns {status, walks: [census...], cost, limitations, last_analysis}."""
    from .heap_walker import remote_cost_note
    from .reachability import analyze_heap_ownership
    t0 = time.monotonic()
    rem_wall, rem_bytes = _remaining(budget)
    wall_allow = rem_wall * cfg.wall_fraction
    bytes_allow = int(rem_bytes * cfg.bytes_fraction)
    deadline = t0 + wall_allow
    n = max(cfg.min_walks, int(cfg.walks))
    spacing = max(cfg.interval_s, cfg.min_walk_spacing_s, cfg.window_s / (n - 1))
    out: Dict[str, Any] = {"status": INV_COMPLETED, "walks": [], "limitations": [], "bytes_read": 0,
                           "spacing_s": round(spacing, 3), "planned_walks": n,
                           "allowance": {"wall_s": round(wall_allow, 3), "bytes": bytes_allow}}
    last_an = None
    last_wall = 0.0
    t_first = None
    for i in range(n):
        now = time.monotonic()
        if i:
            target = t_first + i * spacing
            est = last_wall * 1.5 + 0.02
            if target + est > deadline:
                left = cfg.min_walks - len(out["walks"])
                if left > 0:
                    sp = (deadline - now - est * left) / left
                    if sp < cfg.min_walk_spacing_s:
                        out["limitations"].append("observation budget left room for only %d heap walk(s)"
                                                  % len(out["walks"]) + remote_cost_note(adapter))
                        break
                    target = now + sp
                else:
                    break
            if target > now:
                sleep(target - now)
        used = out["bytes_read"]
        if bytes_allow - used <= 0:
            out["limitations"].append("observation byte budget for heap walks exhausted after %d walk(s)"
                                      % len(out["walks"]) + remote_cost_note(adapter))
            break
        ws = time.monotonic()
        try:
            an = analyze_heap_ownership(
                pid, companion_elf_path=companion_elf, adapter=adapter, manager=None, cache=False,
                include_typed_locals=False, use_libc_debug_info=False, limits=_walk_limits(),
                budget_limits={"max_bytes_read": bytes_allow - used,
                               "max_wall_clock_ms": max(50.0, (deadline - ws) * 1000.0)})
        except Exception as exc:  # noqa: BLE001
            out["limitations"].append("heap walk %d failed: %s: %s" % (i + 1, type(exc).__name__, exc))
            break
        we = time.monotonic()
        last_wall = we - ws
        out["bytes_read"] += int(an.reader.bytes_read)
        if an.walk.status in _WALK_STATUS_UNSUPPORTED:
            out["status"] = INV_UNSUPPORTED
            out["unsupported_status"] = an.walk.status
            out["unsupported_reason"] = an.walk.message
            return out
        c = census(an)
        c["t"] = (ws + we) / 2.0
        c["ok"] = an.ok and an.walk.status in ("OK", "PARTIAL") and not an.info.get("reachability_error")
        c["wall_ms"] = round(last_wall * 1000.0, 1)
        c["bytes_read"] = int(an.reader.bytes_read)
        c["top_catch_up"] = int(getattr(an.analyzer, "walker", None).top_extensions) if an.analyzer else 0
        s = proc_memory_sample(adapter, pid)
        c["rss_kb"] = s["rss_kb"] if s else None
        c["heap_vma_kb"] = s["heap_vma_kb"] if s else None
        out["walks"].append(c)
        if not c["ok"]:
            out["limitations"].append("heap walk %d: %s %s" % (i + 1, an.status, an.message or
                                                               an.info.get("reachability_error") or ""))
            if an.walk.status == "BUDGET_EXHAUSTED" or an.info.get("reachability_error"):
                break
        if t_first is None:
            t_first = ws
        last_an = an
    out["last_analysis"] = last_an
    out["wall_s"] = round(time.monotonic() - t0, 3)
    if sum(1 for w in out["walks"] if w["ok"]) < cfg.min_walks:
        out["status"] = INV_LIMITED
    return out


def investigate(adapter: Any, pid: int, companion_elf: Optional[str], cfg: MemoryObservationConfig,
                budget: Any = None, reason: str = "") -> Dict[str, Any]:
    """Walk series + verdict + corroboration -> plain-data investigation record."""
    series = run_walk_series(adapter, pid, companion_elf, cfg, budget)
    inv: Dict[str, Any] = {"status": series["status"], "reason_run": reason, "walks": len(series["walks"]),
                           "limitations": list(series["limitations"]),
                           "cost": {"bytes_read": series["bytes_read"], "wall_s": series.get("wall_s"),
                                    "walk_wall_ms": [w["wall_ms"] for w in series["walks"]],
                                    "spacing_s": series["spacing_s"], "allowance": series["allowance"],
                                    "top_catch_up": [w.get("top_catch_up", 0) for w in series["walks"]]},
                           "heap_walks": [{k: w.get(k) for k in ("t", "in_use_count", "in_use_bytes", "mmapped_count",
                                                                  "mmapped_bytes", "rss_kb", "heap_vma_kb", "status",
                                                                  "wall_ms", "bytes_read")}
                                          for w in series["walks"]]}
    if series["status"] == INV_UNSUPPORTED:
        inv["verdict"] = V_UNSUPPORTED
        inv["unsupported_status"] = series.get("unsupported_status")
        inv["limitations"].append("leak owner attribution not supported on this target: %s (%s)"
                                  % (series.get("unsupported_status"), series.get("unsupported_reason")))
        return inv
    j = judge(series["walks"], cfg)
    for k, v in j.items():
        if k == "limitations":
            inv["limitations"].extend(v)
        else:
            inv[k] = v
    an = series.get("last_analysis")
    # IMP-009: the last walk (object, not plain data) is handed to the session state by attach_memory_observation
    # so the integrity check can re-use it instead of walking again; never part of the recorded investigation
    inv["_analysis"] = an
    dt = float(j.get("window_s") or 0.0)
    if an is not None and (j.get("unreachable_growth") or j.get("growth_owners")):
        before = int(an.reader.bytes_read)
        try:
            threads = adapter.get_threads(pid) or []
        except Exception:  # noqa: BLE001
            threads = []
        try:
            owners = arena_threads(an, threads, pid)
        except Exception as exc:  # noqa: BLE001
            owners = {}
            inv["limitations"].append("arena-to-thread attribution failed: %s" % exc)
        # transparency (no subject keys here: names only reach subjects through an unambiguous row below)
        inv["arena_attribution"] = {
            str(k): {"thread": v.get("name"), "evidence": v.get("evidence"), "ambiguous": bool(v.get("ambiguous")),
                     "candidates": v.get("candidates")} for k, v in owners.items()}
        inv["arena_attribution_threads_seen"] = len(threads)
        for row in j["growth_owners"] + j["unreachable_growth"]:
            if not row.get("mmapped") and row.get("arena_index") is not None and row.get("arena_index") >= 0:
                at = owners.get(int(row["arena_index"]))
                if at and not at.get("ambiguous") and at.get("name"):
                    row["allocating_thread_name"] = at["name"]
                    row["allocating_thread_tid"] = at["tid"]
                    row["arena_evidence"] = at["evidence"]
                elif at and at.get("ambiguous"):
                    row["arena_threads_ambiguous"] = at.get("candidates")
                if "chunk_size" in row:
                    types = candidate_types(an, row["chunk_size"])
                    if len(types) == 1:
                        row["candidate_type"] = types[0]
                    elif types:
                        row["candidate_types_ambiguous"] = types[:8]
            if "chunk_size" in row:
                inv["facts"].append(_unreachable_fact(row, dt))
            elif row.get("allocating_thread_name"):
                inv["facts"].append("the blocks growing under %s are in arena %s, whose only attached thread is %s "
                                    "(tid %s)" % (row["variable_path"], row["arena_index"],
                                                  row["allocating_thread_name"], row["allocating_thread_tid"]))
        inv["cost"]["bytes_read"] += int(an.reader.bytes_read) - before
    inv["summary"] = "; ".join(inv.get("facts") or []) or "; ".join(inv["limitations"]) or inv.get("verdict", "")
    return inv


# --------------------------------------------------------------------------------------------- provider glue


def _memory_interest(recipe_id: str, classification: Any, cfg: MemoryObservationConfig) -> Optional[str]:
    from .diagnostic_recipes import DiagnosticRecipeRegistry
    if classification is not None and getattr(classification, "primary_category", None) == "MEMORY_LEAK":
        return "symptom classified as MEMORY_LEAK"
    if cfg.target_recipe:
        tr = DiagnosticRecipeRegistry.get_recipe(cfg.target_recipe)
        if tr is not None and tr.domain == "MEMORY_GROWTH":
            return "targeted memory recipe %s" % cfg.target_recipe
    # A memory recipe in the plan is not enough by itself: the planner adds memory recipes for unrelated symptom
    # classes (FUNCTIONAL_STATE_INCONSISTENCY); without a memory symptom the cheap trend decides.
    return None


def _ensure_cheap_trend(provider: Any, pid: int, companion_elf: Optional[str], cfg: MemoryObservationConfig) -> List[Dict[str, Any]]:
    st = _state(provider)
    samples = st["cosamples"].setdefault(int(pid), [])
    if len(samples) < 2 and getattr(provider, "thread_series_cache", None) is not None:
        # Share the thread sampler's window (it is a baseline check and would run anyway): sample it now; the
        # thread recipes later reuse the cached series.
        from .diagnostic_recipes import DiagnosticRecipeRegistry
        thr = DiagnosticRecipeRegistry.get_recipe("RECIPE_THREAD_STATE_ANOMALIES")
        if thr is not None:
            try:
                provider._collect_thread_series(thr, pid, companion_elf, {}, [])
            except Exception:  # noqa: BLE001
                pass
    budget = getattr(provider, "budget_tracker", None)
    while len(samples) < 2:
        rem_wall, _ = _remaining(budget)
        if rem_wall < cfg.own_sample_interval_s * 3:
            break
        if samples:
            time.sleep(cfg.own_sample_interval_s)
        s = proc_memory_sample(provider.adapter, pid)
        if s is None:
            break
        s["source"] = "own_window"
        samples.append(s)
    s = proc_memory_sample(provider.adapter, pid)
    if s is not None:
        if samples and s["t"] - samples[-1]["t"] < 0.05:
            time.sleep(0.05)
            s = proc_memory_sample(provider.adapter, pid) or s
        s["source"] = "recipe"
        samples.append(s)
    return samples


def attach_memory_observation(provider: Any, recipe: Any, pid: int, companion_elf: Optional[str],
                              classification: Any, session_id: Optional[str], observation_data: Dict[str, Any],
                              records: List[Any], target_key: Optional[str] = None) -> None:
    """Called at the end of the provider's memory branch.  Adds ``memory_trend`` / ``leak_investigation`` and
    a multi-observation ``observation_window`` (one investigation per session and pid, shared by the memory
    recipes of the run)."""
    from .runtime_evidence_provider import RuntimeEvidenceRecord, COLLECTION_STATUS_SUCCESS, \
        COLLECTION_STATUS_PARTIAL, PROVENANCE_LIVE_RUNTIME_CAPTURE
    from .temporal_observation_window import MemorySample, ObservationWindow
    import uuid
    cfg: MemoryObservationConfig = provider.memory_observation
    rid = getattr(recipe, "recipe_id", str(recipe))
    st = _state(provider)
    key = (session_id or "default", int(pid))
    inv = st["investigations"].get(key)
    fresh = False
    if inv is None or (inv.get("status") == INV_NOT_RUN and _memory_interest(rid, classification, cfg)):
        samples = _ensure_cheap_trend(provider, pid, companion_elf, cfg)
        trend = cheap_trend(samples, cfg)
        reason = None
        if trend["indicates_growth"]:
            reason = "cheap /proc trend shows growth (RSS %+d KB, anonymous mappings %+d KB over %.2f s)" % (
                trend.get("rss_growth_kb", 0), trend.get("anon_rw_growth_kb", 0), trend["window_s"])
        else:
            reason = _memory_interest(rid, classification, cfg)
        if reason:
            inv = investigate(provider.adapter, pid, companion_elf, cfg, getattr(provider, "budget_tracker", None),
                              reason=reason)
            an_obj = inv.pop("_analysis", None)
            if an_obj is not None:
                st.setdefault("analyses", {})[key] = an_obj
        else:
            inv = {"status": INV_NOT_RUN, "verdict": V_NO_TREND if trend["established"] else V_INSUFFICIENT,
                   "walks": 0, "limitations": [] if trend["established"] else
                   ["fewer than 3 memory samples could be taken"], "cost": {"bytes_read": 0},
                   "summary": "no growth trend (RSS %+d KB over %.2f s, %d samples): heap walks not needed"
                              % (trend.get("rss_growth_kb", 0), trend["window_s"], trend["samples"])}
        inv["memory_trend"] = trend
        st["investigations"][key] = inv
        fresh = True

    trend = inv.get("memory_trend") or {}
    observation_data["memory_trend"] = trend
    observation_data["leak_investigation"] = {k: v for k, v in inv.items() if k != "memory_trend"}
    if fresh and inv.get("cost", {}).get("bytes_read"):
        observation_data["bytes_read"] = int(inv["cost"]["bytes_read"])

    # Multi-observation window: the walk series when walks ran, else the cheap samples.
    win = ObservationWindow(target_pid=pid, target_identity=target_key or "local")
    walks = inv.get("heap_walks") or []
    use_walks = sum(1 for w in walks if w.get("in_use_bytes") is not None) >= 3
    if use_walks:
        for i, w in enumerate(walks, 1):
            win.record_sample(MemorySample(epoch_id=i, monotonic_timestamp=float(w["t"]), rss_kb=w.get("rss_kb"),
                                           heap_vma_kb=w.get("heap_vma_kb"),
                                           allocator_heap_kb=int(w["in_use_bytes"]) // 1024,
                                           live_allocations_count=int(w["in_use_count"])))
        rss = [w.get("rss_kb") for w in walks if w.get("rss_kb") is not None]
    else:
        ss = sorted(st["cosamples"].get(int(pid), []), key=lambda s: s["t"])
        for i, s in enumerate(ss, 1):
            win.record_sample(MemorySample(epoch_id=i, monotonic_timestamp=s["t"], rss_kb=s["rss_kb"],
                                           heap_vma_kb=s["heap_vma_kb"]))
        rss = [s["rss_kb"] for s in ss]
    if win.successful_sample_count() >= 3:
        observation_data["observation_window"] = win
        observation_data["rss_history_kb"] = rss
        observation_data["epoch_count"] = win.successful_sample_count()
        observation_data["samples_count"] = win.sample_count()
        # The legacy per-step sample history (steps run milliseconds apart) is superseded by this series.
        for k in ("insufficient_temporal_separation", "out_of_order_epoch_detected"):
            observation_data.pop(k, None)
    if use_walks:
        series = [int(w["in_use_bytes"]) // 1024 for w in walks]
        observation_data["heap_series_kb"] = series
        observation_data["heap_growth_bytes"] = (series[-1] - series[0]) * 1024
        observation_data["live_allocations_count"] = walks[-1]["in_use_count"]
        observation_data["allocator_heap_kb"] = series[-1]

    if fresh:
        ran = inv.get("walks", 0) > 0
        records.append(RuntimeEvidenceRecord(
            evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
            collection_method="heap_walk_series" if ran else "proc_memory_trend",
            target_pid=pid,
            observed_value={"verdict": inv.get("verdict"), "summary": inv.get("summary"),
                            "walks": inv.get("walks"), "trend_samples": trend.get("samples")},
            collection_scope="HEAP_WALK_SERIES" if ran else "PROC_MEMORY_TREND",
            collection_status=COLLECTION_STATUS_SUCCESS if inv.get("status") in (INV_COMPLETED, INV_NOT_RUN)
            else COLLECTION_STATUS_PARTIAL,
            limitations=list(inv.get("limitations") or []),
            provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
            raw_details={"cost": inv.get("cost"), "reason_run": inv.get("reason_run")},
        ))
