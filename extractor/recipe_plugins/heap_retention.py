"""Heap retention / fragmentation - registered entirely from this file (IMP-018 recipe definition file).

"RSS is high but nothing is leaking": the malloc arenas hold far more memory from the system than the program has
in use, because the freed blocks sit between live ones (fragmentation) or in caches, and glibc can only return the
free space at the top of a heap.  This is an explanation and a degradation, never a fault: a finding of this check
carries ``finding_severity = "INFO"`` and, when it is the only finding, the diagnosis verdict is DEGRADED.

Observation kind ``heap_retention`` (read-only, zero-stop, no ptrace):

1. /proc sample (heap mapping size = ``[heap]`` + thread-arena heaps, RSS); a heap below ``MIN_SYSTEM_MEM`` is too
   small for this to matter and is decided from /proc alone (no walk);
2. a second /proc sample ``FLAT_WINDOW_S`` later: a heap whose mappings grow is not assessed (the growth checks
   own that question) and is not walked;
3. one heap walk (``extractor.heap_walker``): the leak investigation's or the integrity check's walk of this
   session when one exists, else an own walk when the estimated heap is at most ``MAX_OWN_WALK_BYTES`` and fits in
   ``BYTES_FRACTION`` of the session's remaining byte budget;
4. per arena: ``system_mem`` (from the arena), in-use chunk bytes, free chunk bytes (bins + tcache + fastbins)
   and count, top chunk; mmapped chunks separately (they are returned on free);
5. a last /proc sample after the walk (heap mappings and RSS still flat).

Verdict rule (``thresholds_and_conditions``)
    SUPPORTED     arena memory >= MIN_SYSTEM_MEM, free-but-held >= MIN_FREE_HELD and >= MIN_FREE_RATIO of the arena
                  memory, and in-use is flat (heap mappings unchanged and RSS within tolerance across the samples;
                  in-use within tolerance across the leak investigation's walks when there are two or more).
                  Category HEAP_RETENTION, severity INFO (not a fault), capped at probable.
    CONTRADICTED  the heap is below MIN_SYSTEM_MEM, or the walk shows little free-but-held memory.
    INSUFFICIENT  no walk (unsupported allocator, budget, heap above the own-walk cap) or the heap is growing.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from ..diagnostic_recipes import (
    CATEGORY_MEMORY_LEAK,
    DOMAIN_MEMORY_GROWTH,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipe,
    RecipeEvaluationResult,
    register_recipe,
)
from ..runtime_evidence_provider import register_observation_collector

RECIPE_HEAP_RETENTION = "RECIPE_HEAP_RETENTION"
CATEGORY_HEAP_RETENTION = "HEAP_RETENTION"
OBS_HEAP_RETENTION = "heap_retention"

MIN_SYSTEM_MEM = 16 << 20        # arena memory below this is a small heap: never reported
MIN_FREE_HELD = 8 << 20          # free chunks (bins + tcache + fastbins) the arenas keep
MIN_FREE_RATIO = 0.5             # ... at least half of what the arenas took from the system
FLAT_WINDOW_S = 0.3
FLAT_HEAP_TOL = 64 << 10         # heap mapping change tolerated as "flat"
FLAT_RSS_TOL_KB = 256            # RSS change tolerated as "flat" (or 1 %)
FLAT_INUSE_TOL = 64 << 10        # in-use change across leak walks tolerated as "flat" (or 1 %)
MAX_OWN_WALK_BYTES = 64 << 20
BYTES_FRACTION = 0.75
WALL_FRACTION = 0.6

_UNSUPPORTED = ("UNSUPPORTED_ALLOCATOR", "UNSUPPORTED_GLIBC_VERSION", "INCONCLUSIVE_ABI_UNDETECTED", "ARENA_NOT_FOUND")


def _proc(adapter: Any, pid: int) -> Optional[Dict[str, Any]]:
    from ..memory_integrity import heap_size_estimate
    try:
        st = adapter.get_process_status(pid) or {}
        maps = adapter.get_proc_maps(pid) or []
        rss = int(str(st.get("VmRSS")).split()[0])
    except Exception:  # noqa: BLE001
        return None
    return {"t": time.monotonic(), "heap_bytes": heap_size_estimate(maps), "rss_kb": rss}


def _shared_walk(provider: Any, key: Any) -> Any:
    an = ((getattr(provider, "_imp008_state", None) or {}).get("analyses") or {}).get(key)
    if an is not None and getattr(an, "walk", None) is not None and an.walk.ok:
        return an.walk, "leak_investigation"
    objs = (getattr(provider, "_imp009_state", None) or {}).get(("walk_objects",) + key) or {}
    w = objs.get("walk")
    if w is not None and w.ok:
        return w, "integrity_check"
    return None, None


def _own_walk(provider: Any, pid: int, est: int) -> Dict[str, Any]:
    from ..heap_walker import BudgetedReader, HeapWalker
    from ..memory_integrity import _remaining
    from ..observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
    wall, byt = _remaining(getattr(provider, "budget_tracker", None))
    allow = int(byt * BYTES_FRACTION)
    if est > MAX_OWN_WALK_BYTES:
        return {"status": "NOT_CHECKED", "reason": "heap (%.1f MiB) above the walk cap of this check (%.0f MiB)"
                % (est / 1048576.0, MAX_OWN_WALK_BYTES / 1048576.0)}
    if allow < est + 65536:
        return {"status": "NOT_CHECKED", "reason": "the observation byte budget left (%d bytes) is below the heap size "
                "(%d bytes)" % (allow, est)}
    hb = ObservationBudgetTracker(ObservationBudgetLimits(
        max_wall_clock_ms=max(100.0, wall * WALL_FRACTION * 1000.0), max_bytes_read=max(65536, allow),
        max_samples=1 << 30, max_bytes_per_observation=1 << 40, max_consecutive_read_failures=1 << 20,
        max_total_read_failures=1 << 20))
    reader = BudgetedReader(adapter=provider.adapter, pid=pid, budget=hb, profile_id="heap_retention")
    walk = HeapWalker(provider.adapter, pid, budget=hb, reader=reader, use_libc_debug_info=False).walk()
    return {"walk": walk, "bytes_read": int(reader.bytes_read)}


def arena_usage(walk: Any) -> Dict[str, Any]:
    """Per arena: system memory, in-use / free / top bytes and free chunk counts from one walk (pure)."""
    from ..heap_walker import ST_FASTBIN, ST_FREE, ST_INTERNAL, ST_IN_USE, ST_MMAPPED, ST_TCACHE, ST_TOP
    ct = walk.chunks
    rows: Dict[int, Dict[str, Any]] = {}
    for a in walk.arenas:
        rows[int(a.get("index", len(rows)))] = {"index": int(a.get("index", len(rows))), "is_main": bool(a.get("is_main")),
                                               "system_mem": int(a.get("system_mem") or 0), "in_use_bytes": 0,
                                               "free_bytes": 0, "free_chunks": 0, "top_bytes": 0,
                                               "free_by_list": {"bins": 0, "tcache": 0, "fastbins": 0},
                                               "largest_free": 0}
    mm_bytes = mm_count = 0
    lists = {ST_FREE: "bins", ST_TCACHE: "tcache", ST_FASTBIN: "fastbins"}
    for i in range(len(ct)):
        st, ai, sz = ct.states[i], int(ct.arena[i]), int(ct.sizes[i])
        if st == ST_MMAPPED or ai < 0:
            mm_bytes += sz
            mm_count += 1
            continue
        r = rows.setdefault(ai, {"index": ai, "is_main": ai == 0, "system_mem": 0, "in_use_bytes": 0, "free_bytes": 0,
                                 "free_chunks": 0, "top_bytes": 0, "free_by_list": {"bins": 0, "tcache": 0,
                                                                                   "fastbins": 0}, "largest_free": 0})
        if st in (ST_IN_USE, ST_INTERNAL):
            r["in_use_bytes"] += sz
        elif st in lists:
            r["free_bytes"] += sz
            r["free_chunks"] += 1
            r["free_by_list"][lists[st]] += sz
            r["largest_free"] = max(r["largest_free"], sz)
        elif st == ST_TOP:
            r["top_bytes"] += sz
    arenas = [r for _, r in sorted(rows.items())]
    tot = {k: sum(r[k] for r in arenas) for k in ("system_mem", "in_use_bytes", "free_bytes", "free_chunks", "top_bytes")}
    tot["largest_free"] = max((r["largest_free"] for r in arenas), default=0)
    return {"arenas": arenas, "totals": tot, "mmapped_bytes": mm_bytes, "mmapped_chunks": mm_count}


def _leak_walks(provider: Any, key: Any) -> List[Dict[str, Any]]:
    inv = ((getattr(provider, "_imp008_state", None) or {}).get("investigations") or {}).get(key) or {}
    return [{"t": w["t"], "in_use_bytes": w["in_use_bytes"]} for w in inv.get("heap_walks") or []
            if isinstance(w, dict) and w.get("status") == "OK" and isinstance(w.get("in_use_bytes"), int)]


def collect_heap_retention(provider: Any, ctx: Dict[str, Any]) -> None:
    from ..runtime_evidence_provider import (COLLECTION_STATUS_PARTIAL, COLLECTION_STATUS_SUCCESS,
                                             PROVENANCE_LIVE_RUNTIME_CAPTURE, RuntimeEvidenceRecord)
    pid = int(ctx["pid"])
    key = (ctx.get("session_id") or "default", pid)
    od = ctx["observation_data"]
    obs: Dict[str, Any] = {"status": "NOT_CHECKED", "proc_samples": [], "limitations": []}
    t0 = time.monotonic()

    def sample() -> Optional[Dict[str, Any]]:
        s = _proc(provider.adapter, pid)
        if s is not None:
            obs["proc_samples"].append({"t_s": round(s["t"] - t0, 3), "heap_mapping_bytes": s["heap_bytes"],
                                        "rss_kb": s["rss_kb"]})
        return s

    s0 = sample()
    walk, source, nbytes = None, None, 0
    if s0 is None:
        obs["reason"] = "/proc/<pid>/maps or status could not be read"
    elif s0["heap_bytes"] < MIN_SYSTEM_MEM:
        obs["status"] = "SMALL_HEAP"
        obs["reason"] = "heap mappings %.1f MiB, below %.0f MiB" % (s0["heap_bytes"] / 1048576.0, MIN_SYSTEM_MEM / 1048576.0)
    else:
        time.sleep(FLAT_WINDOW_S)
        s1 = sample()
        if s1 is None or abs(s1["heap_bytes"] - s0["heap_bytes"]) > FLAT_HEAP_TOL:
            obs["status"] = "HEAP_GROWING" if s1 is not None else "NOT_CHECKED"
            obs["reason"] = "the heap mappings changed during the observation: retention is not assessed while the " \
                            "heap grows or shrinks"
        else:
            walk, source = _shared_walk(provider, key)
            if walk is None:
                own = _own_walk(provider, pid, s1["heap_bytes"])
                walk, nbytes = own.get("walk"), int(own.get("bytes_read") or 0)
                source = "own_walk" if walk is not None else None
                if walk is None:
                    obs["reason"] = own.get("reason")
            if walk is not None and walk.status in _UNSUPPORTED:
                obs["status"] = "UNSUPPORTED"
                obs["reason"] = "%s: %s" % (walk.status, walk.message)
                walk = None
            elif walk is not None and not walk.ok:
                obs["reason"] = "heap walk incomplete: %s (%s)" % (walk.status, walk.message)
                walk = None
            if walk is not None:
                obs.update(arena_usage(walk))
                obs["status"] = "COMPLETED"
                obs["walk_source"] = source
                obs["walk_status"] = walk.status
                obs["counts_by_state"] = (walk.counts() or {}).get("by_state")
                if time.monotonic() - t0 < 2 * FLAT_WINDOW_S:
                    time.sleep(max(0.0, 2 * FLAT_WINDOW_S - (time.monotonic() - t0)))
                sample()
    obs["leak_walks"] = _leak_walks(provider, key)
    if obs.get("reason"):
        obs["limitations"].append("heap retention: " + str(obs["reason"]))
    obs["bytes_read"] = nbytes
    od[OBS_HEAP_RETENTION] = obs
    if nbytes:
        od["bytes_read"] = int(od.get("bytes_read") or 0) + nbytes
    ctx["all_records"].append(RuntimeEvidenceRecord(
        evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
        collection_method="heap_arena_usage",
        target_pid=pid,
        observed_value={"status": obs["status"], "totals": obs.get("totals"), "walk_source": obs.get("walk_source")},
        collection_scope="HEAP_RETENTION",
        collection_status=COLLECTION_STATUS_SUCCESS if obs["status"] in ("COMPLETED", "SMALL_HEAP")
        else COLLECTION_STATUS_PARTIAL,
        limitations=list(obs["limitations"]),
        provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
        raw_details={"bytes_read": nbytes},
    ))
    return None


def _mib(n: Any) -> str:
    v = float(n or 0)
    if v < 1024:
        return "%d B" % v  # chunks below 1 KB are printed in bytes, never as "0 KB"
    return "%.1f MiB" % (v / 1048576.0) if v >= 1 << 20 else "%d KB" % (v // 1024)


def heap_retention_rule(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    rid = recipe.recipe_id
    hr = data.get(OBS_HEAP_RETENTION) or {}
    lims = list(hr.get("limitations") or [])
    st = hr.get("status")
    details: Dict[str, Any] = {"heap_retention": hr, "limitations": lims}
    if st == "SMALL_HEAP":
        txt = "heap too small for retention to matter: %s" % hr.get("reason")
        return RecipeEvaluationResult(recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.8,
                                      confidence_basis=txt, contradicting_facts=[txt],
                                      recommended_action="No heap retention to explain.", details=details)
    tot = hr.get("totals") or {}
    if st != "COMPLETED" or not tot:
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.1,
            confidence_basis="; ".join(lims) or "heap retention not assessed", missing_evidence=["heap_walk"],
            limitations=lims, details=details)
    sysm, inuse, free, top = (int(tot.get(k) or 0) for k in ("system_mem", "in_use_bytes", "free_bytes", "top_bytes"))
    ratio = free / sysm if sysm else 0.0
    shape = ("arenas hold %s from the system: %s in use, %s free in %d free chunks (%.0f %%), top %s"
             % (_mib(sysm), _mib(inuse), _mib(free), int(tot.get("free_chunks") or 0), ratio * 100, _mib(top)))
    details.update(arena_system_bytes=sysm, in_use_bytes=inuse, free_held_bytes=free, free_ratio=round(ratio, 3))
    if sysm < MIN_SYSTEM_MEM or free < MIN_FREE_HELD or ratio < MIN_FREE_RATIO:
        txt = "the heap holds little free memory: " + shape
        return RecipeEvaluationResult(recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.8,
                                      confidence_basis=txt, contradicting_facts=[txt],
                                      recommended_action="No heap retention to explain.", details=details)
    ps = [p for p in hr.get("proc_samples") or [] if isinstance(p, dict)]
    flat_why = []
    if len(ps) < 2:
        flat_why.append("fewer than 2 /proc samples")
    else:
        hb = [int(p["heap_mapping_bytes"]) for p in ps]
        rss = [int(p["rss_kb"]) for p in ps]
        if max(hb) - min(hb) > FLAT_HEAP_TOL:
            flat_why.append("heap mappings changed by %d KB" % ((max(hb) - min(hb)) // 1024))
        if max(rss) - min(rss) > max(FLAT_RSS_TOL_KB, 0.01 * max(rss)):
            flat_why.append("RSS changed by %d KB" % (max(rss) - min(rss)))
    lw = hr.get("leak_walks") or []
    if len(lw) >= 2:
        iu = [int(w["in_use_bytes"]) for w in lw]
        if max(iu) - min(iu) > max(FLAT_INUSE_TOL, 0.01 * max(iu)):
            flat_why.append("in-use heap changed by %d KB across %d heap walks" % ((max(iu) - min(iu)) // 1024, len(iu)))
    if flat_why:
        txt = "heap retention seen (%s) but in-use is not shown flat: %s" % (shape, "; ".join(flat_why))
        return RecipeEvaluationResult(recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.3,
                                      confidence_basis=txt, missing_evidence=["flat_in_use_heap"],
                                      limitations=lims + [txt], details=details)
    win = float(ps[-1]["t_s"]) - float(ps[0]["t_s"])
    facts = ["memory held by the heap but not in use: " + shape,
             "heap mappings and RSS flat over %.1f s (%d samples)" % (win, len(ps))
             + ("; in-use heap flat across %d heap walks" % len(lw) if len(lw) >= 2 else "")]
    big = max(hr.get("arenas") or [{}], key=lambda r: int(r.get("free_bytes") or 0))
    if big:
        facts.append("most free memory in arena %s (%s): %s free in %d chunks%s"
                     % (big.get("index"), "main" if big.get("is_main") else "thread", _mib(big.get("free_bytes")),
                        int(big.get("free_chunks") or 0),
                        ", largest free chunk %s" % _mib(big.get("largest_free")) if big.get("largest_free") else ""))
    details.update(finding_category=CATEGORY_HEAP_RETENTION, finding_severity="INFO", non_fault=True,
                   finding_summary=facts[0], certainty_cap="PROBABLE",
                   certainty_cap_reason="retention explains a high RSS; it is a degradation, not a fault")
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.75, confidence_basis=facts[0],
        supporting_facts=facts, limitations=lims,
        recommended_action="Not a leak. To return the memory: malloc_trim(0), fewer arenas (MALLOC_ARENA_MAX), "
                           "or allocate long-lived and short-lived objects from different pools.",
        details=details)


register_observation_collector(OBS_HEAP_RETENTION, collect_heap_retention)
register_recipe(DiagnosticRecipe(
    recipe_id=RECIPE_HEAP_RETENTION,
    version="1.0.0",
    name="Heap Retention / Fragmentation (memory held by malloc, not in use)",
    domain=DOMAIN_MEMORY_GROWTH,
    # first category = the category of this check's evidence; MEMORY_LEAK only plans it for memory symptoms
    applicable_problem_categories=[CATEGORY_HEAP_RETENTION, CATEGORY_MEMORY_LEAK],
    required_prerequisites=[],
    evidence_sources=["/proc/<pid>/maps", "/proc/<pid>/status", "heap_walk (arena system_mem, chunk states)"],
    collection_steps=[
        {"step": 1, "action": "proc_samples", "purpose": "heap mapping size and RSS, flat?"},
        {"step": 2, "action": "heap_walk", "purpose": "shared walk of the session, else one bounded own walk"},
        {"step": 3, "action": "arena_usage", "purpose": "system_mem vs in-use vs free vs top per arena"},
    ],
    analysis_rules=["arena memory >= %d MiB with >= %d MiB (>= %d %%) in free chunks while in-use is flat is "
                    "retention (a degradation, not a fault)"
                    % (MIN_SYSTEM_MEM >> 20, MIN_FREE_HELD >> 20, int(MIN_FREE_RATIO * 100))],
    thresholds_and_conditions={"min_system_mem_bytes": MIN_SYSTEM_MEM, "min_free_held_bytes": MIN_FREE_HELD,
                               "min_free_ratio": MIN_FREE_RATIO, "flat_window_s": FLAT_WINDOW_S,
                               "flat_heap_tolerance_bytes": FLAT_HEAP_TOL, "flat_rss_tolerance_kb": FLAT_RSS_TOL_KB,
                               "max_own_walk_bytes": MAX_OWN_WALK_BYTES},
    supporting_evidence_criteria=["large free-but-held arena memory with flat in-use"],
    contradicting_evidence_criteria=["small heap", "little free memory in the arenas"],
    verification_procedure="Call malloc_trim(0) in a test build: RSS falls by about the free-but-held amount.",
    stop_conditions=["heap not walkable / above the walk cap / budget"],
    limitations=["free pages inside large free chunks may already have been returned with madvise; free-but-held "
                 "is address space the allocator keeps, an upper bound of what RSS could shrink by",
                 "a heap above %d MiB, or one that grows or shrinks during the check, is not assessed"
                 % (MAX_OWN_WALK_BYTES >> 20)],
    output_structure={"arenas": "list[{index, system_mem, in_use_bytes, free_bytes, free_chunks, top_bytes}]"},
    observations=(OBS_HEAP_RETENTION,),
    rule=heap_retention_rule,
), baseline=False, category=CATEGORY_HEAP_RETENTION)


# ---------------------------------------------------------------------------------------------- presentation
# How this diagnosis is shown to a person (extractor/report_registry.py): en and ko text, the HTML picture.
_TXT = {
    "held": ("The malloc arenas hold {sys} from the system, but only {inuse} of it is in use; {free} ({pct}%) "
             "sits in {n} free chunks and {top} is the free top of the heap.",
             "malloc 아레나가 시스템에서 {sys}를 받아 두고 있지만 사용 중인 것은 {inuse}뿐입니다. {free} ({pct}%)는 "
             "빈 청크 {n}개에, {top}는 힙 맨 끝(top)에 비어 있습니다."),
    "flat": ("The heap mappings and RSS did not change over {win} s ({n} samples){walks}: this is memory kept by "
             "the allocator, not a leak.",
             "{win}초 동안({n}회 샘플) 힙 매핑과 RSS가 변하지 않았습니다{walks}. 누수가 아니라 할당자가 붙잡고 있는 "
             "메모리입니다."),
    "flat_walks": ("; the heap in use was flat across {n} heap walks", ". 힙 조사 {n}회 동안 사용 중인 힙도 그대로였습니다"),
    "arena": ("Most of it is in arena {idx} ({kind}): {free} free in {n} chunks{big}.",
              "대부분은 아레나 {idx}({kind})에 있습니다: 빈 청크 {n}개에 {free}{big}."),
    "arena_big": (", the largest free chunk {big}", ", 가장 큰 빈 청크 {big}"),
    "main": ("main", "메인"), "thread": ("thread arena", "스레드 아레나"),
    "why": ("glibc gives memory back to the system only from the top of a heap; free chunks between blocks still in "
            "use stay mapped. Which allocation pattern left these gaps was not observed.",
            "glibc는 힙의 맨 끝(top)에서만 메모리를 시스템에 돌려줍니다. 사용 중인 블록 사이의 빈 청크는 매핑된 채 "
            "남습니다. 어떤 할당 패턴이 이 빈틈을 남겼는지는 관측되지 않았습니다."),
    "bars": ("Arena {idx} ({kind}): memory taken from the system", "아레나 {idx}({kind}): 시스템에서 받은 메모리"),
    "b_inuse": ("in use", "사용 중"), "b_free": ("free but held", "비었지만 보유"), "b_top": ("top (free)", "top (빈 공간)"),
    "lists": ("Free chunks by list", "목록별 빈 청크"),
    "who": ("Allocation pattern that left the gaps", "빈틈을 남긴 할당 패턴"),
    "src_leak_investigation": ("Heap walk: the leak investigation's walk of this diagnosis",
                               "힙 조사: 이번 진단의 누수 조사에서 한 힙 조사"),
    "src_integrity_check": ("Heap walk: the integrity check's walk of this diagnosis",
                            "힙 조사: 이번 진단의 무결성 검사에서 한 힙 조사"),
    "src_own_walk": ("Heap walk: one walk of this check", "힙 조사: 이 검사가 한 1회 조사"),
}


def _hr_obs(report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    checks = ((report or {}).get("section_d_detailed_inspection_results") or {}).get("checks") or []
    for c in checks:
        if isinstance(c, dict) and c.get("recipe_id") == RECIPE_HEAP_RETENTION:
            hr = (c.get("actual_observations") or {}).get(OBS_HEAP_RETENTION)
            if isinstance(hr, dict):
                return hr
    return {}


def _n(x: Any) -> int:
    return int(x) if isinstance(x, (int, float)) and not isinstance(x, bool) else 0


def _hr_facts(i: int, hr: Dict[str, Any]) -> List[str]:
    tot = hr.get("totals") if isinstance(hr.get("totals"), dict) else {}
    if not tot or not _n(tot.get("system_mem")):
        return []
    sysm = _n(tot.get("system_mem"))
    out = [_TXT["held"][i].format(sys=_mib(sysm), inuse=_mib(_n(tot.get("in_use_bytes"))),
                                   free=_mib(_n(tot.get("free_bytes"))),
                                   pct=round(_n(tot.get("free_bytes")) * 100 / sysm), n=_n(tot.get("free_chunks")),
                                   top=_mib(_n(tot.get("top_bytes"))))]
    ps = [p for p in hr.get("proc_samples") or [] if isinstance(p, dict) and isinstance(p.get("t_s"), (int, float))]
    lw = [w for w in hr.get("leak_walks") or [] if isinstance(w, dict)]
    if len(ps) >= 2:
        out.append(_TXT["flat"][i].format(win="%.1f" % (ps[-1]["t_s"] - ps[0]["t_s"]), n=len(ps),
                                           walks=_TXT["flat_walks"][i].format(n=len(lw)) if len(lw) >= 2 else ""))
    ars = [a for a in hr.get("arenas") or [] if isinstance(a, dict)]
    if ars:
        a = max(ars, key=lambda r: _n(r.get("free_bytes")))
        out.append(_TXT["arena"][i].format(idx=_n(a.get("index")), kind=_TXT["main" if a.get("is_main") else "thread"][i],
                                            free=_mib(_n(a.get("free_bytes"))), n=_n(a.get("free_chunks")),
                                            big=_TXT["arena_big"][i].format(big=_mib(_n(a.get("largest_free"))))
                                            if _n(a.get("largest_free")) else ""))
    out.append(_TXT["why"][i])
    return out


def retention_finding_text(ctx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {"lines": _hr_facts(ctx.i, _hr_obs(report))}


def retention_finding_viz(lx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]], uid: str = "0") -> str:
    from ..report_visuals import chip, esc, facts_list, share_bars
    hr = _hr_obs(report)
    facts = _hr_facts(lx.i, hr)
    if not facts:
        return ""
    i = lx.i
    out: List[str] = []
    ars = [a for a in hr.get("arenas") or [] if isinstance(a, dict) and _n(a.get("system_mem"))]
    for a in sorted(ars, key=lambda r: -_n(r.get("system_mem")))[:4]:
        kind = _TXT["main" if a.get("is_main") else "thread"][i]
        out.append(f'<h4>{esc(_TXT["bars"][i].format(idx=_n(a.get("index")), kind=kind))} {chip(lx, "obs")}</h4>'
                   + share_bars([(_TXT["b_inuse"][i], _n(a.get("in_use_bytes")) / 1048576.0),
                                 (_TXT["b_free"][i], _n(a.get("free_bytes")) / 1048576.0),
                                 (_TXT["b_top"][i], _n(a.get("top_bytes")) / 1048576.0)], " MiB"))
    out.append(facts_list([esc(x) for x in facts]))
    lists = {}
    for a in ars:
        for k, v in (a.get("free_by_list") or {}).items() if isinstance(a.get("free_by_list"), dict) else []:
            lists[str(k)] = lists.get(str(k), 0) + _n(v)
    if any(lists.values()):
        out.append(f'<h4>{esc(_TXT["lists"][i])}</h4>'
                   + share_bars([(k, v / 1048576.0) for k, v in lists.items()], " MiB"))
    src = _TXT.get("src_" + str(hr.get("walk_source")))
    if src:
        out.append(f'<p class="dsv-note">{esc(src[i])}</p>')
    out.append(f'<p class="dsv-note">{esc(_TXT["who"][i])}: {chip(lx, "no")}</p>')
    return "".join(out)


def _register_presentation() -> None:
    from ..report_registry import register_category, register_finding_text, register_finding_viz, register_recipe_label
    register_category(CATEGORY_HEAP_RETENTION, "heap memory held but not in use (fragmentation)",
                      "사용하지 않지만 힙이 붙잡고 있는 메모리 (단편화)")
    register_recipe_label(RECIPE_HEAP_RETENTION, "MEMORY_GROWTH", "Heap retention / fragmentation", "힙 보유 / 단편화",
                          "memory the malloc arenas keep from the system without using it, while in-use is flat",
                          "사용 중인 양은 그대로인데 malloc 아레나가 쓰지 않고 붙잡고 있는 메모리")
    register_finding_text(CATEGORY_HEAP_RETENTION, retention_finding_text)
    register_finding_viz(CATEGORY_HEAP_RETENTION, retention_finding_viz)


_register_presentation()
