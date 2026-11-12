"""IMP-009: memory integrity investigation of one diagnose run (heap metadata, global adjacency, stack margins).

When it runs
------------
``RECIPE_HEAP_METADATA_CORRUPTION`` is a baseline check (planned for every symptom).  A heap overflow in an idle
process produces no growth, so the IMP-008 escalation rule never walks its heap and the symptom can be vague;
the integrity check therefore has its own rule:

* baseline mode (any symptom): ONE bounded integrity walk when the heap is small - the estimated arena heap
  size (``[heap]`` + thread-arena heaps from /proc/PID/maps) must be at most ``baseline_heap_cap_bytes``
  (8 MiB); above it the heap is not walked and ``not_covered`` says "heap integrity not checked: heap larger than
  baseline cap".  The reverse reference map (owner names) is built only when a stable defect was found.
* full mode: the symptom is classified as memory corruption / use-after-free / double free, it mentions a crash,
  or a memory-integrity recipe is targeted: no heap-size cap (only the session budget share
  ``bytes_fraction`` / ``wall_fraction``), owner map always built, "allocation smaller than its type" checked.
* sharing: when the IMP-008 leak investigation of the same session already walked the heap, its last walk (and
  reachability map) is re-used - one walk serves both.  Stability re-reads are made in any case.

Global adjacency (DWARF + symtab, a few hundred bytes) and stack margins (/proc only) run in both modes.

Verdict inputs (``memory_integrity`` observation key, plain data) are evaluated in
:mod:`extractor.diagnostic_recipes` (``_evaluate_integrity_investigation``).
"""

import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

INTEREST_CATEGORIES = ("MEMORY_CORRUPTION", "USE_AFTER_FREE", "INVALID_DOUBLE_FREE", "STACK_CORRUPTION")
_CRASH_WORDS = ("crash", "segfault", "sigsegv", "sigabrt", "abort", "core dump", "corrupt", "overflow",
                "크래시", "세그폴트", "깨졌", "오염")
_WALK_UNSUPPORTED = ("UNSUPPORTED_ALLOCATOR", "UNSUPPORTED_GLIBC_VERSION", "INCONCLUSIVE_ABI_UNDETECTED",
                     "ARENA_NOT_FOUND")


REMOTE_BASELINE_WALL_FACTOR = 10.0   # remote baseline walk: same byte caps, wall cap x10 (SSH round trips)


@dataclass
class IntegrityConfig:
    baseline_heap_cap_bytes: int = 8 * 1024 * 1024
    baseline_wall_cap_s: float = 1.5
    bytes_fraction: float = 0.75
    wall_fraction: float = 0.6
    stability_reads: int = 2
    stability_interval_s: float = 0.03


def _remaining(budget: Any):
    if budget is None:
        return 30.0, 1 << 34
    try:
        wall = (float(budget.limits.max_wall_clock_ms) - float(budget.elapsed_ms)) / 1000.0
        byt = int(budget.limits.max_bytes_read) - int(budget.metrics.bytes_read)
        return max(0.0, wall), max(0, byt)
    except Exception:  # noqa: BLE001
        return 30.0, 1 << 34


def heap_size_estimate(maps: List[Dict[str, Any]], heap_max: int = 64 * 1024 * 1024) -> int:
    """Bytes an integrity walk reads: the brk ``[heap]`` plus the writable part of every thread-arena heap
    (anonymous mappings starting on a ``HEAP_MAX_SIZE`` boundary, where ``heap_info`` lives)."""
    n = 0
    for m in maps:
        p = m.get("pathname") or ""
        perms = m.get("permissions") or ""
        s = int(m.get("start_int") or 0)
        e = int(m.get("end_int") or 0)
        if p == "[heap]":
            n += e - s
        elif not p and "w" in perms and s % heap_max == 0:
            n += e - s
    return n


def _full_reason(classification: Any, target_recipe: Optional[str]) -> Optional[str]:
    cat = getattr(classification, "primary_category", None) if classification is not None else None
    if cat in INTEREST_CATEGORIES:
        return "symptom classified as %s" % cat
    text = str(getattr(classification, "raw_query", "") or "").lower()
    if any(w in text for w in _CRASH_WORDS):
        return "symptom mentions a crash / corruption"
    if target_recipe:
        from .diagnostic_recipes import DiagnosticRecipeRegistry
        r = DiagnosticRecipeRegistry.get_recipe(target_recipe)
        if r is not None and r.domain == "MEMORY_INTEGRITY":
            return "targeted memory-integrity recipe %s" % target_recipe
    return None


def run_integrity(adapter: Any, pid: int, companion_elf: Optional[str], cfg: IntegrityConfig, budget: Any = None,
                  full_reason: Optional[str] = None, shared: Any = None,
                  keep: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """One integrity investigation; returns plain data (see module docstring).  ``keep`` (a dict) receives the
    walk objects (walk, walker, analyzer, t_walk) for the use-after-free check that re-uses this walk."""
    from .heap_walker import BudgetedReader, HeapWalker, remote_cost_note
    from .heap_integrity import HeapIntegrityChecker, undersized_allocations
    from .observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
    from .reachability import ReachabilityLimits, build_reachability, _module_contexts
    t0 = time.monotonic()
    mode = "full" if full_reason else "baseline"
    rec: Dict[str, Any] = {"mode": mode, "reason_run": full_reason or "baseline check (bounded)", "limitations": [],
                           "heap": {"status": "NOT_RUN"}, "globals": {"status": "NOT_RUN"},
                           "stacks": {"status": "NOT_RUN"}, "cost": {"bytes_read": 0}}
    try:
        maps = list(adapter.get_proc_maps(pid) or [])
    except Exception as exc:  # noqa: BLE001
        rec["limitations"].append("memory maps not readable: %s" % exc)
        return rec
    rem_wall, rem_bytes = _remaining(budget)
    bytes_allow = int(rem_bytes * cfg.bytes_fraction)
    wall_allow = rem_wall * cfg.wall_fraction
    if mode == "baseline":
        cap = cfg.baseline_wall_cap_s
        if remote_cost_note(adapter):
            # same byte caps, but a remote walk pays an SSH round trip per batch (about 0.25 s on the QEMU guest):
            # the 1.5 s local wall cap would end it before the libc banner was read
            cap *= REMOTE_BASELINE_WALL_FACTOR
        wall_allow = min(wall_allow, cap)
    heap = rec["heap"]
    est = heap_size_estimate(maps)
    heap["estimated_heap_bytes"] = est
    analyzer = None
    reader = None
    if shared is not None and getattr(shared, "walk", None) is not None and shared.walk.ok:
        walk, walker, analyzer = shared.walk, (shared.analyzer.walker if shared.analyzer else None), shared.analyzer
        heap["walk_source"] = "shared with the leak investigation's last heap walk"
        if walker is None:
            walk = analyzer = None
        else:
            # the re-reads (stability) get a small budget of their own: the shared walk's budget may be spent
            rb = ObservationBudgetTracker(ObservationBudgetLimits(
                max_wall_clock_ms=max(100.0, wall_allow * 1000.0), max_bytes_read=max(65536, bytes_allow),
                max_samples=1 << 30, max_bytes_per_observation=1 << 40, max_consecutive_read_failures=1 << 20,
                max_total_read_failures=1 << 20))
            reader = BudgetedReader(adapter, pid, rb, profile_id="heap_integrity")
    else:
        walk = walker = None
    if walk is None and mode == "baseline" and est > cfg.baseline_heap_cap_bytes:
        heap["status"] = "NOT_CHECKED"
        # structured reason (the HEALTHY rule reads it): a declared cost limit of the baseline, not a failure
        heap["not_checked_reason"] = "above_baseline_cap"
        heap["baseline_cap_bytes"] = int(cfg.baseline_heap_cap_bytes)
        rec["limitations"].append(
            "heap integrity not checked: heap larger than baseline cap (%.1f MiB > %.1f MiB); a memory-corruption or "
            "crash symptom, or targeting RECIPE_HEAP_METADATA_CORRUPTION, runs the full walk"
            % (est / 1048576.0, cfg.baseline_heap_cap_bytes / 1048576.0) + remote_cost_note(adapter))
    elif walk is None and bytes_allow < est + 65536:
        heap["status"] = "NOT_CHECKED"
        heap["not_checked_reason"] = "byte_budget"
        rec["limitations"].append("heap integrity not checked: the observation byte budget left (%d bytes) is below "
                                  "the heap size (%d bytes)" % (bytes_allow, est) + remote_cost_note(adapter))
    else:
        if walk is None:
            hb = ObservationBudgetTracker(ObservationBudgetLimits(
                max_wall_clock_ms=max(100.0, wall_allow * 1000.0), max_bytes_read=max(65536, bytes_allow),
                max_samples=1 << 30, max_bytes_per_observation=1 << 40, max_consecutive_read_failures=1 << 20,
                max_total_read_failures=1 << 20))
            reader = BudgetedReader(adapter, pid, hb, profile_id="heap_integrity")
            walker = HeapWalker(adapter, pid, budget=hb, reader=reader, use_libc_debug_info=False)
            walk = walker.walk()
            heap["walk_source"] = "own integrity walk"
        t_walk = time.monotonic()
        heap["walk_status"] = walk.status
        heap["walk_message"] = walk.message
        if walk.status in _WALK_UNSUPPORTED:
            heap["status"] = "UNSUPPORTED"
            rec["limitations"].append("heap integrity not supported on this target: %s (%s)"
                                      % (walk.status, walk.message))
        elif not walk.ok:
            heap["status"] = "LIMITED"
            rec["limitations"].append("heap integrity walk incomplete: %s (%s)" % (walk.status, walk.message))
        else:
            chk = HeapIntegrityChecker(walk, walker, reader, stability_reads=cfg.stability_reads,
                                       stability_interval_s=cfg.stability_interval_s)
            chk.detect()
            chk.confirm_stability()
            stable = any(not c.why_not for c in chk.candidates)
            if analyzer is None and (stable or mode == "full"):
                info: Dict[str, Any] = {"root_sources": {}}
                analyzer = build_reachability(walk, walker, reader, adapter, pid, companion_elf, None, False,
                                              ReachabilityLimits(max_stack_without_sp_bytes=1024 * 1024), info)
                if info.get("reachability_error"):
                    rec["limitations"].append("owner names incomplete: %s" % info["reachability_error"])
            defects = chk.attribute(analyzer)
            # free-list damage in a free chunk a typed pointer still refers to: use after free, not an overflow
            from .uaf_detection import classify_integrity_defects
            classify_integrity_defects(defects)
            heap["defects"] = defects
            heap["inconsistent_reads_not_evidence"] = chk.transient[:16]
            heap["checked"] = dict(chk.checked, chunks=len(walk.chunks),
                                   damaged_regions_resynchronised=len(walk.damaged_regions))
            if mode == "full" and analyzer is not None:
                heap["undersized_allocations"] = undersized_allocations(analyzer)
            heap["status"] = "COMPLETED" if walk.status == "OK" or walk.damaged_regions or defects else "PARTIAL"
            if walk.status != "OK" and not defects:
                heap["note"] = walk.message
            if keep is not None:
                keep.update(walk=walk, walker=walker, analyzer=analyzer, t_walk=t_walk)
        heap["cost"] = {"bytes_read": int(reader.bytes_read),
                        "walk_wall_ms": (walk.stats or {}).get("wall_ms")}
        rec["cost"]["bytes_read"] += heap["cost"]["bytes_read"]
    # ---- globals
    g = rec["globals"]
    try:
        mods = _module_contexts(adapter, pid, companion_elf, None, maps) if companion_elf else []
    except Exception as exc:  # noqa: BLE001
        mods = []
        g["error"] = "%s: %s" % (type(exc).__name__, exc)
    if mods:
        from .global_adjacency import GlobalAdjacencyChecker
        name, idx, bias, is_dyn = mods[0]
        exe = str(companion_elf).split(",")[0].strip()
        try:
            gc = GlobalAdjacencyChecker(adapter, pid, idx, bias, is_dyn, exe, maps,
                                        interval_s=cfg.stability_interval_s)
            g.update(gc.check())
            g["status"] = "COMPLETED"
            rec["cost"]["bytes_read"] += gc.bytes_read
        except Exception as exc:  # noqa: BLE001
            g["status"] = "FAILED"
            rec["limitations"].append("global adjacency check failed: %s: %s" % (type(exc).__name__, exc))
    else:
        g["status"] = "NOT_RUN"
        rec["limitations"].append("global adjacency check needs the executable's DWARF (no debug image)")
    # ---- stacks
    from .stack_margin import check_stack_margins
    try:
        rec["stacks"] = dict(check_stack_margins(adapter, pid, maps=maps), status="COMPLETED")
    except Exception as exc:  # noqa: BLE001
        rec["stacks"] = {"status": "FAILED"}
        rec["limitations"].append("stack margin check failed: %s: %s" % (type(exc).__name__, exc))
    rec["cost"]["wall_s"] = round(time.monotonic() - t0, 3)
    return rec


def _state(provider: Any) -> Dict[Any, Any]:
    st = getattr(provider, "_imp009_state", None)
    if st is None:
        st = {}
        provider._imp009_state = st
    return st


def ensure_integrity(provider: Any, pid: int, companion_elf: Optional[str], classification: Any,
                     session_id: Optional[str]):
    """The session's integrity record (run once per session and pid) -> (record, walk objects, fresh).  The walk
    objects (walk, walker, analyzer, t_walk) are kept for the use-after-free check, which re-uses the walk."""
    cfg: IntegrityConfig = getattr(provider, "integrity_config", None) or IntegrityConfig()
    mo = getattr(provider, "memory_observation", None)
    key = (session_id or "default", int(pid))
    st = _state(provider)
    rec = st.get(key)
    fresh = rec is None
    if fresh:
        reason = _full_reason(classification, getattr(mo, "target_recipe", None))
        shared = (getattr(provider, "_imp008_state", None) or {}).get("analyses", {}).get(key)
        objs: Dict[str, Any] = {}
        rec = run_integrity(provider.adapter, pid, companion_elf, cfg, getattr(provider, "budget_tracker", None),
                            full_reason=reason, shared=shared, keep=objs)
        st[key] = rec
        st[("walk_objects",) + key] = objs
    return rec, st.get(("walk_objects",) + key) or {}, fresh


def attach_integrity_observation(provider: Any, recipe: Any, pid: int, companion_elf: Optional[str],
                                 classification: Any, session_id: Optional[str], observation_data: Dict[str, Any],
                                 records: List[Any]) -> None:
    from .runtime_evidence_provider import RuntimeEvidenceRecord, COLLECTION_STATUS_SUCCESS, \
        COLLECTION_STATUS_PARTIAL, PROVENANCE_LIVE_RUNTIME_CAPTURE
    rec, _objs, fresh = ensure_integrity(provider, pid, companion_elf, classification, session_id)
    observation_data["memory_integrity"] = rec
    if fresh:
        if rec["cost"].get("bytes_read"):
            observation_data["bytes_read"] = int(observation_data.get("bytes_read") or 0) + int(rec["cost"]["bytes_read"])
        heap = rec.get("heap") or {}
        records.append(RuntimeEvidenceRecord(
            evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
            collection_method="heap_integrity_walk" if heap.get("walk_status") else "memory_integrity_proc",
            target_pid=pid,
            observed_value={"mode": rec["mode"], "heap_status": heap.get("status"),
                            "heap_defects": len(heap.get("defects") or []),
                            "global_candidates": len((rec.get("globals") or {}).get("candidates") or []),
                            "stack_warnings": len((rec.get("stacks") or {}).get("warnings") or [])},
            collection_scope="MEMORY_INTEGRITY",
            collection_status=COLLECTION_STATUS_SUCCESS if heap.get("status") in ("COMPLETED", "PARTIAL")
            else COLLECTION_STATUS_PARTIAL,
            limitations=list(rec.get("limitations") or []),
            provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
            raw_details={"cost": rec.get("cost"), "reason_run": rec.get("reason_run")},
        ))
