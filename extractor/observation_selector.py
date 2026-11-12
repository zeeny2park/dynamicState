"""Discriminating-observation selector of the expert engine's replanning step (IMP-017 / IMP-018).

Ported from the retired adaptive engine (``AdaptiveInvestigationPlanner.select_next_observation``): among the
candidate recipes, pick the cheapest read-only one whose declared observations can change the ranking of the
competing hypotheses that are still unresolved, check its estimated cost against the remaining budget BEFORE it
runs, and record why it won over the runner-up.  It works on the observations each recipe DECLARES
(``DiagnosticRecipe.observations``, see :mod:`extractor.diagnostic_recipes`) and their per-kind cost estimates.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

# Hypothesis states that are settled: an observation can no longer change them.
_SETTLED = frozenset({"CONFIRMED", "REFUTED", "NOT_APPLICABLE"})

# Conservative cost of one observation of each kind (bytes read, wall-clock ms).  Unknown kinds use the default.
OBSERVATION_COSTS: Dict[str, Tuple[int, float]] = {
    "proc_status": (4096, 5.0),
    "proc_fd": (16384, 10.0),
    "memory_maps": (65536, 10.0),
    "memory_trend": (65536, 1500.0),
    "thread_states": (32768, 50.0),
    "thread_samples": (65536, 1500.0),
    "lock_graph": (65536, 200.0),
    "dwarf_globals": (262144, 300.0),
    "heap_walk": (4 * 1024 * 1024, 1500.0),
    "heap_integrity": (4 * 1024 * 1024, 1500.0),
}
DEFAULT_COST: Tuple[int, float] = (131072, 300.0)


def estimate_cost(observations: Iterable[str]) -> Tuple[int, float]:
    """Sum of the declared observations' estimated bytes and latency."""
    b, ms = 0, 0.0
    for kind in observations or ():
        kb, kms = OBSERVATION_COSTS.get(kind, DEFAULT_COST)
        b += kb
        ms += kms
    return (b, ms) if (b or ms) else DEFAULT_COST


def select_discriminating_recipe(
    hypotheses: List[Any],
    candidate_recipes: List[Any],
    budget_tracker: Any = None,
    executed_recipe_ids: Iterable[str] = (),
    capabilities: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], List[Dict[str, Any]], str]:
    """Return ``(recipe_id or None, evaluation_log, rationale)``.

    hypotheses: competing hypotheses (``hypothesis_id``, ``status``, ``applicable_diagnostic_rules``).
    candidate_recipes: :class:`DiagnosticRecipe` objects (``recipe_id``, ``observations``, optional
        ``risk_level``).  executed_recipe_ids: recipes already run (never selected again).
    capabilities: ``{observation_kind: False}`` marks a kind this target cannot provide.
    """
    caps = capabilities or {}
    executed = set(executed_recipe_ids or ())
    unresolved = {h.hypothesis_id: h for h in hypotheses or []
                  if str(getattr(h, "status", "")) not in _SETTLED}
    log: List[Dict[str, Any]] = []
    if not unresolved:
        return None, log, "no unresolved competing hypothesis"
    feasible = []
    for rec in sorted(candidate_recipes or [], key=lambda r: r.recipe_id):
        rid = rec.recipe_id
        if rid in executed:
            continue
        obs = list(getattr(rec, "observations", None) or ())
        entry: Dict[str, Any] = {"recipe_id": rid, "observations": obs}
        risk = getattr(rec, "risk_level", "READ_ONLY")
        if risk not in ("READ_ONLY", "LOW_IMPACT"):
            log.append({**entry, "eligible": False, "rejection_reason": f"not read-only ({risk})"})
            continue
        missing = [k for k in obs if caps.get(k) is False]
        if missing:
            log.append({**entry, "eligible": False, "rejection_reason": f"observation kind unavailable: {missing}"})
            continue
        tested = sorted(hid for hid, h in unresolved.items() if rid in (getattr(h, "applicable_diagnostic_rules", None) or []))
        if not tested:
            log.append({**entry, "eligible": False, "rejection_reason": "tests no unresolved hypothesis"})
            continue
        est_bytes, est_ms = estimate_cost(obs)
        if budget_tracker is not None and hasattr(budget_tracker, "check_pre_execution"):
            ok, why, est_bytes = budget_tracker.check_pre_execution(
                estimated_bytes=est_bytes, estimated_latency_ms=est_ms, estimated_samples=1,
                estimated_stop_ms=0.0, profile_id=rid, profile_ceiling=None)
            if not ok:
                log.append({**entry, "eligible": False, "rejection_reason": f"budget: {why}",
                            "estimated_bytes": est_bytes})
                continue
        discriminating = len(tested)
        can_change = 1 if discriminating >= 2 else 0
        info_gain = 20 + 15 * discriminating
        meta = {**entry, "eligible": True, "tested_hypothesis_ids": tested, "discriminating_count": discriminating,
                "can_materially_change_ranking": bool(can_change), "info_gain_score": info_gain,
                "estimated_bytes": est_bytes, "estimated_latency_ms": est_ms}
        log.append(meta)
        feasible.append(((-can_change, -discriminating, est_bytes, -info_gain, est_ms, rid), meta))
    if not feasible:
        return None, log, "no budget-feasible read-only recipe tests an unresolved hypothesis"
    feasible.sort(key=lambda x: x[0])
    best = feasible[0][1]
    if len(feasible) > 1:
        alt = feasible[1][1]
        why = (f"Selected {best['recipe_id']} (tests {best['tested_hypothesis_ids']}, discriminates="
               f"{best['discriminating_count']}, est_bytes={best['estimated_bytes']}B, est_latency="
               f"{best['estimated_latency_ms']}ms) over {alt['recipe_id']} (discriminates={alt['discriminating_count']}, "
               f"est_bytes={alt['estimated_bytes']}B) as the lowest-cost read-only observation able to change the "
               "ranking of the competing hypotheses.")
    else:
        why = (f"Selected {best['recipe_id']} as the only budget-feasible read-only recipe testing "
               f"{best['tested_hypothesis_ids']} (est_bytes={best['estimated_bytes']}B).")
    return best["recipe_id"], log, why
