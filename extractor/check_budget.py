"""Per-diagnosis time budget for the default checks (roadmap decision 6.1-2).

Default checks are the always-run baseline recipes (``diagnostic_recipes.BASELINE_RECIPE_IDS``) that the symptom did
not ask for.  Before a default check is started its expected cost is estimated; it is not run when

* its estimate exceeds the per-check limit (``per_check_s``), or
* the default checks already run plus this estimate exceed the total (``total_s``).

Checks requested by the symptom's problem categories (and symptom-specific recipes) are never subject to the budget.
A check left out records the structured reason ``not_run_reason == "time_budget"`` on its plan step; a baseline check
left out is a coverage gap, so the HEALTHY rule never clears a diagnosis that skipped one (it is the same
``baseline_check_not_run`` gap as any baseline check that did not run).

Expected cost = the recipe's declared cost (``DiagnosticRecipe.expected_cost_s`` + ``cost_per_thread_s`` x the
target's thread count, + its shared collection (``shared_cost``: observation window, lock-wait samples) when no
earlier check of this run collected it), multiplied by the run's own correction: measured / estimated over the default checks already run
(never below 1, at most ``MAX_CORRECTION``).

Configuration: constructor / ``diagnose`` arguments, else the environment (``DYNAMICSTATE_DEFAULT_CHECK_BUDGET_S``,
``DYNAMICSTATE_DEFAULT_CHECK_MAX_S``), else the defaults below.  A value <= 0 disables that limit.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

ENV_TOTAL = "DYNAMICSTATE_DEFAULT_CHECK_BUDGET_S"
ENV_PER_CHECK = "DYNAMICSTATE_DEFAULT_CHECK_MAX_S"

# Defaults from measurements (see docs/IMPROVEMENT_STRATEGY_AND_ROADMAP_KO.md 8.x): on a quiet 4-core host the
# baseline of a small target costs about 3 s (observation window ~0.8 s, fd sampling ~0.8 s, mapping series ~0.9 s,
# the rest < 0.2 s each) and the healthy benchmark controls' default checks stay below ~4 s even at load ~3.  The
# total leaves room for that, so a quiet healthy target always completes its baseline (the HEALTHY rule needs every
# baseline check); a many-thread target (cost grows with the thread count) is where default checks get left out.
DEFAULT_TOTAL_S = 6.0
DEFAULT_PER_CHECK_S = 2.5

# Collections shared by several recipes within one run: the first check that needs one pays it (base seconds,
# seconds per target thread), later ones reuse it.  Measured on a quiet 4-core aarch64 host: the /proc observation
# window (thread state series + memory samples) 0.76 s at 2 threads, 2.85 s at 301 threads; the lock-wait samples
# 0.17 s at 2 threads, 1.08 s at 301 threads.
SHARED_COSTS: Dict[str, tuple] = {
    "observation_window": (0.75, 0.007),
    "lock_wait_samples": (0.15, 0.003),
}
MAX_CORRECTION = 3.0

NOT_RUN_TIME_BUDGET = "time_budget"
LIMIT_PER_CHECK = "per_check"
LIMIT_TOTAL = "total"


def _env_float(name: str) -> Optional[float]:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _limit(v: Optional[float]) -> float:
    """A configured limit; <= 0 (or not finite) means no limit."""
    if v is None or not math.isfinite(float(v)) or float(v) <= 0:
        return math.inf
    return float(v)


@dataclass
class DefaultCheckBudget:
    total_s: float = DEFAULT_TOTAL_S
    per_check_s: float = DEFAULT_PER_CHECK_S

    @classmethod
    def resolve(cls, total_s: Optional[float] = None, per_check_s: Optional[float] = None) -> "DefaultCheckBudget":
        """Explicit values, else the environment, else the defaults."""
        t = total_s if total_s is not None else _env_float(ENV_TOTAL)
        p = per_check_s if per_check_s is not None else _env_float(ENV_PER_CHECK)
        return cls(total_s=_limit(DEFAULT_TOTAL_S if t is None else t),
                   per_check_s=_limit(DEFAULT_PER_CHECK_S if p is None else p))

    @classmethod
    def from_dict(cls, d: Any) -> "DefaultCheckBudget":
        if isinstance(d, DefaultCheckBudget):
            return d
        d = d if isinstance(d, dict) else {}
        return cls(total_s=_limit(d.get("total_s")), per_check_s=_limit(d.get("per_check_s")))

    def to_dict(self) -> Dict[str, Optional[float]]:
        return {"total_s": None if math.isinf(self.total_s) else self.total_s,
                "per_check_s": None if math.isinf(self.per_check_s) else self.per_check_s}

    def decide(self, expected_s: float, spent_s: float) -> Optional[str]:
        """None when the check may run, else which limit it would exceed (``per_check`` / ``total``)."""
        if expected_s > self.per_check_s:
            return LIMIT_PER_CHECK
        if spent_s + expected_s > self.total_s:
            return LIMIT_TOTAL
        return None


def declared_cost_s(recipe: Any, thread_count: int, collected: Iterable[str] = ()) -> float:
    """The recipe's declared cost on this target, before the run's correction.  ``collected``: the shared
    collections (``SHARED_COSTS`` keys) an earlier check of this run already paid."""
    threads = max(0, int(thread_count or 0))
    base = float(getattr(recipe, "expected_cost_s", 0.0) or 0.0)
    per_thread = float(getattr(recipe, "cost_per_thread_s", 0.0) or 0.0)
    cost = base + per_thread * threads
    shared = getattr(recipe, "shared_cost", "") or ""
    if shared in SHARED_COSTS and shared not in set(collected):
        s_base, s_thread = SHARED_COSTS[shared]
        cost += s_base + s_thread * threads
    return cost


def correction(pairs: Iterable[tuple]) -> float:
    """The run's slowdown: median of measured / estimated over (estimated_s, measured_s) of the default checks already
    run, >= 1 and <= MAX_CORRECTION.  The median keeps one check that did target-dependent extra work (heap walks
    after a memory trend) from inflating every later estimate; a loaded host slows them all."""
    ratios = sorted(float(m) / float(e) for e, m in pairs
                    if isinstance(e, (int, float)) and isinstance(m, (int, float)) and e >= 0.05)
    if not ratios:
        return 1.0
    mid = len(ratios) // 2
    med = ratios[mid] if len(ratios) % 2 else (ratios[mid - 1] + ratios[mid]) / 2.0
    return max(1.0, min(MAX_CORRECTION, med))


def is_default_check(recipe_id: str, baseline_ids: Iterable[str], symptom_categories: Iterable[str],
                     recipe_categories: List[str], targeted_recipe: Optional[str] = None) -> bool:
    """A baseline recipe the symptom did not ask for (no shared problem category, not the targeted recipe)."""
    if recipe_id not in set(baseline_ids) or recipe_id == targeted_recipe:
        return False
    return not (set(symptom_categories or ()) & set(recipe_categories or ()))
