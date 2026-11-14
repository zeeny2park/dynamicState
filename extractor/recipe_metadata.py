"""What each diagnostic recipe can prove (roadmap stage 4, "recipe metadata").

Next to its declared cost (``DiagnosticRecipe.expected_cost_s`` / ``cost_per_thread_s`` / ``shared_cost``, used by
``extractor.check_budget``), every registered recipe declares here:

* ``supports``  the problem categories its positive result can be filed under (a finding of that category);
* ``refutes``   the problem categories its clean, complete result clears (contradicting evidence for them);
* ``evidence``  ``direct`` when it observes the defect itself (a wait-for cycle, a damaged heap header, growth that
  nothing references) or ``indirect`` when what it sees is a symptom consistent with several causes (blocked
  threads, an allocation counter imbalance, a NULL pointer in an active object);
* ``observes``  the signals of ``extractor.cause_predictions.SIGNALS`` its typed evidence can carry: what the
  competing causes' predictions are checked against, and so what an expected-outcome table of the recipe lists.

The table is keyed by recipe id (like the cost table) and kept out of the recipe declarations so that rule and
collector code is not touched by it.  A recipe definition file that registers a new recipe declares its entry with
:func:`declare_proof`; ``tests/test_recipe_metadata.py`` fails when a registered recipe has none.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

EVIDENCE_DIRECT = "direct"
EVIDENCE_INDIRECT = "indirect"


@dataclass(frozen=True)
class RecipeProof:
    supports: Tuple[str, ...]
    refutes: Tuple[str, ...]
    evidence: str
    observes: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {"supports": list(self.supports), "refutes": list(self.refutes), "evidence": self.evidence,
                "observes": list(self.observes)}


def _p(supports, refutes, evidence, observes) -> RecipeProof:
    return RecipeProof(tuple(supports), tuple(refutes), evidence, tuple(observes))


D, I = EVIDENCE_DIRECT, EVIDENCE_INDIRECT

RECIPE_PROOF: Dict[str, RecipeProof] = {
    # memory integrity
    "RECIPE_INVALID_MEMORY_ACCESS": _p(["MEMORY_CORRUPTION", "PROCESS_INSTABILITY"], ["MEMORY_CORRUPTION"], D,
                                       ["address_validity"]),
    "RECIPE_INVALID_FREE": _p(["INVALID_DOUBLE_FREE", "MEMORY_CORRUPTION"], ["INVALID_DOUBLE_FREE"], D,
                              ["address_validity"]),
    "RECIPE_USE_AFTER_FREE": _p(["USE_AFTER_FREE", "MEMORY_CORRUPTION"], ["USE_AFTER_FREE"], D, ["freed_block_use"]),
    "RECIPE_HEAP_METADATA_CORRUPTION": _p(["MEMORY_CORRUPTION", "RESOURCE_EXHAUSTION"], ["MEMORY_CORRUPTION"], D,
                                          ["heap_header_damage"]),
    "RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS": _p(["MEMORY_CORRUPTION", "MEMORY_LEAK"], [], I, []),
    "RECIPE_DOUBLE_FREE": _p(["INVALID_DOUBLE_FREE", "MEMORY_CORRUPTION"], ["INVALID_DOUBLE_FREE"], D,
                             ["free_list_repeat"]),
    "RECIPE_FREED_MEMORY_USE": _p(["USE_AFTER_FREE"], ["USE_AFTER_FREE"], D, ["freed_block_use"]),
    # memory growth
    "RECIPE_PROCESS_MEMORY_GROWTH": _p(["MEMORY_LEAK", "RESOURCE_EXHAUSTION"], ["MEMORY_LEAK"], D,
                                       ["memory_bounded", "heap_in_use_trend", "growth_owner"]),
    "RECIPE_HEAP_GROWTH": _p(["MEMORY_LEAK"], ["MEMORY_LEAK"], D,
                             ["memory_bounded", "heap_in_use_trend", "growth_owner"]),
    "RECIPE_ALLOCATION_FREE_IMBALANCE": _p(["MEMORY_LEAK"], [], I, ["alloc_counter_balance", "memory_bounded"]),
    "RECIPE_OBJECT_LIFETIME_ANOMALIES": _p(["MEMORY_LEAK", "FUNCTIONAL_STATE_INCONSISTENCY"], [], I, ["memory_bounded"]),
    "RECIPE_REPEATED_ALLOCATION_PATTERNS": _p(["MEMORY_LEAK", "RESOURCE_EXHAUSTION"], [], I,
                                              ["memory_bounded", "heap_in_use_trend"]),
    "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION": _p(["MEMORY_LEAK"], ["MEMORY_LEAK"], D,
                                                ["memory_bounded", "heap_in_use_trend", "growth_owner"]),
    "RECIPE_HEAP_RETENTION": _p(["HEAP_RETENTION"], ["HEAP_RETENTION"], D, []),
    "RECIPE_MAPPING_GROWTH": _p(["MAPPING_GROWTH"], ["MAPPING_GROWTH"], D, ["memory_bounded"]),
    # resources
    "RECIPE_FD_LEAK": _p(["FD_LEAK"], ["FD_LEAK"], D, ["resource_bounded"]),
    "RECIPE_THREAD_LEAK": _p(["THREAD_LEAK"], ["THREAD_LEAK"], D, ["resource_bounded"]),
    # program state
    "RECIPE_UNEXPECTED_VARIABLE_CHANGES": _p(["ABNORMAL_VARIABLE_CHANGES", "FUNCTIONAL_STATE_INCONSISTENCY"],
                                             ["ABNORMAL_VARIABLE_CHANGES"], D, ["state_consistency"]),
    "RECIPE_STATE_TRANSITION_VIOLATIONS": _p(["UNEXPECTED_STATE_TRANSITIONS", "FUNCTIONAL_STATE_INCONSISTENCY"],
                                             ["UNEXPECTED_STATE_TRANSITIONS"], D, ["state_consistency"]),
    "RECIPE_INCONSISTENT_RELATED_VARIABLES": _p(["FUNCTIONAL_STATE_INCONSISTENCY", "DATA_RACE_INDICATORS"],
                                                ["FUNCTIONAL_STATE_INCONSISTENCY"], I, ["state_consistency"]),
    "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS": _p(["MEMORY_CORRUPTION", "ABNORMAL_VARIABLE_CHANGES"], [], I,
                                                     ["address_validity"]),
    "RECIPE_SUSPICIOUS_BOUNDARY_VALUES": _p(["ABNORMAL_VARIABLE_CHANGES", "MEMORY_CORRUPTION"], [], I,
                                            ["state_consistency"]),
    "RECIPE_SHARED_STATE_INCONSISTENCIES": _p(["DATA_RACE_INDICATORS", "FUNCTIONAL_STATE_INCONSISTENCY"], [], I,
                                              ["state_consistency"]),
    # threads and locks
    "RECIPE_THREAD_STATE_ANOMALIES": _p(["PROCESS_INSTABILITY", "DEADLOCK_INDICATORS"],
                                        ["PROCESS_INSTABILITY", "DEADLOCK_INDICATORS"], I,
                                        ["thread_state", "threads_blocked"]),
    "RECIPE_LONG_RUNNING_BLOCKED_THREADS": _p(["DEADLOCK_INDICATORS", "PROCESS_INSTABILITY"], ["DEADLOCK_INDICATORS"], I,
                                              ["threads_blocked"]),
    "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP": _p(["DEADLOCK_INDICATORS", "DATA_RACE_INDICATORS"], ["DEADLOCK_INDICATORS"], I,
                                           ["wait_cycle"]),
    "RECIPE_POTENTIAL_DEADLOCK_PATTERNS": _p(["DEADLOCK_INDICATORS"], ["DEADLOCK_INDICATORS"], D, ["wait_cycle"]),
    "RECIPE_LOCK_CONTENTION": _p(["LOCK_CONTENTION"], ["LOCK_CONTENTION"], D, ["lock_queueing"]),
    "RECIPE_ORPHAN_LOCK": _p(["ORPHAN_LOCK"], ["ORPHAN_LOCK"], D, ["lock_owner_gone"]),
    "RECIPE_SELF_DEADLOCK": _p(["SELF_DEADLOCK"], ["SELF_DEADLOCK"], D, ["self_wait"]),
}


def declare_proof(recipe_id: str, supports, refutes, evidence: str, observes=()) -> RecipeProof:
    """Declare what a recipe registered by a definition file can prove (see the module docstring)."""
    if evidence not in (EVIDENCE_DIRECT, EVIDENCE_INDIRECT):
        raise ValueError(f"{recipe_id}: evidence must be {EVIDENCE_DIRECT!r} or {EVIDENCE_INDIRECT!r}")
    RECIPE_PROOF[recipe_id] = _p(supports, refutes, evidence, observes)
    return RECIPE_PROOF[recipe_id]


def proof_of(recipe_id: str) -> Optional[RecipeProof]:
    return RECIPE_PROOF.get(str(recipe_id or ""))
