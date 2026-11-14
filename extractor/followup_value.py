"""Whether an expensive optional follow-up check is worth running (roadmap stage 4: expected outcomes, stop condition).

The adaptive loop of ``AdaptiveInvestigationSession`` adds optional follow-up checks after a result (a discriminating
check after a clean result, growth follow-ups after a supported growth trend).  Checks the symptom asked for and the
baseline checks are never decided here; neither are cheap follow-ups (expected cost below ``EXPENSIVE_FOLLOWUP_S``):
they keep the existing fixed order.  For an expensive follow-up this module builds its expected-outcome table and its
gain:

* **Expected-outcome table.**  For each value a signal the check observes (``recipe_metadata.RecipeProof.observes``)
  can take: the open competing causes that value would support and those it would refute, from the causes' declared
  predictions (``cause_predictions.predicted_outcomes``).  Signals already observed, and signals a pending required
  check (baseline / symptom-requested) will observe anyway, are left out: running the follow-up cannot change what
  they will show.
* **Gain** (stated simply): the number of open competing causes whose outcome at least one possible result of the
  check would change (it would refute or support them), plus 1 when the check gives *direct* evidence
  (``recipe_metadata``) for a problem category that no check of this run has decided and no pending required check
  will look at, i.e. when the check is the only way left to answer a question that could change the verdict.
* **Decision.**  Gain 0: every possible outcome leaves the causes' ranking and the verdict as they are, the check is
  not run (``no_expected_gain``).  Gain below the cost (``gain < expected_cost_s / GAIN_PRICE_S``, one separated cause
  or open verdict question is worth ``GAIN_PRICE_S`` seconds of target observation): not run (``gain_below_cost``).
  Otherwise it may run, and among several the one with the most gain per expected second is chosen.

When the loop has no follow-up left that may run, it stops adding follow-ups; the session records why
(``adaptive_stop``: the stop reason and each check not run with its gain, cost and table).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set

from extractor.cause_predictions import CAUSE_PREDICTIONS, predicted_outcomes
from extractor.recipe_metadata import EVIDENCE_DIRECT, proof_of

EXPENSIVE_FOLLOWUP_S = 0.25       # expected seconds from which a follow-up is decided by its expected outcomes
GAIN_PRICE_S = 1.0                # seconds of observation one separated cause / open verdict question is worth

DECISION_RUN = "run"
NOT_RUN_NO_GAIN = "no_expected_gain"
NOT_RUN_GAIN_BELOW_COST = "gain_below_cost"

STOP_NO_FOLLOWUP_CAN_CHANGE = "NO_FOLLOWUP_CAN_CHANGE_OUTCOME"
STOP_GAIN_BELOW_COST = "GAIN_BELOW_COST"

GAIN_DEFINITION = ("gain = number of open competing causes that at least one possible result of the check would "
                   "refute or support (signals not already observed and not observed by a pending required check), "
                   "+1 when the check gives direct evidence for a problem category no check of the run has decided "
                   f"or will look at; run only when gain > 0 and gain >= expected_cost_s / {GAIN_PRICE_S:g} s")


def is_expensive(expected_cost_s: float) -> bool:
    return float(expected_cost_s or 0.0) >= EXPENSIVE_FOLLOWUP_S


def evaluate_followup(recipe_id: str, expected_cost_s: float, open_causes: List[str], observed: Iterable[str],
                      pending_signals: Iterable[str], decided_categories: Iterable[str],
                      pending_direct_categories: Iterable[str]) -> Dict[str, Any]:
    """The expected-outcome table, gain and decision of one expensive follow-up (see the module docstring).

    ``open_causes``: competing causes not refuted so far.  ``observed``: signals the run has observed.
    ``pending_signals``: signals pending required checks will observe.  ``decided_categories``: problem categories a
    check of the run already decided (PASS / FAIL) with direct evidence.  ``pending_direct_categories``: those a
    pending required check gives direct evidence for."""
    proof = proof_of(recipe_id)
    skip: Set[str] = set(observed) | set(pending_signals)
    signals = [s for s in (proof.observes if proof else ()) if s not in skip]
    table = [r for r in predicted_outcomes(signals, [c for c in open_causes if c in CAUSE_PREDICTIONS])
             if r["supports"] or r["refutes"]]
    separated = sorted({c for r in table for c in r["supports"] + r["refutes"]})
    covered = set(decided_categories) | set(pending_direct_categories)
    open_questions = sorted(set(proof.supports) - covered) if proof and proof.evidence == EVIDENCE_DIRECT else []
    gain = len(separated) + (1 if open_questions else 0)
    cost = round(float(expected_cost_s or 0.0), 4)
    if gain <= 0:
        decision = NOT_RUN_NO_GAIN
    elif gain < cost / GAIN_PRICE_S:
        decision = NOT_RUN_GAIN_BELOW_COST
    else:
        decision = DECISION_RUN
    return {"recipe_id": recipe_id, "expected_cost_s": cost, "signals": signals,
            "signals_left_out": [s for s in (proof.observes if proof else ()) if s in skip],
            "table": table, "outcome_lines": outcome_lines(table), "separates": separated,
            "open_verdict_questions": open_questions, "gain": gain,
            "gain_per_s": round(gain / cost, 3) if cost > 0 else float(gain), "decision": decision}


def outcome_lines(table: List[Dict[str, Any]]) -> List[str]:
    """The table as selection-log lines: 'if wait_cycle=PERSISTENT: supports A; refutes B, C'."""
    out = []
    for r in table:
        parts = []
        if r["supports"]:
            parts.append("supports " + ", ".join(r["supports"]))
        if r["refutes"]:
            parts.append("refutes " + ", ".join(r["refutes"]))
        out.append(f"if {r['signal']}={r['value']}: " + "; ".join(parts))
    return out


def choose(evaluations: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The follow-up to run among evaluated ones: the most gain per expected second (ties: more gain, then id)."""
    ok = [e for e in evaluations if e["decision"] == DECISION_RUN]
    if not ok:
        return None
    return sorted(ok, key=lambda e: (-e["gain_per_s"], -e["gain"], e["recipe_id"]))[0]


def stop_record(not_run: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The structured reason the loop stopped adding follow-ups (None when no follow-up was left out)."""
    if not not_run:
        return None
    reason = (STOP_GAIN_BELOW_COST if any(e["decision"] == NOT_RUN_GAIN_BELOW_COST for e in not_run)
              else STOP_NO_FOLLOWUP_CAN_CHANGE)
    return {"stop_reason": reason, "gain_definition": GAIN_DEFINITION,
            "expensive_followup_s": EXPENSIVE_FOLLOWUP_S, "gain_price_s": GAIN_PRICE_S,
            "not_run": [{k: e.get(k) for k in ("recipe_id", "decision", "gain", "expected_cost_s", "separates",
                                               "open_verdict_questions", "signals", "signals_left_out",
                                               "outcome_lines", "after_recipe")} for e in not_run]}
