"""Investigation progress accounting, stagnation detection, recipe disposition ledger,
and truthful technical vs. analytical failure classification.

Shared identically across local and remote investigation sessions to ensure
large/complex C/C++ targets (100K+ LOC) measure meaningful investigative progress
rather than elapsed wall-clock time alone, detect stagnation, pivot strategy when
current paths are unproductive, and account for every recipe's disposition.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


# Truthful failure classification categories (Phase 7)
FAIL_COLLECTION = "COLLECTION_FAILURE"
FAIL_RECIPE_EXECUTION = "RECIPE_EXECUTION_FAILURE"
FAIL_PLANNING = "PLANNING_FAILURE"
FAIL_NO_ELIGIBLE_RECIPES = "NO_ELIGIBLE_RECIPES"
FAIL_STAGNATION = "INVESTIGATION_STAGNATION"
FAIL_EVIDENCE_INSUFFICIENCY = "EVIDENCE_INSUFFICIENCY"
FAIL_HYPOTHESIS_VERIFICATION = "HYPOTHESIS_VERIFICATION_FAILURE"
FAIL_DEADLINE_EXPIRATION = "DEADLINE_EXPIRATION"
FAIL_CANCELLATION = "CANCELLATION"
FAIL_FINALIZATION = "FINALIZATION_FAILURE"

TECHNICAL_FAILURE_CATEGORIES = frozenset({
    FAIL_COLLECTION,
    FAIL_RECIPE_EXECUTION,
    FAIL_PLANNING,
    FAIL_DEADLINE_EXPIRATION,
    FAIL_CANCELLATION,
    FAIL_FINALIZATION,
})

ANALYTICAL_FAILURE_CATEGORIES = frozenset({
    FAIL_NO_ELIGIBLE_RECIPES,
    FAIL_STAGNATION,
    FAIL_EVIDENCE_INSUFFICIENCY,
    FAIL_HYPOTHESIS_VERIFICATION,
})


def _stable_fingerprint(obj: Any) -> str:
    try:
        raw = json.dumps(obj, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        raw = repr(obj)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class StagnationSignal:
    is_stagnant: bool
    reason: str
    stagnant_domain: Optional[str] = None
    consecutive_stagnant_steps: int = 0
    recommended_action: str = "CONTINUE"  # CONTINUE | SWITCH_DOMAIN | EXPAND_CANDIDATES | HALT_STAGNANT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_stagnant": self.is_stagnant,
            "reason": self.reason,
            "stagnant_domain": self.stagnant_domain,
            "consecutive_stagnant_steps": self.consecutive_stagnant_steps,
            "recommended_action": self.recommended_action,
        }


class InvestigationProgressTracker:
    """Tracks meaningful investigative work (not elapsed time alone) and detects stagnation."""

    def __init__(self, stagnation_threshold: int = 3):
        self.stagnation_threshold = max(2, int(stagnation_threshold))
        self.recipes_executed: int = 0
        self.recipes_completed_with_verdict: int = 0
        self.recipes_inconclusive: int = 0
        self.recipes_failed: int = 0
        self.recipes_repeated: int = 0
        self.new_valid_evidence_count: int = 0
        self.reused_evidence_count: int = 0
        self.hypotheses_created: int = 0
        self.hypotheses_strengthened: int = 0
        self.hypotheses_rejected: int = 0
        self.hypotheses_verified: int = 0
        self.new_candidates_generated: int = 0
        self.replanning_events: int = 0
        self.strategy_changes: int = 0

        self._seen_recipes: Set[str] = set()
        self._seen_evidence_fps: Set[str] = set()
        self._discovered_entities: Set[str] = set()
        self._explored_domains: Set[str] = set()
        self._domain_stagnation: Dict[str, int] = {}
        self._consecutive_stagnant_steps: int = 0
        self._last_domain: Optional[str] = None
        self._last_stagnation_signal: Optional[StagnationSignal] = None
        self._step_history: List[Dict[str, Any]] = []

    def record_step(
        self,
        *,
        recipe_id: str,
        domain: str,
        eval_status: str,
        evidence_items: Sequence[Any] = (),
        discovered_entities: Iterable[str] = (),
        hypotheses_delta: Optional[Dict[str, int]] = None,
        is_reused: bool = False,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Records a recipe execution step and computes whether genuine investigative progress occurred."""
        self.recipes_executed += 1
        dom = str(domain or "UNKNOWN")
        self._explored_domains.add(dom)
        self._last_domain = dom

        is_repeat = recipe_id in self._seen_recipes
        if is_repeat:
            self.recipes_repeated += 1
        else:
            self._seen_recipes.add(recipe_id)

        st_upper = str(eval_status or "").upper()
        if error or st_upper == "ERROR":
            self.recipes_failed += 1
        elif st_upper in ("SUPPORTED", "CONTRADICTED", "PASS", "FAIL"):
            self.recipes_completed_with_verdict += 1
        else:
            self.recipes_inconclusive += 1

        new_ev_this_step = 0
        for ev in evidence_items or ():
            fp = _stable_fingerprint(ev)
            if fp not in self._seen_evidence_fps:
                self._seen_evidence_fps.add(fp)
                new_ev_this_step += 1
            else:
                self.reused_evidence_count += 1
        if is_reused:
            self.reused_evidence_count += 1
        self.new_valid_evidence_count += new_ev_this_step

        new_entities_this_step = 0
        for ent in discovered_entities or ():
            s = str(ent or "").strip()
            if s and s not in self._discovered_entities:
                self._discovered_entities.add(s)
                new_entities_this_step += 1

        hd = hypotheses_delta or {}
        h_created = int(hd.get("created", 0))
        h_strengthened = int(hd.get("strengthened", 0))
        h_rejected = int(hd.get("rejected", 0))
        h_verified = int(hd.get("verified", 0))
        self.hypotheses_created += h_created
        self.hypotheses_strengthened += h_strengthened
        self.hypotheses_rejected += h_rejected
        self.hypotheses_verified += h_verified

        # Genuine progress requires non-duplicate new evidence, newly discovered entities,
        # or hypothesis state movement (a repeated or empty INCONCLUSIVE/ERROR step is NOT progress).
        made_progress = bool(
            (not is_repeat and new_ev_this_step > 0 and st_upper in ("SUPPORTED", "CONTRADICTED", "PASS", "FAIL"))
            or new_entities_this_step > 0
            or (h_created + h_strengthened + h_rejected + h_verified) > 0
        )

        if made_progress:
            self._consecutive_stagnant_steps = 0
            self._domain_stagnation[dom] = 0
        else:
            self._consecutive_stagnant_steps += 1
            self._domain_stagnation[dom] = self._domain_stagnation.get(dom, 0) + 1

        entry = {
            "recipe_id": recipe_id,
            "domain": dom,
            "status": st_upper,
            "is_repeat": is_repeat,
            "new_evidence": new_ev_this_step,
            "new_entities": new_entities_this_step,
            "made_progress": made_progress,
            "consecutive_stagnant_steps": self._consecutive_stagnant_steps,
        }
        self._step_history.append(entry)
        return entry

    def record_replan(self, *, strategy_changed: bool = False, new_candidates: int = 0) -> None:
        self.replanning_events += 1
        if strategy_changed:
            self.strategy_changes += 1
        if new_candidates > 0:
            self.new_candidates_generated += int(new_candidates)

    def detect_stagnation(
        self,
        *,
        remaining_domains: Sequence[str] = (),
        unplanned_eligible_count: int = 0,
    ) -> StagnationSignal:
        """Evaluates whether the investigation is stagnant and recommends the next strategy change."""
        dom = self._last_domain
        dom_stag = self._domain_stagnation.get(dom, 0) if dom else 0

        if self._consecutive_stagnant_steps < self.stagnation_threshold and dom_stag < 2:
            sig = StagnationSignal(
                is_stagnant=False,
                reason="progressing",
                stagnant_domain=None,
                consecutive_stagnant_steps=self._consecutive_stagnant_steps,
                recommended_action="CONTINUE",
            )
            self._last_stagnation_signal = sig
            return sig

        other_domains = [d for d in remaining_domains if d and d != dom]
        if other_domains:
            sig = StagnationSignal(
                is_stagnant=True,
                reason=(
                    f"Domain '{dom}' produced {dom_stag} consecutive unproductive/inconclusive step(s) "
                    f"(overall stagnant streak={self._consecutive_stagnant_steps}); switching to unexplored domain"
                ),
                stagnant_domain=dom,
                consecutive_stagnant_steps=self._consecutive_stagnant_steps,
                recommended_action="SWITCH_DOMAIN",
            )
        elif unplanned_eligible_count > 0:
            sig = StagnationSignal(
                is_stagnant=True,
                reason=(
                    f"{self._consecutive_stagnant_steps} consecutive steps yielded no new evidence; "
                    f"expanding plan with {unplanned_eligible_count} unexplored eligible recipe(s)"
                ),
                stagnant_domain=dom,
                consecutive_stagnant_steps=self._consecutive_stagnant_steps,
                recommended_action="EXPAND_CANDIDATES",
            )
        else:
            sig = StagnationSignal(
                is_stagnant=True,
                reason=(
                    f"Investigation stagnated after {self._consecutive_stagnant_steps} unproductive step(s) "
                    f"with no remaining alternative domains or unexplored eligible recipes"
                ),
                stagnant_domain=dom,
                consecutive_stagnant_steps=self._consecutive_stagnant_steps,
                recommended_action="HALT_STAGNANT",
            )
        self._last_stagnation_signal = sig
        return sig

    @property
    def evidence_reuse_ratio(self) -> float:
        total = self.new_valid_evidence_count + self.reused_evidence_count
        return round(self.reused_evidence_count / total, 4) if total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recipes_executed": self.recipes_executed,
            "recipes_completed_with_verdict": self.recipes_completed_with_verdict,
            "recipes_inconclusive": self.recipes_inconclusive,
            "recipes_failed": self.recipes_failed,
            "recipes_repeated": self.recipes_repeated,
            "new_valid_evidence_count": self.new_valid_evidence_count,
            "reused_evidence_count": self.reused_evidence_count,
            "evidence_reuse_ratio": self.evidence_reuse_ratio,
            "discovered_entities_count": len(self._discovered_entities),
            "explored_domains": sorted(self._explored_domains),
            "hypotheses_created": self.hypotheses_created,
            "hypotheses_strengthened": self.hypotheses_strengthened,
            "hypotheses_rejected": self.hypotheses_rejected,
            "hypotheses_verified": self.hypotheses_verified,
            "new_candidates_generated": self.new_candidates_generated,
            "replanning_events": self.replanning_events,
            "strategy_changes": self.strategy_changes,
            "consecutive_stagnant_steps": self._consecutive_stagnant_steps,
            "last_stagnation": self._last_stagnation_signal.to_dict() if self._last_stagnation_signal else None,
        }


def build_recipe_dispositions(
    plan_steps: Sequence[Any],
    executed_checks: Sequence[Any],
    stop_reason: str = "",
) -> List[Dict[str, Any]]:
    """Builds an exhaustive disposition record for every planned recipe (zero unexplained absences)."""
    by_rid: Dict[str, Any] = {}
    for chk in executed_checks or ():
        rid = str(getattr(chk, "recipe_id", "") or "")
        if rid:
            by_rid[rid] = chk

    dispositions: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    stop_u = str(stop_reason or "").upper()

    for step in plan_steps or ():
        rid = str(getattr(step, "recipe_id", "") or "")
        if not rid or rid in seen:
            continue
        seen.add(rid)
        st = str(getattr(step, "status", "PENDING") or "PENDING").upper()
        nrr = str(getattr(step, "not_run_reason", "") or "")
        chk = by_rid.get(rid)

        if chk is not None:
            chk_st = str(getattr(chk, "status", "")).upper()
            if "." in chk_st:
                chk_st = chk_st.split(".")[-1]
            if chk_st == "FAIL":
                disp = "EXECUTED_SUPPORTED"
            elif chk_st == "PASS":
                disp = "EXECUTED_CLEAN"
            elif chk_st == "ERROR":
                err_txt = str(getattr(chk, "error_details", "") or "").lower()
                if "timeout" in err_txt or "deadline" in err_txt:
                    disp = "TIMEOUT"
                elif "cancel" in err_txt:
                    disp = "CANCELLED"
                else:
                    disp = "FAILED"
            else:
                disp = "EXECUTED_INCONCLUSIVE"
            reason = str(getattr(chk, "technical_interpretation", "") or getattr(chk, "error_details", "") or "")
        elif st == "SKIPPED":
            if nrr == "time_budget":
                disp = "BUDGET_EXCLUDED"
            elif nrr == "early_stop_sufficient_evidence":
                disp = "NO_LONGER_RELEVANT"
            elif nrr == "remote_connection_lost":
                disp = "BLOCKED_BY_PREREQUISITE"
            elif nrr == "already_executed_in_session":
                disp = "SKIPPED"
            else:
                disp = "SKIPPED"
            reason = nrr or "skipped_by_planner"
        elif st == "FAILED":
            disp = "FAILED"
            reason = str((getattr(step, "result", None) or {}).get("error") or "step_failed")
        else:
            # PENDING or RUNNING when session terminated -> attribute explicitly to stop_reason!
            if "BUDGET" in stop_u or "DEADLINE" in stop_u or "TIMEOUT" in stop_u:
                disp = "BUDGET_EXCLUDED"
                reason = f"not_executed_due_to_{stop_u.lower()}"
            elif "CANCEL" in stop_u:
                disp = "CANCELLED"
                reason = "session_cancelled"
            elif "STAGNAT" in stop_u:
                disp = "SKIPPED"
                reason = "investigation_stagnation"
            elif "REMOTE_CONNECTION_LOST" in stop_u:
                disp = "BLOCKED_BY_PREREQUISITE"
                reason = "remote_connection_lost"
            else:
                disp = "PENDING"
                reason = nrr or (f"unexecuted_at_{stop_u.lower()}" if stop_u else "not_reached_before_termination")

        dispositions.append({
            "recipe_id": rid,
            "domain": str(getattr(step, "domain", "") or ""),
            "step_status": st,
            "disposition": disp,
            "reason": reason[:240],
        })

    return dispositions


def classify_diagnosis_failure(
    *,
    verdict: str,
    stop_reason: str,
    dispositions: Sequence[Dict[str, Any]],
    progress: Optional[Dict[str, Any]] = None,
    evidence_count: int = 0,
    error_message: str = "",
) -> Optional[Dict[str, Any]]:
    """Returns structured technical vs. analytical failure classification when verdict is not CONFIRMED/HEALTHY."""
    v_u = str(verdict or "").upper()
    if v_u in ("CONFIRMED_FAULT", "HEALTHY", "DEGRADED"):
        return None

    sr_u = str(stop_reason or "").upper()
    err_l = str(error_message or "").lower()
    prog = progress or {}
    executed = [d for d in dispositions if d["disposition"].startswith("EXECUTED_")]
    failed = [d for d in dispositions if d["disposition"] in ("FAILED", "TIMEOUT")]
    not_run = [d for d in dispositions if not d["disposition"].startswith("EXECUTED_")]

    if "CANCEL" in sr_u or "cancel" in err_l:
        category = FAIL_CANCELLATION
    elif "REMOTE_CONNECTION_LOST" in sr_u or "TARGET_UNREADABLE" in sr_u or "COLLECTION" in sr_u:
        category = FAIL_COLLECTION
    elif "BUDGET_EXHAUSTED" in sr_u or "DEADLINE" in sr_u or "TIMEOUT" in sr_u:
        category = FAIL_DEADLINE_EXPIRATION
    elif "PLAN" in sr_u and "FAIL" in sr_u:
        category = FAIL_PLANNING
    elif not dispositions:
        category = FAIL_NO_ELIGIBLE_RECIPES
    elif "STAGNAT" in sr_u or (prog.get("last_stagnation") or {}).get("recommended_action") == "HALT_STAGNANT":
        category = FAIL_STAGNATION
    elif failed and len(failed) >= max(1, len(executed)):
        category = FAIL_RECIPE_EXECUTION
    elif "FINALIZ" in sr_u:
        category = FAIL_FINALIZATION
    elif "VERIF" in sr_u:
        category = FAIL_HYPOTHESIS_VERIFICATION
    else:
        category = FAIL_EVIDENCE_INSUFFICIENCY

    kind = "TECHNICAL" if category in TECHNICAL_FAILURE_CATEGORIES else "ANALYTICAL"
    missing_reasons = sorted({d["reason"] for d in not_run if d.get("reason")})[:6]

    return {
        "category": category,
        "kind": kind,
        "stop_reason": stop_reason or "UNKNOWN",
        "what_was_investigated": [d["recipe_id"] for d in executed],
        "what_was_not_investigated": [
            {"recipe_id": d["recipe_id"], "disposition": d["disposition"], "reason": d["reason"]}
            for d in not_run
        ],
        "evidence_obtained_count": int(evidence_count),
        "missing_evidence_reasons": missing_reasons,
        "stagnation_detected": bool((prog.get("last_stagnation") or {}).get("is_stagnant", False)),
    }
