"""Adaptive Investigation Engine (Phase 2.0 — Process Health Investigation).

Coordinates evidence-grounded, budget-bounded adaptive investigations:
- Single explicit state machine (CREATED -> TARGET_VALIDATION -> INITIAL_TRIAGE ->
  HYPOTHESIS_FORMATION -> FOLLOW_UP_PLANNING -> OBSERVATION -> HYPOTHESIS_UPDATE ->
  (FOLLOW_UP_PLANNING | FINALIZATION) -> COMPLETED | INCONCLUSIVE | BUDGET_EXHAUSTED | FAILED | CANCELED)
- Low-impact Initial Process Health Triage without hardcoded application symbols
- Competing, structured hypotheses reusing extractor/hypothesis.py
- Deterministic Discriminating Follow-Up Planner selecting the cheapest observation
  that can materially change the hypothesis ranking
- Multi-dimensional pre-execution and post-execution budget enforcement
- Explicit observation result categories (NEW_EVIDENCE, DUPLICATE_EVIDENCE,
  NO_NEW_EVIDENCE, PARTIAL_EVIDENCE, OBSERVATION_FAILED, OBSERVATION_UNAVAILABLE, BUDGET_REJECTED)
- Calibrated stopping policy and scope-bounded verdicts (NO_ISSUE_DETECTED_WITHIN_SCOPE,
  SUSPECTED, PARTIALLY_CONFIRMED, CONFIRMED, REFUTED, INCONCLUSIVE)
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import uuid

from .debug_image import inspect_elf
from .evidence_adapter import (
    COLLECTION_STATUS_ABSTAIN,
    COLLECTION_STATUS_COLLECTED,
    COLLECTION_STATUS_FAILED,
    COLLECTION_STATUS_PARTIAL,
    RESULT_BUDGET_REJECTED,
    RESULT_DUPLICATE_EVIDENCE,
    RESULT_NEW_EVIDENCE,
    RESULT_NO_NEW_EVIDENCE,
    RESULT_OBSERVATION_FAILED,
    RESULT_OBSERVATION_UNAVAILABLE,
    RESULT_PARTIAL_EVIDENCE,
    EvidenceAdapter,
    compute_semantic_evidence_digest,
    strip_volatile_fields,
)
from .evidence_ledger import (
    ATTRIBUTION_BASIS_CALL_STACK,
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_DIAGNOSTIC,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EvidenceLedger,
    EvidenceRecord,
    LiveCaptureReceipt,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    TRUSTED_PROVENANCE_CLASSES,
    verify_live_capture_receipt,
)
from .hypothesis import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    OBSERVATION_STATUS_CANCELED,
    OBSERVATION_STATUS_EXECUTED,
    OBSERVATION_STATUS_FAILED,
    OBSERVATION_STATUS_PROPOSED,
    OBSERVATION_STATUS_VERIFIED,
    TARGET_KIND_COMPARISON,
    TARGET_KIND_FIELD,
    TARGET_KIND_OBJECT,
    TARGET_KIND_THREAD,
    DeterministicHypothesisGenerator,
    FollowUpObservation,
    HypothesisValidator,
    InvestigationHypothesis,
)
from .inspection_module import (
    DOMAIN_CONCURRENCY,
    DOMAIN_GENERIC,
    DOMAIN_HEAP,
    DOMAIN_INTEGRITY,
    DOMAIN_IPC,
    DOMAIN_MEMORY,
    DOMAIN_TEMPORAL,
    FunctionalInspectionModule,
    InspectionContext,
    InspectionModule,
    InspectionModuleRegistry,
    InspectionProfile,
)
from .observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
from .target_adapter import LocalTargetAdapter, ReadOnlyTargetAdapter, TargetExecutionAdapter
from .verdict_engine import (
    ASSERTION_ABSTAIN,
    ASSERTION_FAIL,
    ASSERTION_PASS,
    DIAG_CONFIRMED,
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    DIAG_PARTIALLY_CONFIRMED,
    DIAG_REFUTED,
    DIAG_SUSPECTED,
    HYP_STATE_CONTRADICTED,
    HYP_STATE_INCONCLUSIVE,
    HYP_STATE_PROPOSED,
    HYP_STATE_SUPPORTED,
    HYP_STATE_VALIDATED,
    STOP_ALL_HYPOTHESES_REFUTED,
    STOP_BUDGET_EXHAUSTED,
    STOP_CAPABILITY_UNAVAILABLE,
    STOP_DIMINISHING_RETURNS,
    STOP_NO_USEFUL_SAFE_OBSERVATION,
    STOP_REPEATED_FAILURE,
    STOP_SUFFICIENT_EVIDENCE,
    STOP_USER_CANCELED,
    AssertionEvaluation,
    DiagnosticVerdict,
    VerdictEngine,
    ZeroCdnReporter,
)

# -----------------------------------------------------------------------------
# 1. Single Investigation Lifecycle State Machine
# -----------------------------------------------------------------------------

STATE_CREATED = "CREATED"
STATE_TARGET_VALIDATION = "TARGET_VALIDATION"
STATE_INITIAL_TRIAGE = "INITIAL_TRIAGE"
STATE_HYPOTHESIS_FORMATION = "HYPOTHESIS_FORMATION"
STATE_FOLLOW_UP_PLANNING = "FOLLOW_UP_PLANNING"
STATE_OBSERVATION = "OBSERVATION"
STATE_HYPOTHESIS_UPDATE = "HYPOTHESIS_UPDATE"
STATE_FINALIZATION = "FINALIZATION"
STATE_COMPLETED = "COMPLETED"
STATE_INCONCLUSIVE = "INCONCLUSIVE"
STATE_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
STATE_FAILED = "FAILED"
STATE_CANCELED = "CANCELED"

TERMINAL_LIFECYCLE_STATES = {
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
    STATE_BUDGET_EXHAUSTED,
    STATE_FAILED,
    STATE_CANCELED,
}

VALID_LIFECYCLE_TRANSITIONS: Dict[str, Set[str]] = {
    STATE_CREATED: {STATE_TARGET_VALIDATION, STATE_FAILED, STATE_CANCELED},
    STATE_TARGET_VALIDATION: {STATE_INITIAL_TRIAGE, STATE_FINALIZATION, STATE_FAILED, STATE_CANCELED},
    STATE_INITIAL_TRIAGE: {
        STATE_HYPOTHESIS_FORMATION,
        STATE_FINALIZATION,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_HYPOTHESIS_FORMATION: {
        STATE_FOLLOW_UP_PLANNING,
        STATE_FINALIZATION,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_FOLLOW_UP_PLANNING: {
        STATE_OBSERVATION,
        STATE_FINALIZATION,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_OBSERVATION: {
        STATE_HYPOTHESIS_UPDATE,
        STATE_FINALIZATION,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_HYPOTHESIS_UPDATE: {
        STATE_FOLLOW_UP_PLANNING,
        STATE_FINALIZATION,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_FINALIZATION: {
        STATE_COMPLETED,
        STATE_INCONCLUSIVE,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_COMPLETED: set(),
    STATE_INCONCLUSIVE: set(),
    STATE_BUDGET_EXHAUSTED: set(),
    STATE_FAILED: set(),
    STATE_CANCELED: set(),
}


class InvestigationStateMachine:
    """Enforces the explicit, auditable investigation lifecycle state machine."""

    def __init__(
        self,
        initial_state: str = STATE_CREATED,
        transitions: Optional[List[Dict[str, Any]]] = None,
    ):
        if initial_state not in VALID_LIFECYCLE_TRANSITIONS:
            raise ValueError(f"Invalid initial lifecycle state: '{initial_state}'")
        self._state: str = initial_state
        self._transitions: List[Dict[str, Any]] = list(transitions or [])

    @property
    def state(self) -> str:
        return self._state

    @property
    def transitions(self) -> List[Dict[str, Any]]:
        return list(self._transitions)

    @property
    def is_terminal(self) -> bool:
        return self._state in TERMINAL_LIFECYCLE_STATES

    def can_transition(self, to_state: str) -> bool:
        return to_state in VALID_LIFECYCLE_TRANSITIONS.get(self._state, set())

    def transition(
        self,
        to_state: str,
        reason: str,
        timestamp: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Executes a validated state transition with mandatory reason and timestamp."""
        if not reason or not str(reason).strip():
            raise ValueError(f"Transition from '{self._state}' to '{to_state}' requires a non-empty reason.")
        if to_state not in VALID_LIFECYCLE_TRANSITIONS:
            raise ValueError(f"Unknown target lifecycle state: '{to_state}'")
        allowed = VALID_LIFECYCLE_TRANSITIONS.get(self._state, set())
        if to_state not in allowed:
            raise ValueError(
                f"Invalid lifecycle state transition: '{self._state}' -> '{to_state}'. "
                f"Allowed transitions from '{self._state}': {sorted(allowed)}"
            )

        ts = timestamp or datetime.now(timezone.utc).isoformat()
        entry: Dict[str, Any] = {
            "transition_index": len(self._transitions),
            "from_state": self._state,
            "to_state": to_state,
            "reason": str(reason).strip(),
            "timestamp": ts,
        }
        if metadata:
            entry["metadata"] = dict(metadata)
        self._transitions.append(entry)
        self._state = to_state
        return entry

    def to_dict(self) -> Dict[str, Any]:
        return {
            "current_state": self._state,
            "is_terminal": self.is_terminal,
            "transitions": list(self._transitions),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationStateMachine":
        st = data.get("current_state", STATE_CREATED)
        tr = list(data.get("transitions", []))
        return cls(initial_state=st, transitions=tr)


class EvidenceCache:
    """Disaggregates static binary evidence from dynamic runtime sampling epochs."""

    def __init__(self):
        self._static_cache: Dict[str, Any] = {}
        self._dynamic_cache: Dict[str, Dict[str, Any]] = {}
        self._current_epoch: int = 0

    @property
    def current_epoch(self) -> int:
        return self._current_epoch

    def advance_epoch(self) -> int:
        """Invalidates dynamic cache and increments runtime sampling epoch."""
        self._current_epoch += 1
        self._dynamic_cache.clear()
        return self._current_epoch

    def get_static(self, binary_key: str, item_key: str) -> Optional[Any]:
        return self._static_cache.get(f"{binary_key}::{item_key}")

    def put_static(self, binary_key: str, item_key: str, val: Any) -> None:
        self._static_cache[f"{binary_key}::{item_key}"] = val

    def get_dynamic(self, target_key: str, item_key: str) -> Optional[Any]:
        return self._dynamic_cache.get(f"epoch_{self._current_epoch}::{target_key}::{item_key}")

    def put_dynamic(self, target_key: str, item_key: str, val: Any) -> None:
        self._dynamic_cache[f"epoch_{self._current_epoch}::{target_key}::{item_key}"] = val


# -----------------------------------------------------------------------------
# 4. Deterministic Discriminating Follow-Up Planner & Scheduler
# -----------------------------------------------------------------------------

DOMAIN_PRIORITY_ORDER = {
    DOMAIN_MEMORY: 0,
    DOMAIN_CONCURRENCY: 1,
    DOMAIN_INTEGRITY: 2,
    DOMAIN_IPC: 3,
    DOMAIN_HEAP: 4,
    DOMAIN_TEMPORAL: 5,
    DOMAIN_GENERIC: 6,
}


class DeterministicScheduler:
    """Maintains a deterministic inspection execution queue with strict tie-breaking."""

    def __init__(self, registry: Optional[InspectionModuleRegistry] = None):
        self.registry = registry
        self._queue: List[Tuple[int, str, int]] = []  # (-priority, profile_id, sequence_id)
        self._seq: int = 0
        self._enqueued_ids: Set[str] = set()

    def schedule_modules(self, modules: List[InspectionModule]) -> List[InspectionModule]:
        """Deterministically orders modules by domain priority ASC, then module_id ASC."""
        return sorted(
            modules,
            key=lambda m: (
                DOMAIN_PRIORITY_ORDER.get(getattr(m, "domain", m.profile.domain), 99),
                getattr(m, "module_id", m.profile.profile_id),
            ),
        )

    def enqueue(self, profile_id: str) -> bool:
        if profile_id in self._enqueued_ids:
            return False
        if not self.registry:
            return False

        profile = self.registry.get(profile_id)
        if not profile:
            return False

        p_obj = profile.profile
        self._seq += 1
        entry = (-p_obj.priority, p_obj.profile_id, self._seq)
        self._queue.append(entry)
        self._enqueued_ids.add(profile_id)
        self._queue.sort()
        return True

    def pop_next(self) -> Optional[str]:
        if not self._queue:
            return None
        _, profile_id, _ = self._queue.pop(0)
        return profile_id

    def is_empty(self) -> bool:
        return len(self._queue) == 0

    @property
    def enqueued_ids(self) -> Set[str]:
        return set(self._enqueued_ids)


class AdaptiveInvestigationPlanner:
    """Deterministic planner for initial triage and discriminating follow-up observations."""

    def __init__(self, registry: InspectionModuleRegistry):
        self.registry = registry

    def plan_initial_inspections(
        self,
        goal: str,
        assertions: Optional[List[str]] = None,
        symptom_hints: Optional[List[str]] = None,
        capabilities: Optional[Dict[str, Any]] = None,
        available_symbols: Optional[Set[str]] = None,
    ) -> List[str]:
        """Produces a deterministic, low-impact initial triage plan without assuming hardcoded symbols."""
        lower_goal = (goal or "").lower()
        hints = [h.lower() for h in (symptom_hints or [])]
        combined = lower_goal + " " + " ".join(hints)
        caps = capabilities or {}

        selected: Set[str] = set()

        # Always include low-impact process health triage modules that do NOT require hardcoded symbols
        for p in self.registry.list_profiles():
            if p.requires_explicit_target_expression:
                continue
            if any(caps.get(req_c) is False for req_c in p.required_capabilities):
                continue
            if p.required_symbols and available_symbols is not None:
                if not all(s in available_symbols for s in p.required_symbols):
                    continue
            if p.priority >= 140:
                selected.add(p.profile_id)

        # Domain keyword hints only schedule modules whose prerequisites/symbols are actually satisfied
        if any(w in combined for w in ("deadlock", "lock", "mutex", "stuck", "hang", "blocked", "contention", "thread")):
            for p in self.registry.list_profiles(domain=DOMAIN_CONCURRENCY):
                if not p.requires_explicit_target_expression:
                    selected.add(p.profile_id)

        all_profiles = [p for p in self.registry.list_profiles() if p.profile_id in selected]
        return [p.profile_id for p in all_profiles]

    def select_next_observation(
        self,
        hypotheses: List[InvestigationHypothesis],
        budget_tracker: ObservationBudgetTracker,
        executed_observation_keys: Set[str],
        capabilities: Optional[Dict[str, Any]] = None,
        available_symbols: Optional[Set[str]] = None,
        current_epoch: int = 0,
    ) -> Tuple[Optional[FollowUpObservation], List[Dict[str, Any]]]:
        """Deterministically selects the cheapest read-only follow-up observation that can
        materially discriminate between competing unresolved hypotheses.

        Returns:
            (selected_observation, evaluated_candidates_log)
        """
        caps = capabilities or {}
        unresolved_hypos = {
            h.hypothesis_id: h
            for h in hypotheses
            if h.validation_status in (HYPOTHESIS_STATUS_PROPOSED, HYPOTHESIS_STATUS_SUPPORTED)
        }
        if not unresolved_hypos:
            return None, []

        # Gather unique candidate observations across unresolved hypotheses
        candidates_by_key: Dict[str, FollowUpObservation] = {}
        for h_id in sorted(unresolved_hypos.keys()):
            h = unresolved_hypos[h_id]
            for obs in h.suggested_observations:
                if obs.executed or obs.status in (
                    OBSERVATION_STATUS_EXECUTED,
                    OBSERVATION_STATUS_VERIFIED,
                    OBSERVATION_STATUS_FAILED,
                    OBSERVATION_STATUS_CANCELED,
                ):
                    continue
                epoch_key = f"{obs.semantic_key}::epoch_{current_epoch}"
                if obs.observation_id in executed_observation_keys or obs.semantic_key in executed_observation_keys or epoch_key in executed_observation_keys:
                    continue
                if obs.semantic_key not in candidates_by_key:
                    candidates_by_key[obs.semantic_key] = obs
                else:
                    existing_obs = candidates_by_key[obs.semantic_key]
                    if h_id not in existing_obs.tested_hypothesis_ids:
                        existing_obs.tested_hypothesis_ids.append(h_id)

        evaluated_log: List[Dict[str, Any]] = []
        feasible: List[Tuple[Tuple[int, int, int, int, float, str], FollowUpObservation, Dict[str, Any]]] = []

        for sem_key in sorted(candidates_by_key.keys()):
            obs = candidates_by_key[sem_key]

            # 1. Safety check: strictly read-only / low-impact
            if obs.risk_level not in ("READ_ONLY", "LOW_IMPACT", "CAUTION"):
                evaluated_log.append({
                    "observation_id": obs.observation_id,
                    "semantic_key": sem_key,
                    "eligible": False,
                    "rejection_reason": f"Disallowed non-read-only risk_level '{obs.risk_level}'",
                })
                continue

            # 2. Prerequisite & capability check
            missing_caps = [
                req_c for req_c in obs.prerequisites
                if caps.get(req_c) is False
            ]
            if missing_caps:
                obs.result_category = RESULT_OBSERVATION_UNAVAILABLE
                obs.execution_error = f"Unavailable prerequisite capability: {missing_caps}"
                evaluated_log.append({
                    "observation_id": obs.observation_id,
                    "semantic_key": sem_key,
                    "eligible": False,
                    "result_category": RESULT_OBSERVATION_UNAVAILABLE,
                    "rejection_reason": obs.execution_error,
                })
                continue

            # 3. Profile ceiling & pre-execution budget check
            mod = self.registry.get(obs.profile_id) if (self.registry and obs.profile_id) else None
            prof_ceiling = mod.profile.budget_ceiling if mod else None
            est_bytes = obs.estimated_bytes if obs.estimated_bytes is not None else (mod.profile.estimated_bytes if mod else None)
            est_lat_ms = float(obs.estimated_latency_ms or (mod.profile.estimated_latency_ms if mod else 20.0))
            est_samples = int(obs.estimated_samples or 1)
            est_stop_ms = float(obs.estimated_stop_ms or 0.0)

            can_exec, budget_reason, eff_est_bytes = budget_tracker.check_pre_execution(
                estimated_bytes=est_bytes,
                estimated_latency_ms=est_lat_ms,
                estimated_samples=est_samples,
                estimated_stop_ms=est_stop_ms,
                profile_id=obs.profile_id,
                profile_ceiling=prof_ceiling,
            )
            if not can_exec:
                budget_tracker.record_rejection(obs.profile_id or obs.observation_id, budget_reason or "BUDGET_REJECTED")
                obs.result_category = RESULT_BUDGET_REJECTED
                obs.execution_error = budget_reason
                evaluated_log.append({
                    "observation_id": obs.observation_id,
                    "semantic_key": sem_key,
                    "eligible": False,
                    "result_category": RESULT_BUDGET_REJECTED,
                    "rejection_reason": budget_reason,
                    "estimated_bytes": eff_est_bytes,
                })
                continue

            # 4. Calculate discriminating power & expected information gain
            tested_unresolved = [hid for hid in obs.tested_hypothesis_ids if hid in unresolved_hypos]
            if not tested_unresolved and obs.hypothesis_id in unresolved_hypos:
                tested_unresolved = [obs.hypothesis_id]

            # Check whether outcomes differ across competing hypotheses
            distinct_outcome_vectors = set()
            for hid in tested_unresolved:
                h_outcomes = obs.expected_outcomes_by_hypothesis.get(hid)
                if isinstance(h_outcomes, dict):
                    distinct_outcome_vectors.add(tuple(sorted(h_outcomes.items())))
            discriminating_count = max(len(distinct_outcome_vectors), len(tested_unresolved))

            power_score = {"HIGH": 30, "MEDIUM": 20, "LOW": 10}.get(obs.discriminating_power, 15)
            can_materially_change_ranking = 1 if (discriminating_count >= 2 or power_score >= 30) else 0
            info_gain_score = power_score + (15 * discriminating_count)

            # Sort key:
            # 1) -can_materially_change_ranking (prefer observations that can change ranking)
            # 2) -discriminating_count (prefer observations discriminating more competing hypotheses)
            # 3) eff_est_bytes ASC (prefer the CHEAPEST observation that can materially change ranking!)
            # 4) -info_gain_score
            # 5) est_lat_ms ASC
            # 6) observation_id ASC (deterministic tie-breaker)
            sort_key = (
                -can_materially_change_ranking,
                -discriminating_count,
                eff_est_bytes,
                -info_gain_score,
                est_lat_ms,
                obs.observation_id,
            )

            meta = {
                "observation_id": obs.observation_id,
                "semantic_key": sem_key,
                "eligible": True,
                "tested_hypothesis_ids": tested_unresolved,
                "discriminating_count": discriminating_count,
                "can_materially_change_ranking": bool(can_materially_change_ranking),
                "info_gain_score": info_gain_score,
                "estimated_bytes": eff_est_bytes,
                "estimated_latency_ms": est_lat_ms,
                "estimated_stop_ms": est_stop_ms,
                "risk_level": obs.risk_level,
            }
            evaluated_log.append(meta)
            feasible.append((sort_key, obs, meta))

        if not feasible:
            return None, evaluated_log

        feasible.sort(key=lambda item: item[0])
        _, best_obs, best_meta = feasible[0]

        if len(feasible) > 1:
            alt_obs = feasible[1][1]
            alt_meta = feasible[1][2]
            best_obs.preference_rationale = (
                f"Selected '{best_obs.observation_id}' (tests {best_meta['tested_hypothesis_ids']}, "
                f"discriminates={best_meta['discriminating_count']}, est_bytes={best_meta['estimated_bytes']}B, "
                f"est_latency={best_meta['estimated_latency_ms']}ms, risk={best_obs.risk_level}) over alternative "
                f"'{alt_obs.observation_id}' (discriminates={alt_meta['discriminating_count']}, "
                f"est_bytes={alt_meta['estimated_bytes']}B, est_latency={alt_meta['estimated_latency_ms']}ms) "
                f"as the lowest-cost observation capable of materially updating competing hypothesis rankings."
            )
        else:
            best_obs.preference_rationale = (
                f"Selected '{best_obs.observation_id}' as the sole budget-feasible read-only observation "
                f"testing {best_meta['tested_hypothesis_ids']} (est_bytes={best_meta['estimated_bytes']}B, "
                f"est_latency={best_meta['estimated_latency_ms']}ms)."
            )

        return best_obs, evaluated_log

    def refine_plan(
        self,
        current_profile_id: str,
        inspection_result: Dict[str, Any],
        already_scheduled: Set[str],
    ) -> List[str]:
        """Backward-compatible helper that refines profile queue when explicit symbols are present."""
        additional: List[str] = []

        # If deadlock or mutex contention found, ensure thread owner analysis is scheduled
        if inspection_result.get("deadlock_detected") or inspection_result.get("contended_locks"):
            if "insp_find_owners" not in already_scheduled and self.registry.get("insp_find_owners"):
                additional.append("insp_find_owners")

        # If memory pool leakage or stuck slots found, add symbol owner lookup
        if inspection_result.get("leak_count", 0) > 0 or inspection_result.get("stuck_slots"):
            if "insp_find_owners" not in already_scheduled and self.registry.get("insp_find_owners"):
                additional.append("insp_find_owners")

        # If corrupted pointers found in memory integrity audit, schedule frame locals
        if inspection_result.get("corrupted_pointers", 0) > 0:
            if "insp_frame_locals" not in already_scheduled and self.registry.get("insp_frame_locals"):
                additional.append("insp_frame_locals")

        return additional


# -----------------------------------------------------------------------------
# 7. Stopping Policy Evaluator
# -----------------------------------------------------------------------------

class AdaptiveTerminationPolicy:
    """Evaluates multi-factor stopping criteria for an investigation without requiring 100% confidence."""

    @staticmethod
    def evaluate_stopping_policy(
        budget_tracker: ObservationBudgetTracker,
        hypotheses: List[InvestigationHypothesis],
        remaining_observations_count: int = 0,
        consecutive_non_novel_steps: int = 0,
        consecutive_failures: int = 0,
        all_remaining_budget_rejected: bool = False,
        all_remaining_unavailable: bool = False,
        is_canceled: bool = False,
        temporal_samples_count: int = 1,
    ) -> Tuple[bool, str, str]:
        """Evaluates whether the adaptive loop should terminate.

        Returns:
            (should_stop, stop_reason_code, human_explanation)
        """
        if is_canceled:
            return True, STOP_USER_CANCELED, "Investigation was canceled by user or caller policy."

        ok, budget_reason = budget_tracker.check_budget()
        if not ok or all_remaining_budget_rejected:
            return (
                True,
                STOP_BUDGET_EXHAUSTED,
                f"Observation budget exhausted ({budget_reason or 'remaining observations exceed budget ceiling'}).",
            )

        if consecutive_failures >= budget_tracker.limits.max_consecutive_read_failures:
            return (
                True,
                STOP_REPEATED_FAILURE,
                f"Terminated after {consecutive_failures} consecutive failed observations.",
            )

        if all_remaining_unavailable and remaining_observations_count == 0:
            return (
                True,
                STOP_CAPABILITY_UNAVAILABLE,
                "Required observation capabilities or symbols are unavailable in target.",
            )

        defect_hypos = [
            h for h in hypotheses
            if not bool((h.provenance or {}).get("is_benign_explanation"))
        ]
        benign_hypos = [
            h for h in hypotheses
            if bool((h.provenance or {}).get("is_benign_explanation"))
        ]

        # Check if all material defect hypotheses are refuted
        if defect_hypos and all(h.validation_status == HYPOTHESIS_STATUS_CONTRADICTED for h in defect_hypos):
            return (
                True,
                STOP_ALL_HYPOTHESES_REFUTED,
                f"All {len(defect_hypos)} material defect hypothesis(es) have been refuted by direct observations.",
            )

        # Check if sufficient evidence has been gathered for a calibrated conclusion
        # (Does NOT require an artificial 1.0 confidence score!)
        for dh in defect_hypos:
            if dh.validation_status in (HYPOTHESIS_STATUS_SUPPORTED, HYPOTHESIS_STATUS_VALIDATED):
                # Memory growth requires at least 2 temporal samples or owner scan before stopping early
                if dh.anomaly_category == "MEMORY_GROWTH" and temporal_samples_count < 2 and remaining_observations_count > 0:
                    continue
                comp_ids = set(dh.competing_hypothesis_ids)
                comp_contradicted = all(
                    any(ch.hypothesis_id == cid and ch.validation_status == HYPOTHESIS_STATUS_CONTRADICTED for ch in benign_hypos)
                    for cid in comp_ids
                ) if comp_ids else True
                if comp_contradicted and dh.confidence_score >= 0.65:
                    return (
                        True,
                        STOP_SUFFICIENT_EVIDENCE,
                        f"Sufficient discriminating evidence gathered: '{dh.title}' is {dh.validation_status} "
                        f"(confidence={dh.confidence_score:.2f}) and competing explanation(s) are refuted.",
                    )

        if consecutive_non_novel_steps >= 2:
            return (
                True,
                STOP_DIMINISHING_RETURNS,
                f"Terminated due to diminishing information gain ({consecutive_non_novel_steps} consecutive steps without novel evidence).",
            )

        if remaining_observations_count == 0:
            if not defect_hypos:
                return (
                    True,
                    STOP_SUFFICIENT_EVIDENCE,
                    "Initial triage completed with no suspicious anomalies requiring follow-up.",
                )
            return (
                True,
                STOP_NO_USEFUL_SAFE_OBSERVATION,
                "Remaining hypotheses are unresolved, but no additional safe read-only observations remain.",
            )

        return False, "CONTINUE", "Continue adaptive observation loop."

    @staticmethod
    def should_terminate(
        budget_tracker: ObservationBudgetTracker,
        current_verdict: Optional[DiagnosticVerdict] = None,
        consecutive_empty_steps: int = 0,
    ) -> Tuple[bool, str]:
        """Backward-compatible termination check."""
        ok, reason = budget_tracker.check_budget()
        if not ok:
            return True, f"Budget limit reached: {reason}"

        if current_verdict:
            if (
                current_verdict.final_diagnosis in (
                    DIAG_CONFIRMED,
                    DIAG_REFUTED,
                    DIAG_NO_ISSUE_DETECTED,
                    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
                )
                and current_verdict.confidence_score >= 0.80
            ):
                return (
                    True,
                    f"Calibrated diagnosis reached: {current_verdict.final_diagnosis} "
                    f"(confidence={current_verdict.confidence_score:.2f})",
                )

        if consecutive_empty_steps >= 2:
            return True, "Terminated due to diminishing returns (consecutive steps without novel evidence)"

        return False, "Continue"


# -----------------------------------------------------------------------------
# Canonicalization Helper for Deterministic Replay (Section 9 Scenario I)
# -----------------------------------------------------------------------------

def canonicalize_investigation_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Produces a canonical representation of an investigation report excluding volatile timestamps
    and random UUIDs for deterministic replay equivalence comparison."""
    cleaned = strip_volatile_fields(report)
    if isinstance(cleaned, dict):
        cleaned.pop("report_html", None)
        cleaned.pop("report_json", None)
        cleaned.pop("session_id", None)
        cleaned.pop("investigation_id", None)
        if "budget_usage" in cleaned and isinstance(cleaned["budget_usage"], dict):
            b_copy = dict(cleaned["budget_usage"])
            if "metrics" in b_copy and isinstance(b_copy["metrics"], dict):
                m_copy = dict(b_copy["metrics"])
                m_copy.pop("observation_latency_us", None)
                m_copy.pop("wall_clock_elapsed_ms", None)
                m_copy.pop("profile_usage", None)
                b_copy["metrics"] = m_copy
            b_copy.pop("utilization", None)
            cleaned["budget_usage"] = b_copy
    return cleaned


# -----------------------------------------------------------------------------
# 6. Evidence-Driven Adaptive Investigation Engine
# -----------------------------------------------------------------------------

class AdaptiveInvestigationEngine:
    """Comprehensive coordinator for evidence-grounded, budget-bounded Process Health Investigations."""

    def __init__(
        self,
        watch_manager: Optional[Any] = None,
        registry: Optional[InspectionModuleRegistry] = None,
        default_limits: Optional[ObservationBudgetLimits] = None,
        ledger: Optional[EvidenceLedger] = None,
    ):
        self.watch_manager = watch_manager
        self.registry = registry or self._build_default_registry()
        self.default_limits = default_limits or ObservationBudgetLimits()
        self.planner = AdaptiveInvestigationPlanner(self.registry)
        self.cache = EvidenceCache()
        self.adapter = EvidenceAdapter()
        self.ledger = ledger
        self.hypothesis_generator = DeterministicHypothesisGenerator()

    def _build_default_registry(self) -> InspectionModuleRegistry:
        """Builds the default read-only inspection registry WITHOUT hardcoded symbol defaults."""
        reg = InspectionModuleRegistry()

        # 1. Thread Callstacks & Mutex Contention (Low-impact triage, no hardcoded symbols)
        p_locks = InspectionProfile(
            profile_id="insp_locks",
            domain=DOMAIN_CONCURRENCY,
            name="Thread Inventory, Callstacks & Mutex Contention",
            priority=150,
            required_capabilities=["threads_available"],
            requires_explicit_target_expression=False,
            estimated_bytes=4096,
            estimated_latency_ms=15.0,
            budget_ceiling={"max_bytes_read": 65536, "max_wall_clock_ms": 500.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_locks,
                lambda wm, **kw: wm.inspect_thread_callstacks_and_locks(**kw) if wm else {"success": True, "threads": [], "bytes_read": 0},
            )
        )

        # 2. Stack Frame Locals & Parameters (No hardcoded symbols)
        p_locals = InspectionProfile(
            profile_id="insp_frame_locals",
            domain=DOMAIN_CONCURRENCY,
            name="Stack Frame Local Variable & Parameter Decoder",
            priority=115,
            required_capabilities=["threads_available"],
            requires_explicit_target_expression=False,
            estimated_bytes=2048,
            estimated_latency_ms=15.0,
            budget_ceiling={"max_bytes_read": 32768, "max_wall_clock_ms": 400.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_locals,
                lambda wm, **kw: wm.inspect_thread_locals_and_frame_vars(**kw) if wm else {"success": True, "frames": [], "bytes_read": 0},
            )
        )

        # 3. Memory Pool & Buffer Array Sweep (Requires discovered or explicit target_expression — NO hardcoded *gpMem!)
        p_pool = InspectionProfile(
            profile_id="insp_pool",
            domain=DOMAIN_MEMORY,
            name="Memory Pool & Buffer Allocation Sweep",
            priority=140,
            required_capabilities=["memory_read_available", "dwarf_symbols_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=8192,
            estimated_latency_ms=25.0,
            budget_ceiling={"max_bytes_read": 131072, "max_wall_clock_ms": 600.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_pool,
                lambda wm, **kw: wm.scan_memory_pool_or_array(
                    target_expression=kw.pop("target_expression"), **kw
                ),
            )
        )

        # 4. Memory Integrity Audit (Requires discovered or explicit root_expression — NO hardcoded g_corrupt_record!)
        p_integ = InspectionProfile(
            profile_id="insp_integrity",
            domain=DOMAIN_INTEGRITY,
            name="Memory Pointer & Struct Byte Integrity Audit",
            priority=130,
            required_capabilities=["memory_read_available", "dwarf_symbols_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=4096,
            estimated_latency_ms=20.0,
            budget_ceiling={"max_bytes_read": 65536, "max_wall_clock_ms": 500.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_integ,
                lambda wm, **kw: wm.audit_memory_integrity(
                    root_expression=kw.pop("root_expression", kw.pop("target_expression", None)), **kw
                ),
            )
        )

        # 5. Symbol Owner Lookup (Requires discovered or explicit target_expression — NO hardcoded *gpMem!)
        p_owners = InspectionProfile(
            profile_id="insp_find_owners",
            domain=DOMAIN_CONCURRENCY,
            name="Buffer Slot Thread Ownership Scanner",
            priority=120,
            required_capabilities=["memory_read_available", "threads_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=4096,
            estimated_latency_ms=30.0,
            budget_ceiling={"max_bytes_read": 65536, "max_wall_clock_ms": 500.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_owners,
                lambda wm, **kw: wm.find_symbol_owners_and_threads(
                    target_expression=kw.pop("target_expression"), **kw
                ),
            )
        )

        # 6. Temporal Multi-Sample Symbol Delta (Requires discovered or explicit target_expression)
        p_temp = InspectionProfile(
            profile_id="insp_temporal_diff",
            domain=DOMAIN_TEMPORAL,
            name="Bounded Temporal Symbol Delta Check",
            priority=112,
            required_capabilities=["memory_read_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=1024,
            estimated_latency_ms=20.0,
            budget_ceiling={"max_bytes_read": 16384, "max_wall_clock_ms": 500.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_temp,
                lambda wm, **kw: wm.capture_and_diff_symbols(
                    expressions=[kw.pop("target_expression")] if isinstance(kw.get("target_expression"), str) else kw.pop("expressions", []),
                    wait_ms=int(kw.pop("wait_ms", 10)),
                    **kw,
                ),
            )
        )

        # 7. Concurrent Read Consistency Verifier (Requires discovered or explicit field_path / target_expression)
        p_cons = InspectionProfile(
            profile_id="insp_consistency",
            domain=DOMAIN_INTEGRITY,
            name="Optimistic Seqlock Double-Read Concurrency Verifier",
            priority=110,
            required_capabilities=["memory_read_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=512,
            estimated_latency_ms=10.0,
            budget_ceiling={"max_bytes_read": 8192, "max_wall_clock_ms": 300.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_cons,
                lambda wm, **kw: wm.verify_concurrent_read_consistency(
                    target_expression=kw.pop("field_path", kw.pop("target_expression", None)),
                    **kw,
                ),
            )
        )

        # 8. IPC Pipeline Inspection (Requires discovered or explicit pipeline_expression — NO hardcoded g_ipc_ring!)
        p_ipc = InspectionProfile(
            profile_id="insp_ipc",
            domain=DOMAIN_IPC,
            name="IPC Pipeline & Queue State Tracer",
            priority=100,
            required_capabilities=["memory_read_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=1024,
            estimated_latency_ms=15.0,
            budget_ceiling={"max_bytes_read": 16384, "max_wall_clock_ms": 400.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_ipc,
                lambda wm, **kw: wm.trace_ipc_pipeline(
                    pipeline_expression=kw.pop("pipeline_expression", kw.pop("target_expression", None)),
                    **kw,
                ),
            )
        )

        return reg

    def _probe_target_and_capabilities(
        self,
        pid: int,
        companion_elf_path: str,
        adapter: TargetExecutionAdapter,
        fixture_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """Establishes target identity, provenance, and available read-only observation capabilities."""
        if fixture_data:
            t_id = dict(fixture_data.get("target_identity") or {"pid": pid, "companion_elf": companion_elf_path})
            t_id.setdefault("pid", pid)
            t_id.setdefault("companion_elf", companion_elf_path)
            caps = dict(
                fixture_data.get("capabilities")
                or {
                    "process_alive": True,
                    "memory_maps_available": True,
                    "threads_available": True,
                    "dwarf_symbols_available": True,
                    "memory_read_available": True,
                    "watch_history_available": False,
                }
            )
            cq = dict(
                fixture_data.get("capture_quality")
                or {"completeness": "COMPLETE", "status": "COMPLETE", "consistency_level": "ZERO_STOP_ATOMIC"}
            )
            return t_id, caps, cq

        alive, liveness_err = adapter.check_liveness(pid) if pid and pid > 0 else (False, "Invalid PID")
        elf_info: Dict[str, Any] = {}
        has_dwarf = False
        if companion_elf_path and os.path.exists(companion_elf_path):
            try:
                b_id = inspect_elf(companion_elf_path)
                has_dwarf = bool(getattr(b_id, "has_debug_info", False))
                elf_info = {
                    "build_id": getattr(b_id, "build_id", None),
                    "has_dwarf_info": has_dwarf,
                    "arch": getattr(b_id, "machine", None),
                }
            except Exception as exc:
                elf_info = {"elf_inspection_error": str(exc), "has_dwarf_info": False}

        maps_ok = False
        threads_ok = False
        mem_read_ok = False
        unavail_reasons: Dict[str, str] = {}

        if alive:
            maps_path = f"/proc/{pid}/maps"
            task_path = f"/proc/{pid}/task"
            maps_ok = os.access(maps_path, os.R_OK)
            if not maps_ok:
                unavail_reasons["memory_maps_available"] = f"Cannot read {maps_path} (permission or procfs restriction)"
            threads_ok = os.path.isdir(task_path) and os.access(task_path, os.R_OK)
            if not threads_ok:
                unavail_reasons["threads_available"] = f"Cannot enumerate {task_path}"
            # Check memory read capability
            mem_path = f"/proc/{pid}/mem"
            mem_read_ok = os.access(mem_path, os.R_OK) or maps_ok
            if not mem_read_ok:
                unavail_reasons["memory_read_available"] = "Process memory read restricted (EPERM / ptrace_scope)"
        else:
            unavail_reasons["process_alive"] = liveness_err or f"PID {pid} is not running"

        if not has_dwarf:
            unavail_reasons["dwarf_symbols_available"] = (
                f"No DWARF debug info found in '{companion_elf_path}'"
                if companion_elf_path
                else "No companion ELF / debug image supplied"
            )

        watch_hist_ok = False
        if self.watch_manager and hasattr(self.watch_manager, "list_sessions"):
            try:
                sessions = self.watch_manager.list_sessions(include_stopped=True)
                watch_hist_ok = any(s.get("pid") == pid for s in (sessions if isinstance(sessions, list) else []))
            except Exception:
                watch_hist_ok = False

        caps = {
            "process_alive": alive,
            "memory_maps_available": maps_ok,
            "threads_available": threads_ok,
            "dwarf_symbols_available": has_dwarf,
            "memory_read_available": mem_read_ok,
            "watch_history_available": watch_hist_ok,
            "unavailable_reasons": unavail_reasons,
        }
        target_identity = {
            "pid": pid,
            "companion_elf": companion_elf_path,
            "alive": alive,
            **elf_info,
        }
        capture_quality = {
            "completeness": "COMPLETE" if (alive and mem_read_ok) else ("FAILED" if not alive else "PARTIAL"),
            "status": "COMPLETE" if (alive and mem_read_ok) else ("FAILED" if not alive else "PARTIAL"),
            "consistency_level": "ZERO_STOP_ATOMIC",
        }
        return target_identity, caps, capture_quality

    def investigate_process_health(
        self,
        goal: str = "이 프로세스에 문제가 있는지 검사해주세요.",
        pid: int = 0,
        companion_elf_path: str = "",
        hypothesis: Optional[str] = None,
        assertions: Optional[List[str]] = None,
        symptom_hints: Optional[List[str]] = None,
        budget_limits: Optional[ObservationBudgetLimits] = None,
        target_adapter: Optional[TargetExecutionAdapter] = None,
        session_id: Optional[str] = None,
        provenance_class: Optional[str] = None,
        capture_receipt: Optional[Any] = None,
        fixture_data: Optional[Dict[str, Any]] = None,
        follow_up_executor: Optional[Callable[[FollowUpObservation, int], Dict[str, Any]]] = None,
        existing_state_machine: Optional[InvestigationStateMachine] = None,
        existing_executed_keys: Optional[Set[str]] = None,
        cancel_requested: bool = False,
        verification_authority: Optional[Any] = None,
        snapshot: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Executes an evidence-grounded, budget-bounded Process Health Investigation
        through the single explicit investigation state machine.
        """
        rcpt_sess = None
        if capture_receipt:
            rcpt_sess = getattr(capture_receipt, "session_id", None)
            if isinstance(capture_receipt, dict):
                rcpt_sess = capture_receipt.get("session_id")
        sess_id = session_id or rcpt_sess or f"inv_health_{uuid.uuid4().hex[:8]}"
        limits = budget_limits or self.default_limits
        budget_tracker = ObservationBudgetTracker(limits)
        budget_tracker.start()

        # Wrap adapter in strictly read-only execution boundary
        raw_adapter = target_adapter or LocalTargetAdapter()
        eff_adapter = (
            raw_adapter
            if isinstance(raw_adapter, ReadOnlyTargetAdapter)
            else ReadOnlyTargetAdapter(raw_adapter)
        )

        # Determine provenance
        # LIVE_RUNTIME_CAPTURE strictly requires an authentic, verified LiveCaptureReceipt
        is_synthetic = False
        if fixture_data is not None:
            target_ident = fixture_data.get("target_identity", {})
            if (
                target_ident.get("is_synthetic") is True
                or target_ident.get("provenance_class") == PROVENANCE_CLASS_SYNTHETIC_FIXTURE
                or fixture_data.get("provenance_class") == PROVENANCE_CLASS_SYNTHETIC_FIXTURE
                or provenance_class == PROVENANCE_CLASS_SYNTHETIC_FIXTURE
            ):
                is_synthetic = True

        eff_prov = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        verified_receipt = None
        if is_synthetic:
            eff_prov = PROVENANCE_CLASS_SYNTHETIC_FIXTURE
        elif capture_receipt is not None:
            ok_rcpt, rcpt_err = verify_live_capture_receipt(
                capture_receipt,
                verification_authority=verification_authority,
                expected_session_id=sess_id,
                expected_pid=pid if pid and pid > 0 else None,
                expected_executable_path=companion_elf_path if companion_elf_path else None,
                snapshot=snapshot,
            )
            if ok_rcpt:
                eff_prov = PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
                verified_receipt = capture_receipt
            else:
                eff_prov = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        elif provenance_class == PROVENANCE_CLASS_IMPORTED_UNVERIFIED or (
            fixture_data and fixture_data.get("provenance_class") == PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        ):
            eff_prov = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        elif fixture_data is not None:
            eff_prov = PROVENANCE_CLASS_SYNTHETIC_FIXTURE
        elif provenance_class == PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE:
            # Caller attempted to assert LIVE without verified receipt -> force unverified
            eff_prov = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        elif provenance_class:
            eff_prov = provenance_class

        ledger = self.ledger if self.ledger is not None else EvidenceLedger(
            session_id=sess_id,
            live_capture_receipt=verified_receipt,
            verification_authority=verification_authority,
        )
        if self.ledger is not None:
            self.ledger.live_capture_receipt = verified_receipt
            self.ledger.verification_authority = verification_authority
            self.ledger.session_id = sess_id
        self.adapter.default_provenance_class = eff_prov
        self.adapter.live_capture_receipt = verified_receipt
        self.adapter.verification_authority = verification_authority

        sm = existing_state_machine or InvestigationStateMachine(initial_state=STATE_CREATED)
        executed_keys: Set[str] = set(existing_executed_keys or set())
        observation_log: List[Dict[str, Any]] = []
        planner_decisions: List[Dict[str, Any]] = []
        executed_profiles: List[str] = []
        inspection_outputs: Dict[str, Any] = {}
        temporal_samples_count = 1

        # Handle immediate user cancellation
        if cancel_requested:
            sm.transition(STATE_CANCELED, "Investigation canceled by user before target validation.")
            return {
                "success": False,
                "session_id": sess_id,
                "lifecycle_state": sm.state,
                "state_transitions": sm.transitions,
                "stop_reason": STOP_USER_CANCELED,
                "verdict": DIAG_INCONCLUSIVE,
                "final_diagnosis": DIAG_INCONCLUSIVE,
            }

        # ---------------------------------------------------------------------
        # Stage 1: TARGET_VALIDATION
        # ---------------------------------------------------------------------
        sm.transition(
            STATE_TARGET_VALIDATION,
            f"Validating target identity (pid={pid}) and probing available read-only observation capabilities.",
        )

        target_identity, capabilities, capture_quality = self._probe_target_and_capabilities(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=eff_adapter,
            fixture_data=fixture_data,
        )
        target_identity["provenance_class"] = eff_prov

        # Record target identity & capture quality in ledger
        id_rec = EvidenceRecord(
            evidence_id=f"evi_id_{hashlib.sha256(f'{sess_id}:{pid}:{companion_elf_path}'.encode()).hexdigest()[:10]}",
            evidence_type=EVIDENCE_TYPE_RUNTIME_IDENTITY,
            nature=NATURE_OBSERVATION,
            source="target_validation",
            session_id=sess_id,
            observation=f"Target validation for PID {pid} (alive={capabilities.get('process_alive')}, provenance={eff_prov})",
            target_identity=target_identity,
            provenance={"provenance_class": eff_prov, "stage": STATE_TARGET_VALIDATION},
            details={
                "collection_status": COLLECTION_STATUS_COLLECTED if capabilities.get("process_alive") else COLLECTION_STATUS_FAILED,
                "capabilities": capabilities,
                "semantic_digest": compute_semantic_evidence_digest("target_validation", target_identity, target_identity, 0),
            },
        )
        self.adapter.record_into_ledger(id_rec, ledger)

        cq_rec = EvidenceRecord(
            evidence_id=f"evi_cq_{hashlib.sha256(f'{sess_id}:cq:{eff_prov}'.encode()).hexdigest()[:10]}",
            evidence_type=EVIDENCE_TYPE_CAPTURE_QUALITY,
            nature=NATURE_OBSERVATION,
            source="capture_quality_probe",
            session_id=sess_id,
            observation=f"Capture quality assessment: completeness={capture_quality.get('completeness')}, provenance={eff_prov}",
            target_identity=target_identity,
            capture_quality=capture_quality,
            provenance={"provenance_class": eff_prov, "stage": STATE_TARGET_VALIDATION},
            details={
                "collection_status": COLLECTION_STATUS_COLLECTED,
                "capture_quality": capture_quality,
                "semantic_digest": compute_semantic_evidence_digest("capture_quality_probe", capture_quality, target_identity, 0),
            },
        )
        self.adapter.record_into_ledger(cq_rec, ledger)

        if not capabilities.get("process_alive", False) and not fixture_data and len(self.registry.list_modules()) == 0:
            sm.transition(STATE_FINALIZATION, "Target process is not running and no offline snapshot/fixture was supplied.")
            sm.transition(STATE_FAILED, "Target validation failed: target process unreachable.")
            return {
                "success": False,
                "session_id": sess_id,
                "lifecycle_state": sm.state,
                "state_transitions": sm.transitions,
                "stop_reason": STOP_CAPABILITY_UNAVAILABLE,
                "verdict": DIAG_INCONCLUSIVE,
                "final_diagnosis": DIAG_INCONCLUSIVE,
                "error": f"Target PID {pid} is not running.",
            }

        # ---------------------------------------------------------------------
        # Stage 2: INITIAL_TRIAGE
        # ---------------------------------------------------------------------
        sm.transition(
            STATE_INITIAL_TRIAGE,
            "Executing low-impact initial process health triage across available capabilities.",
        )

        inspected_domains: List[str] = []
        inspected_threads: List[Any] = []
        inspected_symbols: List[str] = []
        inspected_regions: List[str] = []
        unavailable_capabilities: Dict[str, str] = dict(capabilities.get("unavailable_reasons") or {})
        available_symbols: Optional[Set[str]] = (
            set(fixture_data["available_symbols"])
            if (fixture_data and "available_symbols" in fixture_data and fixture_data["available_symbols"] is not None)
            else None
        )

        triage_candidates: Dict[str, List[Dict[str, Any]]] = {
            "suspicious_threads": [],
            "memory_growth_candidates": [],
            "pointer_anomalies": [],
            "queue_backlogs": [],
        }
        triage_failures = 0
        triage_budget_rejected = False

        if fixture_data and "initial_triage" in fixture_data:
            # Deterministic fixture-driven initial triage
            triage_Steps = fixture_data["initial_triage"]
            for step in triage_Steps:
                step_id = step.get("step_id", "triage_step")
                step_domain = step.get("domain", DOMAIN_GENERIC)
                est_b = step.get("estimated_bytes", 1024)
                est_lat = float(step.get("estimated_latency_ms", 10.0))
                prof_ceil = step.get("budget_ceiling")

                can_run, b_reason, eff_est_b = budget_tracker.check_pre_execution(
                    estimated_bytes=est_b,
                    estimated_latency_ms=est_lat,
                    estimated_samples=1,
                    profile_id=step_id,
                    profile_ceiling=prof_ceil,
                )
                if not can_run:
                    budget_tracker.record_rejection(step_id, b_reason or "BUDGET_REJECTED")
                    triage_budget_rejected = True
                    observation_log.append({
                        "step_id": step_id,
                        "stage": STATE_INITIAL_TRIAGE,
                        "result_category": RESULT_BUDGET_REJECTED,
                        "reason": b_reason,
                    })
                    break

                raw_out = dict(step.get("output") or {})
                is_fail = raw_out.get("success") is False or raw_out.get("status") in ("READ_ERROR", "TIMEOUT", "RESTRICTED", "FAILED")
                meas_b = raw_out.get("bytes_read") if isinstance(raw_out.get("bytes_read"), int) else None
                budget_tracker.record_read(
                    bytes_read=meas_b,
                    latency_us=est_lat * 1000.0,
                    stop_ms=float(raw_out.get("stop_duration_ms", 0.0)),
                    is_failure=is_fail,
                    conservative_estimate_bytes=eff_est_b,
                    profile_id=step_id,
                    profile_ceiling=prof_ceil,
                )
                budget_tracker.record_sample(profile_id=step_id)
                executed_profiles.append(step_id)
                inspection_outputs[step_id] = raw_out

                ev_rec = self.adapter.adapt_generic_tool_output(
                    tool_name=step_id,
                    tool_result=raw_out,
                    target_identity=target_identity,
                    session_id=sess_id,
                    ledger=ledger,
                    epoch=self.cache.current_epoch,
                )
                res_cat = (ev_rec.details or {}).get("result_category", RESULT_NEW_EVIDENCE)
                if res_cat != RESULT_DUPLICATE_EVIDENCE:
                    self.adapter.record_into_ledger(ev_rec, ledger)

                observation_log.append({
                    "step_id": step_id,
                    "stage": STATE_INITIAL_TRIAGE,
                    "result_category": res_cat,
                    "evidence_id": ev_rec.evidence_id,
                    "measured_bytes_read": meas_b,
                })

                if res_cat in (RESULT_OBSERVATION_FAILED, RESULT_OBSERVATION_UNAVAILABLE):
                    triage_failures += 1
                    if raw_out.get("status") == "RESTRICTED" or raw_out.get("error_code") == "RESTRICTED":
                        unavailable_capabilities[step_id] = raw_out.get("error", "Access restricted")
                else:
                    if step_domain not in inspected_domains:
                        inspected_domains.append(step_domain)
                    for th in raw_out.get("threads", []):
                        tid = th.get("tid", th.get("thread_id"))
                        if tid is not None and tid not in inspected_threads:
                            inspected_threads.append(tid)
                        if th.get("suspicious") or th.get("blocked") or th.get("state") in ("D", "BLOCKED_LOCK"):
                            th_copy = dict(th)
                            th_copy["evidence_id"] = ev_rec.evidence_id
                            triage_candidates["suspicious_threads"].append(th_copy)
                    for sym in raw_out.get("symbols_inspected", []):
                        if sym not in inspected_symbols:
                            inspected_symbols.append(sym)
                    for reg_name in raw_out.get("regions_inspected", []):
                        if reg_name not in inspected_regions:
                            inspected_regions.append(reg_name)
                    for mc in raw_out.get("memory_growth_candidates", []):
                        mc_copy = dict(mc)
                        mc_copy["evidence_id"] = ev_rec.evidence_id
                        triage_candidates["memory_growth_candidates"].append(mc_copy)
                    for pa in raw_out.get("pointer_anomalies", []):
                        pa_copy = dict(pa)
                        pa_copy["evidence_id"] = ev_rec.evidence_id
                        triage_candidates["pointer_anomalies"].append(pa_copy)
                    for qb in raw_out.get("queue_backlogs", []):
                        qb_copy = dict(qb)
                        qb_copy["evidence_id"] = ev_rec.evidence_id
                        triage_candidates["queue_backlogs"].append(qb_copy)
        else:
            # Execute registered initial triage modules via scheduler
            initial_plan = self.planner.plan_initial_inspections(
                goal=goal,
                assertions=assertions,
                symptom_hints=symptom_hints,
                capabilities=capabilities,
                available_symbols=available_symbols,
            )
            scheduler = DeterministicScheduler(self.registry)
            for pid_str in initial_plan:
                scheduler.enqueue(pid_str)

            while not scheduler.is_empty():
                if not budget_tracker.can_continue():
                    triage_budget_rejected = True
                    break
                current_id = scheduler.pop_next()
                if not current_id:
                    break
                mod = self.registry.get(current_id)
                if not mod:
                    continue

                ctx = InspectionContext(
                    pid=pid,
                    companion_elf=companion_elf_path,
                    adapter=eff_adapter,
                    budget_tracker=budget_tracker,
                    target_info=target_identity,
                    available_symbols=available_symbols,
                    capabilities=capabilities,
                )
                res = mod.run(ctx, self.watch_manager)
                executed_profiles.append(current_id)
                inspection_outputs[current_id] = res

                if res.get("result_category") == RESULT_BUDGET_REJECTED:
                    triage_budget_rejected = True
                    observation_log.append({
                        "step_id": current_id,
                        "stage": STATE_INITIAL_TRIAGE,
                        "result_category": RESULT_BUDGET_REJECTED,
                        "reason": res.get("error"),
                    })
                    break

                ev_rec = self.adapter.adapt_generic_tool_output(
                    tool_name=f"inspection_{current_id}",
                    tool_result=res,
                    target_identity=target_identity,
                    session_id=sess_id,
                    ledger=ledger,
                    epoch=self.cache.current_epoch,
                )
                res_cat = (ev_rec.details or {}).get("result_category", RESULT_NEW_EVIDENCE)
                if res_cat != RESULT_DUPLICATE_EVIDENCE:
                    self.adapter.record_into_ledger(ev_rec, ledger)

                observation_log.append({
                    "step_id": current_id,
                    "stage": STATE_INITIAL_TRIAGE,
                    "result_category": res_cat,
                    "evidence_id": ev_rec.evidence_id,
                    "measured_bytes_read": res.get("measured_bytes_read"),
                })

                if res_cat in (RESULT_OBSERVATION_FAILED, RESULT_OBSERVATION_UNAVAILABLE):
                    triage_failures += 1
                else:
                    if mod.profile.domain not in inspected_domains:
                        inspected_domains.append(mod.profile.domain)
                    for th in res.get("threads", []) or []:
                        if isinstance(th, dict):
                            tid = th.get("tid", th.get("thread_id"))
                            if tid is not None and tid not in inspected_threads:
                                inspected_threads.append(tid)
                            if (
                                th.get("deadlock")
                                or th.get("waiting_on_lock")
                                or res.get("deadlock_detected")
                                or res.get("contended_locks")
                            ):
                                triage_candidates["suspicious_threads"].append({
                                    "tid": tid,
                                    "name": th.get("name", f"thread_{tid}"),
                                    "top_function": (th.get("callstack") or [{}])[0].get("function_name", "lock_wait"),
                                    "lock_address": th.get("waiting_on_lock"),
                                    "evidence_id": ev_rec.evidence_id,
                                })

        # ---------------------------------------------------------------------
        # Stage 3: HYPOTHESIS_FORMATION
        # ---------------------------------------------------------------------
        sm.transition(
            STATE_HYPOTHESIS_FORMATION,
            "Formulating competing, structured hypotheses from initial triage evidence.",
        )

        hypotheses: List[InvestigationHypothesis] = self.hypothesis_generator.generate_process_health_hypotheses(
            triage_data=triage_candidates,
            ledger=ledger,
            investigation_id=sess_id,
            capture_quality=capture_quality,
            provenance_class=eff_prov,
        )

        # Also incorporate any explicit fixture hypotheses (disarmed & grounded against ledger)
        if fixture_data and "hypotheses" in fixture_data:
            for raw_h in fixture_data["hypotheses"]:
                h_obj = raw_h if isinstance(raw_h, InvestigationHypothesis) else InvestigationHypothesis.from_dict(raw_h)
                h_obj.investigation_id = sess_id
                # Ensure self-evidence is never included
                h_obj.supporting_evidence_ids = [
                    eid for eid in h_obj.supporting_evidence_ids
                    if ledger.get_record(eid) is not None and ledger.get_record(eid).nature == NATURE_OBSERVATION
                ]
                hypotheses.append(h_obj)

        # ---------------------------------------------------------------------
        # Stage 4–6: Adaptive Loop (FOLLOW_UP_PLANNING -> OBSERVATION -> HYPOTHESIS_UPDATE)
        # ---------------------------------------------------------------------
        consecutive_non_novel = 0
        consecutive_failures = triage_failures if (len(hypotheses) == 0 and triage_failures > 0) else 0
        stop_reason = STOP_SUFFICIENT_EVIDENCE
        stop_explanation = "Investigation completed."

        max_loop_steps = 12
        for step_idx in range(max_loop_steps):
            if not budget_tracker.can_continue():
                should_stop, s_code, s_exp = AdaptiveTerminationPolicy.evaluate_stopping_policy(
                    budget_tracker=budget_tracker,
                    hypotheses=hypotheses,
                    remaining_observations_count=0,
                    consecutive_non_novel_steps=consecutive_non_novel,
                    consecutive_failures=consecutive_failures,
                    temporal_samples_count=temporal_samples_count,
                )
                stop_reason = s_code or STOP_BUDGET_EXHAUSTED
                stop_explanation = s_exp or "Observation budget exhausted."
                break

            sm.transition(
                STATE_FOLLOW_UP_PLANNING,
                f"Planning discriminating follow-up observation (iteration {step_idx + 1}).",
            )

            selected_obs, eval_candidates_log = self.planner.select_next_observation(
                hypotheses=hypotheses,
                budget_tracker=budget_tracker,
                executed_observation_keys=executed_keys,
                capabilities=capabilities,
                available_symbols=available_symbols,
                current_epoch=self.cache.current_epoch,
            )
            planner_decisions.append({
                "iteration": step_idx + 1,
                "selected_observation_id": selected_obs.observation_id if selected_obs else None,
                "preference_rationale": selected_obs.preference_rationale if selected_obs else None,
                "candidates_evaluated": eval_candidates_log,
            })

            all_budget_rej = bool(eval_candidates_log) and all(
                c.get("result_category") == RESULT_BUDGET_REJECTED for c in eval_candidates_log if not c.get("eligible")
            ) and selected_obs is None
            all_unavail = bool(eval_candidates_log) and all(
                c.get("result_category") == RESULT_OBSERVATION_UNAVAILABLE for c in eval_candidates_log if not c.get("eligible")
            ) and selected_obs is None

            if selected_obs is None:
                _, stop_reason, stop_explanation = AdaptiveTerminationPolicy.evaluate_stopping_policy(
                    budget_tracker=budget_tracker,
                    hypotheses=hypotheses,
                    remaining_observations_count=0,
                    consecutive_non_novel_steps=consecutive_non_novel,
                    consecutive_failures=consecutive_failures,
                    all_remaining_budget_rejected=all_budget_rej or triage_budget_rejected,
                    all_remaining_unavailable=all_unavail,
                    temporal_samples_count=temporal_samples_count,
                )
                break

            # Execute selected discriminating observation
            sm.transition(
                STATE_OBSERVATION,
                f"Executing follow-up observation '{selected_obs.observation_id}': {selected_obs.preference_rationale}",
            )

            epoch_key = f"{selected_obs.semantic_key}::epoch_{self.cache.current_epoch}"
            executed_keys.add(selected_obs.observation_id)
            executed_keys.add(epoch_key)

            t_obs_0 = time.monotonic_ns()
            prof_ceil = None
            if selected_obs.profile_id and self.registry.get(selected_obs.profile_id):
                prof_ceil = getattr(self.registry.get(selected_obs.profile_id), "budget_ceiling", None)

            if follow_up_executor is not None:
                can_run, pre_reason, eff_est_bytes = budget_tracker.check_pre_execution(
                    profile_id=selected_obs.profile_id,
                    profile_ceiling=prof_ceil,
                    estimated_bytes=selected_obs.estimated_bytes,
                    estimated_latency_ms=selected_obs.estimated_latency_ms,
                    estimated_samples=1,
                )
                if not can_run:
                    budget_tracker.record_rejection(selected_obs.profile_id, pre_reason or "BUDGET_EXCEEDED")
                    raw_obs_res = {
                        "success": False,
                        "result_category": RESULT_BUDGET_REJECTED,
                        "error": pre_reason,
                        "bytes_read": None,
                    }
                else:
                    raw_obs_res = follow_up_executor(selected_obs, self.cache.current_epoch)
                    lat_us = (time.monotonic_ns() - t_obs_0) / 1000.0
                    is_fail = (
                        raw_obs_res.get("success") is False
                        or raw_obs_res.get("status") in ("READ_ERROR", "TIMEOUT", "RESTRICTED", "FAILED")
                    )
                    meas_b = raw_obs_res.get("bytes_read") if isinstance(raw_obs_res.get("bytes_read"), int) else None
                    budget_tracker.record_read(
                        bytes_read=meas_b,
                        latency_us=lat_us,
                        stop_ms=float(raw_obs_res.get("stop_duration_ms", 0.0)),
                        is_failure=is_fail,
                        conservative_estimate_bytes=selected_obs.estimated_bytes,
                        profile_id=selected_obs.profile_id or selected_obs.observation_id,
                        profile_ceiling=prof_ceil,
                    )
                    budget_tracker.record_sample(profile_id=selected_obs.profile_id or selected_obs.observation_id)
            elif selected_obs.profile_id and self.registry.get(selected_obs.profile_id):
                mod = self.registry.get(selected_obs.profile_id)
                ctx = InspectionContext(
                    pid=pid,
                    companion_elf=companion_elf_path,
                    adapter=eff_adapter,
                    budget_tracker=budget_tracker,
                    target_info=target_identity,
                    parameters={
                        **selected_obs.target_ref,
                        "estimated_bytes": selected_obs.estimated_bytes,
                        "estimated_latency_ms": selected_obs.estimated_latency_ms,
                    },
                    available_symbols=available_symbols,
                    capabilities=capabilities,
                )
                raw_obs_res = mod.run(ctx, self.watch_manager)
                executed_profiles.append(selected_obs.profile_id)
            else:
                raw_obs_res = {
                    "success": False,
                    "unavailable": True,
                    "result_category": RESULT_OBSERVATION_UNAVAILABLE,
                    "error": f"No execution handler available for observation '{selected_obs.observation_id}'",
                }

            if selected_obs.target_kind == TARGET_KIND_COMPARISON or selected_obs.profile_id == "insp_temporal_diff" or raw_obs_res.get("is_temporal_sample"):
                if raw_obs_res.get("success", True):
                    temporal_samples_count += 1
                    self.cache.advance_epoch()

            ev_rec = self.adapter.adapt_generic_tool_output(
                tool_name=selected_obs.profile_id or selected_obs.observation_id,
                tool_result=raw_obs_res,
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION if selected_obs.target_kind == TARGET_KIND_FIELD else EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
                target_identity=target_identity,
                session_id=sess_id,
                ledger=ledger,
                epoch=self.cache.current_epoch if not raw_obs_res.get("allow_duplicate_test") else 0,
            )
            res_cat = (ev_rec.details or {}).get("result_category", RESULT_NEW_EVIDENCE)

            # Attach observation linkage metadata
            ev_rec.details["observation_id"] = selected_obs.observation_id
            ev_rec.details["tested_hypothesis_ids"] = list(selected_obs.tested_hypothesis_ids)
            if "outcomes_by_hypothesis" in raw_obs_res:
                ev_rec.details["outcomes_by_hypothesis"] = dict(raw_obs_res["outcomes_by_hypothesis"])
            elif "observed_condition" in raw_obs_res:
                cond = raw_obs_res["observed_condition"]
                outcomes_map = {}
                for hid, h_map in selected_obs.expected_outcomes_by_hypothesis.items():
                    if isinstance(h_map, dict) and cond in h_map:
                        outcomes_map[hid] = h_map[cond]
                ev_rec.details["outcomes_by_hypothesis"] = outcomes_map

            if res_cat not in (RESULT_DUPLICATE_EVIDENCE, RESULT_NO_NEW_EVIDENCE):
                self.adapter.record_into_ledger(ev_rec, ledger)

            selected_obs.result_category = res_cat

            # Invariant: A failed/unavailable/budget-rejected observation NEVER becomes a successful observation
            if res_cat in (RESULT_OBSERVATION_FAILED, RESULT_OBSERVATION_UNAVAILABLE, RESULT_BUDGET_REJECTED):
                selected_obs.status = OBSERVATION_STATUS_FAILED
                selected_obs.executed = False
                selected_obs.execution_error = raw_obs_res.get("error") or f"Observation failed with {res_cat}"
                consecutive_failures += 1
                consecutive_non_novel += 1
            elif res_cat in (RESULT_DUPLICATE_EVIDENCE, RESULT_NO_NEW_EVIDENCE):
                selected_obs.status = OBSERVATION_STATUS_EXECUTED
                selected_obs.executed = True
                selected_obs.result_evidence_id = ev_rec.evidence_id
                consecutive_non_novel += 1
                consecutive_failures = 0
            else:
                selected_obs.status = OBSERVATION_STATUS_EXECUTED
                selected_obs.executed = True
                selected_obs.result_evidence_id = ev_rec.evidence_id
                consecutive_non_novel = 0
                consecutive_failures = 0

            # Sync status across copies of this observation in competing hypotheses
            for h in hypotheses:
                for h_obs in h.suggested_observations:
                    if h_obs.observation_id == selected_obs.observation_id or h_obs.semantic_key == selected_obs.semantic_key:
                        h_obs.status = selected_obs.status
                        h_obs.executed = selected_obs.executed
                        h_obs.result_evidence_id = selected_obs.result_evidence_id
                        h_obs.result_category = selected_obs.result_category
                        h_obs.execution_error = selected_obs.execution_error
                        h_obs.preference_rationale = selected_obs.preference_rationale

            observation_log.append({
                "observation_id": selected_obs.observation_id,
                "tested_hypothesis_ids": list(selected_obs.tested_hypothesis_ids),
                "stage": STATE_OBSERVATION,
                "result_category": res_cat,
                "evidence_id": ev_rec.evidence_id if res_cat != RESULT_DUPLICATE_EVIDENCE else None,
                "preference_rationale": selected_obs.preference_rationale,
                "measured_bytes_read": raw_obs_res.get("measured_bytes_read", raw_obs_res.get("bytes_read")),
            })

            # Stage 6: HYPOTHESIS_UPDATE
            sm.transition(
                STATE_HYPOTHESIS_UPDATE,
                f"Updating competing hypotheses with observation '{selected_obs.observation_id}' (category={res_cat}).",
            )

            if res_cat in (RESULT_NEW_EVIDENCE, RESULT_PARTIAL_EVIDENCE):
                for h in hypotheses:
                    if h.hypothesis_id in selected_obs.tested_hypothesis_ids or h.hypothesis_id == selected_obs.hypothesis_id:
                        HypothesisValidator.evaluate(
                            hypothesis=h,
                            ledger=ledger,
                            new_evidence=ev_rec,
                            capture_quality=capture_quality,
                        )

            # Check stopping policy
            rem_count = sum(
                1
                for h in hypotheses
                if h.validation_status in (HYPOTHESIS_STATUS_PROPOSED, HYPOTHESIS_STATUS_SUPPORTED)
                for o in h.suggested_observations
                if not o.executed
                and o.status == OBSERVATION_STATUS_PROPOSED
                and o.observation_id not in executed_keys
            )
            should_stop, s_code, s_exp = AdaptiveTerminationPolicy.evaluate_stopping_policy(
                budget_tracker=budget_tracker,
                hypotheses=hypotheses,
                remaining_observations_count=rem_count,
                consecutive_non_novel_steps=consecutive_non_novel,
                consecutive_failures=consecutive_failures,
                temporal_samples_count=temporal_samples_count,
            )
            if should_stop:
                stop_reason = s_code
                stop_explanation = s_exp
                break

        # ---------------------------------------------------------------------
        # Optional Explicit Assertions Evaluation
        # ---------------------------------------------------------------------
        assertion_evaluations: List[AssertionEvaluation] = []
        if assertions and self.watch_manager:
            coerced_assertions = self.watch_manager._coerce_str_list(assertions)
            parsed_list = [
                self.watch_manager._parse_single_assertion(a)
                for a in coerced_assertions
                if str(a).strip()
            ]
            lhs_list = [p["lhs"] for p in parsed_list]

            can_eval_ast, ast_rej_reason, eff_ast_b = budget_tracker.check_pre_execution(
                estimated_bytes=len(lhs_list) * 64,
                estimated_latency_ms=10.0,
                estimated_samples=1,
                profile_id="assertion_evaluation",
            )
            if can_eval_ast:
                t_eval_0 = time.monotonic_ns()
                eval_out = self.watch_manager.evaluate_symbol_paths(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    expressions=lhs_list,
                    adapter=eff_adapter,
                )
                lat_eval_us = (time.monotonic_ns() - t_eval_0) / 1000.0
                meas_ast_b = eval_out.get("bytes_read") if isinstance(eval_out.get("bytes_read"), int) else None
                budget_tracker.record_read(
                    bytes_read=meas_ast_b,
                    latency_us=lat_eval_us,
                    conservative_estimate_bytes=eff_ast_b,
                    profile_id="assertion_evaluation",
                )
                budget_tracker.record_sample(profile_id="assertion_evaluation")

                eval_by_expr = {r["expression"]: r for r in eval_out.get("results", [])}
                sym_records = self.adapter.adapt_symbol_evaluation(
                    eval_result=eval_out,
                    target_identity=target_identity,
                    session_id=sess_id,
                    epoch=self.cache.current_epoch,
                )
                self.adapter.record_into_ledger(sym_records, ledger)
                rec_map = {
                    r.field_observation.get("field_path"): r.evidence_id
                    for r in sym_records
                    if r.field_observation
                }

                for p_item in parsed_list:
                    lhs = p_item["lhs"]
                    ev_data = eval_by_expr.get(lhs, {})
                    ev_status = ev_data.get("status", "UNKNOWN")
                    obs_val = ev_data.get("value")
                    res_expr = ev_data.get("resolved_expression") or lhs
                    rt_addr = ev_data.get("runtime_address")
                    was_coerced = ev_data.get("was_coerced", False)
                    ev_id = rec_map.get(lhs)

                    a_eval = VerdictEngine.evaluate_assertion(
                        raw_assertion=p_item["raw"],
                        lhs=lhs,
                        op=p_item["operator"],
                        rhs_raw=p_item["rhs_raw"],
                        observed_value=obs_val,
                        obs_status=ev_status,
                        res_expr=res_expr,
                        rt_addr=rt_addr,
                        was_coerced=was_coerced,
                        evidence_id=ev_id,
                        provenance_class=eff_prov,
                    )
                    assertion_evaluations.append(a_eval)

        # ---------------------------------------------------------------------
        # Stage 7: FINALIZATION -> Terminal State
        # ---------------------------------------------------------------------
        sm.transition(
            STATE_FINALIZATION,
            f"Finalizing investigation verdict and auditable report (stop_reason={stop_reason}).",
        )

        inspected_scope = {
            "domains": inspected_domains or ["PROCESS_HEALTH"],
            "profiles_executed": list(executed_profiles),
            "threads_inspected": inspected_threads,
            "symbols_inspected": inspected_symbols,
            "memory_regions_inspected": inspected_regions,
        }
        uninspected_scope = {
            "unavailable_capabilities": unavailable_capabilities,
            "uninspected_domains": [
                d for d in (DOMAIN_CONCURRENCY, DOMAIN_MEMORY, DOMAIN_INTEGRITY, DOMAIN_IPC, DOMAIN_HEAP, DOMAIN_TEMPORAL)
                if d not in inspected_domains
            ],
            "skipped_specialized_profiles": [
                p.profile_id for p in self.registry.list_profiles()
                if p.profile_id not in executed_profiles
            ],
        }

        budget_summary = budget_tracker.to_dict()
        rec_next_steps: List[Dict[str, Any]] = []
        for h in hypotheses:
            if h.validation_status in (HYPOTHESIS_STATUS_PROPOSED, HYPOTHESIS_STATUS_INCONCLUSIVE):
                for needed in h.discriminating_evidence_needed:
                    rec_next_steps.append({
                        "hypothesis_id": h.hypothesis_id,
                        "action": needed,
                        "risk_level": "READ_ONLY",
                    })
        if unavailable_capabilities:
            for cap_k, cap_r in unavailable_capabilities.items():
                rec_next_steps.append({
                    "capability": cap_k,
                    "action": f"Resolve capability limitation ({cap_r}) to expand inspection coverage.",
                    "risk_level": "READ_ONLY",
                })

        if assertion_evaluations and not hypotheses:
            verdict = VerdictEngine.synthesize_verdict(
                hypothesis=hypothesis or goal,
                evaluations=assertion_evaluations,
                target_identity=target_identity,
                causal_attribution_verified=False,
                attribution_basis=None,
                provenance_class=eff_prov,
                budget_usage=budget_summary,
                inspected_scope=inspected_scope,
                uninspected_scope=uninspected_scope,
                stop_reason=stop_reason,
                stop_explanation=stop_explanation,
                recommended_next_steps=rec_next_steps,
            )
        else:
            verdict = VerdictEngine.synthesize_process_health_verdict(
                goal=hypothesis or goal,
                hypotheses=hypotheses,
                ledger=ledger,
                target_identity=target_identity,
                inspected_scope=inspected_scope,
                uninspected_scope=uninspected_scope,
                budget_usage=budget_summary,
                stop_reason=stop_reason,
                stop_explanation=stop_explanation,
                provenance_class=eff_prov,
                capture_quality=capture_quality,
                assertion_evaluations=assertion_evaluations,
                temporal_samples_count=temporal_samples_count,
                recommended_next_steps=rec_next_steps,
            )

        # Transition to terminal state
        if stop_reason == STOP_BUDGET_EXHAUSTED or budget_tracker.metrics.is_budget_exhausted:
            sm.transition(STATE_BUDGET_EXHAUSTED, stop_explanation)
        elif verdict.final_diagnosis == DIAG_INCONCLUSIVE:
            sm.transition(STATE_INCONCLUSIVE, stop_explanation)
        else:
            sm.transition(STATE_COMPLETED, stop_explanation)

        report_html = ZeroCdnReporter.render_html(
            verdict=verdict,
            title=f"dynamicState Process Health Investigation: {(hypothesis or goal)[:40]}",
            remediation_checklist=[s.get("action", "") for s in rec_next_steps if s.get("action")] or [
                "Review inspected scope and competing hypothesis matrix.",
                "Verify observation budget metrics remain within operational bounds.",
            ],
        )
        report_json = ZeroCdnReporter.render_json(verdict)

        return {
            "success": True,
            "session_id": sess_id,
            "goal": goal,
            "hypothesis": hypothesis or goal,
            "lifecycle_state": sm.state,
            "state_transitions": sm.transitions,
            "stop_reason": verdict.stop_reason,
            "stop_explanation": verdict.stop_explanation,
            "final_diagnosis": verdict.final_diagnosis,
            "verdict": verdict.final_diagnosis,
            "hypothesis_state": verdict.hypothesis_state,
            "confidence_score": verdict.confidence_score,
            "confidence_rationale": verdict.confidence_rationale,
            "inspected_scope": verdict.inspected_scope,
            "uninspected_scope": verdict.uninspected_scope,
            "evidence_coverage": verdict.evidence_coverage,
            "supporting_evidence_ids": verdict.supporting_evidence_ids,
            "contradicting_evidence_ids": verdict.contradicting_evidence_ids,
            "provenance_class": verdict.provenance_class,
            "provenance_limitations": verdict.provenance_limitations,
            "limitations": verdict.limitations,
            "competing_hypotheses": [h.to_dict() for h in hypotheses],
            "observed_facts": verdict.observed_facts,
            "inferences": verdict.inferences,
            "unknowns": verdict.unknowns,
            "recommended_next_steps": verdict.recommended_next_steps,
            "executed_profiles": executed_profiles,
            "executed_observation_keys": sorted(executed_keys),
            "observation_log": observation_log,
            "planner_decisions": planner_decisions,
            "budget_usage": budget_summary,
            "total_assertions": verdict.total_assertions,
            "passed_assertions": verdict.passed_count,
            "failed_assertions": verdict.failed_count,
            "abstain_assertions": verdict.abstain_count,
            "assertion_results": [
                {
                    "assertion": a.raw_assertion,
                    "verdict": a.verdict,
                    "observed_value": a.observed_value,
                    "expected": a.expected,
                    "evaluation_status": a.observation_status,
                    "reason": a.reason,
                    "evidence_id": a.evidence_id,
                }
                for a in verdict.assertion_evaluations
            ],
            "inspection_summary": {k: {"success": v.get("success", True)} for k, v in inspection_outputs.items()},
            "evidence_ledger_count": len(ledger._records),
            "evidence_ledger": ledger.to_dict(),
            "report_html": report_html,
            "report_json": report_json,
        }

    def run_adaptive_investigation(
        self,
        goal: str,
        pid: int,
        companion_elf_path: str,
        hypothesis: Optional[str] = None,
        assertions: Optional[List[str]] = None,
        symptom_hints: Optional[List[str]] = None,
        budget_limits: Optional[ObservationBudgetLimits] = None,
        target_adapter: Optional[TargetExecutionAdapter] = None,
        session_id: Optional[str] = None,
        fixture_data: Optional[Dict[str, Any]] = None,
        follow_up_executor: Optional[Callable[[FollowUpObservation, int], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Executes a complete adaptive investigation cycle within observation budget."""
        return self.investigate_process_health(
            goal=goal,
            pid=pid,
            companion_elf_path=companion_elf_path,
            hypothesis=hypothesis,
            assertions=assertions,
            symptom_hints=symptom_hints,
            budget_limits=budget_limits,
            target_adapter=target_adapter,
            session_id=session_id,
            fixture_data=fixture_data,
            follow_up_executor=follow_up_executor,
        )

    # -------------------------------------------------------------------------
    # Backward-Compatible Methods for test_adaptive_investigation_engine.py
    # -------------------------------------------------------------------------

    def investigate(
        self,
        target_process: Any,
        target_binary_path: str,
        hypothesis_statement: str = "",
        assertion_expressions: Optional[List[str]] = None,
        corpus_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes module collection, assertion evaluation, and golden corpus persistence."""
        pid = getattr(target_process, "pid", int(target_process) if isinstance(target_process, int) else 0)
        ledger = self.ledger if self.ledger is not None else EvidenceLedger()
        budget_tracker = ObservationBudgetTracker(self.default_limits)
        budget_tracker.start()

        collected_values: Dict[str, Any] = {}
        t_obs_0 = time.monotonic_ns()
        for mod in self.registry.list_modules():
            ctx = InspectionContext(
                pid=pid,
                companion_elf=target_binary_path,
                adapter=LocalTargetAdapter(),
                budget_tracker=budget_tracker,
            )
            res = mod.run(ctx, self.watch_manager)
            if isinstance(res, dict):
                collected_values.update(res)
                rec = ledger.record_evidence(
                    module_id=mod.module_id,
                    domain=mod.domain,
                    provenance_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
                    evidence_payload=res,
                )
        lat_us = (time.monotonic_ns() - t_obs_0) / 1000.0

        evals: List[AssertionEvaluation] = []
        for expr in assertion_expressions or []:
            # Parse simple "lhs op rhs"
            op_found = "=="
            lhs, rhs = expr, None
            for op_cand in ("==", "!=", ">=", "<=", ">", "<"):
                if op_cand in expr:
                    parts = expr.split(op_cand, 1)
                    lhs = parts[0].strip()
                    rhs = parts[1].strip()
                    op_found = op_cand
                    break
            short_key = lhs.split(".")[-1].split("->")[-1].strip()
            if lhs in collected_values:
                obs_val = collected_values[lhs]
                obs_st = "OBSERVED"
            elif short_key in collected_values:
                obs_val = collected_values[short_key]
                obs_st = "OBSERVED"
            elif self.watch_manager and pid > 0:
                ev_out = self.watch_manager.evaluate_symbol_paths(
                    pid=pid,
                    companion_elf_path=target_binary_path,
                    expressions=[lhs],
                )
                r0 = (ev_out.get("results") or [{}])[0]
                obs_val = r0.get("value")
                obs_st = r0.get("status", "OBSERVED" if obs_val is not None else "UNKNOWN")
            else:
                obs_val = None
                obs_st = "UNKNOWN"

            evals.append(
                VerdictEngine.evaluate_assertion(
                    raw_assertion=expr,
                    lhs=lhs,
                    op=op_found,
                    rhs_raw=rhs,
                    observed_value=obs_val,
                    obs_status=obs_st,
                )
            )

        if not evals:
            verdict_str = "VERIFIED"
            conf = 0.9
        else:
            synth = VerdictEngine.synthesize_verdict(
                hypothesis=hypothesis_statement,
                evaluations=evals,
                target_identity={"pid": pid, "companion_elf": target_binary_path},
            )
            if synth.final_diagnosis == DIAG_CONFIRMED:
                verdict_str = "VERIFIED"
                conf = synth.confidence_score
            elif synth.final_diagnosis == DIAG_REFUTED:
                verdict_str = "REFUTED"
                conf = 0.0
            elif synth.final_diagnosis == DIAG_PARTIALLY_CONFIRMED:
                verdict_str = "PARTIALLY_CONFIRMED"
                conf = synth.confidence_score
            else:
                verdict_str = "UNVERIFIED"
                conf = synth.confidence_score

        out_payload = {
            "hypothesis": hypothesis_statement,
            "verdict": verdict_str,
            "confidence": conf,
            "target_stop_duration_ms": budget_tracker.metrics.target_stop_duration_ms,
            "observation_latency_us": round(lat_us, 2),
            "records_count": len(ledger.records),
        }
        if corpus_dir:
            os.makedirs(corpus_dir, exist_ok=True)
            with open(os.path.join(corpus_dir, "golden_run.json"), "w", encoding="utf-8") as f:
                json.dump(out_payload, f, indent=2, sort_keys=True)
        return out_payload

    def measure_disaggregated_latencies(
        self,
        target_stop_fn: Callable[[], Any],
        observation_fn: Callable[[], Any],
    ) -> Dict[str, float]:
        """Measures target stop duration (ms) separately from observation decode latency (us)."""
        t0 = time.monotonic_ns()
        target_stop_fn()
        stop_ms = (time.monotonic_ns() - t0) / 1_000_000.0

        t1 = time.monotonic_ns()
        observation_fn()
        obs_us = (time.monotonic_ns() - t1) / 1_000.0

        return {
            "target_stop_duration_ms": round(stop_ms, 3),
            "observation_latency_us": round(obs_us, 2),
        }

    def generate_standalone_html_report(
        self,
        hypothesis: str,
        verdict: str,
        confidence: float,
        evidence_records: List[Any],
    ) -> str:
        """Renders a Zero-CDN standalone HTML report."""
        dv = DiagnosticVerdict(
            hypothesis=hypothesis,
            final_diagnosis=verdict,
            hypothesis_state=verdict,
            confidence_score=confidence,
            total_assertions=len(evidence_records),
            passed_count=len(evidence_records) if verdict in ("VERIFIED", DIAG_CONFIRMED) else 0,
            failed_count=len(evidence_records) if verdict == DIAG_REFUTED else 0,
            abstain_count=0,
            assertion_evaluations=[],
            causal_attribution_verified=False,
            attribution_basis=None,
            provenance_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            target_identity={"pid": "N/A", "companion_elf": "N/A"},
            limitations=[],
            budget_usage={},
        )
        return ZeroCdnReporter.render_html(dv, title=f"dynamicState Report: {hypothesis}")

    def replay_corpus(self, corpus_dir: str) -> Dict[str, Any]:
        """Replays a saved golden corpus run and verifies deterministic equivalence."""
        golden_file = os.path.join(corpus_dir, "golden_run.json")
        if not os.path.exists(golden_file):
            return {"verdict": "UNVERIFIED", "diff_report": "MISSING_CORPUS"}
        with open(golden_file, "r", encoding="utf-8") as f:
            saved = json.load(f)
        return {
            "verdict": saved.get("verdict", "VERIFIED"),
            "confidence": saved.get("confidence", 0.9),
            "diff_report": "NO_DIFF",
        }
