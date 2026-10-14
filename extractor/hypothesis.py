"""Structured Hypothesis Model, Follow-up Observation Planning, and Validation Engine.

Provides an evidence-grounded hypothesis framework for dynamicState investigations:
- Structured hypothesis representation with explicit validation states:
  PROPOSED, SUPPORTED, CONTRADICTED, INCONCLUSIVE, VALIDATED
- Follow-up observation planning with discriminating expected outcomes
- Deterministic hypothesis generation from state comparisons, runtime observations,
  and static DWARF linkage
- Causal validation loop with cycle detection, independent evidence verification,
  and strict function candidate vs. validated causal function separation
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .evidence_ledger import (
    EVIDENCE_SCHEMA_VERSION,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_HYPOTHESIS,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_STATIC_LINK,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    compute_attestation_signature,
    compute_evidence_fingerprint,
    is_exact_semantic_path_match,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    TRUSTED_PROVENANCE_CLASSES,
)

# -----------------------------------------------------------------------------
# Canonical Status and Classification Constants
# -----------------------------------------------------------------------------

# Hypothesis validation statuses
HYPOTHESIS_STATUS_PROPOSED = "PROPOSED"
HYPOTHESIS_STATUS_SUPPORTED = "SUPPORTED"
HYPOTHESIS_STATUS_CONTRADICTED = "CONTRADICTED"
HYPOTHESIS_STATUS_INCONCLUSIVE = "INCONCLUSIVE"
HYPOTHESIS_STATUS_VALIDATED = "VALIDATED"

VALID_HYPOTHESIS_STATUSES = {
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_VALIDATED,
}

# Confidence classifications with documented semantics
CONFIDENCE_HIGH = "HIGH"          # Independent multi-source complete/atomic observations, 0 contradictions
CONFIDENCE_MEDIUM = "MEDIUM"      # Grounded in at least one solid observation, but unverified aspects remain
CONFIDENCE_LOW = "LOW"            # Based on partial/non-atomic capture or single uncorroborated observation
CONFIDENCE_SPECULATIVE = "SPECULATIVE"  # Inferred purely from static relationships without direct runtime proof

VALID_CONFIDENCE_LEVELS = {
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_LOW,
    CONFIDENCE_SPECULATIVE,
}

# Function Candidate vs Causal Function Tiers
FUNCTION_TIER_STATIC_CANDIDATE = "STATIC_CANDIDATE"
FUNCTION_TIER_EVIDENCE_SUPPORTED = "EVIDENCE_SUPPORTED_CANDIDATE"
FUNCTION_TIER_VALIDATED_CAUSAL = "VALIDATED_CAUSAL_FUNCTION"
FUNCTION_TIER_UNKNOWN = "UNKNOWN"

VALID_FUNCTION_TIERS = {
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    FUNCTION_TIER_UNKNOWN,
}

# Target kinds for follow-up observations
TARGET_KIND_FIELD = "FIELD"
TARGET_KIND_OBJECT = "OBJECT"
TARGET_KIND_THREAD = "THREAD"
TARGET_KIND_SNAPSHOT = "SNAPSHOT"
TARGET_KIND_COMPARISON = "COMPARISON"
TARGET_KIND_SOURCE = "SOURCE"
TARGET_KIND_MUTATION = "MUTATION"

VALID_TARGET_KINDS = {
    TARGET_KIND_FIELD,
    TARGET_KIND_OBJECT,
    TARGET_KIND_THREAD,
    TARGET_KIND_SNAPSHOT,
    TARGET_KIND_COMPARISON,
    TARGET_KIND_SOURCE,
    TARGET_KIND_MUTATION,
}


# -----------------------------------------------------------------------------
# Follow-Up Observation Model
# -----------------------------------------------------------------------------

@dataclass
class FollowUpObservation:
    """Actionable, read-only planned observation designed to test or discriminate a hypothesis."""
    observation_id: str
    hypothesis_id: str
    question: str
    target_kind: str  # FIELD, OBJECT, THREAD, SNAPSHOT, COMPARISON, SOURCE
    target_ref: Dict[str, Any]
    discriminating_criteria: str
    expected_outcomes: Dict[str, str]  # outcome condition description -> resulting status (e.g. {"matches_baseline": "CONTRADICTED"})
    discriminating_power: str = "HIGH"  # HIGH, MEDIUM, LOW
    required_capture_quality: str = "COMPLETE"  # COMPLETE, ANY
    safety_constraints: List[str] = field(default_factory=list)
    is_suggestion: bool = True
    executed: bool = False
    result_evidence_id: Optional[str] = None
    created_at: str = ""

    def __post_init__(self):
        if not self.observation_id:
            self.observation_id = f"obs_plan_{uuid.uuid4().hex[:8]}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if self.target_kind not in VALID_TARGET_KINDS:
            raise ValueError(f"Invalid target_kind '{self.target_kind}'. Expected one of {sorted(VALID_TARGET_KINDS)}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FollowUpObservation":
        return cls(
            observation_id=data.get("observation_id", f"obs_plan_{uuid.uuid4().hex[:8]}"),
            hypothesis_id=data.get("hypothesis_id", ""),
            question=data.get("question", ""),
            target_kind=data.get("target_kind", TARGET_KIND_FIELD),
            target_ref=dict(data.get("target_ref", {})),
            discriminating_criteria=data.get("discriminating_criteria", ""),
            expected_outcomes=dict(data.get("expected_outcomes", {})),
            discriminating_power=data.get("discriminating_power", "HIGH"),
            required_capture_quality=data.get("required_capture_quality", "COMPLETE"),
            safety_constraints=list(data.get("safety_constraints", [])),
            is_suggestion=data.get("is_suggestion", True),
            executed=data.get("executed", False),
            result_evidence_id=data.get("result_evidence_id"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


# -----------------------------------------------------------------------------
# Structured Hypothesis Model
# -----------------------------------------------------------------------------

@dataclass
class InvestigationHypothesis:
    """A structured, evidence-grounded root-cause hypothesis with auditable validation history."""
    hypothesis_id: str
    investigation_id: str
    title: str
    claim: str
    proposed_mechanism: str
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    unresolved_questions: List[str] = field(default_factory=list)
    confidence: str = CONFIDENCE_MEDIUM
    confidence_rationale: str = ""
    candidate_objects: List[str] = field(default_factory=list)
    candidate_fields: List[str] = field(default_factory=list)
    source_locations: List[str] = field(default_factory=list)
    function_candidates: List[Dict[str, Any]] = field(default_factory=list)
    suggested_observations: List[FollowUpObservation] = field(default_factory=list)
    validation_criteria: List[str] = field(default_factory=list)
    validation_status: str = HYPOTHESIS_STATUS_PROPOSED
    status_history: List[Dict[str, Any]] = field(default_factory=list)
    parent_hypothesis_ids: List[str] = field(default_factory=list)
    parent_evidence_ids: List[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.hypothesis_id:
            self.hypothesis_id = f"hypo_{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
        if self.validation_status not in VALID_HYPOTHESIS_STATUSES:
            raise ValueError(f"Invalid validation_status '{self.validation_status}'. Expected one of {sorted(VALID_HYPOTHESIS_STATUSES)}")
        if self.confidence not in VALID_CONFIDENCE_LEVELS:
            raise ValueError(f"Invalid confidence '{self.confidence}'. Expected one of {sorted(VALID_CONFIDENCE_LEVELS)}")
        if not self.status_history:
            self.status_history = [{
                "from_status": None,
                "to_status": self.validation_status,
                "timestamp": self.created_at,
                "reason": "Initial hypothesis formulation.",
                "trigger_evidence_id": None,
            }]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["suggested_observations"] = [obs.to_dict() for obs in self.suggested_observations]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationHypothesis":
        obs_list = [
            FollowUpObservation.from_dict(o) if isinstance(o, dict) else o
            for o in data.get("suggested_observations", [])
        ]
        return cls(
            hypothesis_id=data.get("hypothesis_id", f"hypo_{uuid.uuid4().hex[:10]}"),
            investigation_id=data.get("investigation_id", ""),
            title=data.get("title", ""),
            claim=data.get("claim", ""),
            proposed_mechanism=data.get("proposed_mechanism", ""),
            supporting_evidence_ids=list(data.get("supporting_evidence_ids", [])),
            contradicting_evidence_ids=list(data.get("contradicting_evidence_ids", [])),
            assumptions=list(data.get("assumptions", [])),
            unresolved_questions=list(data.get("unresolved_questions", [])),
            confidence=data.get("confidence", CONFIDENCE_MEDIUM),
            confidence_rationale=data.get("confidence_rationale", ""),
            candidate_objects=list(data.get("candidate_objects", [])),
            candidate_fields=list(data.get("candidate_fields", [])),
            source_locations=list(data.get("source_locations", [])),
            function_candidates=[dict(c) for c in data.get("function_candidates", [])],
            suggested_observations=obs_list,
            validation_criteria=list(data.get("validation_criteria", [])),
            validation_status=data.get("validation_status", HYPOTHESIS_STATUS_PROPOSED),
            status_history=[dict(h) for h in data.get("status_history", [])],
            parent_hypothesis_ids=list(data.get("parent_hypothesis_ids", [])),
            parent_evidence_ids=list(data.get("parent_evidence_ids", [])),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
            provenance=dict(data.get("provenance", {})),
        )


# -----------------------------------------------------------------------------
# Hypothesis Generator Interface & Deterministic Engine
# -----------------------------------------------------------------------------

class HypothesisGenerator(ABC):
    """Abstract interface for evidence-grounded hypothesis generators."""

    @abstractmethod
    def generate(self, session: Any) -> List[InvestigationHypothesis]:
        """Generate hypotheses from an investigation session's grounded evidence."""
        pass


class DeterministicHypothesisGenerator(HypothesisGenerator):
    """Deterministic, host-side hypothesis generator without external LLM dependencies.

    Generates hypotheses grounded in:
    1. Comparative state diffs (changed scalar values, bitmasks, pointer shifts)
    2. Observed field values and potential invariants
    3. Thread context and concurrency observations
    4. DWARF static types and function candidates
    5. Capture quality and temporal consistency constraints
    """

    def generate(self, session: Any) -> List[InvestigationHypothesis]:
        hypotheses: List[InvestigationHypothesis] = []
        inv_id = getattr(session, "investigation_id", "inv_unknown")
        ledger = getattr(session, "ledger", None)

        # Inspect capture quality first to enforce trust bounds
        cap_stage = getattr(session, "stages", {}).get("capture_quality", {})
        cap_details = cap_stage.get("details", {})
        cap_status = cap_stage.get("status", "COMPLETE")
        is_non_atomic = (
            cap_details.get("consistency_level") == "NON_ATOMIC"
            or cap_details.get("consistency_classification") == "NON_ATOMIC"
        )
        is_partial = (cap_status == "PARTIAL")
        is_untrusted = (cap_status in ("FAILED", "INVALID"))

        # Find findings
        findings = list(getattr(session, "findings", []))
        diff_results = list(getattr(session, "comparison_results", []))

        # ---------------------------------------------------------------------
        # 1. State Comparison / Transition Hypotheses
        # ---------------------------------------------------------------------
        diff_findings = [f for f in findings if f.category == "fact" and f.before_value is not None and f.after_value is not None]

        for df in diff_findings:
            c_path = df.c_type_path or f"{df.object_id}.{df.field_name}"
            field_name = df.field_name or "field"
            before_val = df.before_value
            after_val = df.after_value

            # Build supporting evidence IDs from finding
            supp_ev_ids = list(df.evidence_ids)

            # Classify candidates with strict tiering
            qualified_candidates = []
            for cand in df.function_candidates:
                c_copy = dict(cand)
                ev_lvl = c_copy.get("evidence_level", "static")
                if ev_lvl == "observed":
                    c_copy["candidate_tier"] = FUNCTION_TIER_EVIDENCE_SUPPORTED
                else:
                    c_copy["candidate_tier"] = FUNCTION_TIER_STATIC_CANDIDATE
                c_copy["confirmed_root_cause"] = False
                c_copy["tier_limitation"] = (
                    "Static reference candidate identified via DWARF/ELF analysis; "
                    "not confirmed root-cause function."
                )
                qualified_candidates.append(c_copy)

            # Determine initial confidence
            if is_untrusted:
                conf = CONFIDENCE_LOW
                conf_rationale = f"Capture quality is {cap_status}; hypothesis cannot be substantiated with trusted runtime facts."
                val_status = HYPOTHESIS_STATUS_INCONCLUSIVE
            elif is_partial or is_non_atomic:
                conf = CONFIDENCE_LOW
                skew_note = "NON_ATOMIC capture skew warning: coincident field values do not prove a causal sequence." if is_non_atomic else "PARTIAL capture: memory layout may be incomplete."
                conf_rationale = f"Grounded in observed state comparison ({before_val} -> {after_val}), but {skew_note}"
                val_status = HYPOTHESIS_STATUS_PROPOSED
            else:
                conf = CONFIDENCE_MEDIUM
                conf_rationale = f"Grounded in verified before/after transition ({before_val} -> {after_val}) with COMPLETE capture quality."
                val_status = HYPOTHESIS_STATUS_PROPOSED

            hypo_id = f"hypo_diff_{uuid.uuid4().hex[:8]}"

            # Plan actionable follow-up observations
            obs_plans: List[FollowUpObservation] = []

            # Plan A: Call stack execution check
            obs_plans.append(FollowUpObservation(
                observation_id=f"obs_stack_{uuid.uuid4().hex[:6]}",
                hypothesis_id=hypo_id,
                question=f"Was a candidate function actively executing on a thread stack during the transition that modified {c_path}?",
                target_kind=TARGET_KIND_THREAD,
                target_ref={"field_path": c_path, "thread_id": df.thread_id or "all"},
                discriminating_criteria="Inspect active thread call stack frames in Snapshot B for candidate mutation functions.",
                expected_outcomes={
                    "candidate_found_in_call_stack": "SUPPORTED",
                    "stack_idle_or_unrelated": "INCONCLUSIVE",
                    "conflicting_thread_executing": "CONTRADICTED",
                },
                discriminating_power="HIGH",
                required_capture_quality="COMPLETE",
                safety_constraints=["Read-only stack inspection; zero live target suspension."],
                is_suggestion=True,
                executed=False,
            ))

            # Plan B: Baseline stability check
            obs_plans.append(FollowUpObservation(
                observation_id=f"obs_base_{uuid.uuid4().hex[:6]}",
                hypothesis_id=hypo_id,
                question=f"Does {c_path} remain stable at {before_val} when no transition is triggered?",
                target_kind=TARGET_KIND_COMPARISON,
                target_ref={"field_path": c_path, "expected_baseline_value": before_val},
                discriminating_criteria="Compare across unmutated baseline checkpoints to eliminate spontaneous or background drift.",
                expected_outcomes={
                    "baseline_unchanged": "SUPPORTED",
                    "baseline_spontaneously_mutates": "CONTRADICTED",
                },
                discriminating_power="HIGH",
                required_capture_quality="COMPLETE",
                safety_constraints=["Read-only comparison of existing snapshot bundles."],
                is_suggestion=True,
                executed=False,
            ))

            assumptions = [
                f"Transition was induced by the execution step between observation points rather than spontaneous background drift.",
                f"Memory region containing {c_path} was not concurrently unmapped or repurposed.",
            ]
            if is_non_atomic:
                assumptions.append("NON_ATOMIC capture caveat: relative ordering between cross-thread writes cannot be proven without atomic stop.")

            unresolved = [
                f"Which specific instruction/function performed the write to {c_path}?",
                f"Were concurrent threads writing to adjacent fields in the same cache line?",
            ]

            crit = [
                f"Observation of active write call stack or verified deterministic transition reproducing {before_val} -> {after_val}.",
                f"Demonstration that excluding the candidate mutation prevents the transition.",
                f"Zero contradicting observations showing spontaneous value change under idle conditions.",
            ]

            h = InvestigationHypothesis(
                hypothesis_id=hypo_id,
                investigation_id=inv_id,
                title=f"State Transition Mutation of {c_path}",
                claim=f"Field {c_path} was mutated from {before_val} to {after_val} during the observed transition.",
                proposed_mechanism=f"Thread execution triggered a state transition that updated {field_name} from {before_val} to {after_val}.",
                supporting_evidence_ids=supp_ev_ids,
                contradicting_evidence_ids=[],
                assumptions=assumptions,
                unresolved_questions=unresolved,
                confidence=conf,
                confidence_rationale=conf_rationale,
                candidate_objects=[df.object_id] if df.object_id else [],
                candidate_fields=[field_name],
                source_locations=[df.source_location] if df.source_location else [],
                function_candidates=qualified_candidates,
                suggested_observations=obs_plans,
                validation_criteria=crit,
                validation_status=val_status,
                parent_hypothesis_ids=[],
                parent_evidence_ids=supp_ev_ids,
                provenance={
                    "generator": "DeterministicHypothesisGenerator",
                    "rule": "DIFF_VALUE_MUTATION",
                    "before_value": before_val,
                    "after_value": after_val,
                    "capture_status": cap_status,
                    "is_non_atomic": is_non_atomic,
                },
            )
            hypotheses.append(h)

        # ---------------------------------------------------------------------
        # 2. Field Anomaly / Logic Invariant Hypotheses
        # ---------------------------------------------------------------------
        fact_findings = [f for f in findings if f.category == "fact" and f.before_value is None and f.observed_value is not None]
        for ff in fact_findings:
            c_path = ff.c_type_path or f"{ff.object_id}.{ff.field_name}"
            field_name = ff.field_name or "field"
            obs_val = ff.observed_value

            # Look for anomaly indicators (counter, flags, boundary values)
            is_counter = "counter" in field_name.lower() or "count" in field_name.lower()
            is_flag = "flag" in field_name.lower() or "status" in field_name.lower()

            if is_counter or is_flag or isinstance(obs_val, (int, float)):
                supp_ev_ids = list(ff.evidence_ids)
                hypo_id = f"hypo_inv_{uuid.uuid4().hex[:8]}"

                qualified_candidates = []
                for cand in ff.function_candidates:
                    c_copy = dict(cand)
                    c_copy["candidate_tier"] = FUNCTION_TIER_STATIC_CANDIDATE
                    c_copy["confirmed_root_cause"] = False
                    c_copy["tier_limitation"] = "Static candidate from DWARF debug symbols; unproven causality."
                    qualified_candidates.append(c_copy)

                if is_untrusted:
                    conf = CONFIDENCE_LOW
                    conf_rationale = f"Capture quality is {cap_status}; hypothesis cannot be substantiated."
                    val_status = HYPOTHESIS_STATUS_INCONCLUSIVE
                elif is_partial or is_non_atomic:
                    conf = CONFIDENCE_LOW
                    conf_rationale = "Grounded in single snapshot observation under non-atomic or partial capture."
                    val_status = HYPOTHESIS_STATUS_PROPOSED
                else:
                    conf = CONFIDENCE_MEDIUM
                    conf_rationale = f"Observed scalar value {obs_val} in COMPLETE capture."
                    val_status = HYPOTHESIS_STATUS_PROPOSED

                obs_plans = [
                    FollowUpObservation(
                        observation_id=f"obs_comp_{uuid.uuid4().hex[:6]}",
                        hypothesis_id=hypo_id,
                        question=f"Does {c_path} change value across distinct execution snapshots or remain invariant?",
                        target_kind=TARGET_KIND_COMPARISON,
                        target_ref={"field_path": c_path},
                        discriminating_criteria="Compare against a second snapshot to establish dynamic mutability vs constant invariant.",
                        expected_outcomes={
                            "value_changes_across_runs": "SUPPORTED",
                            "value_strictly_constant": "INCONCLUSIVE",
                        },
                        discriminating_power="MEDIUM",
                        required_capture_quality="COMPLETE",
                        safety_constraints=["Read-only comparative analysis."],
                        is_suggestion=True,
                        executed=False,
                    )
                ]

                h = InvestigationHypothesis(
                    hypothesis_id=hypo_id,
                    investigation_id=inv_id,
                    title=f"Potential Dynamic Invariant in {c_path}",
                    claim=f"Observed value {obs_val} of {c_path} represents an active dynamic state rather than a static invariant.",
                    proposed_mechanism=f"Runtime workers or lifecycle routines update {field_name} during program operation.",
                    supporting_evidence_ids=supp_ev_ids,
                    contradicting_evidence_ids=[],
                    assumptions=[f"{c_path} is read/write accessible in process memory."],
                    unresolved_questions=[f"What is the valid domain/range of {c_path} in normal operation?"],
                    confidence=conf,
                    confidence_rationale=conf_rationale,
                    candidate_objects=[ff.object_id] if ff.object_id else [],
                    candidate_fields=[field_name],
                    source_locations=[ff.source_location] if ff.source_location else [],
                    function_candidates=qualified_candidates,
                    suggested_observations=obs_plans,
                    validation_criteria=[
                        f"Demonstrated value variation across distinct execution checkpoints.",
                        f"Evidence linking candidate functions to write access of {field_name}.",
                    ],
                    validation_status=val_status,
                    parent_hypothesis_ids=[],
                    parent_evidence_ids=supp_ev_ids,
                    provenance={
                        "generator": "DeterministicHypothesisGenerator",
                        "rule": "OBSERVED_VALUE_INVARIANT",
                        "observed_value": obs_val,
                    },
                )
                hypotheses.append(h)

        return hypotheses


# -----------------------------------------------------------------------------
# Hypothesis Validation Engine
# -----------------------------------------------------------------------------

@dataclass
class ValidationTransitionResult:
    """Result of evaluating a hypothesis against evidence."""
    hypothesis_id: str
    from_status: str
    to_status: str
    status_changed: bool
    confidence: str
    reason: str
    trigger_evidence_id: Optional[str]
    supporting_count: int
    contradicting_count: int
    cycle_detected: bool = False
    is_duplicate: bool = False
    provenance_error: Optional[str] = None
    proof_evidence_id: Optional[str] = None
    unverified_claim_rejected: bool = False


class HypothesisValidator:
    """Evaluates and validates hypotheses against the Evidence Ledger with strict criteria."""

    @classmethod
    def check_provenance_ancestry_quality(
        cls,
        ledger: EvidenceLedger,
        start_evidence_id: str,
        max_depth: int = 50,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Verify provenance acyclicity, presence of parent records, and ancestor capture quality.

        Returns: (is_valid: bool, error_message: Optional[str], quality_summary: Dict[str, Any])
        """
        visited: Set[str] = set()
        stack: Set[str] = set()
        quality_summary: Dict[str, Any] = {
            "has_untrusted_ancestor": False,
            "has_partial_ancestor": False,
            "has_non_atomic_ancestor": False,
            "has_missing_quality_ancestor": False,
            "has_cross_session_ancestor": False,
            "ancestor_count": 0,
        }

        def _dfs(eid: str, depth: int) -> Tuple[bool, Optional[str]]:
            if depth > max_depth:
                return False, "Maximum provenance depth exceeded (potential cycle)"
            if eid in stack:
                return False, f"Cycle detected in evidence provenance involving '{eid}'"
            if eid in visited:
                return True, None

            visited.add(eid)
            stack.add(eid)

            rec = ledger.get_record(eid)
            if not rec:
                stack.remove(eid)
                return True, None

            # Check ancestor quality (depth > 0: parent and higher ancestors)
            if depth > 0:
                quality_summary["ancestor_count"] += 1
                if rec.session_id and rec.session_id != ledger.session_id:
                    quality_summary["has_cross_session_ancestor"] = True

                cq = rec.capture_quality
                if not cq or not isinstance(cq, dict):
                    quality_summary["has_missing_quality_ancestor"] = True
                else:
                    c_status = cq.get("completeness") or cq.get("status")
                    if not c_status or c_status in ("FAILED", "INVALID", "UNTRUSTED"):
                        quality_summary["has_untrusted_ancestor"] = True
                    elif c_status == "PARTIAL":
                        quality_summary["has_partial_ancestor"] = True

                    c_level = cq.get("consistency_level") or cq.get("consistency_classification") or (rec.details or {}).get("consistency_classification")
                    if not c_level or c_level not in ("STOPPED", "ATOMIC", "CONSISTENT") or (rec.details or {}).get("is_non_atomic") is True:
                        quality_summary["has_non_atomic_ancestor"] = True

            for parent_id in rec.parent_evidence_ids:
                parent_rec = ledger.get_record(parent_id)
                if not parent_rec:
                    stack.remove(eid)
                    return False, f"Missing parent evidence record '{parent_id}' referenced by '{eid}'"
                ok, err = _dfs(parent_id, depth + 1)
                if not ok or err:
                    stack.remove(eid)
                    return False, err

            stack.remove(eid)
            return True, None

        ok, err = _dfs(start_evidence_id, 0)
        return ok, err, quality_summary

    @classmethod
    def check_provenance_integrity(
        cls,
        ledger: EvidenceLedger,
        start_evidence_id: str,
        max_depth: int = 50,
    ) -> Tuple[bool, Optional[str]]:
        """Verify that the evidence provenance graph is strictly acyclic and all referenced parent records exist.

        Returns: (has_cycle: bool, error_message: Optional[str])
        """
        ok, err, _ = cls.check_provenance_ancestry_quality(ledger, start_evidence_id, max_depth)
        has_cycle = (not ok) and (err is not None) and ("cycle" in err.lower())
        return has_cycle, err

    @classmethod
    def detect_cycles(cls, ledger: EvidenceLedger, start_evidence_id: str, max_depth: int = 50) -> bool:
        """Verify that the evidence provenance graph is strictly acyclic."""
        has_cycle, _ = cls.check_provenance_integrity(ledger, start_evidence_id, max_depth)
        return has_cycle

    @staticmethod
    def is_duplicate_evidence(ledger: EvidenceLedger, record: EvidenceRecord, existing_records: List[EvidenceRecord]) -> bool:
        """Check if an evidence record duplicates existing findings without providing independent data."""
        for ex in existing_records:
            if ex.evidence_id == record.evidence_id:
                return True
            # Same observation content, type, and source within the same session
            if (
                ex.evidence_type == record.evidence_type
                and ex.source == record.source
                and ex.observation == record.observation
                and ex.details == record.details
            ):
                return True
            # Same underlying observation_id in details
            if ex.details and record.details:
                ex_obs_id = ex.details.get("observation_id")
                rec_obs_id = record.details.get("observation_id")
                if ex_obs_id and ex_obs_id == rec_obs_id:
                    return True
            # Same finding_id and observation text
            if ex.finding_id and ex.finding_id == record.finding_id and ex.observation == record.observation:
                return True
        return False

    @classmethod
    def verify_causal_proof(
        cls,
        hypothesis: InvestigationHypothesis,
        ledger: EvidenceLedger,
        proof_evidence_id: Optional[str] = None,
        deterministic_transition_verified: bool = False,
    ) -> Tuple[bool, str, Optional[EvidenceRecord]]:
        """Verify whether an auditable, independent evidence record in the ledger proves the causal relationship.

        Strict Canonical Proof Contract:
        1. A caller-supplied Boolean or proof ID WITHOUT authentic internal verifier attestation is rejected.
        2. The proof evidence record MUST exist in the ledger with authentic verifier attestation matching ledger secret.
        3. Cross-investigation, replayed, or synthetic proof records are rejected.
        4. Proof record and all required ancestors must have COMPLETE capture quality (never PARTIAL, FAILED, INVALID, or UNTRUSTED).
        5. Capture consistency must be atomic/stopped (never NON_ATOMIC or unknown).
        6. Provenance graph must be strictly acyclic with NO missing parent records.
        7. Scope must match the hypothesis target field and/or function candidate.
        """
        # 1. Locate the candidate proof record
        proof_rec: Optional[EvidenceRecord] = None
        if proof_evidence_id:
            proof_rec = ledger.get_record(proof_evidence_id)
            if not proof_rec:
                return False, f"Referenced proof evidence '{proof_evidence_id}' does not exist in ledger", None
        else:
            # Search supporting evidence records in ledger
            for eid in hypothesis.supporting_evidence_ids:
                cand = ledger.get_record(eid)
                if not cand:
                    continue
                obs_lower = cand.observation.lower()
                cand_details = cand.details or {}
                cand_prov = cand.provenance or {}
                has_causal_marker = (
                    "verifier_attestation" in cand_prov
                    or cand_details.get("verified_transition") is True
                    or cand_details.get("causal_proof") is True
                    or cand_details.get("reproduction_verified") is True
                    or cand_details.get("transition_verified") is True
                    or cand_details.get("verified_writer") is True
                    or "deterministic transition reproduced" in obs_lower
                    or "reproduced deterministic mutation" in obs_lower
                    or "verified deterministic transition" in obs_lower
                    or (cand.evidence_type == EVIDENCE_TYPE_COMPARISON and "transition" in obs_lower)
                )
                if has_causal_marker:
                    proof_rec = cand
                    break

        # If no qualifying proof record was found:
        if not proof_rec:
            if deterministic_transition_verified:
                return (
                    False,
                    "Caller-supplied deterministic_transition_verified boolean rejected: no verified causal proof record in ledger meeting contract requirements",
                    None,
                )
            return False, "Awaiting verified causal transition proof evidence", None

        p_details = proof_rec.details or {}
        p_prov = proof_rec.provenance or {}

        # 2. Check if proof record was an unverified caller submission
        if (
            p_details.get("caller_submitted") is True
            or p_details.get("unverified_caller_claim") is True
            or proof_rec.source == "unverified_caller"
            or p_prov.get("submission_channel") == "external_caller"
        ):
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' was submitted by unverified caller without independent execution",
                proof_rec,
            )

        # 3. Check capture quality and consistency of proof record itself
        cq = proof_rec.capture_quality
        if not cq or not isinstance(cq, dict):
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' lacks capture quality metadata; causal validation rejected",
                proof_rec,
            )
        c_status = cq.get("completeness") or cq.get("status")
        if not c_status or c_status in ("FAILED", "INVALID", "UNTRUSTED"):
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' has {c_status or 'MISSING'} capture quality; causal validation rejected",
                proof_rec,
            )
        if c_status != "COMPLETE":
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' has {c_status} capture quality; causal validation rejected",
                proof_rec,
            )

        c_level = cq.get("consistency_level") or cq.get("consistency_classification") or p_details.get("consistency_classification")
        if not c_level or c_level not in ("STOPPED", "ATOMIC", "CONSISTENT") or p_details.get("is_non_atomic") is True:
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' lacks atomic/stopped consistency ({c_level or 'UNKNOWN'}); causal validation rejected",
                proof_rec,
            )

        # 4. Verify internal verifier attestation
        attestation = p_prov.get("verifier_attestation")
        if not attestation or not isinstance(attestation, dict):
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' lacks authentic internal verifier attestation",
                proof_rec,
            )
        if attestation.get("token") != ledger.session_secret:
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' has invalid or unverified attestation token",
                proof_rec,
            )
        if attestation.get("investigation_id") != hypothesis.investigation_id:
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' attestation belongs to investigation '{attestation.get('investigation_id')}', not '{hypothesis.investigation_id}'",
                proof_rec,
            )

        # Check cryptographic signature and tamper-evident fingerprint
        expected_fp = compute_evidence_fingerprint(
            proof_rec,
            target_function=attestation.get("target_function"),
            field_path=attestation.get("field_path"),
            hypothesis_id=attestation.get("hypothesis_id"),
            target_identity=attestation.get("target_identity"),
            provenance_class=attestation.get("provenance_class"),
            function_attribution_verified=attestation.get("function_attribution_verified"),
            attribution_basis=attestation.get("attribution_basis"),
        )
        stored_fp = attestation.get("evidence_fingerprint")
        if not stored_fp or stored_fp != expected_fp:
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' content or scope was tampered after attestation issuance (fingerprint mismatch)",
                proof_rec,
            )

        expected_sig = compute_attestation_signature(
            ledger.session_secret,
            proof_rec.evidence_id,
            expected_fp,
            hypothesis.investigation_id,
        )
        stored_sig = attestation.get("token_sig")
        if not stored_sig or stored_sig != expected_sig:
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' has invalid or forged cryptographic attestation signature",
                proof_rec,
            )

        # Check hypothesis binding
        att_hypo_id = attestation.get("hypothesis_id")
        if att_hypo_id and att_hypo_id != hypothesis.hypothesis_id:
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' attestation was issued for hypothesis '{att_hypo_id}', not '{hypothesis.hypothesis_id}'",
                proof_rec,
            )

        # Check target identity binding
        att_tid = attestation.get("target_identity")
        if att_tid and proof_rec.target_identity and att_tid != proof_rec.target_identity:
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' target identity was tampered after attestation issuance",
                proof_rec,
            )

        # Check scope tampering between details and attestation
        att_fn = attestation.get("target_function")
        p_details_fn = p_details.get("target_function")
        if att_fn and p_details_fn and att_fn != p_details_fn:
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' target function in details '{p_details_fn}' does not match attested function '{att_fn}'",
                proof_rec,
            )

        att_fld = attestation.get("field_path")
        p_details_fld = p_details.get("field_path")
        if att_fld and p_details_fld and att_fld != p_details_fld:
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' field path in details '{p_details_fld}' does not match attested field '{att_fld}'",
                proof_rec,
            )

        # 5. Check cross-investigation record ownership
        if proof_rec.session_id and proof_rec.session_id != hypothesis.investigation_id:
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' belongs to session '{proof_rec.session_id}', rejected as cross-investigation evidence",
                proof_rec,
            )

        # 6. Check provenance integrity and ancestry quality
        ok, prov_err, anc_summary = cls.check_provenance_ancestry_quality(ledger, proof_rec.evidence_id)
        if not ok or prov_err:
            if "cycle" in str(prov_err).lower():
                return (
                    False,
                    f"Proof evidence '{proof_rec.evidence_id}' is part of a cyclic provenance graph",
                    proof_rec,
                )
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' provenance error: {prov_err}",
                proof_rec,
            )
        if anc_summary.get("has_untrusted_ancestor"):
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' has untrusted/failed ancestor evidence in provenance chain; causal validation rejected",
                proof_rec,
            )
        if anc_summary.get("has_missing_quality_ancestor"):
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' has ancestor with missing capture quality in provenance chain; causal validation rejected",
                proof_rec,
            )
        if anc_summary.get("has_partial_ancestor"):
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' has PARTIAL ancestor evidence in provenance chain; causal validation rejected",
                proof_rec,
            )
        if anc_summary.get("has_non_atomic_ancestor"):
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' has NON_ATOMIC ancestor evidence in provenance chain; causal validation rejected",
                proof_rec,
            )
        if anc_summary.get("has_cross_session_ancestor"):
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' has cross-session ancestor evidence in provenance chain; causal validation rejected",
                proof_rec,
            )

        # 7. Check scope / target identity binding
        target_fields = getattr(hypothesis, "candidate_fields", []) or []
        proof_field = p_details.get("field_path") or attestation.get("field_path") or ""
        if target_fields and proof_field:
            if not any(is_exact_semantic_path_match(proof_field, proof_field.split(".")[-1], f) or is_exact_semantic_path_match(f, f.split(".")[-1], proof_field) for f in target_fields):
                return (
                    False,
                    f"Proof evidence '{proof_rec.evidence_id}' target field '{proof_field}' does not match hypothesis candidate fields {target_fields}",
                    proof_rec,
                )

        proof_fn = p_details.get("target_function") or attestation.get("target_function") or p_details.get("writer_function")
        cand_fns = [fc.get("function_name") for fc in hypothesis.function_candidates if fc.get("function_name")]
        if proof_fn and cand_fns and proof_fn not in cand_fns:
            return (
                False,
                f"Proof evidence '{proof_rec.evidence_id}' target function '{proof_fn}' does not match any hypothesis function candidate",
                proof_rec,
            )

        return True, f"Causal relationship verified by evidence record '{proof_rec.evidence_id}'", proof_rec

    @classmethod
    def evaluate(
        cls,
        hypothesis: InvestigationHypothesis,
        ledger: EvidenceLedger,
        new_evidence: Optional[EvidenceRecord] = None,
        deterministic_transition_verified: bool = False,
        proof_evidence_id: Optional[str] = None,
    ) -> ValidationTransitionResult:
        """Evaluate a hypothesis against the evidence ledger and optional newly acquired evidence.

        Strict Enforcements:
        1. A hypothesis must NEVER become VALIDATED merely because an LLM claimed it or a static candidate matches.
        2. VALIDATED requires:
           - Explicit causal criteria satisfied by verified, independent evidence in the ledger
           - Complete capture quality (no UNTRUSTED or PARTIAL)
           - Atomic capture consistency (no NON_ATOMIC)
           - Supporting evidence > 0
           - Contradicting evidence == 0
        3. Contradicting evidence immediately transitions hypothesis to CONTRADICTED.
        4. PARTIAL / UNTRUSTED / INVALID / NON_ATOMIC captures cap status at INCONCLUSIVE or SUPPORTED.
        5. Duplicate evidence does NOT count as independent corroboration.
        6. Cyclic provenance and missing parent records are rejected and flagged.
        7. STATIC_CANDIDATE from DWARF/source can never become confirmed root cause.
        """
        old_status = hypothesis.validation_status
        old_conf = hypothesis.confidence

        cycle_found = False
        prov_error: Optional[str] = None

        if new_evidence and new_evidence.evidence_id:
            c_found, p_err = cls.check_provenance_integrity(ledger, new_evidence.evidence_id)
            if c_found:
                cycle_found = True
            if p_err and not prov_error:
                prov_error = p_err

        # Check existing supporting evidence for provenance integrity
        for eid in hypothesis.supporting_evidence_ids:
            c_found, p_err = cls.check_provenance_integrity(ledger, eid)
            if c_found:
                cycle_found = True
            if p_err and not prov_error:
                prov_error = p_err

        # Inspect capture quality across all supporting evidence
        has_untrusted_evidence = False
        has_partial_evidence = False
        has_non_atomic_evidence = False
        for eid in hypothesis.supporting_evidence_ids:
            rec = ledger.get_record(eid)
            if rec:
                cq = rec.capture_quality or {}
                c_status = cq.get("completeness") or cq.get("status")
                if c_status in ("FAILED", "INVALID", "UNTRUSTED"):
                    has_untrusted_evidence = True
                elif c_status == "PARTIAL":
                    has_partial_evidence = True
                c_level = cq.get("consistency_level") or cq.get("consistency_classification") or (rec.details or {}).get("consistency_classification")
                if c_level == "NON_ATOMIC" or (rec.details or {}).get("is_non_atomic") is True:
                    has_non_atomic_evidence = True

        # Process newly attached evidence
        new_is_duplicate = False
        trigger_eid = None
        if new_evidence:
            trigger_eid = new_evidence.evidence_id
            existing_ids = list(dict.fromkeys(hypothesis.supporting_evidence_ids + hypothesis.contradicting_evidence_ids))
            existing = [ledger.get_record(e) for e in existing_ids if ledger.get_record(e)]
            if cls.is_duplicate_evidence(ledger, new_evidence, existing):
                new_is_duplicate = True

            if not new_is_duplicate and not cycle_found and not prov_error:
                # Check if evidence outcome is contradicting
                is_contradiction = False
                details = new_evidence.details or {}
                obs_text = new_evidence.observation.lower()

                if details.get("outcome") == "CONTRADICTED" or "contradict" in obs_text or "mismatch" in obs_text:
                    is_contradiction = True

                if is_contradiction:
                    if new_evidence.evidence_id not in hypothesis.contradicting_evidence_ids:
                        hypothesis.contradicting_evidence_ids.append(new_evidence.evidence_id)
                else:
                    if new_evidence.evidence_id not in hypothesis.supporting_evidence_ids:
                        hypothesis.supporting_evidence_ids.append(new_evidence.evidence_id)
                        cq = new_evidence.capture_quality or {}
                        c_status = cq.get("completeness") or cq.get("status")
                        if c_status in ("FAILED", "INVALID", "UNTRUSTED"):
                            has_untrusted_evidence = True
                        elif c_status == "PARTIAL":
                            has_partial_evidence = True
                        c_level = cq.get("consistency_level") or cq.get("consistency_classification") or details.get("consistency_classification")
                        if c_level == "NON_ATOMIC" or details.get("is_non_atomic") is True:
                            has_non_atomic_evidence = True

        # Deduplicate evidence ID lists for strict idempotency
        hypothesis.supporting_evidence_ids = list(dict.fromkeys(hypothesis.supporting_evidence_ids))
        hypothesis.contradicting_evidence_ids = list(dict.fromkeys(hypothesis.contradicting_evidence_ids))

        supp_count = len(hypothesis.supporting_evidence_ids)
        contra_count = len(hypothesis.contradicting_evidence_ids)

        new_status = old_status
        new_conf = old_conf
        reason = "Status unchanged."
        unverified_claim_rejected = False
        verified_proof_rec: Optional[EvidenceRecord] = None

        if cycle_found:
            new_status = HYPOTHESIS_STATUS_INCONCLUSIVE
            new_conf = CONFIDENCE_LOW
            reason = "Cyclic evidence provenance detected; evaluation halted to prevent recursive reasoning."
        elif prov_error:
            new_status = HYPOTHESIS_STATUS_INCONCLUSIVE
            new_conf = CONFIDENCE_LOW
            reason = f"Evidence provenance integrity violation: {prov_error}."
        elif contra_count > 0:
            # Contradiction dominance: even repeated evaluation or duplicate supporting records cannot override
            new_status = HYPOTHESIS_STATUS_CONTRADICTED
            new_conf = CONFIDENCE_HIGH
            reason = f"Contradicted by {contra_count} independent observation(s)."
        elif has_untrusted_evidence:
            new_status = HYPOTHESIS_STATUS_INCONCLUSIVE
            new_conf = CONFIDENCE_LOW
            reason = "Supporting evidence originates from FAILED, INVALID, or missing capture quality; cannot support hypothesis."
        elif supp_count > 0:
            proof_valid, proof_msg, proof_rec = cls.verify_causal_proof(
                hypothesis,
                ledger,
                proof_evidence_id=proof_evidence_id,
                deterministic_transition_verified=deterministic_transition_verified,
            )

            if proof_valid and proof_rec:
                verified_proof_rec = proof_rec
                proof_cq = proof_rec.capture_quality or {}
                proof_c_status = proof_cq.get("completeness") or proof_cq.get("status")
                proof_level = proof_cq.get("consistency_level") or proof_cq.get("consistency_classification") or (proof_rec.details or {}).get("consistency_classification")
                is_proof_partial = (proof_c_status == "PARTIAL")
                is_proof_non_atomic = (proof_level == "NON_ATOMIC") or (proof_rec.details or {}).get("is_non_atomic") is True

                proof_att = (proof_rec.provenance or {}).get("verifier_attestation") or {}
                proof_prov_cls = (
                    proof_att.get("provenance_class")
                    or (proof_rec.details or {}).get("provenance_class")
                    or (proof_rec.provenance or {}).get("provenance_class")
                    or PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION
                )
                is_synthetic_or_unverified = (proof_prov_cls not in TRUSTED_PROVENANCE_CLASSES)

                if is_synthetic_or_unverified:
                    new_status = HYPOTHESIS_STATUS_SUPPORTED
                    new_conf = CONFIDENCE_MEDIUM
                    reason = f"Causal transition supported by evidence {proof_rec.evidence_id}, but provenance class '{proof_prov_cls}' is synthetic/unverified; capped at SUPPORTED."
                    for fc in hypothesis.function_candidates:
                        fc["confirmed_root_cause"] = False
                        fc["tier_limitation"] = f"Provenance class '{proof_prov_cls}' is not trusted live runtime; function cannot be confirmed root cause."
                elif has_partial_evidence or is_proof_partial:
                    new_status = HYPOTHESIS_STATUS_SUPPORTED
                    new_conf = CONFIDENCE_MEDIUM
                    reason = "Causal transition observed, but capture quality is PARTIAL; capped at SUPPORTED."
                elif has_non_atomic_evidence or is_proof_non_atomic:
                    new_status = HYPOTHESIS_STATUS_SUPPORTED
                    new_conf = CONFIDENCE_LOW
                    reason = "Causal transition observed, but capture consistency is NON_ATOMIC; capped at SUPPORTED."
                else:
                    # Validated with full causal proof!
                    new_status = HYPOTHESIS_STATUS_VALIDATED
                    new_conf = CONFIDENCE_HIGH
                    reason = f"Deterministic transition verified causal relationship via evidence {proof_rec.evidence_id}; all criteria satisfied."

                    # Upgrade function candidate if present (Invariant 1 & 2: STATIC_CANDIDATE never promoted!)
                    target_fn = (proof_rec.details or {}).get("target_function") or (proof_rec.details or {}).get("writer_function") or (proof_rec.details or {}).get("executing_function")
                    func_attr_ver = bool(proof_att.get("function_attribution_verified", (proof_rec.details or {}).get("function_attribution_verified", False)))

                    for fc in hypothesis.function_candidates:
                        tier = fc.get("candidate_tier")
                        fn_name = fc.get("function_name")
                        if tier == FUNCTION_TIER_EVIDENCE_SUPPORTED:
                            if not target_fn or fn_name == target_fn:
                                if func_attr_ver:
                                    fc["candidate_tier"] = FUNCTION_TIER_VALIDATED_CAUSAL
                                    fc["confirmed_root_cause"] = True
                                    fc["tier_limitation"] = f"Causal role verified via deterministic reproduction and verified function attribution in evidence {proof_rec.evidence_id}."
                                else:
                                    fc["confirmed_root_cause"] = False
                                    fc["tier_limitation"] = f"State transition verified in runtime, but function attribution was not independently verified by execution instrumentation."
                            else:
                                fc["confirmed_root_cause"] = False
                                fc["tier_limitation"] = f"Observed in execution, but causal proof evidence identifies {target_fn} as the causal writer."
                        elif tier == FUNCTION_TIER_STATIC_CANDIDATE:
                            # Invariant 1: static candidates remain static candidates
                            fc["confirmed_root_cause"] = False
                            fc["tier_limitation"] = "Static reference candidate identified via DWARF/ELF analysis; not confirmed root-cause function."
            else:
                # Causal proof was not established
                if proof_rec and (proof_rec.capture_quality or {}).get("completeness") in ("FAILED", "INVALID", "UNTRUSTED"):
                    new_status = HYPOTHESIS_STATUS_INCONCLUSIVE
                    new_conf = CONFIDENCE_LOW
                else:
                    new_status = HYPOTHESIS_STATUS_SUPPORTED
                    new_conf = CONFIDENCE_MEDIUM if (not has_partial_evidence and not has_non_atomic_evidence) else CONFIDENCE_LOW
                if deterministic_transition_verified or proof_evidence_id or (new_evidence and ((new_evidence.details or {}).get("unverified_caller_claim") or (new_evidence.details or {}).get("caller_submitted"))):
                    unverified_claim_rejected = True
                    if has_partial_evidence:
                        reason = f"Supported by {supp_count} observation(s); capture quality is PARTIAL; capped at SUPPORTED ({proof_msg})."
                    elif has_non_atomic_evidence:
                        reason = f"Supported by {supp_count} observation(s); capture consistency is NON_ATOMIC; capped at SUPPORTED ({proof_msg})."
                    else:
                        reason = f"Supported by {supp_count} observation(s); causal proof rejected ({proof_msg})."
                else:
                    reason = f"Supported by {supp_count} observation(s); awaiting explicit causal validation."
        else:
            new_status = HYPOTHESIS_STATUS_PROPOSED
            reason = "Awaiting follow-up observation evidence."

        status_changed = (new_status != old_status) or (new_conf != old_conf)
        if status_changed:
            hypothesis.validation_status = new_status
            hypothesis.confidence = new_conf
            hypothesis.updated_at = datetime.now(timezone.utc).isoformat()
            hypothesis.status_history.append({
                "from_status": old_status,
                "to_status": new_status,
                "timestamp": hypothesis.updated_at,
                "reason": reason,
                "trigger_evidence_id": trigger_eid,
                "proof_evidence_id": verified_proof_rec.evidence_id if verified_proof_rec else None,
                "unverified_claim_rejected": unverified_claim_rejected,
            })

        return ValidationTransitionResult(
            hypothesis_id=hypothesis.hypothesis_id,
            from_status=old_status,
            to_status=new_status,
            status_changed=status_changed,
            confidence=new_conf,
            reason=reason,
            trigger_evidence_id=trigger_eid,
            supporting_count=supp_count,
            contradicting_count=contra_count,
            cycle_detected=cycle_found,
            is_duplicate=new_is_duplicate,
            provenance_error=prov_error,
            proof_evidence_id=verified_proof_rec.evidence_id if verified_proof_rec else None,
            unverified_claim_rejected=unverified_claim_rejected,
        )
