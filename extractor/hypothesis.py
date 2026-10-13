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


class HypothesisValidator:
    """Evaluates and validates hypotheses against the Evidence Ledger with strict criteria."""

    @staticmethod
    def detect_cycles(ledger: EvidenceLedger, start_evidence_id: str, max_depth: int = 50) -> bool:
        """Verify that the evidence provenance graph is strictly acyclic."""
        visited: Set[str] = set()
        stack: Set[str] = set()

        def _dfs(eid: str, depth: int) -> bool:
            if depth > max_depth:
                return True  # Treat excessive depth as potential cycle
            if eid in stack:
                return True  # Cycle detected!
            if eid in visited:
                return False

            visited.add(eid)
            stack.add(eid)

            rec = ledger.get_record(eid)
            if rec:
                for parent_id in rec.parent_evidence_ids:
                    if _dfs(parent_id, depth + 1):
                        return True

            stack.remove(eid)
            return False

        return _dfs(start_evidence_id, 0)

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
        return False

    @classmethod
    def evaluate(
        cls,
        hypothesis: InvestigationHypothesis,
        ledger: EvidenceLedger,
        new_evidence: Optional[EvidenceRecord] = None,
        deterministic_transition_verified: bool = False,
    ) -> ValidationTransitionResult:
        """Evaluate a hypothesis against the evidence ledger and optional newly acquired evidence.

        Strict Enforcements:
        1. A hypothesis must NEVER become VALIDATED merely because an LLM claimed it or a static candidate matches.
        2. VALIDATED requires:
           - Explicit causal criteria satisfied (e.g. deterministic transition verification or verified stack write)
           - Complete capture quality (no UNTRUSTED or PARTIAL)
           - Supporting evidence > 0
           - Contradicting evidence == 0
        3. Contradicting evidence immediately transitions hypothesis to CONTRADICTED.
        4. PARTIAL / UNTRUSTED / INVALID captures cap status at INCONCLUSIVE or PROPOSED.
        5. Duplicate evidence does NOT count as independent corroboration.
        6. Cyclic provenance is rejected and flagged.
        """
        old_status = hypothesis.validation_status
        old_conf = hypothesis.confidence

        cycle_found = False
        if new_evidence and new_evidence.evidence_id:
            cycle_found = cls.detect_cycles(ledger, new_evidence.evidence_id)

        # Inspect capture quality across all supporting evidence
        has_untrusted_evidence = False
        has_partial_evidence = False
        for eid in hypothesis.supporting_evidence_ids:
            rec = ledger.get_record(eid)
            if rec:
                cq = rec.capture_quality or {}
                c_status = cq.get("completeness") or cq.get("status")
                if c_status in ("FAILED", "INVALID"):
                    has_untrusted_evidence = True
                elif c_status == "PARTIAL":
                    has_partial_evidence = True

        # Process newly attached evidence
        new_is_duplicate = False
        trigger_eid = None
        if new_evidence:
            trigger_eid = new_evidence.evidence_id
            existing = [ledger.get_record(e) for e in hypothesis.supporting_evidence_ids if ledger.get_record(e)]
            if cls.is_duplicate_evidence(ledger, new_evidence, existing):
                new_is_duplicate = True

            if not new_is_duplicate and not cycle_found:
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

        # Check evidence counts
        supp_count = len(hypothesis.supporting_evidence_ids)
        contra_count = len(hypothesis.contradicting_evidence_ids)

        new_status = old_status
        new_conf = old_conf
        reason = "Status unchanged."

        if cycle_found:
            new_status = HYPOTHESIS_STATUS_INCONCLUSIVE
            new_conf = CONFIDENCE_LOW
            reason = "Cyclic evidence provenance detected; evaluation halted to prevent recursive reasoning."
        elif contra_count > 0:
            new_status = HYPOTHESIS_STATUS_CONTRADICTED
            new_conf = CONFIDENCE_HIGH
            reason = f"Contradicted by {contra_count} independent observation(s)."
        elif has_untrusted_evidence:
            new_status = HYPOTHESIS_STATUS_INCONCLUSIVE
            new_conf = CONFIDENCE_LOW
            reason = "Supporting evidence originates from FAILED or INVALID capture; cannot support hypothesis."
        elif supp_count > 0:
            if deterministic_transition_verified:
                # Explicit causal proof demonstrated!
                if not has_partial_evidence:
                    new_status = HYPOTHESIS_STATUS_VALIDATED
                    new_conf = CONFIDENCE_HIGH
                    reason = "Deterministic transition verified causal relationship; all criteria satisfied."
                    # Upgrade function candidate if present
                    for fc in hypothesis.function_candidates:
                        if fc.get("candidate_tier") == FUNCTION_TIER_EVIDENCE_SUPPORTED:
                            fc["candidate_tier"] = FUNCTION_TIER_VALIDATED_CAUSAL
                            fc["confirmed_root_cause"] = True
                            fc["tier_limitation"] = "Causal role verified via deterministic reproduction."
                else:
                    new_status = HYPOTHESIS_STATUS_SUPPORTED
                    new_conf = CONFIDENCE_MEDIUM
                    reason = "Causal transition observed, but capture quality is PARTIAL; capped at SUPPORTED."
            else:
                # Supported by observations, but not causally proven
                new_status = HYPOTHESIS_STATUS_SUPPORTED
                new_conf = CONFIDENCE_MEDIUM if not has_partial_evidence else CONFIDENCE_LOW
                reason = f"Supported by {supp_count} observation(s); awaiting explicit causal validation."
        else:
            new_status = HYPOTHESIS_STATUS_PROPOSED
            reason = "Awaiting follow-up observation evidence."

        status_changed = (new_status != old_status)
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
        )
