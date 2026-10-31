import hashlib
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
    EVIDENCE_TYPE_INFERENCE,
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
    CLAIM_ARTIFACT_INTEGRITY_VERIFIED,
    CLAIM_CAPTURE_PROVENANCE_VERIFIED,
    CLAIM_TARGET_IDENTITY_VERIFIED,
    CLAIM_STATE_TRANSITION_VERIFIED,
    CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
)

# -----------------------------------------------------------------------------
# Canonical Status and Classification Constants
# -----------------------------------------------------------------------------

# Evidence and Finding classifications
EVIDENCE_CLASSIFICATION_FACT = "OBSERVED_FACT"
EVIDENCE_CLASSIFICATION_INFERENCE = "INFERENCE"
EVIDENCE_CLASSIFICATION_INFERRED_HYPOTHESIS = "INFERRED_HYPOTHESIS"
EVIDENCE_CLASSIFICATION_UNKNOWN = "UNKNOWN"
EVIDENCE_CLASSIFICATION_PROPOSED_ACTION = "PROPOSED_ACTION"

VALID_EVIDENCE_CLASSIFICATIONS = {
    EVIDENCE_CLASSIFICATION_FACT,
    EVIDENCE_CLASSIFICATION_INFERENCE,
    EVIDENCE_CLASSIFICATION_INFERRED_HYPOTHESIS,
    EVIDENCE_CLASSIFICATION_UNKNOWN,
    EVIDENCE_CLASSIFICATION_PROPOSED_ACTION,
}

# Follow-up observation lifecycle states
OBSERVATION_STATUS_PROPOSED = "proposed"
OBSERVATION_STATUS_EXECUTED = "executed"
OBSERVATION_STATUS_FAILED = "failed"
OBSERVATION_STATUS_VERIFIED = "verified"
OBSERVATION_STATUS_CANCELED = "canceled"

VALID_OBSERVATION_STATUSES = {
    OBSERVATION_STATUS_PROPOSED,
    OBSERVATION_STATUS_EXECUTED,
    OBSERVATION_STATUS_FAILED,
    OBSERVATION_STATUS_VERIFIED,
    OBSERVATION_STATUS_CANCELED,
}

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
CONFIDENCE_VERY_HIGH = "HIGH"     # Alias for maximum confidence
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
FUNCTION_TIER_UNVERIFIED = "UNVERIFIED"
FUNCTION_TIER_UNKNOWN = "UNKNOWN"

VALID_FUNCTION_TIERS = {
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    FUNCTION_TIER_UNVERIFIED,
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
    hypothesis_id: str = ""
    question: str = ""
    target_kind: str = TARGET_KIND_FIELD  # FIELD, OBJECT, THREAD, SNAPSHOT, COMPARISON, SOURCE, MUTATION
    target_ref: Dict[str, Any] = field(default_factory=dict)
    discriminating_criteria: str = ""
    expected_outcomes: Dict[str, str] = field(default_factory=dict)  # outcome condition description -> resulting status
    discriminating_power: str = "HIGH"  # HIGH, MEDIUM, LOW
    required_capture_quality: str = "COMPLETE"  # COMPLETE, ANY
    safety_constraints: List[str] = field(default_factory=list)
    is_suggestion: bool = True
    executed: bool = False
    result_evidence_id: Optional[str] = None
    status: str = OBSERVATION_STATUS_PROPOSED  # proposed, executed, failed, verified, canceled
    prerequisites: List[str] = field(default_factory=list)
    risk_level: str = "READ_ONLY"  # READ_ONLY, CAUTION, MUTATION
    estimated_cost: str = "LOW"  # LOW, MEDIUM, HIGH
    success_criteria: Optional[str] = None
    failure_criteria: Optional[str] = None
    execution_error: Optional[str] = None
    target_identifier: Optional[str] = None
    created_at: str = ""
    tested_hypothesis_ids: List[str] = field(default_factory=list)
    expected_outcomes_by_hypothesis: Dict[str, Any] = field(default_factory=dict)
    estimated_bytes: Optional[int] = 4096
    estimated_latency_ms: float = 20.0
    estimated_samples: int = 1
    estimated_stop_ms: float = 0.0
    preference_rationale: str = ""
    why_needed: str = ""
    profile_id: Optional[str] = None
    semantic_key: str = ""
    result_category: Optional[str] = None

    def __post_init__(self):
        if not self.observation_id:
            self.observation_id = f"obs_plan_{uuid.uuid4().hex[:8]}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if self.target_identifier and not self.target_ref:
            self.target_ref = {"identifier": self.target_identifier}
        if self.target_kind not in VALID_TARGET_KINDS:
            raise ValueError(f"Invalid target_kind '{self.target_kind}'. Expected one of {sorted(VALID_TARGET_KINDS)}")
        if self.status not in VALID_OBSERVATION_STATUSES:
            self.status = OBSERVATION_STATUS_EXECUTED if self.executed else OBSERVATION_STATUS_PROPOSED
        # Invariant: A failed or canceled observation never becomes a successful executed observation
        if self.status in (OBSERVATION_STATUS_FAILED, OBSERVATION_STATUS_CANCELED):
            self.executed = False
        elif self.executed and self.status == OBSERVATION_STATUS_PROPOSED:
            self.status = OBSERVATION_STATUS_EXECUTED
        if self.hypothesis_id and self.hypothesis_id not in self.tested_hypothesis_ids:
            self.tested_hypothesis_ids = [self.hypothesis_id] + list(self.tested_hypothesis_ids)
        if not self.why_needed and self.question:
            self.why_needed = self.question
        if not self.semantic_key:
            import hashlib as _hl
            import json as _js
            raw_k = _js.dumps(
                {
                    "kind": self.target_kind,
                    "ref": self.target_ref,
                    "profile": self.profile_id,
                    "question": self.question,
                },
                sort_keys=True,
                default=str,
            ).encode("utf-8")
            self.semantic_key = f"obs_key_{_hl.sha256(raw_k).hexdigest()[:14]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FollowUpObservation":
        st = data.get("status")
        is_exec = bool(data.get("executed", False))
        if st in (OBSERVATION_STATUS_FAILED, OBSERVATION_STATUS_CANCELED):
            is_exec = False
        if not st:
            st = OBSERVATION_STATUS_EXECUTED if is_exec else OBSERVATION_STATUS_PROPOSED
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
            executed=is_exec,
            result_evidence_id=data.get("result_evidence_id"),
            status=st,
            prerequisites=list(data.get("prerequisites", [])),
            risk_level=data.get("risk_level", "READ_ONLY"),
            estimated_cost=data.get("estimated_cost", "LOW"),
            success_criteria=data.get("success_criteria"),
            failure_criteria=data.get("failure_criteria"),
            execution_error=data.get("execution_error"),
            target_identifier=data.get("target_identifier"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            tested_hypothesis_ids=list(data.get("tested_hypothesis_ids", [])),
            expected_outcomes_by_hypothesis=dict(data.get("expected_outcomes_by_hypothesis", {})),
            estimated_bytes=data.get("estimated_bytes", 4096),
            estimated_latency_ms=float(data.get("estimated_latency_ms", 20.0)),
            estimated_samples=int(data.get("estimated_samples", 1)),
            estimated_stop_ms=float(data.get("estimated_stop_ms", 0.0)),
            preference_rationale=data.get("preference_rationale", ""),
            why_needed=data.get("why_needed", ""),
            profile_id=data.get("profile_id"),
            semantic_key=data.get("semantic_key", ""),
            result_category=data.get("result_category"),
        )


# -----------------------------------------------------------------------------
# Structured Hypothesis Model
# -----------------------------------------------------------------------------

@dataclass
class InvestigationHypothesis:
    """A structured, evidence-grounded root-cause hypothesis with auditable validation history."""
    hypothesis_id: str
    investigation_id: str = ""
    title: str = ""
    claim: str = ""
    proposed_mechanism: str = ""
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
    classification: str = EVIDENCE_CLASSIFICATION_INFERENCE
    uncertainty: Optional[str] = None
    discriminating_evidence_needed: List[str] = field(default_factory=list)
    target_kind: Optional[str] = None
    target_identifier: Optional[str] = None
    competing_hypothesis_ids: List[str] = field(default_factory=list)
    status: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""
    provenance: Dict[str, Any] = field(default_factory=dict)
    target_threads: List[Union[int, str]] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)
    confidence_score: float = 0.5
    anomaly_category: Optional[str] = None

    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        if name == "validation_status" and value is not None and getattr(self, "status", None) != value:
            super().__setattr__("status", value)
        elif name == "status" and value is not None and getattr(self, "validation_status", None) != value:
            super().__setattr__("validation_status", value)

    @property
    def target_object_id(self) -> Optional[str]:
        if self.candidate_objects:
            return self.candidate_objects[0]
        if self.target_identifier and not "." in self.target_identifier:
            return self.target_identifier
        return None

    @property
    def target_field_path(self) -> Optional[str]:
        if self.candidate_fields:
            return self.candidate_fields[0]
        if self.target_identifier and "." in self.target_identifier:
            return self.target_identifier
        return None

    def __post_init__(self):
        if not self.hypothesis_id:
            self.hypothesis_id = f"hypo_{uuid.uuid4().hex[:10]}"
        if self.status:
            self.validation_status = self.status
        else:
            self.status = self.validation_status
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
        if self.validation_status not in VALID_HYPOTHESIS_STATUSES:
            raise ValueError(f"Invalid validation_status '{self.validation_status}'. Expected one of {sorted(VALID_HYPOTHESIS_STATUSES)}")
        if self.confidence not in VALID_CONFIDENCE_LEVELS:
            raise ValueError(f"Invalid confidence '{self.confidence}'. Expected one of {sorted(VALID_CONFIDENCE_LEVELS)}")
        if self.classification not in VALID_EVIDENCE_CLASSIFICATIONS:
            self.classification = EVIDENCE_CLASSIFICATION_INFERENCE
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
        data["suggested_observations"] = [
            obs.to_dict() if hasattr(obs, "to_dict") else obs
            for obs in self.suggested_observations
        ]
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
            classification=data.get("classification", EVIDENCE_CLASSIFICATION_INFERENCE),
            uncertainty=data.get("uncertainty"),
            discriminating_evidence_needed=list(data.get("discriminating_evidence_needed", [])),
            target_kind=data.get("target_kind"),
            target_identifier=data.get("target_identifier"),
            competing_hypothesis_ids=list(data.get("competing_hypothesis_ids", [])),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
            provenance=dict(data.get("provenance", {})),
            target_threads=list(data.get("target_threads", [])),
            target_regions=list(data.get("target_regions", [])),
            confidence_score=float(data.get("confidence_score", 0.5)),
            anomaly_category=data.get("anomaly_category"),
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

    def generate_from_findings(
        self,
        findings: List[Any],
        function_candidates: Optional[List[Any]] = None,
        investigation_id: str = "inv_from_findings",
        capture_quality: Optional[Dict[str, Any]] = None,
    ) -> List[InvestigationHypothesis]:
        """Generate hypotheses directly from finding objects and optional correlated function candidates."""
        hypos: List[InvestigationHypothesis] = []
        cands_list = list(function_candidates or [])

        norm_candidates = []
        for c in cands_list:
            if hasattr(c, "to_dict"):
                cd = c.to_dict()
            elif isinstance(c, dict):
                cd = dict(c)
            else:
                cd = {"function_name": str(c)}
            cd.setdefault("candidate_tier", FUNCTION_TIER_STATIC_CANDIDATE)
            cd.setdefault("confirmed_root_cause", False)
            cd.setdefault("tier_limitation", "Static reference candidate identified via DWARF/ELF analysis; not confirmed root-cause function.")
            norm_candidates.append(cd)

        for finding in findings:
            obj_id = getattr(finding, "object_id", None) or getattr(finding, "target_identifier", "obj")
            field_name = getattr(finding, "field_name", "field")
            c_path = getattr(finding, "c_type_path", None) or f"{obj_id}.{field_name}"
            supp_eids = list(getattr(finding, "supporting_evidence_ids", []) or getattr(finding, "evidence_ids", []))
            finding_cands = list(getattr(finding, "function_candidates", []) or [])
            all_cands = norm_candidates + [
                (c.to_dict() if hasattr(c, "to_dict") else dict(c)) for c in finding_cands
            ]

            if len(all_cands) >= 2:
                for cand in all_cands:
                    cand_fn = cand.get("function_name", "unknown_fn")
                    h_id = f"hypo_comp_{uuid.uuid4().hex[:8]}"
                    other_fns = [c.get("function_name") for c in all_cands if c.get("function_name") != cand_fn]
                    obs = FollowUpObservation(
                        observation_id=f"obs_disc_{uuid.uuid4().hex[:6]}",
                        hypothesis_id=h_id,
                        question=f"Did '{cand_fn}' execute the mutation on {c_path} instead of {other_fns}?",
                        target_kind=TARGET_KIND_THREAD,
                        target_ref={"field_path": c_path, "target_function": cand_fn},
                        discriminating_criteria=f"Verify execution trace or call stack attributing write to {cand_fn}",
                        expected_outcomes={
                            f"{cand_fn}_executed": "SUPPORTED",
                            "competing_function_executed": "CONTRADICTED",
                        },
                        discriminating_power="HIGH",
                        safety_constraints=["Read-only trace inspection."],
                        status=OBSERVATION_STATUS_PROPOSED,
                    )
                    h = InvestigationHypothesis(
                        hypothesis_id=h_id,
                        investigation_id=investigation_id,
                        title=f"Mutation of {c_path} by {cand_fn}",
                        claim=f"Function '{cand_fn}' performed the mutation on {c_path}.",
                        proposed_mechanism=f"Execution in '{cand_fn}' wrote to {field_name}.",
                        supporting_evidence_ids=supp_eids,
                        candidate_objects=[obj_id] if obj_id else [],
                        candidate_fields=[c_path],
                        function_candidates=[cand],
                        suggested_observations=[obs],
                        classification=EVIDENCE_CLASSIFICATION_INFERENCE,
                        confidence=CONFIDENCE_MEDIUM,
                        validation_status=HYPOTHESIS_STATUS_PROPOSED,
                        discriminating_evidence_needed=[
                            f"Execution trace distinguishing {cand_fn} from competing candidates {other_fns}"
                        ],
                    )
                    hypos.append(h)
            else:
                h_id = f"hypo_fnd_{uuid.uuid4().hex[:8]}"
                cand_fn = all_cands[0].get("function_name") if all_cands else "unknown_function"
                mech = (
                    f"Execution in '{cand_fn}' modified {field_name}."
                    if all_cands
                    else f"Observed field modification on {c_path}."
                )
                obs = FollowUpObservation(
                    observation_id=f"obs_fnd_{uuid.uuid4().hex[:6]}",
                    hypothesis_id=h_id,
                    question=f"Does execution in '{cand_fn}' reproduce mutation of {c_path}?",
                    target_kind=TARGET_KIND_FIELD,
                    target_ref={"field_path": c_path},
                    discriminating_criteria=f"Reproduce modification under single-writer condition for {cand_fn}",
                    status=OBSERVATION_STATUS_PROPOSED,
                )
                h = InvestigationHypothesis(
                    hypothesis_id=h_id,
                    investigation_id=investigation_id,
                    title=f"Mutation of {c_path}",
                    claim=f"Field {c_path} was modified by {cand_fn}.",
                    proposed_mechanism=mech,
                    supporting_evidence_ids=supp_eids,
                    candidate_objects=[obj_id] if obj_id else [],
                    candidate_fields=[c_path],
                    function_candidates=all_cands,
                    suggested_observations=[obs],
                    classification=EVIDENCE_CLASSIFICATION_INFERENCE,
                    confidence=CONFIDENCE_MEDIUM,
                    validation_status=HYPOTHESIS_STATUS_PROPOSED,
                    discriminating_evidence_needed=[
                        f"Discriminative execution trace or call stack evidence isolating {c_path}"
                    ],
                )
                hypos.append(h)

        return hypos

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
                classification=EVIDENCE_CLASSIFICATION_INFERENCE,
                uncertainty=conf_rationale if conf in (CONFIDENCE_LOW, CONFIDENCE_SPECULATIVE) else None,
                discriminating_evidence_needed=[f"Discriminative execution trace or call stack evidence isolating the causal writer of {c_path}"],
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

            # Competing candidate hypotheses: when 2+ function candidates are linked via DWARF
            if len(qualified_candidates) >= 2:
                for cand in qualified_candidates[:3]:
                    cand_fn = cand.get("function_name")
                    if not cand_fn:
                        continue
                    comp_hypo_id = f"hypo_cand_{cand_fn}_{uuid.uuid4().hex[:6]}"
                    comp_obs = [
                        FollowUpObservation(
                            observation_id=f"obs_fn_{cand_fn}_{uuid.uuid4().hex[:6]}",
                            hypothesis_id=comp_hypo_id,
                            question=f"Did function '{cand_fn}' execute the write instruction that mutated {c_path}?",
                            target_kind=TARGET_KIND_THREAD,
                            target_ref={"field_path": c_path, "target_function": cand_fn, "thread_id": df.thread_id or "all"},
                            discriminating_criteria=f"Verify execution trace or call stack frame attributing write of {c_path} specifically to {cand_fn}.",
                            expected_outcomes={
                                f"{cand_fn}_executed_write": "SUPPORTED",
                                "other_function_executed_write": "CONTRADICTED",
                                "no_active_write_frame": "INCONCLUSIVE",
                            },
                            discriminating_power="HIGH",
                            required_capture_quality="COMPLETE",
                            safety_constraints=["Read-only trace and call stack inspection."],
                            status=OBSERVATION_STATUS_PROPOSED,
                            risk_level="READ_ONLY",
                            estimated_cost="LOW",
                            success_criteria=f"Independent evidence confirming {cand_fn} as writer of {c_path}",
                            failure_criteria=f"Independent evidence showing competing function or idle state",
                            is_suggestion=True,
                            executed=False,
                        )
                    ]
                    h_cand = InvestigationHypothesis(
                        hypothesis_id=comp_hypo_id,
                        investigation_id=inv_id,
                        title=f"Mutation of {c_path} Attributed to {cand_fn}",
                        claim=f"Function '{cand_fn}' is the causal writer that mutated {c_path} from {before_val} to {after_val}.",
                        proposed_mechanism=f"Thread execution in '{cand_fn}' wrote to offset of {field_name} during the observed transition.",
                        supporting_evidence_ids=supp_ev_ids,
                        contradicting_evidence_ids=[],
                        assumptions=[
                            f"Function '{cand_fn}' has access to memory containing {c_path}.",
                            f"Write instruction in '{cand_fn}' was executed within transition window.",
                        ],
                        unresolved_questions=[
                            f"Did '{cand_fn}' execute on any thread during the transition window?",
                            f"Was another competing function executing concurrently?",
                        ],
                        confidence=CONFIDENCE_MEDIUM if not (is_untrusted or is_partial or is_non_atomic) else CONFIDENCE_LOW,
                        confidence_rationale=f"Candidate function '{cand_fn}' correlated via DWARF; requires independent execution attribution to confirm causality.",
                        candidate_objects=[df.object_id] if df.object_id else [],
                        candidate_fields=[field_name],
                        source_locations=[cand.get("source_file")] if cand.get("source_file") else [],
                        function_candidates=[cand],
                        suggested_observations=comp_obs,
                        validation_criteria=[
                            f"Independent execution trace or stack frame proving '{cand_fn}' wrote to {c_path}.",
                            f"Absence of competing writers modifying {c_path} during the window.",
                        ],
                        validation_status=HYPOTHESIS_STATUS_PROPOSED,
                        parent_hypothesis_ids=[hypo_id],
                        parent_evidence_ids=supp_ev_ids,
                        classification=EVIDENCE_CLASSIFICATION_INFERENCE,
                        uncertainty=f"Attribution to '{cand_fn}' is a candidate hypothesis based on static debug symbols, not confirmed causality.",
                        discriminating_evidence_needed=[f"Verified runtime trace or single-writer isolation proving {cand_fn}"],
                        provenance={
                            "generator": "DeterministicHypothesisGenerator",
                            "rule": "COMPETING_CANDIDATE_ATTRIBUTION",
                            "target_function": cand_fn,
                            "field_path": c_path,
                        },
                    )
                    hypotheses.append(h_cand)

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
                        status=OBSERVATION_STATUS_PROPOSED,
                        risk_level="READ_ONLY",
                        estimated_cost="LOW",
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
                    classification=EVIDENCE_CLASSIFICATION_INFERENCE,
                    uncertainty=conf_rationale if conf in (CONFIDENCE_LOW, CONFIDENCE_SPECULATIVE) else None,
                    discriminating_evidence_needed=[f"Comparison against independent snapshot to prove or disprove invariance"],
                    provenance={
                        "generator": "DeterministicHypothesisGenerator",
                        "rule": "OBSERVED_VALUE_INVARIANT",
                        "observed_value": obs_val,
                    },
                )
                hypotheses.append(h)

        return hypotheses

    def generate_process_health_hypotheses(
        self,
        triage_data: Dict[str, Any],
        ledger: Optional[EvidenceLedger] = None,
        investigation_id: str = "inv_health",
        capture_quality: Optional[Dict[str, Any]] = None,
        provenance_class: str = PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    ) -> List[InvestigationHypothesis]:
        """Generates competing, structured hypotheses from low-impact process health triage evidence."""
        hypotheses: List[InvestigationHypothesis] = []
        cq = capture_quality or {}
        cq_status = cq.get("completeness") or cq.get("status") or "COMPLETE"
        is_partial_or_unverified = (cq_status != "COMPLETE") or (provenance_class not in TRUSTED_PROVENANCE_CLASSES)
        init_conf = CONFIDENCE_LOW if is_partial_or_unverified else CONFIDENCE_MEDIUM
        init_score = 0.35 if is_partial_or_unverified else 0.50

        def _valid_eids(raw_ids: List[str]) -> List[str]:
            if not ledger:
                return [eid for eid in raw_ids if eid]
            out = []
            for eid in raw_ids:
                if not eid:
                    continue
                rec = ledger.get_record(eid)
                if rec and rec.nature == NATURE_OBSERVATION and (rec.details or {}).get("collection_status", "COLLECTED") == "COLLECTED":
                    out.append(eid)
            return out

        # 1. Suspicious / Blocked Threads: Lock Contention/Stall vs Normal Idle Wait
        for th in triage_data.get("suspicious_threads", []):
            tid = th.get("tid", th.get("thread_id", "unknown"))
            th_name = th.get("name", f"thread_{tid}")
            top_fn = th.get("top_function", th.get("function", "blocking_call"))
            lock_ref = th.get("lock_address") or th.get("wait_target") or "sync_primitive"
            prog_expr = th.get("progress_expression") or th.get("target_expression")
            supp_ids = _valid_eids(th.get("evidence_ids", [th.get("evidence_id")] if th.get("evidence_id") else []))

            h_hash = hashlib.sha256(f"{investigation_id}:thread:{tid}:{top_fn}".encode("utf-8")).hexdigest()[:8]
            h1_id = f"hypo_thread_lock_{h_hash}"
            h2_id = f"hypo_thread_idle_{h_hash}"
            obs_id = f"obs_disc_thread_{h_hash}"

            disc_obs = FollowUpObservation(
                observation_id=obs_id,
                hypothesis_id=h1_id,
                tested_hypothesis_ids=[h1_id, h2_id],
                profile_id=th.get("follow_up_profile_id", "insp_frame_locals"),
                question=f"Is thread {tid} ({th_name}) stalled on an unreleasing lock owner or progressing/waiting normally?",
                why_needed=f"Discriminate between lock contention stall ({h1_id}) and normal idle wait ({h2_id}) for thread {tid}.",
                target_kind=TARGET_KIND_THREAD,
                target_ref={
                    "tid": tid,
                    "thread_name": th_name,
                    "lock_address": lock_ref,
                    "target_expression": prog_expr,
                },
                discriminating_criteria=(
                    f"Inspect lock ownership, owner thread progress, and stack frame locals for thread {tid}."
                ),
                expected_outcomes={
                    "stalled_owner_or_deadlock_confirmed": "SUPPORTED",
                    "uncontended_or_normal_progress": "CONTRADICTED",
                },
                expected_outcomes_by_hypothesis={
                    h1_id: {
                        "stalled_owner_or_deadlock_confirmed": "SUPPORTED",
                        "uncontended_or_normal_progress": "CONTRADICTED",
                    },
                    h2_id: {
                        "stalled_owner_or_deadlock_confirmed": "CONTRADICTED",
                        "uncontended_or_normal_progress": "SUPPORTED",
                    },
                },
                discriminating_power="HIGH",
                required_capture_quality="COMPLETE",
                safety_constraints=["Read-only zero-stop stack/lock inspection."],
                prerequisites=["threads_available"],
                risk_level="READ_ONLY",
                estimated_cost="LOW",
                estimated_bytes=2048,
                estimated_latency_ms=15.0,
                estimated_samples=1,
                estimated_stop_ms=0.0,
            )

            h1 = InvestigationHypothesis(
                hypothesis_id=h1_id,
                investigation_id=investigation_id,
                title=f"Thread {tid} ({th_name}) Blocked on Contended Lock or Stalled Owner",
                claim=f"Thread {tid} ({th_name}) is stalled due to lock contention, deadlock, or an unreleasing owner.",
                proposed_mechanism=f"Thread {tid} is blocked in '{top_fn}' waiting on '{lock_ref}' held by a non-progressing owner.",
                supporting_evidence_ids=list(supp_ids),
                contradicting_evidence_ids=[],
                assumptions=[
                    "Synchronization primitive is expected to be released within normal execution bounds.",
                    "Thread is not intentionally idle awaiting external input.",
                ],
                unresolved_questions=[
                    f"Which thread holds '{lock_ref}' and is that owner making forward progress?",
                    f"Do frame locals or progress counters for thread {tid} remain frozen?",
                ],
                confidence=init_conf,
                confidence_score=init_score,
                confidence_rationale=f"Initial triage observed thread {tid} persistent in '{top_fn}'; follow-up needed to distinguish contention from idle wait.",
                candidate_objects=[str(lock_ref)] if lock_ref else [],
                candidate_fields=[prog_expr] if prog_expr else [],
                target_threads=[tid],
                suggested_observations=[disc_obs],
                validation_criteria=[
                    "Follow-up observation confirms circular lock wait, stalled lock owner, or zero progress across samples."
                ],
                validation_status=HYPOTHESIS_STATUS_PROPOSED,
                discriminating_evidence_needed=[
                    f"Lock owner state and frame local / progress check for thread {tid}"
                ],
                target_kind=TARGET_KIND_THREAD,
                target_identifier=str(tid),
                competing_hypothesis_ids=[h2_id],
                anomaly_category="THREAD_PROGRESS",
                provenance={
                    "generator": "DeterministicHypothesisGenerator",
                    "anomaly_category": "THREAD_PROGRESS",
                    "is_benign_explanation": False,
                    "provenance_class": provenance_class,
                },
            )

            h2 = InvestigationHypothesis(
                hypothesis_id=h2_id,
                investigation_id=investigation_id,
                title=f"Thread {tid} ({th_name}) Waiting Normally in Idle / Condition Wait",
                claim=f"Thread {tid} ({th_name}) is parked in a normal idle/work-wait state with no synchronization defect.",
                proposed_mechanism=f"Thread {tid} is parked in '{top_fn}' awaiting work items or timer wakeup as designed.",
                supporting_evidence_ids=list(supp_ids),
                contradicting_evidence_ids=[],
                assumptions=["Worker threads block on condition variables or futexes when work queues are empty."],
                unresolved_questions=[f"Is '{lock_ref}' uncontended and does thread {tid} advance when work is present?"],
                confidence=init_conf,
                confidence_score=init_score,
                confidence_rationale=f"Blocking in '{top_fn}' is consistent with normal idle wait if no contended owner or stalled queue exists.",
                candidate_objects=[str(lock_ref)] if lock_ref else [],
                candidate_fields=[prog_expr] if prog_expr else [],
                target_threads=[tid],
                suggested_observations=[FollowUpObservation.from_dict(disc_obs.to_dict())],
                validation_criteria=[
                    "Follow-up observation shows no contended/stalled lock owner and normal thread/queue state."
                ],
                validation_status=HYPOTHESIS_STATUS_PROPOSED,
                discriminating_evidence_needed=[
                    f"Verification that '{lock_ref}' has no stalled owner and queue/progress state is healthy"
                ],
                target_kind=TARGET_KIND_THREAD,
                target_identifier=str(tid),
                competing_hypothesis_ids=[h1_id],
                anomaly_category="THREAD_PROGRESS",
                provenance={
                    "generator": "DeterministicHypothesisGenerator",
                    "anomaly_category": "THREAD_PROGRESS",
                    "is_benign_explanation": True,
                    "provenance_class": provenance_class,
                },
            )
            hypotheses.extend([h1, h2])

        # 2. Memory / Pool / Heap Growth Candidates: Leak vs Expected Workload Growth
        for mc in triage_data.get("memory_growth_candidates", []):
            target_expr = mc.get("target_expression") or mc.get("symbol") or "heap_or_pool"
            region = mc.get("region", "[heap]")
            supp_ids = _valid_eids(mc.get("evidence_ids", [mc.get("evidence_id")] if mc.get("evidence_id") else []))

            m_hash = hashlib.sha256(f"{investigation_id}:mem:{target_expr}".encode("utf-8")).hexdigest()[:8]
            h1_id = f"hypo_mem_leak_{m_hash}"
            h2_id = f"hypo_mem_workload_{m_hash}"
            obs_temp_id = f"obs_disc_mem_temporal_{m_hash}"
            obs_own_id = f"obs_disc_mem_owners_{m_hash}"

            obs_temporal = FollowUpObservation(
                observation_id=obs_temp_id,
                hypothesis_id=h1_id,
                tested_hypothesis_ids=[h1_id, h2_id],
                profile_id=mc.get("follow_up_profile_id", "insp_temporal_diff"),
                question=f"Does allocation in '{target_expr}' grow monotonically without reclamation across temporal samples?",
                why_needed=f"A single snapshot cannot confirm a memory leak; temporal sampling is required to distinguish leak ({h1_id}) from workload buffering ({h2_id}).",
                target_kind=TARGET_KIND_COMPARISON,
                target_ref={"target_expression": target_expr, "region": region},
                discriminating_criteria=f"Compare allocation metrics for '{target_expr}' across consecutive runtime epochs.",
                expected_outcomes={
                    "monotonic_unreleased_growth_with_orphans": "SUPPORTED",
                    "stable_or_reclaimed_allocation": "CONTRADICTED",
                },
                expected_outcomes_by_hypothesis={
                    h1_id: {
                        "monotonic_unreleased_growth_with_orphans": "SUPPORTED",
                        "stable_or_reclaimed_allocation": "CONTRADICTED",
                    },
                    h2_id: {
                        "monotonic_unreleased_growth_with_orphans": "CONTRADICTED",
                        "stable_or_reclaimed_allocation": "SUPPORTED",
                    },
                },
                discriminating_power="HIGH",
                required_capture_quality="COMPLETE",
                safety_constraints=["Read-only multi-sample delta."],
                prerequisites=["memory_read_available"],
                risk_level="READ_ONLY",
                estimated_cost="LOW",
                estimated_bytes=1024,
                estimated_latency_ms=20.0,
                estimated_samples=1,
                estimated_stop_ms=0.0,
            )

            obs_owners = FollowUpObservation(
                observation_id=obs_own_id,
                hypothesis_id=h1_id,
                tested_hypothesis_ids=[h1_id, h2_id],
                profile_id="insp_find_owners",
                question=f"Are allocated slots/buffers in '{target_expr}' orphaned without active owning threads?",
                why_needed=f"Determine whether allocated items in '{target_expr}' are actively referenced by worker threads or leaked.",
                target_kind=TARGET_KIND_OBJECT,
                target_ref={"target_expression": target_expr, "region": region},
                discriminating_criteria=f"Scan thread stacks and roots for active ownership references to '{target_expr}'.",
                expected_outcomes={
                    "orphaned_slots_found": "SUPPORTED",
                    "all_slots_owned_by_active_threads": "CONTRADICTED",
                },
                expected_outcomes_by_hypothesis={
                    h1_id: {
                        "orphaned_slots_found": "SUPPORTED",
                        "all_slots_owned_by_active_threads": "CONTRADICTED",
                    },
                    h2_id: {
                        "orphaned_slots_found": "CONTRADICTED",
                        "all_slots_owned_by_active_threads": "SUPPORTED",
                    },
                },
                discriminating_power="HIGH",
                required_capture_quality="COMPLETE",
                safety_constraints=["Read-only symbol owner scan."],
                prerequisites=["memory_read_available", "dwarf_symbols_available"],
                risk_level="READ_ONLY",
                estimated_cost="MEDIUM",
                estimated_bytes=4096,
                estimated_latency_ms=30.0,
                estimated_samples=1,
                estimated_stop_ms=0.0,
            )

            h1 = InvestigationHypothesis(
                hypothesis_id=h1_id,
                investigation_id=investigation_id,
                title=f"Memory or Slot Leak in '{target_expr}'",
                claim=f"Allocation growth/occupancy in '{target_expr}' is caused by unreleased or orphaned allocations.",
                proposed_mechanism=f"Buffers or objects in '{target_expr}' remain allocated after task completion without active owner references.",
                supporting_evidence_ids=list(supp_ids),
                contradicting_evidence_ids=[],
                assumptions=[
                    "Allocated items should be freed or recycled when no active thread references them.",
                    "A single snapshot is insufficient to confirm a leak without temporal or ownership evidence.",
                ],
                unresolved_questions=[
                    f"Does '{target_expr}' continue growing across subsequent temporal samples?",
                    f"Are allocated slots in '{target_expr}' orphaned without owning threads?",
                ],
                confidence=CONFIDENCE_LOW,
                confidence_score=0.35,
                confidence_rationale="Single initial observation shows elevated occupancy; temporal delta and owner verification required before confirming leak.",
                candidate_objects=[target_expr],
                candidate_fields=[target_expr],
                target_regions=[region],
                suggested_observations=[obs_temporal, obs_owners],
                validation_criteria=[
                    "Multi-sample temporal evidence confirms monotonic growth AND owner scan confirms orphaned allocations."
                ],
                validation_status=HYPOTHESIS_STATUS_PROPOSED,
                discriminating_evidence_needed=[
                    f"Multi-sample temporal allocation delta for '{target_expr}'",
                    f"Active thread ownership verification for '{target_expr}'",
                ],
                target_kind=TARGET_KIND_OBJECT,
                target_identifier=target_expr,
                competing_hypothesis_ids=[h2_id],
                anomaly_category="MEMORY_GROWTH",
                provenance={
                    "generator": "DeterministicHypothesisGenerator",
                    "anomaly_category": "MEMORY_GROWTH",
                    "is_benign_explanation": False,
                    "provenance_class": provenance_class,
                },
            )

            h2 = InvestigationHypothesis(
                hypothesis_id=h2_id,
                investigation_id=investigation_id,
                title=f"Expected Workload Growth or Active Caching in '{target_expr}'",
                claim=f"Allocation occupancy in '{target_expr}' reflects normal active workload buffering or steady-state caching.",
                proposed_mechanism=f"Worker threads actively hold and recycle buffers in '{target_expr}' proportional to current load.",
                supporting_evidence_ids=list(supp_ids),
                contradicting_evidence_ids=[],
                assumptions=["High watermarks or pool caches remain populated during normal bursty workloads."],
                unresolved_questions=[f"Do active threads own the slots in '{target_expr}' and does usage stabilize over time?"],
                confidence=init_conf,
                confidence_score=init_score,
                confidence_rationale="Elevated allocation in a single sample is consistent with normal workload buffering.",
                candidate_objects=[target_expr],
                candidate_fields=[target_expr],
                target_regions=[region],
                suggested_observations=[
                    FollowUpObservation.from_dict(obs_temporal.to_dict()),
                    FollowUpObservation.from_dict(obs_owners.to_dict()),
                ],
                validation_criteria=[
                    "Follow-up temporal sample shows bounded/reclaimed usage or active thread ownership of allocated slots."
                ],
                validation_status=HYPOTHESIS_STATUS_PROPOSED,
                discriminating_evidence_needed=[
                    f"Temporal stability check and owner verification for '{target_expr}'"
                ],
                target_kind=TARGET_KIND_OBJECT,
                target_identifier=target_expr,
                competing_hypothesis_ids=[h1_id],
                anomaly_category="MEMORY_GROWTH",
                provenance={
                    "generator": "DeterministicHypothesisGenerator",
                    "anomaly_category": "MEMORY_GROWTH",
                    "is_benign_explanation": True,
                    "provenance_class": provenance_class,
                },
            )
            hypotheses.extend([h1, h2])

        # 3. Invalid Pointer / Integrity Candidates: Stale Lifetime vs Concurrent Read Skew / Unreadable Memory
        for pc in triage_data.get("pointer_anomalies", []):
            field_path = pc.get("field_path") or pc.get("target_expression") or "pointer_field"
            supp_ids = _valid_eids(pc.get("evidence_ids", [pc.get("evidence_id")] if pc.get("evidence_id") else []))

            p_hash = hashlib.sha256(f"{investigation_id}:ptr:{field_path}".encode("utf-8")).hexdigest()[:8]
            h1_id = f"hypo_ptr_stale_{p_hash}"
            h2_id = f"hypo_ptr_skew_{p_hash}"
            obs_id = f"obs_disc_ptr_{p_hash}"

            obs_ptr = FollowUpObservation(
                observation_id=obs_id,
                hypothesis_id=h1_id,
                tested_hypothesis_ids=[h1_id, h2_id],
                profile_id=pc.get("follow_up_profile_id", "insp_consistency"),
                question=f"Does '{field_path}' remain an invalid/corrupted pointer under verified consistent double-read?",
                why_needed=f"Distinguish persistent stale/corrupt pointer lifetime ({h1_id}) from concurrent unstopped read skew or unreadable memory ({h2_id}).",
                target_kind=TARGET_KIND_FIELD,
                target_ref={"field_path": field_path, "root_expression": field_path},
                discriminating_criteria=f"Perform Seqlock double-read consistency and memory map validity check on '{field_path}'.",
                expected_outcomes={
                    "consistent_invalid_pointer_confirmed": "SUPPORTED",
                    "transient_read_skew_or_uninitialized": "CONTRADICTED",
                },
                expected_outcomes_by_hypothesis={
                    h1_id: {
                        "consistent_invalid_pointer_confirmed": "SUPPORTED",
                        "transient_read_skew_or_uninitialized": "CONTRADICTED",
                    },
                    h2_id: {
                        "consistent_invalid_pointer_confirmed": "CONTRADICTED",
                        "transient_read_skew_or_uninitialized": "SUPPORTED",
                    },
                },
                discriminating_power="HIGH",
                required_capture_quality="COMPLETE",
                safety_constraints=["Read-only Seqlock double-read verification."],
                prerequisites=["memory_read_available"],
                risk_level="READ_ONLY",
                estimated_cost="LOW",
                estimated_bytes=512,
                estimated_latency_ms=10.0,
                estimated_samples=1,
                estimated_stop_ms=0.0,
            )

            h1 = InvestigationHypothesis(
                hypothesis_id=h1_id,
                investigation_id=investigation_id,
                title=f"Stale Lifetime or Corrupted Pointer in '{field_path}'",
                claim=f"Pointer/field '{field_path}' references an invalid or corrupted address due to stale object lifetime or overwrite.",
                proposed_mechanism=f"Object referenced by '{field_path}' was freed/invalidated or overwritten while still reachable.",
                supporting_evidence_ids=list(supp_ids),
                contradicting_evidence_ids=[],
                assumptions=["Structure containing the pointer has completed initialization."],
                unresolved_questions=[f"Is the invalid value in '{field_path}' stable across a consistent double-read?"],
                confidence=init_conf,
                confidence_score=init_score,
                confidence_rationale=f"Initial read of '{field_path}' showed anomalous pointer state; consistency verification required.",
                candidate_fields=[field_path],
                suggested_observations=[obs_ptr],
                validation_criteria=["Consistent double-read confirms persistent invalid pointer in initialized structure."],
                validation_status=HYPOTHESIS_STATUS_PROPOSED,
                discriminating_evidence_needed=[f"Consistent double-read verification of '{field_path}'"],
                target_kind=TARGET_KIND_FIELD,
                target_identifier=field_path,
                competing_hypothesis_ids=[h2_id],
                anomaly_category="POINTER_INTEGRITY",
                provenance={
                    "generator": "DeterministicHypothesisGenerator",
                    "anomaly_category": "POINTER_INTEGRITY",
                    "is_benign_explanation": False,
                    "provenance_class": provenance_class,
                },
            )

            h2 = InvestigationHypothesis(
                hypothesis_id=h2_id,
                investigation_id=investigation_id,
                title=f"Concurrent Read Skew or Incomplete/Uninitialized State in '{field_path}'",
                claim=f"Apparent anomaly in '{field_path}' is caused by concurrent unstopped read skew or benign uninitialized/unmapped state.",
                proposed_mechanism=f"Zero-stop read observed '{field_path}' mid-update or before lazy initialization.",
                supporting_evidence_ids=list(supp_ids),
                contradicting_evidence_ids=[],
                assumptions=["Unstopped reads can observe transient torn pointer values during concurrent updates."],
                unresolved_questions=[f"Does a repeated double-read of '{field_path}' stabilize to a valid address?"],
                confidence=init_conf,
                confidence_score=init_score,
                confidence_rationale="Unstopped single read cannot rule out transient mutation skew without double-read verification.",
                candidate_fields=[field_path],
                suggested_observations=[FollowUpObservation.from_dict(obs_ptr.to_dict())],
                validation_criteria=["Follow-up double-read detects concurrent write skew or valid stabilized pointer."],
                validation_status=HYPOTHESIS_STATUS_PROPOSED,
                discriminating_evidence_needed=[f"Seqlock double-read consistency check on '{field_path}'"],
                target_kind=TARGET_KIND_FIELD,
                target_identifier=field_path,
                competing_hypothesis_ids=[h1_id],
                anomaly_category="POINTER_INTEGRITY",
                provenance={
                    "generator": "DeterministicHypothesisGenerator",
                    "anomaly_category": "POINTER_INTEGRITY",
                    "is_benign_explanation": True,
                    "provenance_class": provenance_class,
                },
            )
            hypotheses.extend([h1, h2])

        # 4. Queue / IPC Backlog Candidates: Consumer Stall vs Transient Burst
        for qc in triage_data.get("queue_backlogs", []):
            q_expr = qc.get("pipeline_expression") or qc.get("target_expression") or "work_queue"
            supp_ids = _valid_eids(qc.get("evidence_ids", [qc.get("evidence_id")] if qc.get("evidence_id") else []))

            q_hash = hashlib.sha256(f"{investigation_id}:queue:{q_expr}".encode("utf-8")).hexdigest()[:8]
            h1_id = f"hypo_queue_stall_{q_hash}"
            h2_id = f"hypo_queue_burst_{q_hash}"
            obs_id = f"obs_disc_queue_{q_hash}"

            obs_q = FollowUpObservation(
                observation_id=obs_id,
                hypothesis_id=h1_id,
                tested_hypothesis_ids=[h1_id, h2_id],
                profile_id=qc.get("follow_up_profile_id", "insp_ipc"),
                question=f"Is the consumer of '{q_expr}' stalled with zero read-index progress, or actively draining a transient burst?",
                why_needed=f"Discriminate between consumer stall ({h1_id}) and transient workload burst ({h2_id}) on '{q_expr}'.",
                target_kind=TARGET_KIND_COMPARISON,
                target_ref={"pipeline_expression": q_expr, "target_expression": q_expr},
                discriminating_criteria=f"Check consumer read index / processed count advancement on '{q_expr}'.",
                expected_outcomes={
                    "consumer_progress_zero_while_backlogged": "SUPPORTED",
                    "consumer_actively_draining": "CONTRADICTED",
                },
                expected_outcomes_by_hypothesis={
                    h1_id: {
                        "consumer_progress_zero_while_backlogged": "SUPPORTED",
                        "consumer_actively_draining": "CONTRADICTED",
                    },
                    h2_id: {
                        "consumer_progress_zero_while_backlogged": "CONTRADICTED",
                        "consumer_actively_draining": "SUPPORTED",
                    },
                },
                discriminating_power="HIGH",
                required_capture_quality="COMPLETE",
                safety_constraints=["Read-only queue state inspection."],
                prerequisites=["memory_read_available"],
                risk_level="READ_ONLY",
                estimated_cost="LOW",
                estimated_bytes=1024,
                estimated_latency_ms=15.0,
                estimated_samples=1,
                estimated_stop_ms=0.0,
            )

            h1 = InvestigationHypothesis(
                hypothesis_id=h1_id,
                investigation_id=investigation_id,
                title=f"Queue Backlog in '{q_expr}' Caused by Consumer Stall",
                claim=f"Pending backlog in '{q_expr}' is caused by a stalled or blocked consumer failing to drain items.",
                proposed_mechanism=f"Producer continues enqueuing into '{q_expr}' while consumer read index remains stationary.",
                supporting_evidence_ids=list(supp_ids),
                contradicting_evidence_ids=[],
                assumptions=["Consumer thread/process is expected to continuously dequeue pending items."],
                unresolved_questions=[f"Does the consumer read index on '{q_expr}' advance on a follow-up sample?"],
                confidence=init_conf,
                confidence_score=init_score,
                confidence_rationale=f"Backlog observed in '{q_expr}'; follow-up needed to verify whether consumer is progressing.",
                candidate_objects=[q_expr],
                candidate_fields=[q_expr],
                suggested_observations=[obs_q],
                validation_criteria=["Follow-up observation confirms zero consumer progress while backlog persists."],
                validation_status=HYPOTHESIS_STATUS_PROPOSED,
                discriminating_evidence_needed=[f"Temporal consumer progress delta on '{q_expr}'"],
                target_kind=TARGET_KIND_OBJECT,
                target_identifier=q_expr,
                competing_hypothesis_ids=[h2_id],
                anomaly_category="QUEUE_BACKLOG",
                provenance={
                    "generator": "DeterministicHypothesisGenerator",
                    "anomaly_category": "QUEUE_BACKLOG",
                    "is_benign_explanation": False,
                    "provenance_class": provenance_class,
                },
            )

            h2 = InvestigationHypothesis(
                hypothesis_id=h2_id,
                investigation_id=investigation_id,
                title=f"Queue Backlog in '{q_expr}' Caused by Temporary Workload Burst",
                claim=f"Pending items in '{q_expr}' reflect a temporary ingress burst that the consumer is actively draining.",
                proposed_mechanism=f"Short-term arrival rate exceeded drain rate, but consumer continues advancing its read index.",
                supporting_evidence_ids=list(supp_ids),
                contradicting_evidence_ids=[],
                assumptions=["Transient queue spikes occur normally under bursty traffic."],
                unresolved_questions=[f"Is the consumer actively advancing its read counter on '{q_expr}'?"],
                confidence=init_conf,
                confidence_score=init_score,
                confidence_rationale=f"Single-sample queue depth in '{q_expr}' is consistent with a transient burst if consumer advances.",
                candidate_objects=[q_expr],
                candidate_fields=[q_expr],
                suggested_observations=[FollowUpObservation.from_dict(obs_q.to_dict())],
                validation_criteria=["Follow-up observation confirms consumer read counter advancing."],
                validation_status=HYPOTHESIS_STATUS_PROPOSED,
                discriminating_evidence_needed=[f"Consumer progress counter advancement on '{q_expr}'"],
                target_kind=TARGET_KIND_OBJECT,
                target_identifier=q_expr,
                competing_hypothesis_ids=[h1_id],
                anomaly_category="QUEUE_BACKLOG",
                provenance={
                    "generator": "DeterministicHypothesisGenerator",
                    "anomaly_category": "QUEUE_BACKLOG",
                    "is_benign_explanation": True,
                    "provenance_class": provenance_class,
                },
            )
            hypotheses.extend([h1, h2])

        return hypotheses


# -----------------------------------------------------------------------------
# Pluggable LLM & External Hypothesis Sanitization
# -----------------------------------------------------------------------------

def sanitize_and_disarm_llm_hypothesis(
    raw_data: Dict[str, Any],
    ledger: Optional[EvidenceLedger] = None,
) -> InvestigationHypothesis:
    """Sanitize and disarm an externally supplied or LLM-generated hypothesis.

    Security & Evidence Trust Contract:
    1. Caller/LLM cannot claim trusted validation: validation_status is forced to PROPOSED.
    2. Fabricated evidence IDs: any ID not existing in the ledger is stripped.
    3. Untrusted function candidates: cannot claim VALIDATED_CAUSAL_FUNCTION or confirmed_root_cause=True;
       downgraded to STATIC_CANDIDATE with explicit tier_limitation.
    4. Execution traces, verifier attestation, and capability tokens in details/provenance are stripped.
    5. Unknowns and uncertainties are explicitly recorded rather than fabricated.
    6. Classification is forced to INFERENCE.
    """
    data = dict(raw_data)
    inv_id = data.get("investigation_id", "")
    hypo_id = data.get("hypothesis_id") or f"hypo_ext_{uuid.uuid4().hex[:8]}"

    # 1. Filter supporting evidence IDs against actual ledger
    raw_supp_ids = list(data.get("supporting_evidence_ids", []))
    verified_supp_ids: List[str] = []
    fabricated_ids: List[str] = []
    if ledger:
        for eid in raw_supp_ids:
            if ledger.get_record(eid):
                verified_supp_ids.append(eid)
            else:
                fabricated_ids.append(eid)
    else:
        fabricated_ids = list(raw_supp_ids)
        verified_supp_ids = []

    # 2. Filter contradicting evidence IDs
    raw_contra_ids = list(data.get("contradicting_evidence_ids", []))
    verified_contra_ids: List[str] = []
    if ledger:
        for eid in raw_contra_ids:
            if ledger.get_record(eid):
                verified_contra_ids.append(eid)
    else:
        verified_contra_ids = []

    # 3. Disarm validation status & confidence
    val_status = HYPOTHESIS_STATUS_PROPOSED
    conf = data.get("confidence", CONFIDENCE_SPECULATIVE)
    if conf not in VALID_CONFIDENCE_LEVELS or conf == CONFIDENCE_HIGH:
        conf = CONFIDENCE_MEDIUM if verified_supp_ids else CONFIDENCE_SPECULATIVE

    conf_rationale = data.get("confidence_rationale", "")
    uncertainty_notes: List[str] = []
    if fabricated_ids:
        uncertainty_notes.append(f"Stripped {len(fabricated_ids)} ungrounded/fabricated evidence ID(s): {fabricated_ids}")
        conf = CONFIDENCE_SPECULATIVE
    if not verified_supp_ids:
        val_status = HYPOTHESIS_STATUS_PROPOSED
        uncertainty_notes.append("No verified ledger evidence supports this hypothesis; treated as unverified model inference.")

    # 4. Disarm function candidates
    raw_candidates = data.get("function_candidates", [])
    disarmed_candidates: List[Dict[str, Any]] = []
    for cand in raw_candidates:
        c_copy = dict(cand)
        current_tier = c_copy.get("candidate_tier")
        if current_tier == FUNCTION_TIER_UNVERIFIED:
            c_copy["candidate_tier"] = FUNCTION_TIER_UNVERIFIED
            c_copy["confirmed_root_cause"] = False
            c_copy["tier_limitation"] = "Companion ELF debug symbols unavailable or unverified; candidate cannot be validated as causal."
        else:
            c_copy["candidate_tier"] = FUNCTION_TIER_STATIC_CANDIDATE
            c_copy["confirmed_root_cause"] = False
            c_copy["tier_limitation"] = "Model/caller proposed candidate; unproven write causality without verified attestation."
        c_copy.pop("verifier_attestation", None)
        c_copy.pop("execution_provenance", None)
        c_copy.pop("function_attribution_verified", None)
        disarmed_candidates.append(c_copy)

    # 5. Sanitize suggested observations
    raw_obs = data.get("suggested_observations", [])
    clean_obs: List[FollowUpObservation] = []
    for o in raw_obs:
        if isinstance(o, dict):
            o_copy = dict(o)
            o_copy["executed"] = False
            o_copy["status"] = OBSERVATION_STATUS_PROPOSED
            o_copy["result_evidence_id"] = None
            o_copy.pop("verifier_attestation", None)
            clean_obs.append(FollowUpObservation.from_dict(o_copy))
        elif isinstance(o, FollowUpObservation):
            o.executed = False
            o.status = OBSERVATION_STATUS_PROPOSED
            o.result_evidence_id = None
            clean_obs.append(o)

    # 6. Sanitize provenance
    prov = dict(data.get("provenance", {}))
    prov.pop("verifier_attestation", None)
    prov.pop("token", None)
    prov.pop("token_sig", None)
    prov.pop("session_secret", None)
    prov.pop("capability_key", None)
    prov["generator"] = "sanitize_and_disarm_llm_hypothesis"
    prov["trusted"] = False
    prov["requires_verification"] = True
    if fabricated_ids:
        prov["fabricated_evidence_ids_stripped"] = fabricated_ids

    combined_uncertainty = "; ".join(uncertainty_notes) if uncertainty_notes else data.get("uncertainty")

    return InvestigationHypothesis(
        hypothesis_id=hypo_id,
        investigation_id=inv_id,
        title=data.get("title", f"Hypothesis on {data.get('candidate_fields', ['defect'])[0] if data.get('candidate_fields') else 'defect'}"),
        claim=data.get("claim", ""),
        proposed_mechanism=data.get("proposed_mechanism", ""),
        supporting_evidence_ids=verified_supp_ids,
        contradicting_evidence_ids=verified_contra_ids,
        assumptions=list(data.get("assumptions", [])),
        unresolved_questions=list(data.get("unresolved_questions", [])),
        confidence=conf,
        confidence_rationale=conf_rationale or ("Inferred from external/LLM model input." if not verified_supp_ids else "Grounded in ledger evidence."),
        candidate_objects=list(data.get("candidate_objects", [])),
        candidate_fields=list(data.get("candidate_fields", [])),
        source_locations=list(data.get("source_locations", [])),
        function_candidates=disarmed_candidates,
        suggested_observations=clean_obs,
        validation_criteria=list(data.get("validation_criteria", [])),
        validation_status=val_status,
        classification=EVIDENCE_CLASSIFICATION_INFERENCE,
        uncertainty=combined_uncertainty,
        discriminating_evidence_needed=list(data.get("discriminating_evidence_needed", [])),
        provenance=prov,
    )


class OptionalLLMHypothesisAdapter(HypothesisGenerator):
    """Optional pluggable LLM adapter that safely generates hypotheses while strictly disarming unverified claims."""

    def __init__(self, provider_fn: Optional[Any] = None, model_name: str = "llm-optional"):
        self.provider_fn = provider_fn
        self.model_name = model_name
        self.enabled = provider_fn is not None

    def is_available(self) -> bool:
        return self.enabled and self.provider_fn is not None

    def generate(self, session: Any) -> List[InvestigationHypothesis]:
        if not self.is_available():
            return []
        ledger = getattr(session, "ledger", None)
        try:
            raw_items = self.provider_fn(session)
        except Exception:
            return []
        if not isinstance(raw_items, list):
            raw_items = [raw_items] if raw_items else []
        hypotheses = []
        for item in raw_items:
            if isinstance(item, dict):
                hypo = sanitize_and_disarm_llm_hypothesis(item, ledger=ledger)
                hypotheses.append(hypo)
            elif isinstance(item, InvestigationHypothesis):
                hypo = sanitize_and_disarm_llm_hypothesis(item.to_dict(), ledger=ledger)
                hypotheses.append(hypo)
        return hypotheses


class PluggableHypothesisEngine:
    """Orchestrates deterministic and optional secondary hypothesis generators with strict boundary checks."""

    def __init__(
        self,
        primary_generator: Optional[HypothesisGenerator] = None,
        optional_adapter: Optional[HypothesisGenerator] = None,
    ):
        self.primary_generator = primary_generator or DeterministicHypothesisGenerator()
        self.optional_adapter = optional_adapter

    def generate(self, session: Any) -> List[InvestigationHypothesis]:
        results = list(self.primary_generator.generate(session))
        if self.optional_adapter and getattr(self.optional_adapter, "is_available", lambda: True)():
            try:
                sec_results = self.optional_adapter.generate(session)
                results.extend(sec_results)
            except Exception:
                pass
        return results


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
        rec_sem = (record.details or {}).get("semantic_digest") if record.details else None
        for ex in existing_records:
            if ex.evidence_id == record.evidence_id:
                return True
            ex_sem = (ex.details or {}).get("semantic_digest") if ex.details else None
            if rec_sem and ex_sem and rec_sem == ex_sem:
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
        if att_tid and proof_rec.target_identity:
            mismatch = False
            for k in ("pid", "build_id", "binary", "binary_path"):
                v1 = att_tid.get(k)
                v2 = proof_rec.target_identity.get(k)
                if v1 is not None and v2 is not None and str(v1) != str(v2):
                    mismatch = True
                    break
            if mismatch:
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
        capture_quality: Optional[Dict[str, Any]] = None,
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
        if not hypothesis.investigation_id and ledger and getattr(ledger, "session_id", None):
            hypothesis.investigation_id = ledger.session_id

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

        if capture_quality:
            cq_level = capture_quality.get("consistency_level") or capture_quality.get("consistency_classification")
            cq_comp = capture_quality.get("completeness") or capture_quality.get("status")
            if cq_level == "NON_ATOMIC":
                has_non_atomic_evidence = True
            if cq_comp == "PARTIAL":
                has_partial_evidence = True
            if cq_comp in ("FAILED", "INVALID", "UNTRUSTED"):
                has_untrusted_evidence = True

        # Rule: A hypothesis is not evidence for itself, and failed/abstained observations cannot support or refute
        def _is_valid_observational_evidence(rec: Optional[EvidenceRecord], allow_missing_in_ledger: bool = True) -> bool:
            if rec is None:
                return allow_missing_in_ledger
            if rec.nature in (NATURE_HYPOTHESIS, NATURE_INFERENCE) or rec.evidence_id == f"ev_{hypothesis.hypothesis_id}":
                return False
            if rec.evidence_id == f"ev_{hypothesis.hypothesis_id}" or (rec.details or {}).get("hypothesis_id") == hypothesis.hypothesis_id and rec.evidence_type == EVIDENCE_TYPE_HYPOTHESIS:
                return False
            d = rec.details or {}
            if d.get("collection_status") in ("FAILED", "ABSTAIN"):
                return False
            if d.get("result_category") in ("OBSERVATION_FAILED", "OBSERVATION_UNAVAILABLE", "BUDGET_REJECTED", "NO_NEW_EVIDENCE"):
                return False
            fo = rec.field_observation or {}
            if fo.get("evaluation_status") in ("READ_ERROR", "TIMEOUT", "RESTRICTED", "UNKNOWN", "SYMBOL_NOT_FOUND"):
                return False
            return True

        # Prune any self-hypothesis or failed/abstained records from existing lists
        hypothesis.supporting_evidence_ids = [
            eid for eid in hypothesis.supporting_evidence_ids
            if _is_valid_observational_evidence(ledger.get_record(eid))
        ]
        hypothesis.contradicting_evidence_ids = [
            eid for eid in hypothesis.contradicting_evidence_ids
            if _is_valid_observational_evidence(ledger.get_record(eid))
        ]

        # Process newly attached evidence
        new_is_duplicate = False
        trigger_eid = None
        is_inconclusive = False
        if new_evidence:
            trigger_eid = new_evidence.evidence_id
            existing_ids = list(dict.fromkeys(hypothesis.supporting_evidence_ids + hypothesis.contradicting_evidence_ids))
            existing = [ledger.get_record(e) for e in existing_ids if ledger.get_record(e)]
            if cls.is_duplicate_evidence(ledger, new_evidence, existing):
                new_is_duplicate = True

            if not _is_valid_observational_evidence(new_evidence, allow_missing_in_ledger=False):
                is_inconclusive = True
            elif not new_is_duplicate and not cycle_found and not prov_error:
                is_contradiction = False
                details = new_evidence.details or {}
                obs_text = new_evidence.observation.lower()

                outcomes_by_hypo = details.get("outcomes_by_hypothesis") or {}
                specific_outcome = outcomes_by_hypo.get(hypothesis.hypothesis_id) or details.get("outcome")

                if (
                    specific_outcome == "CONTRADICTED"
                    or details.get("contradicts_hypothesis_id") == hypothesis.hypothesis_id
                    or (not outcomes_by_hypo and ("contradict" in obs_text or "mismatch" in obs_text))
                ):
                    is_contradiction = True

                # Competing function contradiction:
                hypo_fn = (hypothesis.provenance or {}).get("target_function")
                obs_fn = details.get("target_function") or details.get("writer_function")
                if hypo_fn and obs_fn and hypo_fn != obs_fn and specific_outcome in ("SUPPORTED", "VALIDATED"):
                    is_contradiction = True

                is_inconclusive = (
                    specific_outcome in ("INCONCLUSIVE", "UNKNOWN", "ABSTAIN")
                    or (not specific_outcome and ("inconclusive" in obs_text or "insufficient" in obs_text))
                )

                if is_contradiction:
                    if new_evidence.evidence_id not in hypothesis.contradicting_evidence_ids:
                        hypothesis.contradicting_evidence_ids.append(new_evidence.evidence_id)
                    for pid in getattr(new_evidence, "parent_evidence_ids", []):
                        if pid and pid not in hypothesis.contradicting_evidence_ids and _is_valid_observational_evidence(ledger.get_record(pid)):
                            hypothesis.contradicting_evidence_ids.append(pid)
                elif is_inconclusive:
                    pass
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

        # Deduplicate evidence ID lists and collapse correlated copies by semantic_digest / observation_id
        def _dedup_independent_ids(eids: List[str]) -> List[str]:
            unique_ids: List[str] = []
            seen_keys: set = set()
            for eid in eids:
                if eid in unique_ids:
                    continue
                rec = ledger.get_record(eid)
                if not rec:
                    unique_ids.append(eid)
                    continue
                d = rec.details or {}
                sem_key = d.get("semantic_digest") or d.get("observation_id") or (rec.source, rec.observation)
                if sem_key in seen_keys:
                    continue
                seen_keys.add(sem_key)
                unique_ids.append(eid)
            return unique_ids

        hypothesis.supporting_evidence_ids = _dedup_independent_ids(hypothesis.supporting_evidence_ids)
        hypothesis.contradicting_evidence_ids = _dedup_independent_ids(hypothesis.contradicting_evidence_ids)

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
                    target_fn = proof_att.get("target_function") or (proof_rec.details or {}).get("target_function")
                    func_attr_ver = bool(proof_att.get("function_attribution_verified", False))
                    attr_lim = proof_att.get("attribution_limitation")

                    for fc in hypothesis.function_candidates:
                        tier = fc.get("candidate_tier")
                        fn_name = fc.get("function_name")
                        if tier == FUNCTION_TIER_EVIDENCE_SUPPORTED:
                            if target_fn and fn_name == target_fn:
                                if func_attr_ver:
                                    fc["candidate_tier"] = FUNCTION_TIER_VALIDATED_CAUSAL
                                    fc["confirmed_root_cause"] = True
                                    fc["tier_limitation"] = f"Causal role verified via deterministic reproduction and verified function attribution in evidence {proof_rec.evidence_id}."
                                else:
                                    fc["confirmed_root_cause"] = False
                                    fc["tier_limitation"] = attr_lim or f"State transition verified in runtime, but function attribution was not independently verified by execution instrumentation."
                            else:
                                fc["confirmed_root_cause"] = False
                                fc["tier_limitation"] = f"Observed in execution, but causal proof evidence identifies {target_fn or 'another function'} as the causal writer."
                        elif tier == FUNCTION_TIER_STATIC_CANDIDATE:
                            if target_fn and fn_name == target_fn and func_attr_ver:
                                fc["candidate_tier"] = FUNCTION_TIER_VALIDATED_CAUSAL
                                fc["confirmed_root_cause"] = True
                                fc["tier_limitation"] = f"Causal role verified via deterministic reproduction and verified function attribution in evidence {proof_rec.evidence_id}."
                            else:
                                # Invariant 1: static candidates remain static candidates without verified attribution
                                fc["confirmed_root_cause"] = False
                                fc["tier_limitation"] = attr_lim or "Static reference candidate identified via DWARF/ELF analysis; not confirmed root-cause function."
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
            if new_evidence and is_inconclusive:
                new_status = HYPOTHESIS_STATUS_INCONCLUSIVE
                new_conf = CONFIDENCE_LOW
                reason = "Observation returned inconclusive or insufficient evidence; outcome is UNKNOWN."
            else:
                new_status = HYPOTHESIS_STATUS_PROPOSED
                reason = "Awaiting follow-up observation evidence."

        if has_non_atomic_evidence:
            if new_conf in (CONFIDENCE_HIGH, CONFIDENCE_VERY_HIGH, CONFIDENCE_MEDIUM):
                new_conf = CONFIDENCE_LOW
            hypothesis.confidence = new_conf
            if "non-atomic" not in (hypothesis.confidence_rationale or "").lower():
                hypothesis.confidence_rationale = (
                    f"{hypothesis.confidence_rationale or ''} (Confidence capped at {new_conf} due to non-atomic / NON_ATOMIC capture consistency)"
                ).strip()
        elif has_partial_evidence:
            if new_conf in (CONFIDENCE_HIGH, CONFIDENCE_VERY_HIGH):
                new_conf = CONFIDENCE_MEDIUM
            hypothesis.confidence = new_conf
            if "partial" not in (hypothesis.confidence_rationale or "").lower():
                hypothesis.confidence_rationale = (
                    f"{hypothesis.confidence_rationale or ''} (Confidence capped at {new_conf} due to PARTIAL capture quality)"
                ).strip()

        # Calibrate numeric confidence_score deterministically to [0.05, 0.95]
        if new_status == HYPOTHESIS_STATUS_VALIDATED:
            hypothesis.confidence_score = 0.95
        elif new_status == HYPOTHESIS_STATUS_CONTRADICTED:
            hypothesis.confidence_score = round(max(0.05, 0.20 * (supp_count / float(max(1, supp_count + contra_count * 2)))), 3)
        elif new_status == HYPOTHESIS_STATUS_SUPPORTED:
            base_c = min(0.85, 0.50 + 0.15 * min(supp_count, 3))
            if has_partial_evidence or has_non_atomic_evidence:
                base_c = min(base_c, 0.55)
            hypothesis.confidence_score = round(base_c, 3)
        else:
            hypothesis.confidence_score = 0.25 if new_status == HYPOTHESIS_STATUS_INCONCLUSIVE else 0.40

        status_changed = (new_status != old_status) or (new_conf != old_conf)
        hypothesis.validation_status = new_status
        hypothesis.confidence = new_conf
        if status_changed:
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
