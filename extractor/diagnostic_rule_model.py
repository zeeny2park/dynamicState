"""Phase 2.1.3 — Structured Diagnostic Rule Model & Explicit Rule Applicability

Defines the structured, versioned diagnostic rule specification, separating:
1. Observation (what was read)
2. Interpretation (what the observed value means)
3. Invariant (engineering rule that applies)
4. Violation (exact condition violating invariant)
5. Counter-evidence (observations weakening/refuting)
6. Scope (what has actually been inspected)
7. Conclusion (verdict and legitimate conclusions)

Enforces strict rule applicability: returns NOT_APPLICABLE when prerequisites
and semantic assumptions are not satisfied.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple, Set


RECIPE_STATUS_SUPPORTED = "SUPPORTED"
RECIPE_STATUS_CONTRADICTED = "CONTRADICTED"
RECIPE_STATUS_AMBIGUOUS = "AMBIGUOUS"
RECIPE_STATUS_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
RECIPE_STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

# Distinct Verdict Semantics (Section 8.2)
VERDICT_CONFIRMED = "CONFIRMED"
VERDICT_LIKELY = "LIKELY"
VERDICT_SUPPORTED = "SUPPORTED"
VERDICT_OBSERVED = "OBSERVED"
VERDICT_REFUTED = "REFUTED"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
VERDICT_NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class RuleApplicabilityResult:
    """Outcome of evaluating whether a rule is applicable to current context."""
    applicable: bool
    reason: str
    missing_prerequisites: List[str] = field(default_factory=list)
    semantic_assumptions_failed: List[str] = field(default_factory=list)


@dataclass
class DiagnosticRule:
    """Structured, versioned specification of a deterministic diagnostic rule."""
    rule_id: str
    version: str
    name: str
    domain: str
    applicable_problem_categories: List[str]
    required_target_capabilities: List[str]
    required_cpp_constructs: List[str]
    required_observations: List[str]
    optional_observations: List[str]
    preconditions: List[str]
    evaluation_expression: str
    thresholds_and_rationale: Dict[str, Any]
    supporting_conditions: List[str]
    contradicting_conditions: List[str]
    inconclusive_conditions: List[str]
    known_limitations: List[str]
    recommended_follow_up: str

    def check_applicability(self, context: Dict[str, Any]) -> RuleApplicabilityResult:
        """Determines if this rule can legitimately be evaluated against the context."""
        missing_prereqs = []
        caps = context.get("capabilities", [])
        for rc in self.required_target_capabilities:
            if rc not in caps and rc != "PROC_FS_AVAILABLE":
                missing_prereqs.append(rc)

        failed_assumptions = []
        # Check required observations
        for ro in self.required_observations:
            if ro not in context or context[ro] is None:
                failed_assumptions.append(f"Missing required observation: {ro}")

        # Semantic assumption checks based on rule domain
        if "IMBALANCE" in self.rule_id:
            # Check counter compatibility
            alloc_name = context.get("alloc_counter_name")
            free_name = context.get("free_counter_name")
            if alloc_name and free_name:
                if context.get("incompatible_counters", False):
                    failed_assumptions.append("Counters have incompatible measurement scopes or semantics")

        if "INCONSISTENT_RELATED_VARIABLES" in self.rule_id:
            if context.get("unrelated_field_pair", False):
                failed_assumptions.append("Fields do not belong to the same logical object or structure")

        if "STATE_TRANSITION" in self.rule_id:
            if not context.get("state_specification") and not context.get("allowed_transitions"):
                failed_assumptions.append("No explicit state specification or observed transition contract defined")

        if missing_prereqs or failed_assumptions:
            reason = "Rule semantic preconditions not satisfied: " + "; ".join(missing_prereqs + failed_assumptions)
            return RuleApplicabilityResult(
                applicable=False,
                reason=reason,
                missing_prerequisites=missing_prereqs,
                semantic_assumptions_failed=failed_assumptions,
            )

        return RuleApplicabilityResult(applicable=True, reason="All preconditions and semantic assumptions satisfied")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
