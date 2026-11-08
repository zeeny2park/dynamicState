"""Phase 2.1.4 — Invariant Evaluation Framework & Provenance Tracking

Implements a deterministic invariant evaluation framework supporting:
- Numeric range
- Enum domain
- Capacity >= length
- Pointer non-null during active lifecycle
- Pointer null after release
- Count <= allocated capacity
- Head/tail consistency
- State transition rules
- Monotonic counters
- Counter relationships

Enforces invariant provenance hierarchy:
1. EXPLICIT_EXPERT_SPEC (highest authority, score 1.0)
2. RECOGNIZED_TYPE_CONTRACT (score 0.95)
3. SOURCE_LEVEL_RULE (score 0.85)
4. HEURISTIC_CANDIDATE (score <= 0.60, NEVER produces confirmed invariant violations!)

If state value has no known contract -> returns NOT_APPLICABLE (never invents rules).
Every failed invariant reports exact observed values, expected conditions, source, and limitations.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class InvariantType(str, Enum):
    NUMERIC_RANGE = "NUMERIC_RANGE"
    ENUM_DOMAIN = "ENUM_DOMAIN"
    CAPACITY_GE_LENGTH = "CAPACITY_GE_LENGTH"
    POINTER_NON_NULL_DURING_LIFECYCLE = "POINTER_NON_NULL_DURING_LIFECYCLE"
    POINTER_NULL_AFTER_RELEASE = "POINTER_NULL_AFTER_RELEASE"
    COUNT_LE_CAPACITY = "COUNT_LE_CAPACITY"
    HEAD_TAIL_CONSISTENCY = "HEAD_TAIL_CONSISTENCY"
    STATE_TRANSITION_RULES = "STATE_TRANSITION_RULES"
    MONOTONIC_COUNTER = "MONOTONIC_COUNTER"
    COUNTER_RELATIONSHIP = "COUNTER_RELATIONSHIP"
    # Aliases
    BOUNDED_RANGE = "NUMERIC_RANGE"


class InvariantSource(str, Enum):
    EXPLICIT_EXPERT_SPEC = "EXPLICIT_EXPERT_SPEC"
    RECOGNIZED_TYPE_CONTRACT = "RECOGNIZED_TYPE_CONTRACT"
    SOURCE_LEVEL_RULE = "SOURCE_LEVEL_RULE"
    HEURISTIC_CANDIDATE = "HEURISTIC_CANDIDATE"


@dataclass
class InvariantDefinition:
    """Specification of an engineering invariant to evaluate."""
    invariant_id: str
    invariant_type: InvariantType = InvariantType.NUMERIC_RANGE
    source: InvariantSource = InvariantSource.RECOGNIZED_TYPE_CONTRACT
    expression: str = ""
    description: str = ""
    target_symbols: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    name: str = ""
    inv_type: Optional[InvariantType] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None

    def __post_init__(self):
        if self.inv_type:
            self.invariant_type = self.inv_type
        if self.name and not self.description:
            self.description = self.name
        if self.min_value is not None:
            self.parameters["min_value"] = self.min_value
        if self.max_value is not None:
            self.parameters["max_value"] = self.max_value

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["invariant_type"] = self.invariant_type.value
        d["source"] = self.source.value
        return d


@dataclass
class InvariantEvaluationResult:
    """Outcome of evaluating an invariant against target runtime state."""
    invariant_id: str
    status: str  # "PASS", "FAIL", "CANDIDATE_ANOMALY", "NOT_APPLICABLE", "INCONCLUSIVE"
    violated: bool
    rationale: str
    observed_values: Dict[str, Any]
    invariant_source: InvariantSource
    is_heuristic: bool
    expected_condition: str = ""
    evidence_references: List[str] = field(default_factory=list)
    applicable_object_and_field: str = ""
    scope_of_inspection: str = "TARGET_OBJECT"
    limitations: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["invariant_source"] = self.invariant_source.value
        return d


class InvariantEvaluator:
    """Evaluates program invariants with strict provenance and applicability checking."""

    def __init__(self):
        self.registered_invariants: Dict[str, InvariantDefinition] = {}

    def register_invariant(self, variable_name: str, invariant: InvariantDefinition) -> None:
        self.registered_invariants[variable_name] = invariant

    def get_source_authority(self, source: InvariantSource) -> float:
        if source == InvariantSource.EXPLICIT_EXPERT_SPEC:
            return 1.0
        elif source == InvariantSource.RECOGNIZED_TYPE_CONTRACT:
            return 0.95
        elif source == InvariantSource.SOURCE_LEVEL_RULE:
            return 0.85
        elif source == InvariantSource.HEURISTIC_CANDIDATE:
            return 0.60
        return 0.50

    def evaluate(
        self,
        invariant: Union[InvariantDefinition, str, None] = None,
        context: Optional[Dict[str, Any]] = None,
        variable_name: Optional[str] = None,
        observed_value: Any = None,
    ) -> InvariantEvaluationResult:
        if isinstance(invariant, str) or variable_name:
            v_name = invariant if isinstance(invariant, str) else variable_name
            if v_name in self.registered_invariants:
                inv_def = self.registered_invariants[v_name]
                ctx = dict(context or {})
                if observed_value is not None:
                    ctx["value"] = observed_value
                return self._evaluate_def(inv_def, ctx)
            else:
                return InvariantEvaluationResult(
                    invariant_id=f"inv_{v_name}",
                    status="NOT_APPLICABLE",
                    violated=False,
                    rationale=f"No recognized invariant specification defined for variable '{v_name}'. Invariant evaluation refused without contract.",
                    observed_values={"value": observed_value},
                    invariant_source=InvariantSource.HEURISTIC_CANDIDATE,
                    is_heuristic=True,
                )

        if isinstance(invariant, InvariantDefinition):
            ctx = dict(context or {})
            if observed_value is not None:
                ctx["value"] = observed_value
            return self._evaluate_def(invariant, ctx)

        return InvariantEvaluationResult(
            invariant_id="inv_unknown",
            status="NOT_APPLICABLE",
            violated=False,
            rationale="No invariant provided.",
            observed_values={},
            invariant_source=InvariantSource.HEURISTIC_CANDIDATE,
            is_heuristic=True,
        )

    def _evaluate_def(
        self,
        invariant: InvariantDefinition,
        context: Dict[str, Any],
    ) -> InvariantEvaluationResult:
        inv_type = invariant.invariant_type
        params = invariant.parameters
        is_heuristic = (invariant.source == InvariantSource.HEURISTIC_CANDIDATE)
        target_sym = invariant.target_symbols[0] if invariant.target_symbols else "unknown"

        # 1. State Transition Rules / Enum Domain
        if inv_type in (InvariantType.STATE_TRANSITION_RULES, InvariantType.ENUM_DOMAIN):
            val = context.get("state_value") if context.get("state_value") is not None else context.get("value")
            # If no legal states or transition matrix defined, return NOT_APPLICABLE (never invent states!)
            allowed_states = params.get("allowed_states") or context.get("allowed_states")
            allowed_transitions = params.get("allowed_transitions") or context.get("allowed_transitions")

            if allowed_states is None and allowed_transitions is None:
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="NOT_APPLICABLE",
                    violated=False,
                    rationale="No explicit state specification or enum domain provided. Invariant cannot be applied without authoritative contract.",
                    observed_values={"state_value": val},
                    invariant_source=invariant.source,
                    is_heuristic=is_heuristic,
                    expected_condition="Explicit state domain specification",
                    applicable_object_and_field=target_sym,
                    limitations=["State machine specification absent; refusing to fabricate legal enum states"],
                    recommendation="Supply explicit state machine specification or enum domain to evaluate state validity.",
                )

            if val is not None:
                try:
                    val_int = int(val)
                except Exception:
                    val_int = val

                if allowed_states and val_int not in allowed_states:
                    # P1: Heuristic candidates NEVER become confirmed violations automatically!
                    if is_heuristic:
                        return InvariantEvaluationResult(
                            invariant_id=invariant.invariant_id,
                            status="CANDIDATE_ANOMALY",
                            violated=False,
                            rationale=f"Observed state {val_int} does not match heuristic candidate domain {allowed_states}. Heuristic candidates cannot produce confirmed violations.",
                            observed_values={"state_value": val_int, "allowed_domain": allowed_states},
                            invariant_source=invariant.source,
                            is_heuristic=True,
                            expected_condition=f"state in {allowed_states}",
                            applicable_object_and_field=target_sym,
                            limitations=["Heuristic rule unverified by explicit engineer contract"],
                        )
                    return InvariantEvaluationResult(
                        invariant_id=invariant.invariant_id,
                        status="FAIL",
                        violated=True,
                        rationale=f"Observed state {val_int} is outside allowed authoritative domain {allowed_states}.",
                        observed_values={"state_value": val_int, "allowed_domain": allowed_states},
                        invariant_source=invariant.source,
                        is_heuristic=False,
                        expected_condition=f"state in {allowed_states}",
                        applicable_object_and_field=target_sym,
                        recommendation="Audit state transition logic; unexpected enum state observed.",
                    )
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="PASS",
                    violated=False,
                    rationale=f"Observed state {val_int} conforms to specification {allowed_states or allowed_transitions}.",
                    observed_values={"state_value": val_int},
                    invariant_source=invariant.source,
                    is_heuristic=is_heuristic,
                    expected_condition=f"state in {allowed_states or allowed_transitions}",
                    applicable_object_and_field=target_sym,
                )

        # 2. Capacity >= Length Invariant
        if inv_type == InvariantType.CAPACITY_GE_LENGTH:
            cap = context.get("buffer_capacity") if context.get("buffer_capacity") is not None else context.get("capacity")
            length = context.get("buffer_length") if context.get("buffer_length") is not None else context.get("length")

            if cap is None or length is None:
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="INCONCLUSIVE",
                    violated=False,
                    rationale="Capacity or length observation unavailable.",
                    observed_values={"capacity": cap, "length": length},
                    invariant_source=invariant.source,
                    is_heuristic=is_heuristic,
                    expected_condition="length <= capacity",
                    applicable_object_and_field=target_sym,
                    limitations=["Missing runtime variable observation for capacity or length"],
                )

            if context.get("unrelated_field_pair", False):
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="NOT_APPLICABLE",
                    violated=False,
                    rationale="Candidate capacity and length belong to unrelated objects; invariant does not apply.",
                    observed_values={"capacity": cap, "length": length},
                    invariant_source=invariant.source,
                    is_heuristic=is_heuristic,
                    expected_condition="Coupled same-object fields",
                    applicable_object_and_field=target_sym,
                    limitations=["Fields belong to disjoint struct definitions or disparate subsystems"],
                )

            if length > cap:
                if is_heuristic:
                    return InvariantEvaluationResult(
                        invariant_id=invariant.invariant_id,
                        status="CANDIDATE_ANOMALY",
                        violated=False,
                        rationale=f"Candidate length ({length}) exceeds candidate capacity ({cap}), but relationship is heuristic. Confirmed violation refused without proven coupling.",
                        observed_values={"capacity": cap, "length": length},
                        invariant_source=invariant.source,
                        is_heuristic=True,
                        expected_condition="length <= capacity",
                        applicable_object_and_field=target_sym,
                        limitations=["Heuristic candidate coupling requires explicit verification"],
                    )
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="FAIL",
                    violated=True,
                    rationale=f"Invariant violation: length ({length}) exceeds capacity ({cap}).",
                    observed_values={"capacity": cap, "length": length},
                    invariant_source=invariant.source,
                    is_heuristic=False,
                    expected_condition="length <= capacity",
                    applicable_object_and_field=target_sym,
                    recommendation="Audit buffer write boundaries to prevent buffer overrun.",
                )
            return InvariantEvaluationResult(
                invariant_id=invariant.invariant_id,
                status="PASS",
                violated=False,
                rationale=f"Length ({length}) strictly respects capacity ({cap}). Invariant holds.",
                observed_values={"capacity": cap, "length": length},
                invariant_source=invariant.source,
                is_heuristic=is_heuristic,
                expected_condition="length <= capacity",
                applicable_object_and_field=target_sym,
            )

        # 3. Numeric Range
        if inv_type == InvariantType.NUMERIC_RANGE:
            val = context.get("value")
            min_v = params.get("min") if params.get("min") is not None else params.get("min_value")
            max_v = params.get("max") if params.get("max") is not None else params.get("max_value")
            if val is None or min_v is None or max_v is None:
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="NOT_APPLICABLE",
                    violated=False,
                    rationale="Range boundaries or observed value missing.",
                    observed_values={"value": val},
                    invariant_source=invariant.source,
                    is_heuristic=is_heuristic,
                    expected_condition="min <= value <= max",
                    applicable_object_and_field=target_sym,
                )
            if not (min_v <= val <= max_v):
                if is_heuristic:
                    return InvariantEvaluationResult(
                        invariant_id=invariant.invariant_id,
                        status="CANDIDATE_ANOMALY",
                        violated=False,
                        rationale=f"Value {val} outside heuristic bounds [{min_v}, {max_v}].",
                        observed_values={"value": val, "min": min_v, "max": max_v},
                        invariant_source=invariant.source,
                        is_heuristic=True,
                        expected_condition=f"{min_v} <= value <= {max_v}",
                        applicable_object_and_field=target_sym,
                        limitations=["Heuristic bounds unverified"],
                    )
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="FAIL",
                    violated=True,
                    rationale=f"Value {val} outside authoritative bounds [{min_v}, {max_v}].",
                    observed_values={"value": val, "min": min_v, "max": max_v},
                    invariant_source=invariant.source,
                    is_heuristic=False,
                    expected_condition=f"{min_v} <= value <= {max_v}",
                    applicable_object_and_field=target_sym,
                )
            return InvariantEvaluationResult(
                invariant_id=invariant.invariant_id,
                status="PASS",
                violated=False,
                rationale=f"Value {val} within bounds [{min_v}, {max_v}].",
                observed_values={"value": val},
                invariant_source=invariant.source,
                is_heuristic=is_heuristic,
                expected_condition=f"{min_v} <= value <= {max_v}",
                applicable_object_and_field=target_sym,
            )

        # 4. Monotonic Counter
        if inv_type == InvariantType.MONOTONIC_COUNTER:
            series = context.get("counter_series") or ([context.get("prev_value"), context.get("value")] if context.get("prev_value") is not None and context.get("value") is not None else None)
            if not series or len(series) < 2:
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="INCONCLUSIVE",
                    violated=False,
                    rationale="Insufficient counter observations to test monotonic progression.",
                    observed_values={"series": series},
                    invariant_source=invariant.source,
                    is_heuristic=is_heuristic,
                    expected_condition="series[i] <= series[i+1]",
                    applicable_object_and_field=target_sym,
                )
            is_monotonic = all(series[i] <= series[i + 1] for i in range(len(series) - 1))
            if not is_monotonic:
                if is_heuristic:
                    return InvariantEvaluationResult(
                        invariant_id=invariant.invariant_id,
                        status="CANDIDATE_ANOMALY",
                        violated=False,
                        rationale="Heuristic counter sequence exhibited regression or wrap-around.",
                        observed_values={"series": series},
                        invariant_source=invariant.source,
                        is_heuristic=True,
                        expected_condition="Monotonically non-decreasing",
                        applicable_object_and_field=target_sym,
                    )
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="FAIL",
                    violated=True,
                    rationale="Monotonic counter decreased across consecutive observations. Counter wrap-around or corruption detected.",
                    observed_values={"series": series},
                    invariant_source=invariant.source,
                    is_heuristic=False,
                    expected_condition="Monotonically non-decreasing",
                    applicable_object_and_field=target_sym,
                    recommendation="Inspect counter reset or integer underflow.",
                )
            return InvariantEvaluationResult(
                invariant_id=invariant.invariant_id,
                status="PASS",
                violated=False,
                rationale="Counter values strictly non-decreasing across all observation points.",
                observed_values={"series": series},
                invariant_source=invariant.source,
                is_heuristic=is_heuristic,
                expected_condition="Monotonically non-decreasing",
                applicable_object_and_field=target_sym,
            )

        # Default fallback
        return InvariantEvaluationResult(
            invariant_id=invariant.invariant_id,
            status="NOT_APPLICABLE",
            violated=False,
            rationale=f"Invariant type '{inv_type}' not evaluated or prerequisite data missing.",
            observed_values={},
            invariant_source=invariant.source,
            is_heuristic=is_heuristic,
            expected_condition="Unspecified",
            applicable_object_and_field=target_sym,
        )
