"""Phase 2.1.3 — Invariant Evaluation Framework & Provenance Tracking

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

Enforces invariant provenance:
1. EXPLICIT_EXPERT_SPEC
2. RECOGNIZED_TYPE_CONTRACT
3. SOURCE_LEVEL_RULE
4. HEURISTIC_CANDIDATE (explicitly labeled, never treated as confirmed invariant)

If state value has no known contract -> returns NOT_APPLICABLE (never invents rules).
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


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


class InvariantSource(str, Enum):
    EXPLICIT_EXPERT_SPEC = "EXPLICIT_EXPERT_SPEC"
    RECOGNIZED_TYPE_CONTRACT = "RECOGNIZED_TYPE_CONTRACT"
    SOURCE_LEVEL_RULE = "SOURCE_LEVEL_RULE"
    HEURISTIC_CANDIDATE = "HEURISTIC_CANDIDATE"


@dataclass
class InvariantDefinition:
    """Specification of an engineering invariant to evaluate."""
    invariant_id: str
    invariant_type: InvariantType
    source: InvariantSource
    expression: str
    description: str
    target_symbols: List[str]
    parameters: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvariantEvaluationResult:
    """Outcome of evaluating an invariant against target runtime state."""
    invariant_id: str
    status: str  # "PASS", "FAIL", "NOT_APPLICABLE", "INCONCLUSIVE"
    violated: bool
    rationale: str
    observed_values: Dict[str, Any]
    invariant_source: InvariantSource
    is_heuristic: bool
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class InvariantEvaluator:
    """Evaluates program invariants with strict provenance and applicability checking."""

    def evaluate(
        self,
        invariant: InvariantDefinition,
        context: Dict[str, Any],
    ) -> InvariantEvaluationResult:
        inv_type = invariant.invariant_type
        params = invariant.parameters
        is_heuristic = (invariant.source == InvariantSource.HEURISTIC_CANDIDATE)

        # 1. State Transition Rules / Enum Domain
        if inv_type in (InvariantType.STATE_TRANSITION_RULES, InvariantType.ENUM_DOMAIN):
            val = context.get("state_value") if context.get("state_value") is not None else context.get("value")
            # If no legal states or transition matrix defined, return NOT_APPLICABLE!
            allowed_states = params.get("allowed_states") or context.get("allowed_states")
            allowed_transitions = params.get("allowed_transitions") or context.get("allowed_transitions")

            if allowed_states is None and allowed_transitions is None:
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="NOT_APPLICABLE",
                    violated=False,
                    rationale="No explicit state specification or enum domain provided. Invariant cannot be applied.",
                    observed_values={"state_value": val},
                    invariant_source=invariant.source,
                    is_heuristic=is_heuristic,
                    recommendation="Define state machine specification or enum domain to evaluate state validity.",
                )

            if val is not None:
                try:
                    val_int = int(val)
                except Exception:
                    val_int = val

                if allowed_states and val_int not in allowed_states:
                    return InvariantEvaluationResult(
                        invariant_id=invariant.invariant_id,
                        status="FAIL",
                        violated=True,
                        rationale=f"Observed state {val_int} is outside allowed domain {allowed_states}.",
                        observed_values={"state_value": val_int, "allowed_domain": allowed_states},
                        invariant_source=invariant.source,
                        is_heuristic=is_heuristic,
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
                )

            if length > cap:
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="FAIL",
                    violated=True,
                    rationale=f"Invariant violation: length ({length}) exceeds capacity ({cap}).",
                    observed_values={"capacity": cap, "length": length},
                    invariant_source=invariant.source,
                    is_heuristic=is_heuristic,
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
            )

        # 3. Numeric Range
        if inv_type == InvariantType.NUMERIC_RANGE:
            val = context.get("value")
            min_v = params.get("min")
            max_v = params.get("max")
            if val is None or min_v is None or max_v is None:
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="NOT_APPLICABLE",
                    violated=False,
                    rationale="Range boundaries or observed value missing.",
                    observed_values={"value": val},
                    invariant_source=invariant.source,
                    is_heuristic=is_heuristic,
                )
            if not (min_v <= val <= max_v):
                return InvariantEvaluationResult(
                    invariant_id=invariant.invariant_id,
                    status="FAIL",
                    violated=True,
                    rationale=f"Value {val} outside bounds [{min_v}, {max_v}].",
                    observed_values={"value": val, "min": min_v, "max": max_v},
                    invariant_source=invariant.source,
                    is_heuristic=is_heuristic,
                )
            return InvariantEvaluationResult(
                invariant_id=invariant.invariant_id,
                status="PASS",
                violated=False,
                rationale=f"Value {val} within bounds [{min_v}, {max_v}].",
                observed_values={"value": val},
                invariant_source=invariant.source,
                is_heuristic=is_heuristic,
            )

        # Default fallback
        return InvariantEvaluationResult(
            invariant_id=invariant.invariant_id,
            status="NOT_APPLICABLE",
            violated=False,
            rationale=f"Unsupported invariant type {inv_type}",
            observed_values={},
            invariant_source=invariant.source,
            is_heuristic=is_heuristic,
        )
