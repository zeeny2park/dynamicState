"""Lifecycle state machine of the staged (snapshot) investigation sessions.

Kept from the retired adaptive engine (IMP-017): extractor/investigation.py sessions still record their lifecycle
with it.  It decides no verdict.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


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
STATE_ABSTAINED = "ABSTAINED"
STATE_CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
STATE_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
STATE_FAILED = "FAILED"
STATE_CANCELED = "CANCELED"

TERMINAL_LIFECYCLE_STATES = {
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
    STATE_ABSTAINED,
    STATE_CAPABILITY_UNAVAILABLE,
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
        STATE_ABSTAINED,
        STATE_CAPABILITY_UNAVAILABLE,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_COMPLETED: set(),
    STATE_INCONCLUSIVE: set(),
    STATE_ABSTAINED: set(),
    STATE_CAPABILITY_UNAVAILABLE: set(),
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
