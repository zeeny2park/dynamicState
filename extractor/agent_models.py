"""Agent-facing models for the Agent Runtime Protocol (Phase 5).

Provides JSON-serializable, high-level semantic abstractions:
- AgentStateContext
- AgentObject
- AgentField
- AgentMutationCandidate
- AgentTransition
- AgentEvidence
- AgentInvariantCandidate
- AgentExplorationResult
- AgentAction and AgentActionResult
"""

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Dict, List, Optional, Union


class _SubscriptableModel:
    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            val = getattr(self, key)
            if hasattr(val, "to_dict"):
                return val.to_dict()
            return val
        raise KeyError(key)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        if hasattr(self, key):
            val = getattr(self, key)
            if hasattr(val, "to_dict"):
                return val.to_dict()
            return val
        return default


@dataclass
class AgentActionError(_SubscriptableModel):
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        res = {"code": self.code, "message": self.message}
        if self.details is not None:
            res["details"] = self.details
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentActionError":
        return cls(
            code=data["code"],
            message=data["message"],
            details=data.get("details")
        )


@dataclass
class AgentActionResult(_SubscriptableModel):
    success: bool
    action: str
    data: Optional[Any] = None
    error: Optional[AgentActionError] = None
    performance: Optional[Dict[str, float]] = None

    def to_dict(self) -> Dict[str, Any]:
        data_dict = self.data
        if hasattr(data_dict, "to_dict"):
            data_dict = data_dict.to_dict()
        elif isinstance(data_dict, list):
            data_dict = [item.to_dict() if hasattr(item, "to_dict") else item for item in data_dict]

        res: Dict[str, Any] = {
            "success": self.success,
            "action": self.action,
            "data": data_dict,
            "error": self.error.to_dict() if self.error else None
        }
        if self.performance is not None:
            res["performance"] = self.performance
        return res

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


@dataclass
class AgentAction(_SubscriptableModel):
    action: str
    snapshot_id: Optional[str] = None
    object_id: Optional[str] = None
    field_path: Optional[str] = None
    candidate_id: Optional[str] = None
    candidate: Optional[Dict[str, Any]] = None
    checkpoint_id: Optional[str] = None
    transition_id: Optional[str] = None
    state_id: Optional[str] = None
    timeout_ms: int = 1000
    max_steps: int = 10
    max_states: int = 20
    corpus_dir: str = "corpus"
    pid: Optional[int] = None
    policy: Optional[str] = None
    max_bytes: Optional[int] = None
    memory_snapshot_id: Optional[str] = None
    debug_image: Optional[str] = None
    mode: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentAction":
        return cls(
            action=data["action"],
            snapshot_id=data.get("snapshot_id"),
            object_id=data.get("object_id"),
            field_path=data.get("field_path"),
            candidate_id=data.get("candidate_id"),
            candidate=data.get("candidate"),
            checkpoint_id=data.get("checkpoint_id"),
            transition_id=data.get("transition_id"),
            state_id=data.get("state_id"),
            timeout_ms=int(data.get("timeout_ms", 1000)),
            max_steps=int(data.get("max_steps", 10)),
            max_states=int(data.get("max_states", 20)),
            corpus_dir=data.get("corpus_dir", "corpus"),
            pid=data.get("pid"),
            policy=data.get("policy"),
            max_bytes=data.get("max_bytes"),
            memory_snapshot_id=data.get("memory_snapshot_id"),
            debug_image=data.get("debug_image"),
            mode=data.get("mode")
        )


@dataclass
class AgentField(_SubscriptableModel):
    object_id: str
    field: str
    type: str
    value: Any
    mutability: str = "mutable"
    object_ref: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        if self.object_ref is None:
            res.pop("object_ref", None)
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentField":
        return cls(
            object_id=data["object_id"],
            field=data["field"],
            type=data["type"],
            value=data["value"],
            mutability=data.get("mutability", "mutable"),
            object_ref=data.get("object_ref")
        )


@dataclass
class AgentObject(_SubscriptableModel):
    object_id: str
    type: str
    storage: Optional[str] = None
    fields: List[Dict[str, Any]] = field(default_factory=list)
    identity_hint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "object_id": self.object_id,
            "type": self.type,
            "fields": self.fields
        }
        if self.storage is not None:
            res["storage"] = self.storage
        if self.identity_hint is not None:
            res["identity_hint"] = self.identity_hint
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentObject":
        return cls(
            object_id=data["object_id"],
            type=data["type"],
            storage=data.get("storage"),
            fields=data.get("fields", []),
            identity_hint=data.get("identity_hint")
        )


@dataclass
class AgentStateContext(_SubscriptableModel):
    """Compact semantic context of the runtime state designed for agent reasoning."""
    snapshot_id: str
    execution: Dict[str, Any]
    objects: List[Dict[str, Any]]
    statistics: Dict[str, Any]
    state_id: Optional[str] = None
    state_hash: Optional[str] = None
    provenance: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "snapshot_id": self.snapshot_id,
            "execution": self.execution,
            "objects": self.objects,
            "statistics": self.statistics
        }
        if self.state_id is not None:
            res["state_id"] = self.state_id
        if self.state_hash is not None:
            res["state_hash"] = self.state_hash
        if self.provenance is not None:
            res["provenance"] = self.provenance
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentStateContext":
        return cls(
            snapshot_id=data["snapshot_id"],
            execution=data["execution"],
            objects=data["objects"],
            statistics=data["statistics"],
            state_id=data.get("state_id"),
            state_hash=data.get("state_hash"),
            provenance=data.get("provenance")
        )


@dataclass
class AgentMutationCandidate(_SubscriptableModel):
    candidate_id: str
    snapshot_id: str
    object_id: str
    field: str
    type: str
    current_value: Any
    proposed_value: Any
    reason: str
    priority_score: float = 0.0
    ranking_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentMutationCandidate":
        return cls(
            candidate_id=data["candidate_id"],
            snapshot_id=data["snapshot_id"],
            object_id=data["object_id"],
            field=data["field"],
            type=data["type"],
            current_value=data["current_value"],
            proposed_value=data["proposed_value"],
            reason=data["reason"],
            priority_score=float(data.get("priority_score", 0.0)),
            ranking_reasons=data.get("ranking_reasons", [])
        )


@dataclass
class AgentEvidence(_SubscriptableModel):
    """A factual observation extracted from transitions or states without speculation."""
    evidence_id: str
    source: str = "transition"
    transition_id: Optional[str] = None
    observation: str = ""
    facts: Dict[str, Any] = field(default_factory=dict)
    snapshot_before: Optional[str] = None
    snapshot_after: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentEvidence":
        return cls(
            evidence_id=data["evidence_id"],
            source=data.get("source", "transition"),
            transition_id=data.get("transition_id"),
            observation=data.get("observation", ""),
            facts=data.get("facts", {}),
            snapshot_before=data.get("snapshot_before"),
            snapshot_after=data.get("snapshot_after")
        )


@dataclass
class AgentTransition(_SubscriptableModel):
    transition_id: str
    parent_snapshot: str
    child_snapshot: Optional[str] = None
    parent_state: Optional[str] = None
    child_state: Optional[str] = None
    mutation: Optional[Dict[str, Any]] = None
    execution: Optional[Dict[str, Any]] = None
    facts: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    performance: Optional[Dict[str, float]] = None

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "transition_id": self.transition_id,
            "parent_snapshot": self.parent_snapshot,
            "child_snapshot": self.child_snapshot,
            "facts": self.facts,
            "evidence": self.evidence
        }
        if self.parent_state is not None:
            res["parent_state"] = self.parent_state
        if self.child_state is not None:
            res["child_state"] = self.child_state
        if self.mutation is not None:
            res["mutation"] = self.mutation
        if self.execution is not None:
            res["execution"] = self.execution
        if self.performance is not None:
            res["performance"] = self.performance
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentTransition":
        return cls(
            transition_id=data["transition_id"],
            parent_snapshot=data["parent_snapshot"],
            child_snapshot=data.get("child_snapshot"),
            parent_state=data.get("parent_state"),
            child_state=data.get("child_state"),
            mutation=data.get("mutation"),
            execution=data.get("execution"),
            facts=data.get("facts", {}),
            evidence=data.get("evidence", []),
            performance=data.get("performance")
        )


@dataclass
class AgentInvariantCandidate(_SubscriptableModel):
    """An observed structural relation candidate (never claimed as a confirmed invariant)."""
    type: str = "invariant_candidate"
    expression: str = ""
    category: str = "boundary"
    evidence: List[str] = field(default_factory=list)
    status: str = "unconfirmed_candidate"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentInvariantCandidate":
        return cls(
            type=data.get("type", "invariant_candidate"),
            expression=data.get("expression", ""),
            category=data.get("category", "boundary"),
            evidence=data.get("evidence", []),
            status=data.get("status", "unconfirmed_candidate")
        )


@dataclass
class AgentExplorationResult(_SubscriptableModel):
    exploration_id: str
    seed_state: str
    steps: int
    new_states: int
    new_transitions: int
    crashes: int
    timeouts: int
    corpus_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentExplorationResult":
        return cls(
            exploration_id=data["exploration_id"],
            seed_state=data["seed_state"],
            steps=data["steps"],
            new_states=data["new_states"],
            new_transitions=data["new_transitions"],
            crashes=data["crashes"],
            timeouts=data["timeouts"],
            corpus_summary=data.get("corpus_summary", {})
        )
