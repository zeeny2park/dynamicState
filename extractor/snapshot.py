"""Snapshot model and persistence, independent of GDB."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional


@dataclass
class RuntimeSnapshot:
    snapshot_id: str
    schema_version: str
    created_at: str
    process: Dict[str, Any]
    execution: Any
    persistent: Any
    metadata: Optional[Dict[str, Any]] = None
    transition: Optional[Dict[str, Any]] = None
    provenance: Optional[Dict[str, Any]] = None

    @classmethod
    def from_runtime_state(cls, state, snapshot_id: str, metadata: Optional[Dict[str, Any]] = None,
                           transition: Optional[Dict[str, Any]] = None,
                           provenance: Optional[Dict[str, Any]] = None) -> "RuntimeSnapshot":
        prov = provenance or getattr(state, "provenance", None)
        return cls(snapshot_id=snapshot_id, schema_version="0.3",
                   created_at=datetime.now(timezone.utc).isoformat(),
                   process=state.process, execution=state.execution,
                   persistent=state.persistent, metadata=metadata,
                   transition=transition, provenance=prov)

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "schema_version": self.schema_version,
            "snapshot": {"snapshot_id": self.snapshot_id, "created_at": self.created_at,
                         "pid": self.process.get("pid"), "binary": self.process.get("binary")},
            "process": self.process,
            "execution": asdict(self.execution) if hasattr(self.execution, "__dataclass_fields__") else self.execution,
            "persistent": asdict(self.persistent) if hasattr(self.persistent, "__dataclass_fields__") else self.persistent,
        }
        if self.metadata is not None:
            data["metadata"] = self.metadata
        if self.transition is not None:
            data["transition"] = self.transition
        if self.provenance is not None:
            data["provenance"] = self.provenance
        return data

    def write_json(self, output: str) -> None:
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
            handle.write("\n")


def load_snapshot(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def load_transition(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


@dataclass
class StateTransition:
    """A deterministic Phase-3 transition record for state transitions and Phase 4 state corpus."""
    transition_id: str
    parent_snapshot: str
    child_snapshot: Optional[str] = None
    mutation: Optional[Any] = None
    execution: Optional[Any] = None
    diff: Optional[Any] = None
    performance: Optional[Dict[str, float]] = None
    schema_version: str = "0.3"

    def to_dict(self) -> Dict[str, Any]:
        mut_dict = self.mutation.to_dict() if hasattr(self.mutation, "to_dict") else self.mutation
        exec_dict = self.execution.to_dict() if hasattr(self.execution, "to_dict") else self.execution
        diff_dict = self.diff.to_dict() if hasattr(self.diff, "to_dict") else self.diff

        trans = {
            "transition_id": self.transition_id,
            "parent_snapshot": self.parent_snapshot,
            "child_snapshot": self.child_snapshot,
            "mutation": mut_dict,
            "execution": exec_dict,
            "diff": diff_dict,
        }
        if self.performance is not None:
            trans["performance"] = self.performance

        return {
            "schema_version": self.schema_version,
            "transition": trans,
            "transition_id": self.transition_id,
            "parent_snapshot": self.parent_snapshot,
            "child_snapshot": self.child_snapshot,
            "mutation": mut_dict,
            "execution": exec_dict,
            "diff": diff_dict,
            "performance": self.performance,
        }

    def write_json(self, output: str) -> None:
        import os
        parent_dir = os.path.dirname(os.path.abspath(output))
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
            handle.write("\n")
