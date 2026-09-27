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

    @classmethod
    def from_runtime_state(cls, state, snapshot_id: str, metadata: Optional[Dict[str, Any]] = None,
                           transition: Optional[Dict[str, Any]] = None) -> "RuntimeSnapshot":
        return cls(snapshot_id=snapshot_id, schema_version="0.3",
                   created_at=datetime.now(timezone.utc).isoformat(),
                   process=state.process, execution=state.execution,
                   persistent=state.persistent, metadata=metadata,
                   transition=transition)

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
        return data

    def write_json(self, output: str) -> None:
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
            handle.write("\n")


def load_snapshot(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


@dataclass
class StateTransition:
    """A deterministic Phase-3 transition record for a future state corpus."""
    transition_id: str
    parent_snapshot: str
    child_snapshot: str
    mutation: Dict[str, Any]
    execution: Dict[str, Any]
    diff: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def write_json(self, output: str) -> None:
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
            handle.write("\n")
