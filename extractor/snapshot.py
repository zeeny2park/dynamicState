"""Snapshot model and persistence, independent of GDB."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Tuple


from .raw_snapshot import RawRuntimeSnapshot


@dataclass
class RuntimeSnapshot:
    snapshot_id: str
    schema_version: str = "0.3"
    created_at: str = ""
    process: Dict[str, Any] = field(default_factory=dict)
    execution: Any = None
    persistent: Any = None
    metadata: Optional[Dict[str, Any]] = None
    transition: Optional[Dict[str, Any]] = None
    provenance: Optional[Dict[str, Any]] = None

    # Section 3 RuntimeSnapshot explicit model fields
    pid: Optional[int] = None
    executable: Optional[str] = None
    executable_build_id: Optional[str] = None
    timestamp: Optional[str] = None
    capture_duration_us: float = 0.0
    thread_metadata: List[Dict[str, Any]] = field(default_factory=list)
    memory_regions: List[Dict[str, Any]] = field(default_factory=list)
    register_state: Dict[str, Any] = field(default_factory=dict)
    captured_ranges: List[Tuple[int, int]] = field(default_factory=list)
    raw_memory: Optional[Any] = None
    capture_backend: str = "unknown"
    observation_metadata: Dict[str, Any] = field(default_factory=dict)
    completeness: str = "COMPLETE"

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.timestamp:
            self.timestamp = self.created_at
        if self.pid is None and isinstance(self.process, dict):
            self.pid = self.process.get("pid")
        if self.executable is None and isinstance(self.process, dict):
            self.executable = self.process.get("binary") or self.process.get("executable")
        if not self.thread_metadata and self.execution:
            exec_dict = self.execution if isinstance(self.execution, dict) else (
                asdict(self.execution) if hasattr(self.execution, "__dataclass_fields__") else {}
            )
            self.thread_metadata = exec_dict.get("threads", [])

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
                         "pid": self.pid or (self.process.get("pid") if isinstance(self.process, dict) else None),
                         "binary": self.executable or (self.process.get("binary") if isinstance(self.process, dict) else None)},
            "process": self.process,
            "execution": asdict(self.execution) if hasattr(self.execution, "__dataclass_fields__") else self.execution,
            "persistent": asdict(self.persistent) if hasattr(self.persistent, "__dataclass_fields__") else self.persistent,
            # Section 3 explicit fields
            "snapshot_id": self.snapshot_id,
            "pid": self.pid,
            "executable": self.executable,
            "executable_build_id": self.executable_build_id,
            "timestamp": self.timestamp,
            "capture_duration_us": self.capture_duration_us,
            "thread_metadata": self.thread_metadata,
            "memory_regions": self.memory_regions,
            "register_state": self.register_state,
            "captured_ranges": [
                ["0x{:x}".format(r[0]), "0x{:x}".format(r[1])] for r in self.captured_ranges
            ],
            "raw_memory": self.raw_memory,
            "capture_backend": self.capture_backend,
            "observation_metadata": self.observation_metadata,
            "completeness": self.completeness,
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
