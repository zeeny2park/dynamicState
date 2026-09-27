"""Backend-neutral runtime state model.

Only JSON-compatible data is kept in these models; runtime objects such as
``gdb.Value`` deliberately never escape the adapter/graph-building boundary.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class FieldState:
    name: str
    type: str
    offset: Optional[int] = None
    value: Any = None
    address: Optional[str] = None
    object_ref: Optional[str] = None
    availability: Optional[str] = None
    error: Optional[str] = None
    traversal: Optional[Dict[str, Any]] = None


@dataclass
class ObjectState:
    object_id: str
    type: str
    address: Optional[str]
    storage: str
    fields: List[FieldState] = field(default_factory=list)
    availability: Optional[str] = None
    error: Optional[str] = None
    thread_id: Optional[int] = None
    frame_level: Optional[int] = None


@dataclass
class VariableState:
    name: str
    type: str
    value: Any = None
    address: Optional[str] = None
    object_ref: Optional[str] = None
    availability: Optional[str] = None
    error: Optional[str] = None
    traversal: Optional[Dict[str, Any]] = None


@dataclass
class FrameState:
    level: int
    function: Optional[str]
    pc: Optional[str]
    arguments: Dict[str, VariableState] = field(default_factory=dict)
    locals: Dict[str, VariableState] = field(default_factory=dict)


@dataclass
class ThreadState:
    thread_id: int
    frames: List[FrameState] = field(default_factory=list)


@dataclass
class ExecutionState:
    threads: List[ThreadState] = field(default_factory=list)


@dataclass
class RootState:
    root_id: str
    name: str
    source: str
    type: str
    address: Optional[str] = None
    object_ref: Optional[str] = None
    thread_id: Optional[int] = None
    frame_level: Optional[int] = None
    function: Optional[str] = None
    availability: Optional[str] = None
    error: Optional[str] = None


@dataclass
class PersistentState:
    roots: List[RootState] = field(default_factory=list)
    objects: List[ObjectState] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    tls: Dict[str, Any] = field(default_factory=lambda: {"availability": "unsupported"})


@dataclass
class RuntimeState:
    schema_version: str
    process: Dict[str, Any]
    execution: ExecutionState
    objects: List[ObjectState]
    persistent: Optional[PersistentState] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
