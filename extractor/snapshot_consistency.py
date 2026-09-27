"""Consistency model and metadata for Phase 5.1 runtime memory snapshots.

Defines consistency levels:
- NON_ATOMIC: process_vm_readv-based capture without suspending inferior (MVP).
- COOPERATIVE: process voluntarily pauses at a designated synchronization point.
- STOPPED: process paused via SIGSTOP / GDB breakpoint.
- ATOMIC: hardware / kernel assisted atomic memory snapshot.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


NON_ATOMIC = "NON_ATOMIC"
COOPERATIVE = "COOPERATIVE"
STOPPED = "STOPPED"
ATOMIC = "ATOMIC"

VALID_CONSISTENCY_LEVELS = {NON_ATOMIC, COOPERATIVE, STOPPED, ATOMIC}

NON_ATOMIC_WARNING = (
    "LOW_IMPACT snapshot is not a globally consistent point-in-time process snapshot. "
    "Values observed across different regions may reflect slightly different execution timestamps."
)


@dataclass
class SnapshotConsistency:
    """Consistency metadata for low-impact memory capture."""
    level: str = NON_ATOMIC
    capture_start_ns: int = 0
    capture_end_ns: int = 0
    duration_us: float = 0.0
    partial_reads: int = 0
    failed_reads: int = 0
    warning: Optional[str] = NON_ATOMIC_WARNING

    def __post_init__(self):
        if self.level not in VALID_CONSISTENCY_LEVELS:
            raise ValueError(
                f"Invalid consistency level '{self.level}'. Must be one of {sorted(VALID_CONSISTENCY_LEVELS)}"
            )
        if self.level == NON_ATOMIC and not self.warning:
            self.warning = NON_ATOMIC_WARNING

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "capture_start_ns": self.capture_start_ns,
            "capture_end_ns": self.capture_end_ns,
            "duration_us": round(self.duration_us, 3),
            "partial_reads": self.partial_reads,
            "failed_reads": self.failed_reads,
            "warning": self.warning,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SnapshotConsistency":
        return cls(
            level=data.get("level", NON_ATOMIC),
            capture_start_ns=data.get("capture_start_ns", 0),
            capture_end_ns=data.get("capture_end_ns", 0),
            duration_us=data.get("duration_us", 0.0),
            partial_reads=data.get("partial_reads", 0),
            failed_reads=data.get("failed_reads", 0),
            warning=data.get("warning"),
        )
