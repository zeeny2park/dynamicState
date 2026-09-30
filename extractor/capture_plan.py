"""Capture Plan model and builders for fast runtime state capture.

Supports multiple capture modes:
- FULL: Capture all readable process memory regions within safety limits.
- TARGETED: Capture only memory regions required for a specific semantic path or object.
- THREAD: Capture thread stack and TLS regions for specified thread ID(s).
- OBJECT: Capture memory regions encompassing specified object addresses/graphs.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class CaptureMode(str, Enum):
    FULL = "FULL"
    TARGETED = "TARGETED"
    THREAD = "THREAD"
    OBJECT = "OBJECT"
    ZERO_STOP = "ZERO_STOP"


@dataclass
class CapturePlan:
    """Specification of what memory regions, threads, and registers to capture."""
    mode: str = CaptureMode.FULL.value
    target_paths: List[str] = field(default_factory=list)
    target_objects: List[str] = field(default_factory=list)
    memory_ranges: List[Tuple[int, int]] = field(default_factory=list)
    thread_ids: List[int] = field(default_factory=list)
    capture_stacks: bool = True
    capture_registers: bool = True
    capture_globals: bool = True
    max_bytes: int = 64 * 1024 * 1024
    max_stop_time_ms: float = 50.0
    timeout_ms: int = 1000

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "target_paths": list(self.target_paths),
            "target_objects": list(self.target_objects),
            "memory_ranges": [
                ["0x{:x}".format(r[0]), "0x{:x}".format(r[1])] for r in self.memory_ranges
            ],
            "thread_ids": list(self.thread_ids),
            "capture_stacks": self.capture_stacks,
            "capture_registers": self.capture_registers,
            "capture_globals": self.capture_globals,
            "max_bytes": self.max_bytes,
            "max_stop_time_ms": self.max_stop_time_ms,
            "timeout_ms": self.timeout_ms,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapturePlan":
        ranges = []
        for r in data.get("memory_ranges", []):
            if isinstance(r, (list, tuple)) and len(r) >= 2:
                s = int(r[0], 16) if isinstance(r[0], str) and r[0].startswith("0x") else int(r[0])
                e = int(r[1], 16) if isinstance(r[1], str) and r[1].startswith("0x") else int(r[1])
                ranges.append((s, e))

        return cls(
            mode=data.get("mode", CaptureMode.FULL.value),
            target_paths=data.get("target_paths", []),
            target_objects=data.get("target_objects", []),
            memory_ranges=ranges,
            thread_ids=data.get("thread_ids", []),
            capture_stacks=data.get("capture_stacks", True),
            capture_registers=data.get("capture_registers", True),
            capture_globals=data.get("capture_globals", True),
            max_bytes=data.get("max_bytes", 64 * 1024 * 1024),
            max_stop_time_ms=data.get("max_stop_time_ms", 50.0),
            timeout_ms=data.get("timeout_ms", 1000),
        )


class CapturePlanBuilder:
    """Builds optimized CapturePlan instances from target paths or previous states."""

    @staticmethod
    def build_full_plan(max_bytes: int = 64 * 1024 * 1024, timeout_ms: int = 1000) -> CapturePlan:
        return CapturePlan(
            mode=CaptureMode.FULL.value,
            capture_stacks=True,
            capture_registers=True,
            capture_globals=True,
            max_bytes=max_bytes,
            timeout_ms=timeout_ms,
        )

    @staticmethod
    def build_targeted_plan(
        target_path: str,
        address: Optional[int] = None,
        size: int = 4096,
        additional_ranges: Optional[List[Tuple[int, int]]] = None,
        timeout_ms: int = 1000,
    ) -> CapturePlan:
        ranges: List[Tuple[int, int]] = []
        if address is not None and address > 0:
            # Align to page boundary
            page_size = 4096
            start_page = (address // page_size) * page_size
            end_page = ((address + size + page_size - 1) // page_size) * page_size
            ranges.append((start_page, end_page))
        if additional_ranges:
            ranges.extend(additional_ranges)

        return CapturePlan(
            mode=CaptureMode.TARGETED.value,
            target_paths=[target_path],
            memory_ranges=ranges,
            capture_stacks=False,
            capture_registers=True,
            capture_globals=False,
            max_bytes=4 * 1024 * 1024,  # Targeted captures require very little memory
            timeout_ms=timeout_ms,
        )

    @staticmethod
    def build_thread_plan(
        thread_ids: List[int],
        timeout_ms: int = 1000
    ) -> CapturePlan:
        return CapturePlan(
            mode=CaptureMode.THREAD.value,
            thread_ids=list(thread_ids),
            capture_stacks=True,
            capture_registers=True,
            capture_globals=False,
            timeout_ms=timeout_ms,
        )

    @staticmethod
    def build_object_plan(
        object_ids: List[str],
        memory_ranges: Optional[List[Tuple[int, int]]] = None,
        timeout_ms: int = 1000
    ) -> CapturePlan:
        return CapturePlan(
            mode=CaptureMode.OBJECT.value,
            target_objects=list(object_ids),
            memory_ranges=list(memory_ranges or []),
            capture_stacks=False,
            capture_registers=False,
            capture_globals=False,
            timeout_ms=timeout_ms,
        )
