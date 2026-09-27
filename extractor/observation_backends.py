"""Observation Backend models and safety contracts for Phase 5.2.

Defines the clean architectural separation between:
1. GDBObservationBackend (CONSISTENT mode): Live GDB execution context, process stopped, mutation permitted.
2. LowImpactObservationBackend (LOW_IMPACT mode): Zero-stop process_vm_readv capture, non-atomic, read-only.
"""

from abc import ABC, abstractmethod
import os
from typing import Any, Dict, List, Optional, Tuple, Union

from .memory_capture import MemoryCapture
from .memory_snapshot import RawMemorySnapshot
from .offline_analyzer import OfflineMemoryAnalyzer
from .snapshot import RuntimeSnapshot
from .snapshot_consistency import NON_ATOMIC


class ObservationBackend(ABC):
    """Abstract base class for state observation backends."""

    @property
    @abstractmethod
    def mode(self) -> str:
        """Observation mode string: 'CONSISTENT' or 'LOW_IMPACT'."""
        pass

    @abstractmethod
    def observe(self, **kwargs) -> Any:
        """Capture and return runtime snapshot."""
        pass

    @abstractmethod
    def capabilities(self) -> Dict[str, Any]:
        """Return backend capability descriptor."""
        pass


class GDBObservationBackend(ObservationBackend):
    """GDB-driven observation backend for CONSISTENT state capture and mutation."""

    def __init__(self, controller: Optional[Any] = None):
        self.controller = controller

    @property
    def mode(self) -> str:
        return "CONSISTENT"

    def observe(self, **kwargs) -> RuntimeSnapshot:
        if not self.controller:
            raise RuntimeError("GDBObservationBackend requires an active RuntimeController")
        return self.controller.observe()

    def capabilities(self) -> Dict[str, Any]:
        return {
            "mode": "CONSISTENT",
            "process_stop": True,
            "ptrace": True,
            "sigstop": True,
            "sigcont": True,
            "gdb_attached": True,
            "typed_mutation": True,
            "checkpoint_restore": True,
            "branch_exploration": True,
            "execution_context": True,
            "consistency": "STOPPED",
            "backend": "gdb",
        }


class LowImpactObservationBackend(ObservationBackend):
    """Zero-stop observation backend using Linux process_vm_readv() and offline DWARF analysis.

    Strict Safety Contract:
    - Never uses ptrace
    - Never uses SIGSTOP or SIGCONT
    - Never attaches GDB to the live process
    - Never sends commands to the live process
    - Never modifies process memory (mutation strictly forbidden)
    - Observation is best-effort and NON_ATOMIC
    """

    def __init__(
        self,
        capturer: Optional[MemoryCapture] = None,
        analyzer: Optional[OfflineMemoryAnalyzer] = None,
    ):
        self.capturer = capturer or MemoryCapture()
        self.analyzer = analyzer or OfflineMemoryAnalyzer()

    @property
    def mode(self) -> str:
        return "LOW_IMPACT"

    def capture_raw(
        self,
        pid: int,
        policy: str = "ALL_READABLE",
        output_dir: Optional[str] = None,
        max_bytes: int = 32 * 1024 * 1024,
        max_region_bytes: int = 16 * 1024 * 1024,
        timeout_ms: int = 2000,
        snapshot_id: Optional[str] = None,
        selected_ranges: Optional[List[Tuple[int, int]]] = None,
    ) -> RawMemorySnapshot:
        """Capture raw physical memory snapshot without halting the target process."""
        return self.capturer.capture(
            pid=pid,
            policy=policy,
            output_dir=output_dir,
            max_bytes=max_bytes,
            max_region_bytes=max_region_bytes,
            timeout_ms=timeout_ms,
            snapshot_id=snapshot_id,
            selected_ranges=selected_ranges,
        )

    def analyze_offline(
        self,
        raw_snapshot: Union[str, RawMemorySnapshot],
        debug_image: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> RuntimeSnapshot:
        """Reconstruct semantic runtime snapshot offline using DWARF debug artifacts."""
        return self.analyzer.analyze(
            memory_snapshot=raw_snapshot,
            debug_image=debug_image,
            search_paths=search_paths,
        )

    def observe(
        self,
        pid: Optional[int] = None,
        debug_image: Optional[str] = None,
        output_dir: Optional[str] = None,
        policy: str = "ALL_READABLE",
        **kwargs,
    ) -> RuntimeSnapshot:
        """Perform end-to-end low-impact observation: capture followed by offline analysis."""
        if pid is None or pid <= 0:
            raise ValueError(f"Valid PID required for low-impact observation; got {pid}")

        raw_snap = self.capture_raw(pid=pid, policy=policy, output_dir=output_dir)
        return self.analyze_offline(raw_snap, debug_image=debug_image)

    def capabilities(self) -> Dict[str, Any]:
        return {
            "mode": "LOW_IMPACT",
            "process_stop": False,
            "ptrace": False,
            "sigstop": False,
            "sigcont": False,
            "gdb_attached": False,
            "typed_mutation": False,
            "checkpoint_restore": False,
            "branch_exploration": False,
            "execution_context": False,
            "consistency": NON_ATOMIC,
            "backend": "process_vm_readv",
            "offline_analysis": True,
            "module_discovery": True,
            "build_id_verification": True,
            "debuglink": True,
        }
