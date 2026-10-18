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


class EbpfObservationBackend(ObservationBackend):
    """Optional userspace eBPF function tracing observation backend (Phase 1 PoC).

    Truthful capabilities:
    - Zero stop (inferior continues executing)
    - Never uses ptrace, SIGSTOP, SIGCONT, or GDB
    - Observations are isolated probe events (PROBE_POINT_EVENT) at function entry/return
    - Never claimed as a consistent process-wide snapshot
    - DWARF dynamic stack variable evaluation is deferred to Phase 2
    """

    def __init__(self, tracer: Optional[Any] = None):
        from .ebpf_tracer import EbpfTracer
        self.tracer = tracer or EbpfTracer()

    @property
    def mode(self) -> str:
        return "EBPF_PROBE"

    def observe(
        self,
        pid: Optional[int] = None,
        binary: Optional[str] = None,
        function: Optional[str] = None,
        debug_image: Optional[str] = None,
        duration_s: float = 3.0,
        **kwargs,
    ) -> Any:
        if pid is None or pid <= 0:
            raise ValueError(f"Valid PID required for eBPF observation; got {pid}")
        if not binary:
            raise ValueError("Target binary path is required for eBPF uprobe observation")
        if not function:
            raise ValueError("Target function name is required for eBPF uprobe observation")

        return self.tracer.trace(
            pid=pid,
            binary_path=binary,
            function_name=function,
            debug_image=debug_image,
            duration_s=duration_s,
            **kwargs,
        )

    def capabilities(self, active_probe: bool = False) -> Dict[str, Any]:
        from .ebpf_tracer import EbpfEnvironmentChecker
        env = EbpfEnvironmentChecker.check_prerequisites(active_probe=active_probe)
        return {
            "mode": "EBPF_PROBE",
            "process_stop": False,
            "ptrace": False,
            "sigstop": False,
            "sigcont": False,
            "gdb_attached": False,
            "typed_mutation": False,
            "checkpoint_restore": False,
            "branch_exploration": False,
            "execution_context": True,
            "consistency": "PROBE_POINT_EVENT",
            "backend": "ebpf_uprobe",
            "ebpf": True,
            "function_entry_tracing": True,
            "function_return_tracing": True,
            "local_variable_dwarf_eval": True,
            "dwarf_eval_status": "SUPPORTED_PROBE_POINT",
            "arbitrary_instruction_offset_probing": False,
            "stack_locals_readable_at_entry": False,
            "locals_readable_at_return": False,
            "uprobe_offset_status": env.uprobe_offset_status,
            "uprobe_offset_supported": env.supports_uprobe_offset,
            "uprobe_offset_reason": env.uprobe_offset_reason,
            "dwarf_eval_scope": {
                "supported_types": [
                    "int8", "int16", "int32", "int64",
                    "uint8", "uint16", "uint32", "uint64",
                    "float", "double", "bool", "pointer",
                ],
                "supported_expressions": [
                    "DW_OP_reg*", "DW_OP_regx",
                    "DW_OP_fbreg", "DW_OP_breg*", "DW_OP_bregx",
                    "DW_OP_entry_value", ".debug_loc/.debug_loclists ranges",
                ],
                "supported_architectures": ["x86_64", "aarch64"],
                "available_probe_points": [
                    "function_entry (uprobe)",
                    "function_return (uretprobe)",
                ],
                "arbitrary_instruction_offset_probing": False,
                "stack_locals_readable_at_entry": False,
                "locals_readable_at_return": False,
                "uprobe_offset_status": env.uprobe_offset_status,
                "uprobe_offset_supported": env.supports_uprobe_offset,
                "value_sources": ["registers", "process_memory"],
                "notes": (
                    "Stack-resident locals are UNAVAILABLE at function entry prior to prologue "
                    "frame establishment. At function return, locals are UNAVAILABLE due to frame "
                    f"destruction. Nonzero uprobe offset status: {env.uprobe_offset_status}. "
                    "Arbitrary instruction-point local variable evaluation is deferred to Phase 2."
                ),
            },
        }

    def probe_uprobe_offset(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Actively test and cache uprobe offset support."""
        return self.capabilities(active_probe=True)

