"""Phase 23: Target Execution Adapter Abstraction.

Separates target host operations (process identity, liveness, maps, threads,
memory reading) from local host operations.

Enforces:
1. Strict namespace separation: a remote PID is interpreted exclusively on the
   target host; local /proc is never touched for remote targets.
2. Safe argument encoding: all remote commands use shlex.quote.
3. Robust transport error handling: explicit timeouts, connection failures,
   cancellation, and graceful termination.
4. Embedded target friendliness: zero Python or debugger required on the target.
   Build ID and architecture are verified host-side from ELF header bytes.
"""

from abc import ABC, abstractmethod
import base64
from dataclasses import dataclass, field
import errno
import os
import re
import shlex
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import uuid

from .debug_image import BinaryIdentity, inspect_elf, ELFInspectionError
from .observation_budget import (
    validate_non_negative_int,
    validate_non_negative_float,
    ObservationAccountingRecord,
)



def _parse_cpulist(cpulist_str: str) -> List[int]:
    """Parses Linux CPU list format (e.g. '2', '0,2-4') into a sorted list of CPU IDs."""
    cpus: List[int] = []
    if not cpulist_str:
        return cpus
    for part in cpulist_str.strip().split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
                if 0 <= lo <= hi and (hi - lo) <= 1024:
                    cpus.extend(range(lo, hi + 1))
            except ValueError:
                pass
        else:
            try:
                cpus.append(int(part))
            except ValueError:
                pass
    return sorted(set(cpus))


def _get_kernel_isolated_cpus() -> List[int]:
    """Reads /sys/devices/system/cpu/isolated and /sys/devices/system/cpu/nohz_full."""
    isolated: List[int] = []
    for sys_path in ("/sys/devices/system/cpu/isolated", "/sys/devices/system/cpu/nohz_full"):
        try:
            if os.path.exists(sys_path):
                with open(sys_path, "r", encoding="utf-8") as f:
                    isolated.extend(_parse_cpulist(f.read().strip()))
        except Exception:
            pass
    return sorted(set(isolated))


def _adapter_supports_admission(adapter: Any, method_name: str) -> bool:
    """Checks whether an adapter's method accepts 'admission' parameter without invoking it."""
    method = getattr(adapter, method_name, None)
    if not callable(method):
        return False
    try:
        import inspect
        sig = inspect.signature(method)
        for p in sig.parameters.values():
            if p.kind == inspect.Parameter.VAR_KEYWORD:
                return True
            if p.name in ("admission", "budget_tracker"):
                return True
        return False
    except (ValueError, TypeError):
        return False


def _adapter_supports_param(adapter: Any, method_name: str, param_name: str) -> bool:
    """Checks whether an adapter's method accepts a named parameter without invoking it."""
    method = getattr(adapter, method_name, None)
    if not callable(method):
        return False
    try:
        import inspect
        sig = inspect.signature(method)
        for p in sig.parameters.values():
            if p.kind == inspect.Parameter.VAR_KEYWORD or p.name == param_name:
                return True
        return False
    except (ValueError, TypeError):
        return False


def normalize_futex_address(val: Any) -> Tuple[Optional[str], Optional[int], str, Any]:
    """Normalize raw syscall arg0 or lock address into canonical hex string and int.
    
    Requirements:
    - Normalizes integer and hexadecimal-string addresses safely.
    - Rejects zero, negative, malformed, and synthetic placeholder addresses ('0x_lock', '0x_futex_lock', '0x0').
    - Preserves the original raw syscall argument separately from its normalized representation.
    
    Returns:
        (canonical_hex, canonical_int, status, raw_arg)
        where status is 'WAIT_ADDRESS_OBSERVED', 'INVALID_ADDRESS', or 'UNAVAILABLE'.
    """
    raw_arg = val
    if val is None:
        return None, None, "UNAVAILABLE", None
    if isinstance(val, bool):
        return None, None, "INVALID_ADDRESS", raw_arg
    if isinstance(val, int):
        if val <= 0:
            return None, None, "INVALID_ADDRESS", raw_arg
        return f"0x{val:x}", val, "WAIT_ADDRESS_OBSERVED", raw_arg
    if isinstance(val, str):
        v = val.strip()
        if not v or v in ("0", "0x0", "0x_lock", "0x_futex_lock") or "lock" in v.lower():
            return None, None, "INVALID_ADDRESS", raw_arg
        try:
            if v.startswith("0x") or v.startswith("0X"):
                i_val = int(v, 16)
            elif v.startswith("-"):
                return None, None, "INVALID_ADDRESS", raw_arg
            else:
                i_val = int(v, 10)
            if i_val <= 0:
                return None, None, "INVALID_ADDRESS", raw_arg
            return f"0x{i_val:x}", i_val, "WAIT_ADDRESS_OBSERVED", raw_arg
        except (ValueError, TypeError):
            return None, None, "INVALID_ADDRESS", raw_arg
    return None, None, "INVALID_ADDRESS", raw_arg


STATUS_OWNER_IDENTIFIED = "OWNER_IDENTIFIED"
STATUS_OWNER_NOT_IDENTIFIED = "OWNER_NOT_IDENTIFIED"
STATUS_MUTEX_LAYOUT_UNSUPPORTED = "MUTEX_LAYOUT_UNSUPPORTED"
STATUS_MUTEX_STATE_INVALID = "MUTEX_STATE_INVALID"
STATUS_MEMORY_READ_UNAVAILABLE = "MEMORY_READ_UNAVAILABLE"
STATUS_PERMISSION_DENIED = "PERMISSION_DENIED"

# Libc / ABI Verification Statuses
ABI_GLIBC_VERIFIED = "GLIBC_ABI_VERIFIED"
ABI_MUSL_UNSUPPORTED = "MUSL_UNSUPPORTED"
ABI_LIBC_UNKNOWN = "LIBC_UNKNOWN"
ABI_STATIC_OR_UNIDENTIFIED = "STATIC_OR_UNIDENTIFIED_RUNTIME"
ABI_ARCH_UNSUPPORTED = "ARCHITECTURE_UNSUPPORTED"
ABI_ELF_CLASS_UNSUPPORTED = "ELF_CLASS_UNSUPPORTED"
ABI_ENDIANNESS_UNSUPPORTED = "ENDIANNESS_UNSUPPORTED"

# Process Identity Verification Statuses
IDENTITY_VERIFIED = "IDENTITY_VERIFIED"
IDENTITY_UNAVAILABLE = "IDENTITY_UNAVAILABLE"
IDENTITY_INCONSISTENT = "IDENTITY_INCONSISTENT"
IDENTITY_UNVERIFIED = "IDENTITY_UNVERIFIED"

LAYOUT_GLIBC_LP64 = "GLIBC_LP64_PTHREAD_MUTEX_V1"


@dataclass
class MutexOwnerResolutionResult:
    """Detailed and auditable result of a pthread_mutex owner resolution attempt.
    
    Guarantees:
    - Explicit verification status (OWNER_IDENTIFIED, OWNER_NOT_IDENTIFIED, etc.)
    - Preserves raw bytes and interpretation metadata
    - Gracefully backward compatible with integer TID checks
    """
    status: str
    owner_tid: Optional[int] = None
    layout_id: Optional[str] = None
    raw_bytes: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def __bool__(self) -> bool:
        return self.status == STATUS_OWNER_IDENTIFIED and self.owner_tid is not None

    def __int__(self) -> int:
        return int(self.owner_tid or 0)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            return self.owner_tid == other
        if isinstance(other, MutexOwnerResolutionResult):
            return self.status == other.status and self.owner_tid == other.owner_tid
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "owner_tid": self.owner_tid,
            "layout_id": self.layout_id,
            "raw_bytes": self.raw_bytes.hex() if self.raw_bytes else None,
            "metadata": self.metadata,
            "error": self.error,
        }


class TargetExecutionAdapter(ABC):
    """Abstract interface for interacting with a local or remote target process."""

    @abstractmethod
    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        """Checks if target process is currently alive and accessible.
        
        Returns:
            (True, None) if alive.
            (False, error_reason) if dead, inaccessible, or transport failure.
        """
        pass

    @abstractmethod
    def get_process_identity(
        self,
        pid: int,
        companion_build_id: Optional[str] = None,
        companion_elf_path: Optional[str] = None,
        budget_tracker: Optional[Any] = None,
        operation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers executable path, architecture, build ID, and ELF type."""
        pass

    def get_process_memory_info(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Reads detailed process memory metrics from /proc/<pid>/statm, /proc/<pid>/status,
        and /proc/<pid>/smaps_rollup (bounded, low-impact).
        
        Strictly distinguishes:
        - Virtual memory size (VSZ)
        - Resident set size (RSS)
        - Mapping size
        - Writable anonymous mapping size
        - Heap mapping size
        - Actual allocation evidence (documented procfs limitation)
        - Object lifetime / release evidence (documented procfs limitation)
        """
        return {"status": "UNAVAILABLE", "pid": pid, "metrics": {}, "mappings_summary": {}, "metadata": {}}

    @abstractmethod
    def get_proc_maps(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Reads /proc/<pid>/maps and returns structured memory mappings."""
        pass

    def get_memory_mappings(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Convenience alias for get_proc_maps."""
        return self.get_proc_maps(pid, admission=admission, budget_tracker=budget_tracker)

    @abstractmethod
    def get_threads(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Discovers active threads from /proc/<pid>/task."""
        pass

    @abstractmethod
    def read_memory(
        self,
        pid: int,
        address: int,
        size: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
        child_read: Optional[Any] = None,
    ) -> Tuple[Optional[bytes], str, Optional[str]]:
        """Reads raw bytes from target memory without suspending the process.
        
        Returns:
            (bytes, "OBSERVED", None) on full success.
            (partial_bytes, "PARTIAL", msg) on partial read.
            (None, "UNAVAILABLE", reason) if unmapped or read error.
            (None, "TARGET_TERMINATED", reason) if target exited.
            (None, "PERMISSION_DENIED", reason) if permission denied.
        """
        pass

    def read_memory_batch(
        self,
        pid: int,
        slices: List[Tuple[int, int]],
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Tuple[Optional[bytes], str, Optional[str]]]:
        """Reads multiple (address, size) slices in a single batch operation when supported."""
        eff_tracker = budget_tracker or getattr(self, "_budget_tracker", None)
        if eff_tracker is None:
            from .observation_budget import ObservationBudgetTracker
            eff_tracker = ObservationBudgetTracker.get_active_thread_tracker()

        total_proj = sum(sz for _, sz in slices)
        adm = admission
        own_adm = False
        if adm is None and eff_tracker is not None:
            if eff_tracker.is_budget_exhausted:
                return [(None, "BUDGET_EXHAUSTED", f"Observation budget exhausted: {eff_tracker.exhaustion_reason}") for _ in slices]
            active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
            try:
                if active_scope is not None and not active_scope.is_finalized:
                    adm = active_scope.admit_read(projected_bytes=total_proj, profile_id="memory_read_batch")
                else:
                    adm = eff_tracker.admit_read(projected_bytes=total_proj, profile_id="memory_read_batch")
                own_adm = True
            except ValueError as ve:
                return [(None, "BUDGET_EXHAUSTED", f"Observation budget admission rejected: {ve}") for _ in slices]

        if adm is not None and not adm.is_terminal:
            adm.mark_physical_read_started()

        results = []
        any_failure = False
        for idx, (addr, sz) in enumerate(slices):
            child_read = None
            if adm is not None:
                child_read = adm.start_child_read(
                    target_type="memory_slice",
                    target_spec={"pid": pid, "address": addr, "size": sz, "slice_index": idx},
                )

            if _adapter_supports_admission(self, "read_memory"):
                kwargs = {"admission": adm, "budget_tracker": eff_tracker}
                if _adapter_supports_param(self, "read_memory", "child_read"):
                    kwargs["child_read"] = child_read
                res = self.read_memory(pid, addr, sz, **kwargs)
            else:
                res = self.read_memory(pid, addr, sz)
            results.append(res)
            raw_b, st, _ = res
            act_b = len(raw_b) if raw_b else 0
            is_fail = (st not in ("OBSERVED", "PARTIAL"))
            if is_fail:
                any_failure = True
            if child_read is not None:
                if child_read.state == "ADMITTED":
                    child_read.release()
                elif child_read.state == "PHYSICAL_READ_STARTED":
                    child_read.consume(actual_bytes=act_b, is_failure=is_fail)

        if own_adm and adm is not None and eff_tracker is not None:
            tot_b = adm.consumed_bytes
            if tot_b > 0 or adm.state == "CONSUMED":
                active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
                if active_scope is not None and not active_scope.is_finalized:
                    active_scope.record_read(bytes_read=tot_b, admission=adm, profile_id="memory_read_batch", is_failure=any_failure)
                else:
                    eff_tracker.commit_transaction(
                        operation_id=f"standalone_batch_{uuid.uuid4().hex[:8]}",
                        profile_id="memory_read_batch",
                        measured_bytes=tot_b,
                        is_failure=any_failure,
                        reservations=[adm],
                    )
            else:
                if adm.state in ("ADMITTED", "RESERVED"):
                    eff_tracker.release_reservation(adm)
        return results
        return results

    @abstractmethod
    def is_remote(self) -> bool:
        """Returns True if the target is on a remote host, False if local."""
        pass

    def set_budget_tracker(self, tracker: Any) -> None:
        """Sets the observation budget tracker for this adapter."""
        self._budget_tracker = tracker

    def get_budget_tracker(self) -> Optional[Any]:
        """Returns the observation budget tracker for this adapter, if set."""
        return getattr(self, "_budget_tracker", None)

    @abstractmethod
    def target_host(self) -> str:
        """Returns the target host identifier (e.g. 'localhost' or 'user@host:port')."""
        pass

    def find_processes(
        self,
        process_name: Optional[str] = None,
        companion_build_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Discovers running processes on the target host, optionally filtered by name or Build ID."""
        return []

    def resolve_mutex_owner(
        self,
        pid: int,
        lock_addr: Union[int, str],
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> MutexOwnerResolutionResult:
        """Resolves mutex owner TID for given lock address if readable and verified, or returns resolution result."""
        return MutexOwnerResolutionResult(
            status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
            error="Mutex owner resolution is not supported on this adapter type",
        )

    def normalize_futex_address(self, val: Any) -> Tuple[Optional[str], Optional[int], str, Any]:
        """Normalize raw syscall arg0 or lock address into canonical hex string and int."""
        return normalize_futex_address(val)

    def get_last_threads_bytes_read(self) -> int:
        """Returns the measured byte count read during the last get_threads call."""
        return getattr(self, "_last_threads_bytes_read", 0)

    def get_last_maps_bytes_read(self) -> int:
        """Returns the measured byte count read during the last get_proc_maps call."""
        return getattr(self, "_last_maps_bytes_read", 0)

    def get_last_identity_bytes_read(self) -> int:
        """Returns the measured byte count read during the last get_process_identity call."""
        return getattr(self, "_last_identity_bytes_read", 0)

    def get_last_identity_latency_us(self) -> float:
        """Returns the measured observation latency in microseconds during the last get_process_identity call."""
        return getattr(self, "_last_identity_latency_us", 0.0)

    def get_last_identity_breakdown(self) -> Dict[str, Any]:
        """Returns detailed breakdown of measured and cached bytes during last get_process_identity call."""
        return getattr(self, "_last_identity_breakdown", {
            "readlink_bytes": 0,
            "stat_bytes": 0,
            "elf_bytes_read": 0,
            "elf_bytes_from_cache": 0,
            "total_measured_bytes": 0,
            "estimated_bytes_read": 0,
            "measurement_status": "UNAVAILABLE",
        })

    def get_last_identity_status(self) -> str:
        """Returns measurement status of last get_process_identity call."""
        return getattr(self, "_last_identity_status", "UNAVAILABLE")

    def get_last_threads_breakdown(self) -> Dict[str, int]:
        """Returns breakdown of bytes read during last get_threads call."""
        return getattr(self, "_last_threads_breakdown", {"maps_bytes": 0, "task_bytes": 0, "memory_bytes": 0, "total_bytes": 0})

    def close(self) -> None:
        """Clean up any active connection or temporary resources."""
        pass


class ReadOnlyTargetAdapter(TargetExecutionAdapter):
    """Strict capability boundary wrapping TargetExecutionAdapter.

    Exposes ONLY pre-approved read-only query methods.
    Blocks any mutating methods, arbitrary command runners, or write operations with PermissionError.
    """
    PERMITTED_READ_METHODS = {
        "check_liveness",
        "get_process_identity",
        "get_process_memory_info",
        "get_proc_maps",
        "get_memory_mappings",
        "get_threads",
        "read_memory",
        "read_memory_batch",
        "resolve_mutex_owner",
        "normalize_futex_address",
        "is_remote",
        "target_host",
        "find_processes",
        "close",
        "get_last_threads_bytes_read",
        "get_last_maps_bytes_read",
        "get_last_identity_bytes_read",
        "get_last_identity_latency_us",
        "get_last_identity_breakdown",
        "get_last_identity_status",
        "get_last_threads_breakdown",
        "_last_threads_bytes_read",
        "_last_maps_bytes_read",
        "_last_identity_bytes_read",
        "_last_identity_latency_us",
        "_last_identity_estimated_bytes",
        "_last_identity_breakdown",
        "_last_identity_status",
        "_last_threads_breakdown",
        "set_budget_tracker",
        "get_budget_tracker",
        "_budget_tracker",
    }

    def __init__(self, inner: TargetExecutionAdapter, budget_tracker: Optional[Any] = None):
        if isinstance(inner, ReadOnlyTargetAdapter):
            self._inner = inner._inner
        else:
            self._inner = inner
        self._budget_tracker = budget_tracker
        if hasattr(self._inner, "set_budget_tracker"):
            self._inner.set_budget_tracker(budget_tracker)

    def set_budget_tracker(self, tracker: Any) -> None:
        self._budget_tracker = tracker
        if hasattr(self._inner, "set_budget_tracker"):
            self._inner.set_budget_tracker(tracker)

    def get_budget_tracker(self) -> Optional[Any]:
        return getattr(self, "_budget_tracker", None) or (self._inner.get_budget_tracker() if hasattr(self._inner, "get_budget_tracker") else None)

    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        return self._inner.check_liveness(pid)

    def get_process_identity(
        self,
        pid: int,
        companion_build_id: Optional[str] = None,
        companion_elf_path: Optional[str] = None,
        budget_tracker: Optional[Any] = None,
        operation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        eff_tracker = budget_tracker or self.get_budget_tracker()
        return self._inner.get_process_identity(
            pid,
            companion_build_id=companion_build_id,
            companion_elf_path=companion_elf_path,
            budget_tracker=eff_tracker,
            operation_id=operation_id,
        )

    def get_process_memory_info(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> Dict[str, Any]:
        eff_tracker = budget_tracker or self.get_budget_tracker()
        supports_adm = _adapter_supports_admission(self._inner, "get_process_memory_info")
        if eff_tracker is not None:
            if not supports_adm:
                raise PermissionError(
                    f"Target adapter {type(self._inner).__name__} does not support budget admission, "
                    f"but budget tracking is active."
                )
            return self._inner.get_process_memory_info(pid, admission=admission, budget_tracker=eff_tracker)
        else:
            if supports_adm:
                return self._inner.get_process_memory_info(pid, admission=admission, budget_tracker=None)
            return self._inner.get_process_memory_info(pid)

    def get_proc_maps(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        eff_tracker = budget_tracker or self.get_budget_tracker()
        supports_adm = _adapter_supports_admission(self._inner, "get_proc_maps")
        if eff_tracker is not None:
            if not supports_adm:
                raise PermissionError(
                    f"Target adapter {type(self._inner).__name__} does not support budget admission, "
                    f"but budget tracking is active."
                )
            return self._inner.get_proc_maps(pid, admission=admission, budget_tracker=eff_tracker)
        else:
            if supports_adm:
                return self._inner.get_proc_maps(pid, admission=admission, budget_tracker=None)
            return self._inner.get_proc_maps(pid)

    def get_memory_mappings(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        return self.get_proc_maps(pid, admission=admission, budget_tracker=budget_tracker)

    def get_threads(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        eff_tracker = budget_tracker or self.get_budget_tracker()
        supports_adm = _adapter_supports_admission(self._inner, "get_threads")
        if eff_tracker is not None:
            if not supports_adm:
                raise PermissionError(
                    f"Target adapter {type(self._inner).__name__} does not support budget admission, "
                    f"but budget tracking is active."
                )
            return self._inner.get_threads(pid, admission=admission, budget_tracker=eff_tracker)
        else:
            if supports_adm:
                return self._inner.get_threads(pid, admission=admission, budget_tracker=None)
            return self._inner.get_threads(pid)

    def read_memory(
        self,
        pid: int,
        address: int,
        size: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
        child_read: Optional[Any] = None,
    ) -> Tuple[Optional[bytes], str, Optional[str]]:
        eff_tracker = budget_tracker or self.get_budget_tracker()
        supports_adm = _adapter_supports_admission(self._inner, "read_memory")
        supports_cr = _adapter_supports_param(self._inner, "read_memory", "child_read")
        kwargs = {}
        if supports_cr and child_read is not None:
            kwargs["child_read"] = child_read
        if eff_tracker is not None:
            if not supports_adm:
                raise PermissionError(
                    f"Target adapter {type(self._inner).__name__} does not support budget admission, "
                    f"but budget tracking is active."
                )
            return self._inner.read_memory(pid, address, size, admission=admission, budget_tracker=eff_tracker, **kwargs)
        else:
            if supports_adm:
                return self._inner.read_memory(pid, address, size, admission=admission, budget_tracker=None, **kwargs)
            return self._inner.read_memory(pid, address, size)

    def read_memory_batch(
        self,
        pid: int,
        requests: List[Tuple[int, int]],
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Tuple[Optional[bytes], str, Optional[str]]]:
        eff_tracker = budget_tracker or self.get_budget_tracker()
        supports_adm = _adapter_supports_admission(self._inner, "read_memory_batch")
        if eff_tracker is not None:
            if not supports_adm:
                raise PermissionError(
                    f"Target adapter {type(self._inner).__name__} does not support budget admission, "
                    f"but budget tracking is active."
                )
            return self._inner.read_memory_batch(pid, requests, admission=admission, budget_tracker=eff_tracker)
        else:
            if supports_adm:
                return self._inner.read_memory_batch(pid, requests, admission=admission, budget_tracker=None)
            return self._inner.read_memory_batch(pid, requests)

    def resolve_mutex_owner(
        self,
        pid: int,
        lock_addr: Union[int, str],
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> MutexOwnerResolutionResult:
        eff_tracker = budget_tracker or self.get_budget_tracker()
        if _adapter_supports_admission(self._inner, "resolve_mutex_owner"):
            return self._inner.resolve_mutex_owner(pid, lock_addr, admission=admission, budget_tracker=eff_tracker)
        return self._inner.resolve_mutex_owner(pid, lock_addr)

    def get_last_threads_bytes_read(self) -> int:
        return self._inner.get_last_threads_bytes_read()

    def get_last_maps_bytes_read(self) -> int:
        return self._inner.get_last_maps_bytes_read()

    def get_last_identity_bytes_read(self) -> int:
        return self._inner.get_last_identity_bytes_read()

    def get_last_identity_latency_us(self) -> float:
        return self._inner.get_last_identity_latency_us()

    def get_last_identity_breakdown(self) -> Dict[str, Any]:
        return self._inner.get_last_identity_breakdown()

    def get_last_identity_status(self) -> str:
        return self._inner.get_last_identity_status()

    def get_last_threads_breakdown(self) -> Dict[str, int]:
        return self._inner.get_last_threads_breakdown()

    def normalize_futex_address(self, val: Any) -> Tuple[Optional[str], Optional[int], str, Any]:
        return self._inner.normalize_futex_address(val)

    def is_remote(self) -> bool:
        return self._inner.is_remote()

    def target_host(self) -> str:
        return self._inner.target_host()

    def find_processes(
        self,
        process_name: Optional[str] = None,
        companion_build_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        return self._inner.find_processes(
            process_name=process_name,
            companion_build_id=companion_build_id,
            limit=limit,
        )

    def close(self) -> None:
        self._inner.close()

    def __getattr__(self, name: str) -> Any:
        if name in self.PERMITTED_READ_METHODS:
            return getattr(self._inner, name)
        raise PermissionError(
            f"Access to capability or attribute '{name}' is strictly denied: "
            "ReadOnlyTargetAdapter allows only permitted read-only target queries."
        )

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_inner", "_budget_tracker"):
            super().__setattr__(name, value)
        else:
            raise PermissionError(
                f"Modifying attribute '{name}' on ReadOnlyTargetAdapter is forbidden."
            )


class LocalTargetAdapter(TargetExecutionAdapter):
    """Execution adapter for local Linux processes using direct /proc and process_vm_readv."""

    def __init__(
        self,
        memory_reader_fn: Optional[Callable[[int, int, int], Tuple[Optional[bytes], str, Optional[str]]]] = None,
        budget_tracker: Optional[Any] = None,
    ):
        self._memory_reader = memory_reader_fn
        self._budget_tracker = budget_tracker
        self._last_threads_bytes_read: int = 0
        self._last_maps_bytes_read: int = 0
        self._last_identity_bytes_read: int = 0
        self._last_identity_estimated_bytes: int = 0
        self._last_identity_latency_us: float = 0.0
        self._last_identity_status: str = "UNAVAILABLE"
        self._last_identity_breakdown: Dict[str, Any] = {
            "readlink_bytes": 0,
            "stat_bytes": 0,
            "elf_bytes_read": 0,
            "elf_bytes_from_cache": 0,
            "total_measured_bytes": 0,
            "estimated_bytes_read": 0,
            "measurement_status": "UNAVAILABLE",
        }
        self._last_threads_breakdown: Dict[str, int] = {"maps_bytes": 0, "task_bytes": 0, "memory_bytes": 0, "total_bytes": 0}

    def set_budget_tracker(self, tracker: Any) -> None:
        self._budget_tracker = tracker

    def get_budget_tracker(self) -> Optional[Any]:
        return getattr(self, "_budget_tracker", None)

    def is_remote(self) -> bool:
        return False

    def target_host(self) -> str:
        try:
            return os.uname().nodename
        except Exception:
            return "localhost"

    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            return False, f"Invalid or reserved system PID {pid} (must be integer > 1)"
        try:
            os.kill(pid, 0)
            stat_path = f"/proc/{pid}/stat"
            if os.path.exists(stat_path):
                try:
                    with open(stat_path, "r", encoding="utf-8", errors="replace") as f:
                        parts = f.read().split()
                        if len(parts) >= 3 and parts[2] in ("Z", "X"):
                            return False, f"Target PID {pid} has terminated (state={parts[2]})"
                except Exception:
                    pass
            return True, None
        except ProcessLookupError:
            return False, f"Target PID {pid} was not found (ESRCH)"
        except PermissionError:
            return False, f"Permission denied accessing target PID {pid} (EPERM)"
        except Exception as e:
            return False, f"Liveness check failed for PID {pid}: {e}"

    def get_process_identity(
        self,
        pid: int,
        companion_build_id: Optional[str] = None,
        companion_elf_path: Optional[str] = None,
        budget_tracker: Optional[Any] = None,
        operation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers process executable, architecture, build ID, and validates process identity.

        Strict Identity Verification Contract:
        - IDENTITY_VERIFIED proves:
          1. Process liveness and existence observed at T0 and T1 via os.kill(pid, 0).
          2. Matching start time observed at T0 and T1 (/proc/<pid>/stat), proving no PID reuse.
          3. Matching executable symlink observed at T0 and T1 (/proc/<pid>/exe).
          4. Stable executable file descriptor opened directly (/proc/<pid>/exe), verified with fstat().
          5. ELF parsing executed directly on that exact open file descriptor without reopening.
          6. Valid non-unknown ELF architecture and ELF class (ELF32/ELF64).
          7. If companion build ID specified, exact byte-for-byte match with runtime ELF build ID.

        - IDENTITY_VERIFIED does NOT prove:
          1. Does NOT prove cryptographic attestation or TPM hardware-rooted trust.
          2. Does NOT prove that target process memory has not been altered via ptrace,
             code injection, or dynamic library preloading (LD_PRELOAD).
          3. Does NOT prove identity across sampling epochs (verified per-epoch).
          4. Does NOT prove libc version or dynamic linker internals beyond ELF headers.
        """
        empty_breakdown = {
            "readlink_bytes": 0,
            "stat_bytes": 0,
            "elf_bytes_read": 0,
            "elf_bytes_from_cache": 0,
            "total_measured_bytes": 0,
            "estimated_bytes_read": 0,
            "measurement_status": "UNAVAILABLE",
        }
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            self._last_identity_bytes_read = 0
            self._last_identity_estimated_bytes = 0
            self._last_identity_status = "UNAVAILABLE"
            self._last_identity_breakdown = empty_breakdown
            self._last_identity_latency_us = 0.0
            return {
                "pid": pid,
                "status": "FAILED",
                "identity_status": IDENTITY_UNAVAILABLE,
                "executable": "",
                "architecture": "unknown",
                "elf_class": "unknown",
                "endianness": "unknown",
                "elf_type": "unknown",
                "build_id": None,
                "is_deleted": False,
                "process_start_time": None,
                "has_debug_info": False,
                "is_remote": False,
                "host": self.target_host(),
                "error": f"Invalid PID {pid}",
                "measured_bytes_read": 0,
                "estimated_bytes_read": 0,
                "charged_bytes": 0,
                "measurement_status": "UNAVAILABLE",
                "measurement_type": "UNKNOWN",
                "accounting_owner": "ADAPTER",
                "accounting_status": "COMMITTED",
                "measurement_breakdown": empty_breakdown,
            }

        eff_tracker = budget_tracker or getattr(self, "_budget_tracker", None)
        if eff_tracker is None:
            from .observation_budget import ObservationBudgetTracker
            eff_tracker = ObservationBudgetTracker.get_active_thread_tracker()

        op_id = operation_id or f"proc_identity_{pid}_{uuid.uuid4().hex[:8]}"
        adm = None
        if eff_tracker is not None:
            if eff_tracker.is_budget_exhausted:
                self._last_identity_bytes_read = 0
                self._last_identity_estimated_bytes = 0
                self._last_identity_status = "BUDGET_EXHAUSTED"
                self._last_identity_breakdown = empty_breakdown
                self._last_identity_latency_us = 0.0
                return {
                    "pid": pid,
                    "status": "BUDGET_EXHAUSTED",
                    "identity_status": IDENTITY_UNAVAILABLE,
                    "executable": "",
                    "architecture": "unknown",
                    "elf_class": "unknown",
                    "endianness": "unknown",
                    "elf_type": "unknown",
                    "build_id": None,
                    "build_id_status": "UNAVAILABLE",
                    "process_start_time": None,
                    "is_remote": False,
                    "is_deleted": False,
                    "has_debug_info": False,
                    "error": "Observation budget exhausted before target identity read",
                    "charged_bytes": 0,
                    "measured_bytes_read": 0,
                    "estimated_bytes_read": 0,
                    "measurement_type": "UNKNOWN",
                    "accounting_owner": "ADAPTER",
                    "accounting_status": "FAILED",
                    "measurement_breakdown": empty_breakdown,
                }
            active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
            try:
                if active_scope is not None and not active_scope.is_finalized:
                    adm = active_scope.admit_read(projected_bytes=min(4096, max(256, eff_tracker.remaining_bytes)), profile_id="target_identity")
                else:
                    adm = eff_tracker.admit_read(projected_bytes=min(4096, max(256, eff_tracker.remaining_bytes)), profile_id="target_identity", operation_id=op_id)
            except ValueError as ve:
                self._last_identity_bytes_read = 0
                self._last_identity_estimated_bytes = 0
                self._last_identity_status = "BUDGET_EXHAUSTED"
                self._last_identity_breakdown = empty_breakdown
                self._last_identity_latency_us = 0.0
                return {
                    "pid": pid,
                    "status": "BUDGET_EXHAUSTED",
                    "identity_status": IDENTITY_UNAVAILABLE,
                    "executable": "",
                    "architecture": "unknown",
                    "elf_class": "unknown",
                    "endianness": "unknown",
                    "elf_type": "unknown",
                    "build_id": None,
                    "is_deleted": False,
                    "process_start_time": None,
                    "has_debug_info": False,
                    "is_remote": False,
                    "host": self.target_host(),
                    "error": f"Observation budget admission rejected: {ve}",
                    "measured_bytes_read": 0,
                    "estimated_bytes_read": 0,
                    "charged_bytes": 0,
                    "measurement_status": "BUDGET_EXHAUSTED",
                    "measurement_type": "UNKNOWN",
                    "accounting_owner": "ADAPTER",
                    "accounting_status": "FAILED",
                    "measurement_breakdown": empty_breakdown,
                }

        if adm is not None:
            adm.mark_physical_read_started()

        # Check process liveness (T0)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            if adm is not None and eff_tracker is not None and adm.state in ("ADMITTED", "RESERVED"):
                eff_tracker.release_reservation(adm)
            self._last_identity_bytes_read = 0
            self._last_identity_estimated_bytes = 0
            self._last_identity_status = "UNAVAILABLE"
            self._last_identity_breakdown = empty_breakdown
            self._last_identity_latency_us = 0.0
            return {
                "pid": pid,
                "status": "TARGET_TERMINATED",
                "identity_status": IDENTITY_UNAVAILABLE,
                "executable": "",
                "architecture": "unknown",
                "elf_class": "unknown",
                "endianness": "unknown",
                "elf_type": "unknown",
                "build_id": None,
                "is_deleted": False,
                "process_start_time": None,
                "has_debug_info": False,
                "is_remote": False,
                "host": self.target_host(),
                "error": f"Target PID {pid} was not found (ESRCH)",
                "measured_bytes_read": 0,
                "estimated_bytes_read": 0,
                "charged_bytes": 0,
                "measurement_status": "UNAVAILABLE",
                "measurement_type": "UNKNOWN",
                "accounting_owner": "ADAPTER",
                "accounting_status": "COMMITTED",
                "measurement_breakdown": empty_breakdown,
            }
        except PermissionError:
            pass

        t_id_start = time.monotonic()
        readlink_bytes = 0
        stat_bytes = 0
        elf_bytes_read = 0
        elf_bytes_from_cache = 0
        estimated_bytes_read = 0
        is_deleted = False
        link_status = "OBSERVED"
        link_err = None
        raw_link = ""
        runtime_exe = ""
        pid_reused = False
        exe_changed = False
        exe_inconsistent = False
        terminated_during_inspection = False

        # 1. Initial read of /proc/<pid>/stat (T0)
        start_time_0 = None
        stat_path = f"/proc/{pid}/stat"
        if os.path.exists(stat_path):
            try:
                with open(stat_path, "r", encoding="utf-8", errors="replace") as f:
                    stat_content_0 = f.read()
                stat_bytes += len(stat_content_0.encode("utf-8", errors="replace"))
                r_paren = stat_content_0.rfind(")")
                if r_paren != -1:
                    fields = stat_content_0[r_paren + 1:].split()
                    if len(fields) >= 20:
                        raw_st0 = int(fields[19])
                        if raw_st0 > 0:
                            start_time_0 = raw_st0
            except ProcessLookupError:
                terminated_during_inspection = True
            except Exception:
                pass

        # 2. Inspect /proc/<pid>/exe link (T0)
        try:
            raw_link = os.readlink(f"/proc/{pid}/exe")
            readlink_bytes += len(raw_link.encode("utf-8", errors="replace"))
            if raw_link.endswith(" (deleted)"):
                is_deleted = True
                runtime_exe = raw_link[:-len(" (deleted)")]
            else:
                runtime_exe = raw_link
        except PermissionError:
            link_status = "PERMISSION_DENIED"
            link_err = f"Permission denied reading /proc/{pid}/exe"
        except FileNotFoundError:
            link_status = "NOT_FOUND"
            link_err = f"/proc/{pid}/exe does not exist"
        except ProcessLookupError:
            terminated_during_inspection = True
        except Exception as e:
            link_status = "FAILED"
            link_err = str(e)

        # 3. Stable executable inspection and ELF identity
        runtime_identity: Optional[BinaryIdentity] = None
        elf_error = None
        stable_fd_verified = False

        if not terminated_during_inspection and link_status == "OBSERVED":
            try:
                # Open stable descriptor directly to /proc/<pid>/exe
                with open(f"/proc/{pid}/exe", "rb") as fd:
                    fd_stat = os.fstat(fd.fileno())
                    if runtime_exe and os.path.exists(runtime_exe) and not is_deleted:
                        try:
                            exe_stat = os.stat(runtime_exe)
                            if fd_stat.st_dev != exe_stat.st_dev or fd_stat.st_ino != exe_stat.st_ino:
                                exe_inconsistent = True
                        except Exception:
                            pass
                    # CRITICAL FIX: Pass the EXACT OPEN FILE DESCRIPTOR to inspect_elf!
                    # inspect_elf uses fstat on that exact descriptor and does not close it.
                    runtime_identity = inspect_elf(fd)
                    elf_bytes_read += runtime_identity.bytes_read
                    if runtime_identity.cached:
                        elf_bytes_from_cache += runtime_identity.cache_bytes_read
                    stable_fd_verified = True
            except (FileNotFoundError, ProcessLookupError):
                terminated_during_inspection = True
            except PermissionError as pe:
                link_status = "PERMISSION_DENIED"
                link_err = str(pe)
            except ELFInspectionError as eie:
                elf_error = str(eie)
                elf_bytes_read += getattr(eie, "bytes_read", 0)
            except Exception as exc:
                elf_error = str(exc)
                elf_bytes_read += getattr(exc, "bytes_read", 0)

        # 4. Post-inspection verification (T1) to detect PID reuse or executable change
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            terminated_during_inspection = True

        start_time_1 = None
        if not terminated_during_inspection and os.path.exists(stat_path):
            try:
                with open(stat_path, "r", encoding="utf-8", errors="replace") as f:
                    stat_content_1 = f.read()
                stat_bytes += len(stat_content_1.encode("utf-8", errors="replace"))
                r_paren = stat_content_1.rfind(")")
                if r_paren != -1:
                    fields = stat_content_1[r_paren + 1:].split()
                    if len(fields) >= 20:
                        raw_st1 = int(fields[19])
                        if raw_st1 > 0:
                            start_time_1 = raw_st1
                if start_time_0 is not None and start_time_1 is not None and start_time_0 != start_time_1:
                    pid_reused = True
            except ProcessLookupError:
                terminated_during_inspection = True
            except Exception:
                pass

        raw_link_1 = None
        link_status_1 = "PENDING"
        if not terminated_during_inspection and link_status == "OBSERVED":
            try:
                raw_link_1 = os.readlink(f"/proc/{pid}/exe")
                readlink_bytes += len(raw_link_1.encode("utf-8", errors="replace"))
                link_status_1 = "OBSERVED"
                if raw_link_1 != raw_link:
                    exe_changed = True
            except PermissionError:
                link_status_1 = "PERMISSION_DENIED"
            except (FileNotFoundError, ProcessLookupError):
                terminated_during_inspection = True
            except Exception:
                link_status_1 = "FAILED"

        # 5. Companion Build ID validation if specified
        build_id_val = runtime_identity.build_id if runtime_identity else None
        build_id_status = "NOT_SPECIFIED"
        build_id_mismatch = False
        build_id_unavailable = False

        target_comp_bid = companion_build_id
        if not target_comp_bid and companion_elf_path and os.path.exists(companion_elf_path):
            try:
                comp_ident = inspect_elf(companion_elf_path)
                target_comp_bid = comp_ident.build_id
                if comp_ident.cached:
                    elf_bytes_from_cache += comp_ident.cache_bytes_read
                else:
                    elf_bytes_read += comp_ident.bytes_read
            except Exception as exc:
                elf_bytes_read += getattr(exc, "bytes_read", 0)

        if target_comp_bid:
            if not build_id_val:
                build_id_status = "BUILD_ID_UNAVAILABLE"
                build_id_unavailable = True
            elif build_id_val != target_comp_bid:
                build_id_status = "BUILD_ID_MISMATCH"
                build_id_mismatch = True
            else:
                build_id_status = "BUILD_ID_MATCHED"

        # 6. Status determination adhering to strict identity verification contract
        if terminated_during_inspection:
            status_val = "TARGET_TERMINATED"
            identity_status = IDENTITY_UNAVAILABLE
        elif link_status == "PERMISSION_DENIED" or link_status_1 == "PERMISSION_DENIED":
            status_val = "PERMISSION_DENIED"
            identity_status = IDENTITY_UNAVAILABLE
        elif pid_reused or exe_changed or exe_inconsistent or build_id_mismatch:
            status_val = "INCONSISTENT"
            identity_status = IDENTITY_INCONSISTENT
        elif (
            link_status == "OBSERVED"
            and link_status_1 == "OBSERVED"
            and not is_deleted
            and raw_link == raw_link_1
            and start_time_0 is not None
            and start_time_1 is not None
            and start_time_0 > 0
            and start_time_0 == start_time_1
            and stable_fd_verified
            and runtime_identity is not None
            and runtime_identity.architecture != "unknown"
            and not build_id_unavailable
            and not build_id_mismatch
        ):
            status_val = "OBSERVED"
            identity_status = IDENTITY_VERIFIED
        elif link_status == "OBSERVED":
            status_val = "OBSERVED"
            identity_status = IDENTITY_UNVERIFIED
        else:
            status_val = "FAILED"
            identity_status = IDENTITY_UNAVAILABLE

        # 7. Exact measurement accounting (NO synthetic byte additions!)
        total_measured_bytes = readlink_bytes + stat_bytes + elf_bytes_read
        meas_status = (
            "EXACT_MEASURED" if (total_measured_bytes > 0 and elf_bytes_from_cache == 0)
            else ("CACHE_HIT" if (elf_bytes_from_cache > 0 and elf_bytes_read == 0)
            else ("MIXED_MEASURED_CACHE" if elf_bytes_from_cache > 0
            else ("UNAVAILABLE" if identity_status == IDENTITY_UNAVAILABLE else "PARTIAL_READ")))
        )
        meas_breakdown = {
            "readlink_bytes": readlink_bytes,
            "stat_bytes": stat_bytes,
            "elf_bytes_read": elf_bytes_read,
            "elf_bytes_from_cache": elf_bytes_from_cache,
            "total_measured_bytes": total_measured_bytes,
            "estimated_bytes_read": estimated_bytes_read,
            "measurement_status": meas_status,
        }

        self._last_identity_bytes_read = total_measured_bytes
        self._last_identity_estimated_bytes = estimated_bytes_read
        self._last_identity_status = meas_status
        self._last_identity_breakdown = meas_breakdown
        self._last_identity_latency_us = (time.monotonic() - t_id_start) * 1_000_000.0

        op_id = operation_id or f"proc_identity_{pid}_{uuid.uuid4().hex[:8]}"
        m_type = "MEASURED" if total_measured_bytes > 0 else ("CACHE_HIT" if elf_bytes_from_cache > 0 else "UNKNOWN")
        acct_status = "PENDING"
        if adm is not None:
            if total_measured_bytes > 0:
                adm.consume(actual_bytes=total_measured_bytes)
            else:
                if eff_tracker is not None and adm.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED") and adm.consumed_bytes == 0:
                    eff_tracker.release_reservation(adm)

        if eff_tracker is not None and total_measured_bytes > 0:
            active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
            if active_scope is not None and not active_scope.is_finalized:
                active_scope.record_read(
                    bytes_read=total_measured_bytes,
                    admission=adm,
                    profile_id="target_identity",
                )
                acct_status = "COMMITTED"
            else:
                record = ObservationAccountingRecord(
                    operation_id=op_id,
                    accounting_owner="ADAPTER",
                    measured_bytes_read=total_measured_bytes,
                    estimated_bytes_read=estimated_bytes_read,
                    charged_bytes=total_measured_bytes,
                    latency_us=self._last_identity_latency_us,
                    measurement_type=m_type,
                )
                ok = eff_tracker.commit_transaction(record, profile_id="target_identity", reservations=[adm] if adm else None)
                acct_status = "COMMITTED" if ok else "FAILED"
        elif total_measured_bytes == 0:
            acct_status = "COMMITTED"

        return {
            "pid": pid,
            "executable": runtime_exe,
            "raw_link": raw_link,
            "is_deleted": is_deleted,
            "process_start_time": start_time_0,
            "architecture": runtime_identity.architecture if runtime_identity else "unknown",
            "elf_class": runtime_identity.elf_class if runtime_identity else "unknown",
            "endianness": runtime_identity.endianness if runtime_identity else "unknown",
            "elf_type": runtime_identity.elf_type if runtime_identity else "unknown",
            "build_id": runtime_identity.build_id if runtime_identity else None,
            "build_id_status": build_id_status,
            "pt_loads": runtime_identity.pt_loads if runtime_identity else [],
            "has_debug_info": bool(getattr(runtime_identity, "has_debug_info", False)) if runtime_identity else False,
            "status": status_val,
            "identity_status": identity_status,
            "stable_fd_verified": stable_fd_verified,
            "measured_bytes_read": total_measured_bytes,
            "estimated_bytes_read": estimated_bytes_read,
            "charged_bytes": total_measured_bytes,
            "measurement_status": meas_status,
            "measurement_type": m_type,
            "accounting_owner": "ADAPTER",
            "accounting_status": acct_status,
            "operation_id": op_id,
            "measurement_breakdown": meas_breakdown,
            "error": link_err or elf_error,
            "is_remote": False,
            "host": self.target_host(),
        }

    def get_process_memory_info(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Reads detailed process memory metrics from /proc/<pid>/statm, /proc/<pid>/status,
        and /proc/<pid>/smaps_rollup (bounded, low-impact).
        
        Strictly distinguishes:
        - Virtual memory size (VSZ)
        - Resident set size (RSS)
        - Mapping size
        - Writable anonymous mapping size
        - Heap mapping size
        - Actual allocation evidence (procfs limitation documented)
        - Object lifetime / release evidence (procfs limitation documented)
        """
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            return {
                "status": "FAILED",
                "pid": pid,
                "error": f"Invalid PID {pid}",
                "metrics": {},
                "mappings_summary": {},
                "metadata": {},
            }

        eff_tracker = budget_tracker or getattr(self, "_budget_tracker", None)
        if eff_tracker is None:
            from .observation_budget import ObservationBudgetTracker
            eff_tracker = ObservationBudgetTracker.get_active_thread_tracker()

        adm = admission
        own_adm = False
        if adm is None and eff_tracker is not None:
            if eff_tracker.is_budget_exhausted:
                return {
                    "status": "BUDGET_EXHAUSTED",
                    "pid": pid,
                    "error": f"Observation budget exhausted: {eff_tracker.exhaustion_reason}",
                    "metrics": {},
                    "mappings_summary": {},
                    "metadata": {},
                }
            proj_b = min(8192, max(512, eff_tracker.remaining_bytes))
            active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
            try:
                if active_scope is not None and not active_scope.is_finalized:
                    adm = active_scope.admit_read(projected_bytes=proj_b, profile_id="target_memory_info")
                else:
                    adm = eff_tracker.admit_read(projected_bytes=proj_b, profile_id="target_memory_info")
                own_adm = True
            except ValueError as ve:
                return {
                    "status": "BUDGET_EXHAUSTED",
                    "pid": pid,
                    "error": f"Admission rejected: {ve}",
                    "metrics": {},
                    "mappings_summary": {},
                    "metadata": {},
                }

        if adm is not None:
            adm.mark_physical_read_started()

        is_alive, live_err = self.check_liveness(pid)
        if not is_alive and live_err and any(k in live_err.lower() for k in ("terminated", "not found", "zombie")):
            if own_adm and adm is not None and eff_tracker is not None:
                if adm.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED") and adm.consumed_bytes == 0:
                    eff_tracker.release_reservation(adm)
            return {
                "status": "TARGET_TERMINATED",
                "pid": pid,
                "error": live_err,
                "metrics": {},
                "mappings_summary": {},
                "metadata": {},
                "heap_rss_bytes": None,
                "heap_physical_residency_available": False,
            }

        t_start = time.time()
        page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
        actual_costs: Dict[str, int] = {}

        # 1. Read /proc/<pid>/statm
        statm_path = f"/proc/{pid}/statm"
        statm_vsz = None
        statm_rss = None
        statm_shared = None
        statm_data = None
        if os.path.exists(statm_path):
            try:
                with open(statm_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                    actual_costs["statm"] = len(content.encode("utf-8"))
                    parts = content.strip().split()
                    if len(parts) >= 6:
                        statm_vsz = int(parts[0]) * page_size
                        statm_rss = int(parts[1]) * page_size
                        statm_shared = int(parts[2]) * page_size
                        statm_data = int(parts[5]) * page_size
            except PermissionError:
                return {
                    "status": "PERMISSION_DENIED",
                    "pid": pid,
                    "error": f"Permission denied reading {statm_path}",
                    "metrics": {},
                    "mappings_summary": {},
                    "metadata": {},
                }
            except Exception:
                pass

        # 2. Read /proc/<pid>/status
        status_path = f"/proc/{pid}/status"
        status_vsz = None
        status_rss = None
        rss_anon = None
        rss_file = None
        rss_shmem = None
        vm_peak = None
        vm_hwm = None
        vm_data = None
        vm_swap = None
        if os.path.exists(status_path):
            try:
                with open(status_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                    actual_costs["status"] = len(content.encode("utf-8"))
                    for line in content.splitlines():
                        line_s = line.strip()
                        if line_s.startswith("VmSize:"):
                            status_vsz = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("VmRSS:"):
                            status_rss = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("RssAnon:"):
                            rss_anon = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("RssFile:"):
                            rss_file = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("RssShmem:"):
                            rss_shmem = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("VmPeak:"):
                            vm_peak = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("VmHWM:"):
                            vm_hwm = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("VmData:"):
                            vm_data = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("VmSwap:"):
                            vm_swap = int(line_s.split()[1]) * 1024
            except PermissionError:
                return {
                    "status": "PERMISSION_DENIED",
                    "pid": pid,
                    "error": f"Permission denied reading {status_path}",
                    "metrics": {},
                    "mappings_summary": {},
                    "metadata": {},
                }
            except Exception:
                pass

        # 3. Read /proc/<pid>/smaps_rollup (bounded to 4096 bytes)
        smaps_rollup_path = f"/proc/{pid}/smaps_rollup"
        pss = None
        private_dirty = None
        private_clean = None
        shared_dirty = None
        shared_clean = None
        smaps_denied = False
        if os.path.exists(smaps_rollup_path):
            try:
                with open(smaps_rollup_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(4096)
                    actual_costs["smaps_rollup"] = len(content.encode("utf-8"))
                    for line in content.splitlines():
                        line_s = line.strip()
                        if line_s.startswith("Pss:"):
                            pss = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("Private_Dirty:"):
                            private_dirty = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("Private_Clean:"):
                            private_clean = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("Shared_Dirty:"):
                            shared_dirty = int(line_s.split()[1]) * 1024
                        elif line_s.startswith("Shared_Clean:"):
                            shared_clean = int(line_s.split()[1]) * 1024
            except PermissionError:
                smaps_denied = True
            except Exception:
                pass

        # 4. Mappings summary from /proc/<pid>/maps
        try:
            if _adapter_supports_admission(self, "get_proc_maps"):
                maps = self.get_proc_maps(pid, admission=adm, budget_tracker=eff_tracker)
            else:
                maps = self.get_proc_maps(pid)
            maps_bytes = getattr(self, "_last_maps_bytes_read", 0)
            actual_costs["maps"] = maps_bytes
            maps_status = "OBSERVED"
        except PermissionError:
            if own_adm and adm is not None and eff_tracker is not None:
                if adm.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED") and adm.consumed_bytes == 0:
                    eff_tracker.release_reservation(adm)
            return {
                "status": "PERMISSION_DENIED",
                "pid": pid,
                "error": f"Permission denied reading /proc/{pid}/maps",
                "metrics": {},
                "mappings_summary": {},
                "metadata": {},
                "sources_status": {"maps": "PERMISSION_DENIED"},
            }

        total_mapping_size = sum(m.get("size", 0) for m in maps)
        heap_mapping_size = sum(m.get("size", 0) for m in maps if m.get("category") == "heap" or m.get("pathname") == "[heap]")
        anon_mapping_size = sum(m.get("size", 0) for m in maps if m.get("category") == "anonymous" and m.get("is_writable"))
        stack_mapping_size = sum(m.get("size", 0) for m in maps if m.get("category") == "stack")

        vsz_eff = status_vsz if status_vsz is not None else (statm_vsz if statm_vsz is not None else total_mapping_size)
        rss_eff = status_rss if status_rss is not None else statm_rss

        sources_status = {
            "statm": "OBSERVED" if statm_vsz is not None else "UNAVAILABLE",
            "status": "OBSERVED" if status_vsz is not None else "UNAVAILABLE",
            "smaps_rollup": "OBSERVED" if pss is not None else ("PERMISSION_DENIED" if smaps_denied else "UNAVAILABLE"),
            "maps": maps_status,
        }

        missing_optional_metrics = []
        if pss is None:
            missing_optional_metrics.extend([
                "pss_bytes", "private_dirty_bytes", "private_clean_bytes",
                "shared_dirty_bytes", "shared_clean_bytes",
            ])

        missing_required_metrics = []
        if statm_vsz is None and status_vsz is None:
            missing_required_metrics.append("vsz_bytes")
        if statm_rss is None and status_rss is None:
            missing_required_metrics.append("rss_bytes")

        actual_bytes_read = sum(actual_costs.values())

        metrics = {
            "vsz_bytes": vsz_eff,
            "rss_bytes": rss_eff,
            "rss_anon_bytes": rss_anon,
            "rss_file_bytes": rss_file,
            "rss_shmem_bytes": rss_shmem,
            "heap_rss_bytes": None,  # procfs does NOT measure heap-specific RSS without an extensive smaps VMA scan; process-wide RSS must NEVER be substituted as heap RSS
            "heap_physical_residency_available": False,
            "vm_peak_bytes": vm_peak,
            "vm_hwm_bytes": vm_hwm,
            "vm_data_bytes": vm_data if vm_data is not None else statm_data,
            "vm_swap_bytes": vm_swap,
            "pss_bytes": pss,
            "private_dirty_bytes": private_dirty,
            "private_clean_bytes": private_clean,
            "shared_dirty_bytes": shared_dirty,
            "shared_clean_bytes": shared_clean,
        }

        mappings_summary = {
            "mapping_count": len(maps),
            "total_mapping_size_bytes": total_mapping_size,
            "heap_mapping_size_bytes": heap_mapping_size,
            "writable_anon_mapping_size_bytes": anon_mapping_size,
            "stack_mapping_size_bytes": stack_mapping_size,
        }

        metadata = {
            "vsz": {
                "source": "/proc/<pid>/status (VmSize) / /proc/<pid>/statm",
                "method": "Procfs virtual memory space counters",
                "limitations": "Measures total reserved virtual address space. Mapping expansion does NOT indicate RAM usage or page allocation.",
                "estimated_cost_bytes": 1024,
                "actual_cost_bytes": actual_costs.get("status", actual_costs.get("statm", 1024)),
            },
            "rss": {
                "source": "/proc/<pid>/status (VmRSS) / /proc/<pid>/statm",
                "method": "Kernel MM task_struct RSS counters",
                "limitations": "Measures physical pages currently resident in RAM. Subject to OS page cache reclamation, lazy faults, and swapping. Does not distinguish allocated vs retained memory.",
                "estimated_cost_bytes": 1024,
                "actual_cost_bytes": actual_costs.get("status", actual_costs.get("statm", 1024)),
            },
            "heap_rss": {
                "source": "None in /proc/statm or /proc/status",
                "method": "N/A",
                "limitations": "Procfs does not provide heap-specific RSS without traversing /proc/<pid>/smaps VMA entries. Process-wide RSS must NEVER be substituted as heap RSS.",
                "estimated_cost_bytes": 0,
                "actual_cost_bytes": 0,
            },
            "mapping_size": {
                "source": "/proc/<pid>/maps",
                "method": "Sequential VMA interval scan",
                "limitations": "Virtual segment intervals only; a mapped region does not guarantee that physical pages are committed.",
                "estimated_cost_bytes": 4096,
                "actual_cost_bytes": len(maps) * 64,
            },
            "private_dirty": {
                "source": "/proc/<pid>/smaps_rollup",
                "method": "Kernel aggregated rollup",
                "limitations": "Unshared modified pages in RAM. Available on Linux 4.14+; bounded read.",
                "estimated_cost_bytes": 1024,
                "actual_cost_bytes": actual_costs.get("smaps_rollup", 0),
            },
            "allocation_evidence": {
                "source": "None in /proc",
                "method": "N/A",
                "limitations": "Procfs metrics only reflect kernel-level virtual memory and page tables. Individual heap chunks (malloc/free, arenas, pools, slab) and object lifetimes cannot be proven by procfs alone without heap introspection or allocator tracing.",
                "estimated_cost_bytes": 0,
                "actual_cost_bytes": 0,
            },
            "object_lifetime_evidence": {
                "source": "None in /proc",
                "method": "N/A",
                "limitations": "Object creation, references, and destruction are application-level events invisible to procfs without runtime tracing or active debugger unwinding.",
                "estimated_cost_bytes": 0,
                "actual_cost_bytes": 0,
            },
        }

        actual_bytes_read = sum(actual_costs.values())
        if adm is not None:
            other_b = sum(v for k, v in actual_costs.items() if k != "maps")
            if other_b > 0:
                adm.consume(actual_bytes=other_b, accumulate=True)

        if own_adm and eff_tracker is not None:
            if actual_bytes_read > 0:
                active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
                if active_scope is not None and not active_scope.is_finalized:
                    active_scope.record_read(bytes_read=actual_bytes_read, admission=adm, profile_id="target_memory_info")
                else:
                    eff_tracker.commit_transaction(
                        operation_id=f"standalone_meminfo_{uuid.uuid4().hex[:8]}",
                        profile_id="target_memory_info",
                        measured_bytes=actual_bytes_read,
                        reservations=[adm],
                    )
            else:
                if adm.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED") and adm.consumed_bytes == 0:
                    eff_tracker.release_reservation(adm)

        return {
            "status": "OBSERVED" if not missing_required_metrics else "PARTIAL",
            "timestamp": t_start,
            "pid": pid,
            "metrics": metrics,
            "mappings_summary": mappings_summary,
            "metadata": metadata,
            "sources_status": sources_status,
            "missing_optional_metrics": missing_optional_metrics,
            "missing_required_metrics": missing_required_metrics,
            "heap_rss_bytes": None,
            "heap_physical_residency_available": False,
            "actual_bytes_read": actual_bytes_read,
            "actual_costs": actual_costs,
        }

    def get_proc_maps(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        maps_path = f"/proc/{pid}/maps"
        mappings: List[Dict[str, Any]] = []
        self._last_maps_bytes_read = 0
        if not os.path.exists(maps_path):
            return mappings

        eff_tracker = budget_tracker or getattr(self, "_budget_tracker", None)
        if eff_tracker is None:
            from .observation_budget import ObservationBudgetTracker
            eff_tracker = ObservationBudgetTracker.get_active_thread_tracker()

        adm = admission
        own_adm = False
        if adm is None and eff_tracker is not None:
            if eff_tracker.is_budget_exhausted:
                self._last_maps_bytes_read = 0
                return []
            proj_b = min(4096, max(256, eff_tracker.remaining_bytes))
            active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
            try:
                if active_scope is not None and not active_scope.is_finalized:
                    adm = active_scope.admit_read(projected_bytes=proj_b, profile_id="target_maps")
                else:
                    adm = eff_tracker.admit_read(projected_bytes=proj_b, profile_id="target_maps")
                own_adm = True
            except ValueError:
                self._last_maps_bytes_read = 0
                return []

        pread_maps = None
        if adm is not None:
            pread_maps = adm.start_child_read(
                target_type="proc_maps",
                target_spec={"pid": pid, "path": maps_path},
            )

        if not os.path.exists(maps_path):
            if pread_maps is not None:
                pread_maps.release()
            if own_adm and adm is not None and eff_tracker is not None:
                eff_tracker.release_reservation(adm)
            self._last_maps_bytes_read = 0
            return []

        if pread_maps is not None:
            pread_maps.mark_started()
        if adm is not None and not adm.is_terminal:
            adm.mark_physical_read_started()

        content = ""
        m_bytes = 0
        read_err = None
        try:
            with open(maps_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
                m_bytes = len(content.encode("utf-8"))
        except Exception as exc:
            read_err = exc

        self._last_maps_bytes_read = m_bytes

        if read_err is None:
            if pread_maps is not None:
                pread_maps.consume(actual_bytes=m_bytes, is_failure=False)
            elif adm is not None:
                adm.consume(actual_bytes=m_bytes, is_failure=False, accumulate=not own_adm)
            if own_adm and eff_tracker is not None:
                active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
                if active_scope is not None and not active_scope.is_finalized:
                    active_scope.record_read(bytes_read=m_bytes, admission=adm, profile_id="target_maps", is_failure=False)
                else:
                    eff_tracker.commit_transaction(
                        operation_id=f"standalone_maps_{uuid.uuid4().hex[:8]}",
                        profile_id="target_maps",
                        measured_bytes=m_bytes,
                        is_failure=False,
                        reservations=[adm] if adm else None,
                    )
        else:
            if pread_maps is not None:
                pread_maps.consume(actual_bytes=None, conservative_estimate_bytes=4096, is_failure=True, failure_reason=str(read_err))
            elif adm is not None:
                adm.consume(actual_bytes=None, is_failure=True, accumulate=not own_adm)
            if own_adm and eff_tracker is not None:
                eff_tracker.commit_transaction(
                    operation_id=f"standalone_maps_{uuid.uuid4().hex[:8]}",
                    profile_id="target_maps",
                    estimated_bytes=4096,
                    is_failure=True,
                    reservations=[adm] if adm else None,
                )

        if read_err is not None and m_bytes == 0:
            return mappings

        for line in content.splitlines():
            parts = line.strip().split(maxsplit=5)
            if len(parts) >= 5:
                addr_range = parts[0]
                perms = parts[1]
                offset = parts[2]
                pathname = parts[5] if len(parts) >= 6 else ""

                try:
                    start_hex, end_hex = addr_range.split("-")
                    s_int = int(start_hex, 16)
                    e_int = int(end_hex, 16)
                    off_int = int(offset, 16)
                except Exception:
                    continue

                path_low = pathname.lower()
                is_hugepage = any(k in path_low for k in ("huge", "rtemap", "hugetlb"))
                category = "anonymous"
                if pathname == "[heap]":
                    category = "heap"
                elif pathname.startswith("[stack"):
                    category = "stack"
                elif is_hugepage and "w" in perms:
                    category = "data"
                elif pathname:
                    if "x" in perms:
                        category = "code"
                    elif "w" in perms:
                        category = "data"
                    else:
                        category = "file"

                mappings.append({
                    "start": f"0x{s_int:x}",
                    "end": f"0x{e_int:x}",
                    "start_int": s_int,
                    "end_int": e_int,
                    "size": e_int - s_int,
                    "permissions": perms,
                    "offset": offset,
                    "offset_int": off_int,
                    "category": category,
                    "pathname": pathname,
                    "is_hugepage": is_hugepage,
                    "is_readable": "r" in perms,
                    "is_writable": "w" in perms,
                    "is_executable": "x" in perms,
                })
        return mappings

    get_memory_mappings = get_proc_maps

    def get_threads(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        import struct as _struct
        threads: List[Dict[str, Any]] = []
        task_dir = f"/proc/{pid}/task"
        if not os.path.exists(task_dir):
            self._last_threads_bytes_read = 0
            self._last_threads_breakdown = {"maps_bytes": 0, "task_bytes": 0, "memory_bytes": 0, "total_bytes": 0}
            return threads

        eff_tracker = budget_tracker or getattr(self, "_budget_tracker", None)
        if eff_tracker is None:
            from .observation_budget import ObservationBudgetTracker
            eff_tracker = ObservationBudgetTracker.get_active_thread_tracker()

        adm = admission
        own_adm = False
        if adm is None and eff_tracker is not None:
            if eff_tracker.is_budget_exhausted:
                self._last_threads_bytes_read = 0
                self._last_threads_breakdown = {"maps_bytes": 0, "task_bytes": 0, "memory_bytes": 0, "total_bytes": 0}
                return []
            proj_b = min(4096, max(256, eff_tracker.remaining_bytes))
            active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
            try:
                if active_scope is not None and not active_scope.is_finalized:
                    adm = active_scope.admit_read(projected_bytes=proj_b, profile_id="target_threads")
                else:
                    adm = eff_tracker.admit_read(projected_bytes=proj_b, profile_id="target_threads")
                own_adm = True
            except ValueError:
                self._last_threads_bytes_read = 0
                self._last_threads_breakdown = {"maps_bytes": 0, "task_bytes": 0, "memory_bytes": 0, "total_bytes": 0}
                return []

        if adm is not None:
            adm.mark_physical_read_started()

        if _adapter_supports_admission(self, "get_proc_maps"):
            maps = self.get_proc_maps(pid, admission=adm, budget_tracker=eff_tracker)
        else:
            maps = self.get_proc_maps(pid)
        maps_b = getattr(self, "_last_maps_bytes_read", 0)
        task_bytes = 0
        mem_bytes = 0
        total_proc_bytes_read = maps_b
        stack_maps = [m for m in maps if m.get("category") == "stack" or m.get("pathname", "").startswith("[stack")]
        kernel_isolated = set(_get_kernel_isolated_cpus())
        sched_policy_names = {
            0: "SCHED_OTHER",
            1: "SCHED_FIFO",
            2: "SCHED_RR",
            3: "SCHED_BATCH",
            5: "SCHED_IDLE",
            6: "SCHED_DEADLINE",
        }

        def _read_proc_file(tid_str: str, fname: str) -> Tuple[str, int]:
            nonlocal total_proc_bytes_read, task_bytes
            fpath = os.path.join(task_dir, tid_str, fname)
            pread_f = None
            if adm is not None:
                pread_f = adm.start_child_read(
                    target_type="proc_task_file",
                    target_spec={"pid": pid, "tid": int(tid_str), "file": fname},
                )
            if not os.path.exists(fpath):
                if pread_f is not None:
                    pread_f.release()
                return "", 0
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    if pread_f is not None:
                        pread_f.mark_started()
                    raw_text = f.read()
                b_count = len(raw_text.encode("utf-8"))
                total_proc_bytes_read += b_count
                task_bytes += b_count
                if pread_f is not None:
                    pread_f.consume(actual_bytes=b_count)
                return raw_text, b_count
            except (FileNotFoundError, ProcessLookupError):
                if pread_f is not None:
                    if pread_f.state == "PHYSICAL_READ_STARTED":
                        pread_f.consume(actual_bytes=0, is_failure=True)
                    elif pread_f.state == "ADMITTED":
                        pread_f.release()
                return "", 0
            except Exception:
                if pread_f is not None:
                    if pread_f.state == "PHYSICAL_READ_STARTED":
                        pread_f.consume(actual_bytes=None, conservative_estimate_bytes=32, is_failure=True)
                    elif pread_f.state == "ADMITTED":
                        pread_f.release()
                return "", 0

        try:
            for tid_entry in os.listdir(task_dir):
                if tid_entry.isdigit():
                    tid = int(tid_entry)
                    comm = "unknown"
                    state = "UNKNOWN"
                    startstack = 0
                    utime_ticks = 0
                    stime_ticks = 0
                    cpu_id: Optional[int] = None
                    rt_priority = 0
                    sched_policy = "SCHED_OTHER"
                    raw_comm, _ = _read_proc_file(tid_entry, "comm")
                    if raw_comm:
                        comm = raw_comm.strip()

                    kstkesp = 0
                    raw_stat, _ = _read_proc_file(tid_entry, "stat")
                    if raw_stat:
                        raw_stat = raw_stat.strip()
                        rparen = raw_stat.rfind(")")
                        if rparen != -1:
                            rest = raw_stat[rparen + 1:].strip().split()
                            if len(rest) >= 1:
                                state = rest[0]
                            if len(rest) >= 13:
                                try:
                                    utime_ticks = int(rest[11])
                                    stime_ticks = int(rest[12])
                                except (ValueError, IndexError):
                                    pass
                            if len(rest) >= 26:
                                try:
                                    startstack = int(rest[25])
                                except (ValueError, IndexError):
                                    pass
                            if len(rest) >= 27:
                                try:
                                    kstkesp = int(rest[26])
                                except (ValueError, IndexError):
                                    pass
                            if len(rest) >= 37:
                                try:
                                    cpu_id = int(rest[36])
                                except (ValueError, IndexError):
                                    pass
                            if len(rest) >= 39:
                                try:
                                    rt_priority = int(rest[37])
                                    pol_num = int(rest[38])
                                    sched_policy = sched_policy_names.get(pol_num, f"POLICY_{pol_num}")
                                except (ValueError, IndexError):
                                    pass

                    cpus_allowed_list = ""
                    numa_nodes_list = ""
                    voluntary_cs = 0
                    nonvoluntary_cs = 0
                    stf_text, _ = _read_proc_file(tid_entry, "status")
                    if stf_text:
                        for sline in stf_text.splitlines():
                            if sline.startswith("Cpus_allowed_list:"):
                                cpus_allowed_list = sline.split(":", 1)[1].strip()
                            elif sline.startswith("Mems_allowed_list:"):
                                numa_nodes_list = sline.split(":", 1)[1].strip()
                            elif sline.startswith("voluntary_ctxt_switches:"):
                                try:
                                    voluntary_cs = int(sline.split(":", 1)[1].strip())
                                except ValueError:
                                    pass
                            elif sline.startswith("nonvoluntary_ctxt_switches:"):
                                try:
                                    nonvoluntary_cs = int(sline.split(":", 1)[1].strip())
                                except ValueError:
                                    pass

                    pinned_cpus = _parse_cpulist(cpus_allowed_list)
                    if not pinned_cpus and hasattr(os, "sched_getaffinity"):
                        try:
                            pinned_cpus = sorted(os.sched_getaffinity(tid))
                            if pinned_cpus and not cpus_allowed_list:
                                cpus_allowed_list = ",".join(str(c) for c in pinned_cpus)
                        except Exception:
                            pass
                    is_single_core_pinned = (len(pinned_cpus) == 1)

                    syscall_sp = 0
                    syscall_nr = None
                    syscall_name = None
                    syscall_arg0 = None
                    wchan = ""
                    raw_wchan, _ = _read_proc_file(tid_entry, "wchan")
                    if raw_wchan:
                        wchan = raw_wchan.strip()

                    is_running_user_space = (state == "R")
                    raw_sy, _ = _read_proc_file(tid_entry, "syscall")
                    if raw_sy:
                        sy_raw = raw_sy.strip()
                        if sy_raw.startswith("running"):
                            is_running_user_space = True
                        else:
                            sy_parts = sy_raw.split()
                            if len(sy_parts) >= 1 and sy_parts[0].isdigit():
                                syscall_nr = int(sy_parts[0])
                                # Support both x86_64 (202) and aarch64 (98) futex syscalls
                                if syscall_nr in (98, 202):
                                    syscall_name = "futex"
                                elif syscall_nr == 422:
                                    syscall_name = "futex_time64"
                                elif syscall_nr == 449:
                                    syscall_name = "futex_waitv"
                            raw_sy_arg0 = None
                            if len(sy_parts) >= 2:
                                raw_sy_arg0 = sy_parts[1]
                                if sy_parts[1].startswith("0x") or sy_parts[1].startswith("0X"):
                                    try:
                                        syscall_arg0 = int(sy_parts[1], 16)
                                    except ValueError:
                                        pass
                                else:
                                    try:
                                        syscall_arg0 = int(sy_parts[1], 10)
                                    except ValueError:
                                        pass
                            if len(sy_parts) >= 2 and sy_parts[-2].startswith("0x"):
                                syscall_sp = int(sy_parts[-2], 16)

                    is_futex = bool(
                        (syscall_name and "futex" in syscall_name)
                        or ("futex" in wchan.lower())
                        or (syscall_nr in (98, 202, 422, 449))
                    )

                    sp_int = syscall_sp or kstkesp

                    stack_info: Dict[str, Any] = {"status": "UNAVAILABLE", "reason": "Thread stack mapping not identifiable in proc maps"}
                    matched_map = None
                    if sp_int > 0:
                        for m in maps:
                            if m["start_int"] <= sp_int < m["end_int"]:
                                matched_map = m
                                break
                    if not matched_map and tid == pid:
                        for m in stack_maps:
                            if m.get("pathname") == "[stack]":
                                matched_map = m
                                break
                    if not matched_map:
                        for m in stack_maps:
                            if m.get("pathname") == f"[stack:{tid}]":
                                matched_map = m
                                break
                    if not matched_map and tid == pid and startstack > 0:
                        for m in maps:
                            if m["start_int"] <= startstack < m["end_int"]:
                                matched_map = m
                                break

                    if matched_map:
                        stack_info = {
                            "status": "AVAILABLE",
                            "start": matched_map["start"],
                            "end": matched_map["end"],
                            "start_int": matched_map["start_int"],
                            "end_int": matched_map["end_int"],
                            "size": matched_map["size"],
                            "permissions": matched_map["permissions"],
                            "sp": f"0x{sp_int:x}" if sp_int > 0 else None,
                            "sp_int": sp_int if sp_int > 0 else None,
                            "tcb_address": None,
                            "tcb_address_int": None,
                        }

                    norm_hex, norm_int, addr_st, raw_arg = normalize_futex_address(syscall_arg0 if syscall_arg0 is not None else raw_sy_arg0)

                    concurrency_state = (
                        "WAITING_IN_FUTEX" if is_futex
                        else ("SLEEPING" if state == "S"
                        else ("BLOCKED_IO" if state == "D"
                        else ("RUNNING" if state == "R" else state)))
                    )

                    threads.append({
                        "tid": tid,
                        "name": comm,
                        "state": state,
                        "concurrency_state": concurrency_state,
                        "is_sleeping": (state == "S"),
                        "is_blocked_uninterruptible": (state == "D"),
                        "syscall_nr": syscall_nr,
                        "syscall_name": syscall_name,
                        "raw_syscall_arg0": raw_arg,
                        "syscall_arg0": norm_hex,
                        "syscall_arg0_int": norm_int,
                        "waiting_on_lock": norm_hex,
                        "lock_address_status": "OBSERVED" if addr_st == "WAIT_ADDRESS_OBSERVED" else "UNAVAILABLE",
                        "wait_address_status": addr_st,
                        "futex_wait_observed": is_futex,
                        "lock_owner_identified": False,
                        "owner_tid": None,
                        "wchan": wchan,
                        "is_futex_wait": is_futex,
                        "cpu_id": cpu_id,
                        "cpus_allowed_list": cpus_allowed_list,
                        "pinned_cpus": pinned_cpus,
                        "is_single_core_pinned": is_single_core_pinned,
                        "is_kernel_isolated_core": bool(cpu_id is not None and cpu_id in kernel_isolated),
                        "numa_nodes_list": numa_nodes_list,
                        "sched_policy": sched_policy,
                        "rt_priority": rt_priority,
                        "utime_ticks": utime_ticks,
                        "stime_ticks": stime_ticks,
                        "voluntary_ctxt_switches": voluntary_cs,
                        "nonvoluntary_ctxt_switches": nonvoluntary_cs,
                        "is_running_user_space": is_running_user_space,
                        "stack_info": stack_info,
                        "local_variables": {
                            "status": "UNSUPPORTED",
                            "reason": "Stack frame inspection requires an active debugger backend (GDB/ptrace frame unwind).",
                        },
                    })

            # Resolve stack_info and TCB address for pure user-space poll-mode threads (e.g. DPDK lcores where sp_int == 0)
            unresolved_threads = [
                t for t in threads
                if t["stack_info"].get("status") != "AVAILABLE" or (t["tid"] != pid and t["stack_info"].get("tcb_address") is None)
            ]
            if unresolved_threads and self._memory_reader is None:
                target_tids = {t["tid"]: t for t in unresolved_threads}
                for m in maps:
                    if not any(t["stack_info"].get("status") != "AVAILABLE" or t["stack_info"].get("tcb_address") is None for t in unresolved_threads):
                        break
                    if not m.get("is_readable") or not m.get("is_writable"):
                        continue
                    pathname = (m.get("pathname") or "").strip()
                    if pathname and not pathname.startswith("[stack") and not m.get("is_hugepage"):
                        continue
                    vma_s = int(m["start_int"])
                    vma_e = int(m["end_int"])
                    sz = vma_e - vma_s
                    if sz < 4096 or sz > 64 * 1024 * 1024:
                        continue
                    top_from = max(vma_s, vma_e - 4096)
                    mem_sz = vma_e - top_from
                    if eff_tracker is not None and eff_tracker.remaining_bytes < mem_sz:
                        break
                    raw_top, r_st, _ = self.read_memory(pid, top_from, mem_sz, admission=adm, budget_tracker=eff_tracker)
                    if raw_top:
                        mem_b = len(raw_top)
                        total_proc_bytes_read += mem_b
                        mem_bytes += mem_b
                    if r_st != "OBSERVED" or not raw_top or len(raw_top) < 64:
                        continue
                    limit = len(raw_top) - 24
                    for off in range(0, limit, 8):
                        cand_tcb = top_from + off
                        w0 = _struct.unpack_from("<Q", raw_top, off)[0]
                        if w0 != cand_tcb:
                            continue
                        w2 = _struct.unpack_from("<Q", raw_top, off + 16)[0]
                        if w2 != cand_tcb:
                            continue
                        tcb_slice = raw_top[off : off + 1536]
                        matched_tid = None
                        if len(tcb_slice) >= 0x2d4:
                            v2d0 = _struct.unpack_from("<i", tcb_slice, 0x2d0)[0]
                            if v2d0 in target_tids:
                                matched_tid = v2d0
                        if matched_tid is None:
                            for toff in range(0x40, min(len(tcb_slice) - 4, 0x580), 4):
                                vtid = _struct.unpack_from("<i", tcb_slice, toff)[0]
                                if vtid in target_tids and vtid != pid:
                                    matched_tid = vtid
                                    break
                        if matched_tid is not None:
                            th_obj = target_tids[matched_tid]
                            s_inf = th_obj["stack_info"]
                            if s_inf.get("status") != "AVAILABLE":
                                th_obj["stack_info"] = {
                                    "status": "AVAILABLE",
                                    "start": m["start"],
                                    "end": m["end"],
                                    "start_int": vma_s,
                                    "end_int": vma_e,
                                    "size": m["size"],
                                    "permissions": m["permissions"],
                                    "sp": None,
                                    "sp_int": None,
                                    "tcb_address": f"0x{cand_tcb:x}",
                                    "tcb_address_int": cand_tcb,
                                }
                            else:
                                s_inf["tcb_address"] = f"0x{cand_tcb:x}"
                                s_inf["tcb_address_int"] = cand_tcb
        except Exception:
            pass

        self._last_threads_bytes_read = total_proc_bytes_read
        self._last_threads_breakdown = {
            "maps_bytes": maps_b,
            "task_bytes": task_bytes,
            "memory_bytes": mem_bytes,
            "total_bytes": total_proc_bytes_read,
        }
        if adm is not None and not getattr(adm, "child_reads", None):
            extra_b = task_bytes + mem_bytes
            if extra_b > 0:
                adm.consume(actual_bytes=extra_b, accumulate=True)

        if own_adm and eff_tracker is not None:
            if total_proc_bytes_read > 0:
                active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
                if active_scope is not None and not active_scope.is_finalized:
                    active_scope.record_read(bytes_read=total_proc_bytes_read, admission=adm, profile_id="target_threads")
                else:
                    eff_tracker.commit_transaction(
                        operation_id=f"standalone_threads_{uuid.uuid4().hex[:8]}",
                        profile_id="target_threads",
                        measured_bytes=total_proc_bytes_read,
                        reservations=[adm] if adm else None,
                    )
            else:
                if adm is not None and adm.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED") and adm.consumed_bytes == 0:
                    eff_tracker.release_reservation(adm)

        threads.sort(key=lambda t: t["tid"])
        return threads

    def read_memory(
        self,
        pid: int,
        address: int,
        size: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
        child_read: Optional[Any] = None,
    ) -> Tuple[Optional[bytes], str, Optional[str]]:
        eff_tracker = budget_tracker or getattr(self, "_budget_tracker", None)
        if eff_tracker is None:
            from .observation_budget import ObservationBudgetTracker
            eff_tracker = ObservationBudgetTracker.get_active_thread_tracker()

        # Pre-validation: Case A (failure before invocation)
        if pid <= 0:
            if child_read is not None and child_read.state == "ADMITTED":
                child_read.release()
            return None, "UNAVAILABLE", f"Invalid PID {pid}"

        adm = admission
        own_adm = False
        if adm is None and eff_tracker is not None:
            if eff_tracker.is_budget_exhausted:
                return None, "BUDGET_EXHAUSTED", f"Observation budget exhausted: {eff_tracker.exhaustion_reason}"
            active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
            try:
                if active_scope is not None and not active_scope.is_finalized:
                    adm = active_scope.admit_read(projected_bytes=size, profile_id="memory_read")
                else:
                    adm = eff_tracker.admit_read(projected_bytes=size, profile_id="memory_read")
                own_adm = True
            except ValueError as ve:
                return None, "BUDGET_EXHAUSTED", f"Observation budget admission rejected: {ve}"

        cr = child_read
        if cr is None and adm is not None:
            cr = adm.start_child_read(
                target_type="memory_slice",
                target_spec={"pid": pid, "address": address, "size": size},
            )

        if cr is not None and cr.state == "ADMITTED":
            cr.mark_started()
        elif adm is not None and not adm.is_terminal:
            adm.mark_physical_read_started()

        try:
            if self._memory_reader:
                res_bytes, res_st, res_err = self._memory_reader(pid, address, size)
            else:
                from .watch_session import read_process_memory_slice
                res_bytes, res_st, res_err = read_process_memory_slice(pid, address, size)
        except Exception as exc:
            if cr is not None and cr.state in ("ADMITTED", "PHYSICAL_READ_STARTED"):
                cr.consume(actual_bytes=None, conservative_estimate_bytes=size, is_failure=True, failure_reason=str(exc))
            elif adm is not None:
                adm.consume(actual_bytes=None, is_failure=True, accumulate=not own_adm)
            if own_adm and eff_tracker is not None:
                try:
                    eff_tracker.commit_transaction(
                        operation_id=f"standalone_read_exc_{uuid.uuid4().hex[:8]}",
                        profile_id="memory_read",
                        estimated_bytes=size,
                        is_failure=True,
                        reservations=[adm],
                    )
                except Exception:
                    pass
            raise exc

        actual_b = len(res_bytes) if res_bytes else 0
        is_fail = (res_st != "OBSERVED")

        if res_bytes is not None:
            if cr is not None:
                cr.consume(actual_bytes=actual_b, is_failure=is_fail, failure_reason=res_err)
            elif adm is not None:
                adm.consume(actual_bytes=actual_b, is_failure=is_fail, accumulate=not own_adm)
        else:
            if cr is not None:
                cr.consume(actual_bytes=0, is_failure=True, failure_reason=res_err)
            elif adm is not None:
                adm.consume(actual_bytes=0, is_failure=True, accumulate=not own_adm)

        if own_adm and eff_tracker is not None:
            active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
            tot_b = adm.consumed_bytes
            if active_scope is not None and not active_scope.is_finalized:
                active_scope.record_read(bytes_read=tot_b, admission=adm, profile_id="memory_read", is_failure=is_fail)
            else:
                eff_tracker.commit_transaction(
                    operation_id=f"standalone_read_{uuid.uuid4().hex[:8]}",
                    profile_id="memory_read",
                    measured_bytes=cr.measured_bytes_read if cr else tot_b,
                    estimated_bytes=cr.estimated_bytes_read if cr else 0,
                    is_failure=is_fail,
                    reservations=[adm],
                )

        return res_bytes, res_st, res_err

    def resolve_mutex_owner(
        self,
        pid: int,
        lock_addr: Union[int, str],
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> MutexOwnerResolutionResult:
        """Inspects target memory at lock_addr to identify pthread_mutex owner TID if readable and valid.
        
        Strict Verification Requirements:
        - Identify supported libc implementations and architectures (Linux LP64 x86_64, aarch64 glibc).
        - Document and enforce the exact pthread_mutex_t ABI layout (LAYOUT_GLIBC_LP64).
        - Reject unsupported libc (musl, non-glibc) and unsupported architectures.
        - Validate mutex internal state (__kind, __lock, __count, __owner).
        - Validate that owner TID belongs to the target process (/proc/<pid>/task/<tid>).
        - Distinguish valid owner observation from coincidental integer memory matching an existing TID.
        - Preserve raw memory evidence and interpretation metadata.
        - Return explicit statuses:
            OWNER_IDENTIFIED, OWNER_NOT_IDENTIFIED, MUTEX_LAYOUT_UNSUPPORTED,
            MUTEX_STATE_INVALID, MEMORY_READ_UNAVAILABLE, PERMISSION_DENIED.
        """
        if not lock_addr:
            return MutexOwnerResolutionResult(
                status=STATUS_OWNER_NOT_IDENTIFIED,
                error="Lock address is empty or zero",
            )
        if isinstance(lock_addr, str):
            try:
                lock_addr_int = int(lock_addr, 16) if lock_addr.startswith("0x") else int(lock_addr, 10)
            except ValueError:
                return MutexOwnerResolutionResult(
                    status=STATUS_OWNER_NOT_IDENTIFIED,
                    error=f"Malformed lock address string: {lock_addr}",
                )
        else:
            lock_addr_int = int(lock_addr)

        if lock_addr_int <= 0:
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_STATE_INVALID,
                error=f"Invalid lock address integer: {lock_addr_int}",
            )

        eff_tracker = budget_tracker or getattr(self, "_budget_tracker", None)
        if eff_tracker is None:
            from .observation_budget import ObservationBudgetTracker
            eff_tracker = ObservationBudgetTracker.get_active_thread_tracker()

        # 1. Architecture, Libc, and ELF ABI Validation
        # Supported Glibc LP64 ABI Layout (glibc NPTL struct pthread_mutex_t):
        # - offset  0: int32_t  __lock   (0=unlocked, 1=locked, 2=contended, or FUTEX_WAITERS|TID for PI)
        # - offset  4: uint32_t __count  (recursion count; 0 for normal non-recursive mutex)
        # - offset  8: int32_t  __owner  (owner thread ID, 0 < tid < 4,194,304)
        # - offset 12: uint32_t __nusers
        # - offset 16: int32_t  __kind   (base kind 0..3 + flags: 0x10=robust, 0x20=pi, 0x80=shared, -1=destroyed)
        # - Supported target environments: Linux LP64 x86_64 and aarch64 glibc (ELF64, Little-Endian).
        if hasattr(self, "get_process_identity"):
            if _adapter_supports_admission(self, "get_process_identity"):
                proc_ident = self.get_process_identity(pid, budget_tracker=eff_tracker)
            else:
                proc_ident = self.get_process_identity(pid)
        else:
            proc_ident = {}
        if proc_ident.get("status") == "TARGET_TERMINATED":
            return MutexOwnerResolutionResult(
                status=STATUS_OWNER_NOT_IDENTIFIED,
                error="Target process terminated",
            )

        arch = (proc_ident.get("architecture") or "unknown").lower()
        if not arch or arch == "unknown":
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
                layout_id=ABI_ARCH_UNSUPPORTED,
                error="Target architecture cannot be established; fallback to host architecture is strictly forbidden",
                metadata={"abi_status": ABI_ARCH_UNSUPPORTED, "architecture": "unknown"},
            )
        if arch not in ("x86_64", "aarch64", "amd64", "arm64"):
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
                layout_id=ABI_ARCH_UNSUPPORTED,
                error=f"Architecture '{arch}' pthread_mutex_t layout is unsupported (only LP64 x86_64 and aarch64 glibc supported)",
                metadata={"abi_status": ABI_ARCH_UNSUPPORTED, "architecture": arch},
            )

        elf_class = proc_ident.get("elf_class") or "unknown"
        if elf_class == "ELF32":
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
                layout_id=ABI_ELF_CLASS_UNSUPPORTED,
                error="Target is 32-bit ELF (ELF32); LP64 glibc pthread_mutex layout requires ELF64",
                metadata={"abi_status": ABI_ELF_CLASS_UNSUPPORTED, "elf_class": elf_class, "architecture": arch},
            )
        if elf_class != "ELF64":
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
                layout_id=ABI_ELF_CLASS_UNSUPPORTED,
                error=f"Target ELF class '{elf_class}' unsupported; only ELF64 supported",
                metadata={"abi_status": ABI_ELF_CLASS_UNSUPPORTED, "elf_class": elf_class, "architecture": arch},
            )

        endianness = (proc_ident.get("endianness") or "unknown").lower()
        if endianness not in ("little", "1", "le"):
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
                layout_id=ABI_ENDIANNESS_UNSUPPORTED,
                error=f"Target endianness '{endianness}' unsupported; only little-endian LP64 supported",
                metadata={"abi_status": ABI_ENDIANNESS_UNSUPPORTED, "endianness": endianness, "architecture": arch},
            )

        # Check for libc runtime evidence in /proc/<pid>/maps
        if _adapter_supports_admission(self, "get_proc_maps"):
            maps = self.get_proc_maps(pid, admission=admission, budget_tracker=eff_tracker)
        else:
            maps = self.get_proc_maps(pid)
        has_musl = any("musl" in (m.get("pathname", "").lower()) for m in maps)
        if has_musl:
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
                layout_id=ABI_MUSL_UNSUPPORTED,
                error="musl libc pthread_mutex_t internal layout is unsupported (does not follow glibc NPTL struct layout)",
                metadata={"abi_status": ABI_MUSL_UNSUPPORTED, "architecture": arch, "elf_class": elf_class, "endianness": endianness},
            )

        # Positive evidence check for supported GNU C Library (glibc)
        has_glibc = any(
            ("libc.so.6" in m.get("pathname", "").lower() or
             "libc-" in m.get("pathname", "").lower() or
             "ld-linux" in m.get("pathname", "").lower())
            for m in maps
        )
        if not has_glibc:
            has_shared_libs = any(m.get("pathname", "").endswith(".so") or ".so." in m.get("pathname", "") for m in maps)
            if not has_shared_libs:
                return MutexOwnerResolutionResult(
                    status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
                    layout_id=ABI_STATIC_OR_UNIDENTIFIED,
                    error="Target binary is statically linked or unidentified runtime; pthread_mutex decoding unsupported",
                    metadata={"abi_status": ABI_STATIC_OR_UNIDENTIFIED, "architecture": arch, "elf_class": elf_class, "endianness": endianness},
                )
            else:
                return MutexOwnerResolutionResult(
                    status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
                    layout_id=ABI_LIBC_UNKNOWN,
                    error="Target libc runtime is unknown or unsupported (no glibc markers detected)",
                    metadata={"abi_status": ABI_LIBC_UNKNOWN, "architecture": arch, "elf_class": elf_class, "endianness": endianness},
                )

        # 2. Read Mutex Memory (glibc LP64 layout requires 40 bytes)
        t_start_read = time.monotonic()
        if _adapter_supports_admission(self, "read_memory"):
            raw, st, err = self.read_memory(pid, lock_addr_int, 40, admission=admission, budget_tracker=eff_tracker)
        else:
            raw, st, err = self.read_memory(pid, lock_addr_int, 40)
        read_latency_us = (time.monotonic() - t_start_read) * 1_000_000.0

        if st == "PERMISSION_DENIED":
            return MutexOwnerResolutionResult(
                status=STATUS_PERMISSION_DENIED,
                error=err or f"Permission denied reading memory at 0x{lock_addr_int:x}",
                metadata={"abi_status": ABI_GLIBC_VERIFIED, "memory_read_status": st, "latency_us": read_latency_us, "read_bytes_len": 0},
            )
        if st != "OBSERVED" or not raw or len(raw) < 20:
            return MutexOwnerResolutionResult(
                status=STATUS_MEMORY_READ_UNAVAILABLE,
                error=err or f"Memory read at 0x{lock_addr_int:x} returned {st} (bytes={len(raw) if raw else 0})",
                metadata={"abi_status": ABI_GLIBC_VERIFIED, "memory_read_status": st, "latency_us": read_latency_us, "read_bytes_len": len(raw) if raw else 0},
            )

        # 3. Unpack and Validate Mutex Structure
        import struct as _struct
        try:
            m_lock, m_count, m_owner, m_nusers, m_kind = _struct.unpack("<iIiIi", raw[:20])
        except Exception as exc:
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_STATE_INVALID,
                error=f"Failed to unpack 20 bytes at 0x{lock_addr_int:x}: {exc}",
                raw_bytes=raw,
            )

        layout_id = LAYOUT_GLIBC_LP64
        meta = {
            "abi_status": ABI_GLIBC_VERIFIED,
            "layout_id": layout_id,
            "architecture": arch,
            "elf_class": elf_class,
            "endianness": endianness,
            "lock_word": m_lock,
            "count": m_count,
            "owner": m_owner,
            "nusers": m_nusers,
            "kind": m_kind,
            "read_bytes_len": len(raw),
            "memory_read_status": "OBSERVED",
            "latency_us": read_latency_us,
        }

        # Validate __kind:
        # PTHREAD_MUTEX_DESTROYED is -1
        if m_kind == -1:
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_STATE_INVALID,
                layout_id=layout_id,
                raw_bytes=raw,
                metadata=meta,
                error="pthread_mutex has been destroyed (__kind == -1)",
            )

        # Base kind must be 0 (TIMED/NORMAL), 1 (RECURSIVE), 2 (ERRORCHECK), 3 (ADAPTIVE)
        base_kind = m_kind & 0x03
        is_robust = bool(m_kind & 0x10)
        is_pi = bool(m_kind & 0x20)
        is_pp = bool(m_kind & 0x40)

        meta["base_kind"] = base_kind
        meta["is_robust"] = is_robust
        meta["is_pi"] = is_pi
        meta["is_pp"] = is_pp

        # Known valid flag bits in glibc:
        # 0x10 (ROBUST), 0x20 (PRIO_INHERIT), 0x40 (PRIO_PROTECT), 0x80 (SHARED), 0x100 (ELISION), 0x200 (NO_ELISION)
        valid_flags_mask = 0x03 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200
        if (m_kind & ~valid_flags_mask) != 0 or m_kind < 0:
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_STATE_INVALID,
                layout_id=layout_id,
                raw_bytes=raw,
                metadata=meta,
                error=f"Invalid mutex kind {m_kind} (unknown flags 0x{m_kind:x}); bytes do not represent a valid pthread_mutex_t",
            )

        # Handle Robust mutexes (0x10):
        # In robust mutexes, if owner died, FUTEX_OWNER_DIED (0x40000000) is set in __lock
        if is_robust and (m_lock & 0x40000000):
            return MutexOwnerResolutionResult(
                status=STATUS_OWNER_NOT_IDENTIFIED,
                layout_id=layout_id,
                raw_bytes=raw,
                metadata=meta,
                error="Robust mutex owner died (FUTEX_OWNER_DIED); no active owner exists",
            )

        # Handle Priority-Inheritance (PI) mutexes (0x20):
        # In PI mutexes, kernel stores owner TID in __lock (with FUTEX_WAITERS 0x80000000)
        if is_pi:
            futex_tid = m_lock & 0x3fffffff
            if futex_tid > 0:
                m_owner = futex_tid
                meta["owner"] = m_owner

        # Validate __lock:
        # If __lock == 0, mutex is unlocked
        if m_lock == 0:
            return MutexOwnerResolutionResult(
                status=STATUS_OWNER_NOT_IDENTIFIED,
                layout_id=layout_id,
                raw_bytes=raw,
                metadata=meta,
                error="Mutex is currently unlocked (__lock == 0); no active owner exists",
            )

        # Validate __count:
        # For non-recursive mutex (NORMAL or ADAPTIVE), count must be 0
        if base_kind in (0, 3) and not is_robust and m_count != 0:
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_STATE_INVALID,
                layout_id=layout_id,
                raw_bytes=raw,
                metadata=meta,
                error=f"Normal/Adaptive mutex has non-zero count ({m_count}); inconsistent state or coincidental memory",
            )
        if m_count > 1000000:
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_STATE_INVALID,
                layout_id=layout_id,
                raw_bytes=raw,
                metadata=meta,
                error=f"Unreasonably large recursion count ({m_count}); bytes do not represent a valid pthread_mutex_t",
            )

        # Validate __owner:
        if m_owner <= 0 or m_owner >= 4194304:
            return MutexOwnerResolutionResult(
                status=STATUS_OWNER_NOT_IDENTIFIED,
                layout_id=layout_id,
                raw_bytes=raw,
                metadata=meta,
                error=f"Mutex owner field contains non-TID value ({m_owner})",
            )

        # 4. Process Membership Verification:
        # Verify that __owner belongs to this exact target process (/proc/<pid>/task/<__owner>)
        task_entry = f"/proc/{pid}/task/{m_owner}"
        if not os.path.exists(task_entry):
            return MutexOwnerResolutionResult(
                status=STATUS_OWNER_NOT_IDENTIFIED,
                layout_id=layout_id,
                raw_bytes=raw,
                metadata=meta,
                error=f"Extracted owner TID {m_owner} does not exist in target process {pid} (/proc/{pid}/task); likely coincidental memory or exited thread",
            )

        # 5. Lock Word vs Owner Consistency:
        # In glibc NPTL:
        # For normal/adaptive mutexes, __lock is typically 1 (locked) or 2 (contended).
        # For PI or robust mutexes, __lock is (FUTEX_WAITERS | owner_tid) or owner_tid.
        futex_tid = m_lock & 0x3fffffff
        is_plausible_lock = (m_lock in (1, 2)) or (futex_tid == m_owner) or (0 < m_lock < 0x40000000)
        if not is_plausible_lock:
            return MutexOwnerResolutionResult(
                status=STATUS_MUTEX_STATE_INVALID,
                layout_id=layout_id,
                raw_bytes=raw,
                metadata=meta,
                error=f"Mutex __lock value {m_lock} is inconsistent with owner {m_owner}",
            )

        # 6. Revalidate owner TID membership immediately before accepting owner result (Requirement 4.8)
        if not os.path.exists(task_entry):
            return MutexOwnerResolutionResult(
                status=STATUS_OWNER_NOT_IDENTIFIED,
                layout_id=layout_id,
                raw_bytes=raw,
                metadata=meta,
                error=f"Owner TID {m_owner} exited during resolution (/proc/{pid}/task)",
            )

        # Everything validated!
        return MutexOwnerResolutionResult(
            status=STATUS_OWNER_IDENTIFIED,
            owner_tid=m_owner,
            layout_id=layout_id,
            raw_bytes=raw,
            metadata=meta,
        )

    def find_processes(
        self,
        process_name: Optional[str] = None,
        companion_build_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        q = (process_name or "").strip().lower()
        target_bid = (companion_build_id or "").strip().lower() or None

        try:
            proc_entries = [e for e in os.listdir("/proc") if e.isdigit()]
        except Exception:
            return results

        for pid_str in proc_entries:
            pid = int(pid_str)
            if pid <= 1:
                continue
            comm = ""
            cmdline = ""
            exe_path = ""
            try:
                with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as f:
                    comm = f.read().strip()
            except Exception:
                continue

            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    raw_cmd = f.read(512)
                    cmdline = raw_cmd.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            except Exception:
                pass

            try:
                exe_path = os.path.realpath(f"/proc/{pid}/exe")
            except Exception:
                exe_path = ""

            exe_base = os.path.basename(exe_path) if exe_path else ""
            if q:
                if q not in comm.lower() and q not in exe_base.lower() and q not in cmdline.lower():
                    continue

            proc_bid = None
            bid_match = False
            has_dwarf = False
            if exe_path and os.path.isfile(exe_path):
                try:
                    ident = inspect_elf(exe_path)
                    proc_bid = ident.build_id
                    has_dwarf = bool(getattr(ident, "has_debug_info", False) or getattr(ident, "has_dwarf_info", False))
                    if target_bid and proc_bid and proc_bid.lower() == target_bid:
                        bid_match = True
                except Exception:
                    pass

            exact_name = bool(q and (comm.lower() == q or exe_base.lower() == q))
            results.append({
                "pid": pid,
                "name": comm or exe_base or f"pid_{pid}",
                "executable": exe_path,
                "cmdline": cmdline,
                "build_id": proc_bid,
                "has_dwarf_info": has_dwarf,
                "build_id_match": bid_match,
                "exact_name_match": exact_name,
                "is_remote": False,
                "host": self.target_host(),
            })

        results.sort(key=lambda r: (
            1 if r.get("build_id_match") else 0,
            1 if r.get("exact_name_match") else 0,
            1 if r.get("has_dwarf_info") else 0,
            r.get("pid", 0),
        ), reverse=True)
        return results[:max(1, limit)]


class RemoteSshTargetAdapter(TargetExecutionAdapter):
    """Execution adapter for remote Linux targets accessed via SSH / SSH Proxy.
    
    Zero-Python on target: uses standard POSIX shell, /proc, and dd/base64.
    Preserves target host namespace: NEVER opens or kills local /proc/<pid>.
    """

    def __init__(
        self,
        host: str,
        user: Optional[str] = None,
        port: int = 22,
        key_file: Optional[str] = None,
        proxy_jump: Optional[str] = None,
        proxy_command: Optional[str] = None,
        timeout_sec: float = 5.0,
        ssh_bin: str = "ssh",
        command_runner: Optional[Callable[[List[str], float], Tuple[int, str, str]]] = None,
        use_control_master: bool = False,
        collector_path: Optional[str] = None,
    ):
        if not host:
            raise ValueError("Remote host must be specified")
        self.host = host
        self.user = user
        self.port = int(port)
        self.key_file = key_file
        self.proxy_jump = proxy_jump
        self.proxy_command = proxy_command
        self.timeout_sec = float(timeout_sec)
        self.ssh_bin = ssh_bin
        self._command_runner = command_runner or self._default_command_runner
        self.use_control_master = bool(use_control_master)
        self.collector_path = (collector_path or "").strip() or None
        self._budget_tracker = None
        self._last_threads_bytes_read: int = 0
        self._last_maps_bytes_read: int = 0
        self._last_identity_bytes_read: int = 0
        self._last_identity_latency_us: float = 0.0

    def is_remote(self) -> bool:
        return True

    def target_host(self) -> str:
        u = f"{self.user}@" if self.user else ""
        p = f":{self.port}" if self.port != 22 else ""
        return f"{u}{self.host}{p}"

    def set_budget_tracker(self, tracker: Any) -> None:
        self._budget_tracker = tracker

    def get_budget_tracker(self) -> Optional[Any]:
        return getattr(self, "_budget_tracker", None)

    def _acquire_remote_admission(
        self,
        projected_bytes: int,
        profile_id: str,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> Tuple[Optional[Any], bool, Optional[str]]:
        eff_tracker = budget_tracker or getattr(self, "_budget_tracker", None)
        if eff_tracker is None:
            from .observation_budget import ObservationBudgetTracker
            eff_tracker = ObservationBudgetTracker.get_active_thread_tracker()

        if admission is not None:
            if getattr(admission, "is_terminal", False):
                return None, False, f"Admission in terminal state '{admission.state}'"
            return admission, False, None

        if eff_tracker is None:
            return None, False, None

        if eff_tracker.is_budget_exhausted:
            return None, False, f"Observation budget exhausted: {eff_tracker.exhaustion_reason}"

        active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
        try:
            if active_scope is not None and not active_scope.is_finalized:
                adm = active_scope.admit_read(projected_bytes=projected_bytes, profile_id=profile_id)
            else:
                adm = eff_tracker.admit_read(projected_bytes=projected_bytes, profile_id=profile_id)
            return adm, True, None
        except ValueError as ve:
            return None, False, f"Observation budget admission rejected: {ve}"

    def _finalize_remote_read(
        self,
        adm: Optional[Any],
        own_adm: bool,
        is_failure: bool,
        profile_id: str,
        budget_tracker: Optional[Any] = None,
        operation_id: Optional[str] = None,
    ) -> None:
        if not own_adm or adm is None:
            return
        eff_tracker = budget_tracker or getattr(self, "_budget_tracker", None)
        if eff_tracker is None:
            from .observation_budget import ObservationBudgetTracker
            eff_tracker = ObservationBudgetTracker.get_active_thread_tracker()
        if eff_tracker is None:
            return

        tot_b = adm.consumed_bytes
        has_child = bool(getattr(adm, "child_reads", None))
        has_consumed_child = any(
            c.state in ("CONSUMED", "ACCOUNTED", "FAILED_ACCOUNTED")
            for c in getattr(adm, "child_reads", {}).values()
        ) if has_child else False

        if tot_b > 0 or adm.state == "CONSUMED" or has_consumed_child:
            active_scope = eff_tracker.get_active_scope() if hasattr(eff_tracker, "get_active_scope") else None
            if active_scope is not None and not active_scope.is_finalized:
                active_scope.record_read(bytes_read=tot_b, admission=adm, profile_id=profile_id, is_failure=is_failure)
            else:
                eff_op_id = operation_id or f"standalone_remote_{profile_id}_{uuid.uuid4().hex[:8]}"
                m_bytes = None
                e_bytes = None
                if not has_child:
                    if is_failure:
                        e_bytes = tot_b
                    else:
                        m_bytes = tot_b
                eff_tracker.commit_transaction(
                    operation_id=eff_op_id,
                    profile_id=profile_id,
                    measured_bytes=m_bytes,
                    estimated_bytes=e_bytes,
                    is_failure=is_failure,
                    reservations=[adm],
                )
        else:
            if adm.state in ("ADMITTED", "RESERVED"):
                eff_tracker.release_reservation(adm)

    def _default_command_runner(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        try:
            res = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"SSH command timed out after {timeout:.1f}s"
        except FileNotFoundError as fnf:
            return -2, "", f"SSH command execution failed before invocation: {fnf}"
        except Exception as e:
            err_msg = str(e)
            if "not found" in err_msg.lower() or "permission" in err_msg.lower():
                return -2, "", f"SSH command execution failed before invocation: {e}"
            return -1, "", f"SSH execution error: {e}"

    def _check_pre_invocation(self, cmd_args: List[str]) -> Tuple[bool, Optional[str]]:
        """Validates command and executable availability strictly before process invocation."""
        if getattr(self._command_runner, "fail_before_execution", False):
            return False, "ssh binary not found on local PATH before execution"
        if hasattr(self._command_runner, "check_preflight"):
            ok, reason = self._command_runner.check_preflight(cmd_args)
            if not ok:
                return False, reason
        if self._command_runner == self._default_command_runner:
            exe = self.ssh_bin
            if not (shutil.which(exe) or (os.path.isabs(exe) and os.access(exe, os.X_OK))):
                return False, f"executable '{exe}' not found on host before process creation"
        return True, None

    def run_ssh(
        self,
        remote_shell_cmd: str,
        timeout: Optional[float] = None,
        admission: Optional[Any] = None,
        child_read: Optional[Union[Any, List[Any]]] = None,
        child_reads: Optional[List[Any]] = None,
        invocation_id: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """Runs a command on the remote target using configured SSH parameters."""
        children: List[Any] = []
        if child_reads is not None:
            children.extend(cr for cr in child_reads if cr is not None)
        if child_read is not None:
            if isinstance(child_read, (list, tuple)):
                children.extend(cr for cr in child_read if cr is not None)
            else:
                children.append(child_read)

        if admission is not None and getattr(admission, "is_terminal", False):
            raise RuntimeError(f"Cannot execute SSH command under terminal admission '{admission.state}'")
        for cr in children:
            if getattr(cr, "is_terminal", False):
                raise RuntimeError(f"Cannot execute SSH command under terminal child read '{cr.state}'")

        t = timeout or self.timeout_sec
        args = [
            self.ssh_bin,
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=5",
        ]
        if self.key_file:
            args.extend(["-i", self.key_file])
        if self.proxy_jump:
            args.extend(["-J", self.proxy_jump])
        if self.proxy_command:
            args.extend(["-o", f"ProxyCommand={self.proxy_command}"])
        if self.use_control_master:
            args.extend([
                "-o", "ControlMaster=auto",
                "-o", "ControlPath=/tmp/dynstate_ssh_%r@%h:%p",
                "-o", "ControlPersist=60s",
            ])

        target_spec = f"{self.user}@{self.host}" if self.user else self.host
        args.append(target_spec)
        args.append(remote_shell_cmd)

        # 1. Pre-invocation boundary: verify executable availability before process creation
        pre_ok, pre_reason = self._check_pre_invocation(args)
        if not pre_ok:
            return -2, "", f"SSH command execution failed before invocation: {pre_reason}"

        # 2. CROSS INVOCATION BOUNDARY: Mark physical execution started immediately before runner invocation
        if admission is not None and not admission.is_terminal and admission.state == "ADMITTED":
            admission.mark_physical_read_started()
        for cr in children:
            if not cr.is_terminal and cr.state == "ADMITTED":
                cr.mark_started()

        # 3. Invoke command runner (in-flight state is guaranteed to be PHYSICAL_READ_STARTED)
        try:
            rc, stdout, stderr = self._command_runner(args, t)
        except subprocess.TimeoutExpired:
            rc, stdout, stderr = -1, "", f"SSH command timed out after {t:.1f}s"
        except Exception as e:
            rc, stdout, stderr = -1, "", f"SSH execution error: {e}"

        return rc, stdout, stderr

    def check_liveness(
        self,
        pid: int,
        admission: Optional[Any] = None,
        child_read: Optional[Any] = None,
    ) -> Tuple[bool, Optional[str]]:
        if pid <= 0:
            return False, f"Invalid PID {pid}"
        
        # Test liveness strictly on remote target host
        cmd = f"kill -0 {int(pid)} 2>/dev/null && echo ALIVE || echo DEAD"
        rc, stdout, stderr = self.run_ssh(cmd, admission=admission, child_read=child_read)
        if rc == -2:
            if child_read is not None and not child_read.is_terminal:
                child_read.release()
            return False, f"SSH command execution failed before invocation: {stderr.strip()}"
        if rc != 0:
            if child_read is not None and not child_read.is_terminal:
                child_read.consume(actual_bytes=None, conservative_estimate_bytes=64, is_failure=True, failure_reason=stderr.strip() or f"Exit {rc}")
            return False, f"SSH transport failure to {self.target_host()}: {stderr.strip() or 'Exit ' + str(rc)}"
        
        out = stdout.strip()
        if child_read is not None and not child_read.is_terminal:
            child_read.consume(actual_bytes=0, is_failure=False)
        if "ALIVE" in out:
            return True, None
        return False, f"Target PID {pid} is not running on {self.target_host()}"

    def get_process_identity(
        self,
        pid: int,
        companion_build_id: Optional[str] = None,
        companion_elf_path: Optional[str] = None,
        budget_tracker: Optional[Any] = None,
        operation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Discovers remote process executable, architecture, and Build ID.
        
        Reads the first 64KB of remote /proc/<pid>/exe and parses ELF header host-side.
        """
        t_id_start = time.monotonic()
        empty_breakdown = {
            "readlink_bytes": 0,
            "stat_bytes": 0,
            "elf_bytes_read": 0,
            "elf_bytes_from_cache": 0,
            "total_measured_bytes": 0,
            "estimated_bytes_read": 0,
            "measurement_status": "UNAVAILABLE",
        }
        if pid <= 0:
            self._last_identity_bytes_read = 0
            self._last_identity_estimated_bytes = 0
            self._last_identity_status = "UNAVAILABLE"
            self._last_identity_breakdown = empty_breakdown
            self._last_identity_latency_us = (time.monotonic() - t_id_start) * 1_000_000.0
            return {
                "pid": pid,
                "status": "FAILED",
                "identity_status": IDENTITY_UNAVAILABLE,
                "executable": "",
                "architecture": "unknown",
                "elf_class": "unknown",
                "endianness": "unknown",
                "elf_type": "unknown",
                "build_id": None,
                "pt_loads": [],
                "process_start_time": None,
                "is_remote": True,
                "host": self.target_host(),
                "error": f"Invalid PID {pid}",
                "measured_bytes_read": 0,
                "estimated_bytes_read": 0,
                "measurement_status": "UNAVAILABLE",
                "measurement_breakdown": empty_breakdown,
            }

        # 1. Pre-read budget admission MUST occur before ANY remote execution (including check_liveness)
        adm, own_adm, rej_err = self._acquire_remote_admission(65536 + 4096, "target_identity", admission=None, budget_tracker=budget_tracker)
        if rej_err:
            self._last_identity_bytes_read = 0
            self._last_identity_estimated_bytes = 0
            self._last_identity_status = "UNAVAILABLE"
            self._last_identity_breakdown = empty_breakdown
            self._last_identity_latency_us = (time.monotonic() - t_id_start) * 1_000_000.0
            return {
                "pid": pid,
                "status": "FAILED",
                "identity_status": IDENTITY_UNAVAILABLE,
                "executable": "",
                "architecture": "unknown",
                "elf_class": "unknown",
                "endianness": "unknown",
                "elf_type": "unknown",
                "build_id": None,
                "pt_loads": [],
                "process_start_time": None,
                "is_remote": True,
                "host": self.target_host(),
                "error": f"Observation budget admission rejected: {rej_err}",
                "measured_bytes_read": 0,
                "estimated_bytes_read": 0,
                "measurement_status": "UNAVAILABLE",
                "measurement_breakdown": empty_breakdown,
            }

        # 2. Check liveness under admission
        pread_live = adm.start_child_read(target_type="remote_identity_liveness", target_spec={"pid": pid}) if adm is not None else None
        alive, live_err = self.check_liveness(pid, admission=adm, child_read=pread_live)
        if not alive:
            self._finalize_remote_read(adm, own_adm, True, "target_identity", budget_tracker, operation_id=f"proc_identity_{pid}_{uuid.uuid4().hex[:8]}")
            self._last_identity_bytes_read = 0
            est_b = sum(c.estimated_bytes_read for c in adm.child_reads.values()) if adm else 0
            self._last_identity_estimated_bytes = est_b
            self._last_identity_status = "UNAVAILABLE"
            self._last_identity_breakdown = empty_breakdown
            self._last_identity_latency_us = (time.monotonic() - t_id_start) * 1_000_000.0
            return {
                "pid": pid,
                "status": "TARGET_TERMINATED",
                "identity_status": IDENTITY_UNAVAILABLE,
                "executable": "",
                "architecture": "unknown",
                "elf_class": "unknown",
                "endianness": "unknown",
                "elf_type": "unknown",
                "build_id": None,
                "pt_loads": [],
                "process_start_time": None,
                "is_remote": True,
                "host": self.target_host(),
                "error": live_err or f"Target PID {pid} is not running on {self.target_host()}",
                "measured_bytes_read": 0,
                "estimated_bytes_read": est_b,
                "measurement_status": "UNAVAILABLE",
                "measurement_breakdown": empty_breakdown,
            }

        readlink_bytes = 0
        stat_bytes = 0
        elf_bytes_read = 0

        # 1. Resolve remote executable path
        pread_exe = adm.start_child_read(target_type="remote_identity_readlink", target_spec={"pid": pid}) if adm is not None else None
        cmd_exe = f"readlink -f /proc/{int(pid)}/exe 2>/dev/null || readlink /proc/{int(pid)}/exe 2>/dev/null"
        rc_exe, stdout_exe, stderr_exe = self.run_ssh(cmd_exe, admission=adm, child_read=pread_exe)
        remote_exe = stdout_exe.strip() if rc_exe == 0 else ""
        b_exe = len(stdout_exe.encode("utf-8", errors="replace")) if (rc_exe == 0 and stdout_exe) else 0
        readlink_bytes += b_exe
        if pread_exe is not None:
            if rc_exe == -2:
                pread_exe.release()
            elif rc_exe == 0 and stdout_exe.strip():
                pread_exe.consume(actual_bytes=b_exe, is_failure=False)
            else:
                pread_exe.consume(actual_bytes=None, conservative_estimate_bytes=1024, is_failure=True, failure_reason=stderr_exe.strip() or f"readlink failed rc={rc_exe}")

        # 2. Extract remote process start time from /proc/<pid>/stat
        pread_stat = adm.start_child_read(target_type="remote_identity_stat", target_spec={"pid": pid}) if adm is not None else None
        cmd_stat = f"cat /proc/{int(pid)}/stat 2>/dev/null"
        rc_stat, stdout_stat, stderr_stat = self.run_ssh(cmd_stat, admission=adm, child_read=pread_stat)
        start_time = None
        b_stat = len(stdout_stat.encode("utf-8", errors="replace")) if (rc_stat == 0 and stdout_stat) else 0
        stat_bytes += b_stat
        if pread_stat is not None:
            if rc_stat == -2:
                pread_stat.release()
            elif rc_stat == 0 and stdout_stat.strip():
                pread_stat.consume(actual_bytes=b_stat, is_failure=False)
            else:
                pread_stat.consume(actual_bytes=None, conservative_estimate_bytes=1024, is_failure=True, failure_reason=stderr_stat.strip() or f"stat failed rc={rc_stat}")

        if rc_stat == 0 and stdout_stat:
            r_paren = stdout_stat.rfind(")")
            if r_paren != -1:
                fields = stdout_stat[r_paren + 1:].split()
                if len(fields) >= 20:
                    try:
                        start_time = int(fields[19])
                    except ValueError:
                        pass

        # 3. Extract first 64KB of executable via base64 to inspect ELF header on host
        pread_hdr = adm.start_child_read(target_type="remote_identity_elf", target_spec={"pid": pid}) if adm is not None else None
        cmd_hdr = f"head -c 65536 /proc/{int(pid)}/exe 2>/dev/null | base64"
        rc_hdr, stdout_b64, stderr_hdr = self.run_ssh(cmd_hdr, timeout=self.timeout_sec * 1.5, admission=adm, child_read=pread_hdr)
        b_hdr = len(stdout_b64.encode("utf-8", errors="replace")) if (rc_hdr == 0 and stdout_b64) else 0
        elf_bytes_read += b_hdr
        if pread_hdr is not None:
            if rc_hdr == -2:
                pread_hdr.release()
            elif rc_hdr == 0 and stdout_b64.strip():
                pread_hdr.consume(actual_bytes=b_hdr, is_failure=False)
            else:
                pread_hdr.consume(actual_bytes=None, conservative_estimate_bytes=65536, is_failure=True, failure_reason=stderr_hdr.strip() or f"ELF header read failed rc={rc_hdr}")

        arch = "unknown"
        elf_class = "unknown"
        endianness = "unknown"
        elf_type = "unknown"
        build_id = None
        pt_loads: List[Dict[str, Any]] = []

        if rc_hdr == 0 and stdout_b64.strip():
            raw_b64 = stdout_b64.strip()
            try:
                raw_elf = base64.b64decode(raw_b64)
                if len(raw_elf) >= 64:
                    with tempfile.NamedTemporaryFile(prefix="rem_elf_", suffix=".tmp", delete=False) as tf:
                        tf.write(raw_elf)
                        tf.flush()
                        tmp_name = tf.name
                    try:
                        ident = inspect_elf(tmp_name)
                        arch = ident.architecture
                        elf_class = ident.elf_class
                        endianness = ident.endianness
                        elf_type = ident.elf_type
                        build_id = ident.build_id
                        pt_loads = ident.pt_loads
                    finally:
                        if os.path.exists(tmp_name):
                            os.remove(tmp_name)
            except Exception:
                pass

        total_measured_bytes = readlink_bytes + stat_bytes + elf_bytes_read
        total_estimated_bytes = sum(c.estimated_bytes_read for c in adm.child_reads.values()) if adm else 0
        total_charged_bytes = total_measured_bytes + total_estimated_bytes
        has_unknown = (total_estimated_bytes > 0)
        meas_status = "EXACT_MEASURED" if (total_measured_bytes > 0 and not has_unknown) else ("PARTIAL_UNKNOWN" if total_measured_bytes > 0 else ("UNKNOWN" if has_unknown else "UNAVAILABLE"))
        meas_breakdown = {
            "readlink_bytes": readlink_bytes,
            "stat_bytes": stat_bytes,
            "elf_bytes_read": elf_bytes_read,
            "elf_bytes_from_cache": 0,
            "total_measured_bytes": total_measured_bytes,
            "estimated_bytes_read": total_estimated_bytes,
            "measurement_status": meas_status,
        }

        self._last_identity_bytes_read = total_measured_bytes
        self._last_identity_estimated_bytes = total_estimated_bytes
        self._last_identity_status = meas_status
        self._last_identity_breakdown = meas_breakdown
        self._last_identity_latency_us = (time.monotonic() - t_id_start) * 1_000_000.0

        # Strict verified identity check for remote targets
        is_verified = bool(remote_exe and start_time and start_time > 0 and arch != "unknown")
        identity_status = IDENTITY_VERIFIED if is_verified else (IDENTITY_UNVERIFIED if remote_exe else IDENTITY_UNAVAILABLE)

        op_id = operation_id or f"proc_identity_{pid}_{uuid.uuid4().hex[:8]}"
        m_type = "MEASURED" if total_measured_bytes > 0 else ("UNKNOWN" if total_charged_bytes > 0 else "NONE")
        acct_status = "PENDING"
        if own_adm and total_charged_bytes > 0:
            acct_status = "COMMITTED"
        self._finalize_remote_read(adm, own_adm, not is_verified, "target_identity", budget_tracker, operation_id=op_id)

        return {
            "pid": pid,
            "executable": remote_exe,
            "process_start_time": start_time,
            "architecture": arch,
            "elf_class": elf_class,
            "endianness": endianness,
            "elf_type": elf_type,
            "build_id": build_id,
            "pt_loads": pt_loads,
            "status": "OBSERVED" if remote_exe else "FAILED",
            "identity_status": identity_status,
            "is_remote": True,
            "host": self.target_host(),
            "measured_bytes_read": total_measured_bytes,
            "estimated_bytes_read": total_estimated_bytes,
            "charged_bytes": total_charged_bytes,
            "measurement_status": meas_status,
            "measurement_type": m_type,
            "accounting_owner": "ADAPTER",
            "accounting_status": acct_status,
            "operation_id": op_id,
            "measurement_breakdown": meas_breakdown,
        }

    def get_process_memory_info(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Reads detailed process memory metrics from remote /proc/<pid>/statm, status, and smaps_rollup."""
        adm, own_adm, rej_err = self._acquire_remote_admission(4096, "target_memory_info", admission=admission, budget_tracker=budget_tracker)
        if rej_err:
            return {"status": "UNAVAILABLE", "pid": pid, "metrics": {}, "mappings_summary": {}, "metadata": {}, "error": rej_err}

        pread_live = adm.start_child_read(target_type="remote_meminfo_liveness", target_spec={"pid": pid}) if adm is not None else None
        alive, live_err = self.check_liveness(pid, admission=adm, child_read=pread_live)
        if not alive:
            self._finalize_remote_read(adm, own_adm, True, "target_memory_info", budget_tracker)
            return {"status": "TARGET_TERMINATED", "pid": pid, "metrics": {}, "mappings_summary": {}, "metadata": {}, "error": live_err or "Remote process terminated"}

        pread = adm.start_child_read(target_type="remote_process_memory_info", target_spec={"pid": pid}) if adm is not None else None
        cmd = (
            f"cat /proc/{int(pid)}/statm 2>/dev/null; "
            f"echo '---DELIM_STATUS---'; cat /proc/{int(pid)}/status 2>/dev/null; "
            f"echo '---DELIM_SMAPS---'; head -c 4096 /proc/{int(pid)}/smaps_rollup 2>/dev/null"
        )
        rc, stdout, stderr = self.run_ssh(cmd, admission=adm, child_read=pread)
        if rc == -2:
            if pread is not None:
                pread.release()
            self._finalize_remote_read(adm, own_adm, False, "target_memory_info", budget_tracker)
            return {"status": "UNAVAILABLE", "pid": pid, "metrics": {}, "mappings_summary": {}, "metadata": {}, "error": stderr.strip()}
        elif rc != 0 or not stdout:
            if pread is not None:
                pread.consume(actual_bytes=None, conservative_estimate_bytes=4096, is_failure=True)
            self._finalize_remote_read(adm, own_adm, True, "target_memory_info", budget_tracker)
            return {"status": "UNAVAILABLE", "pid": pid, "metrics": {}, "mappings_summary": {}, "metadata": {}}

        b_statm = len(stdout.encode("utf-8")) if stdout else 0
        if pread is not None:
            pread.consume(actual_bytes=b_statm)

        parts = stdout.split("---DELIM_STATUS---")
        raw_statm = parts[0].strip() if len(parts) > 0 else ""
        rest = parts[1] if len(parts) > 1 else ""
        subparts = rest.split("---DELIM_SMAPS---")
        raw_status = subparts[0].strip() if len(subparts) > 0 else ""
        raw_smaps = subparts[1].strip() if len(subparts) > 1 else ""

        page_size = 4096
        statm_vsz = None
        statm_rss = None
        statm_shared = None
        statm_data = None
        if raw_statm:
            sm_parts = raw_statm.split()
            if len(sm_parts) >= 6:
                try:
                    statm_vsz = int(sm_parts[0]) * page_size
                    statm_rss = int(sm_parts[1]) * page_size
                    statm_shared = int(sm_parts[2]) * page_size
                    statm_data = int(sm_parts[5]) * page_size
                except ValueError:
                    pass

        status_vsz = None
        status_rss = None
        rss_anon = None
        rss_file = None
        rss_shmem = None
        vm_peak = None
        vm_hwm = None
        vm_data = None
        vm_swap = None
        for line in raw_status.splitlines():
            line_s = line.strip()
            try:
                if line_s.startswith("VmSize:"):
                    status_vsz = int(line_s.split()[1]) * 1024
                elif line_s.startswith("VmRSS:"):
                    status_rss = int(line_s.split()[1]) * 1024
                elif line_s.startswith("RssAnon:"):
                    rss_anon = int(line_s.split()[1]) * 1024
                elif line_s.startswith("RssFile:"):
                    rss_file = int(line_s.split()[1]) * 1024
                elif line_s.startswith("RssShmem:"):
                    rss_shmem = int(line_s.split()[1]) * 1024
                elif line_s.startswith("VmPeak:"):
                    vm_peak = int(line_s.split()[1]) * 1024
                elif line_s.startswith("VmHWM:"):
                    vm_hwm = int(line_s.split()[1]) * 1024
                elif line_s.startswith("VmData:"):
                    vm_data = int(line_s.split()[1]) * 1024
                elif line_s.startswith("VmSwap:"):
                    vm_swap = int(line_s.split()[1]) * 1024
            except (IndexError, ValueError):
                pass

        pss = None
        private_dirty = None
        for line in raw_smaps.splitlines():
            line_s = line.strip()
            try:
                if line_s.startswith("Pss:"):
                    pss = int(line_s.split()[1]) * 1024
                elif line_s.startswith("Private_Dirty:"):
                    private_dirty = int(line_s.split()[1]) * 1024
            except (IndexError, ValueError):
                pass

        maps = self.get_proc_maps(pid, admission=adm, budget_tracker=budget_tracker)
        total_mapping_size = sum(m.get("size", 0) for m in maps)
        heap_mapping_size = sum(m.get("size", 0) for m in maps if m.get("category") == "heap" or m.get("pathname") == "[heap]")
        anon_mapping_size = sum(m.get("size", 0) for m in maps if m.get("category") == "anonymous" and m.get("is_writable"))
        stack_mapping_size = sum(m.get("size", 0) for m in maps if m.get("category") == "stack")

        vsz_eff = status_vsz if status_vsz is not None else (statm_vsz if statm_vsz is not None else total_mapping_size)
        rss_eff = status_rss if status_rss is not None else statm_rss

        self._finalize_remote_read(adm, own_adm, False, "target_memory_info", budget_tracker)

        return {
            "status": "OBSERVED",
            "timestamp": time.time(),
            "pid": pid,
            "metrics": {
                "vsz_bytes": vsz_eff,
                "rss_bytes": rss_eff,
                "rss_anon_bytes": rss_anon,
                "rss_file_bytes": rss_file,
                "rss_shmem_bytes": rss_shmem,
                "vm_peak_bytes": vm_peak,
                "vm_hwm_bytes": vm_hwm,
                "vm_data_bytes": vm_data if vm_data is not None else statm_data,
                "vm_swap_bytes": vm_swap,
                "pss_bytes": pss,
                "private_dirty_bytes": private_dirty,
            },
            "mappings_summary": {
                "mapping_count": len(maps),
                "total_mapping_size_bytes": total_mapping_size,
                "heap_mapping_size_bytes": heap_mapping_size,
                "writable_anon_mapping_size_bytes": anon_mapping_size,
                "stack_mapping_size_bytes": stack_mapping_size,
            },
            "metadata": {
                "vsz": {"source": "remote /proc/<pid>/status", "limitations": "Virtual address space only"},
                "rss": {"source": "remote /proc/<pid>/status", "limitations": "Physical pages in RAM"},
                "allocation_evidence": {"source": "None in /proc", "limitations": "Individual heap chunk lifetimes cannot be proven by procfs alone"},
            },
        }

    def get_proc_maps(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        adm, own_adm, rej_err = self._acquire_remote_admission(4096, "target_maps", admission=admission, budget_tracker=budget_tracker)
        if rej_err:
            self._last_maps_bytes_read = 0
            return []

        pread = adm.start_child_read(target_type="remote_proc_maps", target_spec={"pid": pid}) if adm is not None else None
        cmd = f"cat /proc/{int(pid)}/maps 2>/dev/null"
        rc, stdout, stderr = self.run_ssh(cmd, admission=adm, child_read=pread)
        mappings: List[Dict[str, Any]] = []
        if rc == -2:
            if pread is not None:
                pread.release()
            self._finalize_remote_read(adm, own_adm, False, "target_maps", budget_tracker)
            self._last_maps_bytes_read = 0
            return []
        elif rc != 0:
            if pread is not None:
                pread.consume(actual_bytes=None, conservative_estimate_bytes=4096, is_failure=True)
            self._finalize_remote_read(adm, own_adm, True, "target_maps", budget_tracker)
            self._last_maps_bytes_read = 0
            return []

        b_maps = len(stdout.encode("utf-8")) if stdout else 0
        if not stdout:
            if pread is not None:
                pread.consume(actual_bytes=None, conservative_estimate_bytes=4096, is_failure=True, failure_reason="Empty maps output")
            self._finalize_remote_read(adm, own_adm, True, "target_maps", budget_tracker)
            self._last_maps_bytes_read = 0
            return mappings

        self._last_maps_bytes_read = b_maps
        if pread is not None:
            pread.consume(actual_bytes=b_maps, is_failure=False)
        self._finalize_remote_read(adm, own_adm, False, "target_maps", budget_tracker)

        for line in stdout.splitlines():
            parts = line.strip().split(maxsplit=5)
            if len(parts) >= 5:
                addr_range = parts[0]
                perms = parts[1]
                offset = parts[2]
                pathname = parts[5] if len(parts) >= 6 else ""

                try:
                    start_hex, end_hex = addr_range.split("-")
                    s_int = int(start_hex, 16)
                    e_int = int(end_hex, 16)
                    off_int = int(offset, 16)
                except Exception:
                    continue

                category = "anonymous"
                if pathname == "[heap]":
                    category = "heap"
                elif pathname.startswith("[stack"):
                    category = "stack"
                elif pathname:
                    if "x" in perms:
                        category = "code"
                    elif "w" in perms:
                        category = "data"
                    else:
                        category = "file"

                mappings.append({
                    "start": f"0x{s_int:x}",
                    "end": f"0x{e_int:x}",
                    "start_int": s_int,
                    "end_int": e_int,
                    "size": e_int - s_int,
                    "permissions": perms,
                    "offset": offset,
                    "offset_int": off_int,
                    "category": category,
                    "pathname": pathname,
                    "is_readable": "r" in perms,
                    "is_writable": "w" in perms,
                    "is_executable": "x" in perms,
                })
        return mappings

    def get_threads(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        adm, own_adm, rej_err = self._acquire_remote_admission(4096, "target_threads", admission=admission, budget_tracker=budget_tracker)
        if rej_err:
            self._last_threads_bytes_read = 0
            return []

        pread = adm.start_child_read(target_type="remote_threads", target_spec={"pid": pid}) if adm is not None else None
        # Efficient remote script to list threads without spawning multiple remote processes
        remote_script = (
            f"for t in /proc/{int(pid)}/task/*; do "
            f"[ -d \"$t\" ] || continue; "
            f"tid=$(basename \"$t\"); "
            f"comm=$(cat \"$t/comm\" 2>/dev/null || echo unknown); "
            f"stat=$(cat \"$t/stat\" 2>/dev/null | awk '{{print $3}}' || echo UNKNOWN); "
            f"echo \"$tid $stat $comm\"; "
            f"done"
        )
        rc, stdout, stderr = self.run_ssh(f"sh -c {shlex.quote(remote_script)}", admission=adm, child_read=pread)
        threads: List[Dict[str, Any]] = []
        if rc == -2:
            if pread is not None:
                pread.release()
            self._finalize_remote_read(adm, own_adm, False, "target_threads", budget_tracker)
            self._last_threads_bytes_read = 0
            return []
        elif rc != 0:
            if pread is not None:
                pread.consume(actual_bytes=None, conservative_estimate_bytes=2048, is_failure=True)
            self._finalize_remote_read(adm, own_adm, True, "target_threads", budget_tracker)
            self._last_threads_bytes_read = 0
            return []

        b_threads = len(stdout.encode("utf-8")) if stdout else 0
        if not stdout:
            if pread is not None:
                pread.consume(actual_bytes=None, conservative_estimate_bytes=2048, is_failure=True, failure_reason="Empty threads output")
            self._finalize_remote_read(adm, own_adm, True, "target_threads", budget_tracker)
            self._last_threads_bytes_read = 0
            return []

        self._last_threads_bytes_read = b_threads
        if pread is not None:
            pread.consume(actual_bytes=b_threads, is_failure=False)
        self._finalize_remote_read(adm, own_adm, False, "target_threads", budget_tracker)

        for line in stdout.splitlines():
            tokens = line.strip().split(maxsplit=2)
            if len(tokens) >= 2 and tokens[0].isdigit():
                tid = int(tokens[0])
                state = tokens[1]
                comm = tokens[2] if len(tokens) >= 3 else "unknown"
                threads.append({
                    "tid": tid,
                    "name": comm,
                    "state": state,
                    "stack_info": {
                        "status": "UNAVAILABLE",
                        "reason": "Remote thread stack mapping not inspected over lightweight ssh adapter",
                    },
                    "local_variables": {
                        "status": "UNSUPPORTED",
                        "reason": "Stack frame inspection requires an active debugger backend.",
                    },
                })

        self._last_threads_bytes_read = len(stdout.encode("utf-8")) if stdout else 0
        threads.sort(key=lambda t: t["tid"])
        return threads

    def resolve_mutex_owner(
        self,
        pid: int,
        lock_addr: Union[int, str],
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> MutexOwnerResolutionResult:
        """Remote mutex owner resolution is unsupported without an in-target verified agent.
        
        Strictly fails closed without touching local /proc or local process memory.
        """
        return MutexOwnerResolutionResult(
            status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
            error=f"Remote target {self.target_host()} does not support verified pthread_mutex inspection over lightweight adapter",
        )

    def _read_slices_via_collector(
        self,
        pid: int,
        slices: List[Tuple[int, int]],
        admission: Optional[Any] = None,
        child_reads: Optional[List[Any]] = None,
        invocation_id: Optional[str] = None,
    ) -> Optional[List[Tuple[Optional[bytes], str, Optional[str]]]]:
        """Uses C99 dynamicstate-collector --read-slices on the remote target for zero-stop process_vm_readv batch reads."""
        if not self.collector_path or not slices:
            return None
        import json as _json
        spec = ",".join(f"0x{int(addr):x}:{max(0, int(sz))}" for addr, sz in slices)
        cmd = f"{shlex.quote(self.collector_path)} -p {int(pid)} --read-slices {shlex.quote(spec)} 2>/dev/null"
        rc, stdout, stderr = self.run_ssh(
            cmd,
            admission=admission,
            child_reads=child_reads,
            invocation_id=invocation_id,
        )
        if rc == 127 or "not found" in stderr.lower() or rc == -2:
            return None
        if not stdout.strip():
            return None
        try:
            payload = _json.loads(stdout.strip().splitlines()[-1])
            if not payload.get("success") or "slices" not in payload:
                err_code = payload.get("error")
                if err_code == "TARGET_TERMINATED":
                    return [(None, "TARGET_TERMINATED", "Remote process terminated") for _ in slices]
                if err_code == "PERMISSION_DENIED":
                    return [(None, "PERMISSION_DENIED", "Permission denied accessing remote process memory") for _ in slices]
                return None
            out_list: List[Tuple[Optional[bytes], str, Optional[str]]] = []
            raw_slices = payload.get("slices", [])
            for idx, (req_addr, req_sz) in enumerate(slices):
                if req_sz <= 0:
                    out_list.append((b"", "OBSERVED", None))
                    continue
                s_item = raw_slices[idx] if idx < len(raw_slices) else {}
                st = s_item.get("status", "UNAVAILABLE")
                hex_str = s_item.get("hex", "")
                raw_b = bytes.fromhex(hex_str) if hex_str else b""
                if st == "OBSERVED" and len(raw_b) == req_sz:
                    out_list.append((raw_b, "OBSERVED", None))
                elif len(raw_b) > 0:
                    out_list.append((raw_b, "PARTIAL", f"Partial read: {len(raw_b)}/{req_sz} bytes"))
                else:
                    out_list.append((None, st if st in ("UNAVAILABLE", "PERMISSION_DENIED", "TARGET_TERMINATED") else "UNAVAILABLE", f"Collector read status: {st} at 0x{req_addr:x}"))
            return out_list
        except Exception:
            return None

    def read_memory_batch(
        self,
        pid: int,
        slices: List[Tuple[int, int]],
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Tuple[Optional[bytes], str, Optional[str]]]:
        """Reads multiple memory slices in a single SSH roundtrip (via C99 collector or batched POSIX shell)."""
        if not slices:
            return []

        total_proj = sum(sz for _, sz in slices)
        adm, own_adm, rej_err = self._acquire_remote_admission(total_proj, "memory_read_batch", admission=admission, budget_tracker=budget_tracker)
        if rej_err:
            return [(None, "BUDGET_EXHAUSTED", rej_err) for _ in slices]

        if len(slices) == 1 and not self.collector_path:
            return [self.read_memory(pid, slices[0][0], slices[0][1], admission=adm, budget_tracker=budget_tracker)]

        if self.collector_path:
            inv_coll_id = f"inv_coll_{uuid.uuid4().hex[:12]}"
            child_reads_coll = [
                adm.start_child_read(
                    target_type="remote_collector_memory_slice",
                    target_spec={
                        "pid": pid,
                        "address": addr,
                        "size": sz,
                        "slice_index": idx,
                        "path": self.collector_path,
                        "invocation_id": inv_coll_id,
                        "invocation_type": "collector",
                    },
                )
                for idx, (addr, sz) in enumerate(slices)
            ] if adm is not None else [None for _ in slices]

            coll_res = self._read_slices_via_collector(
                pid,
                slices,
                admission=adm,
                child_reads=child_reads_coll,
                invocation_id=inv_coll_id,
            )
            if coll_res is not None:
                any_fail = False
                for idx, res_item in enumerate(coll_res):
                    res_b, res_st, _ = res_item
                    is_fail = (res_st not in ("OBSERVED", "PARTIAL"))
                    if is_fail:
                        any_fail = True
                    cr = child_reads_coll[idx]
                    req_sz = slices[idx][1]
                    if cr is not None:
                        if is_fail and res_b is None:
                            cr.consume(actual_bytes=None, conservative_estimate_bytes=req_sz, is_failure=True)
                        else:
                            act_b = len(res_b) if res_b else 0
                            cr.consume(actual_bytes=act_b, is_failure=is_fail)
                self._finalize_remote_read(adm, own_adm, any_fail, "memory_read_batch", budget_tracker)
                return coll_res
            else:
                for idx, cr in enumerate(child_reads_coll):
                    if cr is not None:
                        req_sz = slices[idx][1]
                        if cr.state == "PHYSICAL_READ_STARTED":
                            cr.consume(actual_bytes=0, is_failure=True, failure_reason="Collector execution failed")
                        elif cr.state == "ADMITTED":
                            cr.release()

        # Shell fallback path
        inv_shell_id = f"inv_shell_{uuid.uuid4().hex[:12]}"
        child_reads_shell = [
            adm.start_child_read(
                target_type="remote_shell_memory_slice",
                target_spec={
                    "pid": pid,
                    "address": addr,
                    "size": sz,
                    "slice_index": idx,
                    "invocation_id": inv_shell_id,
                    "invocation_type": "shell_fallback",
                },
            )
            for idx, (addr, sz) in enumerate(slices)
        ] if adm is not None else [None for _ in slices]

        cmds = []
        for idx, (addr, sz) in enumerate(slices):
            a_int = int(addr)
            s_int = max(0, int(sz))
            if s_int == 0:
                cmds.append(f"echo '{idx}|'")
                continue
            page_sz = 4096
            page_num = a_int // page_sz
            page_off = a_int % page_sz
            pages_needed = ((page_off + s_int + page_sz - 1) // page_sz)
            cmds.append(
                f"b=$(dd if=/proc/{int(pid)}/mem bs=1 skip={a_int} count={s_int} 2>/dev/null | base64 | tr -d '\\n'); "
                f"if [ -z \"$b\" ]; then "
                f"b=$(dd if=/proc/{int(pid)}/mem bs={page_sz} skip={page_num} count={pages_needed} 2>/dev/null | "
                f"dd bs=1 skip={page_off} count={s_int} 2>/dev/null | base64 | tr -d '\\n'); "
                f"fi; "
                f"echo \"{idx}|$b\""
            )
        remote_script = "; ".join(cmds)
        rc, stdout, stderr = self.run_ssh(
            f"sh -c {shlex.quote(remote_script)}",
            admission=adm,
            child_reads=child_reads_shell,
            invocation_id=inv_shell_id,
        )
        if rc == -2:
            for cr in child_reads_shell:
                if cr is not None and not cr.is_terminal:
                    cr.release()
            self._finalize_remote_read(adm, own_adm, False, "memory_read_batch", budget_tracker)
            return [(None, "UNAVAILABLE", f"SSH transport failed before execution: {stderr.strip()}") for _ in slices]

        if rc != 0:
            for idx, (addr, sz) in enumerate(slices):
                cr = child_reads_shell[idx]
                if cr is not None:
                    cr.consume(actual_bytes=None, conservative_estimate_bytes=sz, is_failure=True, failure_reason=f"SSH batch read failed: {stderr.strip() or rc}")
            self._finalize_remote_read(adm, own_adm, True, "memory_read_batch", budget_tracker)
            alive, live_err = self.check_liveness(pid)
            if not alive:
                st = "UNAVAILABLE" if (live_err and ("transport" in live_err.lower() or "timed out" in live_err.lower())) else "TARGET_TERMINATED"
                return [(None, st, live_err or "Remote process terminated") for _ in slices]
            return [(None, "UNAVAILABLE", f"SSH batch read failed: {stderr.strip()}") for _ in slices]

        by_idx: Dict[int, str] = {}
        for line in stdout.splitlines():
            if "|" in line:
                k_str, val_b64 = line.strip().split("|", 1)
                if k_str.isdigit():
                    by_idx[int(k_str)] = val_b64.strip()

        results: List[Tuple[Optional[bytes], str, Optional[str]]] = []
        any_failure = False
        for idx, (addr, sz) in enumerate(slices):
            cr = child_reads_shell[idx]
            if sz <= 0:
                if cr is not None:
                    cr.consume(actual_bytes=0, is_failure=False)
                results.append((b"", "OBSERVED", None))
                continue
            b64_str = by_idx.get(idx, "")
            if not b64_str:
                if cr is not None:
                    cr.consume(actual_bytes=None, conservative_estimate_bytes=sz, is_failure=True, failure_reason="Missing slice output")
                any_failure = True
                results.append((None, "UNAVAILABLE", f"Address 0x{int(addr):x} is not mapped or inaccessible on {self.target_host()}"))
                continue
            try:
                raw_b = base64.b64decode(b64_str)
                if len(raw_b) == sz:
                    if cr is not None:
                        cr.consume(actual_bytes=len(raw_b), is_failure=False)
                    results.append((raw_b, "OBSERVED", None))
                elif len(raw_b) > 0:
                    if cr is not None:
                        cr.consume(actual_bytes=len(raw_b), is_failure=False)
                    results.append((raw_b, "PARTIAL", f"Partial read: {len(raw_b)}/{sz} bytes"))
                else:
                    if cr is not None:
                        cr.consume(actual_bytes=None, conservative_estimate_bytes=sz, is_failure=True, failure_reason="Zero bytes returned")
                    any_failure = True
                    results.append((None, "UNAVAILABLE", f"Zero bytes returned at 0x{int(addr):x}"))
            except Exception as e:
                if cr is not None:
                    cr.consume(actual_bytes=None, conservative_estimate_bytes=sz, is_failure=True, failure_reason=f"Base64 decode failure: {e}")
                any_failure = True
                results.append((None, "UNAVAILABLE", f"Base64 decode failure: {e}"))

        self._finalize_remote_read(adm, own_adm, any_failure, "memory_read_batch", budget_tracker)
        return results

    def read_memory(
        self,
        pid: int,
        address: int,
        size: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
        child_read: Optional[Any] = None,
    ) -> Tuple[Optional[bytes], str, Optional[str]]:
        if size <= 0:
            return b"", "OBSERVED", None

        adm, own_adm, rej_err = self._acquire_remote_admission(size, "memory_read", admission=admission, budget_tracker=budget_tracker)
        if rej_err:
            return None, "BUDGET_EXHAUSTED", rej_err

        if self.collector_path:
            inv_coll_id = f"inv_coll_{uuid.uuid4().hex[:12]}"
            cr_coll = adm.start_child_read(
                target_type="remote_collector_memory",
                target_spec={
                    "pid": pid,
                    "address": address,
                    "size": size,
                    "path": self.collector_path,
                    "invocation_id": inv_coll_id,
                    "invocation_type": "collector",
                },
            ) if adm is not None else None

            coll_res = self._read_slices_via_collector(
                pid,
                [(address, size)],
                admission=adm,
                child_reads=[cr_coll] if cr_coll else None,
                invocation_id=inv_coll_id,
            )
            if coll_res is not None and len(coll_res) == 1:
                res_b, res_st, res_err = coll_res[0]
                act_b = len(res_b) if res_b else 0
                is_fail = (res_st not in ("OBSERVED", "PARTIAL"))
                if cr_coll is not None:
                    if is_fail and res_b is None:
                        cr_coll.consume(actual_bytes=None, conservative_estimate_bytes=size, is_failure=True)
                    else:
                        cr_coll.consume(actual_bytes=act_b, is_failure=is_fail)
                elif adm is not None:
                    adm.consume(actual_bytes=act_b, is_failure=is_fail, accumulate=not own_adm)
                self._finalize_remote_read(adm, own_adm, is_fail, "memory_read", budget_tracker)
                return coll_res[0]
            else:
                if cr_coll is not None:
                    if cr_coll.state == "PHYSICAL_READ_STARTED":
                        cr_coll.consume(actual_bytes=0, is_failure=True, failure_reason="Collector execution failed")
                    elif cr_coll.state == "ADMITTED":
                        cr_coll.release()

        # Remote memory read via dd and base64: distinct fallback child read
        inv_shell_id = f"inv_shell_{uuid.uuid4().hex[:12]}"
        cr_shell = adm.start_child_read(
            target_type="remote_shell_memory",
            target_spec={
                "pid": pid,
                "address": address,
                "size": size,
                "invocation_id": inv_shell_id,
                "invocation_type": "shell_fallback",
            },
        ) if adm is not None else None

        cmd = f"dd if=/proc/{int(pid)}/mem bs=1 skip={int(address)} count={int(size)} 2>/dev/null | base64"
        rc, stdout, stderr = self.run_ssh(
            cmd,
            admission=adm,
            child_read=cr_shell,
            invocation_id=inv_shell_id,
        )
        if rc == -2:
            if cr_shell is not None:
                cr_shell.release()
            self._finalize_remote_read(adm, own_adm, False, "memory_read", budget_tracker)
            return None, "UNAVAILABLE", f"SSH transport failed before execution at 0x{address:x}: {stderr.strip()}"
        elif rc != 0:
            if cr_shell is not None:
                cr_shell.consume(actual_bytes=None, conservative_estimate_bytes=size, is_failure=True, failure_reason=stderr.strip() or f"SSH transport error rc={rc}")
            elif adm is not None:
                adm.consume(actual_bytes=None, is_failure=True, accumulate=not own_adm)
            self._finalize_remote_read(adm, own_adm, True, "memory_read", budget_tracker)
            return None, "UNAVAILABLE", f"SSH transport failed reading memory at 0x{address:x}: {stderr.strip()}"

        encoded = stdout.strip()
        if not encoded:
            if cr_shell is not None:
                cr_shell.consume(actual_bytes=None, conservative_estimate_bytes=size, is_failure=True, failure_reason=f"Address 0x{address:x} is not mapped or inaccessible")
            elif adm is not None:
                adm.consume(actual_bytes=None, is_failure=True, accumulate=not own_adm)
            self._finalize_remote_read(adm, own_adm, True, "memory_read", budget_tracker)
            return None, "UNAVAILABLE", f"Address 0x{address:x} is not mapped or inaccessible on {self.target_host()}"

        try:
            raw_bytes = base64.b64decode(encoded)
            act_b = len(raw_bytes)
            if act_b == size:
                if cr_shell is not None:
                    cr_shell.consume(actual_bytes=act_b, is_failure=False)
                elif adm is not None:
                    adm.consume(actual_bytes=act_b, is_failure=False, accumulate=not own_adm)
                self._finalize_remote_read(adm, own_adm, False, "memory_read", budget_tracker)
                return raw_bytes, "OBSERVED", None
            elif act_b > 0:
                if cr_shell is not None:
                    cr_shell.consume(actual_bytes=act_b, is_failure=False)
                elif adm is not None:
                    adm.consume(actual_bytes=act_b, is_failure=False, accumulate=not own_adm)
                self._finalize_remote_read(adm, own_adm, False, "memory_read", budget_tracker)
                return raw_bytes, "PARTIAL", f"Partial read: {act_b}/{size} bytes"
            else:
                if cr_shell is not None:
                    cr_shell.consume(actual_bytes=None, conservative_estimate_bytes=size, is_failure=True, failure_reason="Zero bytes returned")
                elif adm is not None:
                    adm.consume(actual_bytes=None, is_failure=True, accumulate=not own_adm)
                self._finalize_remote_read(adm, own_adm, True, "memory_read", budget_tracker)
                return None, "UNAVAILABLE", f"Zero bytes returned at 0x{address:x}"
        except Exception as e:
            if cr_shell is not None:
                cr_shell.consume(actual_bytes=None, conservative_estimate_bytes=size, is_failure=True, failure_reason=f"Base64 decode failure: {e}")
            elif adm is not None:
                adm.consume(actual_bytes=None, is_failure=True, accumulate=not own_adm)
            self._finalize_remote_read(adm, own_adm, True, "memory_read", budget_tracker)
            return None, "UNAVAILABLE", f"Base64 decode failure: {e}"

    def find_processes(
        self,
        process_name: Optional[str] = None,
        companion_build_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Discovers running processes on the remote target via a single POSIX shell scan of /proc."""
        remote_script = (
            "for p in /proc/[0-9]*; do "
            "[ -d \"$p\" ] || continue; "
            "pid=$(basename \"$p\"); "
            "comm=$(cat \"$p/comm\" 2>/dev/null | tr -d '\n' || true); "
            "[ -n \"$comm\" ] || continue; "
            "exe=$(readlink -f \"$p/exe\" 2>/dev/null || readlink \"$p/exe\" 2>/dev/null || true); "
            "cmd=$(tr '\000' ' ' < \"$p/cmdline\" 2>/dev/null | head -c 200 || true); "
            "echo \"$pid|$comm|$exe|$cmd\"; "
            "done"
        )
        rc, stdout, _ = self.run_ssh(f"sh -c {shlex.quote(remote_script)}")
        results: List[Dict[str, Any]] = []
        if rc != 0 or not stdout:
            return results

        q = (process_name or "").strip().lower()
        target_bid = (companion_build_id or "").strip().lower() or None

        for line in stdout.splitlines():
            parts = line.strip().split("|", 3)
            if len(parts) < 2 or not parts[0].isdigit():
                continue
            pid = int(parts[0])
            comm = parts[1].strip()
            exe_path = parts[2].strip() if len(parts) >= 3 else ""
            cmdline = parts[3].strip() if len(parts) >= 4 else ""
            exe_base = os.path.basename(exe_path) if exe_path else ""

            if q:
                if q not in comm.lower() and q not in exe_base.lower() and q not in cmdline.lower():
                    continue

            exact_name = bool(q and (comm.lower() == q or exe_base.lower() == q))
            results.append({
                "pid": pid,
                "name": comm or exe_base or f"pid_{pid}",
                "executable": exe_path,
                "cmdline": cmdline,
                "build_id": None,
                "build_id_match": False,
                "exact_name_match": exact_name,
                "is_remote": True,
                "host": self.target_host(),
            })

        # Sort exact matches first; if target_bid is provided, verify Build ID on top candidates (up to 5)
        results.sort(key=lambda r: (1 if r.get("exact_name_match") else 0, r.get("pid", 0)), reverse=True)
        if target_bid:
            for cand in results[:5]:
                ident = self.get_process_identity(cand["pid"])
                bid = ident.get("build_id")
                cand["build_id"] = bid
                if bid and bid.lower() == target_bid:
                    cand["build_id_match"] = True
            results.sort(key=lambda r: (
                1 if r.get("build_id_match") else 0,
                1 if r.get("exact_name_match") else 0,
                r.get("pid", 0),
            ), reverse=True)

        return results[:max(1, limit)]

    def ensure_remote_collector(
        self,
        local_collector_bin: Optional[str] = None,
        remote_dest: str = "/tmp/dynamicstate-collector",
    ) -> Dict[str, Any]:
        """Checks if dynamicstate-collector is present on the remote target, and if not,
        automatically deploys a matching architecture binary over SSH without requiring scp.
        Falls back gracefully to batched POSIX shell mode if binary architecture mismatches.
        """
        dest = (remote_dest or "/tmp/dynamicstate-collector").strip()
        check_cmd = f"[ -x {shlex.quote(dest)} ] && {shlex.quote(dest)} --help >/dev/null 2>&1 && echo READY || echo MISSING"
        rc, stdout, stderr = self.run_ssh(f"sh -c {shlex.quote(check_cmd)}")
        if rc != 0:
            return {
                "deployed": False,
                "status": "SSH_ERROR",
                "collector_path": None,
                "reason": stderr.strip() or f"SSH exited with {rc}",
            }

        if "READY" in stdout:
            self.collector_path = dest
            return {
                "deployed": True,
                "status": "ALREADY_PRESENT",
                "collector_path": dest,
                "reason": "Collector binary already present and executable on target",
            }

        # Check if local collector binary is available
        cand_bin = local_collector_bin
        if not cand_bin:
            repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            default_bin = os.path.join(repo_root, "target", "collector", "dynamicstate-collector")
            if os.path.isfile(default_bin):
                cand_bin = default_bin

        if not cand_bin or not os.path.isfile(cand_bin):
            return {
                "deployed": False,
                "status": "FALLBACK_SHELL",
                "collector_path": None,
                "reason": "No local dynamicstate-collector binary found to deploy; using batched POSIX shell fallback",
            }

        # Check architecture compatibility between local collector binary and remote uname -m
        try:
            local_ident = inspect_elf(cand_bin)
            local_arch = (local_ident.architecture or "").lower()
        except Exception as e:
            return {
                "deployed": False,
                "status": "FALLBACK_SHELL",
                "collector_path": None,
                "reason": f"Local collector binary is not a valid ELF: {e}",
            }

        rc_u, out_u, _ = self.run_ssh("uname -m 2>/dev/null")
        rem_arch_raw = out_u.strip().lower() if rc_u == 0 else ""
        arch_aliases = {
            "x86_64": ("x86_64", "amd64"),
            "aarch64": ("aarch64", "arm64"),
            "arm": ("arm", "armv7l", "armv6l", "armhf"),
            "riscv64": ("riscv64",),
            "mips": ("mips", "mips64", "mipsel"),
        }
        compatible_remotes = arch_aliases.get(local_arch, (local_arch,))
        if rem_arch_raw and local_arch and rem_arch_raw not in compatible_remotes:
            return {
                "deployed": False,
                "status": "FALLBACK_SHELL",
                "collector_path": None,
                "local_architecture": local_arch,
                "remote_architecture": rem_arch_raw,
                "reason": (
                    f"Architecture mismatch: local collector is '{local_arch}' but remote target is '{rem_arch_raw}'. "
                    f"Cross-compile collector with CC=<arch>-gcc or use batched POSIX shell fallback."
                ),
            }

        with open(cand_bin, "rb") as bf:
            raw_bytes = bf.read()
        b64_payload = base64.b64encode(raw_bytes).decode("ascii")
        upload_cmd = (
            f"sh -c 'echo {shlex.quote(b64_payload)} | base64 -d > {shlex.quote(dest)} && "
            f"chmod 755 {shlex.quote(dest)} && {shlex.quote(dest)} --help >/dev/null 2>&1 && echo DEPLOY_OK'"
        )
        rc_up, out_up, err_up = self.run_ssh(upload_cmd, timeout=max(10.0, self.timeout_sec * 2))
        if rc_up == 0 and "DEPLOY_OK" in out_up:
            self.collector_path = dest
            return {
                "deployed": True,
                "status": "DEPLOYED_BINARY",
                "collector_path": dest,
                "bytes_transferred": len(raw_bytes),
                "architecture": local_arch,
                "reason": f"Successfully deployed dynamicstate-collector ({len(raw_bytes)} bytes) to {dest}",
            }

        return {
            "deployed": False,
            "status": "FALLBACK_SHELL",
            "collector_path": None,
            "reason": f"Failed deploying collector to {dest}: {err_up.strip() or out_up.strip()}",
        }

    def capture_snapshot_via_collector(
        self,
        pid: int,
        remote_output_dir: str,
        timeout_ms: int = 2000,
        policy: str = "all",
        max_mb: int = 64,
        max_region_mb: int = 32,
    ) -> Dict[str, Any]:
        """Runs dynamicstate-collector --json on remote target to capture memory snapshot bundle."""
        if not self.collector_path:
            return {"success": False, "status": "FAILED", "error": "Collector binary not configured on remote adapter"}
        cmd = (
            f"{shlex.quote(self.collector_path)} -p {int(pid)} -o {shlex.quote(remote_output_dir)} "
            f"-t {int(timeout_ms)} --policy {shlex.quote(policy)} -m {int(max_mb)} -r {int(max_region_mb)} --json"
        )
        ssh_timeout = (float(timeout_ms) / 1000.0) + self.timeout_sec
        rc, stdout, stderr = self.run_ssh(cmd, timeout=ssh_timeout)

        # Empty stdout: transport failure, connection dropped, or remote timeout
        if not stdout.strip():
            is_to = (rc == -1 or "timed out" in stderr.lower())
            status = "SSH_TIMEOUT" if is_to else ("SSH_FAILURE" if rc != 0 else "FAILED")
            return {
                "success": False,
                "status": status,
                "error": stderr.strip() or f"Collector exited with rc {rc} but produced empty stdout",
                "returncode": rc,
                "raw_stderr": stderr,
            }

        import json as _json
        try:
            payload = _json.loads(stdout.strip().splitlines()[-1])
            if not isinstance(payload, dict):
                raise ValueError("Collector JSON output is not a dictionary object")
        except Exception as e:
            return {
                "success": False,
                "status": "MALFORMED_OUTPUT",
                "error": f"Failed to parse collector JSON output: {e}",
                "raw_stdout": stdout,
                "raw_stderr": stderr,
                "returncode": rc,
            }

        payload["returncode"] = rc
        payload["raw_stderr"] = stderr
        st = payload.get("status")
        if not st or not isinstance(st, str):
            st = "UNKNOWN"
            payload["status"] = "UNKNOWN"

        regions_count = payload.get("regions", 0)
        bytes_captured = payload.get("bytes_captured", 0)
        regions_requested = payload.get("regions_requested", 0)
        has_usable_evidence = (regions_count > 0 and bytes_captured > 0)

        # State transition matrix reconciling returncode and JSON status:
        if rc != 0:
            if st == "COMPLETE":
                # Contradiction: rc non-zero contradicts COMPLETE status
                if has_usable_evidence:
                    payload["status"] = "PARTIAL"
                    payload["success"] = True
                    warn = f"Process exit code {rc} contradicts COMPLETE status; downgraded to PARTIAL with valid evidence"
                else:
                    payload["status"] = "FAILED"
                    payload["success"] = False
                    warn = f"Process exit code {rc} contradicts COMPLETE status with no usable regions; downgraded to FAILED"
                payload["quality_warning"] = f"{payload.get('quality_warning', '')}; {warn}".strip("; ")
            elif st == "PARTIAL":
                if has_usable_evidence:
                    # Valid partial evidence is preserved
                    payload["status"] = "PARTIAL"
                    payload["success"] = True
                    warn = f"Remote collector exited with non-zero exit code {rc}; partial snapshot data preserved"
                else:
                    # PARTIAL with no usable captured regions/bytes must not count as useful evidence
                    payload["status"] = "FAILED"
                    payload["success"] = False
                    orig_err = payload.get("error")
                    payload["error"] = orig_err if orig_err else f"Remote collector exited with code {rc} and PARTIAL status but 0 usable regions/bytes; degraded to FAILED"
                    payload["degraded_reason"] = f"Remote collector exited with code {rc} and PARTIAL status but 0 usable regions/bytes; degraded to FAILED"
                    warn = f"Remote collector exited with code {rc} and PARTIAL status but 0 usable regions/bytes; degraded to FAILED"
                payload["quality_warning"] = f"{payload.get('quality_warning', '')}; {warn}".strip("; ")
            elif st in ("FAILED", "TIMEOUT", "PROCESS_EXITED", "PERMISSION_DENIED"):
                payload["success"] = False
            else:
                # Unknown or unrecognized status with rc!=0
                payload["status"] = "UNKNOWN_STATUS"
                payload["success"] = False
                payload["error"] = f"Collector exited with rc {rc} and unrecognized status '{st}'"
        else:
            # rc == 0
            if st == "COMPLETE":
                # Check for contradiction between status and success flag or region counts
                if payload.get("success") is False:
                    payload["status"] = "INCONSISTENT_STATUS"
                    payload["success"] = False
                    payload["error"] = "Contradiction in collector output: status is COMPLETE but success is false"
                elif regions_count == 0 and regions_requested > 0:
                    payload["status"] = "INCONSISTENT_STATUS"
                    payload["success"] = False
                    payload["error"] = "Contradiction in collector output: status is COMPLETE but 0 regions were captured"
                else:
                    payload["success"] = True
            elif st == "PARTIAL":
                if has_usable_evidence:
                    payload["success"] = True
                    if "quality_warning" not in payload or not payload["quality_warning"]:
                        payload["quality_warning"] = "PARTIAL_CAPTURE: Some regions failed or timed out during capture"
                else:
                    # PARTIAL with 0 usable captured regions/bytes cannot be accepted as successful capture
                    payload["status"] = "FAILED"
                    payload["success"] = False
                    orig_err = payload.get("error")
                    payload["error"] = orig_err if orig_err else "PARTIAL capture produced 0 usable regions or bytes; degraded to FAILED"
                    payload["degraded_reason"] = "PARTIAL capture produced 0 usable regions or bytes; degraded to FAILED"
            elif st in ("FAILED", "TIMEOUT", "PROCESS_EXITED", "PERMISSION_DENIED"):
                payload["success"] = False
                if "error" not in payload or not payload["error"]:
                    payload["error"] = f"Collector finished with failure status '{st}'"
            else:
                # Unknown status with rc==0
                payload["status"] = "UNKNOWN_STATUS"
                payload["success"] = False
                payload["error"] = f"Collector finished with unrecognized status '{st}'"

        return payload


RemoteTargetAdapter = RemoteSshTargetAdapter
RemoteSSHCollectorTargetAdapter = RemoteSshTargetAdapter

