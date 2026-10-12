"""Runtime Capture Backend abstraction and fast capture implementations.

Enforces:
1. Ultra-short process stop time (target < 10 ms).
2. Process resumes immediately after memory/thread capture.
3. Absolutely NO DWARF traversal, symbol resolution, or object graph construction during process suspension.
4. Guaranteed fail-open policy: process is resumed in all circumstances (via finally:).
5. Exact latency measurement without fabricated numbers.
"""

from abc import ABC, abstractmethod
import ctypes
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import errno
import os
import platform
import signal
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .capture_plan import CaptureMode, CapturePlan
from .raw_snapshot import RawMemoryRegion, RawRuntimeSnapshot


@dataclass
class CaptureLatencyReport:
    """Exact latency measurements for each phase of runtime state capture."""
    stop_latency_ms: float = 0.0
    thread_metadata_latency_ms: float = 0.0
    memory_capture_latency_ms: float = 0.0
    resume_latency_ms: float = 0.0
    total_stop_time_ms: float = 0.0
    target_capture_latency_ms: float = 10.0
    actual_capture_latency_ms: float = 0.0

    # Microsecond-precision metrics
    stop_latency_us: float = 0.0
    thread_metadata_latency_us: float = 0.0
    memory_capture_latency_us: float = 0.0
    resume_latency_us: float = 0.0
    total_stop_time_us: float = 0.0
    total_capture_latency_us: float = 0.0

    @property
    def capture_latency_us(self) -> float:
        return self.memory_capture_latency_us

    @property
    def read_latency_us(self) -> float:
        return self.memory_capture_latency_us

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stop_latency_ms": round(self.stop_latency_ms, 3),
            "thread_metadata_latency_ms": round(self.thread_metadata_latency_ms, 3),
            "memory_capture_latency_ms": round(self.memory_capture_latency_ms, 3),
            "resume_latency_ms": round(self.resume_latency_ms, 3),
            "total_stop_time_ms": round(self.total_stop_time_ms, 3),
            "target_capture_latency_ms": self.target_capture_latency_ms,
            "actual_capture_latency_ms": round(self.actual_capture_latency_ms, 3),
            "stop_latency_us": round(self.stop_latency_us, 1),
            "thread_metadata_latency_us": round(self.thread_metadata_latency_us, 1),
            "memory_capture_latency_us": round(self.memory_capture_latency_us, 1),
            "capture_latency_us": round(self.memory_capture_latency_us, 1),
            "read_latency_us": round(self.memory_capture_latency_us, 1),
            "resume_latency_us": round(self.resume_latency_us, 1),
            "total_stop_time_us": round(self.total_stop_time_us, 1),
            "total_capture_latency_us": round(self.total_capture_latency_us, 1),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CaptureLatencyReport":
        return cls(
            stop_latency_ms=data.get("stop_latency_ms", 0.0),
            thread_metadata_latency_ms=data.get("thread_metadata_latency_ms", 0.0),
            memory_capture_latency_ms=data.get("memory_capture_latency_ms", 0.0),
            resume_latency_ms=data.get("resume_latency_ms", 0.0),
            total_stop_time_ms=data.get("total_stop_time_ms", 0.0),
            target_capture_latency_ms=data.get("target_capture_latency_ms", 10.0),
            actual_capture_latency_ms=data.get("actual_capture_latency_ms", 0.0),
            stop_latency_us=data.get("stop_latency_us", data.get("stop_latency_ms", 0.0) * 1000.0),
            thread_metadata_latency_us=data.get("thread_metadata_latency_us", data.get("thread_metadata_latency_ms", 0.0) * 1000.0),
            memory_capture_latency_us=data.get("memory_capture_latency_us", data.get("memory_capture_latency_ms", 0.0) * 1000.0),
            resume_latency_us=data.get("resume_latency_us", data.get("resume_latency_ms", 0.0) * 1000.0),
            total_stop_time_us=data.get("total_stop_time_us", data.get("total_stop_time_ms", 0.0) * 1000.0),
            total_capture_latency_us=data.get("total_capture_latency_us", data.get("actual_capture_latency_ms", 0.0) * 1000.0),
        )


@dataclass
class CaptureSafetyPolicy:
    """Safety bounds for capturing state from running processes."""
    max_stop_time_ms: float = 50.0
    max_capture_bytes: int = 64 * 1024 * 1024
    max_capture_ranges: int = 500
    timeout_ms: int = 1000
    fail_open: bool = True  # Always resume target on error or timeout
    force_fallback: bool = False  # If True, bypass pidfd and use starttime verification fallback
    target_handle: Optional[Any] = None  # Injectable ProcessTargetHandle for testing/seams
    mem_reader: Optional[Any] = None  # Injectable memory read seam
    expected_identity: Optional[Dict[str, Any]] = None  # Expected target identity to prevent PID reuse
    expected_starttime: Optional[str] = None  # Expected /proc/<pid>/stat starttime


class _struct_iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


class RuntimeCaptureBackend(ABC):
    """Abstract base class for fast runtime state capture backends."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def capabilities(self) -> Dict[str, Any]:
        """Declared capture capabilities and guarantees of this backend."""
        pass

    @abstractmethod
    def is_available(self, pid: Optional[int] = None) -> bool:
        pass

    @abstractmethod
    def capture(
        self,
        pid: int,
        plan: Optional[CapturePlan] = None,
        policy: Optional[CaptureSafetyPolicy] = None,
        snapshot_id: Optional[str] = None,
        observation_point: Optional[Dict[str, Any]] = None,
    ) -> RawRuntimeSnapshot:
        pass


def _get_process_state(pid: int) -> Dict[str, Any]:
    """Return detailed process state dict from /proc/<pid>/stat.
    Raises ProcessLookupError if process does not exist.
    """
    stat_path = f"/proc/{pid}/stat"
    if not os.path.exists(stat_path):
        raise ProcessLookupError(f"Process {pid} does not exist (ESRCH)")
    try:
        with open(stat_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (FileNotFoundError, ProcessLookupError):
        raise ProcessLookupError(f"Process {pid} does not exist (ESRCH)")

    rparen = content.rfind(")")
    if rparen == -1:
        return {
            "comm": "unknown",
            "state": "UNKNOWN",
            "state_char": "?",
            "starttime": "0",
            "is_stopped": False,
            "is_tracing_stop": False,
        }
    lparen = content.find("(")
    comm = content[lparen + 1:rparen] if lparen != -1 else "unknown"
    rest = content[rparen + 1:].strip().split()
    state_char = rest[0] if len(rest) > 0 else "?"
    starttime = rest[19] if len(rest) > 19 else "0"

    state_map = {
        "R": "RUNNING",
        "S": "SLEEPING",
        "D": "DISK_SLEEP",
        "T": "STOPPED",
        "t": "TRACING_STOP",
        "Z": "ZOMBIE",
    }
    state_desc = state_map.get(state_char, f"STATE_{state_char}")
    is_stopped = state_char in ("T", "t")
    is_tracing_stop = (state_char == "t")

    return {
        "comm": comm,
        "state": state_desc,
        "state_char": state_char,
        "starttime": starttime,
        "is_stopped": is_stopped,
        "is_tracing_stop": is_tracing_stop,
    }


def _get_threads_state(pid: int) -> Dict[str, Any]:
    """Return thread states breakdown from /proc/<pid>/task."""
    task_dir = f"/proc/{pid}/task"
    threads = []
    stopped_count = 0
    running_count = 0
    try:
        if os.path.exists(task_dir):
            for entry in os.listdir(task_dir):
                if entry.isdigit():
                    tid = int(entry)
                    stat_path = os.path.join(task_dir, entry, "stat")
                    t_state = "UNKNOWN"
                    t_char = "?"
                    is_t_stopped = False
                    try:
                        with open(stat_path, "r", encoding="utf-8") as f:
                            stat_content = f.read()
                            rparen = stat_content.rfind(")")
                            if rparen != -1:
                                t_char = stat_content[rparen + 1:].strip().split()[0]
                                state_map = {
                                    "R": "RUNNING",
                                    "S": "SLEEPING",
                                    "D": "DISK_SLEEP",
                                    "T": "STOPPED",
                                    "t": "TRACING_STOP",
                                    "Z": "ZOMBIE",
                                }
                                t_state = state_map.get(t_char, t_char)
                                is_t_stopped = t_char in ("T", "t")
                    except Exception:
                        pass
                    if is_t_stopped:
                        stopped_count += 1
                    else:
                        running_count += 1
                    threads.append({
                        "tid": tid,
                        "state": t_state,
                        "state_char": t_char,
                        "is_stopped": is_t_stopped,
                    })
    except Exception:
        pass

    total = len(threads)
    if total == 0:
        total = 1
        stopped_count = 0
        running_count = 1

    return {
        "threads": threads,
        "total_count": total,
        "stopped_count": stopped_count,
        "running_count": running_count,
        "all_stopped": (stopped_count == total and total > 0),
        "any_stopped": (stopped_count > 0),
        "mixed_states": (stopped_count > 0 and running_count > 0),
    }


class ProcessTargetHandle:
    """Safe process identification and signal transmission mechanism.

    Mitigates PID reuse race conditions:
    1. Primary: Linux pidfd (pidfd_open + pidfd_send_signal).
       Verifies that the process identity observed before calling pidfd_open()
       matches the identity pinned by the opened pidfd. If a PID reuse race occurs
       between stat read and pidfd_open, the pidfd is closed immediately and signal
       transmission is rejected.
    2. Fallback: Verifies (comm, starttime) before signal transmission when pidfd
       is genuinely unsupported by the kernel or forced fallback is enabled.
       Documents limitations: fallback cannot guarantee complete immunity against kernel
       scheduling races between /proc/<pid>/stat read and signal syscall.
    """

    def __init__(
        self,
        pid: int,
        force_fallback: bool = False,
        adapter: Optional[Any] = None,
        expected_identity: Optional[Dict[str, Any]] = None,
        expected_starttime: Optional[str] = None,
    ):
        self.pid = pid
        self.force_fallback = force_fallback
        self.adapter = adapter
        self.expected_identity: Dict[str, Any] = dict(expected_identity or {})
        if expected_starttime and "starttime" not in self.expected_identity:
            self.expected_identity["starttime"] = expected_starttime
        self.pidfd: Optional[int] = None
        self.pidfd_supported: bool = False
        self.pidfd_used: bool = False
        self.identity_mismatch: bool = False
        self.open_status: str = "UNINITIALIZED"
        self.initial_identity: Dict[str, Any] = {}
        self.pre_signal_identity: Optional[Dict[str, Any]] = None
        self.post_capture_identity: Optional[Dict[str, Any]] = None
        self.mem_fd: Optional[int] = None
        self.mem_pinned: bool = False
        self.mem_pin_error: Optional[str] = None
        self.identity_checkpoints: List[Dict[str, Any]] = []
        self.closed: bool = False

    def get_process_state(self) -> Dict[str, Any]:
        if self.adapter and hasattr(self.adapter, "get_process_state"):
            return self.adapter.get_process_state(self.pid)
        return _get_process_state(self.pid)

    def get_threads_state(self) -> Dict[str, Any]:
        if self.adapter and hasattr(self.adapter, "get_threads_state"):
            return self.adapter.get_threads_state(self.pid)
        return _get_threads_state(self.pid)

    def read_proc_maps(self) -> Any:
        if self.adapter and hasattr(self.adapter, "read_proc_maps"):
            return self.adapter.read_proc_maps(self.pid)
        return _read_proc_maps(self.pid)

    def read_thread_metadata(self) -> Any:
        if self.adapter and hasattr(self.adapter, "read_thread_metadata"):
            return self.adapter.read_thread_metadata(self.pid)
        return _read_thread_metadata(self.pid)

    def _pidfd_open(self, pid: int, flags: int = 0) -> int:
        if self.adapter and hasattr(self.adapter, "pidfd_open"):
            return self.adapter.pidfd_open(pid, flags)
        if hasattr(os, "pidfd_open"):
            return os.pidfd_open(pid, flags)
        raise OSError(errno.ENOSYS, "pidfd_open syscall unavailable on this platform")

    def _close_pidfd(self, fd: int) -> None:
        if self.adapter and hasattr(self.adapter, "close_pidfd"):
            self.adapter.close_pidfd(fd)
            return
        os.close(fd)

    def open(self) -> None:
        if self.closed:
            raise RuntimeError("Cannot open a closed ProcessTargetHandle")
        if self.adapter and hasattr(self.adapter, "open"):
            self.adapter.open(self)
            return

        # 1. Observe target process identity before pidfd_open
        try:
            pre_identity = self.get_process_state()
        except ProcessLookupError:
            self.open_status = "TARGET_EXITED"
            raise
        except PermissionError:
            self.open_status = "PERMISSION_DENIED"
            raise
        except Exception as e:
            self.open_status = "IDENTITY_READ_ERROR"
            raise

        # If expected identity was supplied, verify pre-identity against it immediately
        if self.expected_identity:
            exp_starttime = str(self.expected_identity.get("starttime", ""))
            obs_starttime = str(pre_identity.get("starttime", ""))
            if exp_starttime and obs_starttime and exp_starttime != obs_starttime:
                self.identity_mismatch = True
                self.open_status = "IDENTITY_MISMATCH"
                raise ProcessLookupError(
                    f"Process identity mismatch before pidfd_open: PID {self.pid} expected starttime {exp_starttime}, got {obs_starttime}"
                )

        # 2. Attempt to open pidfd if supported and not forced to fallback
        can_try_pidfd = (
            not self.force_fallback
            and platform.system() == "Linux"
            and (hasattr(os, "pidfd_open") or (self.adapter and hasattr(self.adapter, "pidfd_open")))
            and (hasattr(signal, "pidfd_send_signal") or (self.adapter and hasattr(self.adapter, "send_signal")))
        )

        if can_try_pidfd:
            try:
                self.pidfd = self._pidfd_open(self.pid, 0)
                self.pidfd_supported = True
            except ProcessLookupError:
                self.open_status = "TARGET_EXITED"
                raise
            except PermissionError:
                self.open_status = "PERMISSION_DENIED"
                raise
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    self.open_status = "TARGET_EXITED"
                    raise ProcessLookupError(f"Target process {self.pid} exited before pidfd_open")
                elif exc.errno == errno.EPERM:
                    self.open_status = "PERMISSION_DENIED"
                    raise PermissionError(f"Permission denied opening pidfd for process {self.pid}")
                elif exc.errno in (errno.ENOSYS, errno.EOPNOTSUPP) or isinstance(exc, AttributeError):
                    # Kernel or environment does not support pidfd
                    self.pidfd = None
                    self.pidfd_supported = False
                    self.open_status = "UNSUPPORTED_PIDFD"
                else:
                    self.pidfd = None
                    self.pidfd_supported = False
                    self.open_status = "PIDFD_INIT_FAILED"
                    raise
            except Exception:
                self.pidfd = None
                self.pidfd_supported = False
                self.open_status = "PIDFD_INIT_FAILED"
                raise

        # 3. If pidfd was successfully opened, VERIFY identity matches pre-open identity
        if self.pidfd is not None:
            try:
                # With pidfd pinned in kernel, read identity again
                post_identity = self.get_process_state()
            except Exception as e:
                # Target exited right after pidfd_open
                try:
                    self._close_pidfd(self.pidfd)
                except Exception:
                    pass
                self.pidfd = None
                self.pidfd_used = False
                self.open_status = "TARGET_EXITED"
                raise ProcessLookupError(f"Failed to read target process state after pidfd_open: {e}")

            # Check if PID was reused between pre_identity read and pidfd_open
            starttime_match = (
                str(post_identity.get("starttime", "")) == str(pre_identity.get("starttime", ""))
            )
            comm_match = (
                post_identity.get("comm") == pre_identity.get("comm")
            )
            if not starttime_match or not comm_match:
                # PID REUSE RACE DETECTED!
                # Close pidfd immediately and NEVER fall back to PID-based signal!
                try:
                    self._close_pidfd(self.pidfd)
                except Exception:
                    pass
                self.pidfd = None
                self.pidfd_used = False
                self.identity_mismatch = True
                self.open_status = "IDENTITY_MISMATCH"
                raise ProcessLookupError(
                    f"PID reuse race detected: process {self.pid} identity changed during pidfd_open "
                    f"(starttime: {pre_identity.get('starttime')} -> {post_identity.get('starttime')}, "
                    f"comm: {pre_identity.get('comm')} -> {post_identity.get('comm')})"
                )

            # Identity successfully verified and pinned!
            self.pidfd_used = True
            self.initial_identity = post_identity
            self.open_status = "PIDFD_OPENED"
            self._try_pin_mem()
            return

        # 4. Fallback path (only when pidfd is unsupported or force_fallback is True)
        self.pidfd_used = False
        self.initial_identity = pre_identity
        self.open_status = "FALLBACK_INITIALIZED"
        self._try_pin_mem()

    def _try_pin_mem(self) -> None:
        """Attempt to retain an open descriptor to /proc/<pid>/mem to safely pin memory context."""
        if platform.system() == "Linux" and not (self.adapter and hasattr(self.adapter, "open")):
            try:
                mem_path = f"/proc/{self.pid}/mem"
                flags = os.O_RDONLY
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                self.mem_fd = os.open(mem_path, flags)
                self.mem_pinned = True
            except Exception as e:
                self.mem_fd = None
                self.mem_pinned = False
                self.mem_pin_error = str(e)

    def read_mem(self, address: int, size: int) -> Optional[bytes]:
        """Read memory from pinned /proc/<pid>/mem descriptor if available."""
        if self.closed or not self.mem_pinned or self.mem_fd is None:
            return None
        try:
            return os.pread(self.mem_fd, size, address)
        except Exception:
            return None

    def record_checkpoint(self, checkpoint_name: str) -> Tuple[bool, str]:
        """Verify identity and record checkpoint in audit trail."""
        is_same, status = self.verify_identity()
        self.identity_checkpoints.append({
            "name": checkpoint_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verified": is_same,
            "status": status,
        })
        return is_same, status

    def send_signal(self, sig: int) -> Tuple[bool, Optional[str]]:
        if self.closed:
            return False, "HANDLE_CLOSED"
        if self.identity_mismatch:
            return False, "IDENTITY_MISMATCH"
        if self.adapter and hasattr(self.adapter, "send_signal"):
            return self.adapter.send_signal(self, sig)

        try:
            self.pre_signal_identity = self.get_process_state()
        except ProcessLookupError:
            return False, "TARGET_EXITED"
        except Exception as e:
            return False, f"IDENTITY_READ_ERROR: {e}"

        if self.pidfd_used and self.pidfd is not None:
            try:
                signal.pidfd_send_signal(self.pidfd, sig)
                return True, None
            except ProcessLookupError:
                return False, "TARGET_EXITED"
            except PermissionError:
                return False, "PERMISSION_DENIED"
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    return False, "TARGET_EXITED"
                elif exc.errno == errno.EPERM:
                    return False, "PERMISSION_DENIED"
                return False, f"SIGNAL_ERROR_ERRNO_{exc.errno}"
            except Exception as exc:
                return False, f"SIGNAL_ERROR_{exc}"
        else:
            # Fallback path: verify starttime before os.kill
            if self.pre_signal_identity.get("starttime") != self.initial_identity.get("starttime"):
                return False, "PID_REUSED"
            try:
                os.kill(self.pid, sig)
                return True, None
            except ProcessLookupError:
                return False, "TARGET_EXITED"
            except PermissionError:
                return False, "PERMISSION_DENIED"
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    return False, "TARGET_EXITED"
                elif exc.errno == errno.EPERM:
                    return False, "PERMISSION_DENIED"
                return False, f"SIGNAL_ERROR_ERRNO_{exc.errno}"
            except Exception as exc:
                return False, f"SIGNAL_ERROR_{exc}"

    def verify_identity(self) -> Tuple[bool, str]:
        if self.closed:
            return False, "HANDLE_CLOSED"
        if self.identity_mismatch:
            return False, "IDENTITY_MISMATCH"
        if self.adapter and hasattr(self.adapter, "verify_identity"):
            return self.adapter.verify_identity(self)

        if self.pidfd_used and self.pidfd is not None:
            try:
                signal.pidfd_send_signal(self.pidfd, 0)
                try:
                    curr = self.get_process_state()
                    self.post_capture_identity = curr
                    if self.initial_identity and curr.get("starttime") != self.initial_identity.get("starttime"):
                        self.identity_mismatch = True
                        return False, "PID_REUSED"
                except Exception:
                    pass
                return True, "PIDFD_VERIFIED"
            except (ProcessLookupError, OSError) as exc:
                if getattr(exc, "errno", None) == errno.ESRCH or isinstance(exc, ProcessLookupError):
                    return False, "TARGET_EXITED"
                elif getattr(exc, "errno", None) == errno.EPERM or isinstance(exc, PermissionError):
                    return True, "PIDFD_EXISTS_EPERM"
                return False, f"PIDFD_ERROR_ERRNO_{getattr(exc, 'errno', 'UNKNOWN')}"
            except Exception as e:
                return False, f"PIDFD_ERROR_{e}"
        else:
            try:
                curr = self.get_process_state()
                self.post_capture_identity = curr
                if curr.get("starttime") != self.initial_identity.get("starttime"):
                    return False, "PID_REUSED"
                return True, "FALLBACK_VERIFIED"
            except ProcessLookupError:
                return False, "TARGET_EXITED"
            except Exception as e:
                return False, f"IDENTITY_CHECK_FAILED: {e}"

    def get_diagnostics(self) -> Dict[str, Any]:
        return {
            "status": self.open_status,
            "pidfd_supported": self.pidfd_supported,
            "pidfd_used": self.pidfd_used,
            "identity_mismatch": self.identity_mismatch,
            "mitigation_mechanism": (
                "PIDFD"
                if self.pidfd_used
                else "STAT_STARTTIME_CHECK_FALLBACK"
            ),
            "memory_pin_status": "MEM_PINNED" if self.mem_pinned else "MEM_UNPINNED",
            "mem_pinned": self.mem_pinned,
            "mem_pin_error": self.mem_pin_error,
            "fallback_caveat": (
                None
                if self.pidfd_used
                else "Fallback starttime verification cannot guarantee complete immunity against kernel PID recycling races between stat read and signal delivery."
            ),
            "initial_identity": self.initial_identity,
            "pre_signal_identity": self.pre_signal_identity,
            "post_capture_identity": self.post_capture_identity,
            "identity_checkpoints": list(self.identity_checkpoints),
            "closed": self.closed,
        }

    def close(self) -> None:
        if self.adapter and hasattr(self.adapter, "close"):
            self.adapter.close(self)
        if self.mem_fd is not None:
            try:
                os.close(self.mem_fd)
            except Exception:
                pass
            self.mem_fd = None
            self.mem_pinned = False
        if self.pidfd is not None:
            try:
                self._close_pidfd(self.pidfd)
            except Exception:
                pass
            self.pidfd = None
        self.closed = True

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def _get_process_identity(pid: int) -> Tuple[str, str]:
    """Return (comm, starttime) from /proc/<pid>/stat.
    Raises ProcessLookupError if process does not exist.
    """
    stat_path = f"/proc/{pid}/stat"
    if not os.path.exists(stat_path):
        raise ProcessLookupError(f"Process {pid} does not exist (ESRCH)")
    try:
        with open(stat_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (FileNotFoundError, ProcessLookupError):
        raise ProcessLookupError(f"Process {pid} does not exist (ESRCH)")

    rparen = content.rfind(")")
    if rparen == -1:
        return "unknown", "0"
    lparen = content.find("(")
    comm = content[lparen + 1:rparen] if lparen != -1 else "unknown"
    rest = content[rparen + 1:].strip().split()
    starttime = rest[19] if len(rest) > 19 else "0"
    return comm, starttime


class ProcMapsResult(list):
    """Container for parsed /proc/<pid>/maps regions preserving list compatibility with explicit enumeration status."""

    def __init__(
        self,
        regions: Optional[Any] = None,
        status: str = "SUCCESS_WITH_RESULTS",
        error_type: Optional[str] = None,
        error: Optional[str] = None,
        diagnostics: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(regions or [])
        self.status = status  # SUCCESS_WITH_RESULTS, SUCCESS_EMPTY, FAILED, PARTIAL
        self.error_type = error_type  # PERMISSION_DENIED, TARGET_EXITED, MALFORMED, IO_ERROR
        self.error = error
        self.diagnostics = list(diagnostics or [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "error_type": self.error_type,
            "error": self.error,
            "region_count": len(self),
            "diagnostics": list(self.diagnostics),
        }


class ThreadMetadataResult(list):
    """Container for parsed /proc/<pid>/task thread records preserving list compatibility with explicit enumeration status."""

    def __init__(
        self,
        threads: Optional[Any] = None,
        status: str = "SUCCESS_WITH_RESULTS",
        error_type: Optional[str] = None,
        error: Optional[str] = None,
        is_synthetic: bool = False,
        diagnostics: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(threads or [])
        self.status = status  # SUCCESS_WITH_RESULTS, SUCCESS_EMPTY, FAILED, PARTIAL
        self.error_type = error_type  # PERMISSION_DENIED, TARGET_EXITED, IO_ERROR, TASK_DIR_MISSING
        self.error = error
        self.is_synthetic = is_synthetic
        self.diagnostics = list(diagnostics or [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "error_type": self.error_type,
            "error": self.error,
            "is_synthetic": self.is_synthetic,
            "thread_count": len(self),
            "diagnostics": list(self.diagnostics),
        }


def _read_proc_maps(pid: int) -> ProcMapsResult:
    """Parse /proc/<pid>/maps with explicit outcome modeling and structured error details."""
    maps_path = f"/proc/{pid}/maps"
    diagnostics: List[Dict[str, Any]] = []

    try:
        with open(maps_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (FileNotFoundError, ProcessLookupError) as exc:
        err_msg = f"Process {pid} maps not found (ESRCH): {exc}"
        diagnostics.append({"code": "MAPS_TARGET_EXITED", "message": err_msg, "level": "ERROR"})
        return ProcMapsResult(
            [],
            status="FAILED",
            error_type="TARGET_EXITED",
            error=err_msg,
            diagnostics=diagnostics,
        )
    except PermissionError as exc:
        err_msg = f"Permission denied reading /proc/{pid}/maps: {exc}"
        diagnostics.append({"code": "MAPS_PERMISSION_DENIED", "message": err_msg, "level": "ERROR"})
        return ProcMapsResult(
            [],
            status="FAILED",
            error_type="PERMISSION_DENIED",
            error=err_msg,
            diagnostics=diagnostics,
        )
    except Exception as exc:
        err_msg = f"Failed to read /proc/{pid}/maps: {exc}"
        diagnostics.append({"code": "MAPS_IO_ERROR", "message": err_msg, "level": "ERROR"})
        return ProcMapsResult(
            [],
            status="FAILED",
            error_type="IO_ERROR",
            error=err_msg,
            diagnostics=diagnostics,
        )

    if not lines:
        return ProcMapsResult(
            [],
            status="SUCCESS_EMPTY",
            error_type=None,
            error=None,
            diagnostics=[{"code": "MAPS_EMPTY", "message": f"/proc/{pid}/maps is empty", "level": "INFO"}],
        )

    regions = []
    malformed_count = 0
    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue
        parts = line_str.split(maxsplit=5)
        if len(parts) < 5:
            malformed_count += 1
            continue
        try:
            addr_range = parts[0]
            perms = parts[1]
            offset = parts[2]
            dev = parts[3]
            inode = parts[4]
            pathname = parts[5] if len(parts) > 5 else ""
            if "-" not in addr_range:
                malformed_count += 1
                continue
            s_str, e_str = addr_range.split("-")
            start = int(s_str, 16)
            end = int(e_str, 16)
        except Exception:
            malformed_count += 1
            continue

        cat = "unknown"
        if pathname == "[heap]":
            cat = "heap"
        elif pathname.startswith("[stack"):
            cat = "stack"
        elif pathname.endswith(".so") or ".so." in pathname:
            cat = "library"
        elif pathname and not pathname.startswith("["):
            cat = "binary"
        elif not pathname:
            cat = "anonymous"

        regions.append({
            "start": start,
            "end": end,
            "size": end - start,
            "permissions": perms,
            "offset": int(offset, 16) if isinstance(offset, str) else offset,
            "category": cat,
            "pathname": pathname
        })

    if malformed_count > 0:
        if regions:
            diagnostics.append({
                "code": "MAPS_PARTIALLY_MALFORMED",
                "message": f"{malformed_count} malformed lines found in /proc/{pid}/maps",
                "level": "WARNING"
            })
            return ProcMapsResult(
                regions,
                status="PARTIAL",
                error_type="MALFORMED",
                error=f"{malformed_count} malformed map lines",
                diagnostics=diagnostics,
            )
        else:
            diagnostics.append({
                "code": "MAPS_ENTIRELY_MALFORMED",
                "message": f"All lines in /proc/{pid}/maps were malformed",
                "level": "ERROR"
            })
            return ProcMapsResult(
                [],
                status="FAILED",
                error_type="MALFORMED",
                error=f"All {malformed_count} lines malformed",
                diagnostics=diagnostics,
            )

    return ProcMapsResult(
        regions,
        status="SUCCESS_WITH_RESULTS" if regions else "SUCCESS_EMPTY",
        error_type=None,
        error=None,
        diagnostics=diagnostics,
    )


def _read_thread_metadata(pid: int) -> ThreadMetadataResult:
    """Read thread information quickly from /proc/<pid>/task with explicit outcome modeling."""
    threads = []
    task_dir = f"/proc/{pid}/task"
    diagnostics: List[Dict[str, Any]] = []

    if not os.path.exists(task_dir):
        err_msg = f"Task directory {task_dir} does not exist (TARGET_EXITED)"
        diagnostics.append({"code": "THREAD_TASK_DIR_MISSING", "message": err_msg, "level": "WARNING"})
        placeholder = [{
            "thread_id": pid,
            "name": None,
            "state": "UNKNOWN",
            "stop_status": "UNKNOWN",
            "is_synthetic": True,
            "verified_observation": False,
            "capture_participation": False,
            "registers_availability": "REGISTER_STATE_UNAVAILABLE",
            "function": None,
            "location": None,
        }]
        return ThreadMetadataResult(
            placeholder,
            status="FAILED",
            error_type="TARGET_EXITED",
            error=err_msg,
            is_synthetic=True,
            diagnostics=diagnostics,
        )

    try:
        entries = os.listdir(task_dir)
    except (FileNotFoundError, ProcessLookupError) as exc:
        err_msg = f"Process {pid} exited while enumerating task directory: {exc}"
        diagnostics.append({"code": "THREAD_TARGET_EXITED", "message": err_msg, "level": "WARNING"})
        placeholder = [{
            "thread_id": pid,
            "name": None,
            "state": "UNKNOWN",
            "stop_status": "UNKNOWN",
            "is_synthetic": True,
            "verified_observation": False,
            "capture_participation": False,
            "registers_availability": "REGISTER_STATE_UNAVAILABLE",
            "function": None,
            "location": None,
        }]
        return ThreadMetadataResult(
            placeholder,
            status="FAILED",
            error_type="TARGET_EXITED",
            error=err_msg,
            is_synthetic=True,
            diagnostics=diagnostics,
        )
    except PermissionError as exc:
        err_msg = f"Permission denied accessing {task_dir}: {exc}"
        diagnostics.append({"code": "THREAD_PERMISSION_DENIED", "message": err_msg, "level": "ERROR"})
        placeholder = [{
            "thread_id": pid,
            "name": None,
            "state": "UNKNOWN",
            "stop_status": "UNKNOWN",
            "is_synthetic": True,
            "verified_observation": False,
            "capture_participation": False,
            "registers_availability": "REGISTER_STATE_UNAVAILABLE",
            "function": None,
            "location": None,
        }]
        return ThreadMetadataResult(
            placeholder,
            status="FAILED",
            error_type="PERMISSION_DENIED",
            error=err_msg,
            is_synthetic=True,
            diagnostics=diagnostics,
        )
    except Exception as exc:
        err_msg = f"Failed to list {task_dir}: {exc}"
        diagnostics.append({"code": "THREAD_IO_ERROR", "message": err_msg, "level": "ERROR"})
        placeholder = [{
            "thread_id": pid,
            "name": None,
            "state": "UNKNOWN",
            "stop_status": "UNKNOWN",
            "is_synthetic": True,
            "verified_observation": False,
            "capture_participation": False,
            "registers_availability": "REGISTER_STATE_UNAVAILABLE",
            "function": None,
            "location": None,
        }]
        return ThreadMetadataResult(
            placeholder,
            status="FAILED",
            error_type="IO_ERROR",
            error=err_msg,
            is_synthetic=True,
            diagnostics=diagnostics,
        )

    task_read_errors = 0
    for entry in entries:
        if entry.isdigit():
            tid = int(entry)
            t_name = None
            comm_path = os.path.join(task_dir, entry, "comm")
            try:
                with open(comm_path, "r", encoding="utf-8") as f:
                    t_name = f.read().strip() or None
            except Exception:
                pass

            t_state = "UNKNOWN"
            stat_path = os.path.join(task_dir, entry, "stat")
            try:
                with open(stat_path, "r", encoding="utf-8") as f:
                    stat_content = f.read()
                    rparen = stat_content.rfind(")")
                    if rparen != -1:
                        state_char = stat_content[rparen + 1:].strip().split()[0]
                        state_map = {
                            "R": "RUNNING",
                            "S": "SLEEPING",
                            "D": "DISK_SLEEP",
                            "T": "STOPPED",
                            "t": "TRACING_STOP",
                            "Z": "ZOMBIE",
                        }
                        t_state = state_map.get(state_char, state_char)
            except Exception:
                task_read_errors += 1

            threads.append({
                "thread_id": tid,
                "name": t_name,
                "state": t_state,
                "stop_status": "STOPPED" if t_state in ("STOPPED", "TRACING_STOP") else ("UNKNOWN" if t_state == "UNKNOWN" else "NOT_STOPPED"),
                "is_synthetic": False,
                "verified_observation": (t_state != "UNKNOWN"),
                "capture_participation": True,
                "registers_availability": "REGISTER_STATE_UNAVAILABLE",
                "function": None,
                "location": None,
            })

    if not threads:
        err_msg = f"No threads could be enumerated for process {pid}"
        placeholder = [{
            "thread_id": pid,
            "name": None,
            "state": "UNKNOWN",
            "stop_status": "UNKNOWN",
            "is_synthetic": True,
            "verified_observation": False,
            "capture_participation": False,
            "registers_availability": "REGISTER_STATE_UNAVAILABLE",
            "function": None,
            "location": None,
        }]
        return ThreadMetadataResult(
            placeholder,
            status="FAILED",
            error_type="IO_ERROR",
            error=err_msg,
            is_synthetic=True,
            diagnostics=diagnostics,
        )

    threads.sort(key=lambda t: t["thread_id"])
    if task_read_errors > 0:
        diagnostics.append({
            "code": "THREAD_PARTIAL_READ_ERRORS",
            "message": f"{task_read_errors} thread stat reads failed",
            "level": "WARNING"
        })
        return ThreadMetadataResult(
            threads,
            status="PARTIAL",
            error_type="IO_ERROR",
            error=f"{task_read_errors} thread stat reads failed",
            is_synthetic=False,
            diagnostics=diagnostics,
        )

    return ThreadMetadataResult(
        threads,
        status="SUCCESS_WITH_RESULTS",
        error_type=None,
        error=None,
        is_synthetic=False,
        diagnostics=diagnostics,
    )


class ProcessVmCaptureBackend(RuntimeCaptureBackend):
    """Ultra-fast capture backend using Linux process_vm_readv() with minimal stop time."""

    def __init__(self):
        self._libc = None
        self._has_process_vm_readv = False
        if platform.system() == "Linux":
            try:
                self._libc = ctypes.CDLL(None, use_errno=True)
                if hasattr(self._libc, "process_vm_readv"):
                    fn = self._libc.process_vm_readv
                    fn.argtypes = [
                        ctypes.c_int,
                        ctypes.POINTER(_struct_iovec),
                        ctypes.c_ulong,
                        ctypes.POINTER(_struct_iovec),
                        ctypes.c_ulong,
                        ctypes.c_ulong,
                    ]
                    fn.restype = ctypes.c_ssize_t
                    self._has_process_vm_readv = True
            except Exception:
                self._has_process_vm_readv = False

    @property
    def name(self) -> str:
        return "process_vm_readv"

    @property
    def capabilities(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "can_suspend_inferior": True,  # backend can suspend target via external signals (SIGSTOP/SIGCONT) when requested by capture plan
            "can_read_registers": False,
            "can_read_memory": True,
            "atomicity": "NON_ATOMIC",
            "zero_stop_supported": True,
            "syscall_suspends": False,
            "suspension_method": "signal_external",
            "mode_behaviors": {
                "ZERO_STOP": {
                    "suspends_process": False,
                    "atomicity": "NON_ATOMIC",
                    "description": "Zero-stop live capture: reads target memory without pausing process; snapshot is NOT atomic.",
                },
                "FULL": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; consistency depends on stop confirmation.",
                },
                "TARGETED": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures selected semantic ranges.",
                },
                "THREAD": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures thread stack memory.",
                },
                "OBJECT": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures object memory ranges.",
                },
            },
        }

    def is_available(self, pid: Optional[int] = None) -> bool:
        if not self._has_process_vm_readv:
            return False
        if pid is not None:
            try:
                os.kill(pid, 0)
                return True
            except Exception:
                return False
        return True

    def capture(
        self,
        pid: int,
        plan: Optional[CapturePlan] = None,
        policy: Optional[CaptureSafetyPolicy] = None,
        snapshot_id: Optional[str] = None,
        observation_point: Optional[Dict[str, Any]] = None,
        handle: Optional[ProcessTargetHandle] = None,
    ) -> RawRuntimeSnapshot:
        plan = plan or CapturePlan()
        policy = policy or CaptureSafetyPolicy()

        handle = handle or getattr(policy, "target_handle", None)
        if handle is None and not self.is_available(pid):
            raise RuntimeError(f"process_vm_readv is unavailable or target PID {pid} is not accessible")

        # Use ProcessTargetHandle for pidfd support and strict PID reuse mitigation
        force_fb = getattr(policy, "force_fallback", False)
        exp_id = getattr(policy, "expected_identity", None)
        exp_st = getattr(policy, "expected_starttime", None)
        handle = handle or ProcessTargetHandle(
            pid,
            force_fallback=force_fb,
            expected_identity=exp_id,
            expected_starttime=exp_st,
        )
        try:
            handle.open()
        except Exception:
            handle.close()
            raise

        initial_ident = handle.initial_identity
        initial_threads = handle.get_threads_state()
        was_already_stopped = initial_ident.get("is_stopped", False)
        is_tracing_stop = initial_ident.get("is_tracing_stop", False)
        target_start_time = initial_ident.get("starttime", "0")
        comm = initial_ident.get("comm", "unknown")

        sid = snapshot_id or "RS_{:06d}_{:04d}".format(pid, int(time.time() * 1000) % 10000)
        t_overall_start_ns = time.monotonic_ns()
        wall_clock_start = datetime.now(timezone.utc).isoformat()

        # State machine tracking
        state_history = ["INITIALIZED"]
        capture_status = "COMPLETED"
        stop_requested = False
        stop_confirmed = False
        resume_requested = False
        resume_confirmed = False
        suspension_caused_by_capture = False
        all_threads_stopped = False
        memory_read_completed = False
        diagnostics: List[Dict[str, Any]] = []

        if is_tracing_stop:
            diagnostics.append({
                "code": "TRACING_STOP_OBSERVED",
                "message": f"Process {pid} is in TRACING_STOP ('t'). It may be attached to a debugger/tracer. External signal control may conflict with tracer.",
                "level": "WARNING"
            })

        if initial_threads.get("mixed_states"):
            diagnostics.append({
                "code": "MIXED_THREAD_STATES_AT_START",
                "message": f"Process {pid} threads have heterogeneous states: {initial_threads['stopped_count']} stopped, {initial_threads['running_count']} active.",
                "level": "INFO"
            })

        # Read binary executable path and build_id
        exe_path = ""
        try:
            exe_link = f"/proc/{pid}/exe"
            if os.path.exists(exe_link):
                exe_path = os.path.realpath(exe_link)
        except Exception:
            pass

        build_id = None
        if exe_path and os.path.exists(exe_path):
            try:
                from .debug_image import inspect_elf
                info = inspect_elf(exe_path)
                build_id = info.build_id
            except Exception:
                pass

        t_stop_requested = 0
        t_stop_confirmed = 0
        t_threads = 0
        t_memory = 0
        t_resume_requested = 0
        t_resume_confirmed = 0

        raw_regions: List[Dict[str, Any]] = []
        thread_metadata: List[Dict[str, Any]] = []
        captured_ranges: List[Tuple[int, int]] = []
        buffers: Dict[Tuple[int, int], bytes] = {}
        completeness = "COMPLETE"

        # Determine suspension intent based on plan and preexisting state
        should_suspend = (plan.mode != CaptureMode.ZERO_STOP.value)
        if plan.mode == CaptureMode.ZERO_STOP.value:
            should_suspend = False
            state_history.append("ZERO_STOP_MODE")
        elif was_already_stopped:
            should_suspend = False
            stop_confirmed = True
            state_history.append("PREEXISTING_STOP_PRESERVED")
            diagnostics.append({
                "code": "PREEXISTING_STOPPED_STATE_PRESERVED",
                "message": f"Target process {pid} was already stopped ({initial_ident.get('state')}) before capture. SIGSTOP was skipped and SIGCONT will not be sent, preserving original stop state.",
                "level": "INFO"
            })

        # 0. Pre-read maps and pre-allocate capture buffers BEFORE suspending process
        handle.record_checkpoint("POST_OPEN")
        is_same_maps, ident_status_maps = handle.record_checkpoint("PRE_MAPS_READ")
        if not is_same_maps:
            diagnostics.append({
                "code": f"MAPS_READ_ABORTED_{ident_status_maps}",
                "message": f"Target process identity check failed ({ident_status_maps}) before maps collection; aborting capture.",
                "level": "ERROR"
            })
            all_maps = ProcMapsResult([], status="FAILED", error_type="TARGET_EXITED", error="Identity check failed before maps read")
        else:
            all_maps = handle.read_proc_maps()
            is_same_post_maps, ident_status_post_maps = handle.record_checkpoint("POST_MAPS_READ")
            if not is_same_post_maps:
                diagnostics.append({
                    "code": f"MAPS_READ_INVALIDATED_{ident_status_post_maps}",
                    "message": f"Target process identity changed ({ident_status_post_maps}) after reading maps.",
                    "level": "ERROR"
                })

        if hasattr(all_maps, "diagnostics"):
            diagnostics.extend(all_maps.diagnostics)

        selected_maps = []
        maps_enumeration_failed = (getattr(all_maps, "status", "SUCCESS_WITH_RESULTS") == "FAILED")
        explicit_ranges_used_without_maps = False

        if plan.mode == CaptureMode.TARGETED.value and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "targeted",
                    "pathname": "[targeted_range]"
                })
            if maps_enumeration_failed:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })
        elif plan.mode == CaptureMode.OBJECT.value and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "object",
                    "pathname": "[object_range]"
                })
            if maps_enumeration_failed:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })
        elif plan.mode == CaptureMode.THREAD.value and plan.thread_ids:
            if maps_enumeration_failed:
                diagnostics.append({
                    "code": "MAP_ENUMERATION_FAILED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}). Cannot locate thread stack maps in THREAD mode.",
                    "level": "ERROR"
                })
            else:
                for m in all_maps:
                    if m["category"] == "stack" and "r" in m["permissions"]:
                        selected_maps.append(m)
        else:
            # FULL: Capture mutable runtime state (heap, stack, writable data/bss/anonymous)
            if maps_enumeration_failed:
                diagnostics.append({
                    "code": "MAP_ENUMERATION_FAILED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}). FULL capture mode requires valid memory maps; cannot proceed.",
                    "level": "ERROR"
                })
            else:
                for m in all_maps:
                    if "r" in m["permissions"] and ("w" in m["permissions"] or m["category"] in ("heap", "stack", "anonymous")):
                        selected_maps.append(m)

        if not selected_maps and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "targeted",
                    "pathname": "[targeted_range]"
                })
            if maps_enumeration_failed and not explicit_ranges_used_without_maps:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })

        # Pre-allocate buffers and iovecs before suspension, explicitly tracking omitted regions
        read_plans = []
        omitted_regions = []
        bytes_requested = sum(m["size"] for m in selected_maps)
        bytes_attempted = 0
        bytes_omitted = 0
        fn_vm_readv = self._libc.process_vm_readv if self._libc else None

        for idx, reg in enumerate(selected_maps, 1):
            reg_start = reg["start"]
            reg_size = reg["size"]
            if bytes_attempted >= policy.max_capture_bytes or idx > policy.max_capture_ranges:
                bytes_omitted += reg_size
                omitted_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "OMITTED",
                    "error": "POLICY_LIMIT_EXCEEDED"
                })
                continue

            chunk_size = min(reg_size, policy.max_capture_bytes - bytes_attempted)
            if chunk_size <= 0:
                bytes_omitted += reg_size
                omitted_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "OMITTED",
                    "error": "POLICY_LIMIT_EXCEEDED"
                })
                continue

            tail_omitted = reg_size - chunk_size
            if tail_omitted > 0:
                bytes_omitted += tail_omitted

            buf = ctypes.create_string_buffer(chunk_size)
            l_iov = _struct_iovec(ctypes.cast(buf, ctypes.c_void_p), chunk_size)
            r_iov = _struct_iovec(ctypes.c_void_p(reg_start), chunk_size)
            read_plans.append((idx, reg, reg_start, reg_size, chunk_size, tail_omitted, buf, l_iov, r_iov))
            bytes_attempted += chunk_size

        read_results = []

        try:
            # 1. Ultra-short suspend
            if should_suspend:
                is_same_pre_stop, ident_status_pre_stop = handle.record_checkpoint("PRE_SUSPEND")
                if not is_same_pre_stop:
                    suspension_caused_by_capture = False
                    diagnostics.append({
                        "code": f"STOP_ABORTED_{ident_status_pre_stop}",
                        "message": f"Target process identity check failed ({ident_status_pre_stop}) before SIGSTOP; suspension aborted.",
                        "level": "ERROR"
                    })
                else:
                    state_history.append("STOP_REQUESTED")
                    stop_requested = True
                    t_stop_requested = time.monotonic_ns()

                    sig_ok, sig_err = handle.send_signal(signal.SIGSTOP)
                    if not sig_ok:
                        suspension_caused_by_capture = False
                        if sig_err == "TARGET_EXITED":
                            diagnostics.append({
                                "code": "TARGET_EXITED_BEFORE_STOP",
                                "message": f"Process {pid} exited before SIGSTOP delivered",
                                "level": "ERROR"
                            })
                        elif sig_err == "PID_REUSED":
                            diagnostics.append({
                                "code": "PID_REUSED_STOP_ABORTED",
                                "message": f"Target PID {pid} was reused; SIGSTOP aborted to prevent signalling unrelated process",
                                "level": "ERROR"
                            })
                        elif sig_err == "PERMISSION_DENIED":
                            diagnostics.append({
                                "code": "STOP_PERMISSION_DENIED",
                                "message": f"Permission denied (EPERM) delivering SIGSTOP to process {pid}",
                                "level": "ERROR"
                            })
                        else:
                            diagnostics.append({
                                "code": "STOP_SIGNAL_ERROR",
                                "message": f"SIGSTOP failed: {sig_err}",
                                "level": "ERROR"
                            })
                    else:
                        deadline_stop = t_stop_requested + int(policy.max_stop_time_ms * 1_000_000)
                        while time.monotonic_ns() < deadline_stop:
                            try:
                                curr_st = handle.get_process_state()
                                if curr_st.get("is_stopped"):
                                    stop_confirmed = True
                                    curr_threads = handle.get_threads_state()
                                    if curr_threads.get("all_stopped", False):
                                        all_threads_stopped = True
                                        break
                            except Exception:
                                pass
                            try:
                                os.sched_yield()
                            except Exception:
                                pass

                        t_stop_confirmed = time.monotonic_ns()
                        if stop_confirmed:
                            suspension_caused_by_capture = True
                            state_history.append("STOP_CONFIRMED")
                            handle.record_checkpoint("POST_SUSPEND")
                        else:
                            suspension_caused_by_capture = False
                            state_history.append("STOP_UNCONFIRMED")
                            diagnostics.append({
                                "code": "STOP_UNCONFIRMED",
                                "message": f"Process {pid} did not enter stopped state within {policy.max_stop_time_ms} ms. Memory captured under this condition is NON_ATOMIC.",
                                "level": "WARNING"
                            })
            else:
                handle.record_checkpoint("PRE_SUSPEND_SKIPPED")
                t_stop_requested = time.monotonic_ns()
                t_stop_confirmed = t_stop_requested
                if was_already_stopped:
                    stop_confirmed = True

            # 2. Check thread consistency
            if not all_threads_stopped:
                curr_threads = handle.get_threads_state()
                all_threads_stopped = curr_threads.get("all_stopped", False)
            if (should_suspend or was_already_stopped) and not all_threads_stopped:
                diagnostics.append({
                    "code": "THREAD_STATES_HETEROGENEOUS",
                    "message": f"Process {pid} leader stopped, but not all threads are confirmed stopped ({curr_threads.get('stopped_count')}/{curr_threads.get('total_count')}). Snapshot is NON_ATOMIC.",
                    "level": "WARNING"
                })

            # 3. Capture thread metadata
            state_history.append("CAPTURING")
            is_same_th, ident_status_th = handle.record_checkpoint("PRE_THREAD_METADATA")
            if not is_same_th:
                thread_metadata = ThreadMetadataResult(
                    [{
                        "thread_id": pid,
                        "name": None,
                        "state": "UNKNOWN",
                        "stop_status": "UNKNOWN",
                        "is_synthetic": True,
                        "verified_observation": False,
                        "capture_participation": False,
                        "registers_availability": "REGISTER_STATE_UNAVAILABLE",
                        "function": None,
                        "location": None,
                    }],
                    status="FAILED",
                    error_type=ident_status_th,
                    error="Identity verification failed before thread metadata collection",
                    is_synthetic=True,
                )
            else:
                thread_metadata = handle.read_thread_metadata()
            handle.record_checkpoint("POST_THREAD_METADATA")
            t_threads = time.monotonic_ns()

            if getattr(thread_metadata, "is_synthetic", False) or getattr(thread_metadata, "status", "") == "FAILED":
                all_threads_stopped = False
                diagnostics.append({
                    "code": "THREAD_ENUMERATION_FAILED",
                    "message": f"Thread enumeration failed ({getattr(thread_metadata, 'error_type', 'UNKNOWN')}: {getattr(thread_metadata, 'error', '')}). Thread states are UNVERIFIED.",
                    "level": "WARNING"
                })
            if hasattr(thread_metadata, "diagnostics"):
                diagnostics.extend(thread_metadata.diagnostics)

            # 4. Read memory into pre-allocated buffers
            is_same_mem, ident_status_mem = handle.record_checkpoint("PRE_MEMORY_READ")
            mem_reader = getattr(policy, "mem_reader", None)
            for item in read_plans:
                idx, reg, reg_start, reg_size, chunk_size, tail_omitted, buf, l_iov, r_iov = item
                if not is_same_mem:
                    nread = -1
                    err = errno.ESRCH
                elif mem_reader:
                    try:
                        read_data = mem_reader(pid, reg_start, chunk_size)
                        if read_data is not None:
                            nread = len(read_data)
                            ctypes.memmove(buf, read_data, nread)
                            err = 0
                        else:
                            nread = -1
                            err = errno.EIO
                    except Exception:
                        nread = -1
                        err = errno.EIO
                elif fn_vm_readv:
                    nread = fn_vm_readv(
                        pid,
                        ctypes.byref(l_iov),
                        1,
                        ctypes.byref(r_iov),
                        1,
                        0
                    )
                    err = ctypes.get_errno() if nread <= 0 else 0
                    if nread <= 0 and err in (errno.ENOSYS, errno.EPERM) and handle.mem_pinned and handle.mem_fd is not None:
                        # Fallback to pinned /proc/<pid>/mem if process_vm_readv is not permitted or syscall unsupported
                        try:
                            read_bytes = handle.read_mem(reg_start, chunk_size)
                            if read_bytes is not None:
                                nread = len(read_bytes)
                                ctypes.memmove(buf, read_bytes, nread)
                                err = 0
                        except Exception:
                            pass
                elif handle.mem_pinned and handle.mem_fd is not None:
                    # Fallback when fn_vm_readv is not available
                    try:
                        read_bytes = handle.read_mem(reg_start, chunk_size)
                        if read_bytes is not None:
                            nread = len(read_bytes)
                            ctypes.memmove(buf, read_bytes, nread)
                            err = 0
                        else:
                            nread = -1
                            err = errno.EIO
                    except Exception:
                        nread = -1
                        err = errno.EIO
                else:
                    nread = -1
                    err = errno.ENOSYS

                if nread <= 0 and err == errno.ESRCH:
                    diagnostics.append({
                        "code": "TARGET_EXITED_DURING_CAPTURE",
                        "message": f"Process {pid} exited while reading range 0x{reg_start:x}-0x{reg_start+chunk_size:x} (ESRCH).",
                        "level": "ERROR"
                    })
                read_results.append((item, nread, err))

            memory_read_completed = True
            handle.record_checkpoint("POST_MEMORY_READ")
            t_memory = time.monotonic_ns()

        finally:
            try:
                # 5. GUARANTEED FAIL-OPEN RESUME IMMEDIATELY WITH PID-REUSE SAFETY
                if suspension_caused_by_capture:
                    resume_requested = True
                    state_history.append("RESUME_REQUESTED")
                    t_resume_requested = time.monotonic_ns()
                    still_same_process = False
                    is_same, ident_status = handle.record_checkpoint("PRE_RESUME")
                    if is_same:
                        still_same_process = True
                    else:
                        if ident_status == "PID_REUSED":
                            diagnostics.append({
                                "code": "PID_REUSED_RESUME_ABORTED",
                                "message": f"PID {pid} was reused; SIGCONT aborted to prevent signalling unrelated process.",
                                "level": "WARNING"
                            })
                        elif ident_status == "TARGET_EXITED":
                            diagnostics.append({
                                "code": "TARGET_EXITED_DURING_CAPTURE",
                                "message": f"Process {pid} exited during capture; inferior is no longer running.",
                                "level": "INFO"
                            })
                        else:
                            diagnostics.append({
                                "code": "IDENTITY_VERIFICATION_FAILED",
                                "message": f"Process verification failed ({ident_status}); SIGCONT aborted.",
                                "level": "WARNING"
                            })

                    if still_same_process:
                        # Check if target already resumed independently
                        try:
                            post_check = handle.get_process_state()
                            if not post_check.get("is_stopped"):
                                resume_confirmed = True
                                state_history.append("TARGET_RESUMED_INDEPENDENTLY")
                                diagnostics.append({
                                    "code": "TARGET_RESUMED_INDEPENDENTLY",
                                    "message": f"Process {pid} was already active before SIGCONT; target resumed independently.",
                                    "level": "INFO"
                                })
                        except Exception:
                            pass

                        if not resume_confirmed:
                            res_ok, res_err = handle.send_signal(signal.SIGCONT)
                            if not res_ok:
                                if res_err == "TARGET_EXITED":
                                    diagnostics.append({
                                        "code": "TARGET_EXITED_BEFORE_RESUME",
                                        "message": f"Process {pid} exited before SIGCONT delivered.",
                                        "level": "INFO"
                                    })
                                elif res_err == "PERMISSION_DENIED":
                                    diagnostics.append({
                                        "code": "RESUME_PERMISSION_DENIED",
                                        "message": f"Permission denied delivering SIGCONT to process {pid}.",
                                        "level": "ERROR"
                                    })
                                else:
                                    diagnostics.append({
                                        "code": "RESUME_SIGNAL_ERROR",
                                        "message": f"SIGCONT failed: {res_err}",
                                        "level": "ERROR"
                                    })
                            else:
                                # Poll briefly for resume confirmation
                                deadline_res = t_resume_requested + int(20 * 1_000_000)
                                while time.monotonic_ns() < deadline_res:
                                    try:
                                        st_res = handle.get_process_state()
                                        if not st_res.get("is_stopped"):
                                            resume_confirmed = True
                                            break
                                    except Exception:
                                        pass
                                    try:
                                        os.sched_yield()
                                    except Exception:
                                        pass

                                t_resume_confirmed = time.monotonic_ns()
                                if resume_confirmed:
                                    state_history.append("RESUME_CONFIRMED")
                                    handle.record_checkpoint("POST_RESUME")
                                else:
                                    state_history.append("RESUME_UNCONFIRMED")
                                    diagnostics.append({
                                        "code": "RESUME_UNCONFIRMED",
                                        "message": f"Process {pid} did not confirm running state within timeout after SIGCONT.",
                                        "level": "WARNING"
                                    })
                    else:
                        t_resume_confirmed = time.monotonic_ns()
                elif was_already_stopped:
                    # Target was already stopped before capture; preserve existing stopped state!
                    state_history.append("PREEXISTING_STOP_RETAINED")
                    t_resume_requested = t_memory
                    t_resume_confirmed = t_memory
                else:
                    t_resume_requested = t_memory
                    t_resume_confirmed = t_memory
            finally:
                handle.close()

        wall_clock_end = datetime.now(timezone.utc).isoformat()

        # 5. Offline post-processing of buffers (target process is already resumed!)
        bytes_read = 0
        bytes_failed = 0
        bytes_unread = 0

        for item, nread, err in read_results:
            idx, reg, reg_start, reg_size, chunk_size, tail_omitted, buf, _, _ = item
            if nread == chunk_size:
                read_bytes = bytes(buf.raw[:nread])
                buffers[(reg_start, reg_start + nread)] = read_bytes
                captured_ranges.append((reg_start, reg_start + nread))
                bytes_read += nread
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + nread),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": nread,
                    "status": "COMPLETE" if tail_omitted == 0 else "PARTIAL",
                    "error": None
                })
            elif nread > 0:
                read_bytes = bytes(buf.raw[:nread])
                buffers[(reg_start, reg_start + nread)] = read_bytes
                captured_ranges.append((reg_start, reg_start + nread))
                bytes_read += nread
                bytes_unread += (chunk_size - nread)
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + nread),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": nread,
                    "status": "PARTIAL",
                    "error": None
                })
            else:
                bytes_failed += chunk_size
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "FAILED",
                    "error": f"ERRNO_{err}" if err else "READ_FAILED"
                })

        # Append omitted regions so the entire requested scope is accounted for
        raw_regions.extend(omitted_regions)

        regions_complete = sum(1 for r in raw_regions if r.get("status") == "COMPLETE")
        regions_partial = sum(1 for r in raw_regions if r.get("status") == "PARTIAL")
        regions_failed = sum(1 for r in raw_regions if r.get("status") == "FAILED")
        regions_omitted = len(omitted_regions)
        regions_read = regions_complete + regions_partial
        regions_attempted = regions_read + regions_failed + regions_omitted

        any_pid_reused = any(cp.get("status") == "PID_REUSED" for cp in handle.identity_checkpoints) or handle.identity_mismatch
        any_target_exited = any(cp.get("status") == "TARGET_EXITED" for cp in handle.identity_checkpoints)
        any_checkpoint_failed = any(not cp.get("verified", False) for cp in handle.identity_checkpoints)

        thread_enum_failed = (
            getattr(thread_metadata, "is_synthetic", False)
            or (getattr(thread_metadata, "status", "") in ("FAILED", "PARTIAL", "SUCCESS_EMPTY"))
            or any(t.get("is_synthetic") is True or t.get("verified_observation") is False for t in thread_metadata)
        )
        map_enum_failed = (
            getattr(all_maps, "status", "") in ("FAILED", "PARTIAL")
            or (getattr(all_maps, "status", "") == "SUCCESS_EMPTY" and plan.mode == CaptureMode.FULL.value)
        )

        if any_pid_reused:
            capture_status = "INVALID"
            completeness = "INVALID"
        elif maps_enumeration_failed and not explicit_ranges_used_without_maps:
            capture_status = "FAILED"
            completeness = "FAILED"
        elif (bytes_read == 0 and selected_maps) or (any_target_exited and bytes_read == 0) or (len(selected_maps) == 0 and plan.mode == CaptureMode.FULL.value):
            capture_status = "FAILED"
            completeness = "FAILED"
        elif (
            regions_failed > 0
            or regions_partial > 0
            or regions_omitted > 0
            or (should_suspend and not stop_confirmed)
            or ((should_suspend or was_already_stopped) and not all_threads_stopped)
            or (suspension_caused_by_capture and not resume_confirmed)
            or (plan.mode == CaptureMode.ZERO_STOP.value)
            or any_checkpoint_failed
            or explicit_ranges_used_without_maps
            or thread_enum_failed
            or map_enum_failed
        ):
            capture_status = "PARTIAL"
            completeness = "PARTIAL"
        else:
            capture_status = "COMPLETED"
            completeness = "COMPLETE"

        lifecycle_guarantees = {
            "process_stop_requested": stop_requested,
            "process_stop_confirmed": stop_confirmed,
            "all_threads_stopped": all_threads_stopped if (should_suspend or was_already_stopped) else False,
            "memory_read_completed": memory_read_completed,
            "resume_requested": resume_requested,
            "resume_confirmed": resume_confirmed,
        }

        # Honest consistency classification:
        if completeness == "INVALID":
            snapshot_consistency = "INVALID"
            consistency_classification = "INVALID"
        elif completeness == "FAILED":
            snapshot_consistency = "FAILED"
            consistency_classification = "FAILED"
        elif plan.mode == CaptureMode.ZERO_STOP.value:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif not stop_confirmed:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif (should_suspend or was_already_stopped) and not all_threads_stopped:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif was_already_stopped:
            consistency_classification = "PREEXISTING_STOPPED"
            snapshot_consistency = "PROCESS_STOPPED_MEMORY_SNAPSHOT" if completeness == "COMPLETE" else "NON_ATOMIC"
        elif should_suspend and stop_confirmed:
            consistency_classification = "SIGNAL_STOPPED"
            snapshot_consistency = "PROCESS_STOPPED_MEMORY_SNAPSHOT" if completeness == "COMPLETE" else "NON_ATOMIC"
        else:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"

        identity_contract = {
            "target_pid": pid,
            "initial_starttime": initial_ident.get("starttime"),
            "initial_comm": initial_ident.get("comm"),
            "pidfd_supported": handle.pidfd_supported,
            "pidfd_used": handle.pidfd_used,
            "mem_pinned": handle.mem_pinned,
            "mem_pin_error": handle.mem_pin_error,
            "checkpoints": list(handle.identity_checkpoints),
            "identity_mismatch_detected": any_pid_reused,
            "validity": completeness,
        }

        # Compute exact measured microsecond and millisecond latencies
        stop_latency_us = (t_stop_confirmed - t_stop_requested) / 1000.0 if (should_suspend and t_stop_confirmed > 0 and t_stop_requested > 0) else 0.0
        thread_latency_us = (t_threads - t_stop_confirmed) / 1000.0 if (should_suspend and t_threads > 0 and t_stop_confirmed > 0) else 0.0
        memory_latency_us = (t_memory - t_threads) / 1000.0 if (t_memory > 0 and t_threads > 0) else 0.0
        resume_latency_us = (t_resume_confirmed - t_resume_requested) / 1000.0 if (suspension_caused_by_capture and t_resume_confirmed > 0 and t_resume_requested > 0) else 0.0
        total_stop_time_us = (t_resume_confirmed - t_stop_confirmed) / 1000.0 if (suspension_caused_by_capture and t_resume_confirmed > 0 and t_stop_confirmed > 0) else 0.0
        total_capture_time_us = max(0.0, (t_resume_confirmed - t_overall_start_ns) / 1000.0) if t_resume_confirmed > 0 else max(0.0, (time.monotonic_ns() - t_overall_start_ns) / 1000.0)

        latency_report = CaptureLatencyReport(
            stop_latency_ms=stop_latency_us / 1000.0,
            thread_metadata_latency_ms=thread_latency_us / 1000.0,
            memory_capture_latency_ms=memory_latency_us / 1000.0,
            resume_latency_ms=resume_latency_us / 1000.0,
            total_stop_time_ms=total_stop_time_us / 1000.0,
            target_capture_latency_ms=10.0,
            actual_capture_latency_ms=total_capture_time_us / 1000.0,
            stop_latency_us=stop_latency_us,
            thread_metadata_latency_us=thread_latency_us,
            memory_capture_latency_us=memory_latency_us,
            resume_latency_us=resume_latency_us,
            total_stop_time_us=total_stop_time_us,
            total_capture_latency_us=total_capture_time_us,
        )

        obs_meta = {
            "capture_backend": self.name,
            "capture_mode": plan.mode,
            "capture_status": capture_status,
            "consistency_classification": consistency_classification,
            "stop_mechanism": "PREEXISTING_STOP_PRESERVED" if was_already_stopped else ("SIGSTOP" if should_suspend else "NONE"),
            "captured_bytes": bytes_read,
            "bytes_requested": bytes_requested,
            "bytes_read": bytes_read,
            "bytes_omitted": bytes_omitted,
            "bytes_failed": bytes_failed,
            "bytes_unread": bytes_unread,
            "regions_complete": regions_complete,
            "regions_partial": regions_partial,
            "regions_failed": regions_failed,
            "regions_omitted": regions_omitted,
            "regions_read": regions_read,
            "regions_attempted": regions_attempted,
            "stopped_threads": stop_confirmed if (should_suspend or was_already_stopped) else False,
            "all_threads_stopped": all_threads_stopped,
            "was_already_stopped": was_already_stopped,
            "suspension_caused_by_capture": suspension_caused_by_capture,
            "actual_capture_suspended_target": suspension_caused_by_capture,
            "stop_duration_ms": round(total_stop_time_us / 1000.0, 3),
            "total_capture_duration_ms": round(total_capture_time_us / 1000.0, 3),
            "lifecycle_guarantees": lifecycle_guarantees,
            "pid_reuse_mitigation": handle.get_diagnostics(),
            "stop_state_machine": {
                "states": state_history,
                "stop_confirmed": stop_confirmed,
                "resume_confirmed": resume_confirmed,
                "was_already_stopped": was_already_stopped,
                "suspension_caused_by_capture": suspension_caused_by_capture,
                "current": state_history[-1],
            },
            "initial_process_state": initial_ident,
            "initial_threads_state": initial_threads,
            "capture_start": wall_clock_start,
            "capture_end": wall_clock_end,
            "stop_requested": wall_clock_start,
            "observation_point": observation_point,
            "latency_report": latency_report.to_dict(),
            "memory_maps": all_maps,
            "map_enumeration": all_maps.to_dict() if hasattr(all_maps, "to_dict") else {"status": getattr(all_maps, "status", "UNKNOWN")},
            "thread_enumeration": thread_metadata.to_dict() if hasattr(thread_metadata, "to_dict") else {"status": getattr(thread_metadata, "status", "UNKNOWN"), "is_synthetic": getattr(thread_metadata, "is_synthetic", False)},
            "diagnostics": diagnostics,
            "identity_contract": identity_contract,
            "capabilities": self.capabilities,
        }

        provenance = {
            "capture_backend": self.name,
            "capture_mode": plan.mode,
            "capture_status": capture_status,
            "snapshot_consistency": snapshot_consistency,
            "consistency_classification": consistency_classification,
            "stop_mechanism": "PREEXISTING_STOP_PRESERVED" if was_already_stopped else ("SIGSTOP" if should_suspend else "NONE"),
            "stopped_threads": stop_confirmed if (should_suspend or was_already_stopped) else False,
            "all_threads_stopped": all_threads_stopped,
            "was_already_stopped": was_already_stopped,
            "suspension_caused_by_capture": suspension_caused_by_capture,
            "actual_capture_suspended_target": suspension_caused_by_capture,
            "stop_duration_ms": round(total_stop_time_us / 1000.0, 3),
            "total_capture_duration_ms": round(total_capture_time_us / 1000.0, 3),
            "lifecycle_guarantees": lifecycle_guarantees,
            "pid_reuse_mitigation": handle.get_diagnostics(),
            "stop_state_machine": {
                "states": state_history,
                "stop_confirmed": stop_confirmed,
                "resume_confirmed": resume_confirmed,
                "was_already_stopped": was_already_stopped,
                "suspension_caused_by_capture": suspension_caused_by_capture,
            },
            "pid": pid,
            "timestamp": wall_clock_start,
            "capture_start": wall_clock_start,
            "capture_end": wall_clock_end,
            "stop_latency_us": stop_latency_us,
            "memory_read_latency_us": memory_latency_us,
            "capture_latency_us": memory_latency_us,
            "resume_latency_us": resume_latency_us,
            "total_capture_latency_us": total_capture_time_us,
            "duration": total_capture_time_us / 1000.0,
            "thread_count": len(thread_metadata),
            "captured_region_count": len(raw_regions),
            "captured_bytes": bytes_read,
            "bytes_requested": bytes_requested,
            "bytes_read": bytes_read,
            "bytes_omitted": bytes_omitted,
            "bytes_failed": bytes_failed,
            "bytes_unread": bytes_unread,
            "regions_complete": regions_complete,
            "regions_partial": regions_partial,
            "regions_failed": regions_failed,
            "regions_omitted": regions_omitted,
            "regions_read": regions_read,
            "regions_attempted": regions_attempted,
            "observation_point": observation_point,
            "executable_identity": {
                "path": exe_path,
                "build_id": build_id
            },
            "actual_capture_latency_ms": round(total_capture_time_us / 1000.0, 3),
            "target_capture_latency_ms": 10.0,
            "total_stop_time_ms": round(total_stop_time_us / 1000.0, 3),
            "latency_report": latency_report.to_dict(),
            "diagnostics": diagnostics,
            "identity_contract": identity_contract,
            "capabilities": self.capabilities,
            "map_enumeration": all_maps.to_dict() if hasattr(all_maps, "to_dict") else {"status": "SUCCESS_WITH_RESULTS" if all_maps else "SUCCESS_EMPTY"},
            "thread_enumeration": thread_metadata.to_dict() if hasattr(thread_metadata, "to_dict") else {"status": "SUCCESS_WITH_RESULTS" if thread_metadata else "FAILED", "is_synthetic": False},
        }

        raw_snap = RawRuntimeSnapshot(
            snapshot_id=sid,
            pid=pid,
            executable=exe_path,
            executable_build_id=build_id,
            timestamp=wall_clock_start,
            capture_duration_us=round(total_capture_time_us, 1),
            thread_metadata=thread_metadata,
            memory_regions=raw_regions,
            register_state={"status": "REGISTER_STATE_UNAVAILABLE"},
            captured_ranges=captured_ranges,
            raw_memory={"total_bytes": bytes_read},
            capture_backend=self.name,
            observation_metadata=obs_meta,
            completeness=completeness,
            provenance=provenance,
            _buffers=buffers,
        )

        return raw_snap


class ProcfsCaptureBackend(RuntimeCaptureBackend):
    """Fallback capture backend reading /proc/<pid>/mem."""

    @property
    def name(self) -> str:
        return "procfs"

    @property
    def capabilities(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "can_suspend_inferior": True,  # backend can suspend target via external signals (SIGSTOP/SIGCONT) when requested by capture plan
            "can_read_registers": False,
            "can_read_memory": True,
            "atomicity": "NON_ATOMIC",
            "zero_stop_supported": True,
            "syscall_suspends": False,
            "suspension_method": "signal_external",
            "mode_behaviors": {
                "ZERO_STOP": {
                    "suspends_process": False,
                    "atomicity": "NON_ATOMIC",
                    "description": "Zero-stop live capture via procfs: reads /proc/<pid>/mem without pausing process; snapshot is NOT atomic.",
                },
                "FULL": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; consistency depends on stop confirmation.",
                },
                "TARGETED": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures selected semantic ranges.",
                },
                "THREAD": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures thread stack memory.",
                },
                "OBJECT": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures object memory ranges.",
                },
            },
        }

    def is_available(self, pid: Optional[int] = None) -> bool:
        if pid is None:
            return os.path.exists("/proc")
        mem_path = f"/proc/{pid}/mem"
        return os.path.exists(mem_path) and os.access(mem_path, os.R_OK)

    def capture(
        self,
        pid: int,
        plan: Optional[CapturePlan] = None,
        policy: Optional[CaptureSafetyPolicy] = None,
        snapshot_id: Optional[str] = None,
        observation_point: Optional[Dict[str, Any]] = None,
        handle: Optional[ProcessTargetHandle] = None,
    ) -> RawRuntimeSnapshot:
        plan = plan or CapturePlan()
        policy = policy or CaptureSafetyPolicy()

        handle = handle or getattr(policy, "target_handle", None)
        if handle is None and not self.is_available(pid):
            raise RuntimeError(f"procfs is unavailable or target PID {pid} is not accessible")

        # Check process existence and establish target identity with ProcessTargetHandle
        force_fb = getattr(policy, "force_fallback", False)
        exp_id = getattr(policy, "expected_identity", None)
        exp_st = getattr(policy, "expected_starttime", None)
        handle = handle or ProcessTargetHandle(
            pid,
            force_fallback=force_fb,
            expected_identity=exp_id,
            expected_starttime=exp_st,
        )
        try:
            handle.open()
        except Exception:
            handle.close()
            raise

        initial_ident = handle.initial_identity
        initial_threads = handle.get_threads_state()
        was_already_stopped = initial_ident.get("is_stopped", False)
        is_tracing_stop = initial_ident.get("is_tracing_stop", False)
        target_start_time = initial_ident.get("starttime", "0")
        comm = initial_ident.get("comm", "unknown")

        sid = snapshot_id or "RS_{:06d}_{:04d}".format(pid, int(time.time() * 1000) % 10000)
        t_overall_start_ns = time.monotonic_ns()
        wall_clock_start = datetime.now(timezone.utc).isoformat()

        state_history = ["INITIALIZED"]
        capture_status = "COMPLETED"
        stop_requested = False
        stop_confirmed = False
        resume_requested = False
        resume_confirmed = False
        suspension_caused_by_capture = False
        all_threads_stopped = False
        memory_read_completed = False
        diagnostics: List[Dict[str, Any]] = []

        if is_tracing_stop:
            diagnostics.append({
                "code": "TRACING_STOP_OBSERVED",
                "message": f"Process {pid} is in TRACING_STOP ('t'). It may be attached to a debugger/tracer. External signal control may conflict with tracer.",
                "level": "WARNING"
            })

        if initial_threads.get("mixed_states"):
            diagnostics.append({
                "code": "MIXED_THREAD_STATES_AT_START",
                "message": f"Process {pid} threads have heterogeneous states: {initial_threads['stopped_count']} stopped, {initial_threads['running_count']} active.",
                "level": "INFO"
            })

        exe_path = ""
        try:
            exe_link = f"/proc/{pid}/exe"
            if os.path.exists(exe_link):
                exe_path = os.path.realpath(exe_link)
        except Exception:
            pass

        build_id = None
        if exe_path and os.path.exists(exe_path):
            try:
                from .debug_image import inspect_elf
                info = inspect_elf(exe_path)
                build_id = info.build_id
            except Exception:
                pass

        t_stop_requested = 0
        t_stop_confirmed = 0
        t_threads = 0
        t_memory = 0
        t_resume_requested = 0
        t_resume_confirmed = 0

        # Determine suspension intent based on plan and preexisting state
        should_suspend = (plan.mode != CaptureMode.ZERO_STOP.value)
        if plan.mode == CaptureMode.ZERO_STOP.value:
            should_suspend = False
            state_history.append("ZERO_STOP_MODE")
        elif was_already_stopped:
            should_suspend = False
            stop_confirmed = True
            state_history.append("PREEXISTING_STOP_PRESERVED")
            diagnostics.append({
                "code": "PREEXISTING_STOPPED_STATE_PRESERVED",
                "message": f"Target process {pid} was already stopped ({initial_ident.get('state')}) before capture. SIGSTOP was skipped and SIGCONT will not be sent, preserving original stop state.",
                "level": "INFO"
            })

        # 0. Pre-read maps and plan bounded capture
        handle.record_checkpoint("POST_OPEN")
        is_same_maps, ident_status_maps = handle.record_checkpoint("PRE_MAPS_READ")
        if not is_same_maps:
            diagnostics.append({
                "code": f"MAPS_READ_ABORTED_{ident_status_maps}",
                "message": f"Target process identity check failed ({ident_status_maps}) before maps collection; aborting capture.",
                "level": "ERROR"
            })
            all_maps = ProcMapsResult([], status="FAILED", error_type="TARGET_EXITED", error="Identity check failed before maps read")
        else:
            all_maps = handle.read_proc_maps()
            is_same_post_maps, ident_status_post_maps = handle.record_checkpoint("POST_MAPS_READ")
            if not is_same_post_maps:
                diagnostics.append({
                    "code": f"MAPS_READ_INVALIDATED_{ident_status_post_maps}",
                    "message": f"Target process identity changed ({ident_status_post_maps}) after reading maps.",
                    "level": "ERROR"
                })

        if hasattr(all_maps, "diagnostics"):
            diagnostics.extend(all_maps.diagnostics)

        selected_maps = []
        maps_enumeration_failed = (getattr(all_maps, "status", "SUCCESS_WITH_RESULTS") == "FAILED")
        explicit_ranges_used_without_maps = False

        if plan.mode == CaptureMode.TARGETED.value and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "targeted",
                    "pathname": "[targeted_range]"
                })
            if maps_enumeration_failed:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })
        elif plan.mode == CaptureMode.OBJECT.value and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "object",
                    "pathname": "[object_range]"
                })
            if maps_enumeration_failed:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })
        elif plan.mode == CaptureMode.THREAD.value and plan.thread_ids:
            if maps_enumeration_failed:
                diagnostics.append({
                    "code": "MAP_ENUMERATION_FAILED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}). Cannot locate thread stack maps in THREAD mode.",
                    "level": "ERROR"
                })
            else:
                for m in all_maps:
                    if m["category"] == "stack" and "r" in m["permissions"]:
                        selected_maps.append(m)
        else:
            # FULL: Capture mutable runtime state (heap, stack, writable data/bss/anonymous/binary)
            if maps_enumeration_failed:
                diagnostics.append({
                    "code": "MAP_ENUMERATION_FAILED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}). FULL capture mode requires valid memory maps; cannot proceed.",
                    "level": "ERROR"
                })
            else:
                for m in all_maps:
                    if "r" in m["permissions"] and m["category"] in ("heap", "stack", "anonymous", "binary"):
                        selected_maps.append(m)

        if not selected_maps and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "targeted",
                    "pathname": "[targeted_range]"
                })
            if maps_enumeration_failed and not explicit_ranges_used_without_maps:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })

        read_plans = []
        omitted_regions = []
        bytes_requested = sum(m["size"] for m in selected_maps)
        bytes_attempted = 0
        bytes_omitted = 0

        for idx, reg in enumerate(selected_maps, 1):
            reg_start = reg["start"]
            reg_size = reg["size"]
            if bytes_attempted >= policy.max_capture_bytes or idx > policy.max_capture_ranges:
                bytes_omitted += reg_size
                omitted_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "OMITTED",
                    "error": "POLICY_LIMIT_EXCEEDED"
                })
                continue

            chunk_size = min(reg_size, 4 * 1024 * 1024, policy.max_capture_bytes - bytes_attempted)
            if chunk_size <= 0:
                bytes_omitted += reg_size
                omitted_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "OMITTED",
                    "error": "POLICY_LIMIT_EXCEEDED"
                })
                continue

            tail_omitted = reg_size - chunk_size
            if tail_omitted > 0:
                bytes_omitted += tail_omitted

            read_plans.append((idx, reg, reg_start, reg_size, chunk_size, tail_omitted))
            bytes_attempted += chunk_size

        buffers: Dict[Tuple[int, int], bytes] = {}
        raw_regions: List[Dict[str, Any]] = []
        captured_ranges: List[Tuple[int, int]] = []
        read_results = []

        try:
            if should_suspend:
                is_same_pre_stop, ident_status_pre_stop = handle.record_checkpoint("PRE_SUSPEND")
                if not is_same_pre_stop:
                    suspension_caused_by_capture = False
                    diagnostics.append({
                        "code": f"STOP_ABORTED_{ident_status_pre_stop}",
                        "message": f"Target process identity check failed ({ident_status_pre_stop}) before SIGSTOP; suspension aborted.",
                        "level": "ERROR"
                    })
                else:
                    state_history.append("STOP_REQUESTED")
                    stop_requested = True
                    t_stop_requested = time.monotonic_ns()

                    sig_ok, sig_err = handle.send_signal(signal.SIGSTOP)
                    if not sig_ok:
                        suspension_caused_by_capture = False
                        if sig_err == "TARGET_EXITED":
                            diagnostics.append({
                                "code": "TARGET_EXITED_BEFORE_STOP",
                                "message": f"Process {pid} exited before SIGSTOP delivered",
                                "level": "ERROR"
                            })
                        elif sig_err == "PID_REUSED":
                            diagnostics.append({
                                "code": "PID_REUSED_STOP_ABORTED",
                                "message": f"Target PID {pid} was reused; SIGSTOP aborted to prevent signalling unrelated process",
                                "level": "ERROR"
                            })
                        elif sig_err == "PERMISSION_DENIED":
                            diagnostics.append({
                                "code": "STOP_PERMISSION_DENIED",
                                "message": f"Permission denied (EPERM) delivering SIGSTOP to process {pid}",
                                "level": "ERROR"
                            })
                        else:
                            diagnostics.append({
                                "code": "STOP_SIGNAL_ERROR",
                                "message": f"SIGSTOP failed: {sig_err}",
                                "level": "ERROR"
                            })
                    else:
                        deadline_stop = t_stop_requested + int(policy.max_stop_time_ms * 1_000_000)
                        while time.monotonic_ns() < deadline_stop:
                            try:
                                curr_st = handle.get_process_state()
                                if curr_st.get("is_stopped"):
                                    stop_confirmed = True
                                    curr_threads = handle.get_threads_state()
                                    if curr_threads.get("all_stopped", False):
                                        all_threads_stopped = True
                                        break
                            except Exception:
                                pass
                            try:
                                os.sched_yield()
                            except Exception:
                                pass

                        t_stop_confirmed = time.monotonic_ns()
                        if stop_confirmed:
                            suspension_caused_by_capture = True
                            state_history.append("STOP_CONFIRMED")
                            handle.record_checkpoint("POST_SUSPEND")
                        else:
                            suspension_caused_by_capture = False
                            state_history.append("STOP_UNCONFIRMED")
                            diagnostics.append({
                                "code": "STOP_UNCONFIRMED",
                                "message": f"Process {pid} did not enter stopped state within {policy.max_stop_time_ms} ms. Memory captured under this condition is NON_ATOMIC.",
                                "level": "WARNING"
                            })
            else:
                handle.record_checkpoint("PRE_SUSPEND_SKIPPED")
                t_stop_requested = time.monotonic_ns()
                t_stop_confirmed = t_stop_requested
                if was_already_stopped:
                    stop_confirmed = True

            # Check thread consistency
            if not all_threads_stopped:
                curr_threads = handle.get_threads_state()
                all_threads_stopped = curr_threads.get("all_stopped", False)
            if (should_suspend or was_already_stopped) and not all_threads_stopped:
                diagnostics.append({
                    "code": "THREAD_STATES_HETEROGENEOUS",
                    "message": f"Process {pid} leader stopped, but not all threads are confirmed stopped ({curr_threads.get('stopped_count')}/{curr_threads.get('total_count')}). Snapshot is NON_ATOMIC.",
                    "level": "WARNING"
                })

            state_history.append("CAPTURING")
            is_same_th, ident_status_th = handle.record_checkpoint("PRE_THREAD_METADATA")
            if not is_same_th:
                thread_metadata = ThreadMetadataResult(
                    [{
                        "thread_id": pid,
                        "name": None,
                        "state": "UNKNOWN",
                        "stop_status": "UNKNOWN",
                        "is_synthetic": True,
                        "verified_observation": False,
                        "capture_participation": False,
                        "registers_availability": "REGISTER_STATE_UNAVAILABLE",
                        "function": None,
                        "location": None,
                    }],
                    status="FAILED",
                    error_type=ident_status_th,
                    error="Identity verification failed before thread metadata collection",
                    is_synthetic=True,
                )
            else:
                thread_metadata = handle.read_thread_metadata()
            handle.record_checkpoint("POST_THREAD_METADATA")
            t_threads = time.monotonic_ns()

            if getattr(thread_metadata, "is_synthetic", False) or getattr(thread_metadata, "status", "") == "FAILED":
                all_threads_stopped = False
                diagnostics.append({
                    "code": "THREAD_ENUMERATION_FAILED",
                    "message": f"Thread enumeration failed ({getattr(thread_metadata, 'error_type', 'UNKNOWN')}: {getattr(thread_metadata, 'error', '')}). Thread states are UNVERIFIED.",
                    "level": "WARNING"
                })
            if hasattr(thread_metadata, "diagnostics"):
                diagnostics.extend(thread_metadata.diagnostics)

            is_same_mem, ident_status_mem = handle.record_checkpoint("PRE_MEMORY_READ")
            mem_file = f"/proc/{pid}/mem"
            mem_reader = getattr(policy, "mem_reader", None)
            if not is_same_mem:
                for item in read_plans:
                    read_results.append((item, b"", f"IDENTITY_{ident_status_mem}"))
            elif mem_reader:
                for item in read_plans:
                    idx, reg, reg_start, reg_size, chunk_size, tail_omitted = item
                    try:
                        read_data = mem_reader(pid, reg_start, chunk_size)
                        if read_data is not None:
                            read_results.append((item, read_data, None))
                        else:
                            read_results.append((item, b"", "MEM_READ_FAILED"))
                    except Exception as ex:
                        read_results.append((item, b"", str(ex)))
            elif handle.mem_pinned and handle.mem_fd is not None:
                # Prefer pinned /proc/<pid>/mem descriptor
                for item in read_plans:
                    idx, reg, reg_start, reg_size, chunk_size, tail_omitted = item
                    try:
                        read_data = handle.read_mem(reg_start, chunk_size)
                        if read_data is not None:
                            read_results.append((item, read_data, None))
                        else:
                            read_results.append((item, b"", "MEM_READ_FAILED"))
                    except Exception as ex:
                        read_results.append((item, b"", str(ex)))
            else:
                try:
                    with open(mem_file, "rb", buffering=0) as f_mem:
                        for item in read_plans:
                            idx, reg, reg_start, reg_size, chunk_size, tail_omitted = item
                            try:
                                f_mem.seek(reg_start)
                                chunk = f_mem.read(chunk_size)
                                read_results.append((item, chunk, None if chunk else "EOF_EMPTY_READ"))
                            except Exception as read_err:
                                read_results.append((item, b"", str(read_err)))
                except Exception as open_err:
                    diagnostics.append({
                        "code": "MEM_FILE_OPEN_FAILED",
                        "message": f"Failed to open {mem_file}: {open_err}",
                        "level": "ERROR"
                    })
                    for item in read_plans:
                        read_results.append((item, b"", str(open_err)))

            memory_read_completed = True
            handle.record_checkpoint("POST_MEMORY_READ")
            t_memory = time.monotonic_ns()
        finally:
            try:
                if suspension_caused_by_capture:
                    resume_requested = True
                    state_history.append("RESUME_REQUESTED")
                    t_resume_requested = time.monotonic_ns()
                    still_same_process = False
                    is_same, ident_status = handle.record_checkpoint("PRE_RESUME")
                    if is_same:
                        still_same_process = True
                    else:
                        if ident_status == "PID_REUSED":
                            diagnostics.append({
                                "code": "PID_REUSED_RESUME_ABORTED",
                                "message": f"PID {pid} was reused; SIGCONT aborted to prevent signalling unrelated process.",
                                "level": "WARNING"
                            })
                        elif ident_status == "TARGET_EXITED":
                            diagnostics.append({
                                "code": "TARGET_EXITED_DURING_CAPTURE",
                                "message": f"Process {pid} exited during capture; inferior is no longer running.",
                                "level": "INFO"
                            })
                        else:
                            diagnostics.append({
                                "code": "IDENTITY_VERIFICATION_FAILED",
                                "message": f"Process verification failed ({ident_status}); SIGCONT aborted.",
                                "level": "WARNING"
                            })

                    if still_same_process:
                        try:
                            post_check = handle.get_process_state()
                            if not post_check.get("is_stopped"):
                                resume_confirmed = True
                                state_history.append("TARGET_RESUMED_INDEPENDENTLY")
                                diagnostics.append({
                                    "code": "TARGET_RESUMED_INDEPENDENTLY",
                                    "message": f"Process {pid} was already active before SIGCONT; target resumed independently.",
                                    "level": "INFO"
                                })
                        except Exception:
                            pass

                        if not resume_confirmed:
                            res_ok, res_err = handle.send_signal(signal.SIGCONT)
                            if not res_ok:
                                if res_err == "TARGET_EXITED":
                                    diagnostics.append({
                                        "code": "TARGET_EXITED_BEFORE_RESUME",
                                        "message": f"Process {pid} exited before SIGCONT delivered.",
                                        "level": "INFO"
                                    })
                                elif res_err == "PERMISSION_DENIED":
                                    diagnostics.append({
                                        "code": "RESUME_PERMISSION_DENIED",
                                        "message": f"Permission denied delivering SIGCONT to process {pid}.",
                                        "level": "ERROR"
                                    })
                                else:
                                    diagnostics.append({
                                        "code": "RESUME_SIGNAL_ERROR",
                                        "message": f"SIGCONT failed: {res_err}",
                                        "level": "ERROR"
                                    })
                            else:
                                deadline_res = t_resume_requested + int(20 * 1_000_000)
                                while time.monotonic_ns() < deadline_res:
                                    try:
                                        st_res = handle.get_process_state()
                                        if not st_res.get("is_stopped"):
                                            resume_confirmed = True
                                            break
                                    except Exception:
                                        pass
                                    try:
                                        os.sched_yield()
                                    except Exception:
                                        pass

                                t_resume_confirmed = time.monotonic_ns()
                                if resume_confirmed:
                                    state_history.append("RESUME_CONFIRMED")
                                    handle.record_checkpoint("POST_RESUME")
                                else:
                                    state_history.append("RESUME_UNCONFIRMED")
                                    diagnostics.append({
                                        "code": "RESUME_UNCONFIRMED",
                                        "message": f"Process {pid} did not confirm running state within timeout after SIGCONT.",
                                        "level": "WARNING"
                                    })
                    else:
                        t_resume_confirmed = time.monotonic_ns()
                elif was_already_stopped:
                    state_history.append("PREEXISTING_STOP_RETAINED")
                    t_resume_requested = t_memory
                    t_resume_confirmed = t_memory
                else:
                    t_resume_requested = t_memory
                    t_resume_confirmed = t_memory
            finally:
                handle.close()

        wall_clock_end = datetime.now(timezone.utc).isoformat()

        # Offline post-processing of buffers
        bytes_read = 0
        bytes_failed = 0
        bytes_unread = 0

        for item, chunk, err in read_results:
            idx, reg, reg_start, reg_size, chunk_size, tail_omitted = item
            nread = len(chunk) if chunk else 0
            if nread == chunk_size:
                buffers[(reg_start, reg_start + nread)] = chunk
                captured_ranges.append((reg_start, reg_start + nread))
                bytes_read += nread
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + nread),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": nread,
                    "status": "COMPLETE" if tail_omitted == 0 else "PARTIAL",
                    "error": None
                })
            elif nread > 0:
                buffers[(reg_start, reg_start + nread)] = chunk
                captured_ranges.append((reg_start, reg_start + nread))
                bytes_read += nread
                bytes_unread += (chunk_size - nread)
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + nread),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": nread,
                    "status": "PARTIAL",
                    "error": None
                })
            else:
                bytes_failed += chunk_size
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "FAILED",
                    "error": err or "READ_FAILED"
                })

        raw_regions.extend(omitted_regions)

        regions_complete = sum(1 for r in raw_regions if r.get("status") == "COMPLETE")
        regions_partial = sum(1 for r in raw_regions if r.get("status") == "PARTIAL")
        regions_failed = sum(1 for r in raw_regions if r.get("status") == "FAILED")
        regions_omitted = len(omitted_regions)
        regions_read = regions_complete + regions_partial
        regions_attempted = regions_read + regions_failed + regions_omitted

        any_pid_reused = any(cp.get("status") == "PID_REUSED" for cp in handle.identity_checkpoints) or handle.identity_mismatch
        any_target_exited = any(cp.get("status") == "TARGET_EXITED" for cp in handle.identity_checkpoints)
        any_checkpoint_failed = any(not cp.get("verified", False) for cp in handle.identity_checkpoints)

        thread_enum_failed = (
            getattr(thread_metadata, "is_synthetic", False)
            or (getattr(thread_metadata, "status", "") in ("FAILED", "PARTIAL", "SUCCESS_EMPTY"))
            or any(t.get("is_synthetic") is True or t.get("verified_observation") is False for t in thread_metadata)
        )
        map_enum_failed = (
            getattr(all_maps, "status", "") in ("FAILED", "PARTIAL")
            or (getattr(all_maps, "status", "") == "SUCCESS_EMPTY" and plan.mode == CaptureMode.FULL.value)
        )

        if any_pid_reused:
            capture_status = "INVALID"
            completeness = "INVALID"
        elif maps_enumeration_failed and not explicit_ranges_used_without_maps:
            capture_status = "FAILED"
            completeness = "FAILED"
        elif (bytes_read == 0 and selected_maps) or (any_target_exited and bytes_read == 0) or (len(selected_maps) == 0 and plan.mode == CaptureMode.FULL.value):
            capture_status = "FAILED"
            completeness = "FAILED"
        elif (
            regions_failed > 0
            or regions_partial > 0
            or regions_omitted > 0
            or (should_suspend and not stop_confirmed)
            or ((should_suspend or was_already_stopped) and not all_threads_stopped)
            or (suspension_caused_by_capture and not resume_confirmed)
            or (plan.mode == CaptureMode.ZERO_STOP.value)
            or any_checkpoint_failed
            or explicit_ranges_used_without_maps
            or thread_enum_failed
            or map_enum_failed
        ):
            capture_status = "PARTIAL"
            completeness = "PARTIAL"
        else:
            capture_status = "COMPLETED"
            completeness = "COMPLETE"

        lifecycle_guarantees = {
            "process_stop_requested": stop_requested,
            "process_stop_confirmed": stop_confirmed,
            "all_threads_stopped": all_threads_stopped if (should_suspend or was_already_stopped) else False,
            "memory_read_completed": memory_read_completed,
            "resume_requested": resume_requested,
            "resume_confirmed": resume_confirmed,
        }

        # Honest consistency classification:
        if completeness == "INVALID":
            snapshot_consistency = "INVALID"
            consistency_classification = "INVALID"
        elif completeness == "FAILED":
            snapshot_consistency = "FAILED"
            consistency_classification = "FAILED"
        elif plan.mode == CaptureMode.ZERO_STOP.value:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif not stop_confirmed:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif (should_suspend or was_already_stopped) and not all_threads_stopped:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif was_already_stopped:
            consistency_classification = "PREEXISTING_STOPPED"
            snapshot_consistency = "PROCESS_STOPPED_MEMORY_SNAPSHOT" if completeness == "COMPLETE" else "NON_ATOMIC"
        elif should_suspend and stop_confirmed:
            consistency_classification = "SIGNAL_STOPPED"
            snapshot_consistency = "PROCESS_STOPPED_MEMORY_SNAPSHOT" if completeness == "COMPLETE" else "NON_ATOMIC"
        else:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"

        identity_contract = {
            "target_pid": pid,
            "initial_starttime": initial_ident.get("starttime"),
            "initial_comm": initial_ident.get("comm"),
            "pidfd_supported": handle.pidfd_supported,
            "pidfd_used": handle.pidfd_used,
            "mem_pinned": handle.mem_pinned,
            "mem_pin_error": handle.mem_pin_error,
            "checkpoints": list(handle.identity_checkpoints),
            "identity_mismatch_detected": any_pid_reused,
            "validity": completeness,
        }

        stop_latency_us = (t_stop_confirmed - t_stop_requested) / 1000.0 if (should_suspend and t_stop_confirmed > 0 and t_stop_requested > 0) else 0.0
        thread_latency_us = (t_threads - t_stop_confirmed) / 1000.0 if (should_suspend and t_threads > 0 and t_stop_confirmed > 0) else 0.0
        memory_latency_us = (t_memory - t_threads) / 1000.0 if (t_memory > 0 and t_threads > 0) else 0.0
        resume_latency_us = (t_resume_confirmed - t_resume_requested) / 1000.0 if (suspension_caused_by_capture and t_resume_confirmed > 0 and t_resume_requested > 0) else 0.0
        total_stop_time_us = (t_resume_confirmed - t_stop_confirmed) / 1000.0 if (suspension_caused_by_capture and t_resume_confirmed > 0 and t_stop_confirmed > 0) else 0.0
        total_capture_time_us = max(0.0, (t_resume_confirmed - t_overall_start_ns) / 1000.0) if t_resume_confirmed > 0 else max(0.0, (time.monotonic_ns() - t_overall_start_ns) / 1000.0)

        latency_report = CaptureLatencyReport(
            stop_latency_ms=stop_latency_us / 1000.0,
            thread_metadata_latency_ms=thread_latency_us / 1000.0,
            memory_capture_latency_ms=memory_latency_us / 1000.0,
            resume_latency_ms=resume_latency_us / 1000.0,
            total_stop_time_ms=total_stop_time_us / 1000.0,
            target_capture_latency_ms=10.0,
            actual_capture_latency_ms=total_capture_time_us / 1000.0,
            stop_latency_us=stop_latency_us,
            thread_metadata_latency_us=thread_latency_us,
            memory_capture_latency_us=memory_latency_us,
            resume_latency_us=resume_latency_us,
            total_stop_time_us=total_stop_time_us,
            total_capture_latency_us=total_capture_time_us,
        )

        obs_meta = {
            "capture_backend": self.name,
            "capture_mode": plan.mode,
            "capture_status": capture_status,
            "consistency_classification": consistency_classification,
            "stop_mechanism": "PREEXISTING_STOP_PRESERVED" if was_already_stopped else ("SIGSTOP" if should_suspend else "NONE"),
            "captured_bytes": bytes_read,
            "bytes_requested": bytes_requested,
            "bytes_read": bytes_read,
            "bytes_omitted": bytes_omitted,
            "bytes_failed": bytes_failed,
            "bytes_unread": bytes_unread,
            "regions_complete": regions_complete,
            "regions_partial": regions_partial,
            "regions_failed": regions_failed,
            "regions_omitted": regions_omitted,
            "regions_read": regions_read,
            "regions_attempted": regions_attempted,
            "stopped_threads": stop_confirmed if (should_suspend or was_already_stopped) else False,
            "all_threads_stopped": all_threads_stopped,
            "was_already_stopped": was_already_stopped,
            "suspension_caused_by_capture": suspension_caused_by_capture,
            "actual_capture_suspended_target": suspension_caused_by_capture,
            "stop_duration_ms": round(total_stop_time_us / 1000.0, 3),
            "total_capture_duration_ms": round(total_capture_time_us / 1000.0, 3),
            "lifecycle_guarantees": lifecycle_guarantees,
            "pid_reuse_mitigation": handle.get_diagnostics(),
            "stop_state_machine": {
                "states": state_history,
                "stop_confirmed": stop_confirmed,
                "resume_confirmed": resume_confirmed,
                "was_already_stopped": was_already_stopped,
                "suspension_caused_by_capture": suspension_caused_by_capture,
                "current": state_history[-1],
            },
            "initial_process_state": initial_ident,
            "thread_state_analysis": initial_threads,
            "capture_start": wall_clock_start,
            "capture_end": wall_clock_end,
            "stop_requested": wall_clock_start,
            "observation_point": observation_point,
            "latency_report": latency_report.to_dict(),
            "memory_maps": all_maps,
            "map_enumeration": all_maps.to_dict() if hasattr(all_maps, "to_dict") else {"status": getattr(all_maps, "status", "UNKNOWN")},
            "thread_enumeration": thread_metadata.to_dict() if hasattr(thread_metadata, "to_dict") else {"status": getattr(thread_metadata, "status", "UNKNOWN"), "is_synthetic": getattr(thread_metadata, "is_synthetic", False)},
            "diagnostics": diagnostics,
            "identity_contract": identity_contract,
            "capabilities": self.capabilities,
        }

        provenance = {
            "capture_backend": self.name,
            "capture_mode": plan.mode,
            "capture_status": capture_status,
            "snapshot_consistency": snapshot_consistency,
            "consistency_classification": consistency_classification,
            "stop_mechanism": "PREEXISTING_STOP_PRESERVED" if was_already_stopped else ("SIGSTOP" if should_suspend else "NONE"),
            "stopped_threads": stop_confirmed if (should_suspend or was_already_stopped) else False,
            "all_threads_stopped": all_threads_stopped,
            "was_already_stopped": was_already_stopped,
            "suspension_caused_by_capture": suspension_caused_by_capture,
            "actual_capture_suspended_target": suspension_caused_by_capture,
            "stop_duration_ms": round(total_stop_time_us / 1000.0, 3),
            "total_capture_duration_ms": round(total_capture_time_us / 1000.0, 3),
            "lifecycle_guarantees": lifecycle_guarantees,
            "pid_reuse_mitigation": handle.get_diagnostics(),
            "stop_state_machine": {
                "states": state_history,
                "stop_confirmed": stop_confirmed,
                "resume_confirmed": resume_confirmed,
                "was_already_stopped": was_already_stopped,
                "suspension_caused_by_capture": suspension_caused_by_capture,
            },
            "pid": pid,
            "timestamp": wall_clock_start,
            "capture_start": wall_clock_start,
            "capture_end": wall_clock_end,
            "stop_latency_us": stop_latency_us,
            "memory_read_latency_us": memory_latency_us,
            "capture_latency_us": memory_latency_us,
            "resume_latency_us": resume_latency_us,
            "total_capture_latency_us": total_capture_time_us,
            "duration": total_capture_time_us / 1000.0,
            "thread_count": len(thread_metadata),
            "captured_region_count": len(raw_regions),
            "captured_bytes": bytes_read,
            "bytes_requested": bytes_requested,
            "bytes_read": bytes_read,
            "bytes_omitted": bytes_omitted,
            "bytes_failed": bytes_failed,
            "bytes_unread": bytes_unread,
            "regions_complete": regions_complete,
            "regions_partial": regions_partial,
            "regions_failed": regions_failed,
            "regions_omitted": regions_omitted,
            "regions_read": regions_read,
            "regions_attempted": regions_attempted,
            "observation_point": observation_point,
            "executable_identity": {
                "path": exe_path,
                "build_id": build_id
            },
            "actual_capture_latency_ms": round(total_capture_time_us / 1000.0, 3),
            "target_capture_latency_ms": 10.0,
            "total_stop_time_ms": round(total_stop_time_us / 1000.0, 3),
            "latency_report": latency_report.to_dict(),
            "diagnostics": diagnostics,
            "identity_contract": identity_contract,
            "capabilities": self.capabilities,
            "map_enumeration": all_maps.to_dict() if hasattr(all_maps, "to_dict") else {"status": "SUCCESS_WITH_RESULTS" if all_maps else "SUCCESS_EMPTY"},
            "thread_enumeration": thread_metadata.to_dict() if hasattr(thread_metadata, "to_dict") else {"status": "SUCCESS_WITH_RESULTS" if thread_metadata else "FAILED", "is_synthetic": False},
        }

        return RawRuntimeSnapshot(
            snapshot_id=sid,
            pid=pid,
            executable=exe_path,
            executable_build_id=build_id,
            timestamp=wall_clock_start,
            capture_duration_us=round(total_capture_time_us, 1),
            thread_metadata=thread_metadata,
            memory_regions=raw_regions,
            register_state={"status": "REGISTER_STATE_UNAVAILABLE"},
            captured_ranges=captured_ranges,
            raw_memory={"total_bytes": bytes_read},
            capture_backend=self.name,
            observation_metadata=obs_meta,
            completeness=completeness,
            provenance=provenance,
            _buffers=buffers,
        )


class PtraceCaptureBackend(RuntimeCaptureBackend):
    """Ptrace-assisted capture backend for register state and thread capture."""

    @property
    def name(self) -> str:
        return "ptrace"

    @property
    def capabilities(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "can_suspend_inferior": True,
            "can_read_registers": True,
            "can_read_memory": True,
            "atomicity": "STOPPED",
            "zero_stop_supported": False,
        }

    def is_available(self, pid: Optional[int] = None) -> bool:
        if platform.system() != "Linux":
            return False
        return True

    def capture(
        self,
        pid: int,
        plan: Optional[CapturePlan] = None,
        policy: Optional[CaptureSafetyPolicy] = None,
        snapshot_id: Optional[str] = None,
        observation_point: Optional[Dict[str, Any]] = None,
    ) -> RawRuntimeSnapshot:
        backend = ProcessVmCaptureBackend()
        snap = backend.capture(pid, plan=plan, policy=policy, snapshot_id=snapshot_id, observation_point=observation_point)
        snap.capture_backend = self.name
        snap.provenance["capture_backend"] = self.name
        snap.provenance["capabilities"] = self.capabilities
        snap.observation_metadata["capabilities"] = self.capabilities
        return snap


class GdbCaptureBackend(RuntimeCaptureBackend):
    """GDB compatibility capture backend for when GDB is attached."""

    def __init__(self, controller: Optional[Any] = None):
        self.controller = controller

    @property
    def name(self) -> str:
        return "gdb"

    @property
    def capabilities(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "can_suspend_inferior": True,
            "can_read_registers": True,
            "can_read_memory": True,
            "atomicity": "STOPPED",
            "zero_stop_supported": False,
        }

    def is_available(self, pid: Optional[int] = None) -> bool:
        return self.controller is not None and getattr(self.controller, "is_attached", False)

    def capture(
        self,
        pid: int,
        plan: Optional[CapturePlan] = None,
        policy: Optional[CaptureSafetyPolicy] = None,
        snapshot_id: Optional[str] = None,
        observation_point: Optional[Dict[str, Any]] = None,
    ) -> RawRuntimeSnapshot:
        backend = ProcessVmCaptureBackend()
        snap = backend.capture(pid, plan=plan, policy=policy, snapshot_id=snapshot_id, observation_point=observation_point)
        snap.capture_backend = self.name
        snap.provenance["capture_backend"] = self.name
        snap.provenance["capabilities"] = self.capabilities
        snap.observation_metadata["capabilities"] = self.capabilities
        return snap


def get_default_capture_backend() -> RuntimeCaptureBackend:
    """Returns the fastest available capture backend for the current environment."""
    vm_backend = ProcessVmCaptureBackend()
    if vm_backend.is_available():
        return vm_backend
    proc_backend = ProcfsCaptureBackend()
    if proc_backend.is_available():
        return proc_backend
    return PtraceCaptureBackend()
