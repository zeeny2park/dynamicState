"""Deterministic Unit Tests for Capture Lifecycle and Byte Statistics using Injectable Seams.

Covers:
1. Running target: stop confirmed & resume confirmed.
2. Pre-existing stopped target: no resume attempted.
3. Stop signal delivery fails: no resume attempted.
4. Stop confirmation times out: no resume attempted, NON_ATOMIC.
5. Target exits before capture finishes: TARGET_EXITED reported cleanly.
6. Memory read raises exception: target safely restored.
7. Target resumes independently: handled without duplicate SIGCONT error.
8. Target stops independently / preexisting stop preserved.
9. Resume signal fails: reported in diagnostics.
10. Target process disappears during cleanup: clean exit without crash.
11. Thread group consistency: heterogeneous states marked NON_ATOMIC.
12. Byte statistics exact invariant across complete, partial, failed, and omitted reads.
"""

import errno
import os
import signal
import tempfile
import unittest
from typing import Any, Dict, List, Optional, Tuple

from extractor.capture_backend import (
    ProcessVmCaptureBackend,
    ProcfsCaptureBackend,
    ProcessTargetHandle,
    CaptureSafetyPolicy,
)
from extractor.capture_plan import CapturePlan, CaptureMode
from extractor.raw_snapshot import RawRuntimeSnapshot


class MockProcessTargetAdapter:
    """Deterministic test double for ProcessTargetHandle.

    Allows precise control over process state, signals, and lifecycle transitions
    without scheduling jitter or dependencies on real external processes.
    """

    def __init__(
        self,
        pid: int = 99999,
        initial_state: str = "RUNNING",
        comm: str = "mock_target",
        starttime: str = "12345",
        all_threads_stopped: bool = True,
        thread_count: int = 2,
    ):
        self.pid = pid
        self.state = initial_state
        self.comm = comm
        self.starttime = starttime
        self.all_threads_stopped = all_threads_stopped
        self.thread_count = thread_count

        self.pidfd_supported = True
        self.pidfd_used = True
        self.closed = False

        self.signals_sent: List[Tuple[int, str]] = []
        self.fail_stop_signal: Optional[str] = None
        self.stop_confirms: bool = True
        self.fail_resume_signal: Optional[str] = None
        self.target_exits_during_cleanup: bool = False
        self.target_resumes_independently_before_cleanup: bool = False

    def open(self, handle: ProcessTargetHandle) -> None:
        handle.initial_identity = self.get_process_state(self.pid)
        handle.pidfd_supported = self.pidfd_supported
        handle.pidfd_used = self.pidfd_used

    def close(self, handle: ProcessTargetHandle) -> None:
        self.closed = True

    def get_process_state(self, pid: int) -> Dict[str, Any]:
        is_stopped = (self.state == "STOPPED")
        is_tracing = (self.state == "TRACING_STOP")
        return {
            "comm": self.comm,
            "state": self.state,
            "state_char": "T" if is_stopped else ("t" if is_tracing else "S"),
            "starttime": self.starttime,
            "is_stopped": is_stopped or is_tracing,
            "is_tracing_stop": is_tracing,
        }

    def get_threads_state(self, pid: int) -> Dict[str, Any]:
        stopped_count = self.thread_count if self.all_threads_stopped else max(0, self.thread_count - 1)
        running_count = self.thread_count - stopped_count
        return {
            "threads": [],
            "total_count": self.thread_count,
            "stopped_count": stopped_count,
            "running_count": running_count,
            "all_stopped": self.all_threads_stopped and (stopped_count == self.thread_count),
            "any_stopped": stopped_count > 0,
            "mixed_states": (stopped_count > 0 and running_count > 0),
        }

    def send_signal(self, handle: ProcessTargetHandle, sig: int) -> Tuple[bool, Optional[str]]:
        if self.closed:
            return False, "HANDLE_CLOSED"

        sig_name = "SIGSTOP" if sig == signal.SIGSTOP else ("SIGCONT" if sig == signal.SIGCONT else str(sig))
        self.signals_sent.append((sig, sig_name))

        if sig == signal.SIGSTOP:
            if self.fail_stop_signal:
                return False, self.fail_stop_signal
            if self.stop_confirms:
                self.state = "STOPPED"
            return True, None

        elif sig == signal.SIGCONT:
            if self.fail_resume_signal:
                return False, self.fail_resume_signal
            self.state = "RUNNING"
            return True, None

        return True, None

    def verify_identity(self, handle: ProcessTargetHandle) -> Tuple[bool, str]:
        if self.closed:
            return False, "HANDLE_CLOSED"
        if self.target_exits_during_cleanup:
            return False, "TARGET_EXITED"
        if self.target_resumes_independently_before_cleanup:
            self.state = "RUNNING"
        return True, "PIDFD_VERIFIED"


class TestCaptureLifecycleSeam(unittest.TestCase):
    """Deterministic unit tests for the 10 lifecycle scenarios and safety guarantees."""

    def test_01_running_target_stopped_and_resumed(self):
        """1. Running target: stop confirmed and resume confirmed."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        def mock_mem(pid, addr, size):
            return b"A" * size

        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=mock_mem)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy)
        obs_meta = snap.observation_metadata

        # Guarantees check
        self.assertFalse(obs_meta["was_already_stopped"])
        self.assertTrue(obs_meta["suspension_caused_by_capture"])
        self.assertTrue(obs_meta["actual_capture_suspended_target"])
        self.assertEqual(obs_meta["stop_mechanism"], "SIGSTOP")
        self.assertEqual(obs_meta["consistency_classification"], "SIGNAL_STOPPED")

        guarantees = obs_meta["lifecycle_guarantees"]
        self.assertTrue(guarantees["process_stop_requested"])
        self.assertTrue(guarantees["process_stop_confirmed"])
        self.assertTrue(guarantees["all_threads_stopped"])
        self.assertTrue(guarantees["memory_read_completed"])
        self.assertTrue(guarantees["resume_requested"])
        self.assertTrue(guarantees["resume_confirmed"])

        # Check signals delivered
        sig_names = [name for _, name in adapter.signals_sent]
        self.assertEqual(sig_names, ["SIGSTOP", "SIGCONT"])
        self.assertTrue(adapter.closed)

    def test_02_preexisting_stopped_target_not_resumed(self):
        """2. Pre-existing stopped target: no SIGSTOP or SIGCONT sent, stop preserved."""
        adapter = MockProcessTargetAdapter(initial_state="STOPPED")
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        def mock_mem(pid, addr, size):
            return b"B" * size

        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=mock_mem)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy)
        obs_meta = snap.observation_metadata

        self.assertTrue(obs_meta["was_already_stopped"])
        self.assertFalse(obs_meta["suspension_caused_by_capture"])
        self.assertEqual(obs_meta["stop_mechanism"], "PREEXISTING_STOP_PRESERVED")
        self.assertEqual(obs_meta["consistency_classification"], "PREEXISTING_STOPPED")

        guarantees = obs_meta["lifecycle_guarantees"]
        self.assertFalse(guarantees["process_stop_requested"])
        self.assertTrue(guarantees["process_stop_confirmed"])
        self.assertFalse(guarantees["resume_requested"])
        self.assertFalse(guarantees["resume_confirmed"])

        # Absolutely NO signals sent!
        self.assertEqual(len(adapter.signals_sent), 0)
        self.assertEqual(adapter.state, "STOPPED")
        self.assertTrue(adapter.closed)

    def test_03_stop_signal_delivery_fails(self):
        """3. Stop signal delivery fails: no resume attempted, stop not confirmed."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter.fail_stop_signal = "PERMISSION_DENIED"
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=lambda p, a, s: b"C" * s)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy)
        obs_meta = snap.observation_metadata

        self.assertFalse(obs_meta["was_already_stopped"])
        self.assertFalse(obs_meta["suspension_caused_by_capture"])

        guarantees = obs_meta["lifecycle_guarantees"]
        self.assertTrue(guarantees["process_stop_requested"])
        self.assertFalse(guarantees["process_stop_confirmed"])
        self.assertFalse(guarantees["resume_requested"])
        self.assertFalse(guarantees["resume_confirmed"])

        # Only SIGSTOP was attempted, NO SIGCONT
        sig_names = [name for _, name in adapter.signals_sent]
        self.assertEqual(sig_names, ["SIGSTOP"])
        diag_codes = [d["code"] for d in snap.observation_metadata.get("diagnostics", [])]
        self.assertIn("STOP_PERMISSION_DENIED", diag_codes)

    def test_04_stop_confirmation_times_out(self):
        """4. Stop confirmation times out: no resume attempted, marked NON_ATOMIC."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter.stop_confirms = False  # Signal is sent, but target never enters STOPPED
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        policy = CaptureSafetyPolicy(max_stop_time_ms=1.0, target_handle=handle, mem_reader=lambda p, a, s: b"D" * s)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy)
        obs_meta = snap.observation_metadata

        self.assertFalse(obs_meta["suspension_caused_by_capture"])
        self.assertEqual(obs_meta["consistency_classification"], "NON_ATOMIC")

        guarantees = obs_meta["lifecycle_guarantees"]
        self.assertTrue(guarantees["process_stop_requested"])
        self.assertFalse(guarantees["process_stop_confirmed"])
        self.assertFalse(guarantees["resume_requested"])
        self.assertFalse(guarantees["resume_confirmed"])

        # Since stop was never confirmed, capture does not own right to resume!
        sig_names = [name for _, name in adapter.signals_sent]
        self.assertEqual(sig_names, ["SIGSTOP"])
        diag_codes = [d["code"] for d in obs_meta.get("diagnostics", [])]
        self.assertIn("STOP_UNCONFIRMED", diag_codes)

    def test_05_target_exits_before_capture_finishes(self):
        """5. Target exits before capture finishes: TARGET_EXITED diagnostic, no crash."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter.fail_stop_signal = "TARGET_EXITED"
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=lambda p, a, s: None)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy)
        diag_codes = [d["code"] for d in snap.observation_metadata.get("diagnostics", [])]
        self.assertIn("TARGET_EXITED_BEFORE_STOP", diag_codes)
        self.assertFalse(snap.observation_metadata["lifecycle_guarantees"]["resume_requested"])

    def test_06_memory_read_raises_exception_restores_target(self):
        """6. Memory read raises exception: target safely restored via finally block."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        def faulty_reader(p, a, s):
            raise IOError("Direct memory access hardware failure")

        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=faulty_reader)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy)

        # Ensure SIGCONT was still delivered
        sig_names = [name for _, name in adapter.signals_sent]
        self.assertIn("SIGCONT", sig_names)
        self.assertTrue(snap.observation_metadata["lifecycle_guarantees"]["resume_requested"])
        self.assertTrue(adapter.closed)

    def test_07_target_resumes_independently(self):
        """7. Target resumes independently: handled without error or duplicate SIGCONT."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter.target_resumes_independently_before_cleanup = True
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=lambda p, a, s: b"X" * s)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy)
        obs_meta = snap.observation_metadata

        diag_codes = [d["code"] for d in obs_meta.get("diagnostics", [])]
        self.assertIn("TARGET_RESUMED_INDEPENDENTLY", diag_codes)
        self.assertTrue(obs_meta["lifecycle_guarantees"]["resume_confirmed"])

    def test_08_resume_signal_fails(self):
        """8. Resume signal fails: failure reported in diagnostics."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter.fail_resume_signal = "PERMISSION_DENIED"
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=lambda p, a, s: b"Y" * s)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy)
        obs_meta = snap.observation_metadata

        guarantees = obs_meta["lifecycle_guarantees"]
        self.assertTrue(guarantees["resume_requested"])
        self.assertFalse(guarantees["resume_confirmed"])

        diag_codes = [d["code"] for d in obs_meta.get("diagnostics", [])]
        self.assertIn("RESUME_PERMISSION_DENIED", diag_codes)

    def test_09_target_disappears_during_cleanup(self):
        """9. Target process disappears during cleanup: clean exit without crash."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter.target_exits_during_cleanup = True
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=lambda p, a, s: b"Z" * s)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy)
        obs_meta = snap.observation_metadata

        diag_codes = [d["code"] for d in obs_meta.get("diagnostics", [])]
        self.assertIn("TARGET_EXITED_DURING_CAPTURE", diag_codes)
        self.assertTrue(adapter.closed)

    def test_10_thread_group_heterogeneity_degrades_atomicity(self):
        """10. Thread-group consistency: heterogeneous thread states degrade consistency to NON_ATOMIC."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING", all_threads_stopped=False, thread_count=4)
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=lambda p, a, s: b"W" * s)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy)
        obs_meta = snap.observation_metadata

        self.assertFalse(obs_meta["all_threads_stopped"])
        self.assertFalse(obs_meta["lifecycle_guarantees"]["all_threads_stopped"])
        self.assertEqual(obs_meta["consistency_classification"], "NON_ATOMIC")

        diag_codes = [d["code"] for d in obs_meta.get("diagnostics", [])]
        self.assertIn("THREAD_STATES_HETEROGENEOUS", diag_codes)


class TestByteStatisticsInvariant(unittest.TestCase):
    """Test exact byte accounting and invariant:
    bytes_requested == bytes_read + bytes_failed + bytes_omitted + bytes_unread
    """

    def _run_byte_test(self, backend_cls, mem_reader, policy_override=None):
        adapter = MockProcessTargetAdapter(initial_state="STOPPED")
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        pol_args = {
            "target_handle": handle,
            "mem_reader": mem_reader,
            "max_capture_bytes": 100000,
            "max_capture_ranges": 100,
        }
        if policy_override:
            pol_args.update(policy_override)
        policy = CaptureSafetyPolicy(**pol_args)

        # 4 regions of 1000 bytes each -> 4000 requested bytes
        ranges = [
            (0x1000, 0x13E8),  # 1000 bytes
            (0x2000, 0x23E8),  # 1000 bytes
            (0x3000, 0x33E8),  # 1000 bytes
            (0x4000, 0x43E8),  # 1000 bytes
        ]
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=ranges)
        backend = backend_cls()
        snap = backend.capture(adapter.pid, plan=plan, policy=policy)

        meta = snap.observation_metadata
        req = meta["bytes_requested"]
        read = meta["bytes_read"]
        failed = meta["bytes_failed"]
        omitted = meta["bytes_omitted"]
        unread = meta["bytes_unread"]

        # 1. Exact Byte Invariant
        self.assertEqual(req, 4000)
        self.assertEqual(
            req,
            read + failed + omitted + unread,
            f"Invariant violated! req={req} != read({read}) + failed({failed}) + omitted({omitted}) + unread({unread})"
        )

        # 2. Region Invariant
        regions_complete = meta["regions_complete"]
        regions_partial = meta["regions_partial"]
        regions_failed = meta["regions_failed"]
        regions_omitted = meta["regions_omitted"]
        regions_read = meta["regions_read"]
        regions_attempted = meta["regions_attempted"]

        self.assertEqual(regions_read, regions_complete + regions_partial)
        self.assertEqual(regions_attempted, regions_read + regions_failed + regions_omitted)

        # 3. Snapshot summary consistency
        self.assertEqual(snap.raw_memory["total_bytes"], read)
        self.assertEqual(meta["captured_bytes"], read)

        return meta

    def test_complete_reads_process_vm(self):
        """All regions read completely with ProcessVmCaptureBackend."""
        mem_reader = lambda pid, addr, sz: b"K" * sz
        meta = self._run_byte_test(ProcessVmCaptureBackend, mem_reader)
        self.assertEqual(meta["bytes_read"], 4000)
        self.assertEqual(meta["bytes_failed"], 0)
        self.assertEqual(meta["bytes_omitted"], 0)
        self.assertEqual(meta["bytes_unread"], 0)
        self.assertEqual(meta["regions_complete"], 4)
        self.assertEqual(meta["regions_partial"], 0)
        self.assertEqual(meta["regions_failed"], 0)
        self.assertEqual(meta["regions_omitted"], 0)

    def test_complete_reads_procfs(self):
        """All regions read completely with ProcfsCaptureBackend."""
        mem_reader = lambda pid, addr, sz: b"K" * sz
        meta = self._run_byte_test(ProcfsCaptureBackend, mem_reader)
        self.assertEqual(meta["bytes_read"], 4000)
        self.assertEqual(meta["regions_complete"], 4)

    def test_partial_and_failed_reads_process_vm(self):
        """Simulate partial read on region 2, failure on region 3."""
        def mem_reader(pid, addr, sz):
            if addr == 0x1000:
                return b"A" * sz       # Complete: 1000
            elif addr == 0x2000:
                return b"B" * 400      # Partial: 400 of 1000 (unread: 600)
            elif addr == 0x3000:
                return None            # Failed: 0 of 1000 (failed: 1000)
            elif addr == 0x4000:
                return b"D" * sz       # Complete: 1000

        meta = self._run_byte_test(ProcessVmCaptureBackend, mem_reader)
        self.assertEqual(meta["bytes_read"], 2400)
        self.assertEqual(meta["bytes_unread"], 600)
        self.assertEqual(meta["bytes_failed"], 1000)
        self.assertEqual(meta["bytes_omitted"], 0)
        self.assertEqual(meta["regions_complete"], 2)
        self.assertEqual(meta["regions_partial"], 1)
        self.assertEqual(meta["regions_failed"], 1)
        self.assertEqual(meta["regions_omitted"], 0)

    def test_partial_and_failed_reads_procfs(self):
        """Simulate partial read on region 2, failure on region 3 for Procfs."""
        def mem_reader(pid, addr, sz):
            if addr == 0x1000:
                return b"A" * sz
            elif addr == 0x2000:
                return b"B" * 400
            elif addr == 0x3000:
                return None
            elif addr == 0x4000:
                return b"D" * sz

        meta = self._run_byte_test(ProcfsCaptureBackend, mem_reader)
        self.assertEqual(meta["bytes_read"], 2400)
        self.assertEqual(meta["bytes_unread"], 600)
        self.assertEqual(meta["bytes_failed"], 1000)
        self.assertEqual(meta["bytes_omitted"], 0)
        self.assertEqual(meta["regions_complete"], 2)
        self.assertEqual(meta["regions_partial"], 1)
        self.assertEqual(meta["regions_failed"], 1)
        self.assertEqual(meta["regions_omitted"], 0)

    def test_oversized_policy_omits_bytes_consistently(self):
        """Policy limits cap byte capture: tail of region 3 and entire region 4 omitted."""
        # max_capture_bytes = 2500
        # Region 1: 1000 read
        # Region 2: 1000 read
        # Region 3: chunk_size=500 read, tail_omitted=500
        # Region 4: entire 1000 omitted
        def mem_reader(pid, addr, sz):
            return b"M" * sz

        meta = self._run_byte_test(
            ProcessVmCaptureBackend,
            mem_reader,
            policy_override={"max_capture_bytes": 2500}
        )
        self.assertEqual(meta["bytes_read"], 2500)
        self.assertEqual(meta["bytes_omitted"], 1500)
        self.assertEqual(meta["bytes_failed"], 0)
        self.assertEqual(meta["bytes_unread"], 0)
        self.assertEqual(meta["regions_complete"], 2)
        self.assertEqual(meta["regions_partial"], 1)
        self.assertEqual(meta["regions_failed"], 0)
        self.assertEqual(meta["regions_omitted"], 1)


class MockPidfdRaceAdapter:
    """Mock adapter simulating precise PID reuse races before and during pidfd initialization."""

    def __init__(
        self,
        pid: int = 12345,
        pre_starttime: str = "100",
        post_starttime: str = "100",
        pre_comm: str = "app",
        post_comm: str = "app",
        pidfd_errno: Optional[int] = None,
        pidfd_val: int = 42,
    ):
        self.pid = pid
        self.pre_starttime = pre_starttime
        self.post_starttime = post_starttime
        self.pre_comm = pre_comm
        self.post_comm = post_comm
        self.pidfd_errno = pidfd_errno
        self.pidfd_val = pidfd_val
        self.pidfd_opened = False
        self.pidfd_closed = False
        self.signals_sent: List[int] = []

    def get_process_state(self, pid: int) -> Dict[str, Any]:
        st = self.post_starttime if self.pidfd_opened else self.pre_starttime
        comm = self.post_comm if self.pidfd_opened else self.pre_comm
        return {
            "comm": comm,
            "state": "RUNNING",
            "state_char": "R",
            "starttime": st,
            "is_stopped": False,
            "is_tracing_stop": False,
        }

    def get_threads_state(self, pid: int) -> Dict[str, Any]:
        return {
            "threads": [],
            "total_count": 1,
            "stopped_count": 0,
            "running_count": 1,
            "all_stopped": False,
            "any_stopped": False,
            "mixed_states": False,
        }

    def pidfd_open(self, pid: int, flags: int = 0) -> int:
        if self.pidfd_errno == errno.ESRCH:
            raise ProcessLookupError("No such process")
        elif self.pidfd_errno == errno.EPERM:
            raise PermissionError("Permission denied")
        elif self.pidfd_errno:
            raise OSError(self.pidfd_errno, os.strerror(self.pidfd_errno))
        self.pidfd_opened = True
        return self.pidfd_val

    def close_pidfd(self, fd: int) -> None:
        self.pidfd_closed = True

    def send_signal(self, handle, sig: int) -> Tuple[bool, Optional[str]]:
        self.signals_sent.append(sig)
        return True, None


class TestPidfdIdentityRaceMitigation(unittest.TestCase):
    """Unit tests proving elimination of the pidfd identity race and safe failure paths."""

    def test_pidfd_identity_mismatch_during_open(self):
        """PID reused between stat read and pidfd_open: detected, pidfd closed, signal aborted."""
        adapter = MockPidfdRaceAdapter(pre_starttime="100", post_starttime="200")
        handle = ProcessTargetHandle(pid=12345, adapter=adapter)

        with self.assertRaises(ProcessLookupError) as ctx:
            handle.open()
        self.assertIn("PID reuse race detected", str(ctx.exception))
        self.assertTrue(handle.identity_mismatch)
        self.assertEqual(handle.open_status, "IDENTITY_MISMATCH")
        self.assertTrue(adapter.pidfd_closed, "Opened pidfd must be closed immediately on mismatch!")
        self.assertIsNone(handle.pidfd)

        # Ensure send_signal fails safely and NEVER sends signals to the reused PID
        ok, err = handle.send_signal(signal.SIGCONT)
        self.assertFalse(ok)
        self.assertEqual(err, "IDENTITY_MISMATCH")
        self.assertEqual(len(adapter.signals_sent), 0)

    def test_pidfd_identity_mismatch_before_open_with_expected_identity(self):
        """Expected identity differs from pre-open identity: aborts before pidfd_open."""
        adapter = MockPidfdRaceAdapter(pre_starttime="150")
        handle = ProcessTargetHandle(pid=12345, adapter=adapter, expected_starttime="100")

        with self.assertRaises(ProcessLookupError) as ctx:
            handle.open()
        self.assertIn("Process identity mismatch before pidfd_open", str(ctx.exception))
        self.assertTrue(handle.identity_mismatch)
        self.assertEqual(handle.open_status, "IDENTITY_MISMATCH")
        self.assertFalse(adapter.pidfd_opened, "pidfd_open must never be called on pre-mismatch!")

    def test_pidfd_unsupported_falls_back_to_starttime_safely(self):
        """When pidfd is unsupported (ENOSYS), gracefully falls back to starttime check."""
        adapter = MockPidfdRaceAdapter(pidfd_errno=errno.ENOSYS)
        handle = ProcessTargetHandle(pid=12345, adapter=adapter)

        handle.open()
        self.assertEqual(handle.open_status, "FALLBACK_INITIALIZED")
        self.assertFalse(handle.pidfd_used)
        self.assertIsNone(handle.pidfd)
        diags = handle.get_diagnostics()
        self.assertEqual(diags["mitigation_mechanism"], "STAT_STARTTIME_CHECK_FALLBACK")
        self.assertIn("Fallback starttime verification", diags["fallback_caveat"])

    def test_pidfd_init_failure_raises_and_cleans_up(self):
        """pidfd_open failures like EMFILE raise cleanly and mark PIDFD_INIT_FAILED."""
        adapter = MockPidfdRaceAdapter(pidfd_errno=errno.EMFILE)
        handle = ProcessTargetHandle(pid=12345, adapter=adapter)

        with self.assertRaises(OSError):
            handle.open()
        self.assertEqual(handle.open_status, "PIDFD_INIT_FAILED")
        self.assertIsNone(handle.pidfd)

    def test_pidfd_target_exited_during_open(self):
        """Target exit during pidfd_open marks TARGET_EXITED and raises ProcessLookupError."""
        adapter = MockPidfdRaceAdapter(pidfd_errno=errno.ESRCH)
        handle = ProcessTargetHandle(pid=12345, adapter=adapter)

        with self.assertRaises(ProcessLookupError):
            handle.open()
        self.assertEqual(handle.open_status, "TARGET_EXITED")

    def test_pidfd_permission_denied_during_open(self):
        """Permission denied during pidfd_open marks PERMISSION_DENIED and raises PermissionError."""
        adapter = MockPidfdRaceAdapter(pidfd_errno=errno.EPERM)
        handle = ProcessTargetHandle(pid=12345, adapter=adapter)

        with self.assertRaises(PermissionError):
            handle.open()
        self.assertEqual(handle.open_status, "PERMISSION_DENIED")

        adapter = MockPidfdRaceAdapter(pre_starttime="100", post_starttime="100")
        handle = ProcessTargetHandle(pid=12345, adapter=adapter)

        handle.open()
        self.assertEqual(handle.open_status, "PIDFD_OPENED")
        self.assertTrue(handle.pidfd_used)
        self.assertFalse(handle.identity_mismatch)
        self.assertEqual(handle.initial_identity["starttime"], "100")


class IdentityRaceDynamicAdapter(MockPidfdRaceAdapter):
    """Mock adapter that can trigger PID reuse or target exit at specific checkpoints."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.call_count = 0
        self.reuse_at_call: Optional[int] = None
        self.exit_at_call: Optional[int] = None
        self.fail_resume = False
        self.stopped = False

    def verify_identity(self, handle) -> Tuple[bool, str]:
        self.call_count += 1
        if self.reuse_at_call is not None and self.call_count >= self.reuse_at_call:
            handle.identity_mismatch = True
            return False, "PID_REUSED"
        if self.exit_at_call is not None and self.call_count >= self.exit_at_call:
            return False, "TARGET_EXITED"
        return True, "PIDFD_VERIFIED"

    def get_process_state(self, pid: int) -> Dict[str, Any]:
        return {
            "comm": "app",
            "state": "STOPPED" if self.stopped else "RUNNING",
            "state_char": "T" if self.stopped else "R",
            "starttime": self.post_starttime,
            "is_stopped": self.stopped,
            "is_tracing_stop": False,
        }

    def get_threads_state(self, pid: int) -> Dict[str, Any]:
        return {
            "threads": [],
            "total_count": 1,
            "stopped_count": 1 if self.stopped else 0,
            "running_count": 0 if self.stopped else 1,
            "all_stopped": self.stopped,
            "any_stopped": self.stopped,
            "mixed_states": False,
        }

    def send_signal(self, handle, sig: int) -> Tuple[bool, Optional[str]]:
        self.signals_sent.append(sig)
        if sig == signal.SIGSTOP:
            self.stopped = True
            return True, None
        elif sig == signal.SIGCONT:
            if self.fail_resume:
                return False, "RESUME_FAILED"
            self.stopped = False
            return True, None
        return True, None


class TestPinnedIdentityAndValidityInvariants(unittest.TestCase):
    """Unit tests proving pinned process identity lifecycle, invariants, and validity."""

    def test_pid_reuse_during_memory_read_yields_invalid_snapshot(self):
        """PID reuse detected during capture lifecycle results in an INVALID snapshot."""
        adapter = IdentityRaceDynamicAdapter()
        adapter.reuse_at_call = 4  # Triggers at PRE_MEMORY_READ

        handle = ProcessTargetHandle(pid=12345, adapter=adapter)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x2000)])
        policy = CaptureSafetyPolicy(
            target_handle=handle,
            mem_reader=lambda p, a, s: b"\xaa" * s,
        )

        backend = ProcessVmCaptureBackend()
        snap = backend.capture(pid=12345, plan=plan, policy=policy, handle=handle)

        self.assertEqual(snap.completeness, "INVALID")
        self.assertEqual(snap.observation_metadata["capture_status"], "INVALID")
        self.assertEqual(snap.provenance["snapshot_consistency"], "INVALID")
        contract = snap.observation_metadata["identity_contract"]
        self.assertEqual(contract["validity"], "INVALID")
        self.assertTrue(contract["identity_mismatch_detected"])
        self.assertTrue(any(cp["status"] == "PID_REUSED" for cp in contract["checkpoints"]))

    def test_target_exit_before_memory_read_yields_failed_snapshot(self):
        """Target process exiting before memory is captured results in a FAILED snapshot."""
        adapter = IdentityRaceDynamicAdapter()
        adapter.exit_at_call = 3  # Triggers at PRE_THREAD_METADATA / PRE_MEMORY_READ

        handle = ProcessTargetHandle(pid=12345, adapter=adapter)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x2000)])
        policy = CaptureSafetyPolicy(
            target_handle=handle,
            mem_reader=lambda p, a, s: None,  # Read returns None on exited process
        )

        backend = ProcessVmCaptureBackend()
        snap = backend.capture(pid=12345, plan=plan, policy=policy, handle=handle)

        self.assertEqual(snap.completeness, "FAILED")
        self.assertEqual(snap.observation_metadata["capture_status"], "FAILED")
        self.assertEqual(snap.provenance["snapshot_consistency"], "FAILED")
        self.assertEqual(snap.observation_metadata["identity_contract"]["validity"], "FAILED")

    def test_resume_failure_yields_partial_snapshot(self):
        """Failed resume signal delivery marks the snapshot as PARTIAL."""
        adapter = IdentityRaceDynamicAdapter()
        adapter.fail_resume = True

        handle = ProcessTargetHandle(pid=12345, adapter=adapter)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x2000)])
        policy = CaptureSafetyPolicy(
            target_handle=handle,
            mem_reader=lambda p, a, s: b"\x42" * s,
        )

        backend = ProcessVmCaptureBackend()
        snap = backend.capture(pid=12345, plan=plan, policy=policy, handle=handle)

        self.assertEqual(snap.completeness, "PARTIAL")
        self.assertEqual(snap.observation_metadata["capture_status"], "PARTIAL")
        self.assertFalse(snap.observation_metadata["lifecycle_guarantees"]["resume_confirmed"])
        self.assertTrue(any(d.get("code") == "RESUME_SIGNAL_ERROR" for d in snap.observation_metadata["diagnostics"]))

    def test_mathematical_byte_invariant_precision(self):
        """Enforces: bytes_requested == bytes_read + bytes_failed + bytes_omitted + bytes_unread."""
        adapter = IdentityRaceDynamicAdapter()
        handle = ProcessTargetHandle(pid=12345, adapter=adapter)

        # Plan with 3 ranges: 100 bytes, 200 bytes, 300 bytes = 600 bytes requested
        plan = CapturePlan(
            mode=CaptureMode.TARGETED.value,
            memory_ranges=[(0x1000, 0x1000 + 100), (0x2000, 0x2000 + 200), (0x3000, 0x3000 + 300)],
        )

        # Policy limits max_capture_bytes to 250 -> range 3 (300 bytes) will be omitted, range 2 partially capped
        policy = CaptureSafetyPolicy(
            target_handle=handle,
            max_capture_bytes=250,
            mem_reader=lambda p, addr, sz: b"\x00" * sz if addr == 0x1000 else None,  # range 1 succeeds, range 2 fails
        )

        backend = ProcessVmCaptureBackend()
        snap = backend.capture(pid=12345, plan=plan, policy=policy, handle=handle)

        obs = snap.observation_metadata
        req = obs["bytes_requested"]
        read = obs["bytes_read"]
        failed = obs["bytes_failed"]
        omitted = obs["bytes_omitted"]
        unread = obs["bytes_unread"]

        self.assertEqual(req, 600)
        self.assertEqual(req, read + failed + omitted + unread)
        self.assertEqual(read, 100)
        self.assertEqual(failed, 150)
        self.assertEqual(omitted, 350)
        self.assertEqual(unread, 0)

    def test_snapshot_save_and_reload_preserves_validity_and_contract(self):
        """Serializing and deserializing INVALID and FAILED snapshots faithfully retains status."""
        for test_status in ["INVALID", "FAILED", "PARTIAL", "COMPLETE"]:
            with tempfile.TemporaryDirectory() as tmpdir:
                snap = RawRuntimeSnapshot(
                    snapshot_id="SNAP_TEST_VAL",
                    pid=12345,
                    executable="/bin/app",
                    executable_build_id="abc123",
                    timestamp="2026-10-12T12:00:00Z",
                    capture_duration_us=123.4,
                    completeness=test_status,
                    observation_metadata={
                        "capture_status": test_status,
                        "identity_contract": {
                            "validity": test_status,
                            "identity_mismatch_detected": (test_status == "INVALID"),
                        },
                    },
                    provenance={"capture_status": test_status},
                )
                snap.register_buffer(0x1000, b"TEST_PAYLOAD")
                snap.save(tmpdir)

                reloaded = RawRuntimeSnapshot.load(tmpdir)
                self.assertEqual(reloaded.completeness, test_status)
                self.assertEqual(reloaded.observation_metadata["capture_status"], test_status)
                self.assertEqual(reloaded.observation_metadata["identity_contract"]["validity"], test_status)
                self.assertEqual(reloaded.read_bytes(0x1000, 12), b"TEST_PAYLOAD")

    def test_complete_identity_checkpoints_recorded_in_order(self):
        """Verifies full checkpoint progression from POST_OPEN through POST_RESUME."""
        adapter = IdentityRaceDynamicAdapter()
        handle = ProcessTargetHandle(pid=12345, adapter=adapter)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        policy = CaptureSafetyPolicy(
            target_handle=handle,
            mem_reader=lambda p, a, s: b"\x01" * s,
        )

        backend = ProcessVmCaptureBackend()
        snap = backend.capture(pid=12345, plan=plan, policy=policy, handle=handle)

        self.assertEqual(snap.completeness, "COMPLETE")
        contract = snap.observation_metadata["identity_contract"]
        checkpoint_names = [cp["name"] for cp in contract["checkpoints"]]

        expected = [
            "POST_OPEN",
            "PRE_MAPS_READ",
            "POST_MAPS_READ",
            "PRE_SUSPEND",
            "POST_SUSPEND",
            "PRE_THREAD_METADATA",
            "POST_THREAD_METADATA",
            "PRE_MEMORY_READ",
            "POST_MEMORY_READ",
            "PRE_RESUME",
            "POST_RESUME",
        ]
        self.assertEqual(checkpoint_names, expected)


if __name__ == "__main__":
    unittest.main()


