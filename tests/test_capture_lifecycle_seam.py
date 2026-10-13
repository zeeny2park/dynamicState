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
    ProcMapsResult,
    ThreadMetadataResult,
    _read_proc_maps,
    _read_thread_metadata,
)
from extractor.capture_plan import CapturePlan, CaptureMode
from extractor.raw_snapshot import RawRuntimeSnapshot
from extractor.cpp_decoder import DwarfRuntimeResolver
from extractor.state_diff import StateDiffEngine
from extractor.investigation import InvestigationManager, InvestigationFinding
from unittest.mock import patch, mock_open


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
        self.fail_maps: bool = False
        self.fail_thread_metadata: bool = False
        self.mock_maps: Optional[List[Dict[str, Any]]] = None

    def open(self, handle: ProcessTargetHandle) -> None:
        handle.initial_identity = self.get_process_state(self.pid)
        handle.pidfd_supported = self.pidfd_supported
        handle.pidfd_used = self.pidfd_used

    def close(self, handle: ProcessTargetHandle) -> None:
        self.closed = True

    def read_proc_maps(self, pid: int) -> ProcMapsResult:
        if self.fail_maps:
            return ProcMapsResult(
                [],
                status="FAILED",
                error_type="PERMISSION_DENIED",
                error="Mocked proc maps permission error",
                diagnostics=[{"code": "MAPS_PERMISSION_DENIED", "message": "Mocked", "level": "ERROR"}],
            )
        regions = self.mock_maps if self.mock_maps is not None else [
            {
                "start": 0x1000,
                "end": 0x5000,
                "size": 0x4000,
                "permissions": "rw-p",
                "offset": 0,
                "category": "anonymous",
                "pathname": "",
            }
        ]
        return ProcMapsResult(regions, status="SUCCESS_WITH_RESULTS" if regions else "SUCCESS_EMPTY")

    def read_thread_metadata(self, pid: int) -> ThreadMetadataResult:
        if self.fail_thread_metadata:
            return ThreadMetadataResult(
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
                error_type="PERMISSION_DENIED",
                error="Mocked thread metadata error",
                is_synthetic=True,
            )
        threads = []
        for i in range(self.thread_count):
            tid = pid if i == 0 else pid + i
            if i == 0:
                is_st = (self.state in ("STOPPED", "TRACING_STOP"))
            else:
                is_st = self.all_threads_stopped and (self.state in ("STOPPED", "TRACING_STOP"))
            st = "T" if is_st else "S"
            threads.append({
                "thread_id": tid,
                "name": f"mock_th_{i}",
                "state": st,
                "stop_status": "STOPPED" if is_st else "RUNNING",
                "is_synthetic": False,
                "verified_observation": True,
                "capture_participation": True,
                "registers_availability": "AVAILABLE",
                "function": "mock_func",
                "location": "mock.cpp:1",
            })
        return ThreadMetadataResult(threads, status="SUCCESS_WITH_RESULTS", is_synthetic=False)

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

    def read_proc_maps(self, pid: int) -> ProcMapsResult:
        regions = [
            {
                "start": 0x1000,
                "end": 0x5000,
                "size": 0x4000,
                "permissions": "rw-p",
                "offset": 0,
                "category": "anonymous",
                "pathname": "",
            }
        ]
        return ProcMapsResult(regions, status="SUCCESS_WITH_RESULTS")

    def read_thread_metadata(self, pid: int) -> ThreadMetadataResult:
        is_st = getattr(self, "stopped", False)
        return ThreadMetadataResult(
            [
                {
                    "thread_id": pid,
                    "name": "main",
                    "state": "T" if is_st else "R",
                    "stop_status": "STOPPED" if is_st else "RUNNING",
                    "is_synthetic": False,
                    "verified_observation": True,
                    "capture_participation": True,
                    "registers_availability": "AVAILABLE",
                    "function": "main",
                    "location": "app.cpp:10",
                }
            ],
            status="SUCCESS_WITH_RESULTS",
            is_synthetic=False,
        )

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



class TestCaptureQualityAndTrustEnforcement(unittest.TestCase):
    """Deterministic regression tests proving Capture Quality Contract & Evidence Trust Enforcement.

    Covers:
    1. _read_proc_maps explicit outcomes (SUCCESS_WITH_RESULTS, SUCCESS_EMPTY, FAILED, PARTIAL)
       and structured error types (PERMISSION_DENIED, TARGET_EXITED, MALFORMED, IO_ERROR).
    2. _read_thread_metadata explicit outcomes and synthetic unverified placeholder contract.
    3. FULL capture mode fails explicitly when map enumeration fails.
    4. TARGETED/OBJECT capture mode with explicit ranges falls back to PARTIAL quality with
       diagnostic MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED.
    5. TARGETED capture mode fails if explicit ranges cannot be read.
    6. Thread enumeration failure demotes snapshot to PARTIAL and NON_ATOMIC.
    7. DwarfRuntimeResolver refuses INVALID and FAILED snapshots, annotates PARTIAL.
    8. StateDiffEngine assigns trust classification (UNTRUSTED_INVALID, UNTRUSTED_FAILED, PARTIAL).
    9. Investigation suppresses fact findings when diff is untrusted.
    10. Investigation report includes capture_quality_assessment with honest trust level.
    """

    def test_read_proc_maps_all_outcomes(self):
        """Verify _read_proc_maps distinguishes success, empty, malformed, permission denied, and exited."""
        # 1. Target exited / file not found
        res_exited = _read_proc_maps(99999999)
        self.assertEqual(res_exited.status, "FAILED")
        self.assertEqual(res_exited.error_type, "TARGET_EXITED")
        self.assertEqual(len(res_exited), 0)
        self.assertTrue(any(d["code"] == "MAPS_TARGET_EXITED" for d in res_exited.diagnostics))

        # 2. Permission denied
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            res_perm = _read_proc_maps(12345)
            self.assertEqual(res_perm.status, "FAILED")
            self.assertEqual(res_perm.error_type, "PERMISSION_DENIED")
            self.assertEqual(len(res_perm), 0)
            self.assertTrue(any(d["code"] == "MAPS_PERMISSION_DENIED" for d in res_perm.diagnostics))

        # 3. Generic IO error
        with patch("builtins.open", side_effect=OSError("I/O failure")):
            res_io = _read_proc_maps(12345)
            self.assertEqual(res_io.status, "FAILED")
            self.assertEqual(res_io.error_type, "IO_ERROR")
            self.assertEqual(len(res_io), 0)
            self.assertTrue(any(d["code"] == "MAPS_IO_ERROR" for d in res_io.diagnostics))

        # 4. Success empty
        with patch("builtins.open", mock_open(read_data="")):
            res_empty = _read_proc_maps(12345)
            self.assertEqual(res_empty.status, "SUCCESS_EMPTY")
            self.assertIsNone(res_empty.error_type)
            self.assertEqual(len(res_empty), 0)

        # 5. All lines malformed -> FAILED MALFORMED
        malformed_data = "garbage line 1\ngarbage line 2\n"
        with patch("builtins.open", mock_open(read_data=malformed_data)):
            res_mal = _read_proc_maps(12345)
            self.assertEqual(res_mal.status, "FAILED")
            self.assertEqual(res_mal.error_type, "MALFORMED")
            self.assertEqual(len(res_mal), 0)
            self.assertTrue(any(d["code"] == "MAPS_ENTIRELY_MALFORMED" for d in res_mal.diagnostics))

        # 6. Partially malformed -> PARTIAL MALFORMED
        part_data = (
            "00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/test_app\n"
            "malformed line without ranges\n"
        )
        with patch("builtins.open", mock_open(read_data=part_data)):
            res_part = _read_proc_maps(12345)
            self.assertEqual(res_part.status, "PARTIAL")
            self.assertEqual(res_part.error_type, "MALFORMED")
            self.assertEqual(len(res_part), 1)
            self.assertTrue(any(d["code"] == "MAPS_PARTIALLY_MALFORMED" for d in res_part.diagnostics))

        # 7. Success with results
        valid_data = (
            "00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/test_app\n"
            "7fff5be07000-7fff5be28000 rw-p 00000000 00:00 0 [stack]\n"
        )
        with patch("builtins.open", mock_open(read_data=valid_data)):
            res_valid = _read_proc_maps(12345)
            self.assertEqual(res_valid.status, "SUCCESS_WITH_RESULTS")
            self.assertIsNone(res_valid.error_type)
            self.assertEqual(len(res_valid), 2)
            self.assertEqual(res_valid[0]["category"], "binary")
            self.assertEqual(res_valid[1]["category"], "stack")

    def test_read_thread_metadata_all_outcomes(self):
        """Verify _read_thread_metadata outcome modeling and synthetic placeholder marking."""
        # 1. Non-existent PID / task directory
        res_exited = _read_thread_metadata(99999999)
        self.assertEqual(res_exited.status, "FAILED")
        self.assertEqual(res_exited.error_type, "TARGET_EXITED")
        self.assertTrue(res_exited.is_synthetic)
        self.assertEqual(len(res_exited), 1)
        synthetic_th = res_exited[0]
        self.assertTrue(synthetic_th["is_synthetic"])
        self.assertEqual(synthetic_th["state"], "UNKNOWN")
        self.assertEqual(synthetic_th["stop_status"], "UNKNOWN")
        self.assertFalse(synthetic_th["verified_observation"])
        self.assertFalse(synthetic_th["capture_participation"])

        # 2. Permission denied on task directory
        with patch("os.path.exists", return_value=True), patch("os.listdir", side_effect=PermissionError("Denied")):
            res_perm = _read_thread_metadata(12345)
            self.assertEqual(res_perm.status, "FAILED")
            self.assertEqual(res_perm.error_type, "PERMISSION_DENIED")
            self.assertTrue(res_perm.is_synthetic)
            self.assertEqual(len(res_perm), 1)
            self.assertFalse(res_perm[0]["verified_observation"])

    def test_full_mode_fails_on_map_enumeration_error(self):
        """FULL capture mode must fail when map enumeration fails, never returning COMPLETE."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter.fail_maps = True
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        plan = CapturePlan(mode=CaptureMode.FULL.value)
        policy = CaptureSafetyPolicy(target_handle=handle)
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy, handle=handle)
        self.assertEqual(snap.completeness, "FAILED")
        self.assertEqual(snap.observation_metadata["capture_status"], "FAILED")
        diag_codes = [d["code"] for d in snap.observation_metadata.get("diagnostics", [])]
        self.assertIn("MAP_ENUMERATION_FAILED", diag_codes)
        self.assertEqual(snap.raw_memory["total_bytes"], 0)

    def test_targeted_mode_with_explicit_ranges_when_maps_fail(self):
        """TARGETED mode with explicit ranges proceeds if maps fail, but is capped at PARTIAL."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter.fail_maps = True
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1200)])
        policy = CaptureSafetyPolicy(
            target_handle=handle,
            mem_reader=lambda p, a, s: b"X" * s,
        )
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy, handle=handle)
        self.assertEqual(snap.completeness, "PARTIAL")
        self.assertEqual(snap.observation_metadata["capture_status"], "PARTIAL")
        diag_codes = [d["code"] for d in snap.observation_metadata.get("diagnostics", [])]
        self.assertIn("MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED", diag_codes)
        self.assertEqual(snap.raw_memory["total_bytes"], 512)

    def test_targeted_mode_fails_when_explicit_ranges_cannot_be_read(self):
        """TARGETED mode with failed maps fails completely if reading explicit ranges fails."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter.fail_maps = True
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1200)])
        policy = CaptureSafetyPolicy(
            target_handle=handle,
            mem_reader=lambda p, a, s: None,  # Read fails
        )
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy, handle=handle)
        self.assertEqual(snap.completeness, "FAILED")
        self.assertEqual(snap.observation_metadata["capture_status"], "FAILED")
        self.assertEqual(snap.raw_memory["total_bytes"], 0)

    def test_thread_enumeration_failure_demotes_to_partial_and_non_atomic(self):
        """Thread enumeration failure prevents COMPLETE status and atomic consistency."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter.fail_thread_metadata = True
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1200)])
        policy = CaptureSafetyPolicy(
            target_handle=handle,
            mem_reader=lambda p, a, s: b"Y" * s,
        )
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy, handle=handle)
        self.assertEqual(snap.completeness, "PARTIAL")
        self.assertEqual(snap.observation_metadata["consistency_classification"], "NON_ATOMIC")
        self.assertFalse(snap.observation_metadata["all_threads_stopped"])
        diag_codes = [d["code"] for d in snap.observation_metadata.get("diagnostics", [])]
        self.assertIn("THREAD_ENUMERATION_FAILED", diag_codes)

    def test_dwarf_resolver_rejects_invalid_and_failed_snapshots(self):
        """DwarfRuntimeResolver refuses to decode INVALID and FAILED snapshots, annotates PARTIAL."""
        # 1. INVALID snapshot
        snap_invalid = RawRuntimeSnapshot(
            snapshot_id="SNAP_INV",
            pid=123,
            executable="/bin/app",
            executable_build_id="b1",
            timestamp="2026-10-12T00:00:00Z",
            capture_duration_us=100.0,
            completeness="INVALID",
            observation_metadata={"capture_status": "INVALID"},
        )
        resolver_inv = DwarfRuntimeResolver(snapshot=snap_invalid, debug_image_path="/bin/app")
        res_inv = resolver_inv.resolve()
        self.assertEqual(res_inv.status, "INVALID_CAPTURE")
        self.assertEqual(res_inv.diagnostics[0]["code"], "INVALID_CAPTURE_IDENTITY")
        self.assertEqual(len(res_inv.objects), 0)

        # 2. FAILED snapshot
        snap_failed = RawRuntimeSnapshot(
            snapshot_id="SNAP_FAIL",
            pid=123,
            executable="/bin/app",
            executable_build_id="b1",
            timestamp="2026-10-12T00:00:00Z",
            capture_duration_us=100.0,
            completeness="FAILED",
            observation_metadata={"capture_status": "FAILED"},
        )
        resolver_fail = DwarfRuntimeResolver(snapshot=snap_failed, debug_image_path="/bin/app")
        res_fail = resolver_fail.resolve()
        self.assertEqual(res_fail.status, "FAILED_CAPTURE")
        self.assertEqual(res_fail.diagnostics[0]["code"], "FAILED_CAPTURE")
        self.assertEqual(len(res_fail.objects), 0)

        # 3. PARTIAL snapshot
        snap_partial = RawRuntimeSnapshot(
            snapshot_id="SNAP_PART",
            pid=123,
            executable="/bin/app",
            executable_build_id="b1",
            timestamp="2026-10-12T00:00:00Z",
            capture_duration_us=100.0,
            completeness="PARTIAL",
            observation_metadata={"capture_status": "PARTIAL"},
        )
        resolver_part = DwarfRuntimeResolver(snapshot=snap_partial, debug_image_path="/bin/app")
        res_part = resolver_part.resolve()
        self.assertTrue(any(d.get("code") == "PARTIAL_CAPTURE_DECODED" for d in res_part.diagnostics))

    def test_state_diff_trust_classification(self):
        """StateDiffEngine assigns proper trust classification when diffing untrusted captures."""
        diff_engine = StateDiffEngine()

        snap_complete = {
            "completeness": "COMPLETE",
            "objects": [{
                "object_id": "obj1",
                "type": "Config",
                "address": 0x1000,
                "fields": [{"name": "threshold", "value": 10, "type": "int"}],
            }],
        }
        snap_invalid = {
            "completeness": "INVALID",
            "objects": [{
                "object_id": "obj1",
                "type": "Config",
                "address": 0x1000,
                "fields": [{"name": "threshold", "value": 20, "type": "int"}],
            }],
        }

        # COMPLETE vs INVALID
        diff_inv = diff_engine.diff(snap_complete, snap_invalid)
        self.assertEqual(diff_inv.trust_classification, "UNTRUSTED_INVALID_CAPTURE")
        self.assertTrue(len(diff_inv.changes) > 0)
        for ch in diff_inv.changes:
            self.assertEqual(ch.get("trust"), "UNTRUSTED")
            self.assertFalse(ch.get("verified", False))

        # COMPLETE vs FAILED
        snap_failed = {
            "completeness": "FAILED",
            "objects": [],
        }
        diff_fail = diff_engine.diff(snap_complete, snap_failed)
        self.assertEqual(diff_fail.trust_classification, "UNTRUSTED_FAILED_CAPTURE")

        # COMPLETE vs PARTIAL
        snap_partial = {
            "completeness": "PARTIAL",
            "objects": [{
                "object_id": "obj1",
                "type": "Config",
                "address": 0x1000,
                "fields": [{"name": "threshold", "value": 20, "type": "int"}],
            }],
        }
        diff_part = diff_engine.diff(snap_complete, snap_partial)
        self.assertEqual(diff_part.trust_classification, "PARTIALLY_TRUSTED")
        for ch in diff_part.changes:
            self.assertEqual(ch.get("trust"), "PARTIAL")

    def test_investigation_suppresses_facts_from_untrusted_diffs(self):
        """compare_observations suppresses category='fact' findings when diff is untrusted."""
        diff_engine = StateDiffEngine()

        snap_complete = RawRuntimeSnapshot(
            snapshot_id="S_COMP",
            pid=100,
            executable="/bin/app",
            executable_build_id="b1",
            timestamp="2026-10-12T00:00:00Z",
            capture_duration_us=100.0,
            completeness="COMPLETE",
        )
        snap_complete.register_buffer(0x1000, b"VAL_A")

        snap_invalid = RawRuntimeSnapshot(
            snapshot_id="S_INV",
            pid=100,
            executable="/bin/app",
            executable_build_id="b1",
            timestamp="2026-10-12T00:00:01Z",
            capture_duration_us=100.0,
            completeness="INVALID",
        )
        snap_invalid.register_buffer(0x1000, b"VAL_B")

        with tempfile.TemporaryDirectory() as tmpdir:
            dir_a = os.path.join(tmpdir, "snap_a")
            dir_b = os.path.join(tmpdir, "snap_b")
            snap_complete.save(dir_a)
            snap_invalid.save(dir_b)

            mgr = InvestigationManager(corpus_dir=tmpdir)
            inv = mgr.start_investigation(goal="test untrusted diff", memory_snapshot_path=dir_a)
            inv_id = inv["investigation_id"]
            mgr.compare_observations(inv_id, dir_a, dir_b)

            session = mgr.sessions[inv_id]
            # Must NOT generate verified facts
            fact_findings = [f for f in session.findings if f.category == "fact"]
            self.assertEqual(len(fact_findings), 0)

            # Must generate warning untrusted finding
            untrusted_findings = [f for f in session.findings if "Untrusted Snapshot Comparison" in f.title]
            self.assertTrue(len(untrusted_findings) > 0)
            self.assertEqual(untrusted_findings[0].status, "UNTRUSTED")

    def test_investigation_pipeline_assessment_honors_capture_quality(self):
        """Investigation pipeline execution marks stage FAILED and report UNTRUSTED for invalid captures."""
        snap_inv = RawRuntimeSnapshot(
            snapshot_id="SNAP_INV_PIPE",
            pid=100,
            executable="/bin/app",
            executable_build_id="b1",
            timestamp="2026-10-12T00:00:00Z",
            capture_duration_us=100.0,
            completeness="INVALID",
            observation_metadata={"capture_status": "INVALID"},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            snap_dir = os.path.join(tmpdir, "snap_inv")
            snap_inv.save(snap_dir)

            mgr = InvestigationManager(corpus_dir=tmpdir)
            inv = mgr.start_investigation(goal="test invalid snap pipeline", memory_snapshot_path=snap_dir)
            inv_id = inv["investigation_id"]
            report = mgr.generate_report(inv_id)

            # Capture quality stage must be FAILED
            quality_stage = report["stages"].get("capture_quality", {})
            self.assertEqual(quality_stage.get("status"), "FAILED")

            # Report assessment must be UNTRUSTED
            assessment = report.get("capture_quality_assessment", {})
            self.assertEqual(assessment.get("status"), "FAILED")
            self.assertEqual(assessment.get("trust_level"), "UNTRUSTED")


    def test_raw_snapshot_from_dict_partial_map_and_thread_never_retains_complete(self):
        """Specifically test that map_enumeration.status == PARTIAL or thread_enumeration.status == PARTIAL degrades completeness."""
        # 1. PARTIAL map enumeration
        data_map_partial = {
            "snapshot_id": "S_MAP_PARTIAL",
            "completeness": "COMPLETE",
            "memory_regions": [{"region_id": "R1", "status": "COMPLETE", "captured_bytes": 100}],
            "provenance": {
                "capture_status": "COMPLETED",
                "bytes_requested": 100,
                "bytes_read": 100,
                "map_enumeration": {"status": "PARTIAL", "error_type": "MALFORMED"},
                "thread_enumeration": {"status": "SUCCESS_WITH_RESULTS", "is_synthetic": False},
            },
        }
        snap_map_p = RawRuntimeSnapshot.from_dict(data_map_partial)
        self.assertEqual(snap_map_p.completeness, "PARTIAL", "PARTIAL map enumeration MUST downgrade completeness from COMPLETE to PARTIAL")

        # 2. PARTIAL thread enumeration
        data_th_partial = {
            "snapshot_id": "S_TH_PARTIAL",
            "completeness": "COMPLETE",
            "memory_regions": [{"region_id": "R1", "status": "COMPLETE", "captured_bytes": 100}],
            "provenance": {
                "capture_status": "COMPLETED",
                "bytes_requested": 100,
                "bytes_read": 100,
                "map_enumeration": {"status": "SUCCESS_WITH_RESULTS"},
                "thread_enumeration": {"status": "PARTIAL", "error_type": "IO_ERROR"},
            },
        }
        snap_th_p = RawRuntimeSnapshot.from_dict(data_th_partial)
        self.assertEqual(snap_th_p.completeness, "PARTIAL", "PARTIAL thread enumeration MUST downgrade completeness from COMPLETE to PARTIAL")

        # 3. Both PARTIAL
        data_both_partial = {
            "snapshot_id": "S_BOTH_PARTIAL",
            "completeness": "COMPLETE",
            "memory_regions": [{"region_id": "R1", "status": "COMPLETE", "captured_bytes": 100}],
            "provenance": {
                "capture_status": "COMPLETED",
                "bytes_requested": 100,
                "bytes_read": 100,
                "map_enumeration": {"status": "PARTIAL"},
                "thread_enumeration": {"status": "PARTIAL"},
            },
        }
        snap_both_p = RawRuntimeSnapshot.from_dict(data_both_partial)
        self.assertEqual(snap_both_p.completeness, "PARTIAL")

    def test_raw_snapshot_from_dict_byte_shortfall_degrades_quality(self):
        """Byte shortfall (bytes_read < bytes_requested) or zero bytes degrades completeness."""
        # Shortfall: 200 requested, 100 read -> PARTIAL
        data_short = {
            "snapshot_id": "S_SHORT",
            "completeness": "COMPLETE",
            "memory_regions": [{"region_id": "R1", "status": "COMPLETE", "captured_bytes": 100}],
            "provenance": {
                "capture_status": "COMPLETED",
                "bytes_requested": 200,
                "bytes_read": 100,
                "map_enumeration": {"status": "SUCCESS_WITH_RESULTS"},
                "thread_enumeration": {"status": "SUCCESS_WITH_RESULTS"},
            },
        }
        snap_short = RawRuntimeSnapshot.from_dict(data_short)
        self.assertEqual(snap_short.completeness, "PARTIAL")

        # Zero read: 200 requested, 0 read -> FAILED
        data_zero = {
            "snapshot_id": "S_ZERO",
            "completeness": "COMPLETE",
            "memory_regions": [],
            "provenance": {
                "capture_status": "COMPLETED",
                "bytes_requested": 200,
                "bytes_read": 0,
                "map_enumeration": {"status": "SUCCESS_WITH_RESULTS"},
                "thread_enumeration": {"status": "SUCCESS_WITH_RESULTS"},
            },
        }
        snap_zero = RawRuntimeSnapshot.from_dict(data_zero)
        self.assertEqual(snap_zero.completeness, "FAILED")

    def test_raw_snapshot_legacy_snapshot_policy(self):
        """Legacy snapshots without provenance are classified conservatively as PARTIAL under migration policy unless verifiable guarantees exist."""
        # 1. Legacy snapshot with regions but no verified lifecycle guarantees degrades conservatively to PARTIAL
        data_legacy_unverified = {
            "snapshot_id": "S_LEGACY_UNVERIFIED",
            "completeness": "COMPLETE",
            "memory_regions": [{"region_id": "R1", "status": "COMPLETE", "captured_bytes": 64}],
            "captured_ranges": [["0x1000", "0x1040"]],
        }
        snap_l_u = RawRuntimeSnapshot.from_dict(data_legacy_unverified)
        self.assertEqual(snap_l_u.completeness, "PARTIAL")
        self.assertTrue(snap_l_u.provenance.get("is_legacy"))
        self.assertEqual(snap_l_u.provenance.get("legacy_migration_policy"), "CONSERVATIVE_UNVERIFIABLE_TO_PARTIAL")
        self.assertTrue(any(d["code"] == "LEGACY_SNAPSHOT_UNVERIFIABLE" for d in snap_l_u.provenance.get("diagnostics", [])))

        # 2. Legacy snapshot with verified lifecycle guarantees preserves COMPLETE
        data_legacy_verified = {
            "snapshot_id": "S_LEGACY_VERIFIED",
            "completeness": "COMPLETE",
            "memory_regions": [{"region_id": "R1", "status": "COMPLETE", "captured_bytes": 64}],
            "captured_ranges": [["0x1000", "0x1040"]],
            "observation_metadata": {
                "lifecycle_guarantees": {
                    "process_stop_confirmed": True,
                    "all_threads_stopped": True,
                }
            }
        }
        snap_l_v = RawRuntimeSnapshot.from_dict(data_legacy_verified)
        self.assertEqual(snap_l_v.completeness, "COMPLETE")
        self.assertTrue(snap_l_v.provenance.get("is_legacy"))

        # 3. Legacy snapshot with NO memory regions and NO ranges cannot claim COMPLETE -> PARTIAL
        data_legacy_empty = {
            "snapshot_id": "S_LEGACY_EMPTY",
            "completeness": "COMPLETE",
            "memory_regions": [],
            "captured_ranges": [],
        }
        snap_l_e = RawRuntimeSnapshot.from_dict(data_legacy_empty)
        self.assertEqual(snap_l_e.completeness, "PARTIAL")

        # 4. Monotonicity: legacy snapshot declared FAILED or INVALID never upgraded to COMPLETE
        for bad_status in ("FAILED", "INVALID", "PARTIAL"):
            data_bad = {
                "snapshot_id": f"S_LEGACY_{bad_status}",
                "completeness": bad_status,
                "memory_regions": [{"region_id": "R1", "status": "COMPLETE", "captured_bytes": 64}],
            }
            snap_bad = RawRuntimeSnapshot.from_dict(data_bad)
            self.assertEqual(snap_bad.completeness, bad_status, f"Legacy status {bad_status} must never be upgraded")

    def test_malformed_and_unknown_completeness_handling(self):
        """Malformed or unknown quality values must never silently upgrade to COMPLETE."""
        for malformed_val in ("UNKNOWN", "CORRUPTED", "", "CUSTOM_INVALID_STATE", None):
            data = {
                "snapshot_id": "S_MALFORMED",
                "completeness": malformed_val,
                "memory_regions": [{"region_id": "R1", "status": "COMPLETE", "captured_bytes": 64}],
                "captured_ranges": [["0x1000", "0x1040"]],
            }
            snap = RawRuntimeSnapshot.from_dict(data)
            self.assertEqual(snap.completeness, "PARTIAL")
            self.assertTrue(any(d["code"] == "MALFORMED_QUALITY_VALUE" for d in snap.provenance.get("diagnostics", [])))

    def test_byte_accounting_invariant_mismatch(self):
        """Byte accounting mismatch between requested and read+omitted+failed must degrade to PARTIAL."""
        data_mismatch = {
            "snapshot_id": "S_BYTE_MISMATCH",
            "completeness": "COMPLETE",
            "memory_regions": [{"region_id": "R1", "status": "COMPLETE", "captured_bytes": 64}],
            "provenance": {
                "bytes_requested": 128,
                "bytes_read": 64,
                "bytes_omitted": 0,
                "bytes_failed": 0,
                "bytes_unread": 0,
                "identity_contract": {"validity": "COMPLETE"},
            },
            "observation_metadata": {
                "lifecycle_guarantees": {"process_stop_confirmed": True, "all_threads_stopped": True}
            }
        }
        snap = RawRuntimeSnapshot.from_dict(data_mismatch)
        self.assertEqual(snap.completeness, "PARTIAL")
        self.assertTrue(any(d["code"] == "BYTE_ACCOUNTING_INVARIANT_VIOLATED" for d in snap.provenance.get("diagnostics", [])))

    def test_stop_budget_exceeded_degrades_to_partial(self):
        """When total suspension time exceeds max_stop_time_ms budget, capture degrades to PARTIAL."""
        import time as _t
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)

        def slow_mem_reader(p, a, s):
            _t.sleep(0.005)  # 5ms duration
            return b"A" * s

        # Budget of 2ms, but memory reading takes ~5ms
        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=slow_mem_reader, max_stop_time_ms=2.0)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap = backend.capture(adapter.pid, plan=plan, policy=policy)
        self.assertEqual(snap.completeness, "PARTIAL")
        self.assertTrue(snap.provenance.get("stop_budget_exceeded"))
        self.assertTrue(any(d["code"] == "STOP_BUDGET_EXCEEDED" for d in snap.provenance.get("diagnostics", [])))

    def test_thread_enumeration_outcomes_and_synthetic_isolation(self):
        """Thread enumeration outcomes: SUCCESS_EMPTY or FAILED marks threads as synthetic/unverified."""
        # 1. FAILED thread enumeration in live capture produces PARTIAL capture
        adapter_fail = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter_fail.read_thread_metadata = lambda pid: ThreadMetadataResult(
            [{
                "thread_id": adapter_fail.pid,
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
            error_type="TARGET_EXITED",
            error="Task directory missing",
            is_synthetic=True,
        )
        handle_fail = ProcessTargetHandle(pid=adapter_fail.pid, adapter=adapter_fail)
        policy_fail = CaptureSafetyPolicy(target_handle=handle_fail, mem_reader=lambda p, a, s: b"X" * s)
        plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x1100)])
        backend = ProcessVmCaptureBackend()

        snap_fail = backend.capture(adapter_fail.pid, plan=plan, policy=policy_fail)
        self.assertEqual(snap_fail.completeness, "PARTIAL")
        self.assertEqual(snap_fail.provenance["thread_enumeration"]["status"], "FAILED")
        self.assertTrue(snap_fail.provenance["thread_enumeration"]["is_synthetic"])

        # 2. SUCCESS_EMPTY thread enumeration produces PARTIAL capture
        adapter_empty = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter_empty.read_thread_metadata = lambda pid: ThreadMetadataResult(
            [],
            status="SUCCESS_EMPTY",
            error_type=None,
            error=None,
            is_synthetic=False,
        )
        handle_empty = ProcessTargetHandle(pid=adapter_empty.pid, adapter=adapter_empty)
        policy_empty = CaptureSafetyPolicy(target_handle=handle_empty, mem_reader=lambda p, a, s: b"Y" * s)

        snap_empty = backend.capture(adapter_empty.pid, plan=plan, policy=policy_empty)
        self.assertEqual(snap_empty.completeness, "PARTIAL")
        self.assertEqual(snap_empty.provenance["thread_enumeration"]["status"], "SUCCESS_EMPTY")

    def test_map_enumeration_full_mode_empty_or_failed_is_fatal(self):
        """In FULL mode, map enumeration failure or empty result is fatal (completeness FAILED)."""
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        adapter.read_proc_maps = lambda pid: ProcMapsResult(
            [],
            status="SUCCESS_EMPTY",
            error_type=None,
            error=None,
        )
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)
        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=lambda p, a, s: b"Z" * s)
        plan_full = CapturePlan(mode=CaptureMode.FULL.value)
        backend = ProcessVmCaptureBackend()

        snap_full = backend.capture(adapter.pid, plan=plan_full, policy=policy)
        self.assertEqual(snap_full.completeness, "FAILED")
        self.assertEqual(snap_full.provenance["capture_status"], "FAILED")


if __name__ == "__main__":
    unittest.main()


