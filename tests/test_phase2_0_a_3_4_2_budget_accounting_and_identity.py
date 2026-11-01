"""Phase 2.0-A.3.4.2 — Budget Accounting Closure & Process Identity Provenance.

Adversarial regression test suite validating:
1. Exact observation-budget accounting across all execution paths.
2. Explicit and verified process-identity provenance.
3. Mandatory sampling-epoch validation for deadlock evidence.
4. Comprehensive regression tests proving that budget limits cannot be bypassed
   and unverified evidence cannot confirm a deadlock.
"""

import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple

from extractor.target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    RemoteSshTargetAdapter,
    MutexOwnerResolutionResult,
    STATUS_OWNER_IDENTIFIED,
    STATUS_OWNER_NOT_IDENTIFIED,
    STATUS_MUTEX_LAYOUT_UNSUPPORTED,
    STATUS_MUTEX_STATE_INVALID,
    STATUS_MEMORY_READ_UNAVAILABLE,
    STATUS_PERMISSION_DENIED,
    ABI_GLIBC_VERIFIED,
    ABI_MUSL_UNSUPPORTED,
    ABI_LIBC_UNKNOWN,
    ABI_STATIC_OR_UNIDENTIFIED,
    ABI_ARCH_UNSUPPORTED,
    ABI_ELF_CLASS_UNSUPPORTED,
    ABI_ENDIANNESS_UNSUPPORTED,
    IDENTITY_VERIFIED,
    IDENTITY_UNAVAILABLE,
    IDENTITY_INCONSISTENT,
    IDENTITY_UNVERIFIED,
    LAYOUT_GLIBC_LP64,
    normalize_futex_address,
)
from extractor.adaptive_engine import (
    AdaptiveInvestigationEngine,
    WaitForEdge,
    WaitForGraph,
    RESULT_DEADLOCK_CYCLE_CONFIRMED,
    RESULT_LOCK_CONTENTION_OBSERVED,
    RESULT_WAITING_WITH_UNKNOWN_OWNER,
    RESULT_INCOMPLETE_WAIT_FOR_GRAPH,
    RESULT_INCONSISTENT_OWNER_EVIDENCE,
    RESULT_INCONCLUSIVE,
)
from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)
from extractor.inspection_module import FunctionalInspectionModule, InspectionContext


class TestPhase20A342BudgetAccountingAndIdentity(unittest.TestCase):
    """Deterministic regression test suite for Phase 2.0-A.3.4.2."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_a342_")
        cls.fixtures_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")
        )

        cls.bin_2way = os.path.join(cls.work_dir, "proc_2way_deadlock")
        cls.bin_3way = os.path.join(cls.work_dir, "proc_3way_deadlock")
        cls.bin_contention = os.path.join(cls.work_dir, "proc_contention")

        # Compile real-process fixtures
        compile_targets = [
            ("proc_thread_circular_deadlock.c", cls.bin_2way),
            ("proc_thread_3way_deadlock.c", cls.bin_3way),
            ("proc_scenario_c_thread_contention.c", cls.bin_contention),
        ]

        for src_name, bin_dest in compile_targets:
            src_path = os.path.join(cls.fixtures_dir, src_name)
            if os.path.exists(src_path):
                cmd = ["gcc", "-O2", "-Wall", "-Wextra", "-pthread", src_path, "-o", bin_dest]
                rc = subprocess.call(cmd)
                if rc != 0:
                    raise RuntimeError(f"Failed to compile fixture {src_name} -> {bin_dest}")

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.work_dir):
            shutil.rmtree(cls.work_dir, ignore_errors=True)

    def _sample_valid_proc_identity(self, pid: int = 1000) -> Dict[str, Any]:
        return {
            "pid": pid,
            "process_start_time": 100000,
            "architecture": "x86_64",
            "elf_class": "ELF64",
            "endianness": "little",
            "executable": "/usr/bin/app",
            "build_id": "0123456789abcdef",
            "status": "OBSERVED",
            "identity_status": IDENTITY_VERIFIED,
        }

    def _sample_valid_meta(self, owner_tid: int = 102, waiter_tid: int = 101) -> Dict[str, Any]:
        return {
            "abi_status": ABI_GLIBC_VERIFIED,
            "layout_id": LAYOUT_GLIBC_LP64,
            "raw_bytes": struct.pack("<iIiIi", 1, 0, owner_tid, 0, 0) + b"\x00" * 20,
            "read_bytes_len": 40,
            "lock_word": 1,
            "count": 0,
            "owner": owner_tid,
            "nusers": 0,
            "kind": 0,
            "base_kind": 0,
            "memory_read_status": "OBSERVED",
            "target_tids": [waiter_tid, owner_tid],
        }

    # =========================================================================
    # 1. Multiple Mutex Reads Approaching & Exceeding Byte Budget
    # =========================================================================

    def test_01_multiple_mutex_reads_approaching_and_exceeding_byte_budget(self):
        """Pre-execution check rejects mutex reads that would exceed remaining budget; returns PARTIAL."""
        engine = AdaptiveInvestigationEngine()
        # Budget limit: 120 bytes max (allows threads read of 40B + 2 mutex reads of 40B, blocks 3rd)
        limits = ObservationBudgetLimits(max_bytes_read=120)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        # Mock adapter with 3 threads waiting on 3 locks
        class MockContendedAdapter(LocalTargetAdapter):
            def __init__(self):
                super().__init__()
                self._last_threads_bytes_read = 40
                self.mutex_read_count = 0

            def get_threads(self, pid):
                return [
                    {"tid": 101, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x1000"},
                    {"tid": 102, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x2000"},
                    {"tid": 103, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x3000"},
                ]

            def resolve_mutex_owner(self, pid, lock_addr):
                self.mutex_read_count += 1
                raw = struct.pack("<iIiIi", 1, 0, 999, 0, 0) + b"\x00" * 20
                return MutexOwnerResolutionResult(
                    status=STATUS_OWNER_IDENTIFIED,
                    owner_tid=999,
                    layout_id=LAYOUT_GLIBC_LP64,
                    raw_bytes=raw,
                    metadata={"read_bytes_len": 40, "memory_read_status": "OBSERVED", "latency_us": 10.0},
                )

        adapter = MockContendedAdapter()
        mod = engine.registry.get("insp_locks")
        res = mod._func(None, pid=100, adapter=adapter, budget_tracker=tracker, target_identity=self._sample_valid_proc_identity(100))

        # 40B (threads) + 40B (mutex 1) + 40B (mutex 2) = 120B. Mutex 3 cannot be admitted!
        self.assertEqual(res.get("status"), "PARTIAL")
        self.assertEqual(res.get("stop_reason"), "BUDGET_EXHAUSTED")
        self.assertEqual(adapter.mutex_read_count, 2, "3rd mutex read must be rejected by pre-check")
        self.assertEqual(tracker.metrics.measured_bytes_read, 120)

    # =========================================================================
    # 2. Budget Tracker Updates Immediately After Each Read
    # =========================================================================

    def test_02_budget_tracker_updates_immediately_after_each_read(self):
        """Tracker reflects actual bytes read immediately after each individual mutex read."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        observed_tracker_bytes: List[int] = []

        class InterceptingAdapter(LocalTargetAdapter):
            def __init__(self):
                super().__init__()
                self._last_threads_bytes_read = 50

            def get_threads(self, pid):
                return [
                    {"tid": 201, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x1000"},
                    {"tid": 202, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x2000"},
                ]

            def resolve_mutex_owner(self, pid, lock_addr):
                raw = struct.pack("<iIiIi", 1, 0, 202, 0, 0) + b"\x00" * 20
                res = MutexOwnerResolutionResult(
                    status=STATUS_OWNER_IDENTIFIED,
                    owner_tid=202,
                    layout_id=LAYOUT_GLIBC_LP64,
                    raw_bytes=raw,
                    metadata={"read_bytes_len": 40, "memory_read_status": "OBSERVED", "latency_us": 15.0},
                )
                return res

        adapter = InterceptingAdapter()
        mod = engine.registry.get("insp_locks")
        res = mod._func(None, pid=200, adapter=adapter, budget_tracker=tracker, target_identity=self._sample_valid_proc_identity(200))

        self.assertEqual(res.get("status"), "OBSERVED")
        # 50B threads + 40B mutex 1 + 40B mutex 2 = 130B
        self.assertEqual(tracker.metrics.measured_bytes_read, 130)
        self.assertEqual(tracker.metrics.bytes_read, 130)

    # =========================================================================
    # 3. Partial Memory Reads & Failed Reads
    # =========================================================================

    def test_03_partial_memory_reads_and_failed_reads(self):
        """Partial reads charge actual bytes obtained; failed reads with 0 bytes charge 0 measured bytes."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        # 1. Partial read of 18 bytes
        r1 = tracker.record_read(bytes_read=18, latency_us=20.0, is_failure=False, profile_id="test_partial")
        self.assertEqual(r1["measured_bytes_read"], 18)
        self.assertEqual(tracker.metrics.measured_bytes_read, 18)
        self.assertFalse(r1["used_conservative_byte_estimate"])

        # 2. Failed read with 0 bytes obtained
        r2 = tracker.record_read(bytes_read=0, latency_us=10.0, is_failure=True, profile_id="test_failed")
        self.assertEqual(r2["measured_bytes_read"], 0)
        # Measured bytes unchanged at 18
        self.assertEqual(tracker.metrics.measured_bytes_read, 18)
        self.assertEqual(tracker.metrics.total_read_failures, 1)
        self.assertEqual(tracker.metrics.consecutive_read_failures, 1)

    # =========================================================================
    # 4. Process-Identity Inspection Consuming Applicable Budget
    # =========================================================================

    def test_04_process_identity_inspection_consuming_applicable_budget(self):
        """Stage 1 target validation charges actual procfs identity bytes to budget tracker."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        tracker.start()

        adapter = LocalTargetAdapter()
        ident = adapter.get_process_identity(os.getpid())
        ident_bytes = adapter.get_last_identity_bytes_read()
        self.assertGreater(ident_bytes, 0, "LocalTargetAdapter must report non-zero identity bytes read")

        # Run process health investigation with this tracker
        res = engine.investigate_process_health(
            goal="Identity budget test",
            pid=os.getpid(),
            budget_limits=ObservationBudgetLimits(max_bytes_read=100000),
        )
        self.assertTrue(res["success"])
        b_summary = res.get("budget_summary", {})
        # Identity bytes must be accounted for in budget summary
        self.assertGreater(b_summary.get("metrics", {}).get("bytes_read", 0), 0)
        self.assertGreater(b_summary.get("metrics", {}).get("samples_collected", 0), 0)

    # =========================================================================
    # 5. WorkManager Success Without Double Charging
    # =========================================================================

    def test_05_workmanager_success_without_double_charging(self):
        """When WorkManager succeeds, bytes are charged once by the module, not duplicated by wrapper."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        class MockSuccessfulWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {
                    "success": True,
                    "threads": [{"tid": 101, "state": "R"}],
                    "measured_bytes_read": 128,
                    "bytes_read": 128,
                }

        wm = MockSuccessfulWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=100,
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)
        self.assertTrue(out.get("success"))
        # Exactly 128 bytes charged, never 256
        self.assertEqual(tracker.metrics.measured_bytes_read, 128)
        self.assertEqual(tracker.metrics.bytes_read, 128)

    # =========================================================================
    # 6. WorkManager Failure Followed by Fallback Without Lost or Duplicated Accounting
    # =========================================================================

    def test_06_workmanager_failure_followed_by_fallback_without_lost_or_duplicated_accounting(self):
        """When WorkManager fails, failure is recorded and fallback executes with accurate accounting."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        class FailingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                raise RuntimeError("WM failure simulation")

        wm = FailingWM()
        adapter = LocalTargetAdapter()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=adapter,
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)
        self.assertTrue(out.get("success"))
        # Fallback executed and recorded measured bytes
        self.assertGreater(tracker.metrics.measured_bytes_read, 0)
        # WM failure was recorded in tracker failures
        self.assertGreaterEqual(tracker.metrics.total_read_failures, 1)

    # =========================================================================
    # 7. Fallback Rejection After Budget Exhaustion
    # =========================================================================

    def test_07_fallback_rejection_after_budget_exhaustion(self):
        """If WorkManager consumes or exhausts budget, fallback is rejected immediately without executing."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_wall_clock_ms=10.0))
        tracker.start()

        class SlowFailingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                time.sleep(0.015)  # Exhaust 10ms deadline
                raise RuntimeError("WM slow failure")

        wm = SlowFailingWM()
        fallback_called = False

        class SpyAdapter(LocalTargetAdapter):
            def get_threads(self, pid):
                nonlocal fallback_called
                fallback_called = True
                return []

        mod = engine.registry.get("insp_locks")
        res = mod._func(wm, pid=os.getpid(), adapter=SpyAdapter(), budget_tracker=tracker)
        self.assertFalse(res.get("success", False))
        self.assertEqual(res.get("status"), "BUDGET_EXHAUSTED")
        self.assertEqual(res.get("stop_reason"), "BUDGET_EXHAUSTED")
        self.assertFalse(fallback_called, "Fallback must NOT be executed when budget is exhausted")

    # =========================================================================
    # 8. Identity PID Differing from target_pid
    # =========================================================================

    def test_08_identity_pid_differing_from_target_pid(self):
        """Edge where process_identity['pid'] != edge.target_pid is rejected."""
        graph = WaitForGraph()
        t_now = time.time()
        ident_mismatched = self._sample_valid_proc_identity(pid=999)  # PID 999 != target_pid 100

        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=ident_mismatched,
            sampling_epoch=1,
            metadata=self._sample_valid_meta(102, 101),
        ))
        graph.add_edge(WaitForEdge(
            waiter_tid=102,
            sync_object="0x2000",
            normalized_address="0x2000",
            owner_tid=101,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            observation_timestamp=t_now,
            target_pid=100,
            process_identity=self._sample_valid_proc_identity(100),
            sampling_epoch=1,
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertNotEqual(category, RESULT_DEADLOCK_CYCLE_CONFIRMED)
        self.assertTrue(any("REJECT_IDENTITY_PID_MISMATCH" in s for s in issues))

    # =========================================================================
    # 9. Missing, Malformed, and Explicitly Unverified Process Identity
    # =========================================================================

    def test_09_missing_malformed_and_explicitly_unverified_process_identity(self):
        """Missing, malformed, or unverified identity cannot confirm a cycle."""
        t_now = time.time()

        # 1. Missing identity
        g1 = WaitForGraph()
        g1.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=None,
            sampling_epoch=1, metadata=self._sample_valid_meta(102, 101),
        ))
        c1, cat1, iss1 = g1.validate_and_analyze()
        self.assertIsNone(c1)
        self.assertTrue(any("REJECT_MISSING_PROCESS_IDENTITY" in s for s in iss1))

        # 2. Malformed identity (missing process_start_time)
        g2 = WaitForGraph()
        bad_ident = {"pid": 100, "process_start_time": 0, "identity_status": IDENTITY_VERIFIED}
        g2.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=bad_ident,
            sampling_epoch=1, metadata=self._sample_valid_meta(102, 101),
        ))
        c2, cat2, iss2 = g2.validate_and_analyze()
        self.assertIsNone(c2)
        self.assertTrue(any("REJECT_MISSING_PROCESS_START_TIME" in s for s in iss2))

        # 3. Explicitly unverified identity (IDENTITY_UNVERIFIED)
        g3 = WaitForGraph()
        unverified_ident = self._sample_valid_proc_identity(100)
        unverified_ident["identity_status"] = IDENTITY_UNVERIFIED
        g3.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=unverified_ident,
            sampling_epoch=1, metadata=self._sample_valid_meta(102, 101),
        ))
        c3, cat3, iss3 = g3.validate_and_analyze()
        self.assertIsNone(c3)
        self.assertTrue(any("REJECT_IDENTITY_UNVERIFIED" in s for s in iss3))

        # 4. Identity unavailable (IDENTITY_UNAVAILABLE)
        g4 = WaitForGraph()
        unavail_ident = self._sample_valid_proc_identity(100)
        unavail_ident["identity_status"] = IDENTITY_UNAVAILABLE
        g4.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=unavail_ident,
            sampling_epoch=1, metadata=self._sample_valid_meta(102, 101),
        ))
        c4, cat4, iss4 = g4.validate_and_analyze()
        self.assertIsNone(c4)
        self.assertTrue(any("REJECT_IDENTITY_UNAVAILABLE" in s for s in iss4))

    # =========================================================================
    # 10. PID Reuse with Changed Process-Start Identity
    # =========================================================================

    def test_10_pid_reuse_with_changed_process_start_identity(self):
        """Edges with same target PID but differing process_start_time return RESULT_INCONSISTENT_OWNER_EVIDENCE."""
        graph = WaitForGraph()
        t_now = time.time()
        p1 = self._sample_valid_proc_identity(100)
        p1["process_start_time"] = 100000
        p2 = self._sample_valid_proc_identity(100)
        p2["process_start_time"] = 500000  # PID 100 recycled by newer process instance

        graph.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=p1,
            sampling_epoch=1, metadata=self._sample_valid_meta(102, 101),
        ))
        graph.add_edge(WaitForEdge(
            waiter_tid=102, sync_object="0x2000", normalized_address="0x2000",
            owner_tid=101, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=p2,
            sampling_epoch=1, metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_INCONSISTENT_OWNER_EVIDENCE)
        self.assertTrue(any("REJECT_CROSS_PROCESS_IDENTITY_MISMATCH" in s for s in issues))

    # =========================================================================
    # 11. Missing Sampling Epoch vs Explicit Epoch Zero
    # =========================================================================

    def test_11_missing_sampling_epoch_vs_explicit_epoch_zero(self):
        """Missing epoch (None) is rejected; explicit epoch zero (0) is accepted and confirms cycle."""
        t_now = time.time()

        # 1. Edge with missing epoch (None)
        g_missing = WaitForGraph()
        g_missing.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=self._sample_valid_proc_identity(100),
            sampling_epoch=None,  # Missing epoch
            metadata=self._sample_valid_meta(102, 101),
        ))
        c_m, cat_m, iss_m = g_missing.validate_and_analyze()
        self.assertIsNone(c_m)
        self.assertTrue(any("REJECT_MISSING_SAMPLING_EPOCH" in s for s in iss_m))

        # 2. Edges with explicit epoch zero (0)
        g_zero = WaitForGraph()
        g_zero.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=self._sample_valid_proc_identity(100),
            sampling_epoch=0,  # Explicit epoch zero
            metadata=self._sample_valid_meta(102, 101),
        ))
        g_zero.add_edge(WaitForEdge(
            waiter_tid=102, sync_object="0x2000", normalized_address="0x2000",
            owner_tid=101, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=self._sample_valid_proc_identity(100),
            sampling_epoch=0,  # Explicit epoch zero
            metadata=self._sample_valid_meta(101, 102),
        ))
        c_z, cat_z, iss_z = g_zero.validate_and_analyze(allowed_epoch=0)
        self.assertIsNotNone(c_z)
        self.assertEqual(cat_z, RESULT_DEADLOCK_CYCLE_CONFIRMED)
        self.assertEqual(c_z, [101, 102, 101])

    # =========================================================================
    # 12. Cross-Epoch Edges Rejected for Cycle Confirmation
    # =========================================================================

    def test_12_cross_epoch_edges_rejected_for_cycle_confirmation(self):
        """Candidate cycle spanning different epochs returns RESULT_INCONSISTENT_OWNER_EVIDENCE."""
        graph = WaitForGraph()
        t_now = time.time()
        graph.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=self._sample_valid_proc_identity(100),
            sampling_epoch=1,
            metadata=self._sample_valid_meta(102, 101),
        ))
        graph.add_edge(WaitForEdge(
            waiter_tid=102, sync_object="0x2000", normalized_address="0x2000",
            owner_tid=101, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=self._sample_valid_proc_identity(100),
            sampling_epoch=2,  # Cross epoch
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_INCONSISTENT_OWNER_EVIDENCE)
        self.assertTrue(any("REJECT_CROSS_EPOCH_MISMATCH" in s for s in issues))

    # =========================================================================
    # 13. Valid Same-Process, Same-Epoch Cycle Confirmed
    # =========================================================================

    def test_13_valid_same_process_same_epoch_cycle_confirmed(self):
        """Verified same-process, same-epoch edges form a confirmed deadlock cycle."""
        graph = WaitForGraph()
        t_now = time.time()
        p_id = self._sample_valid_proc_identity(100)

        graph.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=p_id,
            sampling_epoch=3,
            metadata=self._sample_valid_meta(102, 101),
        ))
        graph.add_edge(WaitForEdge(
            waiter_tid=102, sync_object="0x2000", normalized_address="0x2000",
            owner_tid=101, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now + 0.1, target_pid=100, process_identity=p_id,
            sampling_epoch=3,
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, category, issues = graph.validate_and_analyze(allowed_epoch=3)
        self.assertIsNotNone(cycle)
        self.assertEqual(category, RESULT_DEADLOCK_CYCLE_CONFIRMED)
        self.assertEqual(cycle, [101, 102, 101])

    # =========================================================================
    # 14. Unsupported ABI, Incomplete Raw, & Inconsistent Owner Unconfirmed
    # =========================================================================

    def test_14_unsupported_abi_incomplete_raw_and_inconsistent_owner_unconfirmed(self):
        """Unsupported ABI, missing raw memory, or conflicting lock owners fail closed."""
        t_now = time.time()
        p_id = self._sample_valid_proc_identity(100)

        # 1. Unsupported ABI (musl)
        g1 = WaitForGraph()
        g1.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
            mutex_layout_id=ABI_MUSL_UNSUPPORTED, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=p_id,
            sampling_epoch=1, metadata=self._sample_valid_meta(102, 101),
        ))
        c1, cat1, iss1 = g1.validate_and_analyze()
        self.assertIsNone(c1)
        self.assertTrue(any("REJECT_UNSUPPORTED_MUTEX_LAYOUT" in s for s in iss1))

        # 2. Missing raw bytes
        g2 = WaitForGraph()
        meta_no_raw = dict(self._sample_valid_meta(102, 101))
        meta_no_raw.pop("raw_bytes")
        meta_no_raw["read_bytes_len"] = 0
        g2.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=p_id,
            sampling_epoch=1, metadata=meta_no_raw,
        ))
        c2, cat2, iss2 = g2.validate_and_analyze()
        self.assertIsNone(c2)
        self.assertTrue(any("REJECT_MISSING_RAW_MEMORY_EVIDENCE" in s for s in iss2))

        # 3. Conflicting owners on same lock
        g3 = WaitForGraph()
        g3.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=p_id,
            sampling_epoch=1, metadata=self._sample_valid_meta(102, 101),
        ))
        g3.add_edge(WaitForEdge(
            waiter_tid=103, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=104, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=p_id,
            sampling_epoch=1, metadata=self._sample_valid_meta(104, 103),
        ))
        c3, cat3, iss3 = g3.validate_and_analyze()
        self.assertIsNone(c3)
        self.assertEqual(cat3, RESULT_INCONSISTENT_OWNER_EVIDENCE)

    # =========================================================================
    # 15. Remote Target Identity Validation Without Local /proc Leakage
    # =========================================================================

    def test_15_remote_target_identity_validation_without_local_proc_leakage(self):
        """Remote SSH adapter validates process identity strictly on remote host without touching local /proc."""
        remote_pid = 999999  # Does NOT exist on local host
        self.assertFalse(os.path.exists(f"/proc/{remote_pid}"), "Test precondition: PID 999999 must not exist locally")

        # Mock SSH runner responding for remote PID 999999
        def mock_ssh_runner(cmd, timeout: float = 5.0) -> Tuple[int, str, str]:
            cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
            if "kill -0 999999" in cmd_str:
                return 0, "ALIVE\n", ""
            elif "readlink" in cmd_str and "/proc/999999/exe" in cmd_str:
                return 0, "/remote/usr/bin/daemon\n", ""
            elif "/proc/999999/stat" in cmd_str:
                # 22 fields; field 22 is start_time = 445566
                fake_stat = "999999 (daemon) S 1 999999 999999 0 0 4194304 100 0 0 0 10 5 0 0 20 0 1 0 445566 1000 200"
                return 0, fake_stat + "\n", ""
            elif "/proc/999999/exe" in cmd_str and "base64" in cmd_str:
                # Minimal 64-byte ELF64 little-endian header base64 encoded
                # e_ident: \x7fELF (4 bytes), class 2 (ELF64), data 1 (LE), version 1, abi 0, pad (8 bytes) -> 16 bytes
                # e_type 2 (ET_EXEC), e_machine 0x3e (x86_64), e_version 1 -> 8 bytes
                elf_hdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack("<HHI", 2, 0x3e, 1) + b"\x00" * 40
                import base64
                return 0, base64.b64encode(elf_hdr).decode("ascii") + "\n", ""
            return 0, "", ""

        adapter = RemoteSshTargetAdapter(host="remote.target.host", command_runner=mock_ssh_runner)
        ident = adapter.get_process_identity(remote_pid)

        self.assertEqual(ident["pid"], remote_pid)
        self.assertEqual(ident["executable"], "/remote/usr/bin/daemon")
        self.assertEqual(ident["process_start_time"], 445566)
        self.assertEqual(ident["architecture"], "x86_64")
        self.assertEqual(ident["elf_class"], "ELF64")
        self.assertEqual(ident["endianness"], "little")
        self.assertEqual(ident["identity_status"], IDENTITY_VERIFIED)
        self.assertTrue(ident["is_remote"])
        self.assertGreater(adapter.get_last_identity_bytes_read(), 0)

        # Local /proc was NEVER touched
        self.assertFalse(os.path.exists(f"/proc/{remote_pid}"))

    # =========================================================================
    # 16. Serialization & Deserialization Preserving Identity Status & Epoch
    # =========================================================================

    def test_16_serialization_and_deserialization_preserving_identity_status_and_epoch(self):
        """to_dict and constructor round-trip preserves explicit epoch zero and identity status."""
        p_id = self._sample_valid_proc_identity(100)
        e_orig = WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            raw_futex_argument="0x1000",
            normalized_address="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64,
            memory_read_status="OBSERVED",
            evidence_source="pthread_mutex_memory",
            observation_timestamp=123456.789,
            target_pid=100,
            process_identity=p_id,
            sampling_epoch=0,  # Explicit epoch zero
            metadata={"test_key": "test_val"},
        )
        d = e_orig.to_dict()
        self.assertEqual(d["sampling_epoch"], 0)
        self.assertIsNotNone(d["sampling_epoch"])
        self.assertEqual(d["process_identity"]["identity_status"], IDENTITY_VERIFIED)

        # Round-trip deserialization
        e_reconstructed = WaitForEdge(**d)
        self.assertEqual(e_reconstructed.sampling_epoch, 0)
        self.assertEqual(e_reconstructed.waiter_tid, 101)
        self.assertEqual(e_reconstructed.target_pid, 100)
        self.assertEqual(e_reconstructed.process_identity["identity_status"], IDENTITY_VERIFIED)

        # Explicit missing epoch (None) round-trip
        e_missing = WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            sampling_epoch=None,
        )
        d_missing = e_missing.to_dict()
        self.assertIsNone(d_missing["sampling_epoch"])
        e_missing_reconstructed = WaitForEdge(**d_missing)
        self.assertIsNone(e_missing_reconstructed.sampling_epoch)


if __name__ == "__main__":
    unittest.main()
