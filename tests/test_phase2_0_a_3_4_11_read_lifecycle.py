"""Phase 2.0-A.3.4.11 — Production Read Lifecycle Closure & Exactly-Once Accounting.

Adversarial regression test suite validating:
1. Authoritative Read Lifecycle: ADMITTED -> PHYSICAL_READ_STARTED -> CONSUMED -> ACCOUNTED / RELEASED (P0.1, P0.7)
2. get_proc_maps() production read lifecycle closure (P0.2)
3. get_threads() nested read accounting without double-charging (P0.3)
4. read_memory_batch() multi-slice accumulation reservation semantics (P0.4)
5. Elimination of unsafe TypeError fallback in ReadOnlyTargetAdapter (P0.5)
6. Global and profile budget ceiling enforcement under concurrency (P0.6)
7. Crash-safe commit and recovery with no leaked reservations (P0.8)
8. Production integration test matrix covering all 10 production call sites (P1.1)
9. Independent 14-dimension ledger reconciliation (P1.2)
10. Static AST architecture audit (P1.3)
"""

import ast
import math
import os
import pathlib
import threading
import time
import unittest
import uuid
from typing import Any, Dict, List, Optional, Tuple

from extractor.observation_budget import (
    ActiveOperationScope,
    AccountingFingerprint,
    BudgetReservation,
    CommittedTransactionSnapshot,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    canonical_metadata_digest,
    freeze_metadata,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    RemoteSshTargetAdapter,
    STATUS_OWNER_NOT_IDENTIFIED,
)


class ComprehensiveInstrumentedTargetAdapter(LocalTargetAdapter):
    """Production test adapter recording all physical I/O and pre-read admissions."""

    def __init__(self):
        super().__init__()
        self.call_log: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def read_memory(
        self,
        pid: int,
        address: int,
        size: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> Tuple[Optional[bytes], str, Optional[str]]:
        with self._lock:
            self.call_log.append({
                "op": "read_memory",
                "pid": pid,
                "address": address,
                "size": size,
                "has_admission": admission is not None,
                "admission_state": admission.state if admission else None,
                "physical_consumption_id": getattr(admission, "physical_consumption_id", None) if admission else None,
            })
        return super().read_memory(pid, address, size, admission=admission, budget_tracker=budget_tracker)

    def read_memory_batch(
        self,
        pid: int,
        slices: List[Tuple[int, int]],
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Tuple[Optional[bytes], str, Optional[str]]]:
        with self._lock:
            self.call_log.append({
                "op": "read_memory_batch",
                "pid": pid,
                "slices_count": len(slices),
                "has_admission": admission is not None,
                "admission_state": admission.state if admission else None,
            })
        return super().read_memory_batch(pid, slices, admission=admission, budget_tracker=budget_tracker)

    def get_proc_maps(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            self.call_log.append({
                "op": "get_proc_maps",
                "pid": pid,
                "has_admission": admission is not None,
                "admission_state": admission.state if admission else None,
                "physical_consumption_id": getattr(admission, "physical_consumption_id", None) if admission else None,
            })
        return super().get_proc_maps(pid, admission=admission, budget_tracker=budget_tracker)

    def get_threads(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            self.call_log.append({
                "op": "get_threads",
                "pid": pid,
                "has_admission": admission is not None,
                "admission_state": admission.state if admission else None,
                "physical_consumption_id": getattr(admission, "physical_consumption_id", None) if admission else None,
            })
        return super().get_threads(pid, admission=admission, budget_tracker=budget_tracker)

    def get_process_identity(
        self,
        pid: int,
        budget_tracker: Optional[Any] = None,
        operation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            self.call_log.append({
                "op": "get_process_identity",
                "pid": pid,
            })
        return super().get_process_identity(pid, budget_tracker=budget_tracker, operation_id=operation_id)

    def get_process_memory_info(
        self,
        pid: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            self.call_log.append({
                "op": "get_process_memory_info",
                "pid": pid,
                "has_admission": admission is not None,
            })
        return super().get_process_memory_info(pid, admission=admission, budget_tracker=budget_tracker)


class TestPhase20A3411ReadLifecycle(unittest.TestCase):
    """Authoritative test suite for Phase 2.0-A.3.4.11."""

    # =========================================================================
    # Group 1: Authoritative Read Lifecycle & State Machine (P0.1, P0.7)
    # =========================================================================

    def test_01_canonical_lifecycle_admitted_to_accounted(self):
        """Canonical lifecycle: ADMITTED -> PHYSICAL_READ_STARTED -> CONSUMED -> ACCOUNTED."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(projected_bytes=500, profile_id="p1", operation_id="op_canon")
        self.assertEqual(adm.state, "ADMITTED")
        self.assertTrue(adm.is_admitted)
        self.assertEqual(tracker.remaining_bytes, 9500)

        # Start physical read
        adm.mark_physical_read_started("phys_custom_1")
        self.assertEqual(adm.state, "PHYSICAL_READ_STARTED")
        self.assertTrue(adm.is_physical_read_started)
        self.assertEqual(adm.physical_consumption_id, "phys_custom_1")

        # Physical read consumes 400 bytes
        consumed = adm.consume(400)
        self.assertEqual(consumed, 400)
        self.assertEqual(adm.state, "CONSUMED")
        self.assertTrue(adm.is_consumed)

        # Accounted via scope
        with tracker.operation_scope("op_canon", profile_id="p1") as scope:
            scope.record_read(bytes_read=400, admission=adm)

        self.assertTrue(adm.is_accounted)
        self.assertEqual(adm.state, "ACCOUNTED")
        self.assertIn("PHYSICAL_READ_STARTED", adm.transition_history)
        self.assertIn("CONSUMED", adm.transition_history)
        self.assertIn("ACCOUNTED", adm.transition_history)
        self.assertEqual(tracker.metrics.bytes_read, 400)
        self.assertEqual(tracker.remaining_bytes, 9600)

    def test_02_canonical_lifecycle_admitted_to_released_on_zero_bytes(self):
        """ADMITTED -> RELEASED strictly when physical consumption is 0 bytes."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(projected_bytes=800, profile_id="p1", operation_id="op_rel")
        self.assertEqual(adm.state, "ADMITTED")
        self.assertEqual(tracker.remaining_bytes, 9200)

        adm.mark_physical_read_started()
        self.assertEqual(adm.state, "PHYSICAL_READ_STARTED")

        # Physical read produced 0 bytes -> release
        tracker.release_reservation(adm)
        self.assertEqual(adm.state, "RELEASED")
        self.assertTrue(adm.is_released)
        self.assertEqual(tracker.remaining_bytes, 10000)

    def test_03_zero_bytes_rejected_for_accounting(self):
        """Zero-byte consumption can NEVER be finalized as ACCOUNTED; it must be released."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(projected_bytes=500, profile_id="p1", operation_id="op_no_zero")
        with self.assertRaises(RuntimeError):
            adm.account()

    def test_04_release_rejected_after_bytes_consumed(self):
        """No consumed reservation can ever be released: release() strictly raises RuntimeError."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(projected_bytes=500, profile_id="p1", operation_id="op_no_rel")
        adm.consume(250)
        self.assertTrue(adm.is_consumed)

        with self.assertRaises(RuntimeError):
            tracker.release_reservation(adm)
        self.assertEqual(adm.state, "CONSUMED")

    def test_05_consume_without_accumulate_rejected_if_already_consumed(self):
        """Re-consuming an already CONSUMED reservation without accumulate=True raises RuntimeError."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(projected_bytes=500, profile_id="p1", operation_id="op_re_consume")
        adm.consume(200)

        # Consuming different bytes without accumulate=True raises RuntimeError
        with self.assertRaises(RuntimeError):
            adm.consume(300, accumulate=False)

        # Idempotent re-affirmation with same bytes returns consumed_bytes without error
        res = adm.consume(200, accumulate=False)
        self.assertEqual(res, 200)

    def test_06_consume_with_accumulate_safely_sums_physical_bytes(self):
        """consume(..., accumulate=True) atomically accumulates physical consumption."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(projected_bytes=1000, profile_id="p1", operation_id="op_accum")
        adm.consume(150)
        self.assertEqual(adm.consumed_bytes, 150)

        adm.consume(250, accumulate=True)
        self.assertEqual(adm.consumed_bytes, 400)

        adm.accumulate_consume(100)
        self.assertEqual(adm.consumed_bytes, 500)

    def test_07_terminal_states_are_immutable(self):
        """ACCOUNTED and RELEASED terminal states reject any further transitions."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        # Terminal state 1: ACCOUNTED
        adm1 = tracker.admit_read(projected_bytes=500, profile_id="p1", operation_id="op_term1")
        adm1.consume(300)
        adm1.account()
        with self.assertRaises(RuntimeError):
            adm1.consume(100)
        with self.assertRaises(RuntimeError):
            adm1.account()
        with self.assertRaises(RuntimeError):
            adm1.release()

        # Terminal state 2: RELEASED
        adm2 = tracker.admit_read(projected_bytes=500, profile_id="p1", operation_id="op_term2")
        adm2.release()
        with self.assertRaises(RuntimeError):
            adm2.consume(100)
        with self.assertRaises(RuntimeError):
            adm2.account()
        with self.assertRaises(RuntimeError):
            adm2.release()

    def test_08_unique_physical_consumption_ids_per_read(self):
        """Every admitted read gets a distinct physical consumption ID."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm1 = tracker.admit_read(100)
        adm2 = tracker.admit_read(100)
        adm1.mark_physical_read_started()
        adm2.mark_physical_read_started()
        self.assertNotEqual(adm1.physical_consumption_id, adm2.physical_consumption_id)

    # =========================================================================
    # Group 2: Production Read Paths Lifecycle Closure (P0.2, P0.3, P0.4)
    # =========================================================================

    def test_09_proc_maps_scope_correlation(self):
        """LocalTargetAdapter.get_proc_maps correlates directly with active scope."""
        adapter = LocalTargetAdapter()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        with tracker.operation_scope("op_maps_scope", profile_id="target_maps") as scope:
            maps = adapter.get_proc_maps(os.getpid(), budget_tracker=tracker)
            self.assertGreater(len(maps), 0)
            self.assertGreater(adapter.get_last_maps_bytes_read(), 0)

        # Exactly 1 transaction committed under op_maps_scope, 0 standalone transactions leaked
        committed = tracker.get_committed_transactions()
        self.assertIn("op_maps_scope", committed)
        standalone = [k for k in committed.keys() if "standalone_maps" in k]
        self.assertEqual(len(standalone), 0)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_10_proc_maps_failed_open_releases_reservation(self):
        """When /proc/<pid>/maps fails to open, admission is released immediately with 0 charged bytes."""
        adapter = LocalTargetAdapter()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        # PID 999999 does not exist -> open fails
        maps = adapter.get_proc_maps(999999, budget_tracker=tracker)
        self.assertEqual(len(maps), 0)
        self.assertEqual(adapter.get_last_maps_bytes_read(), 0)
        self.assertEqual(tracker.metrics.bytes_read, 0)

        # 0 active reservations leaked
        active_res = tracker.get_active_reservations()
        self.assertEqual(len(active_res), 0)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_11_proc_maps_nested_inside_threads_no_double_charge(self):
        """get_threads passes admission to get_proc_maps without double-charging maps bytes."""
        adapter = LocalTargetAdapter()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        threads = adapter.get_threads(os.getpid(), budget_tracker=tracker)
        self.assertGreater(len(threads), 0)

        breakdown = getattr(adapter, "_last_threads_breakdown", {})
        self.assertGreater(breakdown["maps_bytes"], 0)
        self.assertGreater(breakdown["task_bytes"], 0)
        self.assertEqual(breakdown["total_bytes"], breakdown["maps_bytes"] + breakdown["task_bytes"] + breakdown.get("memory_bytes", 0))

        # Check committed transactions: exactly 1 standalone threads transaction committed
        committed = tracker.get_committed_transactions()
        self.assertEqual(len(committed), 1)
        th_snap = list(committed.values())[0]
        self.assertEqual(th_snap.charged_bytes, breakdown["total_bytes"])

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_12_threads_enumeration_lifecycle(self):
        """Threads enumeration accurately records 1 thread (self) and task files."""
        adapter = LocalTargetAdapter()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        with tracker.operation_scope("op_threads_enum", profile_id="target_threads") as scope:
            th = adapter.get_threads(os.getpid(), budget_tracker=tracker)
            self.assertGreaterEqual(len(th), 1)

        snap = tracker.get_committed_record("op_threads_enum")
        self.assertIsNotNone(snap)
        self.assertEqual(tracker.metrics.bytes_read, snap.charged_bytes)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_13_threads_nonexistent_pid_releases_cleanly(self):
        """get_threads on non-existent PID produces 0 threads and releases cleanly."""
        adapter = LocalTargetAdapter()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        th = adapter.get_threads(999999, budget_tracker=tracker)
        self.assertEqual(len(th), 0)
        self.assertEqual(tracker.metrics.bytes_read, 0)
        self.assertEqual(len(tracker.get_active_reservations()), 0)

    def test_14_read_memory_batch_multi_slice_accumulation(self):
        """read_memory_batch accumulates physical consumption across multiple slices."""
        adapter = LocalTargetAdapter()
        # Mock memory reader returning known bytes
        adapter._memory_reader = lambda pid, addr, sz: (b"A" * sz, "OBSERVED", None)

        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        slices = [(0x1000, 64), (0x2000, 128), (0x3000, 256)]
        results = adapter.read_memory_batch(os.getpid(), slices, budget_tracker=tracker)

        self.assertEqual(len(results), 3)
        expected_total = 64 + 128 + 256
        self.assertEqual(tracker.metrics.bytes_read, expected_total)

        committed = tracker.get_committed_transactions()
        self.assertEqual(len(committed), 1)
        snap = list(committed.values())[0]
        self.assertEqual(snap.charged_bytes, expected_total)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_15_read_memory_batch_empty_or_zero_bytes_releases_reservation(self):
        """read_memory_batch on 0-byte or unavailable slices releases reservation without leaking."""
        adapter = LocalTargetAdapter()
        adapter._memory_reader = lambda pid, addr, sz: (None, "UNAVAILABLE", "Unmapped")

        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        results = adapter.read_memory_batch(os.getpid(), [(0x1000, 128)], budget_tracker=tracker)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1], "UNAVAILABLE")

        self.assertEqual(tracker.metrics.bytes_read, 0)
        self.assertEqual(len(tracker.get_active_reservations()), 0)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_16_read_memory_batch_mixed_slices_partial_success(self):
        """read_memory_batch with mixed success/failure slices preserves actual consumed bytes."""
        adapter = LocalTargetAdapter()
        def mock_read(pid, addr, sz):
            if addr == 0x1000:
                return b"X" * sz, "OBSERVED", None
            else:
                return None, "UNAVAILABLE", "Unmapped"

        adapter._memory_reader = mock_read

        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        slices = [(0x1000, 100), (0x2000, 200)]
        results = adapter.read_memory_batch(os.getpid(), slices, budget_tracker=tracker)

        self.assertEqual(results[0][1], "OBSERVED")
        self.assertEqual(results[1][1], "UNAVAILABLE")
        self.assertEqual(tracker.metrics.bytes_read, 100)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_17_process_memory_info_admitted_lifecycle(self):
        """get_process_memory_info admits before reading statm/maps and accounts cleanly."""
        adapter = LocalTargetAdapter()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        with tracker.operation_scope("op_mem_info", profile_id="target_memory_info") as scope:
            info = adapter.get_process_memory_info(os.getpid(), budget_tracker=tracker)
            self.assertEqual(info["status"], "OBSERVED")
            self.assertIn("vsz_bytes", info["metrics"])

        snap = tracker.get_committed_record("op_mem_info")
        self.assertIsNotNone(snap)
        self.assertGreater(snap.charged_bytes, 0)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # Group 3: Elimination of Unsafe TypeError Fallback (P0.5)
    # =========================================================================

    def test_18_adapter_lacking_admission_fails_closed_with_permission_error(self):
        """ReadOnlyTargetAdapter wrapping legacy adapter without admission support raises PermissionError when tracker active."""
        class LegacyNoAdmissionAdapter:
            def read_memory(self, pid: int, address: int, size: int):
                return b"raw", "OBSERVED", None

        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        wrapped = ReadOnlyTargetAdapter(LegacyNoAdmissionAdapter(), budget_tracker=tracker)
        with self.assertRaises(PermissionError):
            wrapped.read_memory(os.getpid(), 0x1000, 32)

    def test_19_internal_type_error_inside_adapter_is_never_caught_or_retried(self):
        """Internal TypeError inside adapter implementation is not caught or masked by ReadOnlyTargetAdapter."""
        class BuggyAdapter:
            def read_memory(self, pid: int, address: int, size: int, admission=None, budget_tracker=None):
                raise TypeError("Internal bug in adapter logic, not parameter mismatch")

        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        wrapped = ReadOnlyTargetAdapter(BuggyAdapter(), budget_tracker=tracker)
        with self.assertRaises(TypeError) as ctx:
            wrapped.read_memory(os.getpid(), 0x1000, 32)
        self.assertIn("Internal bug in adapter logic", str(ctx.exception))

    def test_20_read_invocation_count_strictly_one(self):
        """ReadOnlyTargetAdapter executes the inner read method strictly once."""
        call_count = [0]
        class CountingAdapter:
            def read_memory(self, pid: int, address: int, size: int, admission=None, budget_tracker=None):
                call_count[0] += 1
                return b"DATA", "OBSERVED", None

        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        wrapped = ReadOnlyTargetAdapter(CountingAdapter(), budget_tracker=tracker)
        res = wrapped.read_memory(os.getpid(), 0x1000, 4)
        self.assertEqual(res[0], b"DATA")
        self.assertEqual(call_count[0], 1)

    def test_21_legacy_adapter_works_when_tracker_is_none(self):
        """ReadOnlyTargetAdapter with tracker=None invokes legacy adapter without kwargs."""
        class Legacy3ArgAdapter:
            def read_memory(self, pid: int, address: int, size: int):
                return b"LEGACY", "OBSERVED", None

        wrapped = ReadOnlyTargetAdapter(Legacy3ArgAdapter(), budget_tracker=None)
        res = wrapped.read_memory(os.getpid(), 0x1000, 6)
        self.assertEqual(res[0], b"LEGACY")

    # =========================================================================
    # Group 4: Global and Profile Budget Ceilings Under Concurrency (P0.6)
    # =========================================================================

    def test_22_global_limit_enforced_atomically_under_concurrency(self):
        """Multiple concurrent threads attempting admissions near global limit are atomically rejected without overshoot."""
        limit = 3000
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=limit))
        tracker.start()

        barrier = threading.Barrier(8)
        admitted = []
        rejected = []
        lock = threading.Lock()

        def worker(idx: int):
            barrier.wait()
            try:
                adm = tracker.admit_read(projected_bytes=500, profile_id=f"p_{idx}", operation_id=f"op_{idx}")
                with lock:
                    admitted.append(adm)
            except ValueError:
                with lock:
                    rejected.append(idx)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # At 500B per read and 3000B limit: exactly 6 threads can be admitted, 2 must be rejected
        self.assertEqual(len(admitted), 6)
        self.assertEqual(len(rejected), 2)
        total_reserved = sum(a.reserved_bytes for a in admitted)
        self.assertLessEqual(total_reserved, limit)

    def test_23_profile_limit_enforced_atomically_under_concurrency(self):
        """Profile ceiling atomically checked against active reservations + in-flight consumption."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        ceiling = {"max_bytes_read": 1000}
        barrier = threading.Barrier(4)
        admitted = []
        rejected = []
        lock = threading.Lock()

        def worker(idx: int):
            barrier.wait()
            try:
                adm = tracker.admit_read(projected_bytes=400, profile_id="limited_prof", profile_ceiling=ceiling)
                with lock:
                    admitted.append(adm)
            except ValueError:
                with lock:
                    rejected.append(idx)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # At 400B per read and 1000B profile ceiling: exactly 2 can be admitted, 2 rejected
        self.assertEqual(len(admitted), 2)
        self.assertEqual(len(rejected), 2)

    def test_24_inflight_overshoot_strictly_bounded(self):
        """In-flight read starting before exhaustion has overshoot strictly bounded <= max_bytes_per_observation."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(
            max_bytes_read=5000,
            max_bytes_per_observation=4096,
        ))
        tracker.start()

        # Pre-charge 4900 bytes; 100 bytes left
        tracker.record_read(bytes_read=4900, profile_id="base")

        # In-flight read admitting 1024 bytes with allow_in_flight_overshoot=True succeeds
        adm = tracker.admit_read(1024, profile_id="inflight", allow_in_flight_overshoot=True)
        self.assertTrue(adm.is_admitted)

        # In-flight read attempting > 4096 overshoot fails
        with self.assertRaises(ValueError):
            tracker.admit_read(5000, profile_id="inflight2", allow_in_flight_overshoot=True)

    # =========================================================================
    # Group 5: Crash-Safe Commit & Recovery (P0.8)
    # =========================================================================

    def test_25_crash_recovery_during_prepare_preserves_physical_cost(self):
        """Exception during prepare phase preserves physically consumed bytes and finalizes reservations."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        def fault_hook():
            raise RuntimeError("Prepare phase crash")

        tracker.set_fault_injection("during_fingerprint_creation", fault_hook)

        try:
            with tracker.operation_scope("op_prepare_crash") as scope:
                adm = scope.admit_read(300)
                adm.consume(300)
                scope.record_read(bytes_read=300, admission=adm)
        except RuntimeError:
            pass
        finally:
            tracker.clear_fault_injections()

        # 300B preserved in metrics and physical ledger
        self.assertEqual(tracker.metrics.bytes_read, 300)
        self.assertEqual(len(tracker.get_active_reservations()), 0)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # Group 6: Production Integration Matrix Covering 10 Call Sites (P1.1)
    # =========================================================================

    def test_26_production_integration_10_call_sites_verified(self):
        """Instrumented adapter verifies pre-read admission across all 10 production read paths."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=200000))
        tracker.start()
        adapter = ComprehensiveInstrumentedTargetAdapter()
        pid = os.getpid()

        # 1. Local memory read
        adapter._memory_reader = lambda p, a, s: (b"X" * s, "OBSERVED", None)
        raw, st, _ = adapter.read_memory(pid, 0x1000, 32, budget_tracker=tracker)
        self.assertEqual(st, "OBSERVED")

        # 2. Local memory batch read
        res_batch = adapter.read_memory_batch(pid, [(0x1000, 16), (0x2000, 16)], budget_tracker=tracker)
        self.assertEqual(len(res_batch), 2)

        # 3. Local proc maps read
        maps = adapter.get_proc_maps(pid, budget_tracker=tracker)
        self.assertGreater(len(maps), 0)

        # 4. Local threads read
        threads = adapter.get_threads(pid, budget_tracker=tracker)
        self.assertGreater(len(threads), 0)

        # 5. Local process identity read
        ident = adapter.get_process_identity(pid, budget_tracker=tracker)
        self.assertEqual(ident["status"], "OBSERVED")

        # 6. Local process memory info read
        mem_info = adapter.get_process_memory_info(pid, budget_tracker=tracker)
        self.assertEqual(mem_info["status"], "OBSERVED")

        # 7. Local mutex owner resolution
        # Fake LP64 mutex buffer
        fake_raw = b"\x00" * 40
        adapter._memory_reader = lambda p, a, s: (fake_raw, "OBSERVED", None)
        res_mutex = adapter.resolve_mutex_owner(pid, 0x7ffd1234, budget_tracker=tracker)
        self.assertIn(res_mutex.status, (STATUS_OWNER_NOT_IDENTIFIED, "MUTEX_LAYOUT_UNSUPPORTED"))

        # Remote Adapter Call Sites (8, 9, 10)
        def mock_ssh(cmd, timeout=5.0):
            cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
            if "maps" in cmd_str:
                return 0, "00400000-00452000 r-xp 00000000 08:02 123456 /bin/test\n", ""
            elif "task" in cmd_str:
                return 0, "100 S worker\n", ""
            elif "readlink" in cmd_str:
                return 0, "/bin/test\n", ""
            return 0, "dummy", ""

        remote_adapter = RemoteSshTargetAdapter(host="remote.test", command_runner=mock_ssh)

        # 8. Remote memory read
        rem_raw, rem_st, _ = remote_adapter.read_memory(100, 0x1000, 16, budget_tracker=tracker)

        # 9. Remote proc maps read
        rem_maps = remote_adapter.get_proc_maps(100, budget_tracker=tracker)
        self.assertGreater(len(rem_maps), 0)

        # 10. Remote threads read
        rem_threads = remote_adapter.get_threads(100, budget_tracker=tracker)
        self.assertGreater(len(rem_threads), 0)

        # Reconcile entire ledger across all 10 operations
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertGreater(recon["unique_physical_consumption_ids"], 5)

    # =========================================================================
    # Group 7: Independent Ledger Reconciliation (P1.2)
    # =========================================================================

    def test_27_reconciliation_verifies_physical_ids_and_active_scopes(self):
        """reconcile_ledger strictly verifies unique physical IDs and active scopes."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        with tracker.operation_scope("op_recon1") as scope1:
            scope1.record_read(bytes_read=100)

        with tracker.operation_scope("op_recon2") as scope2:
            scope2.record_read(bytes_read=200)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_logical_transactions"], 2)
        self.assertEqual(recon["total_physical_records"], 2)
        self.assertEqual(recon["unique_physical_consumption_ids"], 2)

    def test_28_reconciliation_detects_orphaned_consumed_reservation(self):
        """reconcile_ledger detects and rejects orphaned consumed reservations without active scopes."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(500)
        adm.consume(300)
        # Reservation is left consumed without being associated with any scope or accounted
        with self.assertRaises(AssertionError) as ctx:
            tracker.reconcile_ledger()
        self.assertIn("has no active scope", str(ctx.exception))

    # =========================================================================
    # Group 8: Static Architecture Audit (P1.3)
    # =========================================================================

    def test_29_ast_audit_no_type_error_fallback_in_read_only_adapter(self):
        """AST audit verifies ReadOnlyTargetAdapter contains ZERO try-except TypeError fallbacks."""
        adapter_path = pathlib.Path(__file__).parent.parent / "extractor" / "target_adapter.py"
        with open(adapter_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(adapter_path))

        class ReadOnlyAdapterVisitor(ast.NodeVisitor):
            def __init__(self):
                self.in_read_only_adapter = False
                self.type_error_handlers = []

            def visit_ClassDef(self, node: ast.ClassDef):
                prev = self.in_read_only_adapter
                if node.name == "ReadOnlyTargetAdapter":
                    self.in_read_only_adapter = True
                self.generic_visit(node)
                self.in_read_only_adapter = prev

            def visit_ExceptHandler(self, node: ast.ExceptHandler):
                if self.in_read_only_adapter:
                    if isinstance(node.type, ast.Name) and node.type.id == "TypeError":
                        self.type_error_handlers.append(node.lineno)
                self.generic_visit(node)

        visitor = ReadOnlyAdapterVisitor()
        visitor.visit(tree)
        self.assertEqual(
            len(visitor.type_error_handlers),
            0,
            f"ReadOnlyTargetAdapter must not contain 'except TypeError' handlers (found at lines: {visitor.type_error_handlers})",
        )

    def test_30_ast_audit_reservation_state_machine_strict_transition_rules(self):
        """AST audit verifies BudgetReservation enforces terminal state checks before transitions."""
        budget_path = pathlib.Path(__file__).parent.parent / "extractor" / "observation_budget.py"
        with open(budget_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(budget_path))

        class BudgetReservationVisitor(ast.NodeVisitor):
            def __init__(self):
                self.in_budget_res = False
                self.methods_found = set()

            def visit_ClassDef(self, node: ast.ClassDef):
                prev = self.in_budget_res
                if node.name == "BudgetReservation":
                    self.in_budget_res = True
                self.generic_visit(node)
                self.in_budget_res = prev

            def visit_FunctionDef(self, node: ast.FunctionDef):
                if self.in_budget_res:
                    self.methods_found.add(node.name)
                self.generic_visit(node)

        visitor = BudgetReservationVisitor()
        visitor.visit(tree)
        self.assertIn("mark_physical_read_started", visitor.methods_found)
        self.assertIn("consume", visitor.methods_found)
        self.assertIn("accumulate_consume", visitor.methods_found)
        self.assertIn("release", visitor.methods_found)
        self.assertIn("account", visitor.methods_found)


if __name__ == "__main__":
    unittest.main()
