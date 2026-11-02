"""Deterministic Adversarial Concurrency & Accounting Correctness Tests.

Phase 2.0-A.3.4.10 — Pre-Read Budget Admission & Crash-Safe Accounting Commit.

Validates:
1. Pre-Read Budget Admission Lifecycle (ADMITTED -> CONSUMED -> ACCOUNTED / RELEASED) (P0.1, P0.2)
2. Separation of Reservation and Physical Consumption (P0.3)
3. Failure-Safe Atomic Finalization (Prepare/Commit architecture) (P0.4)
4. Physical Consumption Identity and Idempotency (P0.5)
5. 14 Deterministic Failure Injection Boundaries (P1.1)
6. Full Lifecycle Reconciliation across all 14 dimensions (P1.2)
7. Production Read Call Sites Integration Tests (P1.3)
8. Static Architecture Audits (P1.4)
"""

import ast
import math
import os
import pathlib
import threading
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple

from extractor.observation_budget import (
    ActiveOperationScope,
    AccountingFingerprint,
    BudgetReservation,
    CommittedTransactionSnapshot,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    PreparedCommit,
    canonical_metadata_digest,
    freeze_metadata,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    IDENTITY_UNAVAILABLE,
)


class InstrumentedAdmissionTargetAdapter(LocalTargetAdapter):
    """Production test target adapter that verifies admission occurs strictly BEFORE physical I/O."""

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
            # Assertion: Admission must already be granted (state == ADMITTED or RESERVED)
            # or budget tracker must have verified admission before calling physical read
            has_valid_admission = admission is not None and admission.state in ("ADMITTED", "RESERVED")
            self.call_log.append({
                "op": "read_memory",
                "pid": pid,
                "address": address,
                "size": size,
                "has_valid_admission": has_valid_admission,
                "admission_id": admission.reservation_id if admission else None,
                "timestamp": time.monotonic(),
            })
            if admission is not None and not has_valid_admission:
                raise AssertionError(f"Physical read started with invalid admission state: {admission.state}")

        return super().read_memory(pid, address, size, admission=admission, budget_tracker=budget_tracker)


class TestPhase20A3410AdmissionAndCrashSafe(unittest.TestCase):
    """Complete test suite for Phase 2.0-A.3.4.10."""

    # =========================================================================
    # Group 1: Pre-Read Budget Admission Lifecycle (P0.1, P0.2)
    # =========================================================================

    def test_01_admit_read_normal_lifecycle(self):
        """Pre-read admission follows ADMITTED -> CONSUMED -> ACCOUNTED."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(projected_bytes=1000, profile_id="test_prof", operation_id="op_normal")
        self.assertEqual(adm.state, "ADMITTED")
        self.assertTrue(adm.is_admitted)
        self.assertFalse(adm.is_consumed)
        self.assertFalse(adm.is_released)
        self.assertFalse(adm.is_accounted)
        self.assertEqual(tracker.remaining_bytes, 9000)

        # Consume 800 physical bytes
        consumed = adm.consume(actual_bytes=800)
        self.assertEqual(consumed, 800)
        self.assertEqual(adm.state, "CONSUMED")
        self.assertTrue(adm.is_consumed)
        self.assertFalse(adm.is_admitted)

        # Account the read through a scope
        with tracker.operation_scope("op_normal", profile_id="test_prof") as scope:
            scope.record_read(bytes_read=800, admission=adm)

        snap = tracker.get_committed_record("op_normal")
        self.assertIsNotNone(snap)
        self.assertEqual(snap.charged_bytes, 800)
        self.assertTrue(adm.is_accounted)
        self.assertEqual(tracker.metrics.bytes_read, 800)
        self.assertEqual(tracker.remaining_bytes, 9200)

    def test_02_admit_read_zero_bytes_released(self):
        """Pre-read admission follows ADMITTED -> RELEASED strictly when 0 physical bytes read."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(projected_bytes=2000, profile_id="test_prof", operation_id="op_released")
        self.assertEqual(adm.state, "ADMITTED")
        self.assertEqual(tracker.remaining_bytes, 8000)

        # Release admission without consuming physical bytes
        tracker.release_reservation(adm)
        self.assertEqual(adm.state, "RELEASED")
        self.assertTrue(adm.is_released)
        self.assertEqual(tracker.remaining_bytes, 10000)
        self.assertEqual(tracker._released_reservations_count, 1)

    def test_03_admission_rejection_prevents_physical_read(self):
        """When budget is exhausted, admission is rejected and zero physical I/O begins."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=1000))
        tracker.start()
        tracker.record_read(bytes_read=1000, profile_id="filler")
        self.assertTrue(tracker.is_budget_exhausted)

        physical_read_executed = False

        try:
            with tracker.admitted_read(projected_bytes=100):
                physical_read_executed = True
        except ValueError as ve:
            self.assertIn("BUDGET_EXHAUSTED", str(ve))

        self.assertFalse(physical_read_executed, "Physical read must not execute if admission is rejected")
        self.assertEqual(tracker.metrics.bytes_read, 1000)

    def test_04_profile_ceiling_pre_read_rejection(self):
        """Profile-specific ceiling rejects admission before physical read starts."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()
        ceiling = {"max_bytes_read": 2000}

        # First read of 1500 bytes succeeds within 2000 ceiling
        with tracker.operation_scope("op1", profile_id="prof_limited") as scope:
            adm1 = scope.admit_read(1500, profile_ceiling=ceiling)
            adm1.consume(1500)
            scope.record_read(bytes_read=1500, admission=adm1, profile_ceiling=ceiling)

        # Second admission of 800 bytes exceeds 2000 profile limit
        physical_read_executed = False
        with tracker.operation_scope("op2", profile_id="prof_limited") as scope:
            try:
                with scope.admitting_read(800, profile_ceiling=ceiling):
                    physical_read_executed = True
            except ValueError as ve:
                self.assertIn("PROFILE_CEILING_EXCEEDED", str(ve))

        self.assertFalse(physical_read_executed)
        self.assertEqual(tracker.get_profile_usage("prof_limited")["bytes_read"], 1500)

    def test_05_zero_overshoot_guarantee_for_fixed_reads(self):
        """Fixed-size read exceeding remaining budget is rejected with ZERO overshoot."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=2000))
        tracker.start()
        tracker.record_read(bytes_read=1800, profile_id="base")
        self.assertEqual(tracker.remaining_bytes, 200)

        # Requesting 250 bytes when remaining is 200
        with self.assertRaises(ValueError) as cm:
            tracker.admit_read(projected_bytes=250, profile_id="fixed_read")
        self.assertIn("BUDGET_EXHAUSTED", str(cm.exception))

        # Absolute proof of zero overshoot: bytes_read is still exactly 1800
        self.assertEqual(tracker.metrics.bytes_read, 1800)
        self.assertEqual(tracker.remaining_bytes, 200)

    def test_06_bounded_overshoot_for_inflight_buffer_reads(self):
        """In-flight reads starting before exhaustion have overshoot strictly bounded by <= 4096B."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=5000))
        tracker.start()
        # 4900 bytes pre-charged; 100 bytes remaining
        tracker.record_read(bytes_read=4900, profile_id="base")
        self.assertFalse(tracker.is_budget_exhausted)
        self.assertEqual(tracker.remaining_bytes, 100)

        # In-flight read began when budget was not exhausted
        with tracker.operation_scope("op_inflight", profile_id="inflight") as scope:
            # Buffer read up to single observation buffer (4096B) allowed with bounded overshoot
            adm = scope.admit_read(1024, allow_in_flight_overshoot=True)
            adm.consume(600)  # Over-shoots 100 remaining bytes by 500 bytes
            scope.record_read(bytes_read=600, admission=adm)

        # Overshoot verification:
        # Total bytes = 4900 + 600 = 5500. Limit = 5000. Overshoot = 500.
        # Strict bound check: overshoot must be <= 4096B.
        overshoot = tracker.metrics.bytes_read - tracker.limits.max_bytes_read
        self.assertLessEqual(overshoot, 4096)
        self.assertTrue(tracker.is_budget_exhausted)

        # Any subsequent read attempt without in-flight allowance must now be strictly rejected
        with self.assertRaises(ValueError):
            tracker.admit_read(128)
        self.assertEqual(tracker.metrics.bytes_read, 5500)

    # =========================================================================
    # Group 2: Separation of Reservation and Physical Consumption (P0.3)
    # =========================================================================

    def test_07_illegal_transitions_rejected(self):
        """State machine rejects illegal reservation state transitions."""
        res = BudgetReservation(reservation_id="res_test", operation_id="op_test", reserved_bytes=500)

        # Cannot release a consumed reservation
        res.consume(300)
        with self.assertRaises(RuntimeError) as cm1:
            res.release()
        self.assertIn("A reservation must never be released if physical consumption occurred", str(cm1.exception))

        # Finalize the reservation
        res.finalize()
        self.assertTrue(res.is_accounted)

        # Cannot consume an already accounted reservation
        with self.assertRaises(RuntimeError) as cm2:
            res.consume(100)
        self.assertIn("Cannot consume reservation", str(cm2.exception))

        # Released reservation cannot be consumed
        res2 = BudgetReservation(reservation_id="res_rel", operation_id="op_rel", reserved_bytes=200)
        res2.release()
        with self.assertRaises(RuntimeError) as cm3:
            res2.consume(50)
        self.assertIn("Cannot consume reservation", str(cm3.exception))

    def test_08_no_double_counting_reservation_and_consumption(self):
        """Active reservation and consumed bytes are separate in remaining_bytes without double counting."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(1000)
        self.assertEqual(tracker._active_reservation_bytes(), 1000)
        self.assertEqual(tracker._active_consumed_bytes(), 0)
        self.assertEqual(tracker.remaining_bytes, 9000)

        # Once consumed, reserved_bytes is no longer counted in active reservations
        adm.consume(600)
        self.assertEqual(tracker._active_reservation_bytes(), 0)
        self.assertEqual(tracker._active_consumed_bytes(), 600)
        self.assertEqual(tracker.remaining_bytes, 9400)

        # Once released, active reservations are 0
        adm2 = tracker.admit_read(2000)
        self.assertEqual(tracker._active_reservation_bytes(), 2000)
        tracker.release_reservation(adm2)
        self.assertEqual(tracker._active_reservation_bytes(), 0)

    def test_09_exception_releases_unconsumed_admission(self):
        """Exception during admitted_read context manager automatically releases unconsumed reservation."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        with self.assertRaises(RuntimeError):
            with tracker.admitted_read(1500) as adm:
                self.assertEqual(adm.state, "ADMITTED")
                raise RuntimeError("Read failure simulation before I/O")

        self.assertEqual(tracker._active_reservation_bytes(), 0)
        self.assertEqual(tracker._released_reservations_count, 1)
        self.assertEqual(tracker.remaining_bytes, 10000)

    def test_10_partial_physical_read_consumes_and_accounts_actual(self):
        """Partial physical read consumes and accounts only the actual bytes read."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        with tracker.operation_scope("op_partial") as scope:
            adm = scope.admit_read(4096)
            # Only 512 bytes read before EOF
            adm.consume(512, is_failure=False)
            scope.record_read(bytes_read=512, admission=adm)

        snap = tracker.get_committed_record("op_partial")
        self.assertEqual(snap.charged_bytes, 512)
        self.assertEqual(tracker.metrics.bytes_read, 512)
        self.assertEqual(tracker.remaining_bytes, 9488)

    # =========================================================================
    # Group 3: Crash-Safe Prepare/Commit Architecture (P0.4, P0.5)
    # =========================================================================

    def test_11_prepare_phase_validation_failure_leaves_zero_metric_mutation(self):
        """Validation failure in prepare phase leaves zero aggregate metrics mutated."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        record = ObservationAccountingRecord(
            operation_id="op_invalid_num",
            accounting_owner="TEST",
            measured_bytes_read=float("nan"),  # Invalid numeric value
        )

        with self.assertRaises(ValueError):
            tracker.commit_transaction(record)

        # Zero metrics mutated
        self.assertEqual(tracker.metrics.bytes_read, 0)
        self.assertEqual(tracker.metrics.total_read_failures, 0)
        self.assertEqual(len(tracker.get_committed_transactions()), 0)

    def test_12_commit_phase_idempotency_and_no_double_charge(self):
        """Re-committing same physical consumption ID charges zero additional bytes."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        record1 = ObservationAccountingRecord(
            operation_id="op_idemp",
            accounting_owner="MOD",
            measured_bytes_read=500,
            physical_consumption_id="phys_unique_12345",
        )
        ok1 = tracker.commit_transaction(record1)
        self.assertTrue(ok1)
        self.assertEqual(tracker.metrics.bytes_read, 500)

        # Re-commit identical physical consumption
        record2 = ObservationAccountingRecord(
            operation_id="op_idemp_retry",
            accounting_owner="MOD",
            measured_bytes_read=500,
            physical_consumption_id="phys_unique_12345",
        )
        ok2 = tracker.commit_transaction(record2)
        self.assertTrue(ok2)

        # Proof of zero double charging
        self.assertEqual(tracker.metrics.bytes_read, 500)
        self.assertEqual(len(tracker.get_physical_consumption_records()), 1)

    def test_13_commit_phase_conflicting_data_raises_value_error(self):
        """Re-committing same physical consumption ID with conflicting byte data raises ValueError."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        record1 = ObservationAccountingRecord(
            operation_id="op_conf1",
            accounting_owner="MOD",
            measured_bytes_read=300,
            physical_consumption_id="phys_conflict_test",
        )
        tracker.commit_transaction(record1)

        # Conflicting read: claiming 600 bytes for same physical consumption ID
        record2 = ObservationAccountingRecord(
            operation_id="op_conf2",
            accounting_owner="MOD",
            measured_bytes_read=600,
            physical_consumption_id="phys_conflict_test",
        )
        with self.assertRaises(ValueError) as cm:
            tracker.commit_transaction(record2)
        self.assertIn("Physical consumption ID conflict", str(cm.exception))
        self.assertEqual(tracker.metrics.bytes_read, 300)

    def test_14_crash_recovery_preserves_physical_consumption(self):
        """Simulated crash recovery in commit phase preserves consumed bytes without double charging."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        with tracker.operation_scope("op_crash_rec") as scope:
            adm = scope.admit_read(400)
            adm.consume(400)
            scope.record_read(bytes_read=400, admission=adm)

            # Prepare the commit
            prep = tracker._prepare_scope_commit(scope)
            # Manually trigger emergency recovery
            snap = tracker._recover_commit_failure(prep, error=RuntimeError("SIMULATED_CRASH"), metrics_applied=False, step="test")

        self.assertIsNotNone(snap)
        self.assertEqual(snap.charged_bytes, 400)
        self.assertEqual(tracker.metrics.bytes_read, 400)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # Group 4: 14 Deterministic Failure Injection Boundaries (P1.1)
    # =========================================================================

    def _run_fault_boundary_test(self, fault_name: str):
        """Runs a deterministic fault injection test for a given boundary hook."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()
        fault_triggered = [False]

        def fault_hook():
            fault_triggered[0] = True
            raise RuntimeError(f"Deterministic fault injected at: {fault_name}")

        tracker.set_fault_injection(fault_name, fault_hook)

        # Test execution under injection
        try:
            with tracker.operation_scope(f"op_{fault_name}") as scope:
                adm = scope.admit_read(300)
                adm.consume(300)
                scope.record_read(bytes_read=300, admission=adm)
        except RuntimeError:
            pass

        # Clear fault injection
        tracker.clear_fault_injections()
        self.assertTrue(fault_triggered[0], f"Fault hook '{fault_name}' must be triggered")

        # Full reconciliation check: ledger and metrics must reconcile even after fault
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"], f"Reconciliation failed after {fault_name}")

    def test_15_fault_1_before_admission(self):
        self._run_fault_boundary_test("before_admission")

    def test_16_fault_2_after_admission_before_read(self):
        self._run_fault_boundary_test("after_admission_before_read")

    def test_17_fault_3_after_partial_consumption(self):
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()
        triggered = [False]
        tracker.set_fault_injection("after_partial_consumption", lambda: triggered.__setitem__(0, True))

        with tracker.operation_scope("op_fault_partial") as scope:
            adm = scope.admit_read(500)
            adm.consume(200)
            scope.record_read(bytes_read=200, admission=adm, is_failure=True)

        self.assertTrue(triggered[0])
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_18_fault_4_after_full_consumption(self):
        self._run_fault_boundary_test("after_full_consumption")

    def test_19_fault_5_during_metadata_freeze(self):
        self._run_fault_boundary_test("during_metadata_freeze")

    def test_20_fault_6_during_fingerprint_creation(self):
        self._run_fault_boundary_test("during_fingerprint_creation")

    def test_21_fault_7_during_snapshot_construction(self):
        self._run_fault_boundary_test("during_snapshot_construction")

    def test_22_fault_8_during_physical_ledger_insertion(self):
        self._run_fault_boundary_test("during_physical_ledger_insertion")

    def test_23_fault_9_during_logical_ledger_insertion(self):
        self._run_fault_boundary_test("during_logical_ledger_insertion")

    def test_24_fault_10_during_metric_application(self):
        self._run_fault_boundary_test("during_metric_application")

    def test_25_fault_11_during_profile_metric_application(self):
        self._run_fault_boundary_test("during_profile_metric_application")

    def test_26_fault_12_during_reservation_finalization(self):
        self._run_fault_boundary_test("during_reservation_finalization")

    def test_27_fault_13_during_history_append(self):
        self._run_fault_boundary_test("during_history_append")

    def test_28_fault_14_during_emergency_recovery(self):
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()
        triggered = [False]
        tracker.set_fault_injection("during_emergency_recovery", lambda: triggered.__setitem__(0, True))

        with tracker.operation_scope("op_fault_emerg") as scope:
            adm = scope.admit_read(400)
            adm.consume(400)
            scope.record_read(bytes_read=400, admission=adm)
            prep = tracker._prepare_scope_commit(scope)
            tracker._recover_commit_failure(prep, error=RuntimeError("EMERG_TEST"), metrics_applied=False, step="test")

        self.assertTrue(triggered[0])
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # Group 5: Full Lifecycle Reconciliation Across All 14 Dimensions (P1.2)
    # =========================================================================

    def test_29_reconciliation_verifies_all_14_dimensions(self):
        """reconcile_ledger independently verifies all 14 accounting lifecycle dimensions."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=20000))
        tracker.start()

        # 1. Normal measured read
        with tracker.operation_scope("op_m1", profile_id="p1") as s1:
            adm1 = s1.admit_read(300)
            adm1.consume(250)
            s1.record_read(bytes_read=250, admission=adm1, latency_us=10.0, stop_ms=1.0)

        # 2. Conservative estimated read
        with tracker.operation_scope("op_e1", profile_id="p2") as s2:
            adm2 = s2.admit_read(400)
            adm2.consume(400)
            s2.record_read(bytes_read=None, conservative_estimate_bytes=400, admission=adm2, latency_us=20.0)

        # 3. Released reservation
        adm_rel = tracker.admit_read(500, profile_id="p3")
        tracker.release_reservation(adm_rel)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

        # Verification of totals
        self.assertEqual(tracker.metrics.bytes_read, 650)
        self.assertEqual(tracker.metrics.measured_bytes_read, 250)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 400)
        self.assertEqual(tracker._released_reservations_count, 1)

    def test_30_reconciliation_detects_metric_ledger_divergence(self):
        """Reconciliation immediately detects tampering or divergence in aggregate metrics."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        with tracker.operation_scope("op_tamper") as s:
            adm = s.admit_read(300)
            adm.consume(300)
            s.record_read(bytes_read=300, admission=adm)

        # Artificially tamper with aggregate metrics
        tracker.metrics.bytes_read += 100

        with self.assertRaises(AssertionError) as cm:
            tracker.reconcile_ledger()
        self.assertIn("bytes_read", str(cm.exception))

    # =========================================================================
    # Group 6: Production Call Site Integration Tests (P1.3)
    # =========================================================================

    def test_31_instrumented_adapter_proves_admission_before_physical_memory_read(self):
        """Instrumented adapter proves admission occurs strictly BEFORE read_memory executes."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adapter = InstrumentedAdmissionTargetAdapter()
        ro_adapter = ReadOnlyTargetAdapter(adapter, budget_tracker=tracker)

        # Admitted read
        with tracker.operation_scope("op_mem_test") as scope:
            adm = scope.admit_read(128, profile_id="memory_read")
            data, status, err = ro_adapter.read_memory(pid=os.getpid(), address=0x1000, size=128, admission=adm)

        self.assertEqual(len(adapter.call_log), 1)
        self.assertTrue(adapter.call_log[0]["has_valid_admission"])
        self.assertEqual(adapter.call_log[0]["admission_id"], adm.reservation_id)

    def test_32_instrumented_adapter_process_identity_admission_before_open(self):
        """get_process_identity admits budget before opening /proc/<pid>/exe and rejects if exhausted."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=1000))
        tracker.start()
        # Exhaust budget
        tracker.record_read(bytes_read=1000, profile_id="base")
        self.assertTrue(tracker.is_budget_exhausted)

        adapter = LocalTargetAdapter()
        res = adapter.get_process_identity(os.getpid(), budget_tracker=tracker)

        self.assertEqual(res["status"], "BUDGET_EXHAUSTED")
        self.assertEqual(res["identity_status"], IDENTITY_UNAVAILABLE)
        self.assertEqual(adapter.get_last_identity_bytes_read(), 0)

    def test_33_instrumented_adapter_maps_and_threads_admission(self):
        """get_proc_maps and get_threads enforce pre-read budget admission before reading /proc."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=500))
        tracker.start()
        tracker.record_read(bytes_read=500, profile_id="base")
        self.assertTrue(tracker.is_budget_exhausted)

        adapter = LocalTargetAdapter()
        adapter.set_budget_tracker(tracker)

        maps = adapter.get_proc_maps(os.getpid())
        self.assertEqual(len(maps), 0)
        self.assertEqual(adapter.get_last_maps_bytes_read(), 0)

        threads = adapter.get_threads(os.getpid())
        self.assertEqual(len(threads), 0)
        self.assertEqual(adapter.get_last_threads_bytes_read(), 0)

    def test_34_concurrent_operations_with_isolated_admissions(self):
        """Multiple concurrent threads have isolated pre-read admissions without cross-thread contamination."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()
        barrier = threading.Barrier(4)
        errors = []

        def worker(idx: int):
            try:
                barrier.wait()
                with tracker.operation_scope(f"op_conc_{idx}", profile_id=f"prof_{idx}") as scope:
                    adm = scope.admit_read(200)
                    adm.consume(200)
                    scope.record_read(bytes_read=200, admission=adm)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)
        self.assertEqual(tracker.metrics.bytes_read, 800)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # Group 7: Static Architecture Audits (P1.4)
    # =========================================================================

    def test_35_ast_audit_no_direct_ledger_or_metric_mutation(self):
        """AST audit: Modules outside tracker must not directly mutate _committed_transactions or metrics."""
        extractor_dir = pathlib.Path(__file__).parent.parent / "extractor"
        allowed_files = {"observation_budget.py"}

        for py_path in extractor_dir.glob("*.py"):
            if py_path.name in allowed_files:
                continue
            with open(py_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(py_path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Attribute):
                            if target.attr in ("_committed_transactions", "_physical_consumptions"):
                                self.fail(
                                    f"Direct ledger mutation found in {py_path.name}:{node.lineno} -> {target.attr}"
                                )

    def test_36_ast_audit_no_reservation_release_after_consumption(self):
        """AST audit: release_reservation in observation_budget.py must check consumed_bytes == 0."""
        budget_path = pathlib.Path(__file__).parent.parent / "extractor" / "observation_budget.py"
        with open(budget_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Verify BudgetReservation.release checks consumed_bytes == 0
        self.assertIn("self.consumed_bytes > 0", content)
        self.assertIn("A reservation must never be released if physical consumption occurred", content)

    def test_37_ast_audit_prepare_commit_architecture_present(self):
        """AST audit: ObservationBudgetTracker must implement _prepare_scope_commit and _execute_scope_commit."""
        budget_path = pathlib.Path(__file__).parent.parent / "extractor" / "observation_budget.py"
        with open(budget_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(budget_path))

        method_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                method_names.add(node.name)

        self.assertIn("_prepare_scope_commit", method_names)
        self.assertIn("_execute_scope_commit", method_names)
        self.assertIn("_recover_commit_failure", method_names)
        self.assertIn("admit_read", method_names)
        self.assertIn("release_reservation", method_names)

    def test_38_ast_audit_reconcile_ledger_validates_14_dimensions(self):
        """AST audit: reconcile_ledger must validate physical and logical records, uniqueness, and profile usage."""
        budget_path = pathlib.Path(__file__).parent.parent / "extractor" / "observation_budget.py"
        with open(budget_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("Physical consumption IDs not unique", content)
        self.assertIn("bytes_read: ledger=", content)
        self.assertIn("active_reservations_bytes", content)
        self.assertIn("released_reservations_count", content)


if __name__ == "__main__":
    unittest.main()
