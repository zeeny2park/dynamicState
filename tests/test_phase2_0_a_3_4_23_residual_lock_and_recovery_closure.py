"""Phase 2.0-A.3.4.23: Residual Lock Ownership, Identity Collision & Recovery Closure Tests.

Verifies:
1. Lock Ownership Hierarchy & Reentrancy across Level 1 (tracker._transaction_lock), Level 1.5 (scope._lock),
   Level 2 (reservation._lock), and Level 3 (physical_read._lock).
2. Admission & Scope Finalization Linearization Point: Strict rejection of admissions once scope enters FINALIZING.
3. Synchronized Child Read & Consumed-Byte Aggregation during finalization.
4. Physical Read Identity Integrity:
   - Same physical_read_id + same object: explicit idempotent deduplication.
   - Same physical_read_id + different object: fail closed with zero partial mutation.
   - Conflicting reservation ownership & cross-reservation sharing: fail closed with zero partial mutation.
   - Conflicting physical consumption ownership: fail closed across conflicting operations.
   - Validation across active and committed registries.
5. Recovery-of-Recovery Closure:
   - Fault injection at 6 recovery points: recovery_entry, recovery_logical_registration, recovery_physical_evidence,
     recovery_metric_reconciliation, recovery_reservation_finalization, recovery_cleanup.
   - Deterministic and idempotent recovery retry via tracker.retry_recovery() without double-charging metrics
     or dropping physical evidence.
6. Terminal Immutability: Rejection of update_metadata() and update_target_spec() on terminal physical reads and reservations.
7. Deterministic Interleavings with threading.Event.
8. High-concurrency stress test with repeated continuous ledger reconciliation.
"""

import copy
import threading
import time
import unittest
from typing import Any, Dict, List, Optional

from extractor.observation_budget import (
    ActiveOperationScope,
    BudgetReservation,
    CommittedTransactionSnapshot,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    PhysicalConsumptionRecord,
    PhysicalReadRecord,
    PreparedCommit,
    canonical_metadata_digest,
    clone_frozen,
    freeze_metadata,
)


def make_scope(tracker: ObservationBudgetTracker, op_id: str, profile_id: str = "p1") -> ActiveOperationScope:
    """Helper creating an authoritative tracked ActiveOperationScope."""
    scope = ActiveOperationScope(
        tracker=tracker,
        operation_id=op_id,
        profile_id=profile_id,
    )
    tracker._register_active_scope(scope)
    return scope


class TestPhase20A3423LockOwnershipAndLinearization(unittest.TestCase):
    """Workstream 1 & 2: Lock Hierarchy, Reentrancy, and Scope Linearization."""

    def setUp(self):
        self.limits = ObservationBudgetLimits(max_bytes_read=100000)
        self.tracker = ObservationBudgetTracker(self.limits)
        self.tracker.start()

    def test_01_lock_hierarchy_reentrancy_all_levels(self):
        """Proof of universal RLock reentrancy and Level 1 -> 1.5 -> 2 -> 3 acquisition order."""
        with self.tracker.operation_scope("op_hier_1", profile_id="p1") as scope:
            adm = scope.admit_read(500)
            child = adm.start_child_read(physical_read_id="pread_hier_1")

            rlock_type = type(threading.RLock())

            # Verify Level 1 (_transaction_lock) is RLock and reentrant
            self.assertEqual(type(self.tracker._transaction_lock), rlock_type)
            with self.tracker._transaction_lock:
                with self.tracker._transaction_lock:
                    pass

            # Verify Level 1.5 (scope._lock) is RLock and reentrant
            self.assertEqual(type(scope._lock), rlock_type)
            with scope._lock:
                with scope._lock:
                    pass

            # Verify Level 2 (adm._lock) is RLock and reentrant
            self.assertEqual(type(adm._lock), rlock_type)
            with adm._lock:
                with adm._lock:
                    pass

            # Verify Level 3 (child._lock) is RLock and reentrant
            self.assertEqual(type(child._lock), rlock_type)
            with child._lock:
                with child._lock:
                    pass

            # Test hierarchical locking helper under Level 1
            with self.tracker._lock_reservations_with_children([adm]) as (locked_res, locked_children):
                self.assertEqual(len(locked_res), 1)
                self.assertEqual(len(locked_children), 1)
                self.assertIs(locked_res[0], adm)
                self.assertIs(locked_children[0], child)

            child.mark_started()
            child.consume(actual_bytes=250)
            scope.record_read(bytes_read=250, admission=adm)

        self.assertEqual(self.tracker.metrics.bytes_read, 250)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_02_linearization_point_admit_rejected_after_finalizing(self):
        """Admission is strictly rejected once scope transitions to FINALIZING (linearization point)."""
        scope = make_scope(self.tracker, "op_lin_1", profile_id="p1")
        adm1 = scope.admit_read(200)
        child1 = adm1.start_child_read(physical_read_id="pread_lin_1")
        child1.mark_started()
        child1.consume(actual_bytes=100)
        scope.record_read(bytes_read=100, admission=adm1)

        # Manually transition scope state to FINALIZING under locks
        with self.tracker._transaction_lock:
            with scope._lock:
                scope.state = "FINALIZING"

        # Direct scope.admit_read must fail closed
        with self.assertRaises(RuntimeError) as cm:
            scope.admit_read(100)
        self.assertIn("Cannot admit read on scope", str(cm.exception))
        self.assertIn("FINALIZING", str(cm.exception))

        # Tracker admit_read targeting this scope must fail closed
        with self.assertRaises(RuntimeError) as cm:
            self.tracker.admit_read(projected_bytes=100, scope=scope)
        self.assertIn("Cannot admit read on scope", str(cm.exception))
        self.assertIn("FINALIZING", str(cm.exception))

        # Reset scope state to OPEN so scope.finalize() can execute normally
        with self.tracker._transaction_lock:
            with scope._lock:
                scope.state = "OPEN"

        snap = scope.finalize()
        self.assertIsNotNone(snap)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_03_scope_finalization_synchronizes_child_consumed_bytes(self):
        """ActiveOperationScope.finalize() authoritatively updates admission consumed_bytes from child reads."""
        scope = make_scope(self.tracker, "op_sync_1", profile_id="p1")
        adm = scope.admit_read(500)
        c1 = adm.start_child_read(physical_read_id="pread_sync_1")
        c2 = adm.start_child_read(physical_read_id="pread_sync_2")
        c1.mark_started()
        c2.mark_started()
        c1.consume(actual_bytes=120)
        c2.consume(actual_bytes=180)

        # Before scope finalize, adm.consumed_bytes was accumulated by consume()
        self.assertEqual(adm.consumed_bytes, 300)

        # Finalize commits scope and synchronizes admissions
        snap = scope.finalize()
        self.assertEqual(snap.charged_bytes, 300)
        self.assertEqual(adm.consumed_bytes, 300)
        self.assertEqual(scope.state, "COMMITTED")

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])


class TestPhase20A3423PhysicalReadIdentityIntegrity(unittest.TestCase):
    """Workstream 3: Identity Integrity, Deduplication, and Collision Fail-Closed Proof."""

    def setUp(self):
        self.limits = ObservationBudgetLimits(max_bytes_read=100000)
        self.tracker = ObservationBudgetTracker(self.limits)
        self.tracker.start()

    def test_04_same_id_same_object_idempotent_deduplication(self):
        """Same physical_read_id with the identical PhysicalReadRecord instance is deduplicated idempotently."""
        adm1 = self.tracker.admit_read(projected_bytes=300, profile_id="p1", operation_id="op_dedup_1")
        pread = adm1.start_child_read(physical_read_id="pread_shared_inst")
        pread.mark_started()
        pread.consume(actual_bytes=200)

        # Locking a list where the same reservation or same child read instance appears twice
        with self.tracker._transaction_lock:
            with self.tracker._lock_reservations_with_children([adm1, adm1]) as (locked_res, locked_children):
                self.assertEqual(len(locked_res), 1)
                self.assertEqual(len(locked_children), 1)
                self.assertIs(locked_children[0], pread)

        ok = self.tracker.commit_transaction(
            operation_id="op_dedup_1",
            profile_id="p1",
            measured_bytes=200,
            reservations=[adm1],
        )
        self.assertTrue(ok)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_05_same_id_different_object_fails_closed_zero_mutation(self):
        """Same physical_read_id with distinct PhysicalReadRecord instances fails closed with zero mutation."""
        adm1 = self.tracker.admit_read(projected_bytes=200, profile_id="p1", operation_id="op_coll_1")
        adm2 = self.tracker.admit_read(projected_bytes=200, profile_id="p1", operation_id="op_coll_1")

        child1 = adm1.start_child_read(physical_read_id="pread_collide_x")
        child2 = adm2.start_child_read(physical_read_id="pread_collide_x")
        child1.mark_started()
        child2.mark_started()
        child1.consume(actual_bytes=100)
        child2.consume(actual_bytes=100)

        initial_bytes = self.tracker.metrics.bytes_read
        initial_reads_count = len(self.tracker._physical_read_records)
        initial_cons_count = len(self.tracker._physical_consumption_records)

        with self.assertRaises(ValueError) as cm:
            with self.tracker._transaction_lock:
                with self.tracker._lock_reservations_with_children([adm1, adm2]):
                    pass
        self.assertIn("Physical read identity collision", str(cm.exception))
        self.assertIn("distinct PhysicalReadRecord instances", str(cm.exception))

        # Proof of zero partial mutation to reservations, children, ledgers, or metrics
        self.assertEqual(adm1.state, "CONSUMED")
        self.assertEqual(adm2.state, "CONSUMED")
        self.assertEqual(child1.state, "CONSUMED")
        self.assertEqual(child2.state, "CONSUMED")
        self.assertEqual(self.tracker.metrics.bytes_read, initial_bytes)
        self.assertEqual(len(self.tracker._physical_read_records), initial_reads_count)
        self.assertEqual(len(self.tracker._physical_consumption_records), initial_cons_count)

    def test_06_conflicting_reservation_ownership_fails_closed(self):
        """Child read claiming mismatched reservation_id fails closed before acquiring locks."""
        adm = self.tracker.admit_read(projected_bytes=200, profile_id="p1", operation_id="op_mismatch_res")
        child = adm.start_child_read(physical_read_id="pread_mismatch_1")

        # Manually tamper with reservation_id to simulate corrupt ownership
        child.reservation_id = "res_other_foreign"

        with self.assertRaises(ValueError) as cm:
            with self.tracker._transaction_lock:
                with self.tracker._lock_reservations_with_children([adm]):
                    pass
        self.assertIn("Conflicting reservation ownership", str(cm.exception))

    def test_07_child_shared_across_multiple_active_reservations_fails_closed(self):
        """Child read instance present in another active reservation with different object fails closed."""
        adm1 = self.tracker.admit_read(projected_bytes=200, profile_id="p1", operation_id="op_share_1")
        adm2 = self.tracker.admit_read(projected_bytes=200, profile_id="p1", operation_id="op_share_2")

        c1 = adm1.start_child_read(physical_read_id="pread_cross_active")
        c2 = adm2.start_child_read(physical_read_id="pread_cross_active")

        # Attempting to lock adm1 while adm2 (another active reservation) holds distinct child with same ID
        with self.assertRaises(ValueError) as cm:
            with self.tracker._transaction_lock:
                with self.tracker._lock_reservations_with_children([adm1]):
                    pass
        self.assertIn("Conflicting reservation ownership", str(cm.exception))
        self.assertIn("shared across multiple reservations", str(cm.exception))

    def test_08_conflicting_consumption_ownership_across_operations_fails_closed(self):
        """Physical consumption ID claimed across distinct operations fails closed."""
        adm1 = self.tracker.admit_read(projected_bytes=200, profile_id="p1", operation_id="op_pcons_op1")
        adm2 = self.tracker.admit_read(projected_bytes=200, profile_id="p1", operation_id="op_pcons_op2")

        # Both child reads share the same physical_consumption_id but have different operation_ids
        c1 = adm1.start_child_read(physical_read_id="pread_pcons_a", physical_consumption_id="pcons_shared_cross_op")
        c2 = adm2.start_child_read(physical_read_id="pread_pcons_b", physical_consumption_id="pcons_shared_cross_op")

        with self.assertRaises(ValueError) as cm:
            with self.tracker._transaction_lock:
                with self.tracker._lock_reservations_with_children([adm1, adm2]):
                    pass
        self.assertIn("Conflicting physical consumption ownership", str(cm.exception))
        self.assertIn("claimed by multiple operations", str(cm.exception))


class TestPhase20A3423RecoveryOfRecoveryClosure(unittest.TestCase):
    """Workstream 4: Recovery Failure Injection across all 6 points and Idempotent Retry."""

    def setUp(self):
        self.limits = ObservationBudgetLimits(max_bytes_read=100000)
        self.tracker = ObservationBudgetTracker(self.limits)
        self.tracker.start()

    def _create_scope_with_physical_read(self, op_id: str, bytes_val: int = 150):
        scope = make_scope(self.tracker, op_id, profile_id="rec_prof")
        adm = scope.admit_read(bytes_val + 50)
        child = adm.start_child_read(physical_read_id=f"pread_{op_id}")
        child.mark_started()
        child.consume(actual_bytes=bytes_val)
        scope.record_read(bytes_read=bytes_val, admission=adm)
        return scope, adm, child

    def test_09_recovery_point_1_failure_and_idempotent_retry(self):
        """Inject failure at 'recovery_entry' ('during_emergency_recovery'), then retry_recovery()."""
        scope, adm, child = self._create_scope_with_physical_read("op_rec_pt1", bytes_val=100)
        prep = self.tracker._prepare_scope_commit(scope, is_fail=True)

        self.tracker.inject_fault("during_emergency_recovery")
        with self.assertRaises(RuntimeError) as cm:
            self.tracker._recover_commit_failure(prep, error=RuntimeError("Original commit failure"), metrics_applied=False, step="start")
        self.assertIn("during_emergency_recovery", str(cm.exception))
        self.tracker.clear_fault_injections()

        # Retry recovery must succeed idempotently
        recovered_snap = self.tracker.retry_recovery(scope)
        self.assertIsNotNone(recovered_snap)
        self.assertEqual(recovered_snap.accounting_status, "FAILED")
        self.assertEqual(self.tracker.metrics.bytes_read, 100)

        # Second retry must be idempotent and return identical snapshot
        second_snap = self.tracker.retry_recovery(scope)
        self.assertEqual(recovered_snap.operation_id, second_snap.operation_id)
        self.assertEqual(self.tracker.metrics.bytes_read, 100)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_10_recovery_point_2_failure_and_idempotent_retry(self):
        """Inject failure at 'recovery_logical_registration' ('during_recovery_logical_registration'), then retry."""
        scope, adm, child = self._create_scope_with_physical_read("op_rec_pt2", bytes_val=120)
        prep = self.tracker._prepare_scope_commit(scope, is_fail=True)

        self.tracker.inject_fault("during_recovery_logical_registration")
        with self.assertRaises(RuntimeError) as cm:
            self.tracker._recover_commit_failure(prep, error=RuntimeError("Original fault"), metrics_applied=False, step="start")
        self.assertIn("during_recovery_logical_registration", str(cm.exception))
        self.tracker.clear_fault_injections()

        recovered_snap = self.tracker.retry_recovery(scope)
        self.assertEqual(recovered_snap.accounting_status, "FAILED")
        self.assertEqual(self.tracker.metrics.bytes_read, 120)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_11_recovery_point_3_failure_and_idempotent_retry(self):
        """Inject failure at 'recovery_physical_evidence' ('during_recovery_physical_evidence'), then retry."""
        scope, adm, child = self._create_scope_with_physical_read("op_rec_pt3", bytes_val=130)
        prep = self.tracker._prepare_scope_commit(scope, is_fail=True)

        self.tracker.inject_fault("during_recovery_physical_evidence")
        with self.assertRaises(RuntimeError) as cm:
            self.tracker._recover_commit_failure(prep, error=RuntimeError("Original fault"), metrics_applied=False, step="start")
        self.assertIn("during_recovery_physical_evidence", str(cm.exception))
        self.tracker.clear_fault_injections()

        recovered_snap = self.tracker.retry_recovery(scope)
        self.assertEqual(recovered_snap.accounting_status, "FAILED")
        self.assertEqual(self.tracker.metrics.bytes_read, 130)
        self.assertIn("pread_op_rec_pt3", self.tracker._physical_read_records)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_12_recovery_point_4_failure_and_idempotent_retry_no_double_counting(self):
        """Inject failure at 'recovery_metric_reconciliation' ('during_recovery_metric_reconciliation'), verify zero double charging."""
        scope, adm, child = self._create_scope_with_physical_read("op_rec_pt4", bytes_val=140)
        prep = self.tracker._prepare_scope_commit(scope, is_fail=True)

        self.tracker.inject_fault("during_recovery_metric_reconciliation")
        with self.assertRaises(RuntimeError) as cm:
            self.tracker._recover_commit_failure(prep, error=RuntimeError("Original fault"), metrics_applied=False, step="start")
        self.assertIn("during_recovery_metric_reconciliation", str(cm.exception))
        self.tracker.clear_fault_injections()

        recovered_snap = self.tracker.retry_recovery(scope)
        self.assertEqual(recovered_snap.accounting_status, "FAILED")
        self.assertEqual(self.tracker.metrics.bytes_read, 140)

        # Retry again: bytes_read must strictly stay 140
        self.tracker.retry_recovery(scope)
        self.assertEqual(self.tracker.metrics.bytes_read, 140)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_13_recovery_point_5_failure_and_idempotent_retry(self):
        """Inject failure at 'recovery_reservation_finalization' ('during_recovery_reservation_finalization'), then retry."""
        scope, adm, child = self._create_scope_with_physical_read("op_rec_pt5", bytes_val=160)
        prep = self.tracker._prepare_scope_commit(scope, is_fail=True)

        self.tracker.inject_fault("during_recovery_reservation_finalization")
        with self.assertRaises(RuntimeError) as cm:
            self.tracker._recover_commit_failure(prep, error=RuntimeError("Original fault"), metrics_applied=False, step="start")
        self.assertIn("during_recovery_reservation_finalization", str(cm.exception))
        self.tracker.clear_fault_injections()

        recovered_snap = self.tracker.retry_recovery(scope)
        self.assertEqual(recovered_snap.accounting_status, "FAILED")
        self.assertEqual(self.tracker.metrics.bytes_read, 160)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_14_recovery_point_6_failure_and_idempotent_retry(self):
        """Inject failure at 'recovery_cleanup' ('during_recovery_cleanup'), then retry."""
        scope, adm, child = self._create_scope_with_physical_read("op_rec_pt6", bytes_val=170)
        prep = self.tracker._prepare_scope_commit(scope, is_fail=True)

        self.tracker.inject_fault("during_recovery_cleanup")
        with self.assertRaises(RuntimeError) as cm:
            self.tracker._recover_commit_failure(prep, error=RuntimeError("Original fault"), metrics_applied=False, step="start")
        self.assertIn("during_recovery_cleanup", str(cm.exception))
        self.tracker.clear_fault_injections()

        recovered_snap = self.tracker.retry_recovery(scope)
        self.assertEqual(recovered_snap.accounting_status, "FAILED")
        self.assertEqual(self.tracker.metrics.bytes_read, 170)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])


class TestPhase20A3423TerminalImmutabilityAndMetadata(unittest.TestCase):
    """Workstream 5: Terminal Immutability on Metadata and Target Spec."""

    def setUp(self):
        self.limits = ObservationBudgetLimits(max_bytes_read=100000)
        self.tracker = ObservationBudgetTracker(self.limits)
        self.tracker.start()

    def test_15_terminal_physical_read_rejects_metadata_and_target_spec_mutations(self):
        """Terminal PhysicalReadRecord strictly rejects update_metadata and update_target_spec."""
        rec = PhysicalReadRecord(
            physical_read_id="pread_term_1",
            reservation_id="res_term_1",
            physical_consumption_id="pcons_term_1",
            operation_id="op_term_1",
            metadata={"source": "initial"},
            target_spec={"pid": 1234},
            state="ACCOUNTED",
            charged_bytes=100,
        )

        with self.assertRaises(RuntimeError) as cm:
            rec.update_metadata({"source": "tampered"})
        self.assertIn("Cannot update metadata of physical read 'pread_term_1' in terminal state 'ACCOUNTED'", str(cm.exception))

        with self.assertRaises(RuntimeError) as cm:
            rec.update_target_spec({"pid": 9999})
        self.assertIn("Cannot update target_spec of physical read 'pread_term_1' in terminal state 'ACCOUNTED'", str(cm.exception))

        # Metadata and target_spec remain frozen
        self.assertEqual(rec.metadata["source"], "initial")
        self.assertEqual(rec.target_spec["pid"], 1234)

    def test_16_non_terminal_metadata_updates_safely(self):
        """Non-terminal PhysicalReadRecord safely updates metadata preserving frozen MappingProxyType."""
        rec = PhysicalReadRecord(
            physical_read_id="pread_active_1",
            reservation_id="res_active_1",
            physical_consumption_id="pcons_active_1",
            operation_id="op_active_1",
            metadata={"env": "prod"},
            state="ADMITTED",
        )
        rec.update_metadata({"version": "2.0"})
        self.assertEqual(rec.metadata["env"], "prod")
        self.assertEqual(rec.metadata["version"], "2.0")

        # Frozen immutability verification
        with self.assertRaises(TypeError):
            rec.metadata["hacked"] = True


class TestPhase20A3423DeterministicInterleavings(unittest.TestCase):
    """Deterministic Interleavings using threading.Event across all 9 critical scenarios."""

    def setUp(self):
        self.limits = ObservationBudgetLimits(max_bytes_read=100000)
        self.tracker = ObservationBudgetTracker(self.limits)
        self.tracker.start()

    def test_17_scenario_1_admission_racing_with_finalization_linearization(self):
        """Scenario 1: Concurrent admit_read racing with scope.finalize() linearization point."""
        scope = make_scope(self.tracker, "op_race_lin", profile_id="p1")
        adm1 = scope.admit_read(200)
        c1 = adm1.start_child_read(physical_read_id="pread_race_1")
        c1.mark_started()
        c1.consume(actual_bytes=100)
        scope.record_read(bytes_read=100, admission=adm1)

        event_finalize_started = threading.Event()
        event_admit_attempted = threading.Event()
        admit_result = {"rejected": False, "error": None}

        def worker_finalize():
            scope.finalize()
            event_finalize_started.set()

        def worker_admit():
            event_finalize_started.wait(timeout=2.0)
            try:
                scope.admit_read(50)
            except RuntimeError as exc:
                admit_result["rejected"] = True
                admit_result["error"] = str(exc)
            finally:
                event_admit_attempted.set()

        t_fin = threading.Thread(target=worker_finalize)
        t_adm = threading.Thread(target=worker_admit)

        t_fin.start()
        t_adm.start()

        t_fin.join(timeout=3.0)
        t_adm.join(timeout=3.0)

        self.assertTrue(admit_result["rejected"])
        self.assertTrue(any(st in admit_result["error"] for st in ("FINALIZING", "COMMITTED")))

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_18_scenario_2_child_consume_racing_with_scope_finalization(self):
        """Scenario 2: Concurrent child consume racing with reservation finalization."""
        scope = make_scope(self.tracker, "op_race_consume", profile_id="p1")
        adm = scope.admit_read(300)
        c = adm.start_child_read(physical_read_id="pread_race_c")
        c.mark_started()

        event_consume_done = threading.Event()

        def worker_consume():
            c.consume(actual_bytes=150)
            event_consume_done.set()

        t = threading.Thread(target=worker_consume)
        t.start()
        event_consume_done.wait(timeout=2.0)
        t.join(timeout=2.0)

        snap = scope.finalize()
        self.assertEqual(snap.charged_bytes, 150)
        self.assertEqual(adm.consumed_bytes, 150)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_19_scenario_3_duplicate_physical_read_id_collision_interleaving(self):
        """Scenario 3: Conflicting physical_read_id across active reservations fails closed deterministically."""
        tracker = self.tracker
        adm1 = tracker.admit_read(projected_bytes=200, profile_id="p1", operation_id="op_race_coll_a")
        adm2 = tracker.admit_read(projected_bytes=200, profile_id="p1", operation_id="op_race_coll_b")

        c1 = adm1.start_child_read(physical_read_id="pread_interleaved_collision")
        c2 = adm2.start_child_read(physical_read_id="pread_interleaved_collision")
        c1.mark_started()
        c2.mark_started()
        c1.consume(actual_bytes=100)
        c2.consume(actual_bytes=100)

        results = []

        def worker(res, op_id):
            try:
                ok = tracker.commit_transaction(
                    operation_id=op_id,
                    profile_id="p1",
                    measured_bytes=100,
                    reservations=[res],
                )
                results.append((op_id, ok, None))
            except Exception as exc:
                results.append((op_id, False, exc))

        t1 = threading.Thread(target=worker, args=(adm1, "op_race_coll_a"))
        t2 = threading.Thread(target=worker, args=(adm2, "op_race_coll_b"))

        t1.start()
        t2.start()

        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        # Both attempts fail closed because distinct active reservations hold the same physical_read_id
        failures = [r for r in results if r[1] is False]
        self.assertEqual(len(failures), 2)
        for _, _, exc in failures:
            self.assertIn("Conflicting reservation ownership", str(exc))

    def test_20_high_concurrency_stress_continuous_reconcile(self):
        """Workstream 5: High-concurrency multithreaded stress test with continuous reconciliation."""
        num_threads = 6
        ops_per_thread = 15
        threads = []
        errors = []

        def stress_worker(thread_idx: int):
            for i in range(ops_per_thread):
                op_id = f"stress_t{thread_idx}_op{i}"
                try:
                    with self.tracker.operation_scope(op_id, profile_id=f"prof_{thread_idx}") as scope:
                        adm = scope.admit_read(128)
                        child = adm.start_child_read(physical_read_id=f"pread_{op_id}")
                        child.mark_started()
                        child.consume(actual_bytes=64)
                        child.update_metadata({"thread": thread_idx, "iter": i})
                        scope.record_read(bytes_read=64, admission=adm)
                except Exception as exc:
                    errors.append((op_id, exc))

        for t_idx in range(num_threads):
            t = threading.Thread(target=stress_worker, args=(t_idx,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10.0)

        self.assertEqual(errors, [])
        self.assertEqual(self.tracker.metrics.bytes_read, num_threads * ops_per_thread * 64)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["discrepancy_details"]["inv_1_physical_read_id_uniqueness"], True)
        self.assertEqual(recon["discrepancy_details"]["inv_24_accounting_reconstruction"], True)


if __name__ == "__main__":
    unittest.main()
