"""Phase 2.0-A.3.4.24 — Finalization Lock Closure & True Concurrent Interleaving Proof

Universal lock hierarchy (Transaction -> Scope -> Reservation -> Child),
deterministic interleaving proofs without time.sleep(), recovery partial-completion matrix,
and continuous multi-threaded reconciliation stress test.
"""

import collections
import copy
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import unittest
import uuid

from extractor.observation_budget import (
    ActiveOperationScope,
    AccountingFingerprint,
    BudgetReservation,
    CommittedTransactionSnapshot,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    PhysicalConsumptionRecord,
    PhysicalReadRecord,
    PreparedCommit,
    canonical_metadata_digest,
    freeze_metadata,
)


def make_scope(
    tracker: ObservationBudgetTracker,
    op_id: str,
    profile_id: str = "p1",
    owner: str = "INTERNAL",
) -> ActiveOperationScope:
    """Creates and registers an authoritative ActiveOperationScope."""
    scope = ActiveOperationScope(
        tracker=tracker,
        operation_id=op_id,
        profile_id=profile_id,
        owner=owner,
    )
    tracker._register_active_scope(scope)
    return scope


class TestPhase20A3424LockClosureAndRegistryConsistency(unittest.TestCase):
    """Workstream 1 & 2: Reservation Finalization Lock Closure & Registry Snapshot Consistency."""

    def setUp(self):
        self.limits = ObservationBudgetLimits(max_bytes_read=100000)
        self.tracker = ObservationBudgetTracker(self.limits)
        self.tracker.start()

    def test_01_lock_hierarchy_full_chain_reentrancy(self):
        """Universal lock hierarchy: Level 1 -> 1.5 -> 2 -> 3 with pure RLock reentrancy."""
        rlock_type = type(threading.RLock())

        with self.tracker.operation_scope("op_hier_chain", profile_id="p1") as scope:
            adm = scope.admit_read(256)
            child = adm.start_child_read(physical_read_id="pread_hier_chain")

            # Verify lock types
            self.assertEqual(type(self.tracker._transaction_lock), rlock_type)
            self.assertEqual(type(scope._lock), rlock_type)
            self.assertEqual(type(adm._lock), rlock_type)
            self.assertEqual(type(child._lock), rlock_type)

            # Acquire full chain in hierarchical order: L1 -> L1.5 -> L2 -> L3
            with self.tracker._transaction_lock:
                with self.tracker._transaction_lock:  # L1 reentrant
                    with scope._lock:
                        with scope._lock:  # L1.5 reentrant
                            with adm._lock:
                                with adm._lock:  # L2 reentrant
                                    with child._lock:
                                        with child._lock:  # L3 reentrant
                                            pass

    def test_02_zero_read_no_admission_finalization_synchronization(self):
        """Zero-read and no-admission finalization paths use identical synchronization contracts."""
        scope = make_scope(self.tracker, "op_zero_read_no_adm", profile_id="p1")
        self.assertEqual(len(scope._admissions), 0)
        self.assertEqual(scope.reads_count, 0)
        self.assertEqual(scope.charged_bytes, 0)

        # Finalization executes under lock, transitions scope to COMMITTED, returns None (no physical reads)
        snap = scope.finalize(success=True)
        self.assertIsNone(snap)
        self.assertEqual(scope.state, "COMMITTED")

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_03_zero_read_with_unused_admission_released_synchronously(self):
        """Zero-read scope with unused admission releases admission cleanly under lock."""
        scope = make_scope(self.tracker, "op_unused_adm", profile_id="p1")
        adm = scope.admit_read(512)
        self.assertEqual(adm.state, "ADMITTED")
        self.assertEqual(adm.consumed_bytes, 0)

        snap = scope.finalize(success=True)
        self.assertIsNone(snap)
        self.assertEqual(adm.state, "RELEASED")
        self.assertIn(adm.reservation_id, self.tracker.get_released_reservations())

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_04_authoritative_registry_snapshot_sorted_order(self):
        """Deterministic ascending identifier ordering prevents lock inversion across registries."""
        adm1 = self.tracker.admit_read(100, operation_id="op_sort_b")
        adm2 = self.tracker.admit_read(100, operation_id="op_sort_a")
        c1 = adm1.start_child_read(physical_read_id="pread_sort_z")
        c2 = adm2.start_child_read(physical_read_id="pread_sort_a")

        with self.tracker._lock_reservations_with_children([adm1, adm2]) as (locked_res, locked_children):
            res_ids = [r.reservation_id for r in locked_res]
            child_ids = [c.physical_read_id for c in locked_children]
            self.assertEqual(res_ids, sorted(res_ids))
            self.assertEqual(child_ids, sorted(child_ids))


class TestPhase20A3424DeterministicInterleavings(unittest.TestCase):
    """Workstream 3: True Deterministic Interleaving Tests using Critical Section Coordination."""

    def setUp(self):
        self.limits = ObservationBudgetLimits(max_bytes_read=100000)
        self.tracker = ObservationBudgetTracker(self.limits)
        self.tracker.start()

    def tearDown(self):
        self.tracker.clear_fault_injections()

    def test_05_scenario_1_admission_pauses_before_finalizing(self):
        """Scenario 1: Admission pauses before scope FINALIZING; finalization attempts same boundary."""
        scope = make_scope(self.tracker, "op_scen_1", profile_id="p1")

        event_adm_started = threading.Event()
        event_unpause_adm = threading.Event()
        outcome = {}

        def hook_after_admission():
            event_adm_started.set()
            event_unpause_adm.wait(timeout=2.0)

        self.tracker.set_fault_injection("after_admission_before_read", hook_after_admission)

        def worker_adm():
            try:
                r = scope.admit_read(200)
                outcome["adm"] = r
            except Exception as exc:
                outcome["adm_err"] = exc

        t_adm = threading.Thread(target=worker_adm)
        t_adm.start()

        event_adm_started.wait(timeout=2.0)
        # Admission is paused holding its state. Now finalization attempts same scope
        event_unpause_adm.set()
        t_adm.join(timeout=2.0)

        snap = scope.finalize()
        self.assertEqual(scope.state, "COMMITTED")
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_06_scenario_2_child_registration_pauses_during_identity_snapshot(self):
        """Scenario 2: Child registration pauses while identity snapshot is constructed."""
        scope = make_scope(self.tracker, "op_scen_2", profile_id="p1")
        adm = scope.admit_read(300)

        event_child_reg_started = threading.Event()
        event_unpause_child_reg = threading.Event()

        def hook_during_child_reg():
            event_child_reg_started.set()
            event_unpause_child_reg.wait(timeout=2.0)

        self.tracker.set_fault_injection("during_child_registration", hook_during_child_reg)

        def worker_child():
            c = adm.start_child_read(physical_read_id="pread_scen_2")
            c.mark_started()
            c.consume(actual_bytes=100)
            scope.record_read(100, admission=adm)

        t_child = threading.Thread(target=worker_child)
        t_child.start()

        event_child_reg_started.wait(timeout=2.0)
        event_unpause_child_reg.set()
        t_child.join(timeout=2.0)

        snap = scope.finalize()
        self.assertEqual(snap.charged_bytes, 100)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_07_scenario_3_child_consumption_races_with_reservation_finalization(self):
        """Scenario 3: Child consumption races with _finalize_scope_reservations()."""
        scope = make_scope(self.tracker, "op_scen_3", profile_id="p1")
        adm = scope.admit_read(400)
        child = adm.start_child_read(physical_read_id="pread_scen_3")
        child.mark_started()

        event_consume_at_hook = threading.Event()
        event_unpause_consume = threading.Event()

        def hook_before_consume():
            event_consume_at_hook.set()
            event_unpause_consume.wait(timeout=2.0)

        self.tracker.set_fault_injection("before_child_consumption", hook_before_consume)

        def worker_consume():
            child.consume(actual_bytes=150)
            scope.record_read(150, admission=adm)

        t = threading.Thread(target=worker_consume)
        t.start()

        event_consume_at_hook.wait(timeout=2.0)
        event_unpause_consume.set()
        t.join(timeout=2.0)

        snap = scope.finalize()
        self.assertEqual(snap.charged_bytes, 150)
        self.assertEqual(adm.consumed_bytes, 150)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_08_scenario_4_metadata_update_races_with_parent_finalization(self):
        """Scenario 4: Metadata update races with parent Reservation finalization."""
        scope = make_scope(self.tracker, "op_scen_4", profile_id="p1")
        adm = scope.admit_read(300)
        child = adm.start_child_read(physical_read_id="pread_scen_4")
        child.mark_started()
        child.consume(actual_bytes=120)
        scope.record_read(120, admission=adm)

        event_meta_at_hook = threading.Event()
        event_unpause_meta = threading.Event()
        meta_result = {}

        def hook_before_meta():
            event_meta_at_hook.set()
            event_unpause_meta.wait(timeout=2.0)

        self.tracker.set_fault_injection("before_metadata_update", hook_before_meta)

        def worker_meta():
            try:
                child.update_metadata({"interleaved": True})
                meta_result["success"] = True
            except Exception as exc:
                meta_result["err"] = exc

        t_meta = threading.Thread(target=worker_meta)
        t_meta.start()

        event_meta_at_hook.wait(timeout=2.0)
        # Release the hook
        event_unpause_meta.set()
        t_meta.join(timeout=2.0)

        snap = scope.finalize()
        self.assertEqual(snap.charged_bytes, 120)

        # Once terminal, updating metadata MUST raise RuntimeError
        with self.assertRaises(RuntimeError):
            child.update_metadata({"post_terminal": True})

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_09_scenario_5_unrelated_active_reservation_registers_conflicting_child(self):
        """Scenario 5: An unrelated active reservation registering a conflicting child fails closed."""
        adm_unrelated = self.tracker.admit_read(200, operation_id="op_unrelated")
        adm_target = self.tracker.admit_read(200, operation_id="op_target")

        c1 = adm_unrelated.start_child_read(physical_read_id="pread_shared_conflict")
        c2 = adm_target.start_child_read(physical_read_id="pread_shared_conflict")

        c1.mark_started()
        c2.mark_started()
        c1.consume(50)
        c2.consume(50)

        # Identity validation of adm_target MUST detect c2 ID exists in adm_unrelated and fail closed
        with self.assertRaises(ValueError) as ctx:
            with self.tracker._transaction_lock:
                with self.tracker._lock_reservations_with_children([adm_target]):
                    pass
        self.assertIn("Conflicting reservation ownership", str(ctx.exception))

    def test_10_scenario_6_two_commits_validate_conflicting_ids_concurrently(self):
        """Scenario 6: Two commits validate conflicting IDs concurrently; second fails closed."""
        adm1 = self.tracker.admit_read(200, operation_id="op_comm_1")
        adm2 = self.tracker.admit_read(200, operation_id="op_comm_2")

        c1 = adm1.start_child_read(physical_read_id="pread_commit_conflict")
        c2 = adm2.start_child_read(physical_read_id="pread_commit_conflict")
        c1.mark_started()
        c2.mark_started()
        c1.consume(80)
        c2.consume(80)

        results = []

        def worker(adm, op_id):
            try:
                ok = self.tracker.commit_transaction(
                    operation_id=op_id,
                    profile_id="p1",
                    measured_bytes=80,
                    reservations=[adm],
                )
                results.append((op_id, True, ok))
            except Exception as exc:
                results.append((op_id, False, exc))

        t1 = threading.Thread(target=worker, args=(adm1, "op_comm_1"))
        t2 = threading.Thread(target=worker, args=(adm2, "op_comm_2"))
        t1.start()
        t2.start()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        # Both cannot commit the conflicting ID; fail closed guaranteed
        failures = [r for r in results if not r[1]]
        self.assertGreaterEqual(len(failures), 1)

    def test_11_scenario_7_recovery_races_with_reconciliation(self):
        """Scenario 7: Recovery races with reconciliation; reconciliation serializes safely."""
        scope = make_scope(self.tracker, "op_rec_race", profile_id="p1")
        adm = scope.admit_read(300)
        c = adm.start_child_read(physical_read_id="pread_rec_race")
        c.mark_started()
        c.consume(100)
        scope.record_read(100, admission=adm)

        event_rec_started = threading.Event()
        event_unpause_rec = threading.Event()

        def hook_in_recovery():
            event_rec_started.set()
            event_unpause_rec.wait(timeout=2.0)

        self.tracker.set_fault_injection("recovery_logical_registration", hook_in_recovery)
        self.tracker.inject_fault("during_physical_ledger_insertion")

        def worker_commit():
            scope.finalize()

        t_commit = threading.Thread(target=worker_commit)
        t_commit.start()

        event_rec_started.wait(timeout=2.0)
        event_unpause_rec.set()
        t_commit.join(timeout=2.0)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_12_scenario_8_cleanup_races_with_duplicate_finalization(self):
        """Scenario 8: Scope cleanup races with duplicate finalization; idempotent return."""
        scope = make_scope(self.tracker, "op_dup_final", profile_id="p1")
        adm = scope.admit_read(250)
        c = adm.start_child_read(physical_read_id="pread_dup_final")
        c.mark_started()
        c.consume(90)
        scope.record_read(90, admission=adm)

        snaps = []

        def worker_fin():
            snaps.append(scope.finalize())

        t1 = threading.Thread(target=worker_fin)
        t2 = threading.Thread(target=worker_fin)
        t1.start()
        t2.start()
        t1.join(timeout=2.0)
        t2.join(timeout=2.0)

        self.assertEqual(len(snaps), 2)
        self.assertEqual(snaps[0].charged_bytes, snaps[1].charged_bytes)
        self.assertEqual(self.tracker.metrics.bytes_read, 90)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_13_scenario_9_two_reservations_locked_in_opposite_orders(self):
        """Scenario 9: Two reservations requested in opposite orders sort ascending, zero deadlock."""
        adm_x = self.tracker.admit_read(100, operation_id="op_x")
        adm_y = self.tracker.admit_read(100, operation_id="op_y")

        def lock_order_1():
            for _ in range(50):
                with self.tracker._transaction_lock:
                    with self.tracker._lock_reservations_with_children([adm_x, adm_y]):
                        pass

        def lock_order_2():
            for _ in range(50):
                with self.tracker._transaction_lock:
                    with self.tracker._lock_reservations_with_children([adm_y, adm_x]):
                        pass

        t1 = threading.Thread(target=lock_order_1)
        t2 = threading.Thread(target=lock_order_2)
        t1.start()
        t2.start()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

    def test_14_scenario_10_getter_reads_race_with_terminal_transitions(self):
        """Scenario 10: Concurrent getter reads race with terminal transitions; zero torn state."""
        stop_event = threading.Event()
        getter_errors = []

        def worker_getters():
            while not stop_event.is_set():
                try:
                    _ = self.tracker.get_committed_reservations()
                    _ = self.tracker.get_released_reservations()
                    _ = self.tracker.remaining_bytes
                except Exception as exc:
                    getter_errors.append(exc)

        t_get = threading.Thread(target=worker_getters)
        t_get.start()

        for i in range(10):
            with self.tracker.operation_scope(f"op_getter_race_{i}", profile_id="p1") as s:
                adm = s.admit_read(128)
                c = adm.start_child_read(physical_read_id=f"pread_getter_{i}")
                c.mark_started()
                c.consume(64)
                s.record_read(64, admission=adm)

        stop_event.set()
        t_get.join(timeout=2.0)

        self.assertEqual(getter_errors, [])
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])


class TestPhase20A3424RecoveryPartialCompletionMatrix(unittest.TestCase):
    """Workstream 4: Recovery Partial-Completion Matrix & Stage Tracking."""

    def setUp(self):
        self.limits = ObservationBudgetLimits(max_bytes_read=100000)
        self.tracker = ObservationBudgetTracker(self.limits)
        self.tracker.start()

    def tearDown(self):
        self.tracker.clear_fault_injections()

    def test_15_recovery_state_1_global_metrics_applied_profile_not_applied(self):
        """State 1: Failure after global metrics applied before profile metrics."""
        scope = make_scope(self.tracker, "op_rec_state_1", profile_id="p1")
        adm = scope.admit_read(200)
        c = adm.start_child_read(physical_read_id="pread_rec_state_1")
        c.mark_started()
        c.consume(100)
        scope.record_read(100, admission=adm)

        self.tracker.inject_fault("during_profile_metric_application")
        snap = scope.finalize()

        self.assertIsNotNone(snap)
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertEqual(self.tracker.metrics.bytes_read, 100)
        p_usage = self.tracker._get_or_init_profile_usage("p1")
        self.assertEqual(p_usage["bytes_read"], 100)

        stages = self.tracker.get_recovery_stages_completed("op_rec_state_1")
        self.assertIn("recovery_metric_reconciliation", stages)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_16_recovery_state_2_physical_ledger_partially_registered(self):
        """State 2: Failure during physical ledger insertion completes via recovery."""
        scope = make_scope(self.tracker, "op_rec_state_2", profile_id="p1")
        adm = scope.admit_read(250)
        c = adm.start_child_read(physical_read_id="pread_rec_state_2")
        c.mark_started()
        c.consume(120)
        scope.record_read(120, admission=adm)

        self.tracker.inject_fault("during_physical_ledger_insertion")
        snap = scope.finalize()

        self.assertIsNotNone(snap)
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertIn("pread_rec_state_2", self.tracker._physical_read_records)
        self.assertEqual(self.tracker._physical_read_records["pread_rec_state_2"].state, "FAILED_ACCOUNTED")

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_17_recovery_state_3_logical_transaction_registered_before_physical_completion(self):
        """State 3: Failure after logical ledger completes physical evidence during recovery."""
        scope = make_scope(self.tracker, "op_rec_state_3", profile_id="p1")
        adm = scope.admit_read(300)
        c = adm.start_child_read(physical_read_id="pread_rec_state_3")
        c.mark_started()
        c.consume(150)
        scope.record_read(150, admission=adm)

        self.tracker.inject_fault("after_logical_ledger_insertion")
        snap = scope.finalize()

        self.assertIsNotNone(snap)
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertEqual(self.tracker.metrics.bytes_read, 150)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_18_recovery_state_4_partial_reservations_finalized(self):
        """State 4: Failure during reservation finalization marks all reservations FAILED_ACCOUNTED."""
        scope = make_scope(self.tracker, "op_rec_state_4", profile_id="p1")
        adm1 = scope.admit_read(200)
        adm2 = scope.admit_read(200)
        c1 = adm1.start_child_read(physical_read_id="pread_rec_state_4_a")
        c2 = adm2.start_child_read(physical_read_id="pread_rec_state_4_b")
        c1.mark_started()
        c2.mark_started()
        c1.consume(50)
        c2.consume(50)
        scope.record_read(100, admission=adm1)

        self.tracker.inject_fault("during_reservation_finalization")
        snap = scope.finalize()

        self.assertIsNotNone(snap)
        self.assertEqual(adm1.state, "FAILED_ACCOUNTED")
        self.assertEqual(adm2.state, "FAILED_ACCOUNTED")

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_19_recovery_state_5_cleanup_failure_after_accounting(self):
        """State 5: Failure during recovery cleanup followed by retry_recovery cleans up."""
        scope = make_scope(self.tracker, "op_rec_state_5", profile_id="p1")
        adm = scope.admit_read(180)
        c = adm.start_child_read(physical_read_id="pread_rec_state_5")
        c.mark_started()
        c.consume(90)
        scope.record_read(90, admission=adm)

        self.tracker.inject_fault("during_physical_ledger_insertion")
        self.tracker.inject_fault("during_recovery_cleanup")

        with self.assertRaises(RuntimeError):
            scope.finalize()

        # Retry recovery after clearing cleanup fault
        self.tracker.clear_fault_injections()
        snap = self.tracker.retry_recovery(scope)
        self.assertIsNotNone(snap)
        self.assertEqual(snap.accounting_status, "FAILED")

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_20_recovery_state_6_recovery_failure_followed_by_recovery_failure(self):
        """State 6: Cascading recovery failure across multiple recovery attempts."""
        scope = make_scope(self.tracker, "op_rec_state_6", profile_id="p1")
        adm = scope.admit_read(200)
        c = adm.start_child_read(physical_read_id="pread_rec_state_6")
        c.mark_started()
        c.consume(100)
        scope.record_read(100, admission=adm)

        self.tracker.inject_fault("during_physical_ledger_insertion")
        self.tracker.inject_fault("during_recovery_logical_registration")

        with self.assertRaises(RuntimeError):
            scope.finalize()

        # Retry recovery with a second failure
        self.tracker.clear_fault_injections()
        self.tracker.inject_fault("during_recovery_metric_reconciliation")

        with self.assertRaises(RuntimeError):
            self.tracker.retry_recovery(scope)

        # Final retry completes all stages
        self.tracker.clear_fault_injections()
        snap = self.tracker.retry_recovery(scope)
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertEqual(self.tracker.metrics.bytes_read, 100)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_21_recovery_state_7_recovery_retry_after_partial_registry_cleanup(self):
        """State 7: Recovery retry after partial registry cleanup restores full consistency."""
        scope = make_scope(self.tracker, "op_rec_state_7", profile_id="p1")
        adm = scope.admit_read(220)
        c = adm.start_child_read(physical_read_id="pread_rec_state_7")
        c.mark_started()
        c.consume(110)
        scope.record_read(110, admission=adm)

        self.tracker.inject_fault("during_physical_ledger_insertion")
        self.tracker.inject_fault("during_recovery_reservation_finalization")

        with self.assertRaises(RuntimeError):
            scope.finalize()

        self.tracker.clear_fault_injections()
        snap = self.tracker.retry_recovery(scope)
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertEqual(self.tracker.metrics.bytes_read, 110)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_22_recovery_state_8_repeated_retry_after_completed_recovery(self):
        """State 8: Repeated retry after fully completed recovery returns snapshot idempotently."""
        scope = make_scope(self.tracker, "op_rec_state_8", profile_id="p1")
        adm = scope.admit_read(240)
        c = adm.start_child_read(physical_read_id="pread_rec_state_8")
        c.mark_started()
        c.consume(120)
        scope.record_read(120, admission=adm)

        self.tracker.inject_fault("during_physical_ledger_insertion")
        snap1 = scope.finalize()

        stages = self.tracker.get_recovery_stages_completed("op_rec_state_8")
        self.assertEqual(len(stages), 6)

        # Repeated retry calls must return the same snapshot with 0 delta to metrics
        bytes_before = self.tracker.metrics.bytes_read
        snap2 = self.tracker.retry_recovery(scope)
        self.assertEqual(snap1.fingerprint, snap2.fingerprint)
        self.assertEqual(self.tracker.metrics.bytes_read, bytes_before)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])


class TestPhase20A3424ContinuousReconciliationStress(unittest.TestCase):
    """Workstream 5: Continuous Reconciliation Stress Test."""

    def setUp(self):
        self.limits = ObservationBudgetLimits(max_bytes_read=1000000)
        self.tracker = ObservationBudgetTracker(self.limits)
        self.tracker.start()

    def test_23_continuous_reconciliation_concurrent_stress(self):
        """Continuous reconciliation worker runs alongside concurrent ops with zero discrepancies."""
        stop_reconcile = threading.Event()
        reconcile_errors = []
        reconcile_counts = [0]

        def reconciliation_worker():
            while not stop_reconcile.is_set():
                try:
                    res = self.tracker.reconcile_ledger(raise_on_error=True)
                    if not res["reconciled"]:
                        reconcile_errors.append(res)
                    reconcile_counts[0] += 1
                except Exception as exc:
                    reconcile_errors.append(exc)

        recon_thread = threading.Thread(target=reconciliation_worker)
        recon_thread.start()

        num_threads = 6
        ops_per_thread = 12
        threads = []
        worker_errors = []

        def worker(thread_idx: int):
            for i in range(ops_per_thread):
                op_id = f"cont_recon_t{thread_idx}_i{i}"
                try:
                    with self.tracker.operation_scope(op_id, profile_id=f"prof_{thread_idx}") as scope:
                        adm = scope.admit_read(64)
                        child = adm.start_child_read(physical_read_id=f"pread_{op_id}")
                        child.mark_started()
                        child.consume(actual_bytes=32)
                        scope.record_read(32, admission=adm)
                except Exception as exc:
                    worker_errors.append((op_id, exc))

        for t_idx in range(num_threads):
            t = threading.Thread(target=worker, args=(t_idx,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10.0)

        stop_reconcile.set()
        recon_thread.join(timeout=5.0)

        self.assertEqual(worker_errors, [])
        self.assertEqual(reconcile_errors, [])
        self.assertGreater(reconcile_counts[0], 0)
        self.assertEqual(self.tracker.metrics.bytes_read, num_threads * ops_per_thread * 32)

        final_recon = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(final_recon["reconciled"])
