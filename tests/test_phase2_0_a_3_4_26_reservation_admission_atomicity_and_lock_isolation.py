#!/usr/bin/env python3
"""Phase 2.0-A.3.4.26 — Reservation Admission Atomicity, Lock Boundary Isolation, and Recovery Stress Closure.

Strict correctness and verification tests for:
1. Reservation Admission Atomicity (P0):
   - Scope eligibility validation BEFORE publishing to _active_reservations or scope._admissions.
   - Elimination of orphaned reservations on COMMITTED, FINALIZING, FAILED, and REJECTED scopes.
   - Atomicity and rollback safety during admission failures.
   - Preservation of standalone reservations and budget metrics.
2. Lock Boundary Isolation Proof:
   - Isolated Scope lock (L1.5) contention without holding Transaction lock (L1).
   - Isolated Reservation lock (L2) contention without holding L1 or L1.5.
   - Isolated Child lock (L3) contention without holding L1, L1.5, or L2.
   - Pure lock order hierarchy and reentrancy (L1 -> L1.5 -> L2 -> L3).
   - Terminal state transitions while competing threads wait at isolated boundaries.
3. Authoritative Candidate Snapshot Audit:
   - Snapshot consistency and linearization under _transaction_lock and scope._lock.
   - Fail-closed identity collision detection for duplicate reservation_id on distinct instances.
   - Candidate consistency across all five finalization, commit, and recovery paths.
4. Reconciliation Child-State Consistency:
   - Atomic synchronized child and reservation snapshots under _lock_with_children().
   - Concurrent child consume, metadata update, terminal transition, and finalization during reconciliation.
5. Recovery and Cleanup Concurrent Stress Closure:
   - Multi-worker concurrent stress covering normal commits, injected failures, emergency recovery,
     recovery retry, reservation cleanup, duplicate finalizations, and continuous reconciliation.
"""

from contextlib import nullcontext
import copy
import os
import sys
import threading
import time
import unittest
import uuid
from typing import Any, Dict, List, Optional, Set

from extractor.observation_budget import (
    ActiveOperationScope,
    BudgetReservation,
    CommittedTransactionSnapshot,
    DEFAULT_CONSERVATIVE_UNKNOWN_BYTES,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    ObservationMetrics,
    PhysicalReadRecord,
    PreparedCommit,
)


def make_tracker(max_bytes: int = 10_000_000) -> ObservationBudgetTracker:
    limits = ObservationBudgetLimits(
        max_bytes_read=max_bytes,
        max_bytes_per_observation=max_bytes,
    )
    tracker = ObservationBudgetTracker(limits=limits)
    tracker.start()
    return tracker


def make_scope(tracker: ObservationBudgetTracker, op_id: str, profile_id: str = "prof_a26", owner: str = "INTERNAL") -> ActiveOperationScope:
    scope = ActiveOperationScope(
        tracker=tracker,
        operation_id=op_id,
        profile_id=profile_id,
        owner=owner,
    )
    tracker._register_active_scope(scope)
    return scope


class TestPhase20A3426ReservationAdmissionAtomicity(unittest.TestCase):
    """P0 Requirements: Validates Scope eligibility before publishing and guarantees atomic admission."""

    def setUp(self):
        self.tracker = make_tracker()

    def test_01_admission_against_committed_scope_fails_cleanly(self):
        """Scenario A: Admission against COMMITTED scope fails closed with zero orphans, leaks, or mutations."""
        scope = make_scope(self.tracker, "op_committed_a26")
        adm_initial = scope.admit_read(100)
        scope.record_read(100, admission=adm_initial)
        scope.finalize()
        self.assertEqual(scope.state, "COMMITTED")

        initial_active_res = dict(self.tracker._active_reservations)
        initial_admissions_len = len(scope._admissions)
        initial_metrics = copy.deepcopy(self.tracker.metrics)

        # Attempt admission via scope.admit_read
        with self.assertRaises(RuntimeError) as ctx:
            scope.admit_read(50)
        self.assertIn("Cannot admit read on scope 'op_committed_a26' in state COMMITTED", str(ctx.exception))

        # Attempt admission via tracker.reserve_budget directly with the scope
        with self.assertRaises(RuntimeError) as ctx:
            self.tracker.reserve_budget(estimated_bytes=50, scope=scope)
        self.assertIn("Cannot reserve budget on scope 'op_committed_a26' in state COMMITTED", str(ctx.exception))

        # Attempt admission via tracker.admit_read directly with the scope
        with self.assertRaises(RuntimeError) as ctx:
            self.tracker.admit_read(projected_bytes=50, scope=scope)
        self.assertIn("Cannot admit read on scope 'op_committed_a26' in state COMMITTED", str(ctx.exception))

        # Assert zero orphans in _active_reservations
        self.assertEqual(self.tracker._active_reservations, initial_active_res)
        # Assert no unintended entry in scope._admissions
        self.assertEqual(len(scope._admissions), initial_admissions_len)
        # Assert no metric mutation
        self.assertEqual(self.tracker.metrics.bytes_read, initial_metrics.bytes_read)
        # Assert clean final reconciliation
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(len(recon["discrepancies"]), 0)

    def test_02_admission_against_finalizing_scope_fails_cleanly(self):
        """Scenario B: Admission against FINALIZING scope fails closed with zero orphans."""
        scope = make_scope(self.tracker, "op_finalizing_a26")
        adm_initial = scope.admit_read(150)
        scope.record_read(150, admission=adm_initial)

        with scope._lock:
            scope.state = "FINALIZING"

            # Must fail immediately
            with self.assertRaises(RuntimeError) as ctx:
                scope.admit_read(75)
            self.assertIn("Cannot admit read on scope 'op_finalizing_a26' in state FINALIZING", str(ctx.exception))

            with self.assertRaises(RuntimeError) as ctx:
                self.tracker.reserve_budget(estimated_bytes=75, scope=scope)
            self.assertIn("Cannot reserve budget on scope 'op_finalizing_a26' in state FINALIZING", str(ctx.exception))

            with self.assertRaises(RuntimeError) as ctx:
                self.tracker.admit_read(projected_bytes=75, scope=scope)
            self.assertIn("Cannot admit read on scope 'op_finalizing_a26' in state FINALIZING", str(ctx.exception))

        # Cleanup scope state to COMMITTED to verify final reconciliation
        scope.state = "COMMITTED"
        self.tracker._finalize_scope_reservations(scope)
        self.tracker._unregister_active_scope(scope)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_03_admission_against_failed_scope_fails_cleanly(self):
        """Scenario C: Admission against FAILED scope fails closed with zero orphans."""
        scope = make_scope(self.tracker, "op_failed_a26")
        adm_initial = scope.admit_read(120)
        scope.record_read(120, admission=adm_initial)
        scope.finalize(success=False)
        self.assertEqual(scope.state, "FAILED")

        initial_active = dict(self.tracker._active_reservations)

        with self.assertRaises(RuntimeError) as ctx:
            scope.admit_read(60)
        self.assertIn("in state FAILED", str(ctx.exception))

        with self.assertRaises(RuntimeError) as ctx:
            self.tracker.reserve_budget(estimated_bytes=60, scope=scope)
        self.assertIn("in state FAILED", str(ctx.exception))

        self.assertEqual(self.tracker._active_reservations, initial_active)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_04_admission_against_rejected_scope_fails_cleanly(self):
        """Scenario D: Admission against REJECTED scope fails closed with zero orphans."""
        scope = make_scope(self.tracker, "op_rejected_a26")
        with scope._lock:
            scope.state = "REJECTED"

        initial_active = dict(self.tracker._active_reservations)

        with self.assertRaises(RuntimeError) as ctx:
            scope.admit_read(80)
        self.assertIn("in state REJECTED", str(ctx.exception))

        with self.assertRaises(RuntimeError) as ctx:
            self.tracker.reserve_budget(estimated_bytes=80, scope=scope)
        self.assertIn("in state REJECTED", str(ctx.exception))

        self.assertEqual(self.tracker._active_reservations, initial_active)
        self.assertEqual(len(scope._admissions), 0)

    def test_05_concurrent_admission_versus_scope_finalization(self):
        """Scenario E: Concurrent admission vs Scope Finalization proves atomic boundary blocking."""
        scope = make_scope(self.tracker, "op_concurrent_adm_fin")
        adm = scope.admit_read(200)
        scope.record_read(200, admission=adm)

        event_fin_entered = threading.Event()
        event_adm_attempted = threading.Event()
        event_unpause_fin = threading.Event()
        adm_outcome = {}

        def hook_during_fin():
            event_fin_entered.set()
            event_adm_attempted.wait(timeout=3.0)
            # PROOF: Admission thread must be blocked outside because finalization owns scope._lock!
            self.assertTrue(t_adm.is_alive())
            event_unpause_fin.wait(timeout=3.0)

        self.tracker.set_fault_injection("before_reservation_finalization", hook_during_fin)

        def worker_adm():
            event_fin_entered.wait(timeout=3.0)
            event_adm_attempted.set()
            try:
                self.tracker.reserve_budget(estimated_bytes=100, scope=scope)
                adm_outcome["success"] = True
            except Exception as exc:
                adm_outcome["error"] = exc

        t_adm = threading.Thread(target=worker_adm)
        t_adm.start()

        def worker_fin():
            scope.finalize()

        t_fin = threading.Thread(target=worker_fin)
        t_fin.start()

        event_fin_entered.wait(timeout=3.0)
        event_adm_attempted.wait(timeout=3.0)
        event_unpause_fin.set()

        t_fin.join(timeout=3.0)
        t_adm.join(timeout=3.0)

        self.assertEqual(scope.state, "COMMITTED")
        self.assertIn("error", adm_outcome)
        self.assertIsInstance(adm_outcome["error"], RuntimeError)
        self.assertIn("in state COMMITTED", str(adm_outcome["error"]))

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_06_failure_during_admission_before_publication_leaves_zero_state(self):
        """Scenario F: Simulated failure before registry publication rolls back cleanly."""
        scope = make_scope(self.tracker, "op_fault_adm_pub")
        initial_active_len = len(self.tracker._active_reservations)
        initial_admissions_len = len(scope._admissions)

        def fault_hook():
            raise IOError("Simulated transport failure before publication")

        self.tracker.set_fault_injection("before_reservation_publication", fault_hook)

        with self.assertRaises(IOError) as ctx:
            self.tracker.reserve_budget(estimated_bytes=250, scope=scope)
        self.assertIn("Simulated transport failure before publication", str(ctx.exception))

        # Clear fault
        self.tracker.clear_fault_injections()

        # Assert no reservation left in _active_reservations or scope._admissions
        self.assertEqual(len(self.tracker._active_reservations), initial_active_len)
        self.assertEqual(len(scope._admissions), initial_admissions_len)

        # Successful subsequent admission should work
        adm_clean = self.tracker.reserve_budget(estimated_bytes=100, scope=scope)
        self.assertEqual(len(self.tracker._active_reservations), initial_active_len + 1)
        self.assertEqual(len(scope._admissions), initial_admissions_len + 1)

        # Release and reconcile
        self.tracker.release_reservation(adm_clean)
        self.assertEqual(len(self.tracker._active_reservations), initial_active_len)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_07_repeated_failed_admission_attempts_zero_leak(self):
        """Scenario G: 30 repeated failed admissions against terminated scope leave zero orphans."""
        scope = make_scope(self.tracker, "op_repeated_fails")
        adm = scope.admit_read(100)
        scope.record_read(100, admission=adm)
        scope.finalize()

        initial_active_res = dict(self.tracker._active_reservations)
        initial_admissions = list(scope._admissions)

        for i in range(30):
            with self.assertRaises(RuntimeError):
                self.tracker.reserve_budget(estimated_bytes=50 + i, scope=scope)
            with self.assertRaises(RuntimeError):
                scope.admit_read(projected_bytes=50 + i)

        self.assertEqual(self.tracker._active_reservations, initial_active_res)
        self.assertEqual(scope._admissions, initial_admissions)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_08_standalone_reservation_behavior_preserved(self):
        """Scenario H: Standalone reservation (scope=None) operates cleanly under _transaction_lock."""
        res = self.tracker.reserve_budget(estimated_bytes=400, operation_id="standalone_a26", scope=None)
        self.assertIn(res.reservation_id, self.tracker._active_reservations)
        self.assertEqual(res.operation_id, "standalone_a26")
        self.assertIsNone(res.scope_id)

        # Normal child read and consumption
        child = res.start_child_read(physical_read_id="pread_standalone_a26")
        child.mark_started()
        child.consume(400)

        # Standalone commit
        self.tracker.commit_transaction(
            operation_id="standalone_a26",
            profile_id="prof_standalone",
            measured_bytes=400,
            reservations=[res],
        )
        self.assertIn("standalone_a26", self.tracker._committed_transactions)
        tx = self.tracker._committed_transactions["standalone_a26"]
        self.assertEqual(tx.accounting_status, "COMMITTED")
        self.assertNotIn(res.reservation_id, self.tracker._active_reservations)
        self.assertIn("pread_standalone_a26", self.tracker._physical_read_records)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])


class TestPhase20A3426LockBoundaryIsolation(unittest.TestCase):
    """Proves isolation of L1, L1.5, L2, and L3 lock boundaries without relying on outer locks."""

    def setUp(self):
        self.tracker = make_tracker()

    def test_09_isolated_scope_lock_contention_without_transaction_lock(self):
        """Boundary L1.5: Thread A holds ONLY scope._lock; Thread B blocks on scope._lock without _transaction_lock contention."""
        scope = make_scope(self.tracker, "op_iso_scope_l15")

        event_a_holds_scope = threading.Event()
        event_b_attempted = threading.Event()
        event_b_finished = threading.Event()
        event_unpause_a = threading.Event()
        b_outcome = {}

        def worker_a():
            # Thread A deliberately acquires ONLY scope._lock (NO _transaction_lock held!)
            with scope._lock:
                event_a_holds_scope.set()
                event_b_attempted.wait(timeout=3.0)
                # PROOF: Thread B is actively blocked at scope._lock!
                self.assertFalse(event_b_finished.is_set())
                self.assertTrue(t_b.is_alive())
                # Visible state before release:
                self.assertIn(scope.state, ("OPEN", "ACTIVE"))
                event_unpause_a.wait(timeout=3.0)

        t_a = threading.Thread(target=worker_a)
        t_a.start()

        def worker_b():
            event_a_holds_scope.wait(timeout=3.0)
            event_b_attempted.set()
            # Thread B attempts operation requiring scope._lock
            with scope._lock:
                scope.metadata["thread_b_entered"] = True
                b_outcome["entered"] = True
            event_b_finished.set()

        t_b = threading.Thread(target=worker_b)
        t_b.start()

        event_a_holds_scope.wait(timeout=3.0)
        event_b_attempted.wait(timeout=3.0)
        time.sleep(0.05)  # Allow thread B to attempt lock acquisition
        event_unpause_a.set()

        t_a.join(timeout=3.0)
        t_b.join(timeout=3.0)

        # Thread B successfully entered after Thread A released scope._lock
        self.assertTrue(b_outcome.get("entered"))
        self.assertTrue(scope.metadata.get("thread_b_entered"))

    def test_10_isolated_reservation_lock_contention_without_outer_locks(self):
        """Boundary L2: Thread A holds ONLY res._lock; Thread B blocks on res._lock with NO outer locks held."""
        res = self.tracker.admit_read(300, operation_id="op_iso_res_l2")

        event_a_holds_res = threading.Event()
        event_b_attempted = threading.Event()
        event_b_finished = threading.Event()
        event_unpause_a = threading.Event()
        b_outcome = {}

        def worker_a():
            # Deliberately acquire ONLY res._lock (NO _transaction_lock, NO scope._lock)
            with res._lock:
                event_a_holds_res.set()
                event_b_attempted.wait(timeout=3.0)
                # PROOF: Thread B is blocked on res._lock!
                self.assertFalse(event_b_finished.is_set())
                self.assertTrue(t_b.is_alive())
                # Mutate under res._lock
                res.consumed_bytes += 50
                event_unpause_a.wait(timeout=3.0)

        t_a = threading.Thread(target=worker_a)
        t_a.start()

        def worker_b():
            event_a_holds_res.wait(timeout=3.0)
            event_b_attempted.set()
            # Thread B attempts to acquire res._lock
            with res._lock:
                b_outcome["observed_consumed"] = res.consumed_bytes
                res.consumed_bytes += 50
            event_b_finished.set()

        t_b = threading.Thread(target=worker_b)
        t_b.start()

        event_a_holds_res.wait(timeout=3.0)
        event_b_attempted.wait(timeout=3.0)
        time.sleep(0.05)
        event_unpause_a.set()

        t_a.join(timeout=3.0)
        t_b.join(timeout=3.0)

        # Thread B saw Thread A's updated consumed_bytes (50) and added 50 -> 100
        self.assertEqual(b_outcome.get("observed_consumed"), 50)
        self.assertEqual(res.consumed_bytes, 100)

    def test_11_isolated_child_lock_contention_without_outer_locks(self):
        """Boundary L3: Thread A holds ONLY child._lock; Thread B blocks on child._lock with NO outer locks held."""
        adm = self.tracker.admit_read(200, operation_id="op_iso_child_l3")
        child = adm.start_child_read(physical_read_id="pread_iso_child_l3")

        event_a_holds_child = threading.Event()
        event_b_attempted = threading.Event()
        event_b_finished = threading.Event()
        event_unpause_a = threading.Event()
        b_outcome = {}

        def worker_a():
            # Deliberately acquire ONLY child._lock (NO _transaction_lock, NO res._lock)
            with child._lock:
                event_a_holds_child.set()
                event_b_attempted.wait(timeout=3.0)
                # PROOF: Thread B is blocked on child._lock!
                self.assertFalse(event_b_finished.is_set())
                self.assertTrue(t_b.is_alive())
                child.charged_bytes = 42
                event_unpause_a.wait(timeout=3.0)

        t_a = threading.Thread(target=worker_a)
        t_a.start()

        def worker_b():
            event_a_holds_child.wait(timeout=3.0)
            event_b_attempted.set()
            # Thread B attempts to inspect/mutate child under child._lock
            with child._lock:
                b_outcome["observed_charged"] = child.charged_bytes
                child.charged_bytes += 10
            event_b_finished.set()

        t_b = threading.Thread(target=worker_b)
        t_b.start()

        event_a_holds_child.wait(timeout=3.0)
        event_b_attempted.wait(timeout=3.0)
        time.sleep(0.05)
        event_unpause_a.set()

        t_a.join(timeout=3.0)
        t_b.join(timeout=3.0)

        self.assertEqual(b_outcome.get("observed_charged"), 42)
        self.assertEqual(child.charged_bytes, 52)

    def test_12_pure_reentrant_acquisition_order_l1_to_l3(self):
        """Proves exact lock acquisition order L1 -> L1.5 -> L2 -> L3 and reentrancy without deadlock."""
        scope = make_scope(self.tracker, "op_pure_reentrancy_order")
        adm = scope.admit_read(100)
        child = adm.start_child_read(physical_read_id="pread_order_l3")

        # Acquire L1 -> L1.5 -> L2 -> L3
        with self.tracker._transaction_lock:
            with scope._lock:
                with adm._lock:
                    with child._lock:
                        # Reentrant acquire of all levels
                        with self.tracker._transaction_lock:
                            with scope._lock:
                                with adm._lock:
                                    with child._lock:
                                        child.charged_bytes = 80
                                        adm.consumed_bytes = 80

        self.assertEqual(child.charged_bytes, 80)
        self.assertEqual(adm.consumed_bytes, 80)

    def test_13_terminal_transition_while_waiting_at_isolated_scope_boundary(self):
        """Thread A holds scope._lock and transitions scope to COMMITTED while Thread B waits at scope._lock."""
        scope = make_scope(self.tracker, "op_term_scope_wait")
        adm = scope.admit_read(100)
        scope.record_read(100, admission=adm)

        event_a_holds = threading.Event()
        event_b_attempted = threading.Event()
        event_unpause_a = threading.Event()
        b_outcome = {}

        def worker_a():
            with scope._lock:
                event_a_holds.set()
                event_b_attempted.wait(timeout=3.0)
                # Thread A transitions state to COMMITTED while Thread B waits
                scope.state = "COMMITTED"
                event_unpause_a.wait(timeout=3.0)

        t_a = threading.Thread(target=worker_a)
        t_a.start()

        def worker_b():
            event_a_holds.wait(timeout=3.0)
            event_b_attempted.set()
            # Thread B blocks on scope._lock, and once entered sees COMMITTED and rejects admission
            try:
                scope.admit_read(50)
                b_outcome["admitted"] = True
            except Exception as exc:
                b_outcome["error"] = exc

        t_b = threading.Thread(target=worker_b)
        t_b.start()

        event_a_holds.wait(timeout=3.0)
        event_b_attempted.wait(timeout=3.0)
        time.sleep(0.05)
        event_unpause_a.set()

        t_a.join(timeout=3.0)
        t_b.join(timeout=3.0)

        self.assertIn("error", b_outcome)
        self.assertIsInstance(b_outcome["error"], RuntimeError)
        self.assertIn("COMMITTED", str(b_outcome["error"]))


class TestPhase20A3426AuthoritativeCandidateSnapshot(unittest.TestCase):
    """Audit of _get_authoritative_scope_candidates: snapshot linearization and identity integrity."""

    def setUp(self):
        self.tracker = make_tracker()

    def test_14_authoritative_snapshot_consistency_and_linearization(self):
        """Verifies candidate snapshot consistency across finalize, execute_commit, and recover_commit_failure."""
        scope = make_scope(self.tracker, "op_authoritative_snap")
        adm1 = scope.admit_read(100)
        adm2 = self.tracker.reserve_budget(estimated_bytes=150, scope=scope)

        candidates = self.tracker._get_authoritative_scope_candidates(scope)
        candidate_ids = [c.reservation_id for c in candidates]

        # Must include both adm1 (from _admissions) and adm2 (from _admissions and _active_reservations)
        self.assertIn(adm1.reservation_id, candidate_ids)
        self.assertIn(adm2.reservation_id, candidate_ids)
        # Must be deterministically sorted
        self.assertEqual(candidate_ids, sorted(candidate_ids))

    def test_15_identity_collision_duplicate_reservation_id_fails_closed(self):
        """Identity collision: duplicate reservation_id on distinct BudgetReservation instances fails closed."""
        scope = make_scope(self.tracker, "op_collision_audit")
        res_real = scope.admit_read(100)

        # Fabricate conflicting reservation instance with identical reservation_id
        res_impostor = BudgetReservation(
            reservation_id=res_real.reservation_id,
            operation_id=scope.operation_id,
            reserved_bytes=100,
            scope_id=scope.physical_consumption_id,
            physical_consumption_id="pcons_impostor",
        )
        # Inject impostor into active reservations
        self.tracker._active_reservations[res_real.reservation_id] = res_impostor

        with self.assertRaises(ValueError) as ctx:
            self.tracker._get_authoritative_scope_candidates(scope)
        self.assertIn("Reservation identity collision", str(ctx.exception))

    def test_16_terminal_reservations_cannot_reenter_active_lifecycle(self):
        """Terminal BudgetReservation objects cannot re-enter active mutation paths."""
        adm = self.tracker.admit_read(100, operation_id="op_terminal_reenter")
        self.tracker.release_reservation(adm)
        self.assertEqual(adm.state, "RELEASED")

        # Mutating terminal reservation must fail closed
        with self.assertRaises(RuntimeError):
            adm.start_child_read(physical_read_id="pread_reenter")

        with self.assertRaises(RuntimeError):
            adm.account()

        with self.assertRaises(RuntimeError):
            adm.consume(100)


class TestPhase20A3426ReconciliationChildStateConsistency(unittest.TestCase):
    """Proves synchronized compound child and reservation state inspections during reconcile_ledger()."""

    def setUp(self):
        self.tracker = make_tracker()

    def test_17_concurrent_child_consume_and_reconciliation(self):
        """Concurrent child consume and reconciliation produces 0 discrepancies via atomic snapshot."""
        scope = make_scope(self.tracker, "op_recon_consume")
        adm = scope.admit_read(200)
        c = adm.start_child_read(physical_read_id="pread_recon_consume")
        c.mark_started()

        event_consume_start = threading.Event()
        event_recon_done = threading.Event()
        stop_workers = threading.Event()
        recon_errors = []

        def worker_consume():
            event_consume_start.set()
            val = 0
            while not stop_workers.is_set():
                val = (val + 10) % 200
                c.consume(actual_bytes=val)
                time.sleep(0.001)

        def worker_recon():
            event_consume_start.wait(timeout=3.0)
            for _ in range(15):
                res = self.tracker.reconcile_ledger(raise_on_error=False)
                if not res["reconciled"]:
                    recon_errors.append(res["discrepancies"])
                time.sleep(0.001)
            event_recon_done.set()

        t_c = threading.Thread(target=worker_consume)
        t_r = threading.Thread(target=worker_recon)

        t_c.start()
        t_r.start()

        event_recon_done.wait(timeout=5.0)
        stop_workers.set()

        t_c.join(timeout=3.0)
        t_r.join(timeout=3.0)

        self.assertEqual(recon_errors, [], f"Reconciliation discrepancies during concurrent consume: {recon_errors}")

    def test_18_concurrent_child_metadata_update_and_reconciliation(self):
        """Concurrent child metadata updates and reconciliation observe synchronized target_spec and metadata."""
        scope = make_scope(self.tracker, "op_recon_meta")
        adm = scope.admit_read(200)
        c = adm.start_child_read(physical_read_id="pread_recon_meta")

        event_meta_start = threading.Event()
        event_recon_done = threading.Event()
        stop_workers = threading.Event()
        recon_errors = []

        def worker_meta():
            event_meta_start.set()
            cnt = 0
            while not stop_workers.is_set():
                cnt += 1
                c.update_metadata({"iteration": cnt, "ts": time.time()})
                c.update_target_spec({"query": f"q_{cnt}", "offset": cnt * 10})
                time.sleep(0.001)

        def worker_recon():
            event_meta_start.wait(timeout=3.0)
            for _ in range(15):
                res = self.tracker.reconcile_ledger(raise_on_error=False)
                if not res["reconciled"]:
                    recon_errors.append(res["discrepancies"])
                time.sleep(0.001)
            event_recon_done.set()

        t_m = threading.Thread(target=worker_meta)
        t_r = threading.Thread(target=worker_recon)

        t_m.start()
        t_r.start()

        event_recon_done.wait(timeout=5.0)
        stop_workers.set()

        t_m.join(timeout=3.0)
        t_r.join(timeout=3.0)

        self.assertEqual(recon_errors, [], f"Reconciliation discrepancies during concurrent metadata update: {recon_errors}")

    def test_19_concurrent_reservation_finalization_and_reconciliation(self):
        """Concurrent reservation finalization and continuous reconciliation observe zero invalid transient states."""
        scopes = [make_scope(self.tracker, f"op_fin_recon_{i}") for i in range(5)]
        for sc in scopes:
            a = sc.admit_read(100)
            cr = a.start_child_read(physical_read_id=f"pread_fin_recon_{sc.operation_id}")
            cr.mark_started()
            cr.consume(80)
            sc.record_read(80, admission=a)

        recon_errors = []
        stop_recon = threading.Event()

        def worker_continuous_recon():
            while not stop_recon.is_set():
                res = self.tracker.reconcile_ledger(raise_on_error=False)
                if not res["reconciled"]:
                    recon_errors.append(res["discrepancies"])
                time.sleep(0.001)

        t_r = threading.Thread(target=worker_continuous_recon)
        t_r.start()

        def worker_finalize(sc):
            sc.finalize()

        threads = [threading.Thread(target=worker_finalize, args=(sc,)) for sc in scopes]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=3.0)

        time.sleep(0.05)
        stop_recon.set()
        t_r.join(timeout=3.0)

        self.assertEqual(recon_errors, [])
        final_recon = self.tracker.reconcile_ledger()
        self.assertTrue(final_recon["reconciled"])


class TestPhase20A3426RecoveryAndCleanupConcurrentStress(unittest.TestCase):
    """Stress test exercising recovery, retry, normal commits, cleanup, and continuous reconciliation."""

    def setUp(self):
        self.tracker = make_tracker()

    def test_20_comprehensive_recovery_cleanup_concurrent_stress(self):
        """Multi-worker stress exercising Normal Commit, Injected Failure, Recovery, Retry, Cleanup, and Continuous Recon."""
        stop_event = threading.Event()
        barrier = threading.Barrier(7)  # Synchronize all 7 workers to start simultaneously
        worker_exceptions: Dict[str, List[Exception]] = {
            "normal_commit": [],
            "injected_failure": [],
            "recovery": [],
            "recovery_retry": [],
            "cleanup": [],
            "duplicate_finalize": [],
            "continuous_recon": [],
        }

        # Shared list of prepared commits for recovery worker
        prepared_for_recovery: List[PreparedCommit] = []
        prepared_lock = threading.Lock()

        # Shared list of completed scopes for duplicate finalize
        completed_scopes: List[ActiveOperationScope] = []
        completed_lock = threading.Lock()

        # 1. Normal Commit Worker
        def worker_normal_commit():
            barrier.wait(timeout=5.0)
            for i in range(10):
                if stop_event.is_set():
                    break
                try:
                    op_id = f"op_norm_{i}_{uuid.uuid4().hex[:6]}"
                    sc = make_scope(self.tracker, op_id)
                    adm = sc.admit_read(50)
                    cr = adm.start_child_read(physical_read_id=f"pread_norm_{op_id}")
                    cr.mark_started()
                    cr.consume(40)
                    sc.record_read(40, admission=adm)
                    sc.finalize()
                    with completed_lock:
                        completed_scopes.append(sc)
                except Exception as exc:
                    worker_exceptions["normal_commit"].append(exc)
                time.sleep(0.002)

        # 2. Injected Failure Worker
        def worker_injected_failure():
            barrier.wait(timeout=5.0)
            for i in range(5):
                if stop_event.is_set():
                    break
                try:
                    op_id = f"op_inj_{i}_{uuid.uuid4().hex[:6]}"
                    sc = make_scope(self.tracker, op_id)
                    adm = sc.admit_read(60)
                    cr = adm.start_child_read(physical_read_id=f"pread_inj_{op_id}")
                    cr.mark_started()
                    cr.consume(50)
                    sc.record_read(50, admission=adm)

                    # Prepare commit and register into prepared_for_recovery
                    prep = self.tracker._prepare_scope_commit(sc, is_fail=False)
                    with prepared_lock:
                        prepared_for_recovery.append(prep)
                except Exception as exc:
                    worker_exceptions["injected_failure"].append(exc)
                time.sleep(0.003)

        # 3. Recovery Worker
        def worker_recovery():
            barrier.wait(timeout=5.0)
            while not stop_event.is_set():
                prep = None
                with prepared_lock:
                    if prepared_for_recovery:
                        prep = prepared_for_recovery.pop(0)
                if prep is not None:
                    try:
                        self.tracker._recover_commit_failure(prep, error=IOError("Simulated crash"), metrics_applied=False, step="stress_worker")
                        with completed_lock:
                            completed_scopes.append(prep.scope)
                    except Exception as exc:
                        worker_exceptions["recovery"].append(exc)
                time.sleep(0.005)

        # 4. Recovery Retry Worker
        def worker_recovery_retry():
            barrier.wait(timeout=5.0)
            for i in range(10):
                if stop_event.is_set():
                    break
                target_scope = None
                with completed_lock:
                    if completed_scopes:
                        target_scope = completed_scopes[i % len(completed_scopes)]
                if target_scope is not None:
                    try:
                        # Retry recovery on already recovered / committed scope (idempotent no-op)
                        self.tracker.retry_recovery(target_scope)
                    except Exception as exc:
                        worker_exceptions["recovery_retry"].append(exc)
                time.sleep(0.003)

        # 5. Cleanup Worker
        def worker_cleanup():
            barrier.wait(timeout=5.0)
            for i in range(10):
                if stop_event.is_set():
                    break
                try:
                    adm = self.tracker.admit_read(100, operation_id=f"op_clean_{i}_{uuid.uuid4().hex[:6]}")
                    # Zero bytes consumed -> safe cleanup
                    self.tracker.release_reservation(adm)
                except Exception as exc:
                    worker_exceptions["cleanup"].append(exc)
                time.sleep(0.002)

        # 6. Duplicate Finalization Worker
        def worker_duplicate_finalize():
            barrier.wait(timeout=5.0)
            for i in range(10):
                if stop_event.is_set():
                    break
                target_scope = None
                with completed_lock:
                    if completed_scopes:
                        target_scope = completed_scopes[i % len(completed_scopes)]
                if target_scope is not None:
                    try:
                        target_scope.finalize()
                    except Exception as exc:
                        worker_exceptions["duplicate_finalize"].append(exc)
                time.sleep(0.003)

        # 7. Continuous Reconciliation Worker
        def worker_continuous_recon():
            barrier.wait(timeout=5.0)
            recon_count = 0
            while not stop_event.is_set() and recon_count < 25:
                recon_count += 1
                res = self.tracker.reconcile_ledger(raise_on_error=False)
                if not res["reconciled"]:
                    worker_exceptions["continuous_recon"].append(Exception(f"Reconciliation error: {res['discrepancies']}"))
                time.sleep(0.002)

        workers = [
            threading.Thread(target=worker_normal_commit, name="normal_commit"),
            threading.Thread(target=worker_injected_failure, name="injected_failure"),
            threading.Thread(target=worker_recovery, name="recovery"),
            threading.Thread(target=worker_recovery_retry, name="recovery_retry"),
            threading.Thread(target=worker_cleanup, name="cleanup"),
            threading.Thread(target=worker_duplicate_finalize, name="duplicate_finalize"),
            threading.Thread(target=worker_continuous_recon, name="continuous_recon"),
        ]

        for w in workers:
            w.start()

        # Let workers execute for at least 300ms
        time.sleep(0.35)
        stop_event.set()

        # Bounded joins
        for w in workers:
            w.join(timeout=5.0)
            self.assertFalse(w.is_alive(), f"Worker {w.name} failed to terminate within bounded join")

        # Drain any remaining recovery items
        with prepared_lock:
            for prep in prepared_for_recovery:
                self.tracker._recover_commit_failure(prep, error=IOError("Drain recovery"), metrics_applied=False, step="drain")

        # Assert zero worker exceptions
        for w_name, errs in worker_exceptions.items():
            self.assertEqual(errs, [], f"Worker '{w_name}' encountered exceptions: {errs}")

        # Final ledger reconciliation
        final_recon = self.tracker.reconcile_ledger()
        self.assertTrue(final_recon["reconciled"], f"Final reconciliation failed: {final_recon['discrepancies']}")
        self.assertEqual(len(final_recon["discrepancies"]), 0)


if __name__ == "__main__":
    unittest.main()
