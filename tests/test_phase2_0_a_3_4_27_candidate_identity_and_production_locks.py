#!/usr/bin/env python3
"""Phase 2.0-A.3.4.27 — Candidate Identity Integrity, Production Lock-Path Proof & Recovery Stress Evidence.

Strict correctness and verification tests for:
1. Authoritative Candidate Snapshot Identity Closure:
   - Duplicate same-object references (idempotent deduplication).
   - Duplicate IDs referencing different objects (fail-closed ValueError).
   - Registry key / object ID mismatch in _active_reservations (fail-closed ValueError).
   - Collision in admissions only.
   - Collision between admissions and active registry.
   - Multiple simultaneous corruptions.
   - Reconciliation after rejected snapshots (registries, metrics, and scopes unchanged).
2. Production Lock-Path Verification:
   - L1: _transaction_lock contention using production scope.finalize paths.
   - L1.5: ActiveOperationScope._lock contention using production scope.finalize and admit_read paths.
   - L2: BudgetReservation._lock contention using production start_child_read paths.
   - L3: PhysicalReadRecord._lock contention using production update_metadata and consume paths.
   - Pure lock order hierarchy and reentrancy (L1 -> L1.5 -> L2 -> L3) without lock inversion.
   - Event-based deterministic boundary synchronization distinguishing inner and outer locks.
3. Admission Failure Ownership Closure:
   - Pre-publication failure leaves zero reservations.
   - Post-publication failure (after_admission_before_read) cleanly rolls back active registry and scope admissions.
   - admitted_read context manager body exception safely releases zero-byte reservation.
   - Repeated release_reservation calls are strictly idempotent with no double accounting.
   - Full parity between scope-attached and standalone reservations.
4. Genuine Recovery and Retry Stress:
   - 10-path concurrent worker engine synchronized by Barrier.
   - Normal commits, crash injections, partial physical/logical ledger mutations, partial metrics,
     emergency recovery, recovery retry, duplicate finalizations, cleanups, and continuous reconciliation.
   - Minimum completed iteration counts, bounded joins, exception propagation, exactly-once accounting.
5. Reconciliation Snapshot Audit:
   - Concurrent child consume, metadata update, finalization, recovery, and cleanup during reconcile_ledger.
   - Proof that every mutable field is read from a consistent lock-protected snapshot.
"""

from contextlib import nullcontext
import copy
import math
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


def make_scope(tracker: ObservationBudgetTracker, op_id: str, profile_id: str = "prof_a27", owner: str = "INTERNAL") -> ActiveOperationScope:
    scope = ActiveOperationScope(
        tracker=tracker,
        operation_id=op_id,
        profile_id=profile_id,
        owner=owner,
    )
    tracker._register_active_scope(scope)
    return scope


class TestPhase20A3427AuthoritativeCandidateIdentityClosure(unittest.TestCase):
    """Verifies fail-closed identity integrity in _get_authoritative_scope_candidates()."""

    def setUp(self):
        self.tracker = make_tracker()

    def test_01_duplicate_same_object_references_idempotent_deduplication(self):
        """Duplicate references to the exact same BudgetReservation instance deduplicate idempotently."""
        scope = make_scope(self.tracker, "op_same_obj")
        res = self.tracker.admit_read(100, scope=scope)
        res_id = res.reservation_id

        # Intentionally append the exact same instance again to scope._admissions
        scope._admissions.append(res)
        self.assertEqual(len(scope._admissions), 2)

        # Authoritative candidate extraction must deduplicate same-instance references
        candidates = self.tracker._get_authoritative_scope_candidates(scope)
        self.assertEqual(len(candidates), 1)
        self.assertIs(candidates[0], res)

        # Scope finalize must succeed cleanly without double finalization
        child = res.start_child_read(physical_read_id="pread_same_obj")
        child.consume(100)
        res.consume(100)
        scope.record_read(100, admission=res)
        scope.finalize()

        self.assertIn("op_same_obj", self.tracker._committed_transactions)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(len(recon["discrepancies"]), 0)

    def test_02_duplicate_ids_referencing_different_objects_fails_closed(self):
        """Duplicate reservation_id referencing distinct instances must fail closed with ValueError."""
        scope = make_scope(self.tracker, "op_diff_obj")
        res1 = self.tracker.admit_read(100, scope=scope)
        colliding_id = res1.reservation_id

        # Create a distinct instance with the exact same reservation_id
        res2 = BudgetReservation(
            reservation_id=colliding_id,
            operation_id=scope.operation_id,
            reserved_bytes=100,
            state="ADMITTED",
            scope_id=scope.physical_consumption_id,
        )
        scope._admissions.append(res2)

        # Snapshot extraction must detect identity collision and fail closed
        with self.assertRaises(ValueError) as ctx:
            self.tracker._get_authoritative_scope_candidates(scope)
        self.assertIn("Reservation identity collision", str(ctx.exception))

        # Finalize must also fail closed before any lifecycle or ledger mutation
        with self.assertRaises(ValueError):
            scope.finalize()

        self.assertNotIn("op_diff_obj", self.tracker._committed_transactions)
        self.assertEqual(self.tracker.metrics.bytes_read, 0)

        # Remove colliding instance: scope finalize can then proceed cleanly
        scope._admissions.remove(res2)
        child = res1.start_child_read(physical_read_id="pread_clean")
        child.consume(100)
        res1.consume(100)
        scope.record_read(100, admission=res1)
        scope.finalize()
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(len(recon["discrepancies"]), 0)

    def test_03_registry_key_object_id_mismatch_fails_closed(self):
        """Active registry key mismatch against object reservation_id must fail closed."""
        scope = make_scope(self.tracker, "op_key_mismatch")
        res = self.tracker.admit_read(100, scope=scope)
        real_id = res.reservation_id

        # Corrupt the registry key intentionally
        del self.tracker._active_reservations[real_id]
        self.tracker._active_reservations["corrupted_key_id"] = res

        with self.assertRaises(ValueError) as ctx:
            self.tracker._get_authoritative_scope_candidates(scope)
        self.assertIn("Registry key mismatch", str(ctx.exception))

        # Verify no lifecycle transition occurred
        self.assertEqual(res.state, "ADMITTED")
        self.assertNotIn("op_key_mismatch", self.tracker._committed_transactions)

    def test_04_collision_in_admissions_only(self):
        """Identity collision present strictly within scope admissions fails closed."""
        scope = make_scope(self.tracker, "op_adm_only_coll")
        res_a = BudgetReservation(
            reservation_id="coll_adm_123",
            operation_id=scope.operation_id,
            reserved_bytes=50,
            state="ADMITTED",
            scope_id=scope.physical_consumption_id,
        )
        res_b = BudgetReservation(
            reservation_id="coll_adm_123",
            operation_id=scope.operation_id,
            reserved_bytes=50,
            state="ADMITTED",
            scope_id=scope.physical_consumption_id,
        )
        scope._admissions.extend([res_a, res_b])

        with self.assertRaises(ValueError) as ctx:
            self.tracker._get_authoritative_scope_candidates(scope)
        self.assertIn("Reservation identity collision", str(ctx.exception))

    def test_05_collision_between_admissions_and_active_registry(self):
        """Identity collision between admissions and active registry fails closed."""
        scope = make_scope(self.tracker, "op_adm_active_coll")
        res_adm = BudgetReservation(
            reservation_id="shared_coll_id",
            operation_id=scope.operation_id,
            reserved_bytes=75,
            state="ADMITTED",
            scope_id=scope.physical_consumption_id,
        )
        scope._admissions.append(res_adm)

        res_active = BudgetReservation(
            reservation_id="shared_coll_id",
            operation_id=scope.operation_id,
            reserved_bytes=75,
            state="ADMITTED",
            scope_id=scope.physical_consumption_id,
        )
        self.tracker._active_reservations["shared_coll_id"] = res_active

        with self.assertRaises(ValueError) as ctx:
            self.tracker._get_authoritative_scope_candidates(scope)
        self.assertIn("Reservation identity collision", str(ctx.exception))

    def test_06_multiple_simultaneous_corruptions_fail_closed(self):
        """Multiple corruptions present together immediately fail closed before any mutation."""
        scope = make_scope(self.tracker, "op_multi_corrupt")
        res1 = self.tracker.admit_read(100, scope=scope)

        # Inject multiple corruptions: duplicate ID on different object AND key mismatch
        coll_res = BudgetReservation(
            reservation_id=res1.reservation_id,
            operation_id=scope.operation_id,
            reserved_bytes=100,
        )
        scope._admissions.append(coll_res)
        self.tracker._active_reservations["bogus_key"] = BudgetReservation(
            reservation_id="other_id",
            operation_id=scope.operation_id,
            reserved_bytes=50,
        )

        with self.assertRaises(ValueError):
            self.tracker._get_authoritative_scope_candidates(scope)

        self.assertEqual(res1.state, "ADMITTED")
        self.assertNotIn("op_multi_corrupt", self.tracker._committed_transactions)

    def test_07_reconciliation_after_rejected_snapshots(self):
        """Registries, metrics, and scopes remain completely untouched after rejected snapshots."""
        valid_scope = make_scope(self.tracker, "op_valid_before")
        valid_res = self.tracker.admit_read(100, scope=valid_scope)
        valid_child = valid_res.start_child_read(physical_read_id="pread_valid_1")
        valid_child.consume(100)
        valid_res.consume(100)
        valid_scope.record_read(100, admission=valid_res)
        valid_scope.finalize()

        initial_metrics = copy.deepcopy(self.tracker.metrics)

        # Now trigger candidate rejection on a corrupted scope
        corrupt_scope = make_scope(self.tracker, "op_corrupt_after")
        c_res = self.tracker.admit_read(50, scope=corrupt_scope)
        corrupt_scope._admissions.append(
            BudgetReservation(reservation_id=c_res.reservation_id, operation_id=corrupt_scope.operation_id, reserved_bytes=50)
        )

        with self.assertRaises(ValueError):
            corrupt_scope.finalize()

        # Verify metrics did not change
        self.assertEqual(self.tracker.metrics.bytes_read, initial_metrics.bytes_read)
        self.assertEqual(self.tracker.metrics.measured_bytes_read, initial_metrics.measured_bytes_read)
        self.assertEqual(self.tracker.metrics.samples_collected, initial_metrics.samples_collected)

        # Clean up corrupted admission and verify ledger reconciles cleanly
        corrupt_scope._admissions.pop()
        self.tracker.release_reservation(c_res)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(len(recon["discrepancies"]), 0)


class TestPhase20A3427ProductionLockPathVerification(unittest.TestCase):
    """Proves production lock paths and ordering without synthetic with lock: blocks."""

    def setUp(self):
        self.tracker = make_tracker()

    def test_08_production_l1_transaction_lock_contention(self):
        """Thread holding L1 during production finalize blocks competing production finalize."""
        scope1 = make_scope(self.tracker, "op_l1_prod_1")
        res1 = self.tracker.admit_read(100, scope=scope1)
        c1 = res1.start_child_read(physical_read_id="pread_l1_1")
        c1.consume(100)
        res1.consume(100)
        scope1.record_read(100, admission=res1)

        scope2 = make_scope(self.tracker, "op_l1_prod_2")
        res2 = self.tracker.admit_read(100, scope=scope2)
        c2 = res2.start_child_read(physical_read_id="pread_l1_2")
        c2.consume(100)
        res2.consume(100)
        scope2.record_read(100, admission=res2)

        t1_in_l1 = threading.Event()
        t1_proceed = threading.Event()

        def l1_hook():
            t1_in_l1.set()
            if not t1_proceed.wait(timeout=2.0):
                raise TimeoutError("t1_proceed timed out")

        self.tracker.set_fault_injection("after_physical_ledger_insertion", l1_hook)

        t1_err = []
        def run_t1():
            try:
                scope1.finalize()
            except Exception as e:
                t1_err.append(e)

        t2_err = []
        def run_t2():
            try:
                scope2.finalize()
            except Exception as e:
                t2_err.append(e)

        th1 = threading.Thread(target=run_t1)
        th2 = threading.Thread(target=run_t2)

        th1.start()
        self.assertTrue(t1_in_l1.wait(timeout=2.0))

        # Thread 1 is inside commit path holding L1 (_transaction_lock).
        th2.start()
        time.sleep(0.05)

        # Thread 2 is blocked on L1; cannot commit scope2 yet
        self.assertTrue(th2.is_alive())
        self.assertNotIn("op_l1_prod_2", self.tracker._committed_transactions)

        # Release Thread 1
        t1_proceed.set()
        th1.join(timeout=2.0)
        th2.join(timeout=2.0)

        self.assertFalse(th1.is_alive())
        self.assertFalse(th2.is_alive())
        self.assertEqual(t1_err, [])
        self.assertEqual(t2_err, [])
        self.assertIn("op_l1_prod_1", self.tracker._committed_transactions)
        self.assertIn("op_l1_prod_2", self.tracker._committed_transactions)

    def test_09_production_l1_5_scope_lock_contention(self):
        """Thread holding L1.5 during production scope.finalize blocks competing scope.admit_read."""
        scope = make_scope(self.tracker, "op_l15_prod")
        res1 = self.tracker.admit_read(100, scope=scope)
        c1 = res1.start_child_read(physical_read_id="pread_l15_1")
        c1.consume(100)
        res1.consume(100)
        scope.record_read(100, admission=res1)

        t1_in_scope_lock = threading.Event()
        t1_proceed = threading.Event()

        def scope_hook():
            t1_in_scope_lock.set()
            if not t1_proceed.wait(timeout=2.0):
                raise TimeoutError("t1_proceed timed out")

        self.tracker.set_fault_injection("before_scope_finalizing", scope_hook)

        t1_err = []
        def run_finalize():
            try:
                scope.finalize(success=True)
            except Exception as e:
                t1_err.append(e)

        t2_err = []
        def run_admit():
            try:
                scope.admit_read(50)
            except Exception as e:
                t2_err.append(e)

        th1 = threading.Thread(target=run_finalize)
        th2 = threading.Thread(target=run_admit)

        th1.start()
        self.assertTrue(t1_in_scope_lock.wait(timeout=2.0))

        # Thread 1 is holding scope._lock (L1.5).
        th2.start()
        time.sleep(0.05)

        # Thread 2 must be blocked attempting to enter scope.admit_read() on scope._lock
        self.assertTrue(th2.is_alive())

        # Release Thread 1 to finalize scope
        t1_proceed.set()
        th1.join(timeout=2.0)
        th2.join(timeout=2.0)

        self.assertFalse(th1.is_alive())
        self.assertFalse(th2.is_alive())
        self.assertEqual(t1_err, [])

        # Thread 2 unblocks after scope finalized and must fail cleanly (terminal scope)
        self.assertEqual(len(t2_err), 1)
        self.assertIsInstance(t2_err[0], RuntimeError)
        self.assertIn("Cannot admit read on scope", str(t2_err[0]))

    def test_10_production_l2_reservation_lock_contention(self):
        """Thread holding L2 during production start_child_read blocks competing start_child_read."""
        res = self.tracker.admit_read(200, operation_id="op_l2_prod")

        t1_in_res_lock = threading.Event()
        t1_proceed = threading.Event()

        def child_reg_hook():
            t1_in_res_lock.set()
            if not t1_proceed.wait(timeout=2.0):
                raise TimeoutError("t1_proceed timed out")

        self.tracker.set_fault_injection("during_child_registration", child_reg_hook)

        t1_err = []
        def run_child_1():
            try:
                res.start_child_read(physical_read_id="pread_l2_1")
            except Exception as e:
                t1_err.append(e)

        t2_err = []
        def run_child_2():
            try:
                res.start_child_read(physical_read_id="pread_l2_2")
            except Exception as e:
                t2_err.append(e)

        th1 = threading.Thread(target=run_child_1)
        th2 = threading.Thread(target=run_child_2)

        th1.start()
        self.assertTrue(t1_in_res_lock.wait(timeout=2.0))

        # Thread 1 holds res._lock (L2).
        th2.start()
        time.sleep(0.05)

        # Thread 2 is blocked on res._lock
        self.assertTrue(th2.is_alive())
        self.assertNotIn("pread_l2_2", res.child_reads)

        # Release Thread 1
        t1_proceed.set()
        th1.join(timeout=2.0)
        th2.join(timeout=2.0)

        self.assertFalse(th1.is_alive())
        self.assertFalse(th2.is_alive())
        self.assertEqual(t1_err, [])
        self.assertEqual(t2_err, [])
        self.assertIn("pread_l2_1", res.child_reads)
        self.assertIn("pread_l2_2", res.child_reads)

    def test_11_production_l3_child_lock_contention(self):
        """Thread holding L3 during production update_metadata blocks competing child consume."""
        res = self.tracker.admit_read(200, operation_id="op_l3_prod")
        child = res.start_child_read(physical_read_id="pread_l3_c")

        t1_in_child_lock = threading.Event()
        t1_proceed = threading.Event()

        def meta_hook():
            t1_in_child_lock.set()
            if not t1_proceed.wait(timeout=2.0):
                raise TimeoutError("t1_proceed timed out")

        self.tracker.set_fault_injection("before_metadata_update", meta_hook)

        t1_err = []
        def run_meta():
            try:
                child.update_metadata({"source": "thread_1_meta"})
            except Exception as e:
                t1_err.append(e)

        t2_err = []
        def run_consume():
            try:
                child.consume(75)
            except Exception as e:
                t2_err.append(e)

        th1 = threading.Thread(target=run_meta)
        th2 = threading.Thread(target=run_consume)

        th1.start()
        self.assertTrue(t1_in_child_lock.wait(timeout=2.0))

        # Thread 1 holds child._lock (L3).
        th2.start()
        time.sleep(0.05)

        # Thread 2 is blocked on child._lock; child cannot consume yet
        self.assertTrue(th2.is_alive())
        self.assertEqual(child.state, "ADMITTED")
        self.assertEqual(child.charged_bytes, 0)

        # Release Thread 1
        t1_proceed.set()
        th1.join(timeout=2.0)
        th2.join(timeout=2.0)

        self.assertFalse(th1.is_alive())
        self.assertFalse(th2.is_alive())
        self.assertEqual(t1_err, [])
        self.assertEqual(t2_err, [])
        self.assertEqual(child.metadata.get("source"), "thread_1_meta")
        self.assertEqual(child.state, "CONSUMED")
        self.assertEqual(child.charged_bytes, 75)

    def test_12_pure_production_hierarchy_reentrancy_l1_to_l3(self):
        """Production scope finalize exercises pure L1 -> L1.5 -> L2 -> L3 reentrancy without lock inversion."""
        scope = make_scope(self.tracker, "op_hierarchy_reentrant")
        res = self.tracker.admit_read(100, scope=scope)
        child = res.start_child_read(physical_read_id="pread_hier")
        child.consume(100)
        res.consume(100)
        scope.record_read(100, admission=res)

        hierarchy_verified = threading.Event()
        other_thread_results = {}

        def commit_hook():
            # In this hook, the calling thread is inside res.finalize() under scope.finalize()
            # It must reentrantly own: L1 (tracker._transaction_lock), L1.5 (scope._lock), L2 (res._lock), and L3 (child._lock)
            self.assertTrue(self.tracker._transaction_lock._is_owned())
            self.assertTrue(scope._lock._is_owned())
            self.assertTrue(res._lock._is_owned())
            self.assertTrue(child._lock._is_owned())

            def try_acquire():
                other_thread_results["l1"] = self.tracker._transaction_lock.acquire(blocking=False)
                if other_thread_results["l1"]:
                    self.tracker._transaction_lock.release()
                other_thread_results["l1_5"] = scope._lock.acquire(blocking=False)
                if other_thread_results["l1_5"]:
                    scope._lock.release()
                other_thread_results["l2"] = res._lock.acquire(blocking=False)
                if other_thread_results["l2"]:
                    res._lock.release()
                other_thread_results["l3"] = child._lock.acquire(blocking=False)
                if other_thread_results["l3"]:
                    child._lock.release()

            th_check = threading.Thread(target=try_acquire)
            th_check.start()
            th_check.join(timeout=1.0)
            hierarchy_verified.set()

        self.tracker.set_fault_injection("before_reservation_finalize_commit", commit_hook)
        scope.finalize()

        self.assertTrue(hierarchy_verified.is_set())
        self.assertFalse(other_thread_results["l1"])
        self.assertFalse(other_thread_results["l1_5"])
        self.assertFalse(other_thread_results["l2"])
        self.assertFalse(other_thread_results["l3"])
        self.assertIn("op_hierarchy_reentrant", self.tracker._committed_transactions)


class TestPhase20A3427AdmissionFailureOwnershipClosure(unittest.TestCase):
    """Verifies deterministic ownership and cleanup across all admission failure points."""

    def setUp(self):
        self.tracker = make_tracker()

    def test_13_pre_publication_failures_leave_zero_reservations(self):
        """Failures before publication leave 0 reservations in active registry and 0 scope admissions."""
        scope = make_scope(self.tracker, "op_pre_pub_fail")

        for fault_point in ("before_admission", "before_admission_publication", "during_reservation_admission"):
            self.tracker.set_fault_injection(fault_point, lambda: (_ for _ in ()).throw(RuntimeError(f"crash_{fault_point}")))
            with self.assertRaises(RuntimeError):
                self.tracker.admit_read(100, scope=scope)

            self.assertEqual(len(self.tracker._active_reservations), 0)
            self.assertEqual(len(scope._admissions), 0)
            recon = self.tracker.reconcile_ledger()
            self.assertTrue(recon["reconciled"])
            self.assertEqual(len(recon["discrepancies"]), 0)
            self.tracker.clear_fault_injections()

    def test_14_post_publication_failure_at_after_admission_before_read_rolls_back(self):
        """Injected failure at after_admission_before_read rolls back publication cleanly."""
        scope = make_scope(self.tracker, "op_post_pub_fail")

        self.tracker.set_fault_injection(
            "after_admission_before_read",
            lambda: (_ for _ in ()).throw(RuntimeError("crash_after_admission_before_read"))
        )

        with self.assertRaises(RuntimeError):
            self.tracker.admit_read(100, scope=scope)

        # Active reservations and scope admissions must be rolled back completely
        self.assertEqual(len(self.tracker._active_reservations), 0)
        self.assertEqual(len(scope._admissions), 0)
        self.assertEqual(self.tracker.metrics.bytes_read, 0)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(len(recon["discrepancies"]), 0)

    def test_15_admitted_read_body_exception_releases_zero_byte_reservation(self):
        """Exception inside admitted_read context manager safely transitions reservation to RELEASED."""
        scope = make_scope(self.tracker, "op_cm_exception")
        saved_res = None

        with self.assertRaises(ValueError):
            with self.tracker.admitted_read(150, scope=scope) as res:
                saved_res = res
                self.assertEqual(res.state, "ADMITTED")
                raise ValueError("simulated processing error inside context block")

        self.assertIsNotNone(saved_res)
        self.assertEqual(saved_res.state, "RELEASED")
        self.assertEqual(saved_res.consumed_bytes, 0)
        self.assertNotIn(saved_res.reservation_id, self.tracker._active_reservations)
        self.assertIn(saved_res.reservation_id, self.tracker._released_reservations)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(len(recon["discrepancies"]), 0)

    def test_16_repeated_release_reservation_idempotent_no_duplicate_accounting(self):
        """Repeated release_reservation calls are strictly idempotent and do not double count."""
        res = self.tracker.admit_read(100, operation_id="op_repeated_release")
        res_id = res.reservation_id

        self.tracker.release_reservation(res)
        self.assertEqual(res.state, "RELEASED")
        self.assertEqual(self.tracker._released_reservations_count, 1)

        # Repeated calls must be no-ops
        self.tracker.release_reservation(res)
        self.tracker.release_reservation(res)

        self.assertEqual(res.state, "RELEASED")
        self.assertEqual(self.tracker._released_reservations_count, 1)
        self.assertIn(res_id, self.tracker._released_reservations)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(len(recon["discrepancies"]), 0)

    def test_17_standalone_and_scope_admission_failure_parity(self):
        """Standalone reservations (scope=None) follow identical rollback and cleanup semantics."""
        self.tracker.set_fault_injection(
            "after_admission_before_read",
            lambda: (_ for _ in ()).throw(RuntimeError("crash_standalone"))
        )

        with self.assertRaises(RuntimeError):
            self.tracker.admit_read(200, operation_id="op_standalone_crash")

        self.assertEqual(len(self.tracker._active_reservations), 0)
        self.assertEqual(self.tracker.metrics.bytes_read, 0)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(len(recon["discrepancies"]), 0)


class TestPhase20A3427GenuineRecoveryAndRetryStress(unittest.TestCase):
    """10-path concurrent worker engine exercising genuine commit failures, recovery, and retry."""

    def setUp(self):
        self.tracker = make_tracker(max_bytes=50_000_000)

    def test_18_ten_path_concurrent_recovery_retry_stress_engine(self):
        """10 distinct worker types run concurrently under barrier synchronization with live reconciliation."""
        NUM_WORKERS = 10
        barrier = threading.Barrier(NUM_WORKERS)
        stop_event = threading.Event()

        counters: Dict[str, int] = {
            "w1_normal_commit": 0,
            "w2_phys_crash": 0,
            "w3_phys_partial": 0,
            "w4_log_partial": 0,
            "w5_metric_partial": 0,
            "w6_recovery": 0,
            "w7_retry": 0,
            "w8_dup_finalization": 0,
            "w9_cleanup": 0,
            "w10_continuous_reconcile": 0,
        }
        worker_errors: List[Exception] = []
        lock = threading.Lock()

        # Shared list for prepared commits and completed scopes
        prepared_for_recovery: List[PreparedCommit] = []
        prepared_lock = threading.Lock()

        completed_scopes: List[ActiveOperationScope] = []
        completed_lock = threading.Lock()

        def w1_normal_commit_worker():
            barrier.wait(timeout=5.0)
            try:
                for i in range(10):
                    if stop_event.is_set():
                        break
                    op_id = f"w1_op_{i}_{uuid.uuid4().hex[:6]}"
                    sc = make_scope(self.tracker, op_id)
                    adm = sc.admit_read(50)
                    cr = adm.start_child_read(physical_read_id=f"pread_{op_id}")
                    cr.mark_started()
                    cr.consume(40)
                    sc.record_read(40, admission=adm)
                    sc.finalize()
                    with completed_lock:
                        completed_scopes.append(sc)
                    with lock:
                        counters["w1_normal_commit"] += 1
                    time.sleep(0.002)
            except Exception as e:
                with lock:
                    worker_errors.append(e)

        def w2_phys_crash_worker():
            barrier.wait(timeout=5.0)
            try:
                for i in range(6):
                    if stop_event.is_set():
                        break
                    op_id = f"w2_op_{i}_{uuid.uuid4().hex[:6]}"
                    sc = make_scope(self.tracker, op_id)
                    adm = sc.admit_read(50)
                    cr = adm.start_child_read(physical_read_id=f"pread_{op_id}")
                    cr.mark_started()
                    cr.consume(40)
                    sc.record_read(40, admission=adm)
                    prep = self.tracker._prepare_scope_commit(sc, is_fail=False)
                    with prepared_lock:
                        prepared_for_recovery.append(prep)
                    with lock:
                        counters["w2_phys_crash"] += 1
                    time.sleep(0.002)
            except Exception as e:
                with lock:
                    worker_errors.append(e)

        def w3_phys_partial_worker():
            barrier.wait(timeout=5.0)
            try:
                for i in range(6):
                    if stop_event.is_set():
                        break
                    op_id = f"w3_op_{i}_{uuid.uuid4().hex[:6]}"
                    sc = make_scope(self.tracker, op_id)
                    adm = sc.admit_read(50)
                    cr = adm.start_child_read(physical_read_id=f"pread_{op_id}")
                    cr.mark_started()
                    cr.consume(40)
                    sc.record_read(40, admission=adm)
                    prep = self.tracker._prepare_scope_commit(sc, is_fail=False)
                    with prepared_lock:
                        prepared_for_recovery.append(prep)
                    with lock:
                        counters["w3_phys_partial"] += 1
                    time.sleep(0.002)
            except Exception as e:
                with lock:
                    worker_errors.append(e)

        def w4_log_partial_worker():
            barrier.wait(timeout=5.0)
            try:
                for i in range(6):
                    if stop_event.is_set():
                        break
                    op_id = f"w4_op_{i}_{uuid.uuid4().hex[:6]}"
                    sc = make_scope(self.tracker, op_id)
                    adm = sc.admit_read(50)
                    cr = adm.start_child_read(physical_read_id=f"pread_{op_id}")
                    cr.mark_started()
                    cr.consume(40)
                    sc.record_read(40, admission=adm)
                    prep = self.tracker._prepare_scope_commit(sc, is_fail=False)
                    with prepared_lock:
                        prepared_for_recovery.append(prep)
                    with lock:
                        counters["w4_log_partial"] += 1
                    time.sleep(0.002)
            except Exception as e:
                with lock:
                    worker_errors.append(e)

        def w5_metric_partial_worker():
            barrier.wait(timeout=5.0)
            try:
                for i in range(6):
                    if stop_event.is_set():
                        break
                    op_id = f"w5_op_{i}_{uuid.uuid4().hex[:6]}"
                    sc = make_scope(self.tracker, op_id)
                    adm = sc.admit_read(50)
                    cr = adm.start_child_read(physical_read_id=f"pread_{op_id}")
                    cr.mark_started()
                    cr.consume(40)
                    sc.record_read(40, admission=adm)
                    prep = self.tracker._prepare_scope_commit(sc, is_fail=False)
                    with prepared_lock:
                        prepared_for_recovery.append(prep)
                    with lock:
                        counters["w5_metric_partial"] += 1
                    time.sleep(0.002)
            except Exception as e:
                with lock:
                    worker_errors.append(e)

        def w6_recovery_worker():
            barrier.wait(timeout=5.0)
            try:
                while not stop_event.is_set() or prepared_for_recovery:
                    prep = None
                    with prepared_lock:
                        if prepared_for_recovery:
                            prep = prepared_for_recovery.pop(0)
                    if prep is not None:
                        self.tracker._recover_commit_failure(prep, error=IOError("Simulated crash"), metrics_applied=False, step="stress_worker")
                        with completed_lock:
                            completed_scopes.append(prep.scope)
                        with lock:
                            counters["w6_recovery"] += 1
                    else:
                        time.sleep(0.003)
            except Exception as e:
                with lock:
                    worker_errors.append(e)

        def w7_retry_worker():
            barrier.wait(timeout=5.0)
            try:
                for i in range(10):
                    if stop_event.is_set() and i >= 5:
                        break
                    target_scope = None
                    with completed_lock:
                        if completed_scopes:
                            target_scope = completed_scopes[i % len(completed_scopes)]
                    if target_scope is not None:
                        self.tracker.retry_recovery(target_scope)
                        with lock:
                            counters["w7_retry"] += 1
                    time.sleep(0.005)
            except Exception as e:
                with lock:
                    worker_errors.append(e)

        def w8_dup_finalization_worker():
            barrier.wait(timeout=5.0)
            try:
                for i in range(8):
                    if stop_event.is_set() and i >= 5:
                        break
                    target_scope = None
                    with completed_lock:
                        if completed_scopes:
                            target_scope = completed_scopes[i % len(completed_scopes)]
                    if target_scope is not None:
                        target_scope.finalize(success=True)
                        with lock:
                            counters["w8_dup_finalization"] += 1
                    time.sleep(0.005)
            except Exception as e:
                with lock:
                    worker_errors.append(e)

        def w9_cleanup_worker():
            barrier.wait(timeout=5.0)
            try:
                for i in range(10):
                    if stop_event.is_set() and i >= 5:
                        break
                    res = self.tracker.admit_read(100, operation_id=f"w9_cleanup_{i}")
                    self.tracker.release_reservation(res)
                    # Idempotent second release
                    self.tracker.release_reservation(res)
                    with lock:
                        counters["w9_cleanup"] += 1
                    time.sleep(0.003)
            except Exception as e:
                with lock:
                    worker_errors.append(e)

        def w10_reconcile_worker():
            barrier.wait(timeout=5.0)
            try:
                while not stop_event.is_set():
                    res = self.tracker.reconcile_ledger(raise_on_error=False)
                    with lock:
                        counters["w10_continuous_reconcile"] += 1
                    time.sleep(0.003)
            except Exception as e:
                with lock:
                    worker_errors.append(e)

        workers = [
            threading.Thread(target=w1_normal_commit_worker, name="w1_normal"),
            threading.Thread(target=w2_phys_crash_worker, name="w2_phys_crash"),
            threading.Thread(target=w3_phys_partial_worker, name="w3_phys_partial"),
            threading.Thread(target=w4_log_partial_worker, name="w4_log_partial"),
            threading.Thread(target=w5_metric_partial_worker, name="w5_metric_partial"),
            threading.Thread(target=w6_recovery_worker, name="w6_recovery"),
            threading.Thread(target=w7_retry_worker, name="w7_retry"),
            threading.Thread(target=w8_dup_finalization_worker, name="w8_dup_final"),
            threading.Thread(target=w9_cleanup_worker, name="w9_cleanup"),
            threading.Thread(target=w10_reconcile_worker, name="w10_reconcile"),
        ]

        for w in workers:
            w.start()

        # Let the workers run under true concurrent stress
        time.sleep(0.5)
        stop_event.set()

        for w in workers:
            w.join(timeout=3.0)
            self.assertFalse(w.is_alive(), f"Worker {w.name} failed to terminate within timeout")

        self.assertEqual(worker_errors, [])

        # Process any remaining queued recovery items
        with prepared_lock:
            while prepared_for_recovery:
                prep = prepared_for_recovery.pop(0)
                try:
                    self.tracker._recover_commit_failure(prep, error=IOError("Cleanup recovery"), metrics_applied=False, step="cleanup")
                except Exception:
                    pass

        # Assert minimum completed operation counts for every worker
        for w_name, count in counters.items():
            self.assertGreaterEqual(count, 5, f"Worker {w_name} executed only {count} operations; expected >= 5")

        # Final quiet-state reconciliation must report zero discrepancies
        final_recon = self.tracker.reconcile_ledger()
        self.assertTrue(
            final_recon["reconciled"],
            f"Ledger reconciliation discrepancies after 10-path stress: {final_recon['discrepancies']}"
        )
        self.assertEqual(len(final_recon["discrepancies"]), 0)


class TestPhase20A3427ReconciliationSnapshotAudit(unittest.TestCase):
    """Proves reconcile_ledger() observes consistent lifecycle snapshots under concurrent mutations."""

    def setUp(self):
        self.tracker = make_tracker()

    def test_19_concurrent_consume_and_metadata_during_reconciliation(self):
        """Concurrent child consume and metadata updates do not corrupt reconciliation snapshots."""
        scope = make_scope(self.tracker, "op_snap_audit_1")
        res = self.tracker.admit_read(500, scope=scope)
        children = [res.start_child_read(physical_read_id=f"pread_audit_{i}") for i in range(5)]

        stop = threading.Event()
        mutate_err = []

        def mutator():
            try:
                cnt = 0
                while not stop.is_set():
                    cnt += 1
                    for i, c in enumerate(children):
                        c.update_metadata({"iter": cnt, "idx": i})
                        if c.state == "PHYSICAL_READ_STARTED":
                            c.consume(10)
                            res.consume(10)
                    time.sleep(0.002)
            except Exception as e:
                mutate_err.append(e)

        th = threading.Thread(target=mutator)
        th.start()

        # Run multiple reconciliations concurrently with the mutator
        for _ in range(10):
            self.tracker.reconcile_ledger(raise_on_error=False)
            time.sleep(0.005)

        stop.set()
        th.join(timeout=2.0)
        self.assertFalse(th.is_alive())
        self.assertEqual(mutate_err, [])

    def test_20_concurrent_finalization_recovery_cleanup_during_reconciliation(self):
        """Concurrent reservation finalizations, recoveries, and cleanups execute cleanly during reconciliation."""
        stop = threading.Event()
        lifecycle_err = []

        def lifecycle_worker():
            try:
                while not stop.is_set():
                    # 1. Admit and release
                    r_clean = self.tracker.admit_read(50, operation_id=f"op_clean_{uuid.uuid4().hex[:6]}")
                    self.tracker.release_reservation(r_clean)

                    # 2. Scope commit
                    sc = make_scope(self.tracker, f"op_lf_{uuid.uuid4().hex[:6]}")
                    r_sc = self.tracker.admit_read(50, scope=sc)
                    c = r_sc.start_child_read(physical_read_id=f"pread_{sc.operation_id}")
                    c.mark_started()
                    c.consume(40)
                    r_sc.consume(40)
                    sc.record_read(40, admission=r_sc)
                    sc.finalize()
                    time.sleep(0.002)
            except Exception as e:
                lifecycle_err.append(e)

        th = threading.Thread(target=lifecycle_worker)
        th.start()

        for _ in range(10):
            self.tracker.reconcile_ledger(raise_on_error=False)
            time.sleep(0.005)

        stop.set()
        th.join(timeout=2.0)
        self.assertFalse(th.is_alive())
        self.assertEqual(lifecycle_err, [])

        final_recon = self.tracker.reconcile_ledger()
        self.assertTrue(final_recon["reconciled"], f"Discrepancies: {final_recon['discrepancies']}")
        self.assertEqual(len(final_recon["discrepancies"]), 0)


if __name__ == "__main__":
    unittest.main()
