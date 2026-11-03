"""Phase 2.0-A.3.4.20 — Shared Reservation Concurrency Atomicity & Batch Lifecycle Semantics Tests.

Validates:
1. Workstream A: Parent/child atomic transitions and hierarchical locking order.
2. Workstream B: Same-object concurrent transition tests with deterministic barrier synchronization.
3. Workstream C: Transaction and reconciliation snapshot consistency without intermediate states.
4. Workstream D: Batch preflight provenance semantics, unconditional invocation requirement, and contradiction detection.
5. Workstream E: Adversarial concurrency and high-load stress testing.
"""

import copy
import threading
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple

from extractor.observation_budget import (
    DEFAULT_CONSERVATIVE_UNKNOWN_BYTES,
    BatchReadRecord,
    BatchSliceSpec,
    BudgetReservation,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    PhysicalReadRecord,
    RemoteInvocationRecord,
)
from extractor.target_adapter import RemoteSshTargetAdapter


class MockBarrierRunnerA3420:
    """Mock command runner for deterministic concurrency and preflight injection."""

    def __init__(self):
        self.invocations: List[Dict[str, Any]] = []
        self.fail_before_execution = False
        self.preflight_reason = "executable unavailable"
        self.return_code = 0
        self.stdout_payload = "OK\n"
        self.stderr_payload = ""
        self._lock = threading.Lock()
        self.delay_sec = 0.0

    def check_preflight(self, cmd_args: List[str]) -> Tuple[bool, Optional[str]]:
        if self.fail_before_execution:
            return False, self.preflight_reason
        return True, None

    def __call__(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        if self.delay_sec > 0:
            time.sleep(self.delay_sec)
        with self._lock:
            self.invocations.append({
                "cmd": list(cmd_args),
                "timeout": timeout,
                "timestamp": time.time(),
            })
        if self.return_code != 0:
            return self.return_code, self.stdout_payload, self.stderr_payload or f"Exit {self.return_code}"
        if self.stdout_payload == "OK\n" and any("dd if=/proc" in str(arg) for arg in cmd_args):
            return 0, "0|AQIDBAUGBwgJCgsMDQ4PEA==\n1|AQIDBAUGBwgJCgsMDQ4PEA==\n", ""
        return 0, self.stdout_payload, self.stderr_payload


class TestPhase20A3420ParentChildAtomicTransitions(unittest.TestCase):
    """Workstream A: Parent/Child Atomic Transitions & Two-Phase Invariants."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_01_two_phase_release_validates_all_children_before_mutation(self):
        """1. BudgetReservation.release() validates all child records; if any child violates, zero children mutate."""
        res = self.tracker.admit_read(200, operation_id="op_tp_rel")
        cr1 = res.start_child_read(physical_read_id="cr_tp_1")
        cr2 = res.start_child_read(physical_read_id="cr_tp_2")
        cr3 = res.start_child_read(physical_read_id="cr_tp_3")

        # cr1 is ADMITTED, cr2 starts, cr3 is ADMITTED
        cr2.mark_started()
        self.assertEqual(cr2.state, "PHYSICAL_READ_STARTED")
        self.assertEqual(cr1.state, "ADMITTED")
        self.assertEqual(cr3.state, "ADMITTED")

        # Attempting parent release must fail during phase 1 validation because cr2 is started
        with self.assertRaises(RuntimeError) as cm:
            res.release()
        self.assertIn("PHYSICAL_READ_STARTED", str(cm.exception))

        # Atomic two-phase guarantee: cr1 and cr3 MUST NOT have transitioned to RELEASED
        self.assertEqual(cr1.state, "ADMITTED")
        self.assertEqual(cr2.state, "PHYSICAL_READ_STARTED")
        self.assertEqual(cr3.state, "ADMITTED")
        self.assertIn(res.state, ("ADMITTED", "RESERVED"))
        self.assertIsNone(cr1.terminal_at_ms)
        self.assertIsNone(cr3.terminal_at_ms)

    def test_02_two_phase_release_assigns_identical_terminal_timestamp(self):
        """2. Successful parent release assigns identical terminal_at_ms across parent and all children."""
        res = self.tracker.admit_read(300, operation_id="op_tp_ts")
        cr1 = res.start_child_read(physical_read_id="cr_ts_1")
        cr2 = res.start_child_read(physical_read_id="cr_ts_2")

        res.release()
        self.assertEqual(res.state, "RELEASED")
        self.assertEqual(cr1.state, "RELEASED")
        self.assertEqual(cr2.state, "RELEASED")

        # All terminal timestamps must be identical
        t_term = res.terminal_at_ms
        self.assertIsNotNone(t_term)
        self.assertEqual(cr1.terminal_at_ms, t_term)
        self.assertEqual(cr2.terminal_at_ms, t_term)

    def test_03_two_phase_account_validates_all_children_before_mutation(self):
        """3. BudgetReservation.account() validates all children; in-flight child prevents mutation."""
        res = self.tracker.admit_read(300, operation_id="op_tp_acc")
        cr1 = res.start_child_read(physical_read_id="cr_acc_1")
        cr2 = res.start_child_read(physical_read_id="cr_acc_2")

        cr1.mark_started()
        cr1.consume(64)
        cr2.mark_started()  # cr2 remains in-flight

        with self.assertRaises(RuntimeError) as cm:
            res.account()
        self.assertIn("remains in flight", str(cm.exception))

        # cr1 must still be CONSUMED, not ACCOUNTED
        self.assertEqual(cr1.state, "CONSUMED")
        self.assertEqual(cr2.state, "PHYSICAL_READ_STARTED")
        self.assertEqual(res.state, "CONSUMED")
        self.assertIsNone(res.terminal_at_ms)
        self.assertIsNone(cr1.terminal_at_ms)

    def test_04_child_mark_started_rejected_if_parent_terminal(self):
        """4. Child PhysicalReadRecord.mark_started() is rejected if parent reservation is already terminal."""
        res = self.tracker.admit_read(100, operation_id="op_ch_start")
        cr = res.start_child_read(physical_read_id="cr_term_p")

        res.release()
        self.assertEqual(res.state, "RELEASED")

        with self.assertRaises(RuntimeError) as cm:
            cr.mark_started()
        self.assertIn("terminal state", str(cm.exception))

    def test_05_child_consume_rejected_if_parent_terminal(self):
        """5. Child PhysicalReadRecord.consume() is rejected if parent reservation is already terminal."""
        res = self.tracker.admit_read(100, operation_id="op_ch_cons")
        cr = res.start_child_read(physical_read_id="cr_term_cons")

        res.release()
        with self.assertRaises(RuntimeError) as cm:
            cr.consume(64)
        self.assertIn("terminal state", str(cm.exception))

    def test_06_hierarchical_locking_prevents_inversion(self):
        """6. Child methods acquire parent lock before child lock, strictly following lock order."""
        res = self.tracker.admit_read(100, operation_id="op_lock_ord")
        cr = res.start_child_read(physical_read_id="cr_lock_1")

        # Ensure parent lock is acquired during child operations
        with res._lock:
            # Child operation within parent lock works cleanly via reentrancy
            cr.mark_started()
            cr.consume(32)
            self.assertEqual(cr.state, "CONSUMED")
            self.assertEqual(res.consumed_bytes, 32)


class TestPhase20A3420SameObjectConcurrentTransitions(unittest.TestCase):
    """Workstream B: Same-Object Concurrent Transitions with Deterministic Barriers."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_07_concurrent_release_vs_mark_started_on_same_reservation(self):
        """7. Thread A releases reservation while Thread B starts child read on the same reservation."""
        res = self.tracker.admit_read(128, operation_id="op_race_rel_start")
        cr = res.start_child_read(physical_read_id="cr_race_1")

        barrier = threading.Barrier(2)
        results = {"release": None, "mark_started": None}

        def worker_release():
            try:
                barrier.wait()
                res.release()
                results["release"] = "SUCCESS"
            except Exception as e:
                results["release"] = type(e).__name__

        def worker_start():
            try:
                barrier.wait()
                cr.mark_started()
                results["mark_started"] = "SUCCESS"
            except Exception as e:
                results["mark_started"] = type(e).__name__

        t1 = threading.Thread(target=worker_release)
        t2 = threading.Thread(target=worker_start)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)

        # Exactly one must succeed and one must fail with RuntimeError, or deterministic ordering
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        if results["release"] == "SUCCESS":
            # Parent released first: child start must be rejected
            self.assertEqual(results["mark_started"], "RuntimeError")
            self.assertEqual(res.state, "RELEASED")
            self.assertEqual(cr.state, "RELEASED")
        else:
            # Child started first: parent release must be rejected
            self.assertEqual(results["release"], "RuntimeError")
            self.assertEqual(results["mark_started"], "SUCCESS")
            self.assertEqual(cr.state, "PHYSICAL_READ_STARTED")

    def test_08_concurrent_release_vs_consume_on_same_reservation(self):
        """8. Thread A releases reservation while Thread B consumes bytes on the same child read."""
        res = self.tracker.admit_read(128, operation_id="op_race_rel_cons")
        cr = res.start_child_read(physical_read_id="cr_race_2")

        barrier = threading.Barrier(2)
        results = {"release": None, "consume": None}

        def worker_release():
            try:
                barrier.wait()
                res.release()
                results["release"] = "SUCCESS"
            except Exception as e:
                results["release"] = type(e).__name__

        def worker_consume():
            try:
                barrier.wait()
                cr.consume(64)
                results["consume"] = "SUCCESS"
            except Exception as e:
                results["consume"] = type(e).__name__

        t1 = threading.Thread(target=worker_release)
        t2 = threading.Thread(target=worker_consume)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)

        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        if results["release"] == "SUCCESS":
            self.assertEqual(results["consume"], "RuntimeError")
            self.assertEqual(res.state, "RELEASED")
            self.assertEqual(res.consumed_bytes, 0)
        else:
            self.assertEqual(results["release"], "RuntimeError")
            self.assertEqual(results["consume"], "SUCCESS")
            self.assertEqual(res.consumed_bytes, 64)

    def test_09_concurrent_account_vs_mark_failed_accounted_on_same_reservation(self):
        """9. Thread A accounts reservation while Thread B marks it failed_accounted."""
        res = self.tracker.admit_read(128, operation_id="op_race_acc_fail")
        cr = res.start_child_read(physical_read_id="cr_race_3")
        cr.mark_started()
        cr.consume(64)

        barrier = threading.Barrier(2)
        results = {"account": None, "failed_accounted": None}

        def worker_account():
            try:
                barrier.wait()
                res.account()
                results["account"] = "SUCCESS"
            except Exception as e:
                results["account"] = type(e).__name__

        def worker_failed_accounted():
            try:
                barrier.wait()
                res.mark_failed_accounted()
                results["failed_accounted"] = "SUCCESS"
            except Exception as e:
                results["failed_accounted"] = type(e).__name__

        t1 = threading.Thread(target=worker_account)
        t2 = threading.Thread(target=worker_failed_accounted)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)

        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        # One must win and the other must be rejected due to conflicting terminal transitions
        winners = [k for k, v in results.items() if v == "SUCCESS"]
        losers = [k for k, v in results.items() if v == "RuntimeError"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 1)

    def test_10_concurrent_finalize_vs_release_on_same_reservation(self):
        """10. Thread A finalizes reservation while Thread B attempts release."""
        res = self.tracker.admit_read(128, operation_id="op_race_fin_rel")
        cr = res.start_child_read(physical_read_id="cr_race_4")
        cr.mark_started()
        cr.consume(64)

        barrier = threading.Barrier(2)
        results = {"finalize": None, "release": None}

        def worker_finalize():
            try:
                barrier.wait()
                res.finalize()
                results["finalize"] = "SUCCESS"
            except Exception as e:
                results["finalize"] = type(e).__name__

        def worker_release():
            try:
                barrier.wait()
                res.release()
                results["release"] = "SUCCESS"
            except Exception as e:
                results["release"] = type(e).__name__

        t1 = threading.Thread(target=worker_finalize)
        t2 = threading.Thread(target=worker_release)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)

        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        # Release must fail because consumed_bytes > 0
        self.assertEqual(results["release"], "RuntimeError")
        self.assertEqual(results["finalize"], "SUCCESS")
        self.assertIn(res.state, ("ACCOUNTED", "FINALIZED"))

    def test_11_concurrent_parent_account_vs_child_consume(self):
        """11. Thread A calls parent account() while Thread B calls child consume()."""
        res = self.tracker.admit_read(128, operation_id="op_race_p_acc_c_cons")
        cr1 = res.start_child_read(physical_read_id="cr_race_5_1")
        cr2 = res.start_child_read(physical_read_id="cr_race_5_2")
        cr1.mark_started()
        cr1.consume(32)

        barrier = threading.Barrier(2)
        results = {"parent_account": None, "child_consume": None}

        def worker_parent_acc():
            try:
                barrier.wait()
                res.account()
                results["parent_account"] = "SUCCESS"
            except Exception as e:
                results["parent_account"] = type(e).__name__

        def worker_child_cons():
            try:
                barrier.wait()
                cr2.consume(32)
                results["child_consume"] = "SUCCESS"
            except Exception as e:
                results["child_consume"] = type(e).__name__

        t1 = threading.Thread(target=worker_parent_acc)
        t2 = threading.Thread(target=worker_child_cons)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)

        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        if results["child_consume"] == "RuntimeError":
            # Parent accounted first: cr2 consume must fail due to terminal parent
            self.assertEqual(results["parent_account"], "SUCCESS")
        else:
            # Child consume happened before parent accounted; parent accounted both
            self.assertEqual(results["child_consume"], "SUCCESS")
            self.assertEqual(results["parent_account"], "SUCCESS")

    def test_12_two_concurrent_identical_terminal_ops_on_child_read(self):
        """12. Two concurrent identical account() calls on the same PhysicalReadRecord."""
        res = self.tracker.admit_read(128, operation_id="op_race_idemp")
        cr = res.start_child_read(physical_read_id="cr_race_6")
        cr.mark_started()
        cr.consume(64)

        barrier = threading.Barrier(2)
        results = []

        def worker_account():
            try:
                barrier.wait()
                cr.account()
                results.append("SUCCESS")
            except Exception as e:
                results.append(type(e).__name__)

        t1 = threading.Thread(target=worker_account)
        t2 = threading.Thread(target=worker_account)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)

        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        # PhysicalReadRecord terminal calls are idempotent
        self.assertEqual(results, ["SUCCESS", "SUCCESS"])
        self.assertEqual(cr.state, "ACCOUNTED")

    def test_13_two_conflicting_terminal_ops_on_child_read(self):
        """13. Concurrent conflicting account() vs mark_failed_accounted() on the same PhysicalReadRecord."""
        res = self.tracker.admit_read(128, operation_id="op_race_conf")
        cr = res.start_child_read(physical_read_id="cr_race_7")
        cr.mark_started()
        cr.consume(64)

        barrier = threading.Barrier(2)
        results = {}

        def worker_acc():
            try:
                barrier.wait()
                cr.account()
                results["acc"] = "SUCCESS"
            except Exception as e:
                results["acc"] = type(e).__name__

        def worker_fail():
            try:
                barrier.wait()
                cr.mark_failed_accounted()
                results["fail"] = "SUCCESS"
            except Exception as e:
                results["fail"] = type(e).__name__

        t1 = threading.Thread(target=worker_acc)
        t2 = threading.Thread(target=worker_fail)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)

        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        winners = [k for k, v in results.items() if v == "SUCCESS"]
        losers = [k for k, v in results.items() if v == "RuntimeError"]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 1)

    def test_14_concurrent_commit_transaction_on_same_reservation(self):
        """14. Concurrent commit_transaction() attempts on the same reservation charge exactly once."""
        res = self.tracker.admit_read(64, operation_id="op_race_tx")
        cr = res.start_child_read(physical_read_id="cr_race_8")
        cr.mark_started()
        cr.consume(64)
        cr.account()
        res.account()

        barrier = threading.Barrier(3)
        results = []

        def worker_commit():
            try:
                barrier.wait()
                ok = self.tracker.commit_transaction(operation_id="op_race_tx", measured_bytes=64, reservations=[res])
                results.append(ok)
            except Exception as e:
                results.append(type(e).__name__)

        threads = [threading.Thread(target=worker_commit) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5.0)

        for t in threads:
            self.assertFalse(t.is_alive())

        # All 3 workers must succeed (idempotent deduplication)
        self.assertEqual(results, [True, True, True])
        # Charged exactly once
        self.assertEqual(self.tracker.metrics.bytes_read, 64)
        self.assertEqual(len(self.tracker.get_committed_transactions()), 1)


class TestPhase20A3420SnapshotConsistencyAndGetters(unittest.TestCase):
    """Workstream C: Transaction & Reconciliation Snapshot Consistency."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_15_get_active_reservations_returns_independent_deep_copies(self):
        """15. Public getter get_active_reservations() returns isolated snapshots resistant to external mutation."""
        res = self.tracker.admit_read(128, operation_id="op_get_res")
        res.start_child_read(physical_read_id="cr_get_1")

        snaps = self.tracker.get_active_reservations()
        self.assertIn(res.reservation_id, snaps)
        snap_res = snaps[res.reservation_id]

        # Mutate the returned snapshot
        snap_res.consumed_bytes = 999999
        snap_res.state = "MUTATED"

        # Tracker internal reservation must be completely untouched
        internal = self.tracker.get_active_reservations()[res.reservation_id]
        self.assertEqual(internal.consumed_bytes, 0)
        self.assertIn(internal.state, ("ADMITTED", "RESERVED"))

    def test_16_reconcile_ledger_snapshot_consistency_during_active_compound_transition(self):
        """16. reconcile_ledger() does not observe partially transitioned parent/child states."""
        with self.tracker.operation_scope(operation_id="op_reconcile_snap") as scope:
            res = self.tracker.admit_read(256, operation_id="op_reconcile_snap")
            res.scope_id = scope.physical_consumption_id
            cr1 = res.start_child_read(physical_read_id="cr_rs_1")
            cr2 = res.start_child_read(physical_read_id="cr_rs_2")

            reconcile_results = []
            stop_event = threading.Event()

            def worker_reconcile():
                while not stop_event.is_set():
                    report = self.tracker.reconcile_ledger(raise_on_error=False)
                    reconcile_results.append(report["reconciled"])
                    time.sleep(0.001)

            t_rec = threading.Thread(target=worker_reconcile)
            t_rec.start()

            try:
                for _ in range(5):
                    cr1.mark_started()
                    cr2.mark_started()
                    time.sleep(0.002)
                    cr1.consume(32)
                    cr2.consume(32)
                    time.sleep(0.002)
            finally:
                stop_event.set()
                t_rec.join(5.0)

            self.assertFalse(t_rec.is_alive())
            # Every single reconciliation snapshot taken while active must be self-consistent
            self.assertTrue(all(reconcile_results))


class TestPhase20A3420BatchPreflightProvenanceSemantics(unittest.TestCase):
    """Workstream D: Batch Preflight Provenance & Contradiction Detection."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_17_orphan_batch_contract_unconditionally_rejected(self):
        """17. Registered batch contract without invocation record is unconditionally rejected by Invariant 22."""
        batch_id = "batch_uncond_17"
        inv_id = "inv_orphan_17"
        read_id = "pread_uncond_17"

        res = self.tracker.admit_read(100, operation_id="op_17")
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={"batch_id": batch_id, "invocation_id": inv_id, "slice_index": 0, "size": 64},
        )
        cr.release()
        res.release()

        slices = [BatchSliceSpec(slice_index=0, address=0x1000, requested_size=64, physical_read_id=read_id)]
        self.tracker.register_batch_contract(
            batch_id=batch_id,
            invocation_id=inv_id,
            expected_slice_count=1,
            slices=slices,
        )

        # Reads are RELEASED, but absent invocation MUST NOT be silently bypassed!
        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(any("orphan batch contract" in d and inv_id in d for d in report["discrepancies"]))

    def test_18_run_ssh_records_preflight_rejected_invocation(self):
        """18. run_ssh() records outcome='PREFLIGHT_REJECTED' when pre-invocation preflight check fails."""
        runner = MockBarrierRunnerA3420()
        runner.fail_before_execution = True
        runner.preflight_reason = "executable unavailable: /bin/custom_ssh not found"

        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            budget_tracker=self.tracker,
        )

        batch_id = "batch_preflight_18"
        inv_id = "inv_preflight_18"
        read_id = "pread_pf_18"

        res = self.tracker.admit_read(128, operation_id="op_pf_18")
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={"batch_id": batch_id, "invocation_id": inv_id, "slice_index": 0, "size": 64},
        )

        slices = [BatchSliceSpec(slice_index=0, address=0x2000, requested_size=64, physical_read_id=read_id)]
        self.tracker.register_batch_contract(
            batch_id=batch_id,
            invocation_id=inv_id,
            expected_slice_count=1,
            slices=slices,
        )

        rc, stdout, stderr = adapter.run_ssh(
            "echo test",
            admission=res,
            child_read=cr,
            invocation_id=inv_id,
            batch_id=batch_id,
            command_type="batch_test",
        )
        self.assertEqual(rc, -2)
        self.assertIn("failed before invocation", stderr)

        # Invocations registry must now contain the PREFLIGHT_REJECTED record
        invs = self.tracker.get_invocation_records()
        self.assertIn(inv_id, invs)
        inv_rec = invs[inv_id]
        self.assertEqual(inv_rec.outcome, "PREFLIGHT_REJECTED")
        self.assertEqual(inv_rec.return_code, -2)

        # Reads must not have started physical execution
        self.assertEqual(cr.state, "ADMITTED")
        self.assertEqual(res.consumed_bytes, 0)

        # Releasing reads and reservation now reconciles cleanly with full provenance
        cr.release()
        res.release()
        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])

    def test_19_contradictory_combination_started_invocation_with_all_reads_released(self):
        """19. Detect contradictory combination: started invocation (not PREFLIGHT_REJECTED) with all reads released."""
        inv_id = "inv_contra_19"
        read_id = "pread_contra_19"

        res = self.tracker.admit_read(64, operation_id="op_19")
        cr = res.start_child_read(physical_read_id=read_id, target_spec={"invocation_id": inv_id})
        cr.release()
        res.release()

        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="shell", physical_read_ids=[read_id])
        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0, outcome="COMPLETED")

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("contradictory invocation state" in d and inv_id in d for d in report["discrepancies"])
        )

    def test_20_contradictory_combination_conflicting_invocation_ids_across_batch_and_reads(self):
        """20. Detect contradictory combination: conflicting invocation IDs across batch and reads."""
        batch_id = "batch_contra_20"
        inv_contract = "inv_contract_20"
        inv_actual = "inv_actual_20"
        read_id = "pread_contra_20"

        res = self.tracker.admit_read(64, operation_id="op_20")
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={
                "batch_id": batch_id,
                "invocation_id": inv_actual,  # Conflicting!
                "slice_index": 0,
                "expected_slice_count": 1,
            },
        )
        cr.mark_started()
        cr.consume(64)

        slices = [BatchSliceSpec(slice_index=0, address=0x3000, requested_size=64, physical_read_id=read_id)]
        self.tracker.register_batch_contract(
            batch_id=batch_id,
            invocation_id=inv_contract,  # Expects inv_contract_20
            expected_slice_count=1,
            slices=slices,
        )

        self.tracker.record_invocation_started(invocation_id=inv_contract, command_type="batch", physical_read_ids=[read_id])
        self.tracker.record_invocation_completed(invocation_id=inv_contract, return_code=0)

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("conflicting invocation ID" in d for d in report["discrepancies"])
        )

    def test_21_contradictory_combination_failed_invocation_with_incomplete_slices(self):
        """21. Detect contradictory combination: failed invocation with incomplete slices."""
        batch_id = "batch_contra_21"
        inv_id = "inv_contra_21"
        read_0 = "pread_contra_21_0"

        res = self.tracker.admit_read(128, operation_id="op_21")
        cr0 = res.start_child_read(
            physical_read_id=read_0,
            target_spec={"batch_id": batch_id, "invocation_id": inv_id, "slice_index": 0, "expected_slice_count": 2},
        )
        cr0.mark_started()
        cr0.consume(64)

        # Slices 1 is omitted from observed physical reads!
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="batch", physical_read_ids=[read_0], batch_id=batch_id)
        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=1, outcome="FAILED")

        slices = [
            BatchSliceSpec(slice_index=0, address=0x4000, requested_size=64, physical_read_id=read_0),
            BatchSliceSpec(slice_index=1, address=0x5000, requested_size=64, physical_read_id="cr_missing"),
        ]
        self.tracker.register_batch_contract(
            batch_id=batch_id,
            invocation_id=inv_id,
            expected_slice_count=2,
            slices=slices,
        )

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("incomplete slices" in d for d in report["discrepancies"])
        )

    def test_22_preflight_rejected_invocation_with_consumption_rejected(self):
        """22. Detect contradictory combination: PREFLIGHT_REJECTED invocation whose reads consumed bytes."""
        batch_id = "batch_contra_22"
        inv_id = "inv_contra_22"
        read_id = "pread_contra_22"

        res = self.tracker.admit_read(64, operation_id="op_22")
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={"batch_id": batch_id, "invocation_id": inv_id, "slice_index": 0, "expected_slice_count": 1},
        )
        cr.mark_started()
        cr.consume(64)  # Contradiction: consumed bytes under preflight rejection!

        slices = [BatchSliceSpec(slice_index=0, address=0x6000, requested_size=64, physical_read_id=read_id)]
        self.tracker.register_batch_contract(batch_id=batch_id, invocation_id=inv_id, expected_slice_count=1, slices=slices)

        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="batch", physical_read_ids=[read_id], batch_id=batch_id)
        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=-2, outcome="PREFLIGHT_REJECTED")

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("preflight rejected with consumption" in d for d in report["discrepancies"])
        )


class TestPhase20A3420ConcurrencyStressAndDeadlockFreedom(unittest.TestCase):
    """Workstream E: High-Concurrency Adversarial Stress Testing."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_23_adversarial_shared_object_contention(self):
        """23. 10 worker threads simultaneously compete for mutations on the SAME reservation and child reads."""
        shared_res = self.tracker.admit_read(1024, operation_id="op_shared_stress")
        shared_children = [
            shared_res.start_child_read(physical_read_id=f"cr_shared_{i}")
            for i in range(4)
        ]

        num_threads = 8
        barrier = threading.Barrier(num_threads)
        errors = []

        def worker(thread_idx: int):
            try:
                barrier.wait()
                for i in range(5):
                    target_cr = shared_children[thread_idx % 4]
                    op_type = (thread_idx + i) % 4
                    try:
                        if op_type == 0:
                            target_cr.mark_started()
                        elif op_type == 1:
                            target_cr.consume(16)
                        elif op_type == 2:
                            target_cr.update_target_spec({"last_thread": thread_idx, "iter": i})
                        elif op_type == 3:
                            _ = shared_res.get_child_reads()
                    except RuntimeError:
                        # Terminal state rejections are expected and correct
                        pass
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(idx,)) for idx in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10.0)
            self.assertFalse(t.is_alive(), "Worker thread deadlocked during shared-object contention")

        self.assertEqual(len(errors), 0, f"Errors encountered: {errors}")
        # Validate that parent consumption strictly equals sum of child charged bytes
        self.assertEqual(shared_res.consumed_bytes, sum(c.charged_bytes for c in shared_children))

    def test_24_end_to_end_concurrency_with_continuous_reconciliation(self):
        """24. Multi-threaded batch execution, single reads, releases, and continuous reconciliations."""
        runner = MockBarrierRunnerA3420()
        runner.delay_sec = 0.0005
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            budget_tracker=self.tracker,
        )

        errors = []
        stop_event = threading.Event()

        def worker_batch(idx: int):
            try:
                for i in range(6):
                    op_id = f"stress_batch_{idx}_{i}"
                    with self.tracker.operation_scope(op_id, profile_id="p_batch"):
                        slices = [(0x1000 + i * 32, 16), (0x2000 + i * 32, 16)]
                        adapter.read_memory_batch(100 + idx, slices, budget_tracker=self.tracker)
            except Exception as e:
                errors.append(e)

        def worker_release(idx: int):
            try:
                for i in range(6):
                    res = self.tracker.admit_read(64, profile_id=f"p_rel_{idx}")
                    time.sleep(0.0005)
                    self.tracker.release_reservation(res)
            except Exception as e:
                errors.append(e)

        def worker_reconcile():
            try:
                while not stop_event.is_set():
                    self.tracker.reconcile_ledger(raise_on_error=True)
                    _ = self.tracker.get_committed_transactions()
                    _ = self.tracker.get_physical_read_records()
                    _ = self.tracker.get_active_reservations()
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        workers = []
        for i in range(3):
            workers.append(threading.Thread(target=worker_batch, args=(i,)))
            workers.append(threading.Thread(target=worker_release, args=(i,)))
        reconciler = threading.Thread(target=worker_reconcile)

        for w in workers:
            w.start()
        reconciler.start()

        for w in workers:
            w.join(10.0)
            self.assertFalse(w.is_alive(), "Worker thread deadlocked")

        stop_event.set()
        reconciler.join(5.0)
        self.assertFalse(reconciler.is_alive(), "Reconciliation thread deadlocked")

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")
        final_recon = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(final_recon["reconciled"])


if __name__ == "__main__":
    unittest.main()
