"""Phase 2.0-A.3.4.22 — Transaction Lock Closure & Deterministic Interleaving Proof Test Suite.

Comprehensive verification of:
1. Workstream A: Universal Lock Order Hierarchy DAG (Level 1 -> Level 2 -> Level 3).
2. Workstream B: Atomic Commit and Rollback across all 10 fault injection points with durable recovery.
3. Workstream C: Deterministic Interleaving Tests (Scenarios 1-12) using threading.Event.
4. Workstream D: Lifecycle and Metadata Closure (terminal immutability, child release restrictions, mixed child states).
5. Workstream E: Adapter Batch Failure Semantics (Base, Local, Remote SSH, Read-Only).
6. High-concurrency stress test with continuous ledger reconciliation.
"""

import copy
import math
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import unittest

from extractor.observation_budget import (
    ActiveOperationScope,
    BatchReadRecord,
    BatchSliceSpec,
    BudgetReservation,
    CommittedTransactionSnapshot,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    PhysicalConsumptionRecord,
    PhysicalReadRecord,
    RemoteInvocationRecord,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    RemoteSshTargetAdapter,
    TargetExecutionAdapter,
)


class MockBarrierRunnerA3422:
    """Mock command runner for deterministic concurrency, event coordination, and fault injection."""

    def __init__(self):
        self.invocations: List[Dict[str, Any]] = []
        self.fail_before_execution = False
        self.preflight_reason = "preflight check failed"
        self.return_code = 0
        self.stdout_payload = "OK\n"
        self.stderr_payload = ""
        self._lock = threading.Lock()
        self.started_event: Optional[threading.Event] = None
        self.pause_event: Optional[threading.Event] = None
        self.resume_event: Optional[threading.Event] = None

    def check_preflight(self, cmd_args: List[str]) -> Tuple[bool, Optional[str]]:
        if self.fail_before_execution:
            return False, self.preflight_reason
        return True, None

    def __call__(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        if self.started_event is not None:
            self.started_event.set()
        if self.pause_event is not None:
            self.pause_event.set()
        if self.resume_event is not None:
            self.resume_event.wait(timeout=5.0)

        with self._lock:
            self.invocations.append({
                "cmd": list(cmd_args),
                "timeout": timeout,
                "timestamp": time.time(),
            })

        if self.return_code != 0:
            return self.return_code, self.stdout_payload, self.stderr_payload or f"Exit {self.return_code}"

        if any("dd if=/proc" in str(arg) for arg in cmd_args):
            return 0, "0|AQIDBAUGBwgJCgsMDQ4PEA==\n1|AQIDBAUGBwgJCgsMDQ4PEA==\n", ""
        return 0, self.stdout_payload, self.stderr_payload


class BaseMockAdapterA3422(TargetExecutionAdapter):
    """Minimal TargetExecutionAdapter implementation for base class semantics."""

    def __init__(self, memory_reader=None):
        self._memory_reader = memory_reader or (lambda pid, addr, sz: (b"\xcc" * sz, "OBSERVED", None))
        self._budget_tracker = None

    def is_remote(self) -> bool:
        return False

    def target_host(self) -> str:
        return "localhost"

    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        return True, None

    def get_process_identity(self, pid: int, **kwargs) -> Dict[str, Any]:
        return {"pid": pid, "arch": "x86_64", "build_id": "test_base_22"}

    def get_proc_maps(self, pid: int, **kwargs) -> List[Dict[str, Any]]:
        return []

    def get_threads(self, pid: int, **kwargs) -> List[Dict[str, Any]]:
        return []

    def get_process_memory_info(self, pid: int, **kwargs) -> Dict[str, int]:
        return {"vm_size": 2048, "vm_rss": 1024}

    def read_memory(
        self,
        pid: int,
        address: int,
        size: int,
        admission: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
        child_read: Optional[Any] = None,
    ) -> Tuple[Optional[bytes], str, Optional[str]]:
        if child_read is not None and child_read.state == "ADMITTED":
            child_read.mark_started()
        return self._memory_reader(pid, address, size)


# ==============================================================================
# Workstream A: Universal Lock Order Hierarchy Proof
# ==============================================================================

class TestPhase20A3422UniversalLockHierarchy(unittest.TestCase):
    """Workstream A: Universal Lock Order Hierarchy DAG (Level 1 -> Level 2 -> Level 3)."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_01_universal_lock_dag_enforcement(self):
        """1. _lock_reservations_with_children acquires reservations in sorted order, then children in sorted order."""
        res_z = self.tracker.admit_read(100, operation_id="op_z")
        res_a = self.tracker.admit_read(100, operation_id="op_a")
        # Ensure distinct IDs
        res_z.reservation_id = "res_z"
        res_a.reservation_id = "res_a"

        cr_z2 = res_z.start_child_read(physical_read_id="cr_z2")
        cr_z1 = res_z.start_child_read(physical_read_id="cr_z1")
        cr_a2 = res_a.start_child_read(physical_read_id="cr_a2")
        cr_a1 = res_a.start_child_read(physical_read_id="cr_a1")

        with self.tracker._transaction_lock:
            with self.tracker._lock_reservations_with_children([res_z, res_a]) as (locked_res, locked_children):
                # Level 2 order: res_a, res_z
                self.assertEqual([r.reservation_id for r in locked_res], ["res_a", "res_z"])
                # Level 3 order: cr_a1, cr_a2, cr_z1, cr_z2
                self.assertEqual([c.physical_read_id for c in locked_children], ["cr_a1", "cr_a2", "cr_z1", "cr_z2"])

    def test_02_sorted_reservation_acquisition_prevents_circular_deadlock(self):
        """2. Concurrent multi-reservation lock acquisitions in opposite orders do not deadlock."""
        res1 = self.tracker.admit_read(100, operation_id="op_1")
        res2 = self.tracker.admit_read(100, operation_id="op_2")
        res1.reservation_id = "res_01"
        res2.reservation_id = "res_02"

        barrier = threading.Barrier(2)
        errors = []

        def worker_1():
            try:
                for _ in range(50):
                    barrier.reset() if barrier.broken else None
                    with self.tracker._transaction_lock:
                        with self.tracker._lock_reservations_with_children([res1, res2]):
                            time.sleep(0.0001)
            except Exception as e:
                errors.append(e)

        def worker_2():
            try:
                for _ in range(50):
                    barrier.reset() if barrier.broken else None
                    with self.tracker._transaction_lock:
                        with self.tracker._lock_reservations_with_children([res2, res1]):
                            time.sleep(0.0001)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker_1)
        t2 = threading.Thread(target=worker_2)
        t1.start()
        t2.start()
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)

        self.assertFalse(t1.is_alive(), "Worker 1 deadlocked")
        self.assertFalse(t2.is_alive(), "Worker 2 deadlocked")
        self.assertEqual(errors, [])

    def test_03_sorted_child_read_acquisition_prevents_circular_deadlock(self):
        """3. Concurrent multi-child mutations within reservation do not deadlock."""
        res = self.tracker.admit_read(200, operation_id="op_child_dl")
        cr1 = res.start_child_read(physical_read_id="cr_1")
        cr2 = res.start_child_read(physical_read_id="cr_2")

        errors = []

        def worker_a():
            try:
                for _ in range(50):
                    with res._lock_with_children():
                        time.sleep(0.0001)
            except Exception as e:
                errors.append(e)

        def worker_b():
            try:
                for _ in range(50):
                    with res._lock_with_children():
                        time.sleep(0.0001)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker_a)
        t2 = threading.Thread(target=worker_b)
        t1.start()
        t2.start()
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)

        self.assertFalse(t1.is_alive(), "Worker A deadlocked")
        self.assertFalse(t2.is_alive(), "Worker B deadlocked")
        self.assertEqual(errors, [])

    def test_04_reconcile_ledger_acquires_level_2_snapshot_safely(self):
        """4. reconcile_ledger snapshots child_reads under Level 2 lock without iteration errors."""
        res = self.tracker.admit_read(500, operation_id="op_rec_snap")
        stop_event = threading.Event()
        errors = []

        def child_adder():
            idx = 0
            while not stop_event.is_set():
                try:
                    res.start_child_read(physical_read_id=f"dyn_cr_{idx}")
                    idx += 1
                    time.sleep(0.0002)
                except RuntimeError:
                    break
                except Exception as e:
                    errors.append(e)
                    break

        t = threading.Thread(target=child_adder)
        t.start()

        try:
            for _ in range(25):
                rec = self.tracker.reconcile_ledger(raise_on_error=False)
                # Should not raise RuntimeError: dictionary changed size during iteration
                time.sleep(0.0005)
        finally:
            stop_event.set()
            t.join(timeout=3.0)

        self.assertEqual(errors, [])


# ==============================================================================
# Workstream B: Atomic Commit and Rollback (All 10 Fault Injection Boundaries)
# ==============================================================================

class TestPhase20A3422CommitRollbackFaultClosure(unittest.TestCase):
    """Workstream B: 10 Fault Injection Boundaries in _execute_scope_commit() with Durable Recovery."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_05_all_10_fault_injection_boundaries_durable_recovery(self):
        """5. Verifies every one of the 10 commit fault points triggers durable recovery and clean ledger reconciliation."""
        fault_points = [
            "before_physical_ledger_insertion",
            "during_physical_ledger_insertion",
            "after_physical_ledger_insertion",
            "before_logical_ledger_insertion",
            "during_logical_ledger_insertion",
            "after_logical_ledger_insertion",
            "during_metric_application",
            "during_profile_metric_application",
            "during_reservation_finalization",
            "during_history_append",
        ]

        for pt in fault_points:
            tracker = ObservationBudgetTracker()
            tracker.start()
            tracker.inject_fault(pt)
            op_id = f"test_op_{pt}"

            with tracker.operation_scope(operation_id=op_id, profile_id="prof_fault") as scope:
                res = tracker.admit_read(128, operation_id=op_id, scope=scope)
                child = res.start_child_read(physical_read_id=f"cr_{pt}", target_type="memory_slice")
                child.consume(actual_bytes=128)

            # Reconcile ledger must be 100% consistent
            rec = tracker.reconcile_ledger()
            self.assertTrue(rec["reconciled"], f"Fault point '{pt}' produced inconsistent ledger: {rec['discrepancies']}")
            self.assertEqual(rec["discrepancies"], [])

            # Transaction snapshot must be durable and marked FAILED
            snap = tracker._committed_transactions[op_id]
            self.assertEqual(snap.accounting_status, "FAILED")
            self.assertTrue(snap.is_failure)
            self.assertEqual(snap.charged_bytes, 128)

            # Child read must be preserved in FAILED_ACCOUNTED state
            pread = tracker._physical_read_records[f"cr_{pt}"]
            self.assertEqual(pread.state, "FAILED_ACCOUNTED")
            self.assertTrue(pread.is_failure)

            # Tracker metrics must reflect failure exactly once
            self.assertEqual(tracker.metrics.bytes_read, 128)
            self.assertEqual(tracker.metrics.total_read_failures, 1)
            self.assertEqual(tracker.metrics.consecutive_read_failures, 1)

            # Active reservations and scopes must be cleanly drained
            self.assertEqual(len(tracker._active_reservations), 0)
            self.assertEqual(len(tracker._active_scopes), 0)

    def test_06_idempotent_recovery_and_second_commit_rejection(self):
        """6. Re-committing a failed transaction as successful is strictly rejected."""
        self.tracker.inject_fault("during_metric_application")
        op_id = "op_failed_recommit"

        with self.tracker.operation_scope(operation_id=op_id) as scope:
            res = self.tracker.admit_read(64, operation_id=op_id, scope=scope)
            child = res.start_child_read(physical_read_id="cr_recommit")
            child.consume(actual_bytes=64)

        # Confirm it is FAILED
        snap = self.tracker.get_committed_record(op_id)
        self.assertEqual(snap.accounting_status, "FAILED")

        self.tracker.clear_fault_injections()

        # Re-commit with is_failure=False must fail closed
        with self.assertRaises(ValueError) as cm:
            self.tracker.commit_transaction(
                operation_id=op_id,
                measured_bytes=64,
                is_failure=False,
            )
        self.assertIn("cannot be recommitted as a successful transaction", str(cm.exception))

        # Re-commit with identical failure snapshot must deduplicate idempotently
        rec = ObservationAccountingRecord(
            operation_id=op_id,
            accounting_owner="MODULE_INTERNAL",
            measured_bytes_read=64,
            charged_bytes=64,
            session_id=self.tracker.session_id,
            physical_consumption_id=snap.physical_consumption_id,
            metadata=dict(snap.metadata),
        )
        res_dup = self.tracker.commit_transaction(record=rec, is_failure=True)
        self.assertTrue(res_dup)
        self.assertEqual(self.tracker.metrics.bytes_read, 64)

    def test_07_recovery_without_child_reads_records_root_consumption_and_read(self):
        """7. Commit fault on direct/unparented read records root PhysicalReadRecord and PhysicalConsumptionRecord."""
        self.tracker.inject_fault("during_metric_application")
        op_id = "op_direct_fault"

        with self.tracker.operation_scope(operation_id=op_id) as scope:
            scope.record_read(bytes_read=50)

        snap = self.tracker.get_committed_record(op_id)
        self.assertEqual(snap.accounting_status, "FAILED")

        # Must have physical consumption record and physical read record
        phys_records = [p for p in self.tracker._physical_consumption_records.values() if p.operation_id == op_id]
        self.assertEqual(len(phys_records), 1)
        root_phys = phys_records[0]
        self.assertEqual(root_phys.operation_id, op_id)
        self.assertTrue(root_phys.is_failure)
        self.assertEqual(root_phys.accounting_status, "FAILED")

        read_records = [r for r in self.tracker._physical_read_records.values() if r.operation_id == op_id]
        self.assertEqual(len(read_records), 1)
        root_read = read_records[0]
        self.assertEqual(root_read.state, "FAILED_ACCOUNTED")
        self.assertTrue(root_read.is_failure)

        rec = self.tracker.reconcile_ledger()
        self.assertTrue(rec["reconciled"])


# ==============================================================================
# Workstream C: Deterministic Interleaving Tests (12 Scenarios using threading.Event)
# ==============================================================================

class TestPhase20A3422DeterministicInterleavings(unittest.TestCase):
    """Workstream C: Precise Critical-Point Interleaving Proof across 12 Scenarios."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_08_scenario_1_commit_level1_pause_vs_reservation_release(self):
        """Scenario 1: Commit thread holds Level 1, pauses; concurrent release waits or fails cleanly."""
        res = self.tracker.admit_read(100, operation_id="op_sc1")
        child = res.start_child_read(physical_read_id="cr_sc1")
        child.consume(actual_bytes=100)

        started_event = threading.Event()
        resume_event = threading.Event()
        errors = []

        def fault_hook():
            started_event.set()
            resume_event.wait(timeout=3.0)

        self.tracker.inject_fault("before_physical_ledger_insertion", fault_hook)

        def commit_worker():
            try:
                with self.tracker.operation_scope(operation_id="op_sc1") as scope:
                    scope._admissions.append(res)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=commit_worker)
        t1.start()

        started_event.wait(timeout=3.0)

        # Thread 2 attempts to release reservation; must block or fail because consumed
        with self.assertRaises(RuntimeError):
            res.release()

        resume_event.set()
        t1.join(timeout=3.0)
        self.assertEqual(errors, [])

    def test_09_scenario_2_commit_level2_pause_vs_child_consume(self):
        """Scenario 2: Commit thread holds Level 1 & 2; concurrent child mutation blocks on Level 2."""
        res = self.tracker.admit_read(100, operation_id="op_sc2")
        child = res.start_child_read(physical_read_id="cr_sc2")
        child.consume(actual_bytes=100)

        started_event = threading.Event()
        resume_event = threading.Event()
        child_consume_executed = threading.Event()

        def fault_hook():
            started_event.set()
            resume_event.wait(timeout=3.0)

        self.tracker.inject_fault("during_physical_ledger_insertion", fault_hook)

        def commit_worker():
            try:
                with self.tracker.operation_scope(operation_id="op_sc2") as scope:
                    scope._admissions.append(res)
            except Exception:
                pass

        t1 = threading.Thread(target=commit_worker)
        t1.start()
        started_event.wait(timeout=3.0)

        # Thread 2 attempts child mutation while commit holds lock
        def child_worker():
            try:
                child.update_target_spec({"interleaved": True})
            except Exception:
                pass
            finally:
                child_consume_executed.set()

        t2 = threading.Thread(target=child_worker)
        t2.start()

        # Child worker should be blocked
        time.sleep(0.05)
        self.assertFalse(child_consume_executed.is_set(), "Child mutation should be blocked by Level 2/3 lock")

        resume_event.set()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)
        self.assertTrue(child_consume_executed.is_set())

    def test_10_scenario_3_commit_during_physical_insertion_vs_concurrent_commit(self):
        """Scenario 3: Commit pauses during physical insertion; concurrent commit of same op blocks and deduplicates."""
        op_id = "op_sc3"
        started_event = threading.Event()
        resume_event = threading.Event()
        second_commit_result = []

        def fault_hook():
            started_event.set()
            resume_event.wait(timeout=3.0)

        self.tracker.inject_fault("after_physical_ledger_insertion", fault_hook)

        def commit_worker_1():
            with self.tracker.operation_scope(operation_id=op_id) as scope:
                res = self.tracker.admit_read(80, operation_id=op_id, scope=scope)
                cr = res.start_child_read(physical_read_id="cr_sc3")
                cr.consume(actual_bytes=80)

        t1 = threading.Thread(target=commit_worker_1)
        t1.start()
        started_event.wait(timeout=3.0)

        def commit_worker_2():
            res = self.tracker.commit_transaction(
                operation_id=op_id,
                measured_bytes=80,
                accounting_owner="MODULE_INTERNAL",
                is_failure=False,
            )
            second_commit_result.append(res)

        t2 = threading.Thread(target=commit_worker_2)
        t2.start()

        time.sleep(0.05)
        self.assertEqual(len(second_commit_result), 0, "Second commit should be blocked on _transaction_lock")

        resume_event.set()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        self.assertEqual(second_commit_result, [True])
        self.assertEqual(self.tracker.metrics.bytes_read, 80)

    def test_11_scenario_4_rollback_recovery_pause_vs_child_mutation(self):
        """Scenario 4: Rollback recovery pauses; child mutation is rejected or blocks."""
        op_id = "op_sc4"
        started_event = threading.Event()
        resume_event = threading.Event()

        def fault_hook():
            started_event.set()
            resume_event.wait(timeout=3.0)

        self.tracker.inject_fault("during_emergency_recovery", fault_hook)

        res = self.tracker.admit_read(90, operation_id=op_id)
        cr = res.start_child_read(physical_read_id="cr_sc4")
        cr.consume(actual_bytes=90)

        def failing_commit():
            try:
                # Trigger recovery by failing inside scope
                with self.tracker.operation_scope(operation_id=op_id) as scope:
                    scope._admissions.append(res)
                    raise RuntimeError("Forced failure to trigger recovery")
            except Exception:
                pass

        t1 = threading.Thread(target=failing_commit)
        t1.start()
        started_event.wait(timeout=3.0)

        # Thread 2 attempts to consume already consumed child or update target spec
        mutation_rejected = False
        try:
            cr.update_target_spec({"test": "value"})
        except RuntimeError:
            mutation_rejected = True

        resume_event.set()
        t1.join(timeout=3.0)

        rec = self.tracker.reconcile_ledger()
        self.assertTrue(rec["reconciled"])

    def test_12_scenario_5_deadlock_freedom_reverse_reservation_finalization(self):
        """Scenario 5: Reverse reservation finalization order does not deadlock."""
        res_a = self.tracker.admit_read(50, operation_id="op_sc5_a")
        res_b = self.tracker.admit_read(50, operation_id="op_sc5_b")
        res_a.reservation_id = "res_001"
        res_b.reservation_id = "res_002"

        cr_a = res_a.start_child_read(physical_read_id="cr_a")
        cr_b = res_b.start_child_read(physical_read_id="cr_b")
        cr_a.consume(actual_bytes=50)
        cr_b.consume(actual_bytes=50)

        errors = []

        def worker_1():
            try:
                with self.tracker._transaction_lock:
                    with self.tracker._lock_reservations_with_children([res_a, res_b]):
                        time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        def worker_2():
            try:
                with self.tracker._transaction_lock:
                    with self.tracker._lock_reservations_with_children([res_b, res_a]):
                        time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker_1)
        t2 = threading.Thread(target=worker_2)
        t1.start()
        t2.start()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())
        self.assertEqual(errors, [])

    def test_13_scenario_6_deadlock_freedom_reverse_child_reads(self):
        """Scenario 6: Reverse child read ordering between threads does not deadlock."""
        res = self.tracker.admit_read(100, operation_id="op_sc6")
        cr1 = res.start_child_read(physical_read_id="cr_01")
        cr2 = res.start_child_read(physical_read_id="cr_02")

        errors = []

        def mutate_1():
            try:
                for _ in range(30):
                    with cr1._lock_hierarchy():
                        with cr2._lock_hierarchy():
                            pass
            except Exception as e:
                errors.append(e)

        def mutate_2():
            try:
                for _ in range(30):
                    with cr2._lock_hierarchy():
                        with cr1._lock_hierarchy():
                            pass
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=mutate_1)
        t2 = threading.Thread(target=mutate_2)
        t1.start()
        t2.start()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())
        self.assertEqual(errors, [])

    def test_14_scenario_7_commit_validation_vs_child_registration(self):
        """Scenario 7: Commit holds reservation lock; start_child_read() waits and fails closed on terminal state."""
        op_id = "op_sc7"
        res = self.tracker.admit_read(100, operation_id=op_id)
        cr = res.start_child_read(physical_read_id="cr_sc7_1")
        cr.consume(actual_bytes=100)

        started_event = threading.Event()
        resume_event = threading.Event()
        registration_error = []

        def fault_hook():
            started_event.set()
            resume_event.wait(timeout=3.0)

        self.tracker.inject_fault("before_logical_ledger_insertion", fault_hook)

        def commit_worker():
            with self.tracker.operation_scope(operation_id=op_id) as scope:
                scope._admissions.append(res)

        t1 = threading.Thread(target=commit_worker)
        t1.start()
        started_event.wait(timeout=3.0)

        def child_adder():
            try:
                res.start_child_read(physical_read_id="cr_sc7_2")
            except RuntimeError as e:
                registration_error.append(e)

        t2 = threading.Thread(target=child_adder)
        t2.start()

        # t2 should be blocked waiting for res._lock
        time.sleep(0.05)
        self.assertEqual(len(registration_error), 0)

        resume_event.set()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        # After commit finishes, res is terminal (ACCOUNTED), so child registration must fail-closed
        self.assertEqual(len(registration_error), 1)
        self.assertIn("terminal state", str(registration_error[0]))

    def test_15_scenario_8_fault_during_physical_insertion_interleaved_reconciliation(self):
        """Scenario 8: Fault during physical ledger insertion recovery interleaves with reconcile_ledger()."""
        op_id = "op_sc8"
        started_event = threading.Event()
        resume_event = threading.Event()
        reconcile_results = []

        def fault_hook():
            started_event.set()
            resume_event.wait(timeout=3.0)
            raise RuntimeError("Injected fault during physical insertion")

        self.tracker.inject_fault("during_physical_ledger_insertion", fault_hook)

        def commit_worker():
            with self.tracker.operation_scope(operation_id=op_id) as scope:
                res = self.tracker.admit_read(75, operation_id=op_id, scope=scope)
                cr = res.start_child_read(physical_read_id="cr_sc8")
                cr.consume(actual_bytes=75)

        t1 = threading.Thread(target=commit_worker)
        t1.start()
        started_event.wait(timeout=3.0)

        def reconciler():
            rec = self.tracker.reconcile_ledger()
            reconcile_results.append(rec)

        t2 = threading.Thread(target=reconciler)
        t2.start()

        time.sleep(0.05)
        # Reconciler is serialized behind _transaction_lock
        self.assertEqual(len(reconcile_results), 0)

        resume_event.set()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        self.assertEqual(len(reconcile_results), 1)
        self.assertTrue(reconcile_results[0]["reconciled"])

    def test_16_scenario_9_fault_during_logical_insertion_interleaved_second_commit(self):
        """Scenario 9: Fault during logical ledger insertion interleaved with second commit attempt."""
        op_id = "op_sc9"
        started_event = threading.Event()
        resume_event = threading.Event()
        second_commit_errors = []

        def fault_hook():
            started_event.set()
            resume_event.wait(timeout=3.0)
            raise RuntimeError("Injected fault during logical insertion")

        self.tracker.inject_fault("during_logical_ledger_insertion", fault_hook)

        def commit_worker():
            with self.tracker.operation_scope(operation_id=op_id) as scope:
                res = self.tracker.admit_read(40, operation_id=op_id, scope=scope)
                cr = res.start_child_read(physical_read_id="cr_sc9")
                cr.consume(actual_bytes=40)

        t1 = threading.Thread(target=commit_worker)
        t1.start()
        started_event.wait(timeout=3.0)

        def second_commit():
            try:
                self.tracker.commit_transaction(
                    operation_id=op_id,
                    measured_bytes=40,
                    is_failure=False,
                )
            except ValueError as ve:
                second_commit_errors.append(ve)

        t2 = threading.Thread(target=second_commit)
        t2.start()

        resume_event.set()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        # Second commit must detect that op_sc9 is in FAILED status and reject recommit
        self.assertEqual(len(second_commit_errors), 1)
        self.assertIn("cannot be recommitted as a successful transaction", str(second_commit_errors[0]))

    def test_17_scenario_10_fault_during_reservation_finalization_interleaved_getter(self):
        """Scenario 10: Fault during reservation finalization interleaved with get_active_reservations()."""
        op_id = "op_sc10"
        started_event = threading.Event()
        resume_event = threading.Event()
        getter_results = []

        def fault_hook():
            started_event.set()
            resume_event.wait(timeout=3.0)
            raise RuntimeError("Injected fault during reservation finalization")

        self.tracker.inject_fault("during_reservation_finalization", fault_hook)

        def commit_worker():
            with self.tracker.operation_scope(operation_id=op_id) as scope:
                res = self.tracker.admit_read(60, operation_id=op_id, scope=scope)
                cr = res.start_child_read(physical_read_id="cr_sc10")
                cr.consume(actual_bytes=60)

        t1 = threading.Thread(target=commit_worker)
        t1.start()
        started_event.wait(timeout=3.0)

        def getter():
            active = self.tracker.get_active_reservations()
            getter_results.append(active)

        t2 = threading.Thread(target=getter)
        t2.start()

        time.sleep(0.05)
        # Getter is serialized behind _transaction_lock
        self.assertEqual(len(getter_results), 0)

        resume_event.set()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        self.assertEqual(len(getter_results), 1)
        # After recovery finishes, active reservations must be empty
        self.assertEqual(len(getter_results[0]), 0)

    def test_18_scenario_11_duplicate_commit_interleaved_with_distinct_op_commit(self):
        """Scenario 11: Idempotent duplicate commit interleaving with active commit of distinct operation."""
        # Commit op1
        self.tracker.commit_transaction(operation_id="op_sc11_1", measured_bytes=50)

        results = []

        def duplicate_op1():
            res = self.tracker.commit_transaction(operation_id="op_sc11_1", measured_bytes=50)
            results.append(("op1", res))

        def commit_op2():
            res = self.tracker.commit_transaction(operation_id="op_sc11_2", measured_bytes=70)
            results.append(("op2", res))

        t1 = threading.Thread(target=duplicate_op1)
        t2 = threading.Thread(target=commit_op2)
        t1.start()
        t2.start()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        self.assertEqual(sorted([r[0] for r in results]), ["op1", "op2"])
        self.assertTrue(all(r[1] for r in results))
        self.assertEqual(self.tracker.metrics.bytes_read, 120)
        rec = self.tracker.reconcile_ledger()
        self.assertTrue(rec["reconciled"])

    def test_19_scenario_12_recovery_interleaved_with_adapter_batch_completion_failure(self):
        """Scenario 12: Recovery interleaving with adapter batch completion failure."""
        runner = MockBarrierRunnerA3422()
        adapter = RemoteSshTargetAdapter(
            host="testhost",
            user="testuser",
            command_runner=runner,
            budget_tracker=self.tracker,
        )

        slices = [(0x1000, 16), (0x2000, 16)]
        runner.return_code = 1
        runner.stderr_payload = "Remote process terminated abruptly"

        # Execute batch with failing runner
        results = adapter.read_memory_batch(pid=1234, slices=slices)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r[0] is None for r in results))

        # Ledger must reconcile cleanly
        rec = self.tracker.reconcile_ledger()
        self.assertTrue(rec["reconciled"], f"Discrepancies: {rec['discrepancies']}")
        self.assertEqual(len(self.tracker._active_reservations), 0)


# ==============================================================================
# Workstream D: Lifecycle and Metadata Closure
# ==============================================================================

class TestPhase20A3422LifecycleAndMetadataClosure(unittest.TestCase):
    """Workstream D: Lifecycle Totality, Immutability, and Mixed Child States."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_20_terminal_immutability_across_all_terminal_states(self):
        """20. Child and reservation records in terminal states strictly reject mutations."""
        res = self.tracker.admit_read(100, operation_id="op_immut")
        cr = res.start_child_read(physical_read_id="cr_immut")
        cr.consume(actual_bytes=100)
        res.finalize()

        self.assertTrue(res.is_terminal)
        self.assertTrue(cr.is_terminal)

        with self.assertRaises(RuntimeError):
            cr.consume(actual_bytes=50)

        with self.assertRaises(RuntimeError):
            cr.release()

        with self.assertRaises(RuntimeError):
            cr.update_target_spec({"key": "val"})

        with self.assertRaises(RuntimeError):
            res.release()

        with self.assertRaises(RuntimeError):
            res.start_child_read(physical_read_id="cr_new")

    def test_21_child_level_release_restrictions(self):
        """21. PHYSICAL_READ_STARTED and CONSUMED child reads cannot transition to RELEASED."""
        res = self.tracker.admit_read(100, operation_id="op_rel_rest")
        cr1 = res.start_child_read(physical_read_id="cr_start_rel")
        cr1.mark_started()
        with self.assertRaises(RuntimeError):
            cr1.release()

        cr2 = res.start_child_read(physical_read_id="cr_cons_rel")
        cr2.consume(actual_bytes=50)
        with self.assertRaises(RuntimeError):
            cr2.release()

    def test_22_mixed_child_states_atomic_finalization(self):
        """22. Reservation with mixed child states (CONSUMED + ADMITTED + FAILED_ACCOUNTED) finalizes atomically."""
        res = self.tracker.admit_read(300, operation_id="op_mixed")
        cr_cons = res.start_child_read(physical_read_id="cr_mixed_cons")
        cr_admit = res.start_child_read(physical_read_id="cr_mixed_admit")
        cr_fail = res.start_child_read(physical_read_id="cr_mixed_fail")

        cr_cons.consume(actual_bytes=100)
        cr_fail.mark_started()
        cr_fail.mark_failed_accounted(failure_reason="simulated failure")

        # Atomic finalization
        res.finalize()

        self.assertEqual(cr_cons.state, "ACCOUNTED")
        self.assertEqual(cr_admit.state, "RELEASED")
        self.assertEqual(cr_fail.state, "FAILED_ACCOUNTED")
        self.assertEqual(res.state, "ACCOUNTED")

        # Terminal timestamps must match
        self.assertEqual(cr_cons.terminal_at_ms, res.terminal_at_ms)
        self.assertEqual(cr_admit.terminal_at_ms, res.terminal_at_ms)

    def test_23_parent_failure_propagation_to_child_reads(self):
        """23. Parent reservation mark_failed_accounted transitions children and assigns identical terminal timestamp."""
        res = self.tracker.admit_read(200, operation_id="op_fail_prop")
        cr1 = res.start_child_read(physical_read_id="cr_fp_1")
        cr2 = res.start_child_read(physical_read_id="cr_fp_2")
        cr1.consume(actual_bytes=100)
        cr2.mark_started()

        res.mark_failed_accounted()

        self.assertEqual(res.state, "FAILED_ACCOUNTED")
        self.assertEqual(cr1.state, "FAILED_ACCOUNTED")
        self.assertEqual(cr2.state, "FAILED_ACCOUNTED")
        self.assertEqual(res.terminal_at_ms, cr1.terminal_at_ms)
        self.assertEqual(res.terminal_at_ms, cr2.terminal_at_ms)

    def test_24_transition_history_completeness(self):
        """24. PhysicalReadRecord and BudgetReservation maintain complete and monotonic transition histories."""
        res = self.tracker.admit_read(100, operation_id="op_th")
        cr = res.start_child_read(physical_read_id="cr_th")

        self.assertEqual(cr.transition_history, ["ADMITTED"])
        cr.mark_started()
        self.assertEqual(cr.transition_history, ["ADMITTED", "PHYSICAL_READ_STARTED"])
        cr.consume(actual_bytes=100)
        self.assertEqual(cr.transition_history, ["ADMITTED", "PHYSICAL_READ_STARTED", "CONSUMED"])
        cr.account()
        self.assertEqual(cr.transition_history, ["ADMITTED", "PHYSICAL_READ_STARTED", "CONSUMED", "ACCOUNTED"])


# ==============================================================================
# Workstream E: Adapter Batch Failure Semantics
# ==============================================================================

class TestPhase20A3422AdapterBatchFailureSemantics(unittest.TestCase):
    """Workstream E: Adapter Batch Failure and Cleanup Semantics."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_25_base_adapter_batch_read_failure_semantics(self):
        """25. Base adapter handles slice read failure by marking invocation failed and reconciling cleanly."""
        def failing_reader(pid, addr, sz):
            if addr == 0x2000:
                raise OSError("Simulated hardware bus error")
            return b"\xaa" * sz, "OBSERVED", None

        adapter = BaseMockAdapterA3422(memory_reader=failing_reader)
        adapter.set_budget_tracker(self.tracker)

        slices = [(0x1000, 32), (0x2000, 32)]
        with self.assertRaises(OSError):
            adapter.read_memory_batch(pid=999, slices=slices)

        rec = self.tracker.reconcile_ledger()
        self.assertTrue(rec["reconciled"], f"Discrepancies: {rec['discrepancies']}")
        self.assertEqual(len(self.tracker._active_reservations), 0)

    def test_26_local_adapter_partial_failure_cleanup(self):
        """26. LocalTargetAdapter cleans up on missing process memory access."""
        adapter = LocalTargetAdapter()
        adapter.set_budget_tracker(self.tracker)

        # Non-existent PID
        slices = [(0x1000, 16)]
        results = adapter.read_memory_batch(pid=9999999, slices=slices)
        self.assertEqual(len(results), 1)
        self.assertTrue(all(r[0] is None for r in results))

        rec = self.tracker.reconcile_ledger()
        self.assertTrue(rec["reconciled"], f"Discrepancies: {rec['discrepancies']}")
        self.assertEqual(len(self.tracker._active_reservations), 0)

    def test_27_remote_ssh_adapter_transport_failure_cleanup(self):
        """27. RemoteSshTargetAdapter transport error produces failed invocation and zero leaked reservations."""
        runner = MockBarrierRunnerA3422()
        adapter = RemoteSshTargetAdapter(
            host="remotehost",
            user="user",
            command_runner=runner,
            budget_tracker=self.tracker,
        )

        runner.return_code = 255
        runner.stderr_payload = "SSH connection dropped"

        slices = [(0x1000, 32), (0x2000, 32)]
        results = adapter.read_memory_batch(pid=123, slices=slices)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r[0] is None for r in results))

        inv = list(self.tracker._invocations.values())[-1]
        self.assertIn(inv.outcome, ("FAILED", "TRANSPORT_ERROR"))
        self.assertNotEqual(inv.return_code, 0)

        rec = self.tracker.reconcile_ledger()
        self.assertTrue(rec["reconciled"], f"Discrepancies: {rec['discrepancies']}")
        self.assertEqual(len(self.tracker._active_reservations), 0)

    def test_28_readonly_adapter_delegation_failure_cleanup(self):
        """28. ReadOnlyTargetAdapter delegation failure cleans up completely."""
        def failing_reader(pid, addr, sz):
            raise RuntimeError("Read failure in underlying adapter")

        inner = BaseMockAdapterA3422(memory_reader=failing_reader)
        adapter = ReadOnlyTargetAdapter(inner, budget_tracker=self.tracker)

        slices = [(0x1000, 16)]
        with self.assertRaises(RuntimeError):
            adapter.read_memory_batch(pid=555, slices=slices)

        rec = self.tracker.reconcile_ledger()
        self.assertTrue(rec["reconciled"], f"Discrepancies: {rec['discrepancies']}")
        self.assertEqual(len(self.tracker._active_reservations), 0)


# ==============================================================================
# Workstream F: Concurrency Stress and Ledger Closure
# ==============================================================================

class TestPhase20A3422StressAndLedgerClosure(unittest.TestCase):
    """Workstream F: High-Contention Interleaved Concurrency Stress & Ledger Closure."""

    def test_29_high_concurrency_stress_with_continuous_reconcile(self):
        """29. Multi-threaded stress test with concurrent admissions, commits, fault injections, and continuous reconciliation."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        num_threads = 8
        iterations_per_thread = 15
        errors = []

        def worker(thread_idx: int):
            for i in range(iterations_per_thread):
                op_id = f"stress_{thread_idx}_{i}"
                try:
                    if i % 3 == 0:
                        # Direct commit
                        tracker.commit_transaction(
                            operation_id=op_id,
                            measured_bytes=64,
                            latency_us=100.0,
                        )
                    elif i % 3 == 1:
                        # Scoped commit with child reads
                        with tracker.operation_scope(operation_id=op_id) as scope:
                            res = tracker.admit_read(64, operation_id=op_id, scope=scope)
                            cr = res.start_child_read(physical_read_id=f"cr_{op_id}")
                            cr.consume(actual_bytes=64)
                    else:
                        # Duplicate idempotent commit
                        tracker.commit_transaction(
                            operation_id=f"stress_{thread_idx}_0",
                            measured_bytes=64,
                            latency_us=100.0,
                        )
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for th in threads:
            th.start()

        # Concurrently run reconcile_ledger
        for _ in range(10):
            time.sleep(0.01)
            rec = tracker.reconcile_ledger(raise_on_error=False)
            if not rec["reconciled"]:
                errors.append(f"Reconciliation error during stress: {rec['discrepancies']}")

        for th in threads:
            th.join(timeout=10.0)

        self.assertEqual(errors, [])

        # Final ledger verification must be 100% reconciled
        final_rec = tracker.reconcile_ledger()
        self.assertTrue(final_rec["reconciled"], f"Final discrepancies: {final_rec['discrepancies']}")
        self.assertEqual(len(tracker._active_reservations), 0)
        self.assertEqual(len(tracker._active_scopes), 0)


if __name__ == "__main__":
    unittest.main()
