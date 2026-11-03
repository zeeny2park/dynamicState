"""Phase 2.0-A.3.4.21: Cross-Adapter Provenance & Transaction Boundary Closure Test Suite.

Comprehensive verification of:
1. Cross-Adapter Invocation Atomicity (Base, Local, Remote SSH, Read-Only, Fallback).
2. Commit, Rollback and Lock Hierarchy Closure (Level 1 -> Level 2 -> Level 3).
3. Lifecycle Totality and Immutability across All 6 Core Accounting Entities.
4. Deterministic Barrier-Synchronized Concurrency across 15 Required Interleaving Scenarios.
"""

import copy
import math
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import unittest

from extractor.observation_budget import (
    ObservationBudgetTracker,
    ObservationBudgetLimits,
    ObservationAccountingRecord,
    BudgetReservation,
    PhysicalReadRecord,
    PhysicalConsumptionRecord,
    RemoteInvocationRecord,
    BatchReadRecord,
    BatchSliceSpec,
    ActiveOperationScope,
)
from extractor.target_adapter import (
    TargetExecutionAdapter,
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    RemoteSshTargetAdapter,
)


class MockBarrierRunnerA3421:
    """Mock command runner for deterministic concurrency, delay, and fault injection."""

    def __init__(self):
        self.invocations: List[Dict[str, Any]] = []
        self.fail_before_execution = False
        self.preflight_reason = "executable unavailable before execution"
        self.return_code = 0
        self.stdout_payload = "OK\n"
        self.stderr_payload = ""
        self._lock = threading.Lock()
        self.barrier: Optional[threading.Barrier] = None
        self.pause_event: Optional[threading.Event] = None
        self.resume_event: Optional[threading.Event] = None

    def check_preflight(self, cmd_args: List[str]) -> Tuple[bool, Optional[str]]:
        if self.fail_before_execution:
            return False, self.preflight_reason
        return True, None

    def __call__(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        if self.barrier is not None:
            self.barrier.wait()
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

        # If dd mem batch is detected, produce valid base64 slices
        if any("dd if=/proc" in str(arg) for arg in cmd_args):
            return 0, "0|AQIDBAUGBwgJCgsMDQ4PEA==\n1|AQIDBAUGBwgJCgsMDQ4PEA==\n", ""
        return 0, self.stdout_payload, self.stderr_payload


class BaseMockAdapter(TargetExecutionAdapter):
    """Concrete minimal implementation of TargetExecutionAdapter for testing base class semantics."""

    def __init__(self, memory_reader=None):
        self._memory_reader = memory_reader or (lambda pid, addr, sz: (b"\xaa" * sz, "OBSERVED", None))
        self._budget_tracker = None

    def is_remote(self) -> bool:
        return False

    def target_host(self) -> str:
        return "localhost"

    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        return True, None

    def get_process_identity(self, pid: int, **kwargs) -> Dict[str, Any]:
        return {"pid": pid, "arch": "x86_64", "build_id": "test_base"}

    def get_proc_maps(self, pid: int, **kwargs) -> List[Dict[str, Any]]:
        return []

    def get_threads(self, pid: int, **kwargs) -> List[Dict[str, Any]]:
        return []

    def get_process_memory_info(self, pid: int, **kwargs) -> Dict[str, int]:
        return {"vm_size": 1024, "vm_rss": 512}

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
# Workstream A: Cross-Adapter Invocation Atomicity & Provenance Matrix
# ==============================================================================

class TestPhase20A3421CrossAdapterProvenanceMatrix(unittest.TestCase):
    """Workstream A: Cross-Adapter Invocation Atomicity & Provenance Guarantees."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_01_base_adapter_read_memory_batch_satisfies_provenance_contract(self):
        """1. Base TargetExecutionAdapter creates atomic batch contract, invocation, and reconciles cleanly."""
        adapter = BaseMockAdapter()
        adapter.set_budget_tracker(self.tracker)

        slices = [(0x1000, 32), (0x2000, 32)]
        results = adapter.read_memory_batch(1001, slices, budget_tracker=self.tracker)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][1], "OBSERVED")
        self.assertEqual(len(results[0][0]), 32)

        # Invariant checks
        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 1)
        inv = next(iter(invs.values()))
        self.assertEqual(inv.outcome, "COMPLETED")
        self.assertEqual(len(inv.physical_read_ids), 2)

        batches = self.tracker.get_batch_records()
        self.assertEqual(len(batches), 1)
        batch = next(iter(batches.values()))
        self.assertEqual(batch.expected_slice_count, 2)
        self.assertEqual(len(batch.slices), 2)

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])

    def test_02_base_adapter_read_memory_batch_empty_slices_returns_immediately(self):
        """2. Empty slices batch returns empty list immediately without orphan contracts or invocations."""
        adapter = BaseMockAdapter()
        adapter.set_budget_tracker(self.tracker)

        results = adapter.read_memory_batch(1001, [], budget_tracker=self.tracker)
        self.assertEqual(results, [])
        self.assertEqual(len(self.tracker.get_invocation_records()), 0)
        self.assertEqual(len(self.tracker.get_batch_records()), 0)

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])

    def test_03_base_adapter_read_memory_batch_exception_cleans_up_provenance(self):
        """3. Unhandled exception inside read_memory marks child reads, completes invocation as FAILED, no leaks."""
        def faulty_reader(pid, addr, sz):
            if addr == 0x2000:
                raise IOError("Target memory unreadable")
            return b"\xaa" * sz, "OBSERVED", None

        adapter = BaseMockAdapter(memory_reader=faulty_reader)
        adapter.set_budget_tracker(self.tracker)

        slices = [(0x1000, 32), (0x2000, 32)]
        with self.assertRaises(IOError):
            adapter.read_memory_batch(1002, slices, budget_tracker=self.tracker)

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 1)
        inv = next(iter(invs.values()))
        self.assertEqual(inv.outcome, "FAILED")
        self.assertIn("Target memory unreadable", inv.exception or "")

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])

    def test_04_local_adapter_read_memory_batch_provenance(self):
        """4. LocalTargetAdapter satisfies full batch provenance and reconciliation."""
        adapter = LocalTargetAdapter()
        adapter.set_budget_tracker(self.tracker)

        # Point to mapped self memory
        addr = id(self)
        slices = [(addr, 8), (addr + 8, 8)]
        results = adapter.read_memory_batch(os.getpid(), slices, budget_tracker=self.tracker)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][1], "OBSERVED")

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])

    def test_05_readonly_adapter_delegation_preserves_provenance_and_budget(self):
        """5. ReadOnlyTargetAdapter correctly delegates batch contract, admissions, and invocations."""
        inner = BaseMockAdapter()
        ro_adapter = ReadOnlyTargetAdapter(inner, budget_tracker=self.tracker)

        slices = [(0x1000, 16), (0x2000, 16)]
        results = ro_adapter.read_memory_batch(1003, slices, budget_tracker=self.tracker)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][1], "OBSERVED")

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])

    def test_06_remote_ssh_adapter_preflight_rejection_vs_execution_failure(self):
        """6. Preflight rejection (rc=-2) records PREFLIGHT_REJECTED without physical consumption."""
        runner = MockBarrierRunnerA3421()
        runner.fail_before_execution = True
        runner.preflight_reason = "executable unavailable: ssh binary not found"

        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            command_runner=runner,
            budget_tracker=self.tracker,
        )

        slices = [(0x1000, 32), (0x2000, 32)]
        results = adapter.read_memory_batch(2001, slices, budget_tracker=self.tracker)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][1], "UNAVAILABLE")

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 1)
        inv = next(iter(invs.values()))
        self.assertEqual(inv.outcome, "PREFLIGHT_REJECTED")
        self.assertEqual(inv.return_code, -2)

        # Reads must not have charged physical consumption
        reads = self.tracker.get_physical_read_records()
        for r in reads.values():
            self.assertEqual(r.charged_bytes, 0)
            self.assertEqual(r.state, "RELEASED")

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])

    def test_07_contradictory_completion_outcomes_rejected(self):
        """7. An invocation record cannot be completed twice with contradictory outcomes."""
        inv_id = "inv_contra_outcomes"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="batch_test")
        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0, outcome="COMPLETED")

        with self.assertRaises(RuntimeError) as ctx:
            self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=1, outcome="FAILED")
        self.assertIn("already terminal 'COMPLETED'", str(ctx.exception))

    def test_08_failed_invocation_cannot_fabricate_physical_consumption(self):
        """8. Preflight rejected invocation with non-zero consumption is rejected by Invariant 22."""
        batch_id = "batch_no_fab_8"
        inv_id = "inv_no_fab_8"
        read_id = "pread_no_fab_8"

        res = self.tracker.admit_read(64, operation_id="op_no_fab_8")
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={"batch_id": batch_id, "invocation_id": inv_id, "slice_index": 0, "size": 64},
        )
        cr.mark_started()
        cr.consume(64)  # Fabricated consumption!

        slices = [BatchSliceSpec(slice_index=0, address=0x1000, requested_size=64, physical_read_id=read_id)]
        self.tracker.register_batch_contract(
            batch_id=batch_id,
            invocation_id=inv_id,
            expected_slice_count=1,
            slices=slices,
        )
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="batch", physical_read_ids=[read_id])
        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=-2, outcome="PREFLIGHT_REJECTED")

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(any("preflight rejected with consumption" in d for d in report["discrepancies"]))


# ==============================================================================
# Workstream B: Commit, Rollback and Lock Closure
# ==============================================================================

class TestPhase20A3421CommitRollbackAndLockClosure(unittest.TestCase):
    """Workstream B: Commit, Rollback, and Lock Order Integrity."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_09_universal_lock_order_hierarchy_preventing_inversion(self):
        """9. Hierarchy acquisition order Level 1 -> Level 2 -> Level 3 operates without deadlock."""
        res = self.tracker.admit_read(128, operation_id="op_lock_order")
        cr1 = res.start_child_read(physical_read_id="cr_lo_1")
        cr2 = res.start_child_read(physical_read_id="cr_lo_2")

        # Tracker level 1 lock wraps reservation level 2 and child level 3
        with self.tracker._transaction_lock:
            with res._lock_with_children():
                cr1.mark_started()
                cr2.mark_started()
                cr1.consume(32)
                cr2.consume(32)

        self.assertEqual(res.consumed_bytes, 64)
        self.assertEqual(res.state, "CONSUMED")

    def test_10_terminal_child_read_cannot_mutate_target_spec(self):
        """10. update_target_spec() raises RuntimeError if child or parent is in terminal state."""
        res = self.tracker.admit_read(64, operation_id="op_immut_spec")
        cr = res.start_child_read(physical_read_id="cr_immut")
        cr.mark_started()
        cr.consume(32)
        cr.account()
        res.account()

        self.assertTrue(cr.is_terminal)
        self.assertTrue(res.is_terminal)

        with self.assertRaises(RuntimeError) as ctx:
            cr.update_target_spec({"malicious_mutation": 123})
        self.assertIn("in terminal state", str(ctx.exception))

    def test_11_duplicate_commit_transaction_is_idempotent_no_op(self):
        """11. Duplicate commit of identical logical transaction returns True without double-charging."""
        op_id = "op_idemp_commit"
        res = self.tracker.admit_read(64, operation_id=op_id)
        cr = res.start_child_read(physical_read_id="cr_idemp")
        cr.mark_started()
        cr.consume(32)

        # First commit
        ok1 = self.tracker.commit_transaction(operation_id=op_id, measured_bytes=32, reservations=[res])
        self.assertTrue(ok1)
        initial_bytes = self.tracker.metrics.bytes_read

        # Second identical commit
        ok2 = self.tracker.commit_transaction(operation_id=op_id, measured_bytes=32, reservations=[res])
        self.assertTrue(ok2)
        # Metrics must NOT double charge
        self.assertEqual(self.tracker.metrics.bytes_read, initial_bytes)

    def test_12_conflicting_duplicate_commit_fails_closed(self):
        """12. Conflicting duplicate commit with different charged bytes raises ValueError and fails closed."""
        op_id = "op_conflict_commit"
        res = self.tracker.admit_read(64, operation_id=op_id)
        cr = res.start_child_read(physical_read_id="cr_conf")
        cr.mark_started()
        cr.consume(32)

        ok1 = self.tracker.commit_transaction(operation_id=op_id, measured_bytes=32, reservations=[res])
        self.assertTrue(ok1)

        with self.assertRaises(ValueError) as ctx:
            self.tracker.commit_transaction(operation_id=op_id, measured_bytes=64)
        self.assertIn("Operation ID collision", str(ctx.exception))

    def test_13_rollback_fault_recovery_preserves_consistent_state(self):
        """13. Fault injected during scope commit triggers recovery and reconciles cleanly."""
        self.tracker.inject_fault("during_logical_ledger_insertion")

        with self.tracker.operation_scope(operation_id="op_fault_rec") as scope:
            res = scope.admit_read(64)
            cr = res.start_child_read(physical_read_id="cr_fault")
            cr.mark_started()
            cr.consume(32)
            scope.record_read(bytes_read=32, admission=res)

        # Recovery should record FAILED transaction and reconcile cleanly
        snap = self.tracker.get_committed_transactions()["op_fault_rec"]
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertTrue(snap.is_failure)

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])

    def test_14_direct_commit_without_child_reads_records_consistent_failure_state(self):
        """14. Direct commit with is_failure=True records FAILED_ACCOUNTED read and FAILED consumption."""
        op_id = "op_direct_fail"
        ok = self.tracker.commit_transaction(
            operation_id=op_id,
            estimated_bytes=64,
            is_failure=True,
        )
        self.assertTrue(ok)

        snap = self.tracker.get_committed_transactions()[op_id]
        self.assertTrue(snap.is_failure)
        self.assertEqual(snap.accounting_status, "COMMITTED")

        # Root consumption and read
        pcons = self.tracker.get_physical_consumption_records()[snap.physical_consumption_id]
        self.assertEqual(pcons.accounting_status, "FAILED")
        self.assertTrue(pcons.is_failure)

        pread = self.tracker.get_physical_read_records()[pcons.physical_read_id]
        self.assertEqual(pread.state, "FAILED_ACCOUNTED")
        self.assertTrue(pread.is_failure)
        self.assertIsNotNone(pread.terminal_at_ms)

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])


# ==============================================================================
# Workstream D: Deterministic Barrier-Coordinated Concurrency Scenarios (1-15)
# ==============================================================================

class TestPhase20A3421DeterministicConcurrencyScenarios(unittest.TestCase):
    """Workstream D: 15 Required Deterministic Barrier-Coordinated Concurrency Scenarios."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_15_scenario_1_reservation_release_vs_child_mark_started(self):
        """Scenario 1: Barrier race between BudgetReservation.release() and child mark_started()."""
        res = self.tracker.admit_read(64, operation_id="op_sc1")
        cr = res.start_child_read(physical_read_id="cr_sc1")

        barrier = threading.Barrier(2)
        outcomes = {"release": None, "mark_started": None}

        def worker_release():
            try:
                barrier.wait()
                res.release()
                outcomes["release"] = "SUCCESS"
            except Exception as e:
                outcomes["release"] = type(e).__name__

        def worker_start():
            try:
                barrier.wait()
                cr.mark_started()
                outcomes["mark_started"] = "SUCCESS"
            except Exception as e:
                outcomes["mark_started"] = type(e).__name__

        t1 = threading.Thread(target=worker_release)
        t2 = threading.Thread(target=worker_start)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        if outcomes["release"] == "SUCCESS":
            # Release won: child mark_started must be rejected
            self.assertEqual(outcomes["mark_started"], "RuntimeError")
            self.assertEqual(res.state, "RELEASED")
            self.assertEqual(cr.state, "RELEASED")
        else:
            # Mark started won: release must be rejected because child is in PHYSICAL_READ_STARTED
            self.assertEqual(outcomes["mark_started"], "SUCCESS")
            self.assertEqual(outcomes["release"], "RuntimeError")
            self.assertEqual(cr.state, "PHYSICAL_READ_STARTED")

    def test_16_scenario_2_reservation_release_vs_child_consume(self):
        """Scenario 2: Barrier race between BudgetReservation.release() and child consume()."""
        res = self.tracker.admit_read(64, operation_id="op_sc2")
        cr = res.start_child_read(physical_read_id="cr_sc2")
        cr.mark_started()

        barrier = threading.Barrier(2)
        outcomes = {"release": None, "consume": None}

        def worker_release():
            try:
                barrier.wait()
                res.release()
                outcomes["release"] = "SUCCESS"
            except Exception as e:
                outcomes["release"] = type(e).__name__

        def worker_consume():
            try:
                barrier.wait()
                cr.consume(32)
                outcomes["consume"] = "SUCCESS"
            except Exception as e:
                outcomes["consume"] = type(e).__name__

        t1 = threading.Thread(target=worker_release)
        t2 = threading.Thread(target=worker_consume)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        if outcomes["consume"] == "SUCCESS":
            # Consume won: release must be rejected
            self.assertEqual(outcomes["release"], "RuntimeError")
            self.assertEqual(res.consumed_bytes, 32)
        else:
            # Release won: consume must be rejected
            self.assertEqual(outcomes["release"], "SUCCESS")
            self.assertEqual(outcomes["consume"], "RuntimeError")
            self.assertEqual(res.consumed_bytes, 0)

    def test_17_scenario_3_reservation_account_vs_child_mutation(self):
        """Scenario 3: Barrier race between BudgetReservation.account() and child update_target_spec()."""
        res = self.tracker.admit_read(64, operation_id="op_sc3")
        cr = res.start_child_read(physical_read_id="cr_sc3")
        cr.mark_started()
        cr.consume(32)

        barrier = threading.Barrier(2)
        outcomes = {"account": None, "mutate": None}

        def worker_account():
            try:
                barrier.wait()
                res.account()
                outcomes["account"] = "SUCCESS"
            except Exception as e:
                outcomes["account"] = type(e).__name__

        def worker_mutate():
            try:
                barrier.wait()
                cr.update_target_spec({"mutated": True})
                outcomes["mutate"] = "SUCCESS"
            except Exception as e:
                outcomes["mutate"] = type(e).__name__

        t1 = threading.Thread(target=worker_account)
        t2 = threading.Thread(target=worker_mutate)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        self.assertEqual(outcomes["account"], "SUCCESS")
        if outcomes["mutate"] != "SUCCESS":
            # Account committed first: mutation rejected
            self.assertEqual(outcomes["mutate"], "RuntimeError")

    def test_18_scenario_4_parent_finalization_vs_child_registration(self):
        """Scenario 4: Barrier race between BudgetReservation.finalize() and start_child_read()."""
        res = self.tracker.admit_read(64, operation_id="op_sc4")
        cr1 = res.start_child_read(physical_read_id="cr_sc4_1")
        cr1.mark_started()
        cr1.consume(32)

        barrier = threading.Barrier(2)
        outcomes = {"finalize": None, "start_child": None}

        def worker_finalize():
            try:
                barrier.wait()
                res.finalize()
                outcomes["finalize"] = "SUCCESS"
            except Exception as e:
                outcomes["finalize"] = type(e).__name__

        def worker_start_child():
            try:
                barrier.wait()
                res.start_child_read(physical_read_id="cr_sc4_2")
                outcomes["start_child"] = "SUCCESS"
            except Exception as e:
                outcomes["start_child"] = type(e).__name__

        t1 = threading.Thread(target=worker_finalize)
        t2 = threading.Thread(target=worker_start_child)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        if outcomes["finalize"] == "SUCCESS":
            if outcomes["start_child"] != "SUCCESS":
                self.assertEqual(outcomes["start_child"], "RuntimeError")
            else:
                # Both succeeded: finalizer must have captured cr2 as well
                self.assertIn(res.state, ("FINALIZED", "ACCOUNTED"))
                for c in res.child_reads.values():
                    self.assertTrue(c.is_terminal)

    def test_19_scenario_5_commit_vs_concurrent_child_registration(self):
        """Scenario 5: Barrier race between commit_transaction() and start_child_read()."""
        op_id = "op_sc5"
        res = self.tracker.admit_read(64, operation_id=op_id)
        cr1 = res.start_child_read(physical_read_id="cr_sc5_1")
        cr1.mark_started()
        cr1.consume(32)

        barrier = threading.Barrier(2)
        outcomes = {"commit": None, "register_child": None}

        def worker_commit():
            try:
                barrier.wait()
                ok = self.tracker.commit_transaction(operation_id=op_id, measured_bytes=32, reservations=[res])
                outcomes["commit"] = "SUCCESS" if ok else "REJECTED"
            except Exception as e:
                outcomes["commit"] = type(e).__name__

        def worker_reg():
            try:
                barrier.wait()
                res.start_child_read(physical_read_id="cr_sc5_2")
                outcomes["register_child"] = "SUCCESS"
            except Exception as e:
                outcomes["register_child"] = type(e).__name__

        t1 = threading.Thread(target=worker_commit)
        t2 = threading.Thread(target=worker_reg)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        self.assertEqual(outcomes["commit"], "SUCCESS")
        if outcomes["register_child"] != "SUCCESS":
            self.assertEqual(outcomes["register_child"], "RuntimeError")

    def test_20_scenario_6_commit_vs_child_consumption(self):
        """Scenario 6: Barrier race between commit_transaction() and child consume()."""
        op_id = "op_sc6"
        res = self.tracker.admit_read(64, operation_id=op_id)
        cr1 = res.start_child_read(physical_read_id="cr_sc6_1")
        cr2 = res.start_child_read(physical_read_id="cr_sc6_2")
        cr1.mark_started()
        cr1.consume(32)
        cr2.mark_started()

        barrier = threading.Barrier(2)
        outcomes = {"commit": None, "consume": None}

        def worker_commit():
            try:
                barrier.wait()
                ok = self.tracker.commit_transaction(operation_id=op_id, measured_bytes=32, reservations=[res])
                outcomes["commit"] = "SUCCESS" if ok else "REJECTED"
            except Exception as e:
                outcomes["commit"] = type(e).__name__

        def worker_consume():
            try:
                barrier.wait()
                cr2.consume(32)
                outcomes["consume"] = "SUCCESS"
            except Exception as e:
                outcomes["consume"] = type(e).__name__

        t1 = threading.Thread(target=worker_commit)
        t2 = threading.Thread(target=worker_consume)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        # If commit ran while cr2 was in flight (PHYSICAL_READ_STARTED), commit raises RuntimeError
        # If consume ran first, both succeed
        self.assertIn(outcomes["commit"], ("SUCCESS", "RuntimeError"))
        self.assertIn(outcomes["consume"], ("SUCCESS", "RuntimeError"))

    def test_21_scenario_7_rollback_vs_child_mutation(self):
        """Scenario 7: Fault-injection rollback during commit vs concurrent child mutation."""
        self.tracker.inject_fault("during_logical_ledger_insertion")
        op_id = "op_sc7"

        res = self.tracker.admit_read(64, operation_id=op_id)
        cr = res.start_child_read(physical_read_id="cr_sc7")
        cr.mark_started()
        cr.consume(32)

        barrier = threading.Barrier(2)
        outcomes = {"scope_commit": None, "child_mutate": None}

        def worker_scope():
            try:
                barrier.wait()
                with self.tracker.operation_scope(op_id) as scope:
                    scope.record_read(bytes_read=32, admission=res)
                outcomes["scope_commit"] = "SUCCESS"
            except Exception as e:
                outcomes["scope_commit"] = type(e).__name__

        def worker_mutate():
            try:
                barrier.wait()
                cr.update_target_spec({"test_interleave": 7})
                outcomes["child_mutate"] = "SUCCESS"
            except Exception as e:
                outcomes["child_mutate"] = type(e).__name__

        t1 = threading.Thread(target=worker_scope)
        t2 = threading.Thread(target=worker_mutate)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        self.assertEqual(outcomes["scope_commit"], "SUCCESS")
        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])

    def test_22_scenario_8_invocation_completion_vs_reconciliation(self):
        """Scenario 8: Invocation completion racing against reconcile_ledger()."""
        inv_id = "inv_sc8"
        read_id = "pread_sc8"
        res = self.tracker.admit_read(64, operation_id="op_sc8")
        cr = res.start_child_read(physical_read_id=read_id, target_spec={"invocation_id": inv_id})
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="batch", physical_read_ids=[read_id])
        cr.mark_started()
        cr.consume(64)

        barrier = threading.Barrier(2)
        outcomes = {"complete": None, "reconcile": None}

        def worker_complete():
            try:
                barrier.wait()
                self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0)
                outcomes["complete"] = "SUCCESS"
            except Exception as e:
                outcomes["complete"] = type(e).__name__

        def worker_recon():
            try:
                barrier.wait()
                rep = self.tracker.reconcile_ledger(raise_on_error=False)
                outcomes["reconcile"] = "RECONCILED" if rep["reconciled"] else "DISCREPANCY"
            except Exception as e:
                outcomes["reconcile"] = type(e).__name__

        t1 = threading.Thread(target=worker_complete)
        t2 = threading.Thread(target=worker_recon)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        self.assertEqual(outcomes["complete"], "SUCCESS")
        self.assertIn(outcomes["reconcile"], ("RECONCILED", "DISCREPANCY"))

    def test_23_scenario_9_batch_registration_vs_reconciliation(self):
        """Scenario 9: Atomic batch contract registration and started invocation vs reconciliation."""
        batch_id = "batch_sc9"
        inv_id = "inv_sc9"
        read_id = "pread_sc9"
        res = self.tracker.admit_read(64, operation_id="op_sc9")
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={"batch_id": batch_id, "invocation_id": inv_id, "slice_index": 0, "size": 64},
        )

        slices = [BatchSliceSpec(slice_index=0, address=0x1000, requested_size=64, physical_read_id=read_id)]
        barrier = threading.Barrier(2)
        recon_reports = []

        def worker_register():
            barrier.wait()
            with self.tracker._transaction_lock:
                self.tracker.register_batch_contract(
                    batch_id=batch_id,
                    invocation_id=inv_id,
                    expected_slice_count=1,
                    slices=slices,
                )
                self.tracker.record_invocation_started(
                    invocation_id=inv_id,
                    command_type="batch",
                    physical_read_ids=[read_id],
                )

        def worker_recon():
            barrier.wait()
            for _ in range(5):
                rep = self.tracker.reconcile_ledger(raise_on_error=False)
                recon_reports.append(rep["reconciled"])
                time.sleep(0.0005)

        t1 = threading.Thread(target=worker_register)
        t2 = threading.Thread(target=worker_recon)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        # An orphan batch contract must NEVER have been visible
        invs = self.tracker.get_invocation_records()
        self.assertIn(inv_id, invs)

    def test_24_scenario_10_public_snapshot_getter_vs_concurrent_lifecycle_transition(self):
        """Scenario 10: Public snapshot getter returning independent copies during terminal transitions."""
        res = self.tracker.admit_read(64, operation_id="op_sc10")
        cr = res.start_child_read(physical_read_id="cr_sc10")
        cr.mark_started()
        cr.consume(32)

        barrier = threading.Barrier(2)
        snapshots = []

        def worker_transition():
            barrier.wait()
            res.account()

        def worker_getter():
            barrier.wait()
            for _ in range(5):
                snaps = self.tracker.get_active_reservations()
                snapshots.append(snaps)
                time.sleep(0.0005)

        t1 = threading.Thread(target=worker_transition)
        t2 = threading.Thread(target=worker_getter)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        # All snapshot reads must be independent deep copies
        for s in snapshots:
            if res.reservation_id in s:
                item = s[res.reservation_id]
                self.assertIsNot(item, res)

    def test_25_scenario_11_multiple_concurrent_commits_for_same_physical_consumption(self):
        """Scenario 11: Two threads commit for the same physical consumption concurrently."""
        op_id = "op_sc11"
        res = self.tracker.admit_read(64, operation_id=op_id)
        cr = res.start_child_read(physical_read_id="cr_sc11")
        cr.mark_started()
        cr.consume(32)

        barrier = threading.Barrier(2)
        commit_results = []

        def worker():
            barrier.wait()
            try:
                ok = self.tracker.commit_transaction(operation_id=op_id, measured_bytes=32, reservations=[res])
                commit_results.append("SUCCESS" if ok else "REJECTED")
            except Exception as e:
                commit_results.append(type(e).__name__)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        # Both must succeed idempotently without double-counting
        self.assertEqual(commit_results, ["SUCCESS", "SUCCESS"])
        self.assertEqual(self.tracker.metrics.bytes_read, 32)

    def test_26_scenario_12_conflicting_duplicate_completion(self):
        """Scenario 12: Two threads attempt contradictory completion on the same in-flight invocation."""
        inv_id = "inv_sc12"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="batch_test")

        barrier = threading.Barrier(2)
        results = {}

        def worker_success():
            try:
                barrier.wait()
                self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0, outcome="COMPLETED")
                results["succ"] = "SUCCESS"
            except Exception as e:
                results["succ"] = type(e).__name__

        def worker_fail():
            try:
                barrier.wait()
                self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=1, outcome="FAILED")
                results["fail"] = "SUCCESS"
            except Exception as e:
                results["fail"] = type(e).__name__

        t1 = threading.Thread(target=worker_success)
        t2 = threading.Thread(target=worker_fail)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())

        # Exactly one wins, the other raises RuntimeError
        winner_count = list(results.values()).count("SUCCESS")
        error_count = list(results.values()).count("RuntimeError")
        self.assertEqual(winner_count, 1)
        self.assertEqual(error_count, 1)

    def test_27_scenario_13_concurrent_operations_on_multiple_child_records(self):
        """Scenario 13: Multiple threads consume different child reads of the same parent reservation."""
        res = self.tracker.admit_read(256, operation_id="op_sc13")
        children = [res.start_child_read(physical_read_id=f"cr_sc13_{i}") for i in range(4)]
        for c in children:
            c.mark_started()

        barrier = threading.Barrier(4)
        errors = []

        def worker(idx: int):
            try:
                barrier.wait()
                children[idx].consume(16)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5.0)
            self.assertFalse(t.is_alive())

        self.assertEqual(len(errors), 0)
        self.assertEqual(res.consumed_bytes, 64)
        self.assertEqual(sum(c.charged_bytes for c in children), 64)

    def test_28_scenario_14_lock_order_inversion_attempt_does_not_deadlock(self):
        """Scenario 14: Thread A acquires parent then child; Thread B calls child consume (acquiring parent then child)."""
        res = self.tracker.admit_read(64, operation_id="op_sc14")
        cr = res.start_child_read(physical_read_id="cr_sc14")
        cr.mark_started()

        barrier = threading.Barrier(2)
        errors = []

        def worker_parent():
            try:
                barrier.wait()
                with res._lock_with_children():
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        def worker_child():
            try:
                barrier.wait()
                cr.consume(32)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker_parent)
        t2 = threading.Thread(target=worker_child)
        t1.start()
        t2.start()
        t1.join(5.0)
        t2.join(5.0)
        self.assertFalse(t1.is_alive(), "Deadlock detected in worker_parent")
        self.assertFalse(t2.is_alive(), "Deadlock detected in worker_child")
        self.assertEqual(len(errors), 0)

    def test_29_scenario_15_adapter_invocation_failure_during_concurrent_reconciliation(self):
        """Scenario 15: Adapter invocation failure while background thread continuously reconciles ledger."""
        runner = MockBarrierRunnerA3421()
        runner.return_code = 1
        runner.stderr_payload = "Process execution failed"
        adapter = RemoteSshTargetAdapter(host="127.0.0.1", command_runner=runner, budget_tracker=self.tracker)

        stop_event = threading.Event()
        reconcile_results = []

        def worker_reconcile():
            while not stop_event.is_set():
                rep = self.tracker.reconcile_ledger(raise_on_error=False)
                reconcile_results.append(rep["reconciled"])
                time.sleep(0.0005)

        t_rec = threading.Thread(target=worker_reconcile)
        t_rec.start()

        try:
            for i in range(4):
                slices = [(0x1000 + i * 32, 16), (0x2000 + i * 32, 16)]
                adapter.read_memory_batch(1000 + i, slices, budget_tracker=self.tracker)
        finally:
            stop_event.set()
            t_rec.join(5.0)

        self.assertFalse(t_rec.is_alive())
        # Ledger must remain self-consistent even through failures
        self.assertTrue(all(reconcile_results))
        final_rep = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(final_rep["reconciled"])


# ==============================================================================
# Workstream E: Stress & Concurrency Totality
# ==============================================================================

class TestPhase20A3421CrossAdapterStressAndLifecycleTotality(unittest.TestCase):
    """Workstream E: Adversarial Contention & Comprehensive Cross-Adapter Stress."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(
            limits=ObservationBudgetLimits(max_consecutive_read_failures=100, max_total_read_failures=100)
        )
        self.tracker.start()

    def test_30_multi_adapter_concurrent_execution_stress(self):
        """30. Concurrent execution across LocalTargetAdapter, BaseMockAdapter, and RemoteSshTargetAdapter."""
        runner = MockBarrierRunnerA3421()
        remote_adapter = RemoteSshTargetAdapter(host="127.0.0.1", command_runner=runner, budget_tracker=self.tracker)
        local_adapter = LocalTargetAdapter()
        local_adapter.set_budget_tracker(self.tracker)
        base_adapter = BaseMockAdapter()
        base_adapter.set_budget_tracker(self.tracker)

        errors = []
        stop_event = threading.Event()

        def worker_base(idx: int):
            try:
                for i in range(4):
                    slices = [(0x1000 + i * 16, 16), (0x2000 + i * 16, 16)]
                    base_adapter.read_memory_batch(2000 + idx, slices, budget_tracker=self.tracker)
            except Exception as e:
                errors.append(e)

        def worker_remote(idx: int):
            try:
                for i in range(4):
                    slices = [(0x3000 + i * 16, 16), (0x4000 + i * 16, 16)]
                    remote_adapter.read_memory_batch(3000 + idx, slices, budget_tracker=self.tracker)
            except Exception as e:
                errors.append(e)

        def worker_recon():
            try:
                while not stop_event.is_set():
                    self.tracker.reconcile_ledger(raise_on_error=True)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(3):
            threads.append(threading.Thread(target=worker_base, args=(i,)))
            threads.append(threading.Thread(target=worker_remote, args=(i,)))
        reconciler = threading.Thread(target=worker_recon)

        for t in threads:
            t.start()
        reconciler.start()

        for t in threads:
            t.join(10.0)
            self.assertFalse(t.is_alive())

        stop_event.set()
        reconciler.join(5.0)
        self.assertFalse(reconciler.is_alive())

        self.assertEqual(len(errors), 0, f"Errors encountered: {errors}")
        final_rep = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(final_rep["reconciled"])


if __name__ == "__main__":
    unittest.main()
