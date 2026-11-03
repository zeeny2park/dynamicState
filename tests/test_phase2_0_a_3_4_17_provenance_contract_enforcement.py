"""Phase 2.0-A.3.4.17 — Provenance Contract Enforcement & Immutable Lifecycle Closure.

Hardens the provenance model across:
1. Section 2: Authoritative Invocation Identity & Conflict Rejection
2. Section 3: Authoritative Batch Contracts & Complete Coverage
3. Section 4: Provenance Storage Immutability & Concurrency Safety
4. Section 5: Timestamp Unit Consistency & Monotonic Durations
5. Section 6: Complete Reconciliation Across All Registries (Full Provenance Graph)
6. Section 7 & 8: Accounting Semantics & Production Remote Call Graph Verification
"""

import copy
import dataclasses
import os
import threading
import time
import unittest
import uuid
from typing import Any, Dict, List, Optional, Tuple

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
    RemoteSshTargetAdapter,
)


class MockCommandRunner:
    """Mock command runner with fine-grained failure injection and call interception."""

    def __init__(self):
        self.invocations: List[Dict[str, Any]] = []
        self.fail_before_execution = False
        self.raise_exception: Optional[Exception] = None
        self.timeout_sec: Optional[float] = None
        self.return_code = 0
        self.stdout_payload = "OK\n"
        self.stderr_payload = ""
        self._lock = threading.Lock()

    def check_preflight(self, cmd_args: List[str]) -> Tuple[bool, Optional[str]]:
        if self.fail_before_execution:
            return False, "preflight runner rejection"
        return True, None

    def __call__(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        with self._lock:
            self.invocations.append({
                "args": list(cmd_args),
                "timeout": timeout,
                "start_time": time.time(),
            })

        if self.raise_exception is not None:
            raise self.raise_exception

        cmd_str = " ".join(cmd_args) if isinstance(cmd_args, (list, tuple)) else str(cmd_args)

        # Handle batch shell dd/base64 simulation
        if "dd if=/proc/" in cmd_str and "base64" in cmd_str:
            import base64
            lines = []
            if "0|" in cmd_str or "echo \"" in cmd_str:
                for idx in range(10):
                    data = base64.b64encode(b"X" * 32).decode("ascii")
                    lines.append(f"{idx}|{data}")
                return 0, "\n".join(lines), ""
            else:
                data = base64.b64encode(b"Y" * 32).decode("ascii")
                return 0, data + "\n", ""

        if "kill -0" in cmd_str:
            return 0, "ALIVE\n", ""
        if "readlink" in cmd_str:
            return 0, "/usr/bin/test_target\n", ""
        if "stat" in cmd_str:
            return 0, "1234 (target) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 12345678 0 0 0\n", ""
        if "maps" in cmd_str:
            return 0, "00400000-00452000 r-xp 00000000 08:02 123456 /bin/test\n", ""
        if "status" in cmd_str or "statm" in cmd_str:
            return 0, "1000 500 200 100 0 200 0\n---DELIM_STATUS---\nVmRSS: 2048 kB\n---DELIM_SMAPS---\n", ""
        if "task" in cmd_str or "comm" in cmd_str:
            return 0, "1234|worker_thread\n", ""

        return self.return_code, self.stdout_payload, self.stderr_payload


class TestPhase20A3417AuthoritativeInvocationIdentity(unittest.TestCase):
    """Section 2: Enforce Authoritative Invocation Identity & Conflict Rejection."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(session_id="test_sess_inv_id")
        self.runner = MockCommandRunner()
        self.adapter = RemoteSshTargetAdapter(host="target.example.com", command_runner=self.runner)
        self.adapter.set_budget_tracker(self.tracker)

    def test_01_conflicting_child_invocation_id_rejected_before_execution(self):
        """Child read pre-configured with conflicting invocation_id is rejected before command runner execution."""
        adm = self.tracker.admit_read(projected_bytes=64, profile_id="prof_inv")
        cr = adm.start_child_read(
            target_type="remote_command_slice",
            target_spec={"invocation_id": "inv_child_orig"},
        )
        # Attempt to run SSH passing a conflicting invocation_id
        with self.assertRaises(ValueError) as ctx:
            self.adapter.run_ssh(
                "echo test",
                admission=adm,
                child_read=cr,
                invocation_id="inv_runner_conflicting",
            )
        self.assertIn("Conflicting child invocation_id 'inv_child_orig'", str(ctx.exception))
        # Ensure command runner was never invoked
        self.assertEqual(len(self.runner.invocations), 0)
        self.assertEqual(len(self.tracker.get_invocation_records()), 0)

    def test_02_conflicting_sibling_child_invocation_ids_rejected(self):
        """Multiple child reads with differing invocation_ids in the same execution are rejected."""
        adm = self.tracker.admit_read(projected_bytes=128, profile_id="prof_inv")
        cr1 = adm.start_child_read(target_spec={"invocation_id": "inv_A"})
        cr2 = adm.start_child_read(target_spec={"invocation_id": "inv_B"})
        with self.assertRaises(ValueError) as ctx:
            self.adapter.run_ssh("echo test", admission=adm, child_reads=[cr1, cr2])
        self.assertIn("Conflicting child invocation_id", str(ctx.exception))
        self.assertEqual(len(self.runner.invocations), 0)

    def test_03_cannot_replace_invocation_id_after_started(self):
        """Physical read already in PHYSICAL_READ_STARTED cannot have invocation_id replaced."""
        adm = self.tracker.admit_read(projected_bytes=64, profile_id="prof_inv")
        cr = adm.start_child_read(target_spec={"invocation_id": "inv_started_1"})
        cr.mark_started()
        with self.assertRaises(RuntimeError) as ctx:
            self.adapter.run_ssh(
                "echo test",
                admission=adm,
                child_read=cr,
                invocation_id="inv_replacement_bad",
            )
        self.assertIn("Cannot replace invocation_id", str(ctx.exception))

    def test_04_missing_invocation_registration_fails_closed(self):
        """record_invocation_completed fails closed if start record was not registered; never fabricates dummy record."""
        with self.assertRaises(RuntimeError) as ctx:
            self.tracker.record_invocation_completed("inv_never_started", return_code=0)
        self.assertIn("no start record registered", str(ctx.exception))
        self.assertNotIn("inv_never_started", self.tracker.get_invocation_records())

    def test_05_duplicate_invocation_start_rejected(self):
        """Registering the same invocation_id twice in record_invocation_started raises ValueError."""
        self.tracker.record_invocation_started(
            invocation_id="inv_dup_start",
            command_type="read",
            physical_read_ids=["cr_1"],
        )
        with self.assertRaises(ValueError) as ctx:
            self.tracker.record_invocation_started(
                invocation_id="inv_dup_start",
                command_type="read",
                physical_read_ids=["cr_1"],
            )
        self.assertIn("Duplicate invocation start", str(ctx.exception))

    def test_06_duplicate_invocation_completion_rejected(self):
        """Completing an invocation that is already terminal raises RuntimeError."""
        self.tracker.record_invocation_started(
            invocation_id="inv_dup_comp",
            command_type="read",
            physical_read_ids=["cr_1"],
        )
        self.tracker.record_invocation_completed(
            invocation_id="inv_dup_comp",
            return_code=0,
            outcome="COMPLETED",
        )
        with self.assertRaises(RuntimeError) as ctx:
            self.tracker.record_invocation_completed(
                invocation_id="inv_dup_comp",
                return_code=0,
                outcome="COMPLETED",
            )
        self.assertIn("Duplicate completion for invocation 'inv_dup_comp'", str(ctx.exception))

    def test_07_concurrent_duplicate_invocation_registration(self):
        """Under concurrent registration of the same invocation_id, exactly one succeeds and others raise."""
        success_count = 0
        error_count = 0
        barrier = threading.Barrier(10)

        def worker():
            nonlocal success_count, error_count
            barrier.wait()
            try:
                self.tracker.record_invocation_started(
                    invocation_id="inv_race_target",
                    command_type="race_cmd",
                    physical_read_ids=["cr_race"],
                )
                success_count += 1
            except ValueError:
                error_count += 1

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(success_count, 1)
        self.assertEqual(error_count, 9)
        self.assertEqual(len(self.tracker.get_invocation_records()), 1)

    def test_08_runner_exception_after_start_records_transport_error(self):
        """Runner exception after execution start records TRANSPORT_ERROR with exception details."""
        adm = self.tracker.admit_read(projected_bytes=64, profile_id="prof_inv")
        cr = adm.start_child_read(target_type="remote_cmd")
        self.runner.raise_exception = ConnectionResetError("SSH connection reset by peer")

        rc, _, err = self.adapter.run_ssh("echo fail", admission=adm, child_read=cr)
        self.assertEqual(rc, -1)
        self.assertIn("connection reset", err.lower())

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 1)
        inv = next(iter(invs.values()))
        self.assertEqual(inv.outcome, "TRANSPORT_ERROR")
        self.assertIn("ConnectionResetError", inv.exception or "")

    def test_09_runner_timeout_after_start_records_timeout_outcome(self):
        """Runner timeout records TIMEOUT outcome and preserves monotonic ordering."""
        adm = self.tracker.admit_read(projected_bytes=64, profile_id="prof_inv")
        cr = adm.start_child_read(target_type="remote_cmd")
        import subprocess
        self.runner.raise_exception = subprocess.TimeoutExpired(cmd=["ssh"], timeout=2.0)

        rc, _, err = self.adapter.run_ssh("sleep 10", timeout=2.0, admission=adm, child_read=cr)
        self.assertEqual(rc, -1)
        self.assertIn("timed out", err.lower())

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 1)
        inv = next(iter(invs.values()))
        self.assertEqual(inv.outcome, "TIMEOUT")
        self.assertIsNotNone(inv.completion_time_ms)
        self.assertGreaterEqual(inv.completion_time_ms, inv.start_time_ms)

    def test_10_preflight_rejection_leaves_zero_executed_invocations(self):
        """Preflight rejection before execution (rc=-2) leaves zero executed invocation records."""
        adm = self.tracker.admit_read(projected_bytes=64, profile_id="prof_inv")
        cr = adm.start_child_read(target_type="remote_cmd")
        self.runner.fail_before_execution = True

        rc, _, err = self.adapter.run_ssh("echo preflight", admission=adm, child_read=cr)
        self.assertEqual(rc, -2)
        self.assertIn("failed before invocation", err)

        # Zero executed invocations in tracker and adapter
        self.assertEqual(len(self.tracker.get_invocation_records()), 0)
        self.assertEqual(len(self.adapter.get_invocation_records()), 0)
        self.assertEqual(cr.state, "ADMITTED")
        cr.release()
        self.assertEqual(cr.state, "RELEASED")


class TestPhase20A3417AuthoritativeBatchContracts(unittest.TestCase):
    """Section 3: Batch Contracts Must Be Authoritative."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(session_id="test_sess_batch")

    def test_11_registered_batch_with_zero_slices_fails_reconciliation(self):
        """Batch contract registered before invocation but observing 0 slices fails Invariant 20."""
        self.tracker.record_invocation_started("inv_b0", "batch", [])
        self.tracker.register_batch_contract(
            batch_id="b_empty",
            invocation_id="inv_b0",
            expected_slice_count=3,
        )
        self.tracker.record_invocation_completed("inv_b0", return_code=0, outcome="COMPLETED")

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        self.assertFalse(recon["discrepancy_details"]["inv_20_batch_slice_completeness"])
        err = "; ".join(recon["discrepancies"])
        self.assertIn("has 0 observed slice records (expected 3)", err)

    def test_12_registered_batch_with_missing_final_slice_detected(self):
        """Batch missing final slice index fails Invariant 20."""
        inv_id = "inv_mf"
        self.tracker.record_invocation_started(inv_id, "batch", ["cr_0", "cr_1"])
        self.tracker.register_batch_contract("b_mf", inv_id, expected_slice_count=3)

        adm = self.tracker.admit_read(128, profile_id="prof_b")
        cr0 = adm.start_child_read(
            target_spec={"batch_id": "b_mf", "invocation_id": inv_id, "slice_index": 0, "expected_slice_count": 3, "address": 0x1000, "requested_size": 64},
            physical_read_id="cr_0",
        )
        cr1 = adm.start_child_read(
            target_spec={"batch_id": "b_mf", "invocation_id": inv_id, "slice_index": 1, "expected_slice_count": 3, "address": 0x2000, "requested_size": 64},
            physical_read_id="cr_1",
        )
        cr0.mark_started()
        cr0.consume(actual_bytes=64)
        cr1.mark_started()
        cr1.consume(actual_bytes=64)
        self.tracker.record_invocation_completed(inv_id, return_code=0, outcome="COMPLETED")

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        err = "; ".join(recon["discrepancies"])
        self.assertIn("missing slice indices: [2]", err)

    def test_13_missing_batch_registration_and_expected_count_fails_reconciliation(self):
        """Batch slices without explicit expected_slice_count fail reconciliation (no fallback to len(group))."""
        adm = self.tracker.admit_read(128, profile_id="prof_b")
        cr0 = adm.start_child_read(target_spec={"batch_id": "b_unreg", "invocation_id": "inv_unreg", "slice_index": 0})
        cr0.mark_started()
        cr0.consume(actual_bytes=64)

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        err = "; ".join(recon["discrepancies"])
        self.assertIn("has no explicit expected_slice_count recorded", err)

    def test_14_expected_count_immutable_after_registration(self):
        """BatchReadRecord.expected_slice_count is frozen and re-registration with differing count raises ValueError."""
        b_rec = self.tracker.register_batch_contract("b_immut", "inv_immut", expected_slice_count=4)
        with self.assertRaises((dataclasses.FrozenInstanceError, AttributeError)):
            b_rec.expected_slice_count = 10  # type: ignore

        # Re-registering with differing count raises ValueError
        with self.assertRaises(ValueError) as ctx:
            self.tracker.register_batch_contract("b_immut", "inv_immut", expected_slice_count=5)
        self.assertIn("Cannot modify expected_slice_count", str(ctx.exception))

    def test_15_duplicate_batch_registration_rejected(self):
        """Duplicate registration of the identical batch contract raises ValueError to prevent accidental overwrites."""
        self.tracker.register_batch_contract("b_dup", "inv_dup", expected_slice_count=3)
        with self.assertRaises(ValueError) as ctx:
            self.tracker.register_batch_contract("b_dup", "inv_dup", expected_slice_count=3)
        self.assertIn("Duplicate batch contract registration", str(ctx.exception))

    def test_16_conflicting_batch_slice_metadata_rejected(self):
        """Slices for the same slice index with conflicting address/size metadata violate Invariant 20."""
        inv_id = "inv_meta_conf"
        self.tracker.record_invocation_started(inv_id, "batch", ["cr_mc_0a", "cr_mc_0b"])
        self.tracker.register_batch_contract("b_meta_conf", inv_id, expected_slice_count=1)

        adm = self.tracker.admit_read(128, profile_id="prof_b")
        cr_a = adm.start_child_read(
            target_spec={"batch_id": "b_meta_conf", "invocation_id": inv_id, "slice_index": 0, "expected_slice_count": 1, "address": 0x1000, "requested_size": 64},
            physical_read_id="cr_mc_0a",
        )
        cr_b = adm.start_child_read(
            target_spec={"batch_id": "b_meta_conf", "invocation_id": inv_id, "slice_index": 0, "expected_slice_count": 1, "address": 0x9000, "requested_size": 128},
            physical_read_id="cr_mc_0b",
        )
        cr_a.mark_started()
        cr_a.consume(64)
        cr_b.mark_started()
        cr_b.consume(64)
        self.tracker.record_invocation_completed(inv_id, return_code=0, outcome="COMPLETED")

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        err = "; ".join(recon["discrepancies"])
        self.assertIn("has conflicting metadata", err)

    def test_17_collector_batch_with_nonterminal_slices_fails_reconciliation(self):
        """Committed batch with slices left in NOT_EXECUTED status violates Invariant 20."""
        inv_id = "inv_nonterm"
        self.tracker.record_invocation_started(inv_id, "batch", ["cr_nt_0"])
        self.tracker.register_batch_contract("b_nonterm", inv_id, expected_slice_count=1)

        adm = self.tracker.admit_read(64, profile_id="prof_b")
        cr = adm.start_child_read(
            target_spec={"batch_id": "b_nonterm", "invocation_id": inv_id, "slice_index": 0, "expected_slice_count": 1, "completion_status": "NOT_EXECUTED"},
            physical_read_id="cr_nt_0",
        )
        cr.mark_started()
        cr.consume(64)
        self.tracker.record_invocation_completed(inv_id, return_code=0, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_nonterm",
            profile_id="prof_b",
            measured_bytes=64,
            reservations=[adm],
        )

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        err = "; ".join(recon["discrepancies"])
        self.assertIn("non-terminal completion_status 'NOT_EXECUTED'", err)

    def test_18_fallback_batch_with_missing_middle_slice_detected(self):
        """Fallback batch missing middle slice fails Invariant 20."""
        inv_id = "inv_fb_mid"
        self.tracker.record_invocation_started(inv_id, "batch", ["cr_fb_0", "cr_fb_2"])
        self.tracker.register_batch_contract("b_fb", inv_id, expected_slice_count=3)

        adm = self.tracker.admit_read(128, profile_id="prof_b")
        cr0 = adm.start_child_read(
            target_spec={"batch_id": "b_fb", "invocation_id": inv_id, "slice_index": 0, "expected_slice_count": 3, "address": 0x1000, "requested_size": 64},
            physical_read_id="cr_fb_0",
        )
        cr2 = adm.start_child_read(
            target_spec={"batch_id": "b_fb", "invocation_id": inv_id, "slice_index": 2, "expected_slice_count": 3, "address": 0x3000, "requested_size": 64},
            physical_read_id="cr_fb_2",
        )
        cr0.mark_started()
        cr0.consume(64)
        cr2.mark_started()
        cr2.consume(64)
        self.tracker.record_invocation_completed(inv_id, return_code=0, outcome="COMPLETED")

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        err = "; ".join(recon["discrepancies"])
        self.assertIn("missing slice indices: [1]", err)


class TestPhase20A3417StorageImmutabilityAndConcurrency(unittest.TestCase):
    """Section 4: Provenance Storage Immutability & Concurrency Safety."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(session_id="test_sess_immut")
        self.runner = MockCommandRunner()
        self.adapter = RemoteSshTargetAdapter(host="target.test", command_runner=self.runner)
        self.adapter.set_budget_tracker(self.tracker)

    def test_19_invocation_and_batch_records_are_frozen(self):
        """RemoteInvocationRecord, BatchSliceSpec, BatchReadRecord instances are completely frozen."""
        inv = self.tracker.record_invocation_started("inv_f1", "cmd", ["cr_f1"])
        with self.assertRaises((dataclasses.FrozenInstanceError, AttributeError)):
            inv.outcome = "MUTATED"  # type: ignore

        slice_spec = BatchSliceSpec(
            slice_index=0,
            address=0x1000,
            requested_size=64,
            physical_read_id="cr_f1",
            physical_consumption_id="cons_f1",
        )
        with self.assertRaises((dataclasses.FrozenInstanceError, AttributeError)):
            slice_spec.completion_status = "MUTATED"  # type: ignore

        batch_rec = self.tracker.register_batch_contract(
            "b_f1", "inv_f1", expected_slice_count=1, slices=[slice_spec]
        )
        with self.assertRaises((dataclasses.FrozenInstanceError, AttributeError)):
            batch_rec.expected_slice_count = 99  # type: ignore

    def test_20_public_getters_return_independent_deep_copies(self):
        """get_invocation_records and get_batch_records return defensive deep copies."""
        self.tracker.record_invocation_started("inv_dc1", "cmd", ["cr_1"])
        self.tracker.register_batch_contract("b_dc1", "inv_dc1", expected_slice_count=1)

        invs = self.tracker.get_invocation_records()
        batches = self.tracker.get_batch_records()

        # Mutating dictionary copies does not affect tracker internal storage
        del invs["inv_dc1"]
        del batches["b_dc1::inv_dc1"]

        self.assertIn("inv_dc1", self.tracker.get_invocation_records())
        self.assertIn("b_dc1::inv_dc1", self.tracker.get_batch_records())

    def test_21_adapter_invocation_storage_thread_safe_under_concurrency(self):
        """Adapter-local _invocations registry handles concurrent reads and updates without racing."""
        errors: List[Exception] = []

        def worker(idx: int):
            try:
                inv_id = f"inv_thread_{idx}"
                self.adapter.run_ssh(f"echo {idx}", invocation_id=inv_id)
                recs = self.adapter.get_invocation_records()
                self.assertIn(inv_id, recs)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)
        adapter_recs = self.adapter.get_invocation_records()
        self.assertEqual(len(adapter_recs), 20)

    def test_22_reconciliation_does_not_mutate_ledger(self):
        """reconcile_ledger is strictly read-only and does not mutate active or committed ledger states."""
        adm = self.tracker.admit_read(64, profile_id="prof_p")
        cr = adm.start_child_read(target_spec={"pid": 100})
        cr.mark_started()
        cr.consume(64)
        self.tracker.commit_transaction(operation_id="op_ro", profile_id="prof_p", measured_bytes=64, reservations=[adm])

        inv_before = copy.deepcopy(self.tracker.get_invocation_records())
        batch_before = copy.deepcopy(self.tracker.get_batch_records())
        phys_before = copy.deepcopy(self.tracker.get_physical_read_records())
        tx_before = copy.deepcopy(self.tracker.get_committed_transactions())

        # Perform reconciliation
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

        inv_after = copy.deepcopy(self.tracker.get_invocation_records())
        batch_after = copy.deepcopy(self.tracker.get_batch_records())
        phys_after = copy.deepcopy(self.tracker.get_physical_read_records())
        tx_after = copy.deepcopy(self.tracker.get_committed_transactions())

        self.assertEqual(inv_before, inv_after)
        self.assertEqual(batch_before, batch_after)
        self.assertEqual(phys_before, phys_after)
        self.assertEqual(tx_before, tx_after)


class TestPhase20A3417TimestampSemantics(unittest.TestCase):
    """Section 5: Timestamp Unit Consistency & Monotonic Durations."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(session_id="test_sess_ts")
        self.runner = MockCommandRunner()
        self.adapter = RemoteSshTargetAdapter(host="target.test", command_runner=self.runner)
        self.adapter.set_budget_tracker(self.tracker)

    def test_23_timestamp_unit_consistency(self):
        """All fields named *_time_ms and *_at_ms store Unix epoch milliseconds, not seconds."""
        t_before_ms = time.time() * 1000.0 - 50.0
        adm = self.tracker.admit_read(64, profile_id="prof_ts")
        cr = adm.start_child_read(target_spec={"pid": 100})

        self.adapter.run_ssh("echo ts", admission=adm, child_read=cr)
        t_after_ms = time.time() * 1000.0 + 50.0

        inv = next(iter(self.tracker.get_invocation_records().values()))
        # Must be in epoch milliseconds (> 1.7e12)
        self.assertGreater(inv.start_time_ms, 1.7e12)
        self.assertGreater(inv.completion_time_ms, 1.7e12)
        self.assertGreaterEqual(inv.start_time_ms, t_before_ms)
        self.assertLessEqual(inv.completion_time_ms, t_after_ms)

        # Child read timestamps
        self.assertGreater(cr.created_at_ms, 1.7e12)

    def test_24_monotonic_ordering_under_concurrent_invocations(self):
        """Under concurrent execution, completion_time_ms is strictly >= start_time_ms for every invocation."""
        def worker(idx: int):
            self.adapter.run_ssh(f"echo {idx}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(15)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 15)
        for inv_id, inv in invs.items():
            self.assertIsNotNone(inv.completion_time_ms)
            self.assertGreaterEqual(
                inv.completion_time_ms,
                inv.start_time_ms,
                f"Invocation {inv_id} has completion_time_ms < start_time_ms",
            )


class TestPhase20A3417FullProvenanceGraphReconciliation(unittest.TestCase):
    """Section 6: Complete Reconciliation Across All Registries (Full Provenance Graph)."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(session_id="test_sess_graph")

    def test_25_orphan_batch_contract_detected(self):
        """Registered batch contract referencing non-existent invocation_id violates Invariant 22."""
        self.tracker.record_invocation_started("inv_valid", "cmd", [])
        self.tracker.register_batch_contract("b_orphan", "inv_phantom_missing", expected_slice_count=1)

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        self.assertFalse(recon["discrepancy_details"]["inv_22_invocation_provenance_and_orphan_detection"])
        err = "; ".join(recon["discrepancies"])
        self.assertIn("orphan batch contract", err)

    def test_26_unresolved_in_flight_invocation_detected(self):
        """Invocation remaining IN_FLIGHT after all child reads have terminated violates Invariant 22."""
        inv_id = "inv_stuck_flight"
        self.tracker.record_invocation_started(inv_id, "read", ["cr_stuck"])

        adm = self.tracker.admit_read(64, profile_id="prof_g")
        cr = adm.start_child_read(target_spec={"invocation_id": inv_id}, physical_read_id="cr_stuck")
        cr.mark_started()
        cr.consume(64)

        # Commit scope/transaction while invocation was never marked completed
        self.tracker.commit_transaction(operation_id="op_stuck", profile_id="prof_g", measured_bytes=64, reservations=[adm])

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        err = "; ".join(recon["discrepancies"])
        self.assertIn("unresolved in-flight invocation", err)

    def test_27_complete_6_stage_provenance_graph_reconciliation(self):
        """Complete 6-stage provenance graph: Batch -> Invocation -> Slices -> Consumption -> Reservation -> Transaction."""
        batch_id = "b_golden_6"
        inv_id = "inv_golden_6"
        expected_slices = 2

        adm = self.tracker.admit_read(128, profile_id="prof_g6")
        cr0 = adm.start_child_read(
            target_spec={"batch_id": batch_id, "invocation_id": inv_id, "slice_index": 0, "expected_slice_count": expected_slices, "address": 0x1000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_g6_0",
        )
        cr1 = adm.start_child_read(
            target_spec={"batch_id": batch_id, "invocation_id": inv_id, "slice_index": 1, "expected_slice_count": expected_slices, "address": 0x2000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_g6_1",
        )

        slice_specs = [
            BatchSliceSpec(0, 0x1000, 64, cr0.physical_read_id, cr0.physical_consumption_id, "OBSERVED", 64, 0),
            BatchSliceSpec(1, 0x2000, 64, cr1.physical_read_id, cr1.physical_consumption_id, "OBSERVED", 64, 0),
        ]
        self.tracker.register_batch_contract(batch_id, inv_id, expected_slices, slices=slice_specs)
        self.tracker.record_invocation_started(inv_id, "batch_io", [cr0.physical_read_id, cr1.physical_read_id], batch_id=batch_id)

        cr0.mark_started()
        cr0.consume(64)
        cr1.mark_started()
        cr1.consume(64)

        self.tracker.record_invocation_completed(inv_id, return_code=0, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_golden_6",
            profile_id="prof_g6",
            measured_bytes=128,
            reservations=[adm],
        )

        recon = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(recon["reconciled"])
        self.assertEqual(len(recon["discrepancies"]), 0)
        self.assertEqual(recon["total_measured_bytes"], 128)


class TestPhase20A3417AccountingAndProductionCallGraph(unittest.TestCase):
    """Sections 7 & 8: Accounting Semantics & Production Remote Call Graph Verification."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(session_id="test_sess_prod")
        self.runner = MockCommandRunner()
        self.adapter = RemoteSshTargetAdapter(host="remote.target", command_runner=self.runner)
        self.adapter.set_budget_tracker(self.tracker)

    def test_28_collector_failure_fallback_success_accounting_independence(self):
        """Collector failure accounts 0 bytes under collector invocation; shell fallback accounts true measured bytes."""
        slices = [(0x1000, 32), (0x2000, 32)]
        self.adapter.collector_path = "/bin/collector"
        # Simulate collector failing on invocation
        orig_runner = self.runner

        def collector_fail_then_shell(cmd_args, timeout):
            cmd_str = " ".join(cmd_args)
            if "/bin/collector" in cmd_str:
                return 127, "", "collector: command not found"
            return orig_runner(cmd_args, timeout)

        self.adapter._command_runner = collector_fail_then_shell
        res = self.adapter.read_memory_batch(1234, slices, budget_tracker=self.tracker)

        self.assertEqual(len(res), 2)
        for data, st, _ in res:
            self.assertEqual(st, "OBSERVED")
            self.assertEqual(len(data), 32)

        # 64 bytes charged exactly once (zero double-charging)
        self.assertEqual(self.tracker.metrics.bytes_read, 64)

        recon = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(recon["reconciled"])
        self.assertTrue(recon["discrepancy_details"]["inv_21_collector_fallback_provenance_separation"])

    def test_29_unknown_consumption_never_zero_after_failure(self):
        """Physical read failure with unknown output uses conservative bytes and is never zero."""
        adm = self.tracker.admit_read(64, profile_id="prof_unk")
        cr = adm.start_child_read(target_type="remote_fail")
        cr.mark_started()
        cr.mark_failed_accounted("Remote process terminated during I/O")

        self.assertEqual(cr.charged_bytes, 65536)
        self.assertEqual(cr.estimated_bytes_read, 65536)
        self.assertIsNone(cr.measured_bytes_read)

        self.tracker.commit_transaction(operation_id="op_unk", profile_id="prof_unk", estimated_bytes=65536, is_failure=True, reservations=[adm])
        recon = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(recon["reconciled"])
        self.assertTrue(recon["discrepancy_details"]["inv_19_unknown_consumption_never_zero"])

    def test_30_production_callgraph_all_endpoints(self):
        """Verifies invocation tracking and provenance across all remote adapter production endpoints."""
        pid = 1234

        # 1. check_liveness
        alive, _ = self.adapter.check_liveness(pid, budget_tracker=self.tracker)
        self.assertTrue(alive)

        # 2. get_process_identity
        ident = self.adapter.get_process_identity(pid, budget_tracker=self.tracker)
        self.assertEqual(ident["status"], "OBSERVED")

        # 3. get_process_memory_info
        mem = self.adapter.get_process_memory_info(pid, budget_tracker=self.tracker)
        self.assertEqual(mem["status"], "OBSERVED")

        # 4. get_proc_maps
        maps = self.adapter.get_proc_maps(pid, budget_tracker=self.tracker)
        self.assertGreater(len(maps), 0)

        # 5. get_threads
        threads = self.adapter.get_threads(pid, budget_tracker=self.tracker)
        self.assertGreater(len(threads), 0)

        # 6. read_memory
        data, st, _ = self.adapter.read_memory(pid, 0x1000, 32, budget_tracker=self.tracker)
        self.assertEqual(st, "OBSERVED")

        # 7. read_memory_batch
        res_batch = self.adapter.read_memory_batch(pid, [(0x1000, 32), (0x2000, 32)], budget_tracker=self.tracker)
        self.assertEqual(len(res_batch), 2)

        # 8. find_processes
        procs = self.adapter.find_processes(budget_tracker=self.tracker)

        # Reconcile complete tracker ledger
        recon = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(recon["reconciled"])


if __name__ == "__main__":
    unittest.main()
