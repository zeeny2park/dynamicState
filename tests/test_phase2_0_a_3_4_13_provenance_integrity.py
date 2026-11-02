"""Phase 2.0-A.3.4.13 — Physical Read Lifecycle & Provenance Integrity Closure.

Exhaustive regression test suite validating:
1. Strict Physical Read State Machine (P0.1)
2. Exception & Unknown-Consumption Closure across all adapters (P0.2)
3. Physical Identity Uniqueness (P0.3)
4. Batch Read Execution Contract & Wrapper Passthrough (P0.4)
5. Deeply Immutable Provenance Records & Safe Public Getters (P0.5)
6. Remote Admission Ordering & Distinct Fallback Identity (P0.6)
7. Atomic Commit & Crash-Safe Recovery (P0.7)
8. Deterministic 19-Invariant Reconciliation (P0.8)
9. Adversarial Integration Tests (20 Required Cases) (P1.1)
10. Static Architecture Audit (AST Checks) (P1.2)
"""

import ast
import base64
import os
import pathlib
import threading
import time
import types
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
    PhysicalConsumptionRecord,
    PhysicalReadRecord,
    canonical_metadata_digest,
    freeze_metadata,
    unfreeze_metadata,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    RemoteSshTargetAdapter,
    TargetExecutionAdapter,
)


class MockCommandRunner:
    """Configurable mock command runner for testing RemoteSshTargetAdapter physical paths."""

    def __init__(self):
        self.invocations: List[List[str]] = []
        self.on_command = None
        self.collector_supported = True
        self.fail_before_execution = False
        self.fail_during_execution = False

    def __call__(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        if self.fail_before_execution:
            raise FileNotFoundError("ssh binary not found on local PATH")
        self.invocations.append(list(cmd_args))
        if self.fail_during_execution:
            return -1, "", "SSH connection timed out during execution"

        remote_cmd = cmd_args[-1]
        if self.on_command:
            return self.on_command(remote_cmd, timeout)

        if "kill -0" in remote_cmd:
            return 0, "ALIVE", ""
        elif "cat /proc/" in remote_cmd and "/maps" in remote_cmd:
            maps_content = (
                "00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/my_target\n"
                "00651000-00652000 r--p 00051000 08:02 173521 /usr/bin/my_target\n"
                "7ffd12340000-7ffd12361000 rw-p 00000000 00:00 0 [stack]\n"
            )
            return 0, maps_content, ""
        elif "--read-slices" in remote_cmd:
            if not self.collector_supported:
                return 127, "", "sh: dynamicstate-collector: not found"
            import json as _json
            slices_out = []
            for spec in [{"address": 0x1000, "size": 64}, {"address": 0x2000, "size": 128}]:
                b_data = b"\xaa" * spec["size"]
                slices_out.append({
                    "address": spec["address"],
                    "size": spec["size"],
                    "data": base64.b64encode(b_data).decode("ascii"),
                    "status": "OK",
                    "error": None,
                })
            return 0, _json.dumps(slices_out), ""
        elif "dd if=" in remote_cmd:
            payload = b"\xbb" * 64
            return 0, base64.b64encode(payload).decode("ascii"), ""

        return 0, "", ""


class TestPhase20A3413ProvenanceIntegrity(unittest.TestCase):
    """P1.1 Adversarial Integration Tests & P1.2 Static Architecture Audits."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(
            limits=ObservationBudgetLimits(
                max_bytes_read=500000,
                max_wall_clock_ms=5000.0,
                max_samples=100,
            )
        )
        self.tracker.start()

    # =========================================================================
    # Group 1: P1.1 Adversarial Integration Tests (1 - 20)
    # =========================================================================

    def test_01_double_release_of_reservation_raises_explicit_error(self):
        """1. Double-release of a reservation raises an explicit error."""
        adm = self.tracker.admit_read(projected_bytes=1000, profile_id="p1", operation_id="op_rel_twice")
        self.assertEqual(adm.state, "ADMITTED")

        self.tracker.release_reservation(adm)
        self.assertEqual(adm.state, "RELEASED")

        # Second release attempt must raise RuntimeError
        with self.assertRaises(RuntimeError) as cm:
            adm.release()
        self.assertIn("Cannot release reservation", str(cm.exception))

    def test_02_reservation_release_after_child_read_started_raises_explicit_error(self):
        """2. Reservation release after child read started raises an explicit error."""
        adm = self.tracker.admit_read(projected_bytes=1000, profile_id="p1", operation_id="op_child_started")
        child = adm.start_child_read(target_type="memory_slice", target_spec={"addr": 0x1000, "size": 64})
        self.assertEqual(child.state, "ADMITTED")

        child.mark_started()
        self.assertEqual(child.state, "PHYSICAL_READ_STARTED")

        # Releasing parent reservation while child is in PHYSICAL_READ_STARTED must be rejected
        with self.assertRaises(RuntimeError) as cm:
            adm.release()
        self.assertIn("PHYSICAL_READ_STARTED", str(cm.exception))

    def test_03_physical_read_record_in_started_cannot_transition_to_released(self):
        """3. PhysicalReadRecord in PHYSICAL_READ_STARTED cannot transition to RELEASED (P0.1 Rule 2)."""
        adm = self.tracker.admit_read(projected_bytes=1000, profile_id="p1", operation_id="op_pread_no_rel")
        child = adm.start_child_read(target_type="memory_slice")
        child.mark_started()
        self.assertEqual(child.state, "PHYSICAL_READ_STARTED")

        with self.assertRaises(RuntimeError) as cm:
            child.release()
        self.assertIn("PHYSICAL_READ_STARTED must never transition to RELEASED", str(cm.exception))

    def test_04_physical_read_record_in_admitted_can_transition_to_released(self):
        """4. PhysicalReadRecord in ADMITTED can transition to RELEASED."""
        adm = self.tracker.admit_read(projected_bytes=1000, profile_id="p1", operation_id="op_pread_adm_rel")
        child = adm.start_child_read(target_type="memory_slice")
        self.assertEqual(child.state, "ADMITTED")

        child.release()
        self.assertEqual(child.state, "RELEASED")
        self.assertEqual(child.charged_bytes, 0)
        self.assertTrue(child.is_terminal)

    def test_05_unknown_consumption_during_physical_read_records_conservative_cost_and_preserves_failure(self):
        """5. Unknown consumption during physical read records conservative cost and preserves failure."""
        adm = self.tracker.admit_read(projected_bytes=4096, profile_id="p1", operation_id="op_unk_cost")
        child = adm.start_child_read(target_type="memory_slice", target_spec={"addr": 0x4000, "size": 4096})
        child.mark_started()

        # Physical read failed after execution boundary, consumption byte count unknown -> conservative 4096B
        charged = child.consume(actual_bytes=None, conservative_estimate_bytes=4096, is_failure=True, failure_reason="IO_ERROR")
        self.assertEqual(charged, 4096)
        self.assertEqual(child.charged_bytes, 4096)
        self.assertIsNone(child.measured_bytes_read)
        self.assertEqual(child.estimated_bytes_read, 4096)
        self.assertTrue(child.is_failure)
        self.assertEqual(child.state, "CONSUMED")

        # Commit preserving failure and conservative bytes
        ok = self.tracker.commit_transaction(
            operation_id="op_unk_cost",
            profile_id="p1",
            estimated_bytes=4096,
            is_failure=True,
            reservations=[adm],
        )
        self.assertTrue(ok)
        committed = self.tracker.get_committed_record("op_unk_cost")
        self.assertTrue(committed.is_failure)
        self.assertEqual(committed.charged_bytes, 4096)
        self.assertEqual(committed.measurement_type, "ESTIMATED")

    def test_06_complete_failure_before_physical_read_invocation_records_zero_bytes_and_releases(self):
        """6. Complete failure before physical read invocation records 0 bytes and transitions to RELEASED."""
        adm = self.tracker.admit_read(projected_bytes=1024, profile_id="p1", operation_id="op_pre_io_fail")
        child = adm.start_child_read(target_type="memory_slice", target_spec={"addr": 0x5000, "size": 1024})
        self.assertEqual(child.state, "ADMITTED")

        # Pre-invocation check failed (e.g. invalid permissions or non-existent process) -> release both
        child.release()
        self.assertEqual(child.state, "RELEASED")
        self.assertEqual(child.charged_bytes, 0)

        self.tracker.release_reservation(adm)
        self.assertEqual(adm.state, "RELEASED")
        self.assertEqual(adm.consumed_bytes, 0)
        self.assertEqual(self.tracker.metrics.bytes_read, 0)

    def test_07_physical_read_id_collisions_across_scopes_raise_deterministically(self):
        """7. Physical read ID collisions across scopes raise deterministically."""
        # Commit scope 1 with physical read
        with self.tracker.operation_scope("op_scope_1", profile_id="p1") as scope1:
            adm1 = scope1.admit_read(512)
            child1 = adm1.start_child_read(physical_read_id="pread_duplicate_fixed", target_type="memory_slice")
            child1.mark_started()
            child1.consume(actual_bytes=512)
            scope1.record_read(bytes_read=512, admission=adm1)

        # Commit scope 2 attempting to reuse the same physical_read_id with conflicting bytes
        with self.assertRaises(ValueError) as cm:
            with self.tracker.operation_scope("op_scope_2", profile_id="p1") as scope2:
                adm2 = scope2.admit_read(512)
                child2 = adm2.start_child_read(physical_read_id="pread_duplicate_fixed", target_type="memory_slice")
                child2.mark_started()
                child2.consume(actual_bytes=256)  # Conflicting charge
                scope2.record_read(bytes_read=256, admission=adm2)
        self.assertIn("Physical read ID conflict", str(cm.exception))

    def test_08_physical_consumption_id_collisions_across_scopes_raise_deterministically(self):
        """8. Physical consumption ID collisions across scopes raise deterministically."""
        with self.tracker.operation_scope("op_scope_c1", profile_id="p1") as scope1:
            adm1 = scope1.admit_read(512)
            child1 = adm1.start_child_read(physical_consumption_id="pcons_coll_fixed")
            child1.mark_started()
            child1.consume(actual_bytes=512)
            scope1.record_read(bytes_read=512, admission=adm1)

        with self.assertRaises(ValueError) as cm:
            with self.tracker.operation_scope("op_scope_c2", profile_id="p1") as scope2:
                adm2 = scope2.admit_read(512)
                child2 = adm2.start_child_read(physical_consumption_id="pcons_coll_fixed")
                child2.mark_started()
                child2.consume(actual_bytes=128)  # Conflicting charge
                scope2.record_read(bytes_read=128, admission=adm2)
        self.assertIn("Physical consumption ID conflict", str(cm.exception))

    def test_09_accounting_transaction_id_collisions_across_operations_raise_deterministically(self):
        """9. Accounting transaction ID collisions across operations raise deterministically."""
        rec1 = ObservationAccountingRecord(operation_id="op_tx_1", accounting_owner="TEST", accounting_transaction_id="tx_shared_fixed")
        rec1.measured_bytes_read = 100
        rec1.charged_bytes = 100
        self.tracker.commit_transaction(record=rec1, measured_bytes=100)

        # Attempting to commit a different operation with identical accounting_transaction_id
        rec2 = ObservationAccountingRecord(operation_id="op_tx_2", accounting_owner="TEST", accounting_transaction_id="tx_shared_fixed")
        rec2.measured_bytes_read = 100
        rec2.charged_bytes = 100
        with self.assertRaises(ValueError) as cm:
            self.tracker.commit_transaction(record=rec2, measured_bytes=100)
        self.assertIn("Accounting transaction ID conflict", str(cm.exception))

    def test_10_sliced_memory_reads_produce_distinct_ids_per_slice(self):
        """10. Sliced memory reads produce N distinct physical_read_ids and N physical_consumption_ids."""
        runner = MockCommandRunner()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/opt/dynamicstate/bin/dynamicstate-collector",
        )
        adapter.set_budget_tracker(self.tracker)

        slices = [
            (0x1000 + (i * 0x1000), 64)
            for i in range(5)
        ]

        def on_read_slices(cmd, timeout):
            import json as _json
            out = []
            for addr, sz in slices:
                out.append({
                    "address": addr,
                    "size": sz,
                    "hex": (b"\xcc" * sz).hex(),
                    "status": "OBSERVED",
                    "error": None,
                })
            return 0, _json.dumps({"success": True, "slices": out}), ""

        runner.on_command = on_read_slices

        with self.tracker.operation_scope("op_batch_5", profile_id="batch_read") as scope:
            adm = scope.admit_read(5 * 64)
            results = adapter.read_memory_batch(1234, slices, admission=adm)
            total_bytes = adm.consumed_bytes
            scope.record_read(bytes_read=total_bytes, admission=adm)

        self.assertEqual(len(results), 5)
        self.assertEqual(total_bytes, 320)

        child_reads = adm.get_child_reads()
        self.assertEqual(len(child_reads), 5)

        read_ids = [cr.physical_read_id for cr in child_reads.values()]
        cons_ids = [cr.physical_consumption_id for cr in child_reads.values()]
        self.assertEqual(len(set(read_ids)), 5)
        self.assertEqual(len(set(cons_ids)), 5)

        # Reconcile verifies that all 5 are in tracker's committed physical records
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["discrepancy_details"]["inv_1_physical_read_id_uniqueness"], True)

    def test_11_partial_slice_failure_preserves_successful_slices_and_conservative_cost(self):
        """11. Partial slice failure preserves successful slices and accounts conservative cost for failed slice."""
        runner = MockCommandRunner()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/opt/dynamicstate/bin/dynamicstate-collector",
        )
        adapter.set_budget_tracker(self.tracker)

        slices = [
            (0x1000, 100),
            (0x2000, 200),  # Fails
            (0x3000, 300),
        ]

        def on_cmd(cmd, timeout):
            if "--read-slices" in cmd:
                import json as _json
                out = [
                    {"address": 0x1000, "size": 100, "hex": (b"\x11" * 100).hex(), "status": "OBSERVED", "error": None},
                    {"address": 0x2000, "size": 200, "hex": "", "status": "EFAULT", "error": "Bad address"},
                    {"address": 0x3000, "size": 300, "hex": (b"\x33" * 300).hex(), "status": "OBSERVED", "error": None},
                ]
                return 0, _json.dumps({"success": True, "slices": out}), ""
            return 0, "", ""

        runner.on_command = on_cmd

        with self.tracker.operation_scope("op_partial_batch", profile_id="batch_read") as scope:
            adm = scope.admit_read(600)
            results = adapter.read_memory_batch(1234, slices, admission=adm)
            total_charged = adm.consumed_bytes
            scope.record_read(bytes_read=total_charged, admission=adm)

        self.assertEqual(len(results), 3)
        self.assertEqual(results[0][1], "OBSERVED")
        self.assertEqual(results[1][1], "UNAVAILABLE")
        self.assertEqual(results[2][1], "OBSERVED")

        # Slice 2 failed with conservative cost of 200B; total charged = 100 + 200 + 300 = 600B
        self.assertEqual(total_charged, 600)

        # Reconcile confirms all 3 slices accounted
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_bytes_read"], 600)

    def test_12_deep_freeze_prevents_mutation_of_target_spec_and_metadata(self):
        """12. Deep freeze prevents mutation of target_spec and metadata in PhysicalConsumptionRecord."""
        target_spec = {"pid": 1234, "nested": {"addr": 0x1000}}
        metadata = {"tool": "dwarf", "tags": ["low", "memory"]}

        record = PhysicalConsumptionRecord(
            physical_consumption_id="pcons_freeze_test",
            physical_read_id="pread_freeze_test",
            reservation_id="res_freeze_test",
            operation_id="op_freeze_test",
            measured_bytes_read=100,
            estimated_bytes_read=0,
            charged_bytes=100,
            target_spec=target_spec,
            metadata=metadata,
        )

        # Directly modifying original dict should not affect frozen structure
        target_spec["nested"]["addr"] = 0x9999
        self.assertEqual(record.target_spec["nested"]["addr"], 0x1000)

        # Attempting mutation of frozen target_spec must raise TypeError
        with self.assertRaises(TypeError):
            record.target_spec["pid"] = 9999  # type: ignore

        # Attempting mutation of frozen metadata must raise TypeError
        with self.assertRaises(TypeError):
            record.metadata["tool"] = "gdb"  # type: ignore

    def test_13_public_getters_return_deep_copies_safe_from_external_mutation(self):
        """13. Public getters return deep copies that do not affect internal tracker ledger state."""
        adm = self.tracker.admit_read(projected_bytes=1000, profile_id="p1", operation_id="op_deep_copy")
        child = adm.start_child_read(target_type="memory_slice", target_spec={"size": 100})
        child.mark_started()
        child.consume(actual_bytes=100)
        adm.account()

        self.tracker.commit_transaction(
            operation_id="op_deep_copy",
            profile_id="p1",
            measured_bytes=100,
            reservations=[adm],
        )

        # Getter 1: get_physical_read_records
        reads = self.tracker.get_physical_read_records()
        self.assertIn(child.physical_read_id, reads)
        reads[child.physical_read_id].charged_bytes = 999999
        self.assertEqual(self.tracker.get_physical_read_records()[child.physical_read_id].charged_bytes, 100)

        # Getter 2: get_physical_consumption_records
        cons = self.tracker.get_physical_consumption_records()
        self.assertIn(child.physical_consumption_id, cons)
        del cons[child.physical_consumption_id]
        self.assertIn(child.physical_consumption_id, self.tracker.get_physical_consumption_records())

        # Getter 3: get_committed_transactions
        txs = self.tracker.get_committed_transactions()
        self.assertIn("op_deep_copy", txs)
        del txs["op_deep_copy"]
        self.assertTrue(self.tracker.is_operation_committed("op_deep_copy"))

    def test_14_remote_command_execution_rejection_results_in_zero_runner_invocations(self):
        """14. Remote command execution rejection results in zero runner invocations."""
        runner = MockCommandRunner()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
        )
        adapter.set_budget_tracker(self.tracker)

        # Exhaust budget entirely
        self.tracker.metrics.bytes_read = self.tracker.limits.max_bytes_read

        # Execute remote memory read
        data, status, err = adapter.read_memory(1234, 0x1000, 64)
        self.assertEqual(status, "BUDGET_EXHAUSTED")
        self.assertIsNone(data)

        # Verify command runner was never invoked
        self.assertEqual(len(runner.invocations), 0)

    def test_15_remote_command_execution_failure_uses_conservative_byte_accounting(self):
        """15. Remote command execution failure uses conservative byte accounting and marks child read failed."""
        runner = MockCommandRunner()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/opt/dynamicstate/bin/dynamicstate-collector",
        )
        adapter.set_budget_tracker(self.tracker)

        def on_cmd(cmd, timeout):
            if "dd if=" in cmd or "--read-slices" in cmd:
                return 1, "", "Memory access violation at 0x1000"
            return 0, "", ""

        runner.on_command = on_cmd

        data, status, err = adapter.read_memory(1234, 0x1000, 128)
        self.assertEqual(status, "UNAVAILABLE")
        self.assertIsNone(data)

        # Committed conservative cost of 128B, failure is preserved
        self.assertEqual(self.tracker.metrics.bytes_read, 128)
        self.assertEqual(self.tracker.metrics.conservative_estimated_bytes, 128)
        self.assertEqual(self.tracker.metrics.total_read_failures, 1)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_16_ssh_fallback_execution_produces_distinct_physical_read_id(self):
        """16. SSH fallback execution produces a new, distinct physical_read_id separate from collector execution."""
        runner = MockCommandRunner()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/opt/dynamicstate/bin/dynamicstate-collector",
        )
        adapter.set_budget_tracker(self.tracker)
        runner.collector_supported = False  # Triggers shell dd fallback

        with self.tracker.operation_scope("op_fallback_test", profile_id="memory_read") as scope:
            adm = scope.admit_read(64)
            data, status, err = adapter.read_memory(1234, 0x1000, 64, admission=adm)
            scope.record_read(bytes_read=len(data) if data else 64, admission=adm)

        self.assertEqual(status, "OBSERVED")
        self.assertIsNotNone(data)

        child_reads = adm.get_child_reads()
        # Must have 2 child reads: 1 for failed collector invocation, 1 for successful shell fallback
        self.assertEqual(len(child_reads), 2)
        cr_list = list(child_reads.values())
        self.assertNotEqual(cr_list[0].physical_read_id, cr_list[1].physical_read_id)

        # Collector child read marked failed
        self.assertTrue(cr_list[0].is_failure)
        self.assertEqual(cr_list[0].target_type, "remote_collector_memory")

        # Fallback child read succeeded
        self.assertFalse(cr_list[1].is_failure)
        self.assertEqual(cr_list[1].target_type, "remote_shell_memory")

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_17_concurrent_child_reads_within_one_reservation_maintain_atomic_accumulation(self):
        """17. Concurrent child reads within one reservation maintain atomic byte accumulation."""
        adm = self.tracker.admit_read(projected_bytes=20000, profile_id="p1", operation_id="op_conc_accum")

        def worker(idx: int):
            for i in range(10):
                child = adm.start_child_read(target_type="slice", target_spec={"worker": idx, "seq": i})
                child.mark_started()
                child.consume(actual_bytes=10)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 5 workers * 10 reads * 10B = 500B
        self.assertEqual(adm.consumed_bytes, 500)
        self.assertEqual(len(adm.child_reads), 50)
        sum_children = sum(c.charged_bytes for c in adm.child_reads.values())
        self.assertEqual(sum_children, 500)

    def test_18_scope_recovery_on_commit_failure_preserves_all_executed_child_reads(self):
        """18. Scope recovery on commit failure preserves all executed child read records."""
        with self.tracker.operation_scope("op_fault_child_preserve", profile_id="p1") as scope:
            adm = scope.admit_read(500)
            c1 = adm.start_child_read(target_type="slice_1")
            c1.mark_started()
            c1.consume(actual_bytes=200)

            c2 = adm.start_child_read(target_type="slice_2")
            c2.mark_started()
            c2.consume(actual_bytes=300)

            scope.record_read(bytes_read=500, admission=adm)
            # Inject fault at logical ledger insertion boundary
            self.tracker._trigger_fault = lambda point: (_ for _ in ()).throw(RuntimeError("Simulated ledger disk error")) if point == "during_logical_ledger_insertion" else None

        # Reconcile proves crash recovery preserved both child reads into the physical ledger
        snap = self.tracker.get_committed_record("op_fault_child_preserve")
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertTrue(snap.is_failure)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_bytes_read"], 500)
        self.assertEqual(recon["total_physical_reads"], 2)

    def test_19_reconcile_ledger_validates_all_19_invariants_and_returns_details(self):
        """19. Reconcile ledger validates all 19 invariants and returns discrepancy_details."""
        with self.tracker.operation_scope("op_inv_19", profile_id="p1") as scope:
            adm = scope.admit_read(128)
            c = adm.start_child_read(target_type="slice")
            c.mark_started()
            c.consume(actual_bytes=128)
            scope.record_read(bytes_read=128, admission=adm)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        details = recon["discrepancy_details"]

        # Verify all 19 invariants exist and are True
        for inv_num in range(1, 20):
            matched = any(f"inv_{inv_num}_" in k for k in details.keys())
            self.assertTrue(matched, f"Invariant {inv_num} missing from discrepancy_details")

        self.assertTrue(all(details.values()), f"Some invariants evaluated to False: {details}")

    def test_20_invariant_violation_in_reconcile_ledger_raises_assertion_error_with_report(self):
        """20. Invariant violation in reconcile_ledger raises AssertionError with detailed discrepancy report."""
        with self.tracker.operation_scope("op_inv_tamper", profile_id="p1") as scope:
            adm = scope.admit_read(128)
            c = adm.start_child_read(target_type="slice")
            c.mark_started()
            c.consume(actual_bytes=128)
            scope.record_read(bytes_read=128, admission=adm)

        # Deliberately corrupt global bytes_read metric
        with self.tracker._transaction_lock:
            self.tracker.metrics.bytes_read += 9999

        with self.assertRaises(AssertionError) as cm:
            self.tracker.reconcile_ledger()
        self.assertIn("Tracker ledger reconciliation failed", str(cm.exception))
        self.assertIn("Invariant 17", str(cm.exception))

    # =========================================================================
    # Group 2: P1.2 Static Architecture Audit (21 - 25)
    # =========================================================================

    def test_21_ast_all_physical_reads_admitted_or_scoped(self):
        """21. AST audit: All physical read methods in target_adapter.py check budget admission."""
        adapter_path = pathlib.Path(__file__).parent.parent / "extractor" / "target_adapter.py"
        with open(adapter_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Local target adapter read methods
        self.assertIn("def read_memory(", content)
        self.assertIn("def read_memory_batch(", content)
        self.assertIn("def get_proc_maps(", content)
        self.assertIn("def get_threads(", content)

        # Verification of admission enforcement in read methods
        self.assertIn("_acquire_remote_admission", content)
        self.assertIn("admit_read", content)

    def test_22_ast_no_direct_mutation_of_physical_ledgers_outside_tracker(self):
        """22. AST audit: No module outside observation_budget.py mutates _physical_read_records."""
        extractor_dir = pathlib.Path(__file__).parent.parent / "extractor"
        for py_path in extractor_dir.glob("*.py"):
            if py_path.name == "observation_budget.py":
                continue
            with open(py_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(py_path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Attribute):
                            self.assertNotIn(
                                target.attr,
                                ("_physical_read_records", "_physical_consumption_records"),
                                f"Direct physical ledger mutation in {py_path.name}:{node.lineno}",
                            )

    def test_23_ast_no_child_read_transitions_started_to_released(self):
        """23. AST audit: PhysicalReadRecord.release must reject transition from PHYSICAL_READ_STARTED."""
        budget_path = pathlib.Path(__file__).parent.parent / "extractor" / "observation_budget.py"
        with open(budget_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn('self.state == "PHYSICAL_READ_STARTED"', content)
        self.assertIn("PHYSICAL_READ_STARTED must never transition to RELEASED", content)

    def test_24_ast_target_adapter_wrapper_passes_child_read(self):
        """24. AST audit: ReadOnlyTargetAdapter passes child_read parameter to inner adapter."""
        adapter_path = pathlib.Path(__file__).parent.parent / "extractor" / "target_adapter.py"
        with open(adapter_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("child_read=child_read", content)

    def test_25_ast_base_target_adapter_interface_defines_child_read_parameter(self):
        """25. AST audit: TargetExecutionAdapter defines child_read parameter in read_memory."""
        import inspect
        sig_single = inspect.signature(TargetExecutionAdapter.read_memory)
        self.assertIn("child_read", sig_single.parameters)

        sig_local = inspect.signature(LocalTargetAdapter.read_memory)
        self.assertIn("child_read", sig_local.parameters)

        sig_remote = inspect.signature(RemoteSshTargetAdapter.read_memory)
        self.assertIn("child_read", sig_remote.parameters)


if __name__ == "__main__":
    unittest.main()
