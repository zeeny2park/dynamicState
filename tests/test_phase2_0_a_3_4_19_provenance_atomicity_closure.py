"""Phase 2.0-A.3.4.19 — Provenance Validation Totality & Atomic Lifecycle Closure.

Adversarial test suite covering:
1. Workstream A (Invariant 22 Totality):
   - Empty invocation registry with orphan batch contract.
   - Empty invocation registry with physical read referencing unknown invocation.
   - Unrelated invocation + orphan batch contract.
   - Invocation referencing missing physical reads.
   - Bidirectional linkage mismatches.
   - Valid preflight rejection without physical execution.
   - Valid in-flight invocation with nonterminal physical reads.
   - Unexecuted batch contracts in ADMITTED/RELEASED states.
2. Workstream B (Atomic Temporal State Transitions):
   - Pre-validation of terminal timestamps before state mutation.
   - Atomicity and rollback on timestamp regression (PhysicalReadRecord and BudgetReservation).
   - Validation that rejected transitions leave states, timestamps, transition histories, and registries untouched.
   - BudgetReservation.mark_failed_accounted() terminal_at_ms assignment completeness.
   - Idempotency of identical terminal operations and rejection of conflicting terminal operations.
3. Workstream C (Monotonic Duration Lifecycle):
   - Monotonic start entry consumption and cleanup on successful completion (including explicit duration_ms).
   - Rejection of invalid/negative/infinite/NaN duration values before state or registry mutation.
   - Preservation of retryable in-flight state after rejected completion.
   - Monotonic regression detection failing closed.
   - Rejection of repeated invocation completion.
   - Direct construction validation of RemoteInvocationRecord.
4. Workstream D (Reconciliation & Lifecycle Closure):
   - Detection of terminal records without terminal timestamps.
   - Detection of timestamp regressions.
   - Detection of invalid transitions (e.g. PHYSICAL_READ_STARTED -> RELEASED, consumed_bytes > 0 -> RELEASED).
   - Detection of inconsistent parent/child terminal states.
   - Detection of residual monotonic tracking entries for completed invocations.
   - Full ledger reconciliation across all legitimate lifecycles.
5. Workstream E (Concurrency and Immutability):
   - Public getter snapshot isolation and deep immutability.
   - Multi-threaded concurrent terminal transitions and reconciliations.
"""

import copy
import math
import threading
import time
import unittest
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import patch

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


class TestPhase20A3419WorkstreamAInvariant22Totality(unittest.TestCase):
    """Workstream A: Invariant 22 Totality & Provenance Linkage Verification."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_01_empty_invocation_registry_with_orphan_batch_contract_triggers_invariant_22(self):
        """1. Empty invocation registry with an orphan batch contract is detected by Invariant 22."""
        self.assertEqual(len(self.tracker.get_invocation_records()), 0)

        inv_orphan = "inv_nonexistent_01"
        batch_id = "batch_orphan_01"
        read_id = "read_orphan_01"

        res = self.tracker.admit_read(100)
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={"pid": 100, "address": 0x1000, "size": 64, "invocation_id": inv_orphan},
        )
        cr.mark_started()
        cr.consume(64)

        slices = [BatchSliceSpec(slice_index=0, address=0x1000, requested_size=64, physical_read_id=read_id)]
        self.tracker.register_batch_contract(
            batch_id=batch_id,
            invocation_id=inv_orphan,
            expected_slice_count=1,
            slices=slices,
        )

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        discrepancies = report["discrepancies"]
        self.assertTrue(
            any("Invariant 22" in d and "orphan batch contract" in d and inv_orphan in d for d in discrepancies),
            f"Expected orphan batch contract discrepancy in: {discrepancies}",
        )

    def test_02_empty_invocation_registry_with_orphan_physical_read_triggers_invariant_22(self):
        """2. Empty invocation registry with a physical read referencing an unknown invocation is detected."""
        self.assertEqual(len(self.tracker.get_invocation_records()), 0)

        res = self.tracker.admit_read(100)
        read_id = "pread_orphan_02"
        inv_unknown = "inv_unknown_02"
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={"pid": 101, "address": 0x2000, "size": 32, "invocation_id": inv_unknown},
        )
        cr.mark_started()

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        discrepancies = report["discrepancies"]
        self.assertTrue(
            any("Invariant 22" in d and "references unknown invocation_id" in d and inv_unknown in d for d in discrepancies),
            f"Expected unknown invocation discrepancy in: {discrepancies}",
        )

    def test_03_nonempty_invocation_registry_with_orphan_batch_contract_triggers_invariant_22(self):
        """3. One unrelated invocation plus an orphan batch contract is detected."""
        inv_valid = "inv_valid_03"
        read_valid = "pread_valid_03"
        self.tracker.record_invocation_started(invocation_id=inv_valid, command_type="shell", physical_read_ids=[read_valid])

        res_v = self.tracker.admit_read(100)
        cr_v = res_v.start_child_read(
            physical_read_id=read_valid,
            target_spec={"pid": 102, "address": 0x2500, "size": 64, "invocation_id": inv_valid},
        )
        cr_v.mark_started()
        self.tracker.record_invocation_completed(invocation_id=inv_valid, return_code=0)

        inv_orphan = "inv_orphan_03"
        read_id = "read_orphan_03"
        res = self.tracker.admit_read(100)
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={"pid": 102, "address": 0x3000, "size": 64, "invocation_id": inv_valid},
        )
        cr.mark_started()
        cr.consume(64)

        slices = [BatchSliceSpec(slice_index=0, address=0x3000, requested_size=64, physical_read_id=read_id)]
        self.tracker.register_batch_contract(
            batch_id="batch_03",
            invocation_id=inv_orphan,
            expected_slice_count=1,
            slices=slices,
        )

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        discrepancies = report["discrepancies"]
        self.assertTrue(
            any("Invariant 22" in d and "orphan batch contract" in d and inv_orphan in d for d in discrepancies),
            f"Expected orphan batch contract discrepancy in: {discrepancies}",
        )

    def test_04_invocation_referencing_missing_physical_reads_triggers_invariant_22(self):
        """4. Invocation referencing missing physical reads is detected by Invariant 22."""
        inv_id = "inv_missing_reads_04"
        missing_read_id = "pread_does_not_exist_04"

        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="shell",
            physical_read_ids=[missing_read_id],
        )
        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0)

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        discrepancies = report["discrepancies"]
        self.assertTrue(
            any("Invariant 22" in d and "references non-existent physical_read_id" in d and missing_read_id in d for d in discrepancies),
            f"Expected missing physical read discrepancy in: {discrepancies}",
        )

    def test_05_bidirectional_linkage_mismatch_invocation_references_read_with_different_invocation(self):
        """5. Invocation references read_1, but read_1 has invocation_id pointing to different invocation."""
        inv_a = "inv_a_05"
        inv_b = "inv_b_05"
        read_id = "pread_05"

        res = self.tracker.admit_read(100)
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={"pid": 103, "address": 0x4000, "size": 32, "invocation_id": inv_b},
        )
        cr.mark_started()

        self.tracker.record_invocation_started(invocation_id=inv_a, command_type="shell", physical_read_ids=[read_id])
        self.tracker.record_invocation_completed(invocation_id=inv_a, return_code=0)

        self.tracker.record_invocation_started(invocation_id=inv_b, command_type="shell", physical_read_ids=[])
        self.tracker.record_invocation_completed(invocation_id=inv_b, return_code=0)

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        discrepancies = report["discrepancies"]
        self.assertTrue(
            any("Invariant 22" in d and "invocation linkage mismatch" in d for d in discrepancies),
            f"Expected bidirectional linkage mismatch in: {discrepancies}",
        )

    def test_06_bidirectional_linkage_mismatch_read_points_to_invocation_not_listing_it(self):
        """6. Read references inv_a, but inv_a.physical_read_ids does not list read."""
        inv_a = "inv_a_06"
        read_id = "pread_06"

        res = self.tracker.admit_read(100)
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={"pid": 104, "address": 0x5000, "size": 32, "invocation_id": inv_a},
        )
        cr.mark_started()

        self.tracker.record_invocation_started(invocation_id=inv_a, command_type="shell", physical_read_ids=[])
        self.tracker.record_invocation_completed(invocation_id=inv_a, return_code=0)

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        discrepancies = report["discrepancies"]
        self.assertTrue(
            any("Invariant 22" in d and "is not listed in invocation" in d for d in discrepancies),
            f"Expected read not listed in invocation discrepancy in: {discrepancies}",
        )

    def test_07_valid_preflight_rejection_without_physical_execution_passes_invariant_22(self):
        """7. Valid preflight rejection (outcome='PREFLIGHT_REJECTED') without physical execution passes."""
        inv_pf = "inv_preflight_07"
        read_id = "pread_07"

        res = self.tracker.admit_read(100)
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={
                "pid": 105,
                "address": 0x6000,
                "size": 64,
                "invocation_id": inv_pf,
                "batch_id": "batch_07",
                "slice_index": 0,
                "expected_slice_count": 1,
                "completion_status": "NOT_EXECUTED",
            },
        )
        cr.release()
        res.release()

        slices = [BatchSliceSpec(slice_index=0, address=0x6000, requested_size=64, physical_read_id=read_id)]
        self.tracker.register_batch_contract(
            batch_id="batch_07",
            invocation_id=inv_pf,
            expected_slice_count=1,
            slices=slices,
        )

        self.tracker.record_invocation_started(invocation_id=inv_pf, command_type="shell", physical_read_ids=[read_id])
        self.tracker.record_invocation_completed(
            invocation_id=inv_pf,
            return_code=-2,
            outcome="PREFLIGHT_REJECTED",
        )

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])
        self.assertEqual(len(report["discrepancies"]), 0)

    def test_08_valid_in_flight_invocation_with_nonterminal_physical_reads_passes(self):
        """8. Valid in-flight invocation with active non-terminal physical read passes reconciliation."""
        inv_inflight = "inv_inflight_08"
        read_id = "pread_08"

        res = self.tracker.admit_read(100)
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={"pid": 106, "address": 0x7000, "size": 64, "invocation_id": inv_inflight},
        )
        cr.mark_started()

        self.tracker.record_invocation_started(
            invocation_id=inv_inflight,
            command_type="shell",
            physical_read_ids=[read_id],
        )

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])
        self.assertEqual(len(report["discrepancies"]), 0)

    def test_09_unexecuted_batch_contract_reads_in_admitted_released_pass_invariant_22(self):
        """9. Batch contract whose reads definitely never crossed physical boundary (ADMITTED/RELEASED) is permitted."""
        inv_unreached = "inv_not_executed_09"
        read_id = "pread_09"

        res = self.tracker.admit_read(100)
        cr = res.start_child_read(
            physical_read_id=read_id,
            target_spec={
                "pid": 107,
                "address": 0x8000,
                "size": 64,
                "batch_id": "batch_09",
                "slice_index": 0,
                "expected_slice_count": 1,
                "invocation_id": inv_unreached,
                "completion_status": "NOT_EXECUTED",
            },
        )
        cr.release()
        res.release()

        slices = [BatchSliceSpec(slice_index=0, address=0x8000, requested_size=64, physical_read_id=read_id)]
        self.tracker.register_batch_contract(
            batch_id="batch_09",
            invocation_id=inv_unreached,
            expected_slice_count=1,
            slices=slices,
        )

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])


class TestPhase20A3419WorkstreamBAtomicTemporalTransitions(unittest.TestCase):
    """Workstream B: Atomic Temporal State Transitions & State Immutability on Rejection."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_10_physical_read_release_timestamp_regression_rolls_back_atomically(self):
        """10. PhysicalReadRecord.release() rolls back atomically if terminal timestamp regresses."""
        t_base = 1700000000000.0
        read = PhysicalReadRecord(
            physical_read_id="pread_10",
            reservation_id="res_10",
            physical_consumption_id="pcons_10",
            created_at_ms=t_base,
            target_spec={"pid": 10},
        )
        self.assertEqual(read.state, "ADMITTED")
        self.assertIsNone(read.terminal_at_ms)
        self.assertEqual(read.transition_history, ["ADMITTED"])

        t_regress = (t_base - 1000.0) / 1000.0
        with patch("time.time", return_value=t_regress):
            with self.assertRaises(ValueError) as cm:
                read.release()
            self.assertIn("regression", str(cm.exception).lower())

        self.assertEqual(read.state, "ADMITTED")
        self.assertIsNone(read.terminal_at_ms)
        self.assertEqual(read.transition_history, ["ADMITTED"])

    def test_11_physical_read_account_timestamp_regression_rolls_back_atomically(self):
        """11. PhysicalReadRecord.account() rolls back atomically if terminal timestamp regresses."""
        t_base = 1700000000000.0
        read = PhysicalReadRecord(
            physical_read_id="pread_11",
            reservation_id="res_11",
            physical_consumption_id="pcons_11",
            created_at_ms=t_base,
            target_spec={"pid": 11},
        )
        read.mark_started()
        read.consume(64)
        self.assertEqual(read.state, "CONSUMED")
        self.assertIsNone(read.terminal_at_ms)
        expected_history = ["ADMITTED", "PHYSICAL_READ_STARTED", "CONSUMED"]
        self.assertEqual(read.transition_history, expected_history)

        t_regress = (t_base - 500.0) / 1000.0
        with patch("time.time", return_value=t_regress):
            with self.assertRaises(ValueError) as cm:
                read.account()
            self.assertIn("regression", str(cm.exception).lower())

        self.assertEqual(read.state, "CONSUMED")
        self.assertIsNone(read.terminal_at_ms)
        self.assertEqual(read.transition_history, expected_history)

    def test_12_physical_read_mark_failed_accounted_timestamp_regression_rolls_back_atomically(self):
        """12. PhysicalReadRecord.mark_failed_accounted() rolls back atomically on timestamp regression."""
        t_base = 1700000000000.0
        read = PhysicalReadRecord(
            physical_read_id="pread_12",
            reservation_id="res_12",
            physical_consumption_id="pcons_12",
            created_at_ms=t_base,
            target_spec={"pid": 12},
        )
        read.mark_started()
        self.assertEqual(read.state, "PHYSICAL_READ_STARTED")
        self.assertIsNone(read.terminal_at_ms)
        self.assertIsNone(read.failure_reason)
        expected_history = ["ADMITTED", "PHYSICAL_READ_STARTED"]
        self.assertEqual(read.transition_history, expected_history)

        t_regress = (t_base - 200.0) / 1000.0
        with patch("time.time", return_value=t_regress):
            with self.assertRaises(ValueError) as cm:
                read.mark_failed_accounted(failure_reason="hardware timeout")
            self.assertIn("regression", str(cm.exception).lower())

        self.assertEqual(read.state, "PHYSICAL_READ_STARTED")
        self.assertIsNone(read.terminal_at_ms)
        self.assertIsNone(read.failure_reason)
        self.assertEqual(read.transition_history, expected_history)

    def test_13_budget_reservation_release_timestamp_regression_rolls_back_parent_and_children(self):
        """13. BudgetReservation.release() validates timestamps before mutating parent or child reads."""
        t_base = 1700000000000.0
        res = BudgetReservation(
            reservation_id="res_13",
            operation_id="op_13",
            reserved_bytes=128,
            created_at_ms=t_base,
        )
        cr1 = res.start_child_read(physical_read_id="cr_13_1", physical_consumption_id="pcons_13_1")
        cr2 = res.start_child_read(physical_read_id="cr_13_2", physical_consumption_id="pcons_13_2")
        cr1.created_at_ms = t_base
        cr2.created_at_ms = t_base

        self.assertEqual(res.state, "ADMITTED")
        self.assertEqual(cr1.state, "ADMITTED")
        self.assertEqual(cr2.state, "ADMITTED")

        t_regress = (t_base - 100.0) / 1000.0
        with patch("time.time", return_value=t_regress):
            with self.assertRaises(ValueError) as cm:
                res.release()
            self.assertIn("regression", str(cm.exception).lower())

        self.assertEqual(res.state, "ADMITTED")
        self.assertIsNone(res.terminal_at_ms)

        self.assertEqual(cr1.state, "ADMITTED")
        self.assertIsNone(cr1.terminal_at_ms)
        self.assertEqual(cr1.transition_history, ["ADMITTED"])

        self.assertEqual(cr2.state, "ADMITTED")
        self.assertIsNone(cr2.terminal_at_ms)
        self.assertEqual(cr2.transition_history, ["ADMITTED"])

    def test_14_budget_reservation_account_timestamp_regression_rolls_back_parent_and_children(self):
        """14. BudgetReservation.account() rolls back atomically on timestamp regression."""
        t_base = 1700000000000.0
        res = BudgetReservation(
            reservation_id="res_14",
            operation_id="op_14",
            reserved_bytes=128,
            created_at_ms=t_base,
        )
        cr1 = res.start_child_read(physical_read_id="cr_14_1", physical_consumption_id="pcons_14_1")
        cr1.created_at_ms = t_base
        cr1.mark_started()
        cr1.consume(64)
        res.consumed_bytes = 64
        res.state = "CONSUMED"

        t_regress = (t_base - 50.0) / 1000.0
        with patch("time.time", return_value=t_regress):
            with self.assertRaises(ValueError) as cm:
                res.account()
            self.assertIn("regression", str(cm.exception).lower())

        self.assertEqual(res.state, "CONSUMED")
        self.assertIsNone(res.terminal_at_ms)
        self.assertEqual(cr1.state, "CONSUMED")
        self.assertIsNone(cr1.terminal_at_ms)

    def test_15_budget_reservation_finalize_timestamp_regression_rolls_back_parent_and_children(self):
        """15. BudgetReservation.finalize() rolls back atomically on timestamp regression."""
        t_base = 1700000000000.0
        res = BudgetReservation(
            reservation_id="res_15",
            operation_id="op_15",
            reserved_bytes=128,
            created_at_ms=t_base,
        )
        cr1 = res.start_child_read(physical_read_id="cr_15_1", physical_consumption_id="pcons_15_1")
        cr1.created_at_ms = t_base
        cr1.mark_started()
        cr1.consume(64)
        res.consumed_bytes = 64
        res.state = "CONSUMED"

        t_regress = (t_base - 50.0) / 1000.0
        with patch("time.time", return_value=t_regress):
            with self.assertRaises(ValueError) as cm:
                res.finalize()
            self.assertIn("regression", str(cm.exception).lower())

        self.assertEqual(res.state, "CONSUMED")
        self.assertIsNone(res.terminal_at_ms)
        self.assertEqual(cr1.state, "CONSUMED")
        self.assertIsNone(cr1.terminal_at_ms)

    def test_16_budget_reservation_mark_failed_accounted_timestamp_regression_rolls_back_atomically(self):
        """16. BudgetReservation.mark_failed_accounted() rolls back atomically on timestamp regression."""
        t_base = 1700000000000.0
        res = BudgetReservation(
            reservation_id="res_16",
            operation_id="op_16",
            reserved_bytes=128,
            created_at_ms=t_base,
        )
        cr1 = res.start_child_read(physical_read_id="cr_16_1", physical_consumption_id="pcons_16_1")
        cr1.created_at_ms = t_base
        cr1.mark_started()

        t_regress = (t_base - 50.0) / 1000.0
        with patch("time.time", return_value=t_regress):
            with self.assertRaises(ValueError) as cm:
                res.mark_failed_accounted()
            self.assertIn("regression", str(cm.exception).lower())

        self.assertEqual(res.state, "ADMITTED")
        self.assertIsNone(res.terminal_at_ms)
        self.assertEqual(cr1.state, "PHYSICAL_READ_STARTED")
        self.assertIsNone(cr1.terminal_at_ms)

    def test_17_budget_reservation_mark_failed_accounted_assigns_terminal_at_ms_on_success(self):
        """17. Workstream B fix: BudgetReservation.mark_failed_accounted() properly assigns terminal_at_ms."""
        res = self.tracker.admit_read(128)
        cr = res.start_child_read(physical_read_id="cr_17")
        cr.mark_started()

        t_before = round(time.time() * 1000.0, 3)
        res.mark_failed_accounted()
        t_after = round(time.time() * 1000.0, 3)

        self.assertEqual(res.state, "FAILED_ACCOUNTED")
        self.assertIsNotNone(res.terminal_at_ms)
        self.assertGreaterEqual(res.terminal_at_ms, t_before)
        self.assertLessEqual(res.terminal_at_ms, t_after)
        self.assertEqual(cr.state, "FAILED_ACCOUNTED")
        self.assertIsNotNone(cr.terminal_at_ms)
        self.assertAlmostEqual(cr.terminal_at_ms, res.terminal_at_ms, delta=50.0)

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])

    def test_18_idempotent_and_conflicting_terminal_transitions(self):
        """18. Verify idempotency of identical terminal transitions and rejection of conflicting ones."""
        # PhysicalReadRecord idempotency
        read = PhysicalReadRecord(
            physical_read_id="pread_18",
            reservation_id="res_18",
            physical_consumption_id="pcons_18",
            created_at_ms=1000.0,
            target_spec={"pid": 18},
        )
        read.release()
        t_rel = read.terminal_at_ms
        self.assertEqual(read.state, "RELEASED")
        read.release()
        self.assertEqual(read.state, "RELEASED")
        self.assertEqual(read.terminal_at_ms, t_rel)

        with self.assertRaises(RuntimeError):
            read.account()

        with self.assertRaises(RuntimeError):
            read.mark_failed_accounted()

        # BudgetReservation duplicate release raises RuntimeError
        res = BudgetReservation(
            reservation_id="res_18_b",
            operation_id="op_18_b",
            reserved_bytes=100,
            created_at_ms=1000.0,
        )
        res.release()
        self.assertEqual(res.state, "RELEASED")
        with self.assertRaises(RuntimeError):
            res.release()

        with self.assertRaises(RuntimeError):
            res.account()

        with self.assertRaises(RuntimeError):
            res.finalize()


class TestPhase20A3419WorkstreamCMonotonicDurationLifecycle(unittest.TestCase):
    """Workstream C: Monotonic Duration Lifecycle & Parameter Validation."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_19_successful_completion_removes_monotonic_start_entry(self):
        """19. Successful invocation completion removes its monotonic start entry exactly once."""
        inv_id = "inv_clean_19"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="shell", physical_read_ids=[])

        self.assertIn(inv_id, self.tracker._invocation_start_mono_ns)

        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0)

        self.assertNotIn(inv_id, self.tracker._invocation_start_mono_ns)

    def test_20_explicit_duration_removes_monotonic_start_entry_without_leak(self):
        """20. Explicit duration_ms also removes monotonic start entry without leakage."""
        inv_id = "inv_clean_20"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="shell", physical_read_ids=[])
        self.assertIn(inv_id, self.tracker._invocation_start_mono_ns)

        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0, duration_ms=25.5)

        self.assertNotIn(inv_id, self.tracker._invocation_start_mono_ns)
        rec = self.tracker.get_invocation_records()[inv_id]
        self.assertEqual(rec.duration_ms, 25.5)

    def test_21_invalid_negative_duration_rejected_before_state_mutation(self):
        """21. Negative duration_ms is rejected before state mutation; preserves retryable state."""
        inv_id = "inv_neg_21"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="shell", physical_read_ids=[])
        self.assertIn(inv_id, self.tracker._invocation_start_mono_ns)

        with self.assertRaises(ValueError) as cm:
            self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0, duration_ms=-10.0)
        self.assertIn("duration_ms", str(cm.exception).lower())

        rec = self.tracker.get_invocation_records()[inv_id]
        self.assertEqual(rec.outcome, "IN_FLIGHT")
        self.assertIsNone(rec.completion_time_ms)
        self.assertIsNone(rec.duration_ms)

        self.assertIn(inv_id, self.tracker._invocation_start_mono_ns)

    def test_22_invalid_nan_and_inf_duration_rejected_before_state_mutation(self):
        """22. NaN and Inf duration values are rejected before state mutation."""
        inv_id = "inv_nan_22"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="shell", physical_read_ids=[])

        for bad_val in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError) as cm:
                self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0, duration_ms=bad_val)
            self.assertIn("duration_ms", str(cm.exception).lower())
            rec = self.tracker.get_invocation_records()[inv_id]
            self.assertEqual(rec.outcome, "IN_FLIGHT")
            self.assertIn(inv_id, self.tracker._invocation_start_mono_ns)

    def test_23_retry_completion_succeeds_after_rejected_invalid_duration(self):
        """23. In-flight invocation preserves retryable state and can complete successfully on retry."""
        inv_id = "inv_retry_23"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="shell", physical_read_ids=[])

        with self.assertRaises(ValueError):
            self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0, duration_ms=-5.0)

        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0, duration_ms=15.0)

        rec = self.tracker.get_invocation_records()[inv_id]
        self.assertEqual(rec.outcome, "COMPLETED")
        self.assertEqual(rec.duration_ms, 15.0)
        self.assertNotIn(inv_id, self.tracker._invocation_start_mono_ns)

    def test_24_monotonic_regression_fails_closed_preserving_in_flight_state(self):
        """24. Monotonic clock regression fails closed with ValueError and preserves retryable state."""
        inv_id = "inv_mono_regress_24"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="shell", physical_read_ids=[])
        t_start_mono = self.tracker._invocation_start_mono_ns[inv_id]

        regressed_mono = t_start_mono - 10000000
        with patch("time.monotonic_ns", return_value=regressed_mono):
            with self.assertRaises(ValueError) as cm:
                self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0)
            self.assertIn("regressed", str(cm.exception).lower())

        rec = self.tracker.get_invocation_records()[inv_id]
        self.assertEqual(rec.outcome, "IN_FLIGHT")
        self.assertIn(inv_id, self.tracker._invocation_start_mono_ns)

    def test_25_repeated_completion_remains_rejected(self):
        """25. Repeated completion attempts on already completed invocation remain rejected."""
        inv_id = "inv_double_comp_25"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="shell", physical_read_ids=[])
        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0)

        with self.assertRaises(RuntimeError) as cm:
            self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0)
        self.assertIn("already terminal", str(cm.exception).lower())

    def test_26_remote_invocation_record_direct_construction_validation(self):
        """26. RemoteInvocationRecord directly validates duration and timestamps on construction."""
        with self.assertRaises(ValueError):
            RemoteInvocationRecord(invocation_id="i1", command_type="sh", physical_read_ids=(), start_time_ms=-100.0)

        with self.assertRaises(ValueError):
            RemoteInvocationRecord(invocation_id="i2", command_type="sh", physical_read_ids=(), start_time_ms=float("nan"))

        with self.assertRaises(ValueError):
            RemoteInvocationRecord(
                invocation_id="i3",
                command_type="sh",
                physical_read_ids=(),
                start_time_ms=1000.0,
                completion_time_ms=500.0,
            )

        with self.assertRaises(ValueError):
            RemoteInvocationRecord(
                invocation_id="i4",
                command_type="sh",
                physical_read_ids=(),
                start_time_ms=1000.0,
                completion_time_ms=1500.0,
                duration_ms=-1.0,
            )

        with self.assertRaises(ValueError):
            RemoteInvocationRecord(
                invocation_id="i5",
                command_type="sh",
                physical_read_ids=(),
                start_time_ms=1000.0,
                completion_time_ms=1500.0,
                duration_ms=float("nan"),
            )

        rec = RemoteInvocationRecord(
            invocation_id="i6",
            command_type="sh",
            physical_read_ids=(),
            start_time_ms=1000.0,
            completion_time_ms=1050.0,
            duration_ms=50.0,
        )
        self.assertEqual(rec.duration_ms, 50.0)
        self.assertEqual(rec.completion_time_ms, 1050.0)


class TestPhase20A3419WorkstreamDReconciliationAndLifecycleClosure(unittest.TestCase):
    """Workstream D: Reconciliation & Lifecycle Closure Detection."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_27_reconciliation_detects_terminal_reservation_missing_terminal_at_ms(self):
        """27. Reconcile ledger flags terminal reservation with terminal_at_ms = None."""
        res = self.tracker.admit_read(100)
        res.state = "RELEASED"
        res.terminal_at_ms = None

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("terminal timestamp completeness" in d for d in report["discrepancies"]),
            f"Expected terminal timestamp completeness violation in: {report['discrepancies']}",
        )

    def test_28_reconciliation_detects_reservation_terminal_timestamp_regression(self):
        """28. Reconcile ledger flags reservation with terminal_at_ms < created_at_ms."""
        res = self.tracker.admit_read(100)
        res.state = "RELEASED"
        res.terminal_at_ms = res.created_at_ms - 500.0

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("timestamp regression" in d and "reservation" in d for d in report["discrepancies"]),
            f"Expected timestamp regression violation in: {report['discrepancies']}",
        )

    def test_29_reconciliation_detects_released_reservation_with_consumed_bytes(self):
        """29. Reconcile ledger flags reservation that has consumed bytes > 0 but is RELEASED."""
        res = self.tracker.admit_read(100)
        res.state = "RELEASED"
        res.consumed_bytes = 64
        res.terminal_at_ms = res.created_at_ms + 10.0

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("has consumed 64B but is RELEASED" in d for d in report["discrepancies"]),
            f"Expected invalid transition discrepancy in: {report['discrepancies']}",
        )

    def test_30_reconciliation_detects_accounted_reservation_with_nonterminal_child(self):
        """30. Reconcile ledger flags accounted reservation having a child read in non-terminal state."""
        res = self.tracker.admit_read(100)
        cr = res.start_child_read(physical_read_id="cr_nonterm_30", target_spec={"pid": 30})
        cr.state = "PHYSICAL_READ_STARTED"

        res.state = "ACCOUNTED"
        res.terminal_at_ms = res.created_at_ms + 20.0

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("parent/child consistency" in d and "non-terminal" in d for d in report["discrepancies"]),
            f"Expected parent/child consistency discrepancy in: {report['discrepancies']}",
        )

    def test_31_reconciliation_detects_released_reservation_with_nonreleased_child(self):
        """31. Reconcile ledger flags released reservation having a child read not in RELEASED."""
        res = self.tracker.admit_read(100)
        cr = res.start_child_read(physical_read_id="cr_nonrel_31", target_spec={"pid": 31})
        cr.state = "CONSUMED"

        res.state = "RELEASED"
        res.terminal_at_ms = res.created_at_ms + 10.0

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("has non-released child read" in d for d in report["discrepancies"]),
            f"Expected parent/child released consistency discrepancy in: {report['discrepancies']}",
        )

    def test_32_reconciliation_detects_terminal_read_missing_terminal_at_ms(self):
        """32. Reconcile ledger flags terminal physical read missing terminal_at_ms."""
        res = self.tracker.admit_read(100)
        cr = res.start_child_read(physical_read_id="cr_32", target_spec={"pid": 32})
        cr.state = "ACCOUNTED"
        cr.terminal_at_ms = None

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("terminal read 'cr_32' in state 'ACCOUNTED' has no terminal_at_ms" in d for d in report["discrepancies"]),
            f"Expected terminal read missing terminal_at_ms in: {report['discrepancies']}",
        )

    def test_33_reconciliation_detects_read_terminal_timestamp_regression(self):
        """33. Reconcile ledger flags terminal physical read with terminal_at_ms < created_at_ms."""
        res = self.tracker.admit_read(100)
        cr = res.start_child_read(physical_read_id="cr_33", target_spec={"pid": 33})
        cr.state = "ACCOUNTED"
        cr.terminal_at_ms = cr.created_at_ms - 100.0

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("read 'cr_33' terminal_at_ms" in d and "< created_at_ms" in d for d in report["discrepancies"]),
            f"Expected read timestamp regression in: {report['discrepancies']}",
        )

    def test_34_reconciliation_detects_read_transitioned_to_released_after_started(self):
        """34. Reconcile ledger flags physical read that transitioned to RELEASED after execution started."""
        res = self.tracker.admit_read(100)
        cr = res.start_child_read(physical_read_id="cr_34", target_spec={"pid": 34})
        cr._transition_history = ["ADMITTED", "PHYSICAL_READ_STARTED", "RELEASED"]
        cr.state = "RELEASED"
        cr.terminal_at_ms = cr.created_at_ms + 10.0

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("started execution but transitioned to RELEASED" in d for d in report["discrepancies"]),
            f"Expected started -> released violation in: {report['discrepancies']}",
        )

    def test_35_reconciliation_detects_residual_monotonic_tracking_entry_for_completed_invocation(self):
        """35. Reconcile ledger flags residual monotonic tracking entry for a completed invocation."""
        inv_id = "inv_leak_35"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="shell", physical_read_ids=[])
        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0)

        self.tracker._invocation_start_mono_ns[inv_id] = 123456789

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("residual" in d and "_invocation_start_mono_ns" in d and inv_id in d for d in report["discrepancies"]),
            f"Expected residual monotonic entry discrepancy in: {report['discrepancies']}",
        )

    def test_36_reconciliation_detects_completed_invocation_with_negative_duration(self):
        """36. Reconcile ledger flags completed invocation with negative duration."""
        inv_id = "inv_neg_dur_36"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="shell", physical_read_ids=[])
        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0)

        internal_rec = self.tracker._invocations[inv_id]
        object.__setattr__(internal_rec, "duration_ms", -42.0)

        report = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(report["reconciled"])
        self.assertTrue(
            any("invalid duration" in d and inv_id in d for d in report["discrepancies"]),
            f"Expected negative duration discrepancy in: {report['discrepancies']}",
        )

    def test_37_full_ledger_reconciliation_clean_across_standard_lifecycles(self):
        """37. Full ledger reconciliation satisfies 100% of invariants across standard lifecycles."""
        # 1. Normal execution and commit
        inv_normal = "inv_clean_normal_37"
        read_normal = "pread_normal_37"
        adm1 = self.tracker.admit_read(64, operation_id="op_normal_37")
        cr1 = adm1.start_child_read(physical_read_id=read_normal, target_spec={"pid": 100, "invocation_id": inv_normal})
        self.tracker.record_invocation_started(invocation_id=inv_normal, command_type="shell", physical_read_ids=[read_normal])
        cr1.mark_started()
        cr1.consume(64)
        cr1.account()
        adm1.account()
        self.tracker.record_invocation_completed(invocation_id=inv_normal, return_code=0, output_byte_count=64)
        self.tracker.commit_transaction(operation_id="op_normal_37", measured_bytes=64, reservations=[adm1])

        # 2. Failed execution with conservative accounting
        inv_failed = "inv_clean_failed_37"
        read_failed = "pread_failed_37"
        adm2 = self.tracker.admit_read(200, operation_id="op_failed_37")
        cr2 = adm2.start_child_read(physical_read_id=read_failed, target_spec={"pid": 200, "invocation_id": inv_failed})
        self.tracker.record_invocation_started(invocation_id=inv_failed, command_type="shell", physical_read_ids=[read_failed])
        cr2.mark_started()
        cr2.mark_failed_accounted("remote crash")
        adm2.mark_failed_accounted()
        self.tracker.record_invocation_completed(invocation_id=inv_failed, return_code=1, outcome="EXECUTION_FAILED")
        self.tracker.commit_transaction(operation_id="op_failed_37", estimated_bytes=cr2.charged_bytes, is_failure=True, reservations=[adm2])

        # 3. Clean preflight rejection
        inv_pf = "inv_clean_pf_37"
        read_pf = "pread_pf_37"
        adm3 = self.tracker.admit_read(50, operation_id="op_pf_37")
        cr3 = adm3.start_child_read(physical_read_id=read_pf, target_spec={"pid": 300, "invocation_id": inv_pf})
        self.tracker.record_invocation_started(invocation_id=inv_pf, command_type="shell", physical_read_ids=[read_pf])
        cr3.release()
        adm3.release()
        self.tracker.record_invocation_completed(invocation_id=inv_pf, return_code=-2, outcome="PREFLIGHT_REJECTED")

        # Verify ledger satisfies all 24 invariants
        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])
        self.assertEqual(len(report["discrepancies"]), 0)


class TestPhase20A3419WorkstreamEConcurrencyAndImmutabilityRegressions(unittest.TestCase):
    """Workstream E: Snapshot Isolation, Deep Immutability, and Concurrent Execution Stress."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_38_public_getters_return_deep_copies_preventing_mutation_leaks(self):
        """38. All public getters return independent copies; mutations do not affect tracker state."""
        inv_id = "inv_iso_38"
        self.tracker.record_invocation_started(invocation_id=inv_id, command_type="shell", physical_read_ids=[])
        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0)

        adm = self.tracker.admit_read(100, operation_id="op_38")
        cr = adm.start_child_read(physical_read_id="cr_38", target_spec={"pid": 38, "nested": {"key": 1}})
        cr.mark_started()
        cr.consume(32)
        cr.account()
        adm.account()
        self.tracker.commit_transaction(operation_id="op_38", measured_bytes=32, reservations=[adm])

        # 1. get_invocation_records()
        inv_map = self.tracker.get_invocation_records()
        self.assertIn(inv_id, inv_map)
        inv_map.clear()
        self.assertIn(inv_id, self.tracker.get_invocation_records())

        # 2. get_physical_read_records()
        reads = self.tracker.get_physical_read_records()
        self.assertIn("cr_38", reads)
        reads.clear()
        self.assertIn("cr_38", self.tracker.get_physical_read_records())

        # 3. get_committed_transactions()
        txs = self.tracker.get_committed_transactions()
        self.assertEqual(len(txs), 1)
        txs.clear()
        self.assertEqual(len(self.tracker.get_committed_transactions()), 1)

        # 4. get_committed_record()
        rec = self.tracker.get_committed_record("op_38")
        self.assertIsNotNone(rec)

    def test_39_concurrent_terminal_transitions_and_reconciliations_thread_safety(self):
        """39. Concurrent execution of terminal operations, completes, and reconciliations has zero race/deadlock."""
        num_threads = 6
        iterations_per_thread = 4
        threads = []
        errors = []

        def worker(thread_idx: int):
            try:
                for i in range(iterations_per_thread):
                    inv_id = f"inv_conc_{thread_idx}_{i}"
                    read_id = f"pread_conc_{thread_idx}_{i}"
                    op_id = f"op_conc_{thread_idx}_{i}"

                    adm = self.tracker.admit_read(64, operation_id=op_id)
                    cr = adm.start_child_read(
                        physical_read_id=read_id,
                        target_spec={"pid": 1000 + thread_idx, "invocation_id": inv_id},
                    )

                    self.tracker.record_invocation_started(
                        invocation_id=inv_id,
                        command_type="shell",
                        physical_read_ids=[read_id],
                    )

                    if (thread_idx + i) % 3 == 0:
                        # Success path: invocation completes, then accounting commits
                        cr.mark_started()
                        cr.consume(64)
                        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=0, output_byte_count=64)
                        cr.account()
                        adm.account()
                        self.tracker.commit_transaction(operation_id=op_id, measured_bytes=64, reservations=[adm])
                    elif (thread_idx + i) % 3 == 1:
                        # Failure path: invocation completes with failure, then accounting commits
                        cr.mark_started()
                        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=1, outcome="EXECUTION_FAILED")
                        cr.mark_failed_accounted("injected fault")
                        adm.mark_failed_accounted()
                        self.tracker.commit_transaction(operation_id=op_id, estimated_bytes=cr.charged_bytes, is_failure=True, reservations=[adm])
                    else:
                        # Preflight rejection path (reads not started)
                        self.tracker.record_invocation_completed(invocation_id=inv_id, return_code=-2, outcome="PREFLIGHT_REJECTED")
                        cr.release()
                        adm.release()

                    report = self.tracker.reconcile_ledger(raise_on_error=False)
                    if not report["reconciled"]:
                        errors.append(f"Reconciliation error in thread {thread_idx}: {report['discrepancies']}")

            except Exception as ex:
                errors.append(f"Exception in thread {thread_idx}: {type(ex).__name__}: {ex}")

        for t_i in range(num_threads):
            t = threading.Thread(target=worker, args=(t_i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10.0)
            self.assertFalse(t.is_alive(), "Worker thread deadlocked or timed out")

        self.assertEqual(len(errors), 0, f"Thread errors encountered: {errors}")

        report = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(report["reconciled"])
        self.assertEqual(len(report["discrepancies"]), 0)


if __name__ == "__main__":
    unittest.main()
