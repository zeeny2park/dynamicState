"""Deterministic Adversarial Concurrency & Accounting Correctness Tests.

Phase 2.0-A.3.4.9 — Physical Consumption Accounting, Atomic Reservation & Failure-Safe Commit.

Validates:
1. Physical Consumption Accounting vs Logical Deduplication (P0.1)
2. Atomic Budget Reservation Lifecycle (RESERVED -> CONSUMED -> FINALIZED / RELEASED) (P0.2)
3. Failure-Safe Atomic Finalization (Prepare/Validate/Commit) (P0.3)
4. Scope Lifecycle & Nested Exception Semantics (P0.4)
5. Metadata Provenance & Canonical Digest (P1.1)
6. Complete Ledger Reconciliation across all dimensions (P1.2)
7. Deterministic Adversarial Concurrency Cases (P1.3)
8. Static Architecture Audits (P1.4)
"""

import ast
import math
import os
import pathlib
import threading
import types
import unittest
from typing import Any, Dict, List

from extractor.observation_budget import (
    ActiveOperationScope,
    AccountingFingerprint,
    BudgetReservation,
    CommittedTransactionSnapshot,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    canonical_metadata_digest,
    freeze_metadata,
    unfreeze_metadata,
)


class TestPhase20A349PhysicalAccounting(unittest.TestCase):
    """Deterministic concurrency and accounting tests for Phase 2.0-A.3.4.9."""

    # =========================================================================
    # 1. Same ID, identical concurrent scopes, both perform physical reads
    # =========================================================================

    def test_01_same_id_identical_concurrent_scopes_both_perform_physical_reads(self):
        """Two concurrent scopes with identical ID and fingerprint both perform physical reads:
        Both physical costs MUST be preserved in tracker metrics and ledger snapshots.
        """
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(2)
        outcomes = []

        def worker():
            barrier.wait()
            with tracker.operation_scope("op_dup_phys", profile_id="prof_dup", owner="WORKER") as scope:
                scope.record_read(bytes_read=150, latency_us=25.0, stop_ms=1.5)
            snap = tracker.get_committed_record("op_dup_phys")
            outcomes.append(snap)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(outcomes), 2)
        # Both physical reads (150B + 150B = 300B) MUST be preserved
        self.assertEqual(tracker.metrics.bytes_read, 300)
        self.assertEqual(tracker.metrics.measured_bytes_read, 300)

        # Authoritative ledger contains both the primary and duplicate execution records
        ledger = tracker.get_committed_transactions()
        self.assertEqual(len(ledger), 2)
        self.assertIn("op_dup_phys", ledger)
        dup_keys = [k for k in ledger if k.startswith("op_dup_phys#duplicate_")]
        self.assertEqual(len(dup_keys), 1)

        # Both records are COMMITTED
        self.assertEqual(ledger["op_dup_phys"].accounting_status, "COMMITTED")
        self.assertEqual(ledger[dup_keys[0]].accounting_status, "COMMITTED")

        # Physical consumption records map contains both
        phys_records = tracker.get_physical_consumption_records()
        self.assertEqual(len(phys_records), 2)

        # Full reconciliation proves every byte is accounted for
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_bytes_read"], 300)
        self.assertEqual(recon["duplicate_logical_operations_count"], 1)

    # =========================================================================
    # 2. Same ID, conflicting concurrent scopes, both perform reads
    # =========================================================================

    def test_02_same_id_conflicting_concurrent_scopes_both_perform_reads(self):
        """Two concurrent scopes with same ID and conflicting costs: one commits as COMMITTED,
        other is rejected and raises ValueError, but preserves consumed physical bytes in REJECTED collision snapshot.
        """
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(2)
        errors = []
        snapshots = []

        def worker(read_bytes):
            barrier.wait()
            try:
                with tracker.operation_scope("op_conflict_phys", profile_id="prof_conf") as scope:
                    scope.record_read(bytes_read=read_bytes, latency_us=10.0)
                snapshots.append((read_bytes, tracker.get_committed_record("op_conflict_phys")))
            except ValueError as ve:
                errors.append((read_bytes, str(ve)))

        t1 = threading.Thread(target=worker, args=(100,))
        t2 = threading.Thread(target=worker, args=(250,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(snapshots), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("Operation ID collision", errors[0][1])

        # Both costs are preserved in the ledger: winning as COMMITTED, losing as REJECTED
        ledger = tracker.get_committed_transactions()
        self.assertEqual(len(ledger), 2)
        self.assertEqual(tracker.metrics.bytes_read, 350)
        self.assertEqual(tracker.metrics.total_read_failures, 1)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_rejected_outcomes"], 1)

    # =========================================================================
    # 3. Concurrent budget reservations near the global limit
    # =========================================================================

    def test_03_concurrent_budget_reservations_near_global_limit(self):
        """Concurrent budget reservations near limit: atomic check grants to one and rejects the other."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=1000))
        tracker.start()

        # Pre-commit 800 bytes (200 bytes remaining)
        with tracker.operation_scope("op_initial") as s:
            s.record_read(bytes_read=800)

        barrier = threading.Barrier(2)
        successes = []
        exhaustions = []

        def worker(requested_bytes):
            barrier.wait()
            try:
                res = tracker.reserve_budget(estimated_bytes=requested_bytes)
                res.consume(actual_bytes=requested_bytes)
                with tracker.operation_scope(f"op_res_{requested_bytes}") as scope:
                    scope.record_read(bytes_read=requested_bytes, reservation=res)
                successes.append(requested_bytes)
            except ValueError as ve:
                if "BUDGET_EXHAUSTED" in str(ve):
                    exhaustions.append((requested_bytes, str(ve)))
                else:
                    raise

        t1 = threading.Thread(target=worker, args=(150,))
        t2 = threading.Thread(target=worker, args=(120,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Since 150 + 120 = 270 > 200, exactly one succeeded and one was rejected
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(exhaustions), 1)
        self.assertLessEqual(tracker.metrics.bytes_read, 1000)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 4. Concurrent profile budget exhaustion
    # =========================================================================

    def test_04_concurrent_profile_budget_exhaustion(self):
        """Concurrent reservations against profile ceiling: profile limit is enforced atomically."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        tracker.start()

        profile_ceil = {"max_bytes_read": 500}
        barrier = threading.Barrier(2)
        successes = []
        profile_exceeded = []

        def worker(requested_bytes):
            barrier.wait()
            try:
                res = tracker.reserve_budget(
                    estimated_bytes=requested_bytes,
                    profile_id="prof_limited",
                    profile_ceiling=profile_ceil,
                )
                res.consume(actual_bytes=requested_bytes)
                with tracker.operation_scope(f"op_prof_{requested_bytes}", profile_id="prof_limited") as scope:
                    scope.record_read(bytes_read=requested_bytes, reservation=res, profile_id="prof_limited", profile_ceiling=profile_ceil)
                successes.append(requested_bytes)
            except ValueError as ve:
                if "PROFILE_CEILING_EXCEEDED" in str(ve):
                    profile_exceeded.append((requested_bytes, str(ve)))
                else:
                    raise

        t1 = threading.Thread(target=worker, args=(300,))
        t2 = threading.Thread(target=worker, args=(300,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Exactly one succeeded within the 500B ceiling, the other rejected
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(profile_exceeded), 1)
        self.assertEqual(tracker.metrics.profile_usage["prof_limited"]["bytes_read"], 300)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 5. Read begins before exhaustion and completes afterward (Overshoot Semantics)
    # =========================================================================

    def test_05_read_begins_before_exhaustion_and_completes_afterward(self):
        """In-flight read beginning before exhaustion is accepted and preserved upon completion,
        with overshoot explicitly quantified and bounded.
        """
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=1000))
        tracker.start()

        # Step 1: Pre-commit 700 bytes (300B remaining)
        with tracker.operation_scope("op_setup") as s:
            s.record_read(bytes_read=700)

        # Step 2: In-flight read reserves 200 bytes (100B remaining)
        res_inflight = tracker.reserve_budget(estimated_bytes=200, operation_id="op_inflight")
        self.assertEqual(res_inflight.state, "RESERVED")

        # Step 3: Concurrent operation consumes the remaining 300 bytes and exhausts tracker
        with tracker.operation_scope("op_exhaust") as s:
            s.record_read(bytes_read=300)
        self.assertTrue(tracker.is_budget_exhausted)

        # Step 4: The in-flight read completes physical I/O with 250 bytes (50B more than reserved)
        res_inflight.consume(actual_bytes=250)
        with tracker.operation_scope("op_inflight") as scope:
            scope.record_read(bytes_read=250, reservation=res_inflight)

        # Physical consumption is preserved in the ledger: 700 + 300 + 250 = 1250
        self.assertEqual(tracker.metrics.bytes_read, 1250)
        overshoot = tracker.metrics.bytes_read - tracker.limits.max_bytes_read
        self.assertEqual(overshoot, 250)
        self.assertLessEqual(overshoot, 250)  # Bounded by single in-flight read chunk

        # Any NEW read is rejected
        with self.assertRaises(ValueError) as ctx:
            tracker.reserve_budget(estimated_bytes=10)
        self.assertIn("BUDGET_EXHAUSTED", str(ctx.exception))

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 6. Reservation release before physical read
    # =========================================================================

    def test_06_reservation_release_before_physical_read(self):
        """Unused reservation is cleanly released to RELEASED state; cannot release if consumption occurred."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        res = tracker.reserve_budget(estimated_bytes=200, operation_id="op_to_release")
        self.assertEqual(res.state, "RESERVED")
        self.assertIn(res.reservation_id, tracker.get_active_reservations())

        # Release when zero bytes were consumed
        tracker.release_reservation(res)
        self.assertEqual(res.state, "RELEASED")
        self.assertNotIn(res.reservation_id, tracker.get_active_reservations())
        self.assertEqual(tracker.metrics.bytes_read, 0)

        # Attempting to release a reservation that consumed bytes raises RuntimeError
        res2 = tracker.reserve_budget(estimated_bytes=100, operation_id="op_consumed")
        res2.consume(actual_bytes=50)
        with self.assertRaises(RuntimeError) as ctx:
            tracker.release_reservation(res2)
        self.assertIn("A reservation must never be released if physical consumption occurred", str(ctx.exception))

    # =========================================================================
    # 7. Read failure after partial physical consumption
    # =========================================================================

    def test_07_read_failure_after_partial_physical_consumption(self):
        """Failed read after partial consumption preserves actual consumed costs in ledger as FAILED."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        try:
            with tracker.operation_scope("op_partial_fail", profile_id="prof_fail") as scope:
                scope.record_read(bytes_read=120, latency_us=15.0, is_failure=True)
                raise IOError("Target process connection dropped mid-read")
        except IOError:
            pass

        self.assertEqual(tracker.metrics.bytes_read, 120)
        self.assertEqual(tracker.metrics.measured_bytes_read, 120)
        self.assertEqual(tracker.metrics.total_read_failures, 1)

        snap = tracker.get_committed_record("op_partial_fail")
        self.assertIsNotNone(snap)
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertEqual(snap.charged_bytes, 120)
        self.assertTrue(snap.is_failure)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 8. Exception during finalization after accounting preparation
    # =========================================================================

    def test_08_exception_during_finalization_after_accounting_preparation(self):
        """Unexpected finalization error preserves physical consumption through emergency failure commit."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        scope = ActiveOperationScope(
            tracker=tracker,
            operation_id="op_emergency",
            profile_id="prof_emerg",
            owner="TEST",
        )
        tracker._register_active_scope(scope)
        scope.record_read(bytes_read=88, latency_us=12.0)

        # Inject emergency failure snapshot directly
        snap = tracker._record_emergency_failure_snapshot(scope, error=RuntimeError("Simulated finalization crash"))
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertEqual(tracker.metrics.bytes_read, 88)
        self.assertEqual(tracker.metrics.total_read_failures, 1)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 9. Snapshot construction failure
    # =========================================================================

    def test_09_snapshot_construction_failure(self):
        """Scope with corrupted/unfreezable metadata during finalization preserves physical bytes safely."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        scope = ActiveOperationScope(
            tracker=tracker,
            operation_id="op_bad_meta",
            profile_id="prof_bad",
            owner="TEST",
        )
        tracker._register_active_scope(scope)
        scope.record_read(bytes_read=75)
        # Corrupt metadata with unfreezable non-string dict key
        scope.metadata = {123: "invalid_key_type"}

        # Finalize scope: metadata error is caught and physical consumption preserved as FAILED
        snap = scope.finalize(success=True)
        self.assertIsNotNone(snap)
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertEqual(tracker.metrics.bytes_read, 75)
        self.assertIn("metadata_error", snap.metadata)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 10. Ledger commit failure atomicity
    # =========================================================================

    def test_10_ledger_commit_failure_atomicity(self):
        """Prepare/validate/commit sequence guarantees metrics cannot be incremented without a ledger snapshot."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        # Pass a record that fails validation (negative bytes)
        rec = ObservationAccountingRecord(
            operation_id="op_invalid_val",
            accounting_owner="TEST",
            measured_bytes_read=-50,
            session_id=tracker.session_id,
        )

        with self.assertRaises(ValueError):
            tracker.commit_transaction(rec)

        # Metrics remain 0, ledger remains empty
        self.assertEqual(tracker.metrics.bytes_read, 0)
        self.assertEqual(len(tracker.get_committed_transactions()), 0)
        self.assertEqual(len(tracker.get_physical_consumption_records()), 0)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 11. Nested exception caught by outer scope
    # =========================================================================

    def test_11_nested_exception_caught_by_outer_scope(self):
        """When inner scope fails and outer caller catches it, inner is recorded as FAILED and outer can complete."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        with tracker.operation_scope("op_outer_catch") as outer:
            try:
                with tracker.operation_scope("op_inner_fail") as inner:
                    inner.record_read(bytes_read=100)
                    raise ValueError("Inner failure simulation")
            except ValueError:
                pass  # Caller explicitly handles inner error

            outer.record_read(bytes_read=200)

        ledger = tracker.get_committed_transactions()
        self.assertEqual(len(ledger), 2)
        self.assertEqual(ledger["op_inner_fail"].accounting_status, "FAILED")
        self.assertEqual(ledger["op_outer_catch"].accounting_status, "COMMITTED")

        self.assertEqual(tracker.metrics.bytes_read, 300)
        self.assertEqual(tracker.metrics.total_read_failures, 1)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 12. Nested exception propagated to outer scope
    # =========================================================================

    def test_12_nested_exception_propagated_to_outer_scope(self):
        """When inner scope fails and exception propagates through outer, both are marked FAILED with stack clean."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        with self.assertRaises(RuntimeError):
            with tracker.operation_scope("op_outer_prop") as outer:
                outer.record_read(bytes_read=50)
                with tracker.operation_scope("op_inner_prop") as inner:
                    inner.record_read(bytes_read=70)
                    raise RuntimeError("Unhandled inner error")

        # Stack is fully cleaned up
        self.assertEqual(len(tracker._thread_local.scope_stack), 0)
        self.assertIsNone(tracker._thread_local.current_scope)

        ledger = tracker.get_committed_transactions()
        self.assertEqual(ledger["op_inner_prop"].accounting_status, "FAILED")
        self.assertEqual(ledger["op_outer_prop"].accounting_status, "FAILED")

        self.assertEqual(tracker.metrics.bytes_read, 120)
        self.assertEqual(tracker.metrics.total_read_failures, 2)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 13. BaseException and cancellation cleanup
    # =========================================================================

    def test_13_base_exception_and_cancellation_cleanup(self):
        """BaseException (e.g. KeyboardInterrupt) cleans up scope stack and preserves physical consumption."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        with self.assertRaises(KeyboardInterrupt):
            with tracker.operation_scope("op_cancelled") as scope:
                scope.record_read(bytes_read=45)
                raise KeyboardInterrupt("Thread cancelled")

        # Stack is restored
        self.assertEqual(len(tracker._thread_local.scope_stack), 0)
        self.assertNotIn("op_cancelled", tracker._active_scopes)

        # Physical bytes preserved as FAILED
        snap = tracker.get_committed_record("op_cancelled")
        self.assertIsNotNone(snap)
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertEqual(tracker.metrics.bytes_read, 45)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 14. Retry after FAILED and REJECTED
    # =========================================================================

    def test_14_retry_after_failed_and_rejected(self):
        """Cannot recommit a failed or rejected operation ID as successful; retry with a new operation ID succeeds."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        # Part A: Failed transaction commit
        rec_fail = ObservationAccountingRecord(
            operation_id="op_will_fail",
            accounting_owner="MOD",
            measured_bytes_read=50,
            session_id=tracker.session_id,
        )
        tracker.commit_transaction(rec_fail, is_failure=True)
        snap_fail = tracker.get_committed_record("op_will_fail")
        self.assertTrue(snap_fail.is_failure)

        # Attempting to recommit same ID as successful raises ValueError
        rec_retry_same = ObservationAccountingRecord(
            operation_id="op_will_fail",
            accounting_owner="MOD",
            measured_bytes_read=50,
            session_id=tracker.session_id,
        )
        with self.assertRaises(ValueError) as ctx:
            tracker.commit_transaction(rec_retry_same, is_failure=False)
        self.assertIn("cannot be recommitted as a successful transaction", str(ctx.exception))

        # Part B: Scope failure has FAILED status
        try:
            with tracker.operation_scope("op_scope_failed") as s:
                s.record_read(bytes_read=40, is_failure=True)
                raise RuntimeError("Scope failed")
        except RuntimeError:
            pass

        snap_scope_fail = tracker.get_committed_record("op_scope_failed")
        self.assertEqual(snap_scope_fail.accounting_status, "FAILED")

        # Part C: Retry with new operation ID succeeds cleanly
        rec_retry_new = ObservationAccountingRecord(
            operation_id="op_retry_new_id",
            accounting_owner="MOD",
            measured_bytes_read=80,
            session_id=tracker.session_id,
        )
        ok = tracker.commit_transaction(rec_retry_new, is_failure=False)
        self.assertTrue(ok)
        self.assertEqual(tracker.get_committed_record("op_retry_new_id").accounting_status, "COMMITTED")

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 15. Duplicate commit and duplicate physical consumption
    # =========================================================================

    def test_15_duplicate_commit_vs_duplicate_physical_consumption(self):
        """Distinguishes duplicate commit (0 additional physical cost, charges once)
        from duplicate physical consumption (two physical reads, charges both).
        """
        tracker = ObservationBudgetTracker()
        tracker.start()

        # Part A: Duplicate commit of the exact same record charges once
        rec = ObservationAccountingRecord(
            operation_id="tx_dup_commit",
            accounting_owner="MOD",
            measured_bytes_read=200,
            session_id=tracker.session_id,
        )
        ok1 = tracker.commit_transaction(rec)
        ok2 = tracker.commit_transaction(rec)
        self.assertTrue(ok1)
        self.assertTrue(ok2)
        self.assertEqual(tracker.metrics.bytes_read, 200)

        # Part B: Two distinct scopes performing physical reads for same ID charge both
        with tracker.operation_scope("op_phys_dup") as s1:
            s1.record_read(bytes_read=100)

        with tracker.operation_scope("op_phys_dup") as s2:
            s2.record_read(bytes_read=100)

        # 200 (Part A) + 100 + 100 (Part B) = 400 total bytes read
        self.assertEqual(tracker.metrics.bytes_read, 400)
        self.assertEqual(tracker.metrics.measured_bytes_read, 400)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 16. Reconciliation with active scopes and outstanding reservations
    # =========================================================================

    def test_16_reconciliation_with_active_scopes_and_outstanding_reservations(self):
        """reconcile_ledger() accurately separates committed totals from active reservations and in-flight bytes."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        # 1. Committed snapshot
        with tracker.operation_scope("op_comm") as s:
            s.record_read(bytes_read=500)

        # 2. Active reservation
        res = tracker.reserve_budget(estimated_bytes=300, operation_id="op_res_active")

        # 3. Active in-flight scope
        scope_active = ActiveOperationScope(tracker, operation_id="op_flight", owner="TEST")
        tracker._register_active_scope(scope_active)
        scope_active.record_read(bytes_read=200)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_bytes_read"], 500)
        self.assertEqual(recon["active_reservations_bytes"], 300)
        self.assertEqual(recon["active_in_flight_bytes"], 200)

        # remaining_bytes accounts for all three: 10000 - 500 - 300 - 200 = 9000
        self.assertEqual(tracker.remaining_bytes, 9000)

        # Clean up active resources
        tracker.release_reservation(res)
        scope_active.finalize(success=True)

    # =========================================================================
    # 17. Concurrent different operation IDs
    # =========================================================================

    def test_17_concurrent_different_operation_ids(self):
        """Multiple concurrent threads executing distinct operation IDs all complete and reconcile."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        n_threads = 8
        barrier = threading.Barrier(n_threads)
        errors = []

        def worker(idx):
            barrier.wait()
            try:
                op_id = f"op_conc_{idx}"
                with tracker.operation_scope(op_id, profile_id=f"prof_{idx}") as scope:
                    scope.record_read(bytes_read=50 * (idx + 1), latency_us=10.0 * idx)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        expected_bytes = sum(50 * (i + 1) for i in range(n_threads))
        self.assertEqual(tracker.metrics.bytes_read, expected_bytes)
        self.assertEqual(len(tracker.get_committed_transactions()), n_threads)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # 18. Metadata provenance preservation
    # =========================================================================

    def test_18_metadata_provenance_preservation(self):
        """Scope metadata is preserved into committed snapshot, serialized cleanly, and validates digests."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        meta_input = {
            "source": "dwarf_resolver",
            "tags": ("identity", "elf"),
            "run": 42,
        }

        with tracker.operation_scope("op_provenance", metadata=meta_input) as scope:
            scope.record_read(bytes_read=64, metadata={"step": "header_read"})

        snap = tracker.get_committed_record("op_provenance")
        self.assertIsNotNone(snap)
        self.assertEqual(snap.metadata["source"], "dwarf_resolver")
        self.assertEqual(snap.metadata["tags"], ("identity", "elf"))
        self.assertEqual(snap.metadata["step"], "header_read")

        # to_dict converts metadata back to mutable structures
        snap_dict = snap.to_dict()
        self.assertIsInstance(snap_dict["metadata"], dict)

        # Reject unsupported object type for canonical metadata digest (no silent string conversion)
        class CustomObj:
            pass

        with self.assertRaises(TypeError) as ctx:
            canonical_metadata_digest({"obj": CustomObj()})
        self.assertIn("Unsupported metadata value type for canonical identity", str(ctx.exception))

    # =========================================================================
    # 19. Static Architecture Audit: No External Writes to Tracker or Ledger
    # =========================================================================

    def test_19_static_audit_no_external_writes_to_tracker_or_ledger(self):
        """Static AST audit verifies zero external production code writes to tracker private transaction state."""
        extractor_dir = pathlib.Path(__file__).parent.parent / "extractor"
        forbidden_attrs = {
            "_committed_transactions",
            "_physical_consumption_records",
            "_active_reservations",
            "_transaction_lock",
            "_failed_operations",
            "_active_scopes",
        }
        metric_fields = {
            "bytes_read",
            "measured_bytes_read",
            "conservative_estimated_bytes",
        }

        violations = []
        for py_path in extractor_dir.rglob("*.py"):
            if py_path.name == "observation_budget.py":
                continue

            code = py_path.read_text(encoding="utf-8")
            tree = ast.parse(code, filename=str(py_path))

            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for tgt in targets:
                        if isinstance(tgt, ast.Attribute):
                            if tgt.attr in forbidden_attrs:
                                violations.append(f"{py_path.name}:{node.lineno} writes to '{tgt.attr}'")
                            if tgt.attr in metric_fields:
                                if isinstance(tgt.value, ast.Attribute) and tgt.value.attr == "metrics":
                                    violations.append(f"{py_path.name}:{node.lineno} writes to 'metrics.{tgt.attr}'")

        self.assertEqual(
            violations,
            [],
            f"Static audit failed: unauthorized external writes to tracker internal state: {violations}",
        )

    # =========================================================================
    # 20. Static Architecture Audit: Metadata Subscript Mutation Prevention
    # =========================================================================

    def test_20_static_audit_no_direct_mutation_of_committed_metadata(self):
        """Static AST audit verifies zero external code attempts direct subscript mutation on snapshot.metadata."""
        extractor_dir = pathlib.Path(__file__).parent.parent / "extractor"
        violations = []

        for py_path in extractor_dir.rglob("*.py"):
            code = py_path.read_text(encoding="utf-8")
            tree = ast.parse(code, filename=str(py_path))

            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for tgt in targets:
                        if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Attribute) and tgt.value.attr == "metadata":
                            violations.append(f"{py_path.name}:{node.lineno} mutates metadata subscript directly")

        self.assertEqual(
            violations,
            [],
            f"Static audit failed: unauthorized metadata subscript mutation: {violations}",
        )


if __name__ == "__main__":
    unittest.main()
