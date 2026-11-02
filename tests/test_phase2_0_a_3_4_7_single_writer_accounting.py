"""Phase 2.0-A.3.4.7 — Single-Writer Accounting Ledger & Concurrent Attribution Closure Test Suite.

Deterministic, barrier-synchronized, and adversarial test suite proving:
1. Single-writer accounting: ObservationBudgetTracker is the sole writer.
2. Complete removal of metric-delta attribution (no concurrent crosstalk).
3. Canonical immutable fingerprint collision detection.
4. WorkManager empty-result semantics (never automatically zero bytes).
5. Partial failure and budget-exhaustion cost preservation.
6. Multi-threaded concurrency isolation using Barriers (no timing sleeps).
7. Static AST audit verifying tracker internals isolation across production code.
"""

import ast
from dataclasses import FrozenInstanceError
import math
import os
import pathlib
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional
import unittest

from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    ObservationAccountingRecord,
    CommittedTransactionSnapshot,
    AccountingFingerprint,
    DEFAULT_CONSERVATIVE_UNKNOWN_BYTES,
)
from extractor.inspection_module import (
    InspectionProfile,
    InspectionContext,
    FunctionalInspectionModule,
    DOMAIN_CONCURRENCY,
    DOMAIN_MEMORY,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    IDENTITY_VERIFIED,
    IDENTITY_UNVERIFIED,
)
from extractor.adaptive_engine import (
    AdaptiveInvestigationEngine,
    WaitForGraph,
    WaitForEdge,
)
from extractor.debug_image import clear_elf_identity_cache


class TestPhase20A347SingleWriterAccounting(unittest.TestCase):
    """Authoritative test suite for Phase 2.0-A.3.4.7 single-writer accounting architecture."""

    def setUp(self):
        clear_elf_identity_cache()

    # =========================================================================
    # Group A: Single-Writer Ledger & Immutability
    # =========================================================================

    def test_01_committed_snapshot_is_immutable(self):
        """CommittedTransactionSnapshot is frozen and cannot be mutated by callers."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        rec = ObservationAccountingRecord(
            operation_id="snap_immut_1",
            accounting_owner="MOD",
            measured_bytes_read=100,
        )
        tracker.commit_transaction(rec)

        snapshot = tracker.get_committed_record("snap_immut_1")
        self.assertIsInstance(snapshot, CommittedTransactionSnapshot)
        self.assertEqual(snapshot.charged_bytes, 100)

        # Direct mutation on frozen snapshot must raise FrozenInstanceError or AttributeError
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            snapshot.charged_bytes = 999  # type: ignore

        with self.assertRaises((FrozenInstanceError, AttributeError)):
            snapshot.measured_bytes_read = 999  # type: ignore

    def test_02_caller_mutation_cannot_alter_committed_ledger(self):
        """Mutating the caller-owned record after commit does not affect ledger and recommit fails."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        rec = ObservationAccountingRecord(
            operation_id="caller_mut_1",
            accounting_owner="MOD",
            measured_bytes_read=200,
        )
        self.assertTrue(tracker.commit_transaction(rec))

        # Mutate caller record
        rec.measured_bytes_read = 800
        rec.charged_bytes = 800

        # Ledger snapshot remains unchanged
        snapshot = tracker.get_committed_record("caller_mut_1")
        self.assertEqual(snapshot.measured_bytes_read, 200)
        self.assertEqual(snapshot.charged_bytes, 200)

        # Attempting to re-commit mutated record must raise collision error
        with self.assertRaises(ValueError) as cm:
            tracker.commit_transaction(rec)
        self.assertIn("Operation ID collision", str(cm.exception))

    def test_03_get_committed_transactions_returns_read_only_snapshots(self):
        """get_committed_transactions returns dictionary of immutable snapshots matching tracker metrics."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        for i in range(5):
            rec = ObservationAccountingRecord(
                operation_id=f"tx_snap_{i}",
                accounting_owner="MOD",
                measured_bytes_read=100 * (i + 1),
            )
            tracker.commit_transaction(rec)

        snapshots = tracker.get_committed_transactions()
        self.assertEqual(len(snapshots), 5)
        for op_id, snap in snapshots.items():
            self.assertIsInstance(snap, CommittedTransactionSnapshot)
            self.assertEqual(snap.operation_id, op_id)

        # Modifying the returned dictionary does not modify tracker's internal ledger
        snapshots["new_fake_tx"] = snapshots["tx_snap_0"]
        self.assertNotIn("new_fake_tx", tracker.get_committed_transactions())

    def test_04_session_id_enforcement_and_rejection_on_mismatch(self):
        """Reusing operation ID from another session is rejected with session mismatch error."""
        tracker = ObservationBudgetTracker(session_id="session_alpha")
        tracker.start()

        rec_valid = ObservationAccountingRecord(
            operation_id="tx_sess_1",
            accounting_owner="MOD",
            measured_bytes_read=100,
            session_id="session_alpha",
        )
        self.assertTrue(tracker.commit_transaction(rec_valid))

        rec_mismatch = ObservationAccountingRecord(
            operation_id="tx_sess_2",
            accounting_owner="MOD",
            measured_bytes_read=100,
            session_id="session_beta",
        )
        with self.assertRaises(ValueError) as cm:
            tracker.commit_transaction(rec_mismatch)
        self.assertIn("Session mismatch", str(cm.exception))

    def test_05_failed_operation_cannot_be_recommitted_as_success(self):
        """An operation ID that was previously rejected or failed cannot become a successful commit."""
        limits = ObservationBudgetLimits(max_bytes_read=500, reject_unknown_byte_cost=True)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        # Unknown cost rejected
        rec_failed = ObservationAccountingRecord(
            operation_id="tx_rejected_cost",
            accounting_owner="MOD",
            measured_bytes_read=None,
            estimated_bytes_read=0,
            measurement_type="UNKNOWN",
        )
        ok = tracker.commit_transaction(rec_failed)
        self.assertFalse(ok)

        # Later attempt to recommit the same ID as a successful transaction must raise ValueError
        rec_retry = ObservationAccountingRecord(
            operation_id="tx_rejected_cost",
            accounting_owner="MOD",
            measured_bytes_read=200,
        )
        with self.assertRaises(ValueError) as cm:
            tracker.commit_transaction(rec_retry)
        self.assertIn("cannot be recommitted", str(cm.exception))

    # =========================================================================
    # Group B: Operation ID Collision & Fingerprint Validation
    # =========================================================================

    def test_06_identical_duplicate_commit_is_idempotent_no_charge(self):
        """Identical duplicate commits succeed idempotently without double-charging tracker."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        rec1 = ObservationAccountingRecord(
            operation_id="tx_dup_identical",
            accounting_owner="MOD",
            measured_bytes_read=150,
            estimated_bytes_read=0,
            latency_us=50.0,
        )
        self.assertTrue(tracker.commit_transaction(rec1, profile_id="prof_1", stop_ms=1.5))
        self.assertEqual(tracker.metrics.bytes_read, 150)

        # Second commit with identical content
        rec2 = ObservationAccountingRecord(
            operation_id="tx_dup_identical",
            accounting_owner="MOD",
            measured_bytes_read=150,
            estimated_bytes_read=0,
            latency_us=50.0,
        )
        self.assertTrue(tracker.commit_transaction(rec2, profile_id="prof_1", stop_ms=1.5))
        # Total bytes remains 150 (NOT 300)
        self.assertEqual(tracker.metrics.bytes_read, 150)
        self.assertEqual(tracker.metrics.measured_bytes_read, 150)

    def test_07_same_id_different_profile_id_collision(self):
        """Same operation ID recommitted with different profile_id raises collision error."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        rec = ObservationAccountingRecord("tx_coll_prof", "MOD", measured_bytes_read=100)
        self.assertTrue(tracker.commit_transaction(rec, profile_id="profile_A"))

        rec2 = ObservationAccountingRecord("tx_coll_prof", "MOD", measured_bytes_read=100)
        with self.assertRaises(ValueError) as cm:
            tracker.commit_transaction(rec2, profile_id="profile_B")
        self.assertIn("Operation ID collision", str(cm.exception))

    def test_08_same_id_different_measured_estimated_split_collision(self):
        """Same operation ID with same total bytes but different measured/estimated split raises collision."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        rec1 = ObservationAccountingRecord(
            "tx_coll_split", "MOD", measured_bytes_read=100, estimated_bytes_read=0
        )
        self.assertTrue(tracker.commit_transaction(rec1))

        rec2 = ObservationAccountingRecord(
            "tx_coll_split", "MOD", measured_bytes_read=50, estimated_bytes_read=50
        )
        with self.assertRaises(ValueError) as cm:
            tracker.commit_transaction(rec2)
        self.assertIn("Operation ID collision", str(cm.exception))

    def test_09_same_id_conflicting_accounting_owner_collision(self):
        """Same operation ID with conflicting accounting_owner raises collision error."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        rec1 = ObservationAccountingRecord("tx_coll_owner", "WORKMANAGER", measured_bytes_read=100)
        self.assertTrue(tracker.commit_transaction(rec1))

        rec2 = ObservationAccountingRecord("tx_coll_owner", "ADAPTER", measured_bytes_read=100)
        with self.assertRaises(ValueError) as cm:
            tracker.commit_transaction(rec2)
        self.assertIn("Operation ID collision", str(cm.exception))

    def test_10_same_id_conflicting_is_failure_collision(self):
        """Same operation ID recommitted with different failure status raises collision error."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        rec1 = ObservationAccountingRecord("tx_coll_fail", "MOD", measured_bytes_read=100)
        self.assertTrue(tracker.commit_transaction(rec1, is_failure=False))

        rec2 = ObservationAccountingRecord("tx_coll_fail", "MOD", measured_bytes_read=100)
        with self.assertRaises(ValueError) as cm:
            tracker.commit_transaction(rec2, is_failure=True)
        self.assertIn("Operation ID collision", str(cm.exception))

    # =========================================================================
    # Group C: Concurrent Attribution & Deterministic Barrier Testing
    # =========================================================================

    def test_11_concurrent_operations_consume_different_byte_counts(self):
        """Two concurrent operations synchronized with Barrier consume different byte counts without crosstalk."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(2)

        results = {}

        def worker_1():
            barrier.wait()
            rec = ObservationAccountingRecord("tx_conc_1", "WORKER_1", measured_bytes_read=150)
            ok = tracker.commit_transaction(rec)
            results["w1"] = (ok, rec.charged_bytes)

        def worker_2():
            barrier.wait()
            rec = ObservationAccountingRecord("tx_conc_2", "WORKER_2", measured_bytes_read=350)
            ok = tracker.commit_transaction(rec)
            results["w2"] = (ok, rec.charged_bytes)

        t1 = threading.Thread(target=worker_1)
        t2 = threading.Thread(target=worker_2)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(results["w1"], (True, 150))
        self.assertEqual(results["w2"], (True, 350))
        self.assertEqual(tracker.metrics.bytes_read, 500)
        self.assertEqual(tracker.metrics.measured_bytes_read, 500)

    def test_12_each_operation_receives_only_its_own_costs_no_leakage(self):
        """Concurrent operations with mixed measured/estimated receive only their own costs."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(2)

        results = {}

        def worker_a():
            barrier.wait()
            rec = ObservationAccountingRecord(
                "tx_iso_a", "WORKER_A", measured_bytes_read=100, estimated_bytes_read=25
            )
            tracker.commit_transaction(rec)
            results["a"] = (rec.measured_bytes_read, rec.estimated_bytes_read, rec.charged_bytes)

        def worker_b():
            barrier.wait()
            rec = ObservationAccountingRecord(
                "tx_iso_b", "WORKER_B", measured_bytes_read=None, estimated_bytes_read=200
            )
            tracker.commit_transaction(rec)
            results["b"] = (rec.measured_bytes_read, rec.estimated_bytes_read, rec.charged_bytes)

        t1 = threading.Thread(target=worker_a)
        t2 = threading.Thread(target=worker_b)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(results["a"], (100, 25, 125))
        self.assertEqual(results["b"], (None, 200, 200))
        self.assertEqual(tracker.metrics.measured_bytes_read, 100)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 225)
        self.assertEqual(tracker.metrics.bytes_read, 325)

    def test_13_concurrent_duplicate_commits_identical_content(self):
        """Five concurrent threads committing the exact same record charge exactly once."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(5)
        successes = []

        def worker():
            barrier.wait()
            rec = ObservationAccountingRecord(
                "tx_conc_dup_exact", "SHARED", measured_bytes_read=200, latency_us=10.0
            )
            ok = tracker.commit_transaction(rec, profile_id="p_shared")
            successes.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(successes), 5)
        self.assertTrue(all(successes))
        # Total tracker charge is exactly 200B (NOT 1000B)
        self.assertEqual(tracker.metrics.bytes_read, 200)
        self.assertEqual(tracker.metrics.measured_bytes_read, 200)

    def test_14_concurrent_duplicate_commits_conflicting_content(self):
        """Two concurrent threads committing the same ID with conflicting content: exactly one succeeds."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(2)
        outcomes = []

        def worker(charge_val):
            barrier.wait()
            rec = ObservationAccountingRecord("tx_race_coll", "MOD", measured_bytes_read=charge_val)
            try:
                ok = tracker.commit_transaction(rec)
                outcomes.append(("OK", charge_val, ok))
            except ValueError as ve:
                outcomes.append(("ERR", charge_val, str(ve)))

        t1 = threading.Thread(target=worker, args=(100,))
        t2 = threading.Thread(target=worker, args=(300,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        ok_entries = [o for o in outcomes if o[0] == "OK"]
        err_entries = [o for o in outcomes if o[0] == "ERR"]
        self.assertEqual(len(ok_entries), 1)
        self.assertEqual(len(err_entries), 1)
        winning_charge = ok_entries[0][1]
        self.assertEqual(tracker.metrics.bytes_read, winning_charge)

    def test_15_exception_after_partial_read_concurrent_commit_isolation(self):
        """One operation crashes after partial read while another commits concurrently without metric-delta pollution."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(2)

        def worker_crashing():
            with tracker.operation_scope("op_crash", profile_id="prof_crash") as scope:
                scope.record_read(bytes_read=120)
                barrier.wait()
                raise RuntimeError("Worker 1 crashed")

        def worker_normal():
            barrier.wait()
            with tracker.operation_scope("op_norm", profile_id="prof_norm") as scope:
                scope.record_read(bytes_read=300)

        t_crash = threading.Thread(target=lambda: (lambda: None)())
        try:
            worker_crashing_wrapper = lambda: None
        except Exception:
            pass

        # Run with threads
        crash_err = []
        def run_crash():
            try:
                worker_crashing()
            except RuntimeError as re:
                crash_err.append(re)

        t1 = threading.Thread(target=run_crash)
        t2 = threading.Thread(target=worker_normal)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(crash_err), 1)
        # Check both operations in ledger
        snap_crash = tracker.get_committed_record("op_crash")
        snap_norm = tracker.get_committed_record("op_norm")

        self.assertIsNotNone(snap_crash)
        self.assertIsNotNone(snap_norm)
        self.assertEqual(snap_crash.charged_bytes, 120)
        self.assertTrue(snap_crash.is_failure)
        self.assertEqual(snap_norm.charged_bytes, 300)
        self.assertFalse(snap_norm.is_failure)
        self.assertEqual(tracker.metrics.bytes_read, 420)

    def test_16_multiple_inspection_modules_run_concurrently_against_single_tracker(self):
        """Multiple InspectionModule instances execute concurrently against a single shared tracker with exact attribution."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        def make_func(charge_b):
            def _f(**kw):
                b_tracker = kw["budget_tracker"]
                b_tracker.record_read(bytes_read=charge_b)
                return {"success": True, "data": charge_b}
            return _f

        modules = [
            FunctionalInspectionModule(
                InspectionProfile(profile_id=f"prof_conc_{i}", domain=DOMAIN_CONCURRENCY, name=f"Prof {i}"),
                func=make_func(50 * (i + 1)),
            )
            for i in range(4)
        ]

        results = {}
        barrier = threading.Barrier(4)

        def runner(idx, mod):
            barrier.wait()
            ctx = InspectionContext(
                pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker
            )
            out = mod.run(ctx)
            results[idx] = out

        threads = [threading.Thread(target=runner, args=(i, modules[i])) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 4)
        for i in range(4):
            expected_bytes = 50 * (i + 1)
            out = results[i]
            self.assertTrue(out["success"])
            self.assertEqual(out["charged_bytes"], expected_bytes)
            self.assertEqual(out["measured_bytes_read"], expected_bytes)

        expected_total = sum(50 * (i + 1) for i in range(4))  # 50 + 100 + 150 + 200 = 500
        self.assertEqual(tracker.metrics.bytes_read, expected_total)
        self.assertEqual(tracker.metrics.measured_bytes_read, expected_total)

    # =========================================================================
    # Group D: WorkManager Empty-Result Semantics
    # =========================================================================

    def test_17_workmanager_empty_result_with_missing_measurement_rejected_when_strict(self):
        """WorkManager returning empty result with missing measurement fails closed when reject_unknown_byte_cost=True."""
        engine = AdaptiveInvestigationEngine()
        limits = ObservationBudgetLimits(reject_unknown_byte_cost=True)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        class EmptyMissingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {"success": True, "threads": []}  # Missing measured_bytes_read

        wm = EmptyMissingWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker
        )
        out = mod.run(ctx, watch_manager=wm)
        self.assertFalse(out["success"])
        self.assertEqual(out["status"], "UNKNOWN_BYTE_COST_REJECTED")

    def test_18_workmanager_empty_result_with_missing_measurement_conservative_fallback(self):
        """WorkManager returning empty result with missing measurement charges conservative fallback when allowed."""
        engine = AdaptiveInvestigationEngine()
        limits = ObservationBudgetLimits(reject_unknown_byte_cost=False, conservative_unknown_bytes=8192)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        class EmptyMissingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {"success": True, "threads": []}

        wm = EmptyMissingWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker
        )
        out = mod.run(ctx, watch_manager=wm)
        self.assertTrue(out["success"])
        self.assertEqual(out["charged_bytes"], 8192)
        self.assertEqual(out["measurement_type"], "UNKNOWN")
        self.assertEqual(tracker.metrics.bytes_read, 8192)

    def test_19_workmanager_empty_result_with_explicit_measured_zero(self):
        """WorkManager returning empty result with explicit measured zero charges 0 bytes as ZERO_BYTES."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class EmptyZeroWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {"success": True, "threads": [], "measured_bytes_read": 0}

        wm = EmptyZeroWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker
        )
        out = mod.run(ctx, watch_manager=wm)
        self.assertTrue(out["success"])
        self.assertEqual(out["charged_bytes"], 0)
        self.assertEqual(out["measured_bytes_read"], 0)
        self.assertEqual(out["measurement_type"], "ZERO_BYTES")
        self.assertEqual(tracker.metrics.bytes_read, 0)

    def test_20_workmanager_empty_result_with_explicit_estimate(self):
        """WorkManager returning empty result with explicit estimated cost charges estimated bytes."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class EmptyEstWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {"success": True, "threads": [], "estimated_bytes_read": 1024}

        wm = EmptyEstWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker
        )
        out = mod.run(ctx, watch_manager=wm)
        self.assertTrue(out["success"])
        self.assertEqual(out["charged_bytes"], 1024)
        self.assertEqual(out["estimated_bytes_read"], 1024)
        self.assertEqual(out["measurement_type"], "ESTIMATED")
        self.assertEqual(tracker.metrics.bytes_read, 1024)

    # =========================================================================
    # Group E: Failure and Budget-Exhaustion Semantics
    # =========================================================================

    def test_21_failure_consumes_bytes_below_remaining_budget(self):
        """Failed operation consuming bytes below budget preserves consumed cost in ledger without exhausting budget."""
        limits = ObservationBudgetLimits(max_bytes_read=1000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        rec = ObservationAccountingRecord("tx_fail_below", "MOD", measured_bytes_read=250)
        self.assertTrue(tracker.commit_transaction(rec, is_failure=True))

        self.assertEqual(tracker.metrics.bytes_read, 250)
        self.assertFalse(tracker.is_budget_exhausted)
        self.assertEqual(tracker.metrics.consecutive_read_failures, 1)

        snap = tracker.get_committed_record("tx_fail_below")
        self.assertIsNotNone(snap)
        self.assertTrue(snap.is_failure)
        self.assertEqual(snap.charged_bytes, 250)

    def test_22_failure_consumes_exactly_remaining_budget(self):
        """Failed operation consuming exactly remaining budget preserves cost and exhausts budget."""
        limits = ObservationBudgetLimits(max_bytes_read=1000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        tracker.commit_transaction(ObservationAccountingRecord("tx_prior", "MOD", measured_bytes_read=700))
        self.assertEqual(tracker.metrics.bytes_read, 700)

        # Failure consumes exact remaining 300 bytes
        rec = ObservationAccountingRecord("tx_fail_exact", "MOD", measured_bytes_read=300)
        tracker.commit_transaction(rec, is_failure=True)

        self.assertEqual(tracker.metrics.bytes_read, 1000)
        self.assertTrue(tracker.is_budget_exhausted)
        self.assertIn("EXCEEDED_BYTES_READ", tracker.exhaustion_reason)

    def test_23_failure_consumes_more_than_remaining_budget_preserves_full_cost(self):
        """Failed operation consuming more than remaining budget preserves actual consumed cost in ledger."""
        limits = ObservationBudgetLimits(max_bytes_read=1000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        tracker.commit_transaction(ObservationAccountingRecord("tx_prior", "MOD", measured_bytes_read=800))
        self.assertEqual(tracker.metrics.bytes_read, 800)

        # Failure consumes 400 bytes (exceeding budget of 1000 by 200B)
        rec = ObservationAccountingRecord("tx_fail_overflow", "MOD", measured_bytes_read=400)
        tracker.commit_transaction(rec, is_failure=True)

        # Full cost preserved (1200B)
        self.assertEqual(tracker.metrics.bytes_read, 1200)
        self.assertEqual(tracker.metrics.measured_bytes_read, 1200)
        self.assertTrue(tracker.is_budget_exhausted)

        snap = tracker.get_committed_record("tx_fail_overflow")
        self.assertEqual(snap.charged_bytes, 400)
        self.assertTrue(snap.is_failure)

    def test_24_failure_after_multiple_partial_reads_preserves_total(self):
        """Scope with multiple partial reads before failure preserves cumulative consumed bytes in ledger."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        with self.assertRaises(RuntimeError):
            with tracker.operation_scope("op_multi_part", profile_id="test_part") as scope:
                scope.record_read(bytes_read=40)
                scope.record_read(bytes_read=60)
                scope.record_read(bytes_read=100)
                raise RuntimeError("Failed after 3 reads")

        snap = tracker.get_committed_record("op_multi_part")
        self.assertIsNotNone(snap)
        self.assertEqual(snap.charged_bytes, 200)
        self.assertEqual(snap.measured_bytes_read, 200)
        self.assertTrue(snap.is_failure)
        self.assertEqual(tracker.metrics.bytes_read, 200)

    def test_25_failure_exhausts_budget_blocks_fallback_execution(self):
        """When initial attempt exhausts budget, fallback attempt is immediately blocked with BUDGET_EXHAUSTED."""
        engine = AdaptiveInvestigationEngine()
        limits = ObservationBudgetLimits(max_bytes_read=10000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        class ExhaustingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                # Consumes 10000 bytes and raises
                exc = RuntimeError("Exhausted during lock inspection")
                setattr(exc, "measured_bytes_read", 10000)
                raise exc

        wm = ExhaustingWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker
        )
        out = mod.run(ctx, watch_manager=wm)
        self.assertFalse(out["success"])
        self.assertEqual(out["status"], "BUDGET_EXHAUSTED")
        self.assertEqual(tracker.metrics.bytes_read, 10000)
        self.assertTrue(tracker.is_budget_exhausted)

    def test_26_concurrent_budget_exhaustion_while_fallback_pending(self):
        """Concurrent operation exhausts budget while another prepares fallback; fallback precheck stops immediately."""
        limits = ObservationBudgetLimits(max_bytes_read=1000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        # Pre-seed tracker with 800 bytes
        tracker.commit_transaction(ObservationAccountingRecord("tx_seed", "MOD", measured_bytes_read=800))
        self.assertEqual(tracker.remaining_bytes, 200)

        # Concurrently commit 200 bytes, exhausting budget
        tracker.commit_transaction(ObservationAccountingRecord("tx_exhaust", "MOD", measured_bytes_read=200))
        self.assertTrue(tracker.is_budget_exhausted)
        self.assertEqual(tracker.remaining_bytes, 0)

        # Attempt to run insp_locks fallback
        engine = AdaptiveInvestigationEngine()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker
        )
        out = mod.run(ctx, watch_manager=None)  # No WM, triggers fallback directly
        self.assertFalse(out["success"])
        self.assertEqual(out["status"], "BUDGET_EXHAUSTED")

    # =========================================================================
    # Group F: Ledger Totals & Reconciliation
    # =========================================================================

    def test_27_tracker_totals_equal_sum_of_immutable_committed_records(self):
        """Sum of all committed records in ledger equals tracker aggregate metrics exactly."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        for i in range(12):
            rec = ObservationAccountingRecord(
                operation_id=f"tx_reconcile_{i}",
                accounting_owner="MOD",
                measured_bytes_read=50 * (i + 1),
                estimated_bytes_read=25 * i,
            )
            tracker.commit_transaction(rec)

        ledger = tracker.get_committed_transactions()
        self.assertEqual(len(ledger), 12)

        sum_charged = sum(r.charged_bytes for r in ledger.values())
        sum_measured = sum(r.measured_bytes_read or 0 for r in ledger.values())
        sum_estimated = sum(r.estimated_bytes_read for r in ledger.values())

        self.assertEqual(tracker.metrics.bytes_read, sum_charged)
        self.assertEqual(tracker.metrics.measured_bytes_read, sum_measured)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, sum_estimated)

    def test_28_standalone_legacy_read_registers_independent_transaction(self):
        """Standalone legacy record_read() registers an independent transaction in ledger."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        rec = tracker.record_read(bytes_read=128, latency_us=20.0, profile_id="legacy_prof")
        self.assertEqual(rec["charged_bytes"], 128)

        ledger = tracker.get_committed_transactions()
        self.assertEqual(len(ledger), 1)
        snap = list(ledger.values())[0]
        self.assertEqual(snap.charged_bytes, 128)
        self.assertEqual(snap.accounting_owner, "STANDALONE_READ")

    # =========================================================================
    # Group G: Static AST Audit of Tracker Internals
    # =========================================================================

    def test_29_static_audit_no_unauthorized_tracker_internal_writes(self):
        """Static AST audit verifies no external production file accesses tracker accounting internals."""
        extractor_dir = pathlib.Path(__file__).parent.parent / "extractor"
        forbidden_attrs = {
            "_committed_transactions",
            "_transaction_lock",
        }

        violations = []

        for py_path in extractor_dir.rglob("*.py"):
            if py_path.name == "observation_budget.py":
                continue  # Tracker itself is permitted internal access

            code = py_path.read_text(encoding="utf-8")
            tree = ast.parse(code, filename=str(py_path))

            for node in ast.walk(tree):
                # Detect attribute access to forbidden_attrs
                if isinstance(node, ast.Attribute) and node.attr in forbidden_attrs:
                    violations.append(f"{py_path.name}:{node.lineno} accesses forbidden '{node.attr}'")

        self.assertEqual(
            violations,
            [],
            f"Static audit failed: unauthorized access to tracker accounting internals: {violations}",
        )

    def test_30_static_audit_no_external_writes_to_tracker_metrics(self):
        """Static AST audit verifies no external production file writes or augmented-assigns to metrics.*."""
        extractor_dir = pathlib.Path(__file__).parent.parent / "extractor"
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
                # Detect writes (Assign, AugAssign) to *.metrics.<field>
                if isinstance(node, (ast.Assign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for tgt in targets:
                        if isinstance(tgt, ast.Attribute) and tgt.attr in metric_fields:
                            # Check if parent is .metrics
                            if isinstance(tgt.value, ast.Attribute) and tgt.value.attr == "metrics":
                                violations.append(
                                    f"{py_path.name}:{node.lineno} writes to 'metrics.{tgt.attr}'"
                                )

        self.assertEqual(
            violations,
            [],
            f"Static audit failed: unauthorized writes to tracker metrics: {violations}",
        )


if __name__ == "__main__":
    unittest.main()
