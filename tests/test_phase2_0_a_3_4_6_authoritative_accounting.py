"""Phase 2.0-A.3.4.6 — Authoritative Accounting Transactions & Unknown-Cost Closure.

Adversarial regression test suite validating:
Group A: Transaction correctness
- Duplicate commit in one thread (idempotent, no double-charge).
- Concurrent duplicate commit from multiple threads (thread-safe, exactly-once).
- Commit failure due to malformed numeric values.
- Interrupted commit and failure cost preservation.
- Invalid transaction state transitions.
- Operation ID collision with conflicting parameters.
- Repeated operation IDs across independent sessions.

Group B: Unknown-cost handling
- Successful WorkManager result with no byte metadata (conservative unknown cost).
- Successful result with explicit measured zero (ZERO_BYTES, 0 cost).
- Successful result with estimated bytes (ESTIMATED, preserved).
- WorkManager exception with no byte metadata (conservative unknown cost).
- Malformed estimate values rejected strictly.
- reject_unknown_byte_cost enabled fails closed on missing metadata.
- Unknown cost at exact budget boundary.

Group C: Cross-layer ownership
- WorkManager commits and InspectionModule does not charge again.
- Adapter commits and InspectionModule does not charge again.
- Spoofed dictionary claiming COMMITTED is detected and authoritatively charged.
- Spoofed MODULE_INTERNAL without tracker commit is authoritatively charged.
- Exception after partial accounting reconciled without double-charging.

Group D: Metrics reconciliation
- Mixed operation (measured + estimated) reconciliation.
- Cache hit reconciliation (0 current measured bytes, 0 charged).
- Tracker totals equal the sum of authoritative operation records.
- Concurrent distinct operations reconciliation.

Group E: Budget enforcement & Exact Boundary Testing
- Remaining budget equals measured cost.
- Remaining budget is one byte below measured cost.
- First attempt exhausts budget before fallback, blocking fallback.
- Fallback itself exhausts budget, stopping gracefully.

Group F: Full regression
- Real two-thread circular deadlock fixture confirmation.
- Remote adapter namespace isolation and provenance.
"""

import math
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock
from typing import Any, Dict, List, Optional, Tuple

from extractor.target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    RemoteSshTargetAdapter,
    IDENTITY_VERIFIED,
    IDENTITY_UNAVAILABLE,
    IDENTITY_INCONSISTENT,
    IDENTITY_UNVERIFIED,
    STATUS_OWNER_IDENTIFIED,
    STATUS_OWNER_NOT_IDENTIFIED,
    LAYOUT_GLIBC_LP64,
)
from extractor.debug_image import (
    BinaryIdentity,
    clear_elf_identity_cache,
)
from extractor.adaptive_engine import (
    AdaptiveInvestigationEngine,
    WaitForEdge,
    WaitForGraph,
    RESULT_DEADLOCK_CYCLE_CONFIRMED,
    RESULT_LOCK_CONTENTION_OBSERVED,
    RESULT_INCONCLUSIVE,
)
from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    ObservationAccountingRecord,
    DEFAULT_CONSERVATIVE_UNKNOWN_BYTES,
    validate_non_negative_int,
    validate_non_negative_float,
)
from extractor.inspection_module import (
    FunctionalInspectionModule,
    InspectionContext,
    InspectionProfile,
    DOMAIN_CONCURRENCY,
)


class TestPhase20A346AuthoritativeAccounting(unittest.TestCase):
    """Deterministic adversarial test suite for Phase 2.0-A.3.4.6."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_a346_")
        cls.fixtures_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")
        )
        cls.bin_2way = os.path.join(cls.work_dir, "proc_2way_deadlock")

        src_path = os.path.join(cls.fixtures_dir, "proc_thread_circular_deadlock.c")
        if os.path.exists(src_path):
            cmd = ["gcc", "-O2", "-Wall", "-Wextra", "-pthread", src_path, "-o", cls.bin_2way]
            rc = subprocess.call(cmd)
            if rc != 0:
                raise RuntimeError(f"Failed to compile fixture {src_path} -> {cls.bin_2way}")

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.work_dir):
            shutil.rmtree(cls.work_dir, ignore_errors=True)

    def setUp(self):
        clear_elf_identity_cache()

    def _sample_valid_proc_identity(self, pid: int = 1000) -> Dict[str, Any]:
        return {
            "pid": pid,
            "process_start_time": 100000,
            "architecture": "x86_64",
            "elf_class": "ELF64",
            "endianness": "little",
            "executable": "/usr/bin/app",
            "identity_status": IDENTITY_VERIFIED,
            "measured_bytes_read": 128,
            "estimated_bytes_read": 0,
            "charged_bytes": 128,
            "accounting_status": "COMMITTED",
        }

    # =========================================================================
    # Group A: Transaction Correctness
    # =========================================================================

    def test_01_duplicate_commit_in_one_thread(self):
        """Duplicate commit in one thread is idempotent and never double-charges."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        record = ObservationAccountingRecord(
            operation_id="op_dup_single",
            accounting_owner="WORKMANAGER",
            measured_bytes_read=300,
            latency_us=50.0,
        )
        self.assertEqual(record.accounting_status, "PENDING")

        ok1 = record.commit(tracker)
        self.assertTrue(ok1)
        self.assertEqual(record.accounting_status, "COMMITTED")
        self.assertEqual(tracker.metrics.measured_bytes_read, 300)
        self.assertEqual(tracker.metrics.bytes_read, 300)
        self.assertEqual(tracker.metrics.observation_latency_us, 50.0)

        # Second commit must be a no-op
        ok2 = record.commit(tracker)
        self.assertTrue(ok2)
        self.assertEqual(record.accounting_status, "COMMITTED")
        self.assertEqual(tracker.metrics.measured_bytes_read, 300)
        self.assertEqual(tracker.metrics.bytes_read, 300)
        self.assertEqual(tracker.metrics.observation_latency_us, 50.0)

        # Exactly one history commit event
        commit_events = [e for e in tracker._history if e.get("event") == "TRANSACTION_COMMIT"]
        self.assertEqual(len(commit_events), 1)

    def test_02_concurrent_duplicate_commit_from_multiple_threads(self):
        """Concurrent commits for the same operation_id from multiple threads charge exactly once."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        record = ObservationAccountingRecord(
            operation_id="op_concurrent_dup",
            accounting_owner="WORKMANAGER",
            measured_bytes_read=450,
            latency_us=120.0,
        )

        results = []
        threads = []

        def worker():
            ok = tracker.commit_transaction(record)
            results.append(ok)

        for _ in range(12):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(len(results), 12)
        self.assertTrue(all(results))
        self.assertEqual(tracker.metrics.measured_bytes_read, 450)
        self.assertEqual(tracker.metrics.bytes_read, 450)
        self.assertEqual(tracker.metrics.observation_latency_us, 120.0)

        commit_events = [e for e in tracker._history if e.get("event") == "TRANSACTION_COMMIT"]
        self.assertEqual(len(commit_events), 1)

    def test_03_commit_failure_due_to_malformed_numeric(self):
        """Malformed numeric values cause commit to fail and transition to FAILED without charging."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        # Test boolean rejection
        rec_bool = ObservationAccountingRecord(
            operation_id="op_bad_bool",
            accounting_owner="TOOL",
            measured_bytes_read=True,  # type: ignore
        )
        with self.assertRaises(ValueError):
            tracker.commit_transaction(rec_bool)
        self.assertEqual(rec_bool.accounting_status, "FAILED")
        self.assertFalse(tracker.is_operation_committed("op_bad_bool"))
        self.assertEqual(tracker.metrics.bytes_read, 0)

        # Test negative rejection
        rec_neg = ObservationAccountingRecord(
            operation_id="op_bad_neg",
            accounting_owner="TOOL",
            estimated_bytes_read=-50,
        )
        with self.assertRaises(ValueError):
            tracker.commit_transaction(rec_neg)
        self.assertEqual(rec_neg.accounting_status, "FAILED")

        # Test NaN rejection
        rec_nan = ObservationAccountingRecord(
            operation_id="op_bad_nan",
            accounting_owner="TOOL",
            latency_us=float("nan"),
        )
        with self.assertRaises(ValueError):
            tracker.commit_transaction(rec_nan)
        self.assertEqual(rec_nan.accounting_status, "FAILED")

    def test_04_interrupted_or_failing_commit_preserves_costs_on_failure(self):
        """Failed operations preserve known consumed bytes and increment failure counters."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        record = ObservationAccountingRecord(
            operation_id="op_partial_fail",
            accounting_owner="TOOL",
            measured_bytes_read=250,
            latency_us=80.0,
        )

        ok = tracker.commit_transaction(record, is_failure=True)
        self.assertTrue(ok)
        self.assertEqual(record.accounting_status, "COMMITTED")
        self.assertEqual(tracker.metrics.measured_bytes_read, 250)
        self.assertEqual(tracker.metrics.bytes_read, 250)
        self.assertEqual(tracker.metrics.total_read_failures, 1)
        self.assertEqual(tracker.metrics.consecutive_read_failures, 1)

    def test_05_invalid_transaction_state_transitions(self):
        """ObservationAccountingRecord strictly enforces valid state machine transitions."""
        rec = ObservationAccountingRecord(operation_id="op_state", accounting_owner="TEST")
        self.assertEqual(rec.accounting_status, "PENDING")

        rec.transition_to("COMMITTED")
        self.assertEqual(rec.accounting_status, "COMMITTED")

        # COMMITTED -> PENDING is illegal
        with self.assertRaises(RuntimeError):
            rec.transition_to("PENDING")

        # COMMITTED -> FAILED is illegal
        with self.assertRaises(RuntimeError):
            rec.transition_to("FAILED")

        # Fresh record to FAILED
        rec_fail = ObservationAccountingRecord(operation_id="op_fail", accounting_owner="TEST")
        rec_fail.transition_to("FAILED")
        self.assertEqual(rec_fail.accounting_status, "FAILED")

        # FAILED -> COMMITTED is illegal
        with self.assertRaises(RuntimeError):
            rec_fail.transition_to("COMMITTED")

        # Arbitrary status is illegal
        with self.assertRaises(ValueError):
            rec_fail.transition_to("UNKNOWN_STATUS")

    def test_06_operation_id_collision_conflicting_parameters(self):
        """Different records with the same operation_id but conflicting parameters raise collision error."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        rec1 = ObservationAccountingRecord(
            operation_id="op_shared_id",
            accounting_owner="OWNER_A",
            measured_bytes_read=100,
        )
        ok1 = tracker.commit_transaction(rec1)
        self.assertTrue(ok1)
        self.assertEqual(tracker.metrics.bytes_read, 100)

        # Different record with conflicting owner and charge
        rec2 = ObservationAccountingRecord(
            operation_id="op_shared_id",
            accounting_owner="OWNER_B",
            measured_bytes_read=600,
        )
        with self.assertRaises(ValueError) as ctx:
            tracker.commit_transaction(rec2)
        self.assertIn("Operation ID collision", str(ctx.exception))
        # Tracker charge unchanged
        self.assertEqual(tracker.metrics.bytes_read, 100)

    def test_07_repeated_operation_ids_across_independent_sessions(self):
        """Independent tracker sessions can safely use identical operation_ids without interference."""
        tracker1 = ObservationBudgetTracker()
        tracker1.start()
        tracker2 = ObservationBudgetTracker()
        tracker2.start()

        rec1 = ObservationAccountingRecord(
            operation_id="common_op_id",
            accounting_owner="MOD",
            measured_bytes_read=150,
        )
        rec2 = ObservationAccountingRecord(
            operation_id="common_op_id",
            accounting_owner="MOD",
            measured_bytes_read=250,
        )

        ok1 = tracker1.commit_transaction(rec1)
        ok2 = tracker2.commit_transaction(rec2)

        self.assertTrue(ok1)
        self.assertTrue(ok2)
        self.assertEqual(tracker1.metrics.bytes_read, 150)
        self.assertEqual(tracker2.metrics.bytes_read, 250)

    # =========================================================================
    # Group B: Unknown-Cost Handling
    # =========================================================================

    def test_08_workmanager_success_with_no_byte_metadata(self):
        """Successful WorkManager result with missing byte metadata uses conservative unknown cost."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class MissingCostWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {
                    "success": True,
                    "threads": [{"tid": 101, "state": "S"}],
                    # No measured_bytes_read, estimated_bytes_read, or bytes_read
                }

        wm = MissingCostWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)

        self.assertTrue(out["success"])
        self.assertIsNone(out["measured_bytes_read"])
        self.assertGreater(out["estimated_bytes_read"], 0)
        self.assertEqual(out["charged_bytes"], out["estimated_bytes_read"])
        self.assertEqual(out["measurement_type"], "UNKNOWN")
        self.assertEqual(out["accounting_owner"], "WORKMANAGER")
        self.assertEqual(out["accounting_status"], "COMMITTED")
        self.assertEqual(tracker.metrics.measured_bytes_read, 0)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, out["charged_bytes"])

    def test_09_workmanager_success_with_explicit_measured_zero(self):
        """Explicit measured zero bytes remains distinguished from missing measurements."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class ExplicitZeroWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {
                    "success": True,
                    "threads": [{"tid": 102, "state": "S"}],
                    "measured_bytes_read": 0,
                }

        wm = ExplicitZeroWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)

        self.assertTrue(out["success"])
        self.assertEqual(out["measured_bytes_read"], 0)
        self.assertEqual(out["estimated_bytes_read"], 0)
        self.assertEqual(out["charged_bytes"], 0)
        self.assertEqual(out["measurement_type"], "ZERO_BYTES")
        self.assertEqual(out["accounting_status"], "COMMITTED")
        self.assertEqual(tracker.metrics.bytes_read, 0)

    def test_10_workmanager_success_with_explicit_estimated_bytes(self):
        """WorkManager returning explicit estimated_bytes_read is preserved without fabrication."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class EstimatedWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {
                    "success": True,
                    "threads": [{"tid": 103, "state": "S"}],
                    "estimated_bytes_read": 750,
                }

        wm = EstimatedWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)

        self.assertTrue(out["success"])
        self.assertIsNone(out["measured_bytes_read"])
        self.assertEqual(out["estimated_bytes_read"], 750)
        self.assertEqual(out["charged_bytes"], 750)
        self.assertEqual(out["measurement_type"], "ESTIMATED")
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 750)
        self.assertEqual(tracker.metrics.measured_bytes_read, 0)

    def test_11_workmanager_exception_with_no_byte_metadata(self):
        """WorkManager exception without byte metadata charges conservative unknown cost."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class ExcWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                raise RuntimeError("WM failure without metadata")

        wm = ExcWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)

        self.assertTrue(out["success"])  # Fallback succeeded
        self.assertGreaterEqual(tracker.metrics.total_read_failures, 1)
        # WM exception unknown cost was recorded
        self.assertGreater(tracker.metrics.conservative_estimated_bytes, 0)

    def test_12_workmanager_malformed_numeric_values_rejected(self):
        """Malformed numeric values in WorkManager results raise ValueError immediately."""
        engine = AdaptiveInvestigationEngine()
        mod = engine.registry.get("insp_locks")

        for bad_val in (True, -10, float("nan"), float("inf"), "invalid_str"):
            tracker = ObservationBudgetTracker()
            tracker.start()

            class BadWM:
                def inspect_thread_callstacks_and_locks(self, **kw):
                    return {
                        "success": True,
                        "threads": [{"tid": 104, "state": "S"}],
                        "measured_bytes_read": bad_val,
                    }

            ctx = InspectionContext(
                pid=os.getpid(),
                companion_elf="",
                adapter=LocalTargetAdapter(),
                budget_tracker=tracker,
            )
            out = mod.run(ctx, watch_manager=BadWM())
            self.assertFalse(out["success"])
            self.assertEqual(out["result_category"], "OBSERVATION_FAILED")
            self.assertEqual(out["error_code"], "ValueError")

    def test_13_reject_unknown_byte_cost_enabled_workmanager_success(self):
        """When reject_unknown_byte_cost is enabled, missing byte cost fails closed."""
        engine = AdaptiveInvestigationEngine()
        limits = ObservationBudgetLimits(reject_unknown_byte_cost=True)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        class MissingCostWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {
                    "success": True,
                    "threads": [{"tid": 105, "state": "S"}],
                }

        wm = MissingCostWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)

        self.assertFalse(out["success"])
        self.assertEqual(out["status"], "UNKNOWN_BYTE_COST_REJECTED")
        self.assertEqual(out["accounting_status"], "FAILED")
        self.assertEqual(tracker.metrics.bytes_read, 0)

    def test_14_reject_unknown_byte_cost_enabled_workmanager_exception(self):
        """When reject_unknown_byte_cost is enabled, WM exception with unknown cost fails closed."""
        engine = AdaptiveInvestigationEngine()
        limits = ObservationBudgetLimits(reject_unknown_byte_cost=True)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        class FailingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                raise RuntimeError("WM failure without metadata")

        wm = FailingWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)

        self.assertFalse(out["success"])
        self.assertEqual(out["status"], "UNKNOWN_BYTE_COST_REJECTED")
        self.assertEqual(tracker.metrics.bytes_read, 0)

    def test_15_unknown_cost_at_exact_budget_boundary(self):
        """Unknown cost is checked against remaining budget and rejected if it exceeds remaining."""
        # 1. Exact fit
        limits = ObservationBudgetLimits(max_bytes_read=DEFAULT_CONSERVATIVE_UNKNOWN_BYTES)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        record = ObservationAccountingRecord(
            operation_id="op_exact_boundary",
            accounting_owner="TOOL",
            measurement_type="UNKNOWN",
        )
        ok = tracker.commit_transaction(record)
        self.assertTrue(ok)
        self.assertEqual(tracker.metrics.bytes_read, DEFAULT_CONSERVATIVE_UNKNOWN_BYTES)

        # 2. 1 byte below remaining
        limits2 = ObservationBudgetLimits(max_bytes_read=DEFAULT_CONSERVATIVE_UNKNOWN_BYTES - 1)
        tracker2 = ObservationBudgetTracker(limits2)
        tracker2.start()

        record2 = ObservationAccountingRecord(
            operation_id="op_exceed_boundary",
            accounting_owner="TOOL",
            measurement_type="UNKNOWN",
        )
        ok2 = tracker2.commit_transaction(record2)
        self.assertFalse(ok2)
        self.assertEqual(record2.accounting_status, "FAILED")
        self.assertEqual(tracker2.metrics.bytes_read, 0)

    # =========================================================================
    # Group C: Cross-Layer Ownership
    # =========================================================================

    def test_16_workmanager_commits_module_does_not_charge_again(self):
        """When WorkManager authoritatively commits a transaction, InspectionModule does not double-charge."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class CommittingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                op_id = kw.get("operation_id", "wm_tx_1")
                b_tracker = kw.get("budget_tracker")
                rec = ObservationAccountingRecord(
                    operation_id=op_id,
                    accounting_owner="WORKMANAGER",
                    measured_bytes_read=500,
                    latency_us=40.0,
                )
                b_tracker.commit_transaction(rec)
                return {
                    "success": True,
                    "threads": [{"tid": 106, "state": "S"}],
                    "operation_id": op_id,
                    "measured_bytes_read": 500,
                    "accounting_owner": "WORKMANAGER",
                    "accounting_status": "COMMITTED",
                }

        wm = CommittingWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)

        self.assertTrue(out["success"])
        # Exactly 500 charged, NOT 1000
        self.assertEqual(tracker.metrics.bytes_read, 500)
        self.assertEqual(out["charged_bytes"], 500)
        self.assertEqual(out["accounting_status"], "COMMITTED")

    def test_17_adapter_commits_module_does_not_charge_again(self):
        """When adapter commits an identity transaction, module reconciles without double-charging."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        adapter = LocalTargetAdapter()
        # Call adapter directly with budget_tracker
        res = adapter.get_process_identity(os.getpid(), budget_tracker=tracker)
        self.assertEqual(res["accounting_status"], "COMMITTED")
        bytes_charged = res["charged_bytes"]
        self.assertEqual(tracker.metrics.bytes_read, bytes_charged)

        # FunctionalInspectionModule running the same op
        profile = InspectionProfile(profile_id="insp_id_test", domain=DOMAIN_CONCURRENCY, name="ID Test")
        mod = FunctionalInspectionModule(profile, func=lambda **kw: res)
        ctx = InspectionContext(pid=os.getpid(), companion_elf="", adapter=adapter, budget_tracker=tracker)
        out = mod.run(ctx)

        # Must not charge again
        self.assertEqual(tracker.metrics.bytes_read, bytes_charged)
        self.assertEqual(out["charged_bytes"], bytes_charged)

    def test_18_spoofed_dictionary_claimed_committed_is_detected_and_charged(self):
        """Arbitrary dictionary claiming COMMITTED without tracker commit is detected and charged."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        def spoofed_fn(**kw):
            # Function lies: claims COMMITTED and WORKMANAGER without ever touching tracker!
            return {
                "success": True,
                "measured_bytes_read": 350,
                "accounting_owner": "WORKMANAGER",
                "accounting_status": "COMMITTED",
                "already_budget_accounted": True,
            }

        profile = InspectionProfile(profile_id="test_spoof", domain=DOMAIN_CONCURRENCY, name="Spoof Test")
        mod = FunctionalInspectionModule(profile, func=spoofed_fn)
        ctx = InspectionContext(pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker)

        out = mod.run(ctx)
        self.assertTrue(out["success"])
        # Tracker was NOT bypassed! Module detected lack of authoritative commit and charged 350
        self.assertEqual(tracker.metrics.bytes_read, 350)
        self.assertEqual(tracker.metrics.measured_bytes_read, 350)
        self.assertEqual(out["charged_bytes"], 350)
        self.assertEqual(out["accounting_status"], "COMMITTED")

    def test_19_spoofed_module_internal_without_tracker_commit_is_charged(self):
        """Dictionary claiming MODULE_INTERNAL without tracker registration is authoritatively charged."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        def spoofed_internal(**kw):
            return {
                "success": True,
                "estimated_bytes_read": 200,
                "accounting_owner": "MODULE_INTERNAL",
                "accounting_status": "COMMITTED",
            }

        profile = InspectionProfile(profile_id="test_internal_spoof", domain=DOMAIN_CONCURRENCY, name="Internal Spoof")
        mod = FunctionalInspectionModule(profile, func=spoofed_internal)
        ctx = InspectionContext(pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker)

        out = mod.run(ctx)
        self.assertTrue(out["success"])
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 200)
        self.assertEqual(tracker.metrics.bytes_read, 200)

    def test_20_exception_after_partial_accounting_reconciled(self):
        """Partial charge before exception is preserved and not double-charged by exception handler."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        def partial_then_fail(**kw):
            b_tracker = kw["budget_tracker"]
            # Charge 120 bytes
            b_tracker.record_read(bytes_read=120, profile_id="test_fail_reconcile")
            raise RuntimeError("Crashed after partial read")

        profile = InspectionProfile(profile_id="test_fail_reconcile", domain=DOMAIN_CONCURRENCY, name="Partial Fail")
        mod = FunctionalInspectionModule(profile, func=partial_then_fail)
        ctx = InspectionContext(pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker)

        out = mod.run(ctx)
        self.assertFalse(out["success"])
        # Exactly 120 bytes charged, NOT double-charged
        self.assertEqual(tracker.metrics.bytes_read, 120)
        self.assertEqual(out["charged_bytes"], 120)

    # =========================================================================
    # Group D: Metrics Reconciliation
    # =========================================================================

    def test_21_mixed_operation_reconciliation(self):
        """Mixed operation preserves both measured and estimated byte components."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        record = ObservationAccountingRecord(
            operation_id="op_mixed",
            accounting_owner="MOD",
            measured_bytes_read=300,
            estimated_bytes_read=200,
        )
        ok = tracker.commit_transaction(record)
        self.assertTrue(ok)
        self.assertEqual(record.measurement_type, "MIXED")
        self.assertEqual(record.charged_bytes, 500)
        self.assertEqual(tracker.metrics.measured_bytes_read, 300)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 200)
        self.assertEqual(tracker.metrics.bytes_read, 500)

    def test_22_cache_hit_reconciliation(self):
        """CACHE_HIT records 0 measured bytes and 0 charged bytes."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        record = ObservationAccountingRecord(
            operation_id="op_cache_hit",
            accounting_owner="ADAPTER",
            measured_bytes_read=0,
            estimated_bytes_read=0,
            measurement_type="CACHE_HIT",
        )
        ok = tracker.commit_transaction(record)
        self.assertTrue(ok)
        self.assertEqual(record.charged_bytes, 0)
        self.assertEqual(tracker.metrics.measured_bytes_read, 0)
        self.assertEqual(tracker.metrics.bytes_read, 0)

    def test_23_tracker_totals_equal_sum_of_committed_records(self):
        """Mathematical reconciliation: tracker totals exactly equal sum of committed transactions."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        # Commit 5 distinct operations
        ops = [
            ObservationAccountingRecord("tx1", "MOD", measured_bytes_read=100),
            ObservationAccountingRecord("tx2", "MOD", estimated_bytes_read=200),
            ObservationAccountingRecord("tx3", "MOD", measured_bytes_read=300, estimated_bytes_read=50),
            ObservationAccountingRecord("tx4", "MOD", measured_bytes_read=0, measurement_type="ZERO_BYTES"),
            ObservationAccountingRecord("tx5", "MOD", measured_bytes_read=0, measurement_type="CACHE_HIT"),
        ]

        for op in ops:
            tracker.commit_transaction(op)

        committed = tracker.get_committed_transactions()
        self.assertEqual(len(committed), 5)

        total_charged = sum(r.charged_bytes for r in committed.values())
        total_meas = sum(r.measured_bytes_read or 0 for r in committed.values())
        total_est = sum(r.estimated_bytes_read or 0 for r in committed.values())

        self.assertEqual(tracker.metrics.bytes_read, total_charged)
        self.assertEqual(tracker.metrics.measured_bytes_read, total_meas)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, total_est)
        self.assertEqual(tracker.metrics.bytes_read, 650)
        self.assertEqual(tracker.metrics.measured_bytes_read, 400)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 250)

    def test_24_concurrent_operations_reconciliation(self):
        """Concurrent distinct operations maintain exact reconciliation."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        threads = []
        for i in range(10):
            rec = ObservationAccountingRecord(
                operation_id=f"tx_concurrent_{i}",
                accounting_owner="WORKER",
                measured_bytes_read=100 * (i + 1),
            )
            t = threading.Thread(target=tracker.commit_transaction, args=(rec,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        committed = tracker.get_committed_transactions()
        self.assertEqual(len(committed), 10)
        expected_total = sum(100 * (i + 1) for i in range(10))  # 5500
        self.assertEqual(tracker.metrics.bytes_read, expected_total)
        self.assertEqual(tracker.metrics.measured_bytes_read, expected_total)

    # =========================================================================
    # Group E: Budget Enforcement & Exact Boundary Testing
    # =========================================================================

    def test_25_remaining_budget_equals_measured_cost(self):
        """Operation whose cost exactly equals remaining budget succeeds; subsequent operation fails."""
        limits = ObservationBudgetLimits(max_bytes_read=1000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        # First operation: 800 bytes
        tracker.commit_transaction(ObservationAccountingRecord("tx_800", "MOD", measured_bytes_read=800))
        self.assertEqual(tracker.metrics.bytes_read, 800)

        # Remaining is exactly 200 bytes. Operation requiring 200 bytes succeeds
        ok = tracker.commit_transaction(ObservationAccountingRecord("tx_200", "MOD", measured_bytes_read=200))
        self.assertTrue(ok)
        self.assertEqual(tracker.metrics.bytes_read, 1000)

        # Next operation blocked
        ok_next = tracker.commit_transaction(ObservationAccountingRecord("tx_next", "MOD", measured_bytes_read=1))
        self.assertFalse(ok_next)

    def test_26_remaining_budget_one_byte_below_measured_cost(self):
        """Operation requiring 1 byte more than remaining budget is rejected at pre-check."""
        limits = ObservationBudgetLimits(max_bytes_read=1000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        # Charge 801 bytes. Remaining is 199 bytes
        tracker.commit_transaction(ObservationAccountingRecord("tx_801", "MOD", measured_bytes_read=801))
        self.assertEqual(tracker.metrics.bytes_read, 801)

        # Operation requiring 200 bytes is rejected
        rec_exceed = ObservationAccountingRecord("tx_exceed", "MOD", measured_bytes_read=200)
        ok = tracker.commit_transaction(rec_exceed)
        self.assertFalse(ok)
        self.assertEqual(rec_exceed.accounting_status, "FAILED")
        self.assertEqual(tracker.metrics.bytes_read, 801)

    def test_27_first_attempt_exhausts_budget_blocks_fallback(self):
        """When initial attempt exhausts remaining budget, fallback is blocked immediately."""
        limits = ObservationBudgetLimits(max_bytes_read=5000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        fallback_called = False

        class FailingSpyAdapter(LocalTargetAdapter):
            def get_threads(self, pid):
                nonlocal fallback_called
                fallback_called = True
                return []

        class ExhaustingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                # Simulate WM consuming 5000 bytes before failing
                err = RuntimeError("Exhausted during WM")
                setattr(err, "measured_bytes_read", 5000)
                raise err

        engine = AdaptiveInvestigationEngine()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=FailingSpyAdapter(),
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=ExhaustingWM())

        self.assertFalse(out["success"])
        self.assertEqual(out["status"], "BUDGET_EXHAUSTED")
        self.assertFalse(fallback_called)  # Fallback was blocked!

    def test_28_fallback_itself_exhausts_budget(self):
        """When fallback encounters budget limit during mutex reads, it stops with PARTIAL status."""
        limits = ObservationBudgetLimits(max_bytes_read=5000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        class FailingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                err = RuntimeError("Quick WM failure")
                setattr(err, "measured_bytes_read", 4800)
                raise err

        class LimitedAdapter(LocalTargetAdapter):
            def __init__(self):
                super().__init__()
                self._last_threads_bytes_read = 150

            def get_threads(self, pid):
                # 150 bytes read
                return [{"tid": 201, "state": "D", "is_futex_wait": True, "syscall_arg0": "0x1000"}]

            def resolve_mutex_owner(self, pid, addr):
                from extractor.target_adapter import MutexOwnerResolutionResult
                # 150 bytes read, exceeding remaining budget (4800 WM + 150 threads + 150 mutex = 5100 > 5000)
                return MutexOwnerResolutionResult(
                    owner_tid=None,
                    status=STATUS_OWNER_NOT_IDENTIFIED,
                    metadata={"read_bytes_len": 150, "latency_us": 10.0},
                )

        engine = AdaptiveInvestigationEngine()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LimitedAdapter(),
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=FailingWM())

        self.assertTrue(out["success"])
        self.assertEqual(out["status"], "PARTIAL")
        self.assertEqual(out["stop_reason"], "BUDGET_EXHAUSTED")

    # =========================================================================
    # Group F: Full Regression
    # =========================================================================

    def test_29_real_two_thread_circular_deadlock_confirmed(self):
        """Real two-thread circular deadlock fixture is confirmed with authoritative accounting."""
        if not os.path.exists(self.bin_2way):
            self.skipTest(f"Fixture binary not found: {self.bin_2way}")

        proc = subprocess.Popen([self.bin_2way], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.3)  # Allow fixture threads to deadlock
            adapter = LocalTargetAdapter()
            tracker = ObservationBudgetTracker()
            tracker.start()

            engine = AdaptiveInvestigationEngine()
            mod = engine.registry.get("insp_locks")
            ctx = InspectionContext(
                pid=proc.pid,
                companion_elf=self.bin_2way,
                adapter=adapter,
                budget_tracker=tracker,
                parameters={"sampling_epoch": 0},
            )

            res = mod.run(ctx)
            self.assertTrue(res["success"])
            self.assertEqual(res["result_category"], RESULT_DEADLOCK_CYCLE_CONFIRMED)
            self.assertTrue(res["deadlock_detected"])
            self.assertEqual(len(set(res["deadlock_cycle"])), 2)
            self.assertEqual(res["accounting_status"], "COMMITTED")
            self.assertGreater(tracker.metrics.bytes_read, 0)
        finally:
            proc.kill()
            proc.wait()

    def test_30_remote_adapter_isolation_and_provenance(self):
        """Remote target adapter operates within its remote namespace and records transaction."""
        adapter = RemoteSshTargetAdapter(host="remote.target.internal", port=2222, user="test")
        tracker = ObservationBudgetTracker()
        tracker.start()

        def fake_run_ssh(cmd, **kw):
            if "kill -0" in cmd or "test -d" in cmd:
                return 0, "ALIVE\n", ""
            elif "readlink" in cmd:
                return 0, "/usr/bin/remote_daemon\n", ""
            elif "stat" in cmd:
                stat_line = "1234 (remote_daemon) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 54321 1000 200"
                return 0, stat_line, ""
            return 1, "", "command not supported"

        adapter.run_ssh = fake_run_ssh

        res = adapter.get_process_identity(1234, budget_tracker=tracker)
        self.assertTrue(res["is_remote"])
        self.assertEqual(res["host"], adapter.target_host())
        self.assertEqual(res["process_start_time"], 54321)
        self.assertEqual(res["accounting_status"], "COMMITTED")
        self.assertTrue(tracker.is_operation_committed(res["operation_id"]))
        self.assertEqual(tracker.metrics.bytes_read, res["charged_bytes"])


if __name__ == "__main__":
    unittest.main()
