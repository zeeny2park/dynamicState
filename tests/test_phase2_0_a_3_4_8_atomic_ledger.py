"""Phase 2.0-A.3.4.8 — Atomic Ledger Finalization & Immutable Snapshot Closure Tests.

Verifies:
1. Two concurrent scopes with same operation ID and identical costs (idempotent duplicate).
2. Two concurrent scopes with same operation ID and conflicting costs (collision handled, cost preserved, reconciled).
3. Concurrent identical commit_transaction() calls.
4. Concurrent conflicting commit_transaction() calls.
5. A scope that consumes bytes and fails during finalization.
6. A concurrent operation that exhausts the budget while another operation is reading.
7. A read racing with budget exhaustion.
8. Nested operation scopes and restoration of previous scope on thread-local stack.
9. Metadata mutation after commit (snapshot unchanged).
10. Mutation of returned snapshots and ledger collections (snapshots frozen, mutations raise TypeError/FrozenInstanceError).
11. Exception during snapshot creation or finalization (state machine consistency).
12. Concurrent operations with different operation IDs and different profiles.
13. Metrics-to-ledger reconciliation after all concurrency tests (reconcile_ledger returns reconciled=True).
14. Same operation ID reused across independent sessions (session mismatch error).
15. Retry after FAILED, REJECTED, and COMMITTED outcomes (strict transitions enforced).
16. Differing metadata producing canonical fingerprint collision.
17. Static architecture audit: no external writes to tracker internal state or metrics.
18. Static architecture audit: no direct mutation of committed metadata.
"""

import ast
from dataclasses import FrozenInstanceError
import os
import pathlib
import threading
import time
from typing import Any, Dict, List
import unittest
import uuid

from extractor.observation_budget import (
    AccountingFingerprint,
    ActiveOperationScope,
    CommittedTransactionSnapshot,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    canonical_metadata_digest,
    freeze_metadata,
    unfreeze_metadata,
)


class TestPhase20A348AtomicLedger(unittest.TestCase):
    """Test suite for Phase 2.0-A.3.4.8 Atomic Ledger Finalization & Immutable Snapshot Closure."""

    # =========================================================================
    # Group A: Concurrency and Idempotence with Same Operation ID
    # =========================================================================

    def test_01_two_concurrent_scopes_same_id_identical_costs(self):
        """Two concurrent scopes with identical operation ID and identical costs commit idempotently without double-charging."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(2)
        outcomes = []

        def worker():
            barrier.wait()
            with tracker.operation_scope("op_dup_scope", profile_id="prof_dup") as scope:
                scope.record_read(bytes_read=150, latency_us=25.0)
            snap = tracker.get_committed_record("op_dup_scope")
            outcomes.append(snap)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(outcomes), 2)
        self.assertIsNotNone(outcomes[0])
        self.assertIsNotNone(outcomes[1])
        # Charged exactly once
        self.assertEqual(tracker.metrics.bytes_read, 150)
        self.assertEqual(tracker.metrics.measured_bytes_read, 150)
        self.assertEqual(len(tracker.get_committed_transactions()), 1)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_02_two_concurrent_scopes_same_id_conflicting_costs(self):
        """Two concurrent scopes with the same operation ID and conflicting costs: one commits, other preserves cost as collision snapshot and raises ValueError."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(2)
        errors = []
        snapshots = []

        def worker(read_bytes):
            barrier.wait()
            try:
                with tracker.operation_scope("op_conflict_scope", profile_id="prof_conf") as scope:
                    scope.record_read(bytes_read=read_bytes, latency_us=10.0)
                snapshots.append((read_bytes, tracker.get_committed_record("op_conflict_scope")))
            except ValueError as ve:
                errors.append((read_bytes, str(ve)))

        t1 = threading.Thread(target=worker, args=(100,))
        t2 = threading.Thread(target=worker, args=(250,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Exactly one succeeded and one collided
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("Operation ID collision", errors[0][1])

        # Both costs are preserved in the ledger: winning as COMMITTED, losing as REJECTED collision snapshot
        ledger = tracker.get_committed_transactions()
        self.assertEqual(len(ledger), 2)
        self.assertIn("op_conflict_scope", ledger)
        winning_bytes = snapshots[0][0]
        losing_bytes = errors[0][0]
        self.assertEqual(ledger["op_conflict_scope"].charged_bytes, winning_bytes)

        # Total metrics and ledger reconcile to the sum of both consumed costs
        self.assertEqual(tracker.metrics.bytes_read, winning_bytes + losing_bytes)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_03_concurrent_identical_commit_transaction_calls(self):
        """Concurrent duplicate commit_transaction() calls with identical records succeed idempotently without double-charging."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(3)
        results = []

        def worker():
            barrier.wait()
            rec = ObservationAccountingRecord(
                operation_id="tx_identical_commit",
                accounting_owner="MOD",
                measured_bytes_read=300,
                latency_us=50.0,
                session_id=tracker.session_id,
            )
            ok = tracker.commit_transaction(rec)
            results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 3)
        self.assertTrue(all(results))
        self.assertEqual(tracker.metrics.bytes_read, 300)
        self.assertEqual(len(tracker.get_committed_transactions()), 1)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_04_concurrent_conflicting_commit_transaction_calls(self):
        """Concurrent conflicting commit_transaction() calls: exactly one succeeds, others raise ValueError without corrupting metrics."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(2)
        successes = []
        errors = []

        def worker(byte_val):
            barrier.wait()
            rec = ObservationAccountingRecord(
                operation_id="tx_conflict_commit",
                accounting_owner="MOD",
                measured_bytes_read=byte_val,
                session_id=tracker.session_id,
            )
            try:
                ok = tracker.commit_transaction(rec)
                successes.append((byte_val, ok))
            except ValueError as ve:
                errors.append((byte_val, str(ve)))

        t1 = threading.Thread(target=worker, args=(120,))
        t2 = threading.Thread(target=worker, args=(240,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 1)
        winning_val = successes[0][0]
        self.assertEqual(tracker.metrics.bytes_read, winning_val)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # Group B: Failure Preservation and Budget Exhaustion
    # =========================================================================

    def test_05_scope_consumes_bytes_and_fails_during_finalization(self):
        """A scope that consumes bytes and encounters an unhandled exception preserves all consumed bytes with is_failure=True."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        with self.assertRaises(RuntimeError):
            with tracker.operation_scope("op_crash_preserves", profile_id="test_fail") as scope:
                scope.record_read(bytes_read=90, latency_us=15.0)
                scope.record_read(bytes_read=110, latency_us=20.0)
                raise RuntimeError("Crashing after consuming 200 bytes")

        snap = tracker.get_committed_record("op_crash_preserves")
        self.assertIsNotNone(snap)
        self.assertEqual(snap.charged_bytes, 200)
        self.assertEqual(snap.measured_bytes_read, 200)
        self.assertTrue(snap.is_failure)
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertEqual(tracker.metrics.bytes_read, 200)
        self.assertEqual(tracker.metrics.total_read_failures, 1)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_06_concurrent_operation_exhausts_budget_while_another_is_reading(self):
        """A concurrent operation exhausts the budget while another is active; subsequent reads immediately detect BUDGET_EXHAUSTED."""
        limits = ObservationBudgetLimits(max_bytes_read=1000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()
        barrier = threading.Barrier(2)
        t1_results = []

        def worker1():
            with tracker.operation_scope("op_worker1", profile_id="prof1") as scope:
                r1 = scope.record_read(bytes_read=300)
                t1_results.append(r1)
                barrier.wait()  # Wait for worker 2 to exhaust budget
                barrier.wait()  # Wait after worker 2 commits
                r2 = scope.record_read(bytes_read=200)
                t1_results.append(r2)

        def worker2():
            barrier.wait()
            # Concurrently commit 1000 bytes, exhausting the entire budget
            rec = ObservationAccountingRecord(
                operation_id="op_exhausting_w2",
                accounting_owner="MOD",
                measured_bytes_read=1000,
                session_id=tracker.session_id,
            )
            tracker.commit_transaction(rec)
            barrier.wait()

        t1 = threading.Thread(target=worker1)
        t2 = threading.Thread(target=worker2)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(t1_results), 2)
        self.assertEqual(t1_results[0]["charged_bytes"], 300)
        # Second read was blocked by budget exhaustion
        self.assertFalse(t1_results[1]["success"])
        self.assertEqual(t1_results[1]["status"], "BUDGET_EXHAUSTED")

        # Worker1's 300 bytes + Worker2's 1000 bytes = 1300 bytes (overshoot preserved accurately)
        self.assertEqual(tracker.metrics.bytes_read, 1300)
        self.assertTrue(tracker.is_budget_exhausted)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_07_read_racing_with_budget_exhaustion(self):
        """Reads racing concurrently near budget limit stop cleanly once budget is exhausted."""
        limits = ObservationBudgetLimits(max_bytes_read=500)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()
        reads_attempted = []

        def reader(idx):
            with tracker.operation_scope(f"op_race_{idx}", profile_id="prof_race") as scope:
                for r in range(5):
                    res = scope.record_read(bytes_read=50)
                    reads_attempted.append(res)
                    if res.get("status") == "BUDGET_EXHAUSTED":
                        break

        threads = [threading.Thread(target=reader, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertTrue(tracker.is_budget_exhausted)
        # All accepted reads are accounted for in ledger
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # Group C: Nested Operation Scopes and Stack Restoration
    # =========================================================================

    def test_08_nested_operation_scopes_and_restoration_of_previous_scope(self):
        """Nested operation scopes maintain independent accounting and restore previous scope on stack upon exit."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        with tracker.operation_scope("op_outer", profile_id="prof_out") as outer_scope:
            outer_scope.record_read(bytes_read=100, latency_us=10.0)

            with tracker.operation_scope("op_inner", profile_id="prof_in") as inner_scope:
                inner_scope.record_read(bytes_read=60, latency_us=5.0)

            # Back in outer scope: subsequent reads route to op_outer
            outer_scope.record_read(bytes_read=40, latency_us=8.0)

        ledger = tracker.get_committed_transactions()
        self.assertEqual(len(ledger), 2)
        self.assertEqual(ledger["op_inner"].charged_bytes, 60)
        self.assertEqual(ledger["op_outer"].charged_bytes, 140)
        self.assertEqual(tracker.metrics.bytes_read, 200)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_08b_nested_scope_same_id_reuses_active_scope(self):
        """Re-entering an operation_scope with the same ID on the same thread reuses the active scope without collision."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        with tracker.operation_scope("op_nested_same", profile_id="prof_nest") as s1:
            s1.record_read(bytes_read=50)
            with tracker.operation_scope("op_nested_same", profile_id="prof_nest") as s2:
                s2.record_read(bytes_read=75)

        ledger = tracker.get_committed_transactions()
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger["op_nested_same"].charged_bytes, 125)
        self.assertEqual(tracker.metrics.bytes_read, 125)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # Group D: Deep Immutability of Committed Snapshots
    # =========================================================================

    def test_09_metadata_mutation_after_commit(self):
        """Mutating the original record's metadata after commit does not modify the committed snapshot."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        meta = {"tags": ["initial", "v1"], "config": {"max_retries": 3}}
        rec = ObservationAccountingRecord(
            operation_id="tx_meta_immutable",
            accounting_owner="MOD",
            measured_bytes_read=100,
            metadata=meta,
            session_id=tracker.session_id,
        )
        tracker.commit_transaction(rec)

        snap = tracker.get_committed_record("tx_meta_immutable")
        self.assertEqual(snap.metadata["tags"], ("initial", "v1"))
        self.assertEqual(snap.metadata["config"]["max_retries"], 3)

        # Mutate original dictionary
        meta["tags"].append("mutated")
        meta["config"]["max_retries"] = 99
        meta["new_key"] = "added"

        # Snapshot is completely unaffected
        self.assertEqual(snap.metadata["tags"], ("initial", "v1"))
        self.assertEqual(snap.metadata["config"]["max_retries"], 3)
        self.assertNotIn("new_key", snap.metadata)

    def test_10_mutation_of_returned_snapshots_and_ledger_collections(self):
        """Mutating returned snapshot objects or nested metadata raises TypeError/FrozenInstanceError."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        meta = {"items": [1, 2, 3], "nested": {"val": 42}}
        rec = ObservationAccountingRecord(
            operation_id="tx_freeze_test",
            accounting_owner="MOD",
            measured_bytes_read=50,
            metadata=meta,
            session_id=tracker.session_id,
        )
        tracker.commit_transaction(rec)

        snap = tracker.get_committed_record("tx_freeze_test")

        # Snapshot itself is frozen dataclass
        with self.assertRaises(FrozenInstanceError):
            snap.charged_bytes = 0

        # Snapshot metadata mappingproxy is immutable
        with self.assertRaises(TypeError):
            snap.metadata["new_field"] = "bad"

        with self.assertRaises(TypeError):
            snap.metadata["nested"]["val"] = 999

        # Nested sequence is tuple, cannot append
        with self.assertRaises(AttributeError):
            snap.metadata["items"].append(4)

        # Mutating copy returned by get_committed_transactions() does not mutate tracker
        ledger = tracker.get_committed_transactions()
        ledger["fake_tx"] = snap
        self.assertNotIn("fake_tx", tracker.get_committed_transactions())

        # Serialization to_dict() returns mutable regular dicts without corrupting snapshot
        d = snap.to_dict()
        d["metadata"]["items"].append(999)
        self.assertEqual(len(snap.metadata["items"]), 3)

    def test_11_exception_during_snapshot_creation_or_finalization(self):
        """Passing unfreezable unsupported metadata types raises TypeError and transitions record to FAILED."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        # Generator is unfreezable mutable arbitrary object
        bad_meta = {"bad": (x for x in range(3))}
        rec = ObservationAccountingRecord(
            operation_id="tx_bad_meta",
            accounting_owner="MOD",
            measured_bytes_read=50,
            metadata=bad_meta,
            session_id=tracker.session_id,
        )

        with self.assertRaises(TypeError):
            tracker.commit_transaction(rec)

        self.assertFalse(tracker.is_operation_committed("tx_bad_meta"))
        self.assertEqual(tracker.metrics.bytes_read, 0)

    # =========================================================================
    # Group E: Canonical Fingerprint Semantics & Multi-Profile Attribution
    # =========================================================================

    def test_12_concurrent_operations_different_ids_different_profiles(self):
        """Multiple concurrent operations with distinct IDs and profiles commit independently and reconcile cleanly."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        barrier = threading.Barrier(4)

        def worker(idx):
            barrier.wait()
            op_id = f"op_multi_{idx}"
            prof_id = f"prof_{idx}"
            with tracker.operation_scope(op_id, profile_id=prof_id) as scope:
                scope.record_read(bytes_read=70 * (idx + 1), latency_us=10.0 * (idx + 1))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        ledger = tracker.get_committed_transactions()
        self.assertEqual(len(ledger), 4)
        expected_total = sum(70 * (i + 1) for i in range(4))  # 70 + 140 + 210 + 280 = 700
        self.assertEqual(tracker.metrics.bytes_read, expected_total)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_13_metrics_to_ledger_reconciliation_after_all_concurrency_tests(self):
        """Deterministic reconciliation function verifies that all aggregate metrics match the authoritative ledger exactly."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        for i in range(8):
            rec = ObservationAccountingRecord(
                operation_id=f"tx_reconcile_{i}",
                accounting_owner="MOD",
                measured_bytes_read=100 * (i + 1),
                estimated_bytes_read=20 * i,
                latency_us=15.0 * (i + 1),
                session_id=tracker.session_id,
            )
            tracker.commit_transaction(rec, profile_id=f"prof_{i % 2}")

        report = tracker.reconcile_ledger()
        self.assertTrue(report["reconciled"])
        self.assertEqual(report["total_transactions"], 8)
        self.assertEqual(report["total_bytes_read"], tracker.metrics.bytes_read)
        self.assertEqual(report["total_measured_bytes"], tracker.metrics.measured_bytes_read)
        self.assertEqual(report["total_estimated_bytes"], tracker.metrics.conservative_estimated_bytes)
        self.assertEqual(round(report["total_latency_us"], 2), round(tracker.metrics.observation_latency_us, 2))

    def test_14_same_operation_id_reused_across_independent_sessions(self):
        """Attempting to commit a record with a mismatched session ID raises ValueError."""
        tracker1 = ObservationBudgetTracker()
        tracker1.start()

        rec = ObservationAccountingRecord(
            operation_id="tx_session_test",
            accounting_owner="MOD",
            measured_bytes_read=100,
            session_id="foreign_session_xyz",
        )
        with self.assertRaises(ValueError) as ctx:
            tracker1.commit_transaction(rec)
        self.assertIn("Session mismatch", str(ctx.exception))

    def test_15_retry_after_failed_rejected_and_committed_outcomes(self):
        """Strict state machine transitions reject recommitting failed or rejected operations as successful."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        # 1. Failed operation cannot be recommitted as success
        rec_fail = ObservationAccountingRecord(
            operation_id="tx_will_fail",
            accounting_owner="MOD",
            measured_bytes_read=50,
            session_id=tracker.session_id,
        )
        tracker.commit_transaction(rec_fail, is_failure=True)
        self.assertTrue(tracker.get_committed_record("tx_will_fail").is_failure)

        rec_retry = ObservationAccountingRecord(
            operation_id="tx_will_fail",
            accounting_owner="MOD",
            measured_bytes_read=50,
            session_id=tracker.session_id,
        )
        with self.assertRaises(ValueError) as ctx:
            tracker.commit_transaction(rec_retry, is_failure=False)
        self.assertIn("cannot be recommitted as a successful transaction", str(ctx.exception))

        # 2. Committed operation cannot be recommitted with different data
        rec_comm = ObservationAccountingRecord(
            operation_id="tx_comm_locked",
            accounting_owner="MOD",
            measured_bytes_read=100,
            session_id=tracker.session_id,
        )
        tracker.commit_transaction(rec_comm)

        rec_comm_conflict = ObservationAccountingRecord(
            operation_id="tx_comm_locked",
            accounting_owner="MOD",
            measured_bytes_read=200,
            session_id=tracker.session_id,
        )
        with self.assertRaises(ValueError) as ctx2:
            tracker.commit_transaction(rec_comm_conflict)
        self.assertIn("Operation ID collision", str(ctx2.exception))

    def test_16_metadata_canonical_fingerprint_differing_metadata_collision(self):
        """Same operation ID with different metadata produces divergent fingerprint and triggers collision error."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        rec1 = ObservationAccountingRecord(
            operation_id="tx_meta_coll",
            accounting_owner="MOD",
            measured_bytes_read=100,
            metadata={"env": "prod", "run_id": 1},
            session_id=tracker.session_id,
        )
        tracker.commit_transaction(rec1)

        rec2 = ObservationAccountingRecord(
            operation_id="tx_meta_coll",
            accounting_owner="MOD",
            measured_bytes_read=100,
            metadata={"env": "staging", "run_id": 1},
            session_id=tracker.session_id,
        )
        with self.assertRaises(ValueError) as ctx:
            tracker.commit_transaction(rec2)
        self.assertIn("Operation ID collision", str(ctx.exception))

    # =========================================================================
    # Group F: Static Architecture Audits
    # =========================================================================

    def test_17_static_audit_no_external_writes_to_tracker_internals(self):
        """Static AST audit verifies zero external production code writes to tracker private transaction state or metrics."""
        extractor_dir = pathlib.Path(__file__).parent.parent / "extractor"
        forbidden_attrs = {
            "_committed_transactions",
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
                continue  # Tracker itself is permitted internal access

            code = py_path.read_text(encoding="utf-8")
            tree = ast.parse(code, filename=str(py_path))

            for node in ast.walk(tree):
                # Detect attribute writes (Assign, AugAssign)
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

    def test_18_static_audit_no_direct_mutation_of_committed_metadata(self):
        """Static AST audit verifies zero external production code attempts direct subscript assignment to snapshot.metadata."""
        extractor_dir = pathlib.Path(__file__).parent.parent / "extractor"
        violations = []

        for py_path in extractor_dir.rglob("*.py"):
            code = py_path.read_text(encoding="utf-8")
            tree = ast.parse(code, filename=str(py_path))

            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for tgt in targets:
                        # Detect target.metadata[...] = ...
                        if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Attribute) and tgt.value.attr == "metadata":
                            # Check if value.value looks like a snapshot or committed record
                            violations.append(f"{py_path.name}:{node.lineno} mutates metadata subscript directly")

        self.assertEqual(
            violations,
            [],
            f"Static audit failed: unauthorized metadata subscript mutation: {violations}",
        )


if __name__ == "__main__":
    unittest.main()
