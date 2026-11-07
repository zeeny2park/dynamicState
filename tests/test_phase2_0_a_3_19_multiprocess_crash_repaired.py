#!/usr/bin/env python3
"""
Unit tests for Phase 2.0-A.3.19 P1-4: Repaired Multiprocess Crash & Real Persistence Failures.

Validates:
1. Real injected persistence failure (NOT_COMMITTED) with verified in-memory rollback.
2. Real injected directory fsync failure triggering COMMIT_UNKNOWN and disk reconciliation.
3. Explicit verification of worker termination and exit codes.
4. Bounded get(timeout=...) without relying on Queue.empty().
5. Crash before reservation, after durable reservation, after receipt binding, and exact recovery vs conflicting replay across process restart boundaries.
"""

import multiprocessing as mp
import os
import shutil
import stat
import tempfile
import unittest

from extractor.capture_backend import (
    CaptureKeyStore,
    CausalAttestation,
    CausalVerifierAuthority,
    DurableCommitError,
    DurableCommitOutcome,
    DurableTrustStore,
)


def _worker_injected_persistence_failure(store_path, op_id, res_q):
    """Worker that encounters a real disk write permission failure during save."""
    try:
        store = DurableTrustStore(store_path)
        store.load()
        # Revoke write permissions on the directory to inject a real OS persistence failure
        store_dir = os.path.dirname(store_path)
        orig_mode = os.stat(store_dir).st_mode
        try:
            os.chmod(store_dir, 0o500)
            caught_dce = False
            try:
                store.record_used_operation(op_id, "sess_fail", 9100)
            except DurableCommitError as dce:
                caught_dce = True
                rolled_back = op_id not in store.used_operation_ids
                res_q.put({
                    "outcome": dce.outcome.value,
                    "rolled_back": rolled_back,
                    "caught_dce": caught_dce,
                })
            except Exception as e:
                res_q.put({"error": f"Unexpected exception: {type(e).__name__}: {e}"})
        finally:
            os.chmod(store_dir, orig_mode)
    except Exception as outer_e:
        res_q.put({"error": f"Outer failure: {outer_e}"})


def _worker_injected_fsync_commit_unknown(store_path, op_id, res_q):
    """Worker where parent directory fsync fails after os.replace, triggering COMMIT_UNKNOWN."""
    try:
        store = DurableTrustStore(store_path)
        store.load()

        # Monkeypatch os.fsync to fail ONLY when called on a directory descriptor
        orig_fsync = os.fsync
        def bad_fsync(fd):
            try:
                st = os.fstat(fd)
                is_dir = stat.S_ISDIR(st.st_mode)
            except OSError:
                is_dir = False
            if is_dir:
                raise OSError(5, "Injected directory I/O error during fsync")
            return orig_fsync(fd)

        os.fsync = bad_fsync
        caught_unknown = False
        try:
            store.record_used_operation(op_id, "sess_unknown", 9101)
            res_q.put({"error": "Expected DurableCommitError was not raised"})
        except DurableCommitError as dce:
            caught_unknown = (dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN)
            # Verify reconciliation loaded the committed disk state
            reconciled = op_id in store.used_operation_ids
            res_q.put({
                "outcome": dce.outcome.value,
                "reconciled": reconciled,
                "caught_unknown": caught_unknown,
            })
        except Exception as e:
            res_q.put({"error": f"Unexpected exception: {type(e).__name__}: {e}"})
        finally:
            os.fsync = orig_fsync
    except Exception as outer_e:
        res_q.put({"error": f"Outer failure: {outer_e}"})


def _worker_crash_before_reservation(store_path, op_id, res_q):
    """Worker that crashes unconditionally before performing reservation."""
    store = DurableTrustStore(store_path)
    store.load()
    # Crash with distinct exitcode
    raise SystemExit(77)


def _worker_reserve_and_crash(store_path, op_id, session_id, pid, res_q):
    """Worker that successfully commits reservation to disk and then crashes."""
    store = DurableTrustStore(store_path)
    store.load()
    store.record_used_operation(op_id, session_id, pid)
    # Crash after reservation committed
    raise SystemExit(88)


def _worker_bind_receipt_and_crash(store_path, op_id, receipt_id, res_q):
    """Worker that binds receipt to operation and then crashes."""
    store = DurableTrustStore(store_path)
    store.load()
    store.bind_operation_receipt(op_id, receipt_id)
    # Crash after receipt bound
    raise SystemExit(99)


def _worker_verify_and_recover(store_path, op_id, session_id, pid, res_q):
    """Worker in a fresh process attempting idempotent recovery vs conflicting replay."""
    try:
        store = DurableTrustStore(store_path)
        store.load()
        # 1. Idempotent recovery with matching session & pid
        idem_ok = False
        try:
            store.record_used_operation(op_id, session_id, pid, allow_idempotent=True)
            idem_ok = True
        except Exception:
            idem_ok = False

        # 2. Conflicting replay with mismatched session
        conflict_detected = False
        try:
            store.record_used_operation(op_id, "sess_different_rogue", pid, allow_idempotent=True)
        except ValueError:
            conflict_detected = True

        res_q.put({
            "idem_ok": idem_ok,
            "conflict_detected": conflict_detected,
        })
    except Exception as e:
        res_q.put({"error": str(e)})


def _worker_verify_receipt_conflict(store_path, op_id, conflicting_rcpt, res_q):
    """Worker verifying receipt binding persistence after crash."""
    try:
        store = DurableTrustStore(store_path)
        store.load()
        conflict_ok = False
        try:
            store.bind_operation_receipt(op_id, conflicting_rcpt)
        except ValueError as ve:
            if "already bound to receipt" in str(ve):
                conflict_ok = True
        res_q.put({"conflict_ok": conflict_ok})
    except Exception as e:
        res_q.put({"error": str(e)})


class TestPhase20A319MultiprocessCrashRepaired(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a319_mp_repaired_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)
        self.trust_store.save()  # Initialize empty valid store on disk
        self.ctx = mp.get_context("spawn")

    def tearDown(self):
        # Restore permissions in case a test failed before cleanup
        try:
            os.chmod(self.test_dir, 0o700)
        except OSError:
            pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_real_injected_persistence_failure_rollback(self):
        """Worker experiencing real OS disk permission failure raises NOT_COMMITTED and rolls back in-memory."""
        res_q = self.ctx.Queue()
        p = self.ctx.Process(
            target=_worker_injected_persistence_failure,
            args=(self.store_path, "op_fail_01", res_q),
        )
        p.start()
        p.join(timeout=10)

        self.assertFalse(p.is_alive())
        self.assertEqual(p.exitcode, 0)

        # Bounded read without Queue.empty()
        res = res_q.get(timeout=5)
        self.assertNotIn("error", res)
        self.assertTrue(res["caught_dce"])
        self.assertEqual(res["outcome"], "NOT_COMMITTED")
        self.assertTrue(res["rolled_back"])

        # Verify disk state was unaffected
        self.trust_store.load()
        self.assertNotIn("op_fail_01", self.trust_store.used_operation_ids)

    def test_02_real_injected_fsync_commit_unknown_reconciliation(self):
        """Parent directory fsync failure after os.replace raises COMMIT_UNKNOWN and reconciles from disk."""
        res_q = self.ctx.Queue()
        p = self.ctx.Process(
            target=_worker_injected_fsync_commit_unknown,
            args=(self.store_path, "op_unknown_01", res_q),
        )
        p.start()
        p.join(timeout=10)

        self.assertFalse(p.is_alive())
        self.assertEqual(p.exitcode, 0)

        res = res_q.get(timeout=5)
        self.assertNotIn("error", res)
        self.assertTrue(res["caught_unknown"])
        self.assertEqual(res["outcome"], "COMMIT_UNKNOWN")
        self.assertTrue(res["reconciled"])

        # Verify disk contains the committed data
        fresh_store = DurableTrustStore(self.store_path)
        fresh_store.load()
        self.assertIn("op_unknown_01", fresh_store.used_operation_ids)

    def test_03_crash_before_reservation_termination_and_recovery(self):
        """Process crashing before reservation terminates with exitcode 77; store remains intact."""
        res_q = self.ctx.Queue()
        p = self.ctx.Process(
            target=_worker_crash_before_reservation,
            args=(self.store_path, "op_crash_pre", res_q),
        )
        p.start()
        p.join(timeout=10)

        self.assertFalse(p.is_alive())
        self.assertEqual(p.exitcode, 77)

        # Store should not contain the operation
        self.trust_store.load()
        self.assertNotIn("op_crash_pre", self.trust_store.used_operation_ids)

    def test_04_crash_after_reservation_exact_recovery_and_replay_rejection(self):
        """Process crashes after durable reservation (exitcode 88); restart recovers idempotently and rejects conflict."""
        res_q = self.ctx.Queue()
        op_id = "op_crash_post"
        sess = "sess_post_crash"
        pid = 9200

        # Worker 1 commits reservation and crashes
        p1 = self.ctx.Process(
            target=_worker_reserve_and_crash,
            args=(self.store_path, op_id, sess, pid, res_q),
        )
        p1.start()
        p1.join(timeout=10)
        self.assertFalse(p1.is_alive())
        self.assertEqual(p1.exitcode, 88)

        # Worker 2 in fresh process tests idempotent recovery vs conflicting replay
        p2 = self.ctx.Process(
            target=_worker_verify_and_recover,
            args=(self.store_path, op_id, sess, pid, res_q),
        )
        p2.start()
        p2.join(timeout=10)
        self.assertFalse(p2.is_alive())
        self.assertEqual(p2.exitcode, 0)

        res = res_q.get(timeout=5)
        self.assertNotIn("error", res)
        self.assertTrue(res["idem_ok"], "Idempotent recovery should succeed")
        self.assertTrue(res["conflict_detected"], "Conflicting replay should be rejected")

    def test_05_crash_after_receipt_binding_conflict_enforcement(self):
        """Process crashes after binding receipt (exitcode 99); subsequent worker rejects conflicting receipt."""
        res_q = self.ctx.Queue()
        op_id = "op_rcpt_crash"
        rcpt_id = "rcpt_bound_alpha"

        # Pre-record operation
        self.trust_store.record_used_operation(op_id, "sess_rcpt", 9300)

        # Worker 1 binds receipt and crashes
        p1 = self.ctx.Process(
            target=_worker_bind_receipt_and_crash,
            args=(self.store_path, op_id, rcpt_id, res_q),
        )
        p1.start()
        p1.join(timeout=10)
        self.assertFalse(p1.is_alive())
        self.assertEqual(p1.exitcode, 99)

        # Worker 2 verifies that conflicting receipt is rejected
        p2 = self.ctx.Process(
            target=_worker_verify_receipt_conflict,
            args=(self.store_path, op_id, "rcpt_conflicting_beta", res_q),
        )
        p2.start()
        p2.join(timeout=10)
        self.assertFalse(p2.is_alive())
        self.assertEqual(p2.exitcode, 0)

        res = res_q.get(timeout=5)
        self.assertNotIn("error", res)
        self.assertTrue(res["conflict_ok"], "Conflicting receipt must be rejected")


if __name__ == "__main__":
    unittest.main()
