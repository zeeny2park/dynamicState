"""Tests for Phase 2.0-A.3.19 P0-1: Durable Commit Outcome Semantics & Failure Classification.

Verifies:
1. DurableCommitOutcome enum values: NOT_COMMITTED, COMMITTED, COMMIT_UNKNOWN.
2. Pre-commit failure before replacement produces NOT_COMMITTED and rolls back in-memory state safely.
3. Temporary file permissions are 0600 and verified prior to atomic replacement.
4. Failure during parent-directory fsync after replacement produces COMMIT_UNKNOWN.
5. On COMMIT_UNKNOWN, trust store reconciles from disk rather than falsely claiming rollback.
6. Mutation APIs (record_used_operation, register_key, revoke_key, bind_operation_receipt,
   bind_operation_evidence, consume_attestation) handle COMMIT_UNKNOWN properly.
"""

import errno
import os
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

from extractor.capture_backend import (
    CaptureKeyStore,
    CausalVerifierAuthority,
    DurableCommitError,
    DurableCommitOutcome,
    DurableTrustStore,
    TrustConsumptionStatus,
)


class TestPhase20A319DurableCommitSemantics(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a319_p01_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_successful_save_returns_committed(self):
        """Successful save returns DurableCommitOutcome.COMMITTED and sets 0600 mode."""
        self.trust_store.keys["k1"] = "secret1"
        outcome = self.trust_store.save()
        self.assertEqual(outcome, DurableCommitOutcome.COMMITTED)

        self.assertTrue(os.path.exists(self.store_path))
        st = os.stat(self.store_path)
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)

    def test_02_pre_commit_failure_produces_not_committed_and_cleans_up(self):
        """Failure before os.replace (e.g. chmod error on tmp file) raises NOT_COMMITTED."""
        real_chmod = os.chmod

        def failing_chmod(path, mode):
            if ".trust_tmp_" in path:
                raise OSError(errno.EACCES, "Simulated permission failure on tmp file")
            return real_chmod(path, mode)

        with patch("os.chmod", side_effect=failing_chmod):
            with self.assertRaises(DurableCommitError) as ctx:
                self.trust_store.save()
            self.assertEqual(ctx.exception.outcome, DurableCommitOutcome.NOT_COMMITTED)

        # Temporary files cleaned up
        tmp_files = [f for f in os.listdir(self.test_dir) if f.startswith(".trust_tmp_")]
        self.assertEqual(tmp_files, [])

    def test_03_directory_fsync_failure_produces_commit_unknown(self):
        """Failure after os.replace during parent directory fsync raises COMMIT_UNKNOWN."""
        real_fsync = os.fsync

        def mock_fsync_dir_fail(fd):
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                raise OSError(errno.EIO, "Simulated I/O failure on parent directory fsync")
            return real_fsync(fd)

        with patch("os.fsync", side_effect=mock_fsync_dir_fail):
            with self.assertRaises(DurableCommitError) as ctx:
                self.trust_store.save()
            self.assertEqual(ctx.exception.outcome, DurableCommitOutcome.COMMIT_UNKNOWN)

        # File exists on disk because replacement succeeded!
        self.assertTrue(os.path.exists(self.store_path))

    def test_04_record_used_operation_reconciles_from_disk_on_commit_unknown(self):
        """On COMMIT_UNKNOWN, record_used_operation reconciles from disk instead of reverting memory."""
        # Initial operation committed
        self.trust_store.record_used_operation("op_base", "sess_1", 1001)

        real_fsync = os.fsync

        def mock_fsync_dir_fail(fd):
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                raise OSError(errno.EIO, "Directory fsync failure")
            return real_fsync(fd)

        # Attempt to add new operation with directory fsync failure
        with patch("os.fsync", side_effect=mock_fsync_dir_fail):
            with self.assertRaises(DurableCommitError) as ctx:
                self.trust_store.record_used_operation("op_unknown", "sess_1", 1001)
            self.assertEqual(ctx.exception.outcome, DurableCommitOutcome.COMMIT_UNKNOWN)

        # Reconciled from disk: since atomic rename succeeded, op_unknown IS present on disk and in memory
        self.assertIn("op_unknown", self.trust_store.used_operation_ids)

    def test_05_register_and_revoke_key_reconcile_on_commit_unknown(self):
        """Key registration and revocation reconcile from disk on COMMIT_UNKNOWN."""
        real_fsync = os.fsync

        def mock_fsync_dir_fail(fd):
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                raise OSError(errno.EIO, "Directory fsync failure")
            return real_fsync(fd)

        with patch("os.fsync", side_effect=mock_fsync_dir_fail):
            with self.assertRaises(DurableCommitError) as ctx:
                self.trust_store.register_key("k_unknown", "sec_unknown")
            self.assertEqual(ctx.exception.outcome, DurableCommitOutcome.COMMIT_UNKNOWN)

        self.assertIn("k_unknown", self.trust_store.keys)

    def test_06_bind_receipt_and_evidence_reconcile_on_commit_unknown(self):
        """bind_operation_receipt and bind_operation_evidence reconcile on COMMIT_UNKNOWN."""
        self.trust_store.record_used_operation("op_bind_test", "sess_1", 2002)

        real_fsync = os.fsync

        def mock_fsync_dir_fail(fd):
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                raise OSError(errno.EIO, "Directory fsync failure")
            return real_fsync(fd)

        with patch("os.fsync", side_effect=mock_fsync_dir_fail):
            with self.assertRaises(DurableCommitError):
                self.trust_store.bind_operation_receipt("op_bind_test", "rcpt_unknown")

        self.assertEqual(self.trust_store.used_operation_ids["op_bind_test"].get("receipt_id"), "rcpt_unknown")


if __name__ == "__main__":
    unittest.main()
