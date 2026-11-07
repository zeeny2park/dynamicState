"""Tests for Phase 2.0-A.3.18 P0-1: Persistence Failure Closure & Rollback Guarantees.

Verifies:
1. record_used_operation(allow_idempotent=True) never swallows save failures and rolls back mutations.
2. New operation registration rolls back in-memory mutation when save fails.
3. bind_operation_receipt rolls back in-memory mutation when save fails.
4. bind_operation_evidence rolls back in-memory mutation when save fails.
5. save() propagates os.chmod failures.
6. save() propagates file fsync failures.
7. save() propagates directory fsync failures.
8. Temporary files are cleaned up on all persistence failure paths.
"""

import errno
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from extractor.capture_backend import DurableTrustStore


class TestPhase20A318PersistenceFailureClosure(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a318_p01_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_idempotent_record_used_operation_propagates_save_failure_and_rolls_back(self):
        """record_used_operation(allow_idempotent=True) must NOT swallow save failures and must roll back."""
        # Record initial operation
        self.trust_store.record_used_operation(
            op_id="op_initial",
            session_id="sess_1",
            pid=1001,
            metadata={"process_identity": "proc_1", "initial_flag": "yes"},
        )
        self.assertIn("op_initial", self.trust_store.used_operation_ids)
        self.assertEqual(self.trust_store.used_operation_ids["op_initial"].get("initial_flag"), "yes")

        # Now attempt idempotent update while simulating save() failure
        with patch.object(self.trust_store, "save", side_effect=IOError("Simulated disk full during save")):
            with self.assertRaises(IOError) as ctx:
                self.trust_store.record_used_operation(
                    op_id="op_initial",
                    session_id="sess_1",
                    pid=1001,
                    metadata={"new_field": "should_be_rolled_back"},
                    allow_idempotent=True,
                )
            self.assertIn("Simulated disk full", str(ctx.exception))

        # Verify in-memory state was completely rolled back
        op_rec = self.trust_store.used_operation_ids["op_initial"]
        self.assertNotIn("new_field", op_rec)
        self.assertEqual(op_rec.get("initial_flag"), "yes")

    def test_02_new_operation_registration_rolls_back_on_save_failure(self):
        """New operation registration rolls back in-memory mutation when save() fails."""
        with patch.object(self.trust_store, "save", side_effect=RuntimeError("Disk failure")):
            with self.assertRaises(RuntimeError):
                self.trust_store.record_used_operation(
                    op_id="op_fail_new",
                    session_id="sess_fail",
                    pid=2002,
                )
        self.assertNotIn("op_fail_new", self.trust_store.used_operation_ids)

    def test_03_bind_operation_receipt_rolls_back_on_save_failure(self):
        """bind_operation_receipt rolls back in-memory mutation when save() fails."""
        self.trust_store.record_used_operation("op_bind", "sess_1", 3003)
        self.assertIsNone(self.trust_store.used_operation_ids["op_bind"].get("receipt_id"))

        with patch.object(self.trust_store, "save", side_effect=IOError("Write failed")):
            with self.assertRaises(IOError):
                self.trust_store.bind_operation_receipt("op_bind", "rcpt_fail")

        self.assertIsNone(self.trust_store.used_operation_ids["op_bind"].get("receipt_id"))

    def test_04_bind_operation_evidence_rolls_back_on_save_failure(self):
        """bind_operation_evidence rolls back in-memory mutation when save() fails."""
        self.trust_store.record_used_operation("op_ev", "sess_1", 4004)
        orig_eids = list(self.trust_store.used_operation_ids["op_ev"].get("evidence_ids", []))

        with patch.object(self.trust_store, "save", side_effect=IOError("Storage error")):
            with self.assertRaises(IOError):
                self.trust_store.bind_operation_evidence("op_ev", "ev_fail_1")

        cur_eids = self.trust_store.used_operation_ids["op_ev"].get("evidence_ids", [])
        self.assertEqual(cur_eids, orig_eids)
        self.assertNotIn("ev_fail_1", cur_eids)

    def test_05_save_propagates_chmod_failure(self):
        """save() must propagate os.chmod failure as RuntimeError and clean up temp file."""
        with patch("os.chmod", side_effect=PermissionError("Simulated chmod permission denied")):
            with self.assertRaises(RuntimeError) as ctx:
                self.trust_store.save()
            self.assertIn("Simulated chmod permission denied", str(ctx.exception))

        # Verify no tmp files leaked in directory
        tmp_files = [f for f in os.listdir(self.test_dir) if f.startswith(".trust_tmp_")]
        self.assertEqual(tmp_files, [])

    def test_06_save_propagates_file_fsync_failure(self):
        """save() must propagate file fsync failure as RuntimeError and clean up temp file."""
        real_fsync = os.fsync

        def mock_fsync(fd):
            # Only fail on regular file fsync (not directory)
            raise OSError(errno.EIO, "Simulated I/O error on file fsync")

        with patch("os.fsync", side_effect=mock_fsync):
            with self.assertRaises(RuntimeError) as ctx:
                self.trust_store.save()
            self.assertIn("Simulated I/O error on file fsync", str(ctx.exception))

        tmp_files = [f for f in os.listdir(self.test_dir) if f.startswith(".trust_tmp_")]
        self.assertEqual(tmp_files, [])

    def test_07_save_propagates_directory_fsync_failure(self):
        """save() must propagate directory fsync failure as RuntimeError."""
        real_fsync = os.fsync

        def mock_fsync_conditional(fd):
            # Fail directory fsync specifically
            import stat
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                raise OSError(errno.EIO, "Simulated I/O error on directory fsync")
            return real_fsync(fd)

        with patch("os.fsync", side_effect=mock_fsync_conditional):
            with self.assertRaises(RuntimeError) as ctx:
                self.trust_store.save()
            self.assertIn("Simulated I/O error on directory fsync", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
