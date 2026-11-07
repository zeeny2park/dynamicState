"""Tests for Phase 2.0-A.3.17 P0-5: DurableTrustStore Hardening, Locking & Mutation Safety.

Verifies:
1. Direct save() acquires _file_lock() and guarantees atomic persistence.
2. Re-entrant file lock does not deadlock on nested acquisitions within the same thread.
3. Permission errors during persistence propagate immediately to caller.
4. fsync failures propagate as exceptions and are not swallowed.
5. Schema validation rejects corrupted top-level and nested types with fail-closed RuntimeError.
6. Failed persistence cannot yield in-memory trust acceptance (rollback on failure).
7. POSIX/Linux assumptions are documented on DurableTrustStore.
"""

import errno
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from extractor.capture_backend import DurableTrustStore


class TestPhase20A317TrustStoreHardening(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a317_hardening_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_direct_save_locks_and_persists_atomically(self):
        """Direct save() executes under _file_lock() and updates file permissions to 0600."""
        self.trust_store.keys["test_key"] = "test_secret"
        self.trust_store.save()

        self.assertTrue(os.path.exists(self.store_path))
        st = os.stat(self.store_path)
        self.assertEqual(st.st_mode & 0o777, 0o600)

        # Reload from another instance
        store2 = DurableTrustStore(self.store_path)
        self.assertEqual(store2.keys.get("test_key"), "test_secret")

    def test_02_reentrant_file_lock_does_not_deadlock(self):
        """Re-entrant _file_lock() acquisitions on the same thread do not deadlock."""
        with self.trust_store._file_lock():
            self.assertEqual(self.trust_store._lock_depth, 1)
            with self.trust_store._file_lock():
                self.assertEqual(self.trust_store._lock_depth, 2)
                # Calling save() inside nested lock also enters _file_lock() cleanly
                self.trust_store.keys["k_nested"] = "sec_nested"
                self.trust_store.save()
            self.assertEqual(self.trust_store._lock_depth, 1)
        self.assertEqual(self.trust_store._lock_depth, 0)
        self.assertIsNone(self.trust_store._lock_fd)

    def test_03_permission_errors_propagate(self):
        """PermissionError during file creation or writing propagates and is not swallowed."""
        with patch("os.open", side_effect=PermissionError("Permission denied [simulated]")):
            with self.assertRaises((RuntimeError, PermissionError)) as ctx:
                self.trust_store.save()
            self.assertIn("Permission denied", str(ctx.exception))

    def test_04_fsync_failures_propagate(self):
        """fsync failure during save propagates as RuntimeError and does not swallow the error."""
        with patch("os.fsync", side_effect=OSError(errno.EIO, "I/O error on fsync")):
            with self.assertRaises(RuntimeError) as ctx:
                self.trust_store.save()
            self.assertIn("I/O error", str(ctx.exception))

    def test_05_schema_validation_rejects_malformed_nested_types(self):
        """Corrupted nested structures in trust store fail closed with RuntimeError."""
        # 1. Non-dict root
        with open(self.store_path, "w", encoding="utf-8") as f:
            f.write("[\"not_a_dict\"]")
        with self.assertRaises(RuntimeError):
            DurableTrustStore(self.store_path)

        # 2. Corrupted revoked_keys entry (missing revoked_at)
        bad_payload = {
            "schema_version": "1.1.0",
            "keys": {"k1": "sec1"},
            "revoked_keys": {"k1": {"reason": "missing_revoked_at"}},
        }
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump(bad_payload, f)
        with self.assertRaises(RuntimeError):
            DurableTrustStore(self.store_path)

        # 3. Corrupted used_operation_ids entry (missing session_id or pid)
        bad_payload2 = {
            "schema_version": "1.1.0",
            "keys": {},
            "used_operation_ids": {"op_1": {"no_session": True}},
        }
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump(bad_payload2, f)
        with self.assertRaises(RuntimeError):
            DurableTrustStore(self.store_path)

    def test_06_failed_persistence_rolls_back_in_memory_acceptance(self):
        """Failed persistence in record_used_operation and register_key rolls back in-memory state."""
        self.trust_store.save()  # Initialize file

        with patch.object(self.trust_store, "save", side_effect=OSError("Persistence failure")):
            with self.assertRaises(OSError):
                self.trust_store.record_used_operation("op_fail", "sess_fail", 1234)
            self.assertNotIn("op_fail", self.trust_store.used_operation_ids)

            with self.assertRaises(OSError):
                self.trust_store.register_key("k_fail", "sec_fail")
            self.assertNotIn("k_fail", self.trust_store.keys)

    def test_07_posix_linux_assumptions_documented(self):
        """DurableTrustStore class docstring thoroughly documents POSIX/Linux assumptions."""
        doc = DurableTrustStore.__doc__
        self.assertIsNotNone(doc)
        self.assertIn("POSIX / Linux Platform Assumptions", doc)
        self.assertIn("os.replace()", doc)
        self.assertIn("fcntl.flock", doc)
        self.assertIn("os.fsync", doc)
        self.assertIn("0600", doc)


if __name__ == "__main__":
    unittest.main()
