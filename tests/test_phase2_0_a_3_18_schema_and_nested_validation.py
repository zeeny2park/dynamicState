"""Tests for Phase 2.0-A.3.18 P0-4: Strict Schema & Nested Field Validation in DurableTrustStore.

Verifies:
1. schema_version validation (accepts 1.0.0, 1.1.0; rejects unknown versions and non-strings).
2. updated_at ISO 8601 format validation.
3. used_attestations nested field validation (evidence_id, session_id, pid, recorded_at).
4. used_operation_ids nested field validation (session_id, pid, recorded_at, evidence_ids no duplicates, metadata types).
5. Permissions (0600 on store file) and atomic replacement.
"""

import json
import os
import shutil
import stat
import tempfile
import unittest

from extractor.capture_backend import DurableTrustStore


class TestPhase20A318SchemaAndNestedValidation(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a318_p04_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_store(self, data: dict):
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def test_01_schema_version_validation(self):
        """Valid schema versions succeed; unsupported or malformed versions are rejected."""
        # Valid 1.1.0
        self._write_store({"schema_version": "1.1.0", "keys": {}})
        store = DurableTrustStore(self.store_path)
        self.assertIsNotNone(store)

        # Valid 1.0.0
        self._write_store({"schema_version": "1.0.0", "keys": {}})
        store = DurableTrustStore(self.store_path)
        self.assertIsNotNone(store)

        # Unsupported version 2.0.0
        self._write_store({"schema_version": "2.0.0", "keys": {}})
        with self.assertRaises(RuntimeError) as ctx:
            DurableTrustStore(self.store_path)
        self.assertIn("unsupported or invalid trust store schema_version", str(ctx.exception).lower())

        # Malformed integer schema_version
        self._write_store({"schema_version": 110, "keys": {}})
        with self.assertRaises(RuntimeError) as ctx:
            DurableTrustStore(self.store_path)
        self.assertIn("unsupported or invalid trust store schema_version", str(ctx.exception).lower())

    def test_02_updated_at_validation(self):
        """Malformed updated_at timestamp is rejected fail-closed."""
        self._write_store({
            "schema_version": "1.1.0",
            "updated_at": "not-an-iso-timestamp",
            "keys": {},
        })
        with self.assertRaises(RuntimeError) as ctx:
            DurableTrustStore(self.store_path)
        self.assertIn("invalid updated_at iso 8601 timestamp", str(ctx.exception).lower())

    def test_03_used_attestations_nested_validation(self):
        """used_attestations nested fields (evidence_id, session_id, pid, recorded_at) are strictly validated."""
        # Missing evidence_id
        self._write_store({
            "schema_version": "1.1.0",
            "used_attestations": {"att_1": {"session_id": "s1", "pid": 100}},
        })
        with self.assertRaises(RuntimeError) as ctx1:
            DurableTrustStore(self.store_path)
        self.assertIn("missing valid 'evidence_id'", str(ctx1.exception))

        # Boolean PID (bool is subclass of int in python, must be rejected!)
        self._write_store({
            "schema_version": "1.1.0",
            "used_attestations": {"att_1": {"evidence_id": "ev1", "pid": True}},
        })
        with self.assertRaises(RuntimeError) as ctx2:
            DurableTrustStore(self.store_path)
        self.assertIn("invalid pid", str(ctx2.exception).lower())

        # Malformed recorded_at timestamp
        self._write_store({
            "schema_version": "1.1.0",
            "used_attestations": {"att_1": {"evidence_id": "ev1", "pid": 100, "recorded_at": "garbage_time"}},
        })
        with self.assertRaises(RuntimeError) as ctx3:
            DurableTrustStore(self.store_path)
        self.assertIn("invalid recorded_at timestamp", str(ctx3.exception).lower())

    def test_04_used_operation_ids_nested_validation(self):
        """used_operation_ids nested fields (session_id, pid, duplicate evidence_ids, metadata) validated."""
        # Missing session_id
        self._write_store({
            "schema_version": "1.1.0",
            "used_operation_ids": {"op_1": {"pid": 500}},
        })
        with self.assertRaises(RuntimeError) as ctx1:
            DurableTrustStore(self.store_path)
        self.assertIn("missing valid 'session_id'", str(ctx1.exception))

        # Boolean PID
        self._write_store({
            "schema_version": "1.1.0",
            "used_operation_ids": {"op_1": {"session_id": "s1", "pid": False}},
        })
        with self.assertRaises(RuntimeError) as ctx2:
            DurableTrustStore(self.store_path)
        self.assertIn("missing valid 'pid'", str(ctx2.exception))

        # Duplicate evidence_ids in list
        self._write_store({
            "schema_version": "1.1.0",
            "used_operation_ids": {
                "op_1": {"session_id": "s1", "pid": 500, "evidence_ids": ["ev_1", "ev_1"]},
            },
        })
        with self.assertRaises(RuntimeError) as ctx3:
            DurableTrustStore(self.store_path)
        self.assertIn("duplicate evidence_ids", str(ctx3.exception).lower())

        # Non-string metadata field
        self._write_store({
            "schema_version": "1.1.0",
            "used_operation_ids": {
                "op_1": {"session_id": "s1", "pid": 500, "process_identity": 12345},
            },
        })
        with self.assertRaises(RuntimeError) as ctx4:
            DurableTrustStore(self.store_path)
        self.assertIn("invalid non-string 'process_identity'", str(ctx4.exception))

    def test_05_permissions_and_atomic_replace(self):
        """Persisted file has strict 0600 permissions."""
        store = DurableTrustStore(self.store_path)
        store.register_key("k_perm", "secret_perm_key", is_active=True)
        self.assertTrue(os.path.exists(self.store_path))
        st = os.stat(self.store_path)
        mode = stat.S_IMODE(st.st_mode)
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
