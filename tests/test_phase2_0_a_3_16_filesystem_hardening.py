"""Phase 2.0-A.3.16 Durable Trust Store Filesystem Hardening Tests.

Verifies:
1. Restrictive file permissions (0600) on persisted store file.
2. Symlink rejection on both load() and save() (TOCTOU protection).
3. Safe temporary file creation with atomic replacement.
4. Strict schema validation and fail-closed behavior on corrupted contents.
5. Incomplete or failed write cleanup (no lingering tmp files).
"""

import json
import os
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

from extractor.capture_backend import DurableTrustStore


class TestPhase20A316FilesystemHardening(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="a316_fs_")
        self.store_path = os.path.join(self.tmp_dir, "trust_store.json")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # 1. Restrictive file permissions (0600)
    def test_01_restrictive_file_permissions(self):
        store = DurableTrustStore(self.store_path)
        store.register_key("k_sec", "secret_value_123")
        self.assertTrue(os.path.exists(self.store_path))

        mode = stat.S_IMODE(os.stat(self.store_path).st_mode)
        # Permissions must be 0600 (read/write by owner only)
        self.assertEqual(mode, 0o600)

    # 2. Symlink rejection on save() and load()
    def test_02_symlink_rejection_save_and_load(self):
        target_real = os.path.join(self.tmp_dir, "real_target.json")
        symlink_path = os.path.join(self.tmp_dir, "symlink_store.json")
        os.symlink(target_real, symlink_path)

        # Attempt to save to symlink -> Refused fail-closed
        store_sym = DurableTrustStore(symlink_path)
        with self.assertRaises(RuntimeError) as ctx_save:
            store_sym.register_key("k_sym", "sec_sym")
        self.assertIn("refusing to save trust store to symlink", str(ctx_save.exception).lower())

        # Create real content in target_real
        with open(target_real, "w", encoding="utf-8") as f:
            f.write(json.dumps({"schema_version": "1.0.0", "keys": {}}))

        # Attempt to load from symlink -> Refused fail-closed
        with self.assertRaises(RuntimeError) as ctx_load:
            DurableTrustStore(symlink_path)
        self.assertIn("refusing to load trust store from symlink", str(ctx_load.exception).lower())

    # 3. Strict schema validation
    def test_03_strict_schema_validation(self):
        # Array instead of dictionary
        with open(self.store_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(["not", "a", "dict"]))
        with self.assertRaises(RuntimeError) as ctx1:
            DurableTrustStore(self.store_path)
        self.assertIn("must be a json dictionary", str(ctx1.exception).lower())

        # Malformed revoked_keys (list instead of dict)
        with open(self.store_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"keys": {}, "revoked_keys": ["k1"]}))
        with self.assertRaises(RuntimeError) as ctx2:
            DurableTrustStore(self.store_path)
        self.assertIn("revoked_keys' field must be a dictionary", str(ctx2.exception).lower())

        # Malformed used_operation_ids (list instead of dict)
        with open(self.store_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"keys": {}, "used_operation_ids": ["op1"]}))
        with self.assertRaises(RuntimeError) as ctx3:
            DurableTrustStore(self.store_path)
        self.assertIn("used_operation_ids' must be a dictionary", str(ctx3.exception).lower())

    # 4. Clean error handling on failed write (no leftover tmp files)
    def test_04_incomplete_write_cleaned_up(self):
        store = DurableTrustStore(self.store_path)

        # Force failure during atomic replace
        with patch("os.replace", side_effect=OSError("Disk write error")):
            with self.assertRaises(RuntimeError):
                store.register_key("k_fail", "sec_fail")

        # Verify no tmp files (.trust_tmp_*) left behind in tmp_dir
        tmp_files = [f for f in os.listdir(self.tmp_dir) if f.startswith(".trust_tmp_")]
        self.assertEqual(len(tmp_files), 0)


if __name__ == "__main__":
    unittest.main()
