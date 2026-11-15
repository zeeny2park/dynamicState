"""Unit tests for Process Identity 4-tuple and Canonical Replay Identity integrity.

Verifies:
1. Process Identity matching strictly requires all 4 fields:
   (host_identity, boot_id, pid, process_start_time)
2. PID reuse defense: identical PID with different boot_id or process_start_time
   must be rejected as replay violation.
3. Canonical Operation Identity completeness and missing field fail-closed behavior.
"""

import os
import tempfile
import unittest

from extractor.capture_backend import (
    CanonicalOperationIdentity,
    DurableTrustStore,
    MissingIdentityFieldError,
    ProcessIdentity,
    ProcessIdentityMismatchError,
)


class TestTrustBoundaryReplayIdentity(unittest.TestCase):
    """Regression test suite for Replay Defense and Process Identity."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.tmpdir.name, "trust_store.json")
        self.store = DurableTrustStore(store_path=self.store_path)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_process_identity_equality_and_matching(self):
        """ProcessIdentity must require exact 4-tuple equality."""
        p1 = ProcessIdentity(
            host_identity="host-alpha",
            boot_id="boot-001",
            pid=4242,
            process_start_time=1000200,
        )
        p2 = ProcessIdentity(
            host_identity="host-alpha",
            boot_id="boot-001",
            pid=4242,
            process_start_time=1000200,
        )
        self.assertEqual(p1, p2)
        self.assertTrue(p1.matches(p2))

        # Different process_start_time (PID reuse in same boot)
        p_reused_pid = ProcessIdentity(
            host_identity="host-alpha",
            boot_id="boot-001",
            pid=4242,
            process_start_time=1055000,
        )
        self.assertNotEqual(p1, p_reused_pid)
        self.assertFalse(p1.matches(p_reused_pid))

        # Different boot_id (reboot with same PID)
        p_rebooted = ProcessIdentity(
            host_identity="host-alpha",
            boot_id="boot-002",
            pid=4242,
            process_start_time=1000200,
        )
        self.assertNotEqual(p1, p_rebooted)
        self.assertFalse(p1.matches(p_rebooted))

    def test_missing_mandatory_identity_field_fails_closed(self):
        """Missing or empty mandatory identity fields must raise MissingIdentityFieldError."""
        with self.assertRaises(MissingIdentityFieldError):
            CanonicalOperationIdentity(
                operation_id="op-001",
                operation_kind="LIVE_CAPTURE",
                process_identity=None,  # Missing ProcessIdentity
                build_id="build-abc",
                session_identity="sess-01",
                request_scope="scope-01",
                normalized_parameters={},
                schema_version="1.0",
            )

    def test_pid_reuse_rejection_in_store(self):
        """DurableTrustStore must reject operation replay when PID is reused across start times or boots."""
        op_id = "op-capture-100"
        session_id = "sess-alpha"

        # 1. Record initial operation
        self.store.record_used_operation(
            op_id=op_id,
            session_id=session_id,
            pid=5001,
            metadata={
                "host_identity": "host-alpha",
                "boot_id": "boot-111",
                "process_start_time": 200000,
                "build_id": "build-v1",
            },
        )

        # 2. Attempt to record same op_id on same PID, but different process_start_time (PID rollover)
        with self.assertRaises(ValueError) as ctx:
            self.store.record_used_operation(
                op_id=op_id,
                session_id=session_id,
                pid=5001,
                metadata={
                    "host_identity": "host-alpha",
                    "boot_id": "boot-111",
                    "process_start_time": 999999,  # Different start time
                    "build_id": "build-v1",
                },
                allow_idempotent=True,
            )
        self.assertIn("PID reuse", str(ctx.exception))

        # 3. Attempt to record same op_id on same PID, but different boot_id
        with self.assertRaises(ValueError) as ctx:
            self.store.record_used_operation(
                op_id=op_id,
                session_id=session_id,
                pid=5001,
                metadata={
                    "host_identity": "host-alpha",
                    "boot_id": "boot-222",  # Different boot_id
                    "process_start_time": 200000,
                    "build_id": "build-v1",
                },
                allow_idempotent=True,
            )
        self.assertIn("boot", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
