"""Unit tests for Metadata Monotonicity and Identity Conflict containment.

Verifies:
1. Empty or None incoming metadata never overwrites or erases existing identity fields (build_id, etc.).
2. Conflicting metadata raises IdentityConflictError.
3. Crucial invariant: A conflicting incoming request does NOT mutate an existing
   COMMITTED operation into FAILED. The existing committed record remains COMMITTED,
   while the conflicting attempt is rejected.
4. An IdentityConflictEvent is recorded for audit.
"""

import os
import tempfile
import unittest

from extractor.capture_backend import (
    DurableTrustStore,
    IdentityConflictError,
    OperationLifecycleState,
)


class TestTrustBoundaryMetadataConflict(unittest.TestCase):
    """Regression test suite for Metadata Monotonicity and Identity Conflict."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.tmpdir.name, "trust_store.json")
        self.store = DurableTrustStore(store_path=self.store_path)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_empty_metadata_preserves_existing_identity(self):
        """Injected empty or None metadata must never clear established build_id or target fields."""
        op_id = "op-monotonic-01"
        self.store.record_used_operation(
            op_id=op_id,
            session_id="sess-01",
            pid=1234,
            metadata={
                "build_id": "build-hash-aaaa",
                "process_identity": "proc-main",
                "target_host": "host-1",
            },
        )

        # Idempotent re-record with empty metadata dict
        self.store.record_used_operation(
            op_id=op_id,
            session_id="sess-01",
            pid=1234,
            metadata={},
            allow_idempotent=True,
        )

        record = self.store.used_operation_ids[op_id]
        self.assertEqual(record["build_id"], "build-hash-aaaa")
        self.assertEqual(record["process_identity"], "proc-main")
        self.assertEqual(record["target_host"], "host-1")

    def test_conflicting_metadata_raises_error_and_preserves_committed_state(self):
        """Conflicting incoming identity metadata must raise IdentityConflictError without corrupting existing record."""
        op_id = "op-conflict-01"
        self.store.record_used_operation(
            op_id=op_id,
            session_id="sess-01",
            pid=1234,
            metadata={
                "build_id": "build-hash-original",
                "process_identity": "proc-alpha",
                "state": OperationLifecycleState.COMMITTED.value,
            },
        )

        # Separate conflicting request attempt with different build_id
        with self.assertRaises(IdentityConflictError):
            self.store.record_used_operation(
                op_id=op_id,
                session_id="sess-01",
                pid=1234,
                metadata={
                    "build_id": "build-hash-DIFFERENT",
                },
                allow_idempotent=True,
            )

        # Existing record MUST still be COMMITTED and have original build_id!
        record = self.store.used_operation_ids[op_id]
        self.assertEqual(record["build_id"], "build-hash-original")
        self.assertEqual(record.get("state"), OperationLifecycleState.COMMITTED.value)

        # Verify conflict event is recorded for audit
        self.assertTrue(hasattr(self.store, "identity_conflict_events"))
        events = [e for e in self.store.identity_conflict_events if e.get("operation_id") == op_id]
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0]["field_name"], "build_id")
        self.assertEqual(events[0]["existing_value"], "build-hash-original")
        self.assertEqual(events[0]["attempted_value"], "build-hash-DIFFERENT")


if __name__ == "__main__":
    unittest.main()
