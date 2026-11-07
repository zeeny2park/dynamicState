"""Tests for Phase 2.0-A.3.17 P0-2: Operation Lifecycle Integration into Trust Store.

Verifies:
1. CaptureTransaction commit records used operation into DurableTrustStore binding identity metadata.
2. Failed trust store persistence rolls back CaptureTransaction and leaves committed=False.
3. LiveCaptureReceipt issuance binds receipt_id to the operation in DurableTrustStore.
4. Binding a conflicting receipt_id to the same operation is rejected.
5. EvidenceLedger.add_record() binds operation and evidence_id in DurableTrustStore.
6. Reusing an operation ID across conflicting sessions, PIDs, or target identities is rejected.
"""

import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from extractor.capture_backend import (
    CaptureKeyStore,
    DurableTrustStore,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
    set_default_trust_store,
)
from extractor.evidence_ledger import EvidenceLedger, EvidenceRecord
from extractor.target_adapter import CaptureTransaction, TargetExecutionAdapter


class MockTargetExecutionAdapter(TargetExecutionAdapter):
    """Concrete mock target adapter for testing transaction commit and receipt issuance."""

    def __init__(self, trust_store=None):
        super().__init__()
        self._ensure_tracking_state()
        self.trust_store = trust_store
        self.mock_ident = {
            "pid": 1024,
            "start_time": 123456,
            "boot_id": "boot_mock_1",
            "process_identity": "1024:123456:boot_mock_1",
            "executable": "/usr/bin/target_mock",
            "executable_identity": "/usr/bin/target_mock:9999",
            "build_id": "sha1_mock_build_id",
            "exe_inode": 9999,
        }

    def get_process_identity(self, pid: int):
        return dict(self.mock_ident)

    def check_liveness(self, pid: int):
        return True, "Process running"

    def is_remote(self) -> bool:
        return False

    def target_host(self) -> str:
        return "localhost"

    def get_proc_maps(self, pid: int):
        return []

    def get_threads(self, pid: int):
        return []

    def read_memory(self, pid: int, address: int, size: int):
        data = b"\x42" * size
        self._record_physical_read(num_bytes=size, num_reads=1, data=data, pid=pid, address=address)
        return data, "OBSERVED", None


class TestPhase20A317OperationLifecycleIntegration(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a317_op_lifecycle_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)
        set_default_trust_store(self.trust_store)
        self.session_id = "sess_a317_op_test"
        self.pid = 1024
        self.adapter = MockTargetExecutionAdapter(trust_store=self.trust_store)

    def tearDown(self):
        set_default_trust_store(None)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_commit_transaction_records_operation_and_metadata(self):
        """Committing a CaptureTransaction records operation into DurableTrustStore with identity metadata."""
        tx = self.adapter.begin_capture_transaction(self.session_id, self.pid)
        self.adapter.read_memory(self.pid, 0x1000, 64)
        committed_tx = self.adapter.commit_capture_transaction(tx)

        self.assertTrue(committed_tx.committed)
        self.assertTrue(self.trust_store.is_operation_used(tx.transaction_id))

        op_rec = self.trust_store.used_operation_ids[tx.transaction_id]
        self.assertEqual(op_rec["session_id"], self.session_id)
        self.assertEqual(op_rec["pid"], self.pid)
        self.assertEqual(op_rec["process_identity"], self.adapter.mock_ident["process_identity"])
        self.assertEqual(op_rec["executable_identity"], self.adapter.mock_ident["executable_identity"])
        self.assertEqual(op_rec["build_id"], self.adapter.mock_ident["build_id"])
        self.assertEqual(op_rec["target_host"], "localhost")
        self.assertEqual(op_rec["physical_bytes_read"], 64)

    def test_02_persistence_failure_aborts_transaction_commit(self):
        """Failed trust store persistence during commit rolls back transaction and leaves committed=False."""
        tx = self.adapter.begin_capture_transaction(self.session_id, self.pid)
        self.adapter.read_memory(self.pid, 0x2000, 32)

        with patch.object(self.trust_store, "record_used_operation", side_effect=RuntimeError("Disk write simulated failure")):
            with self.assertRaises(RuntimeError):
                self.adapter.commit_capture_transaction(tx)

        self.assertFalse(tx.committed)
        self.assertTrue(tx.aborted)
        self.assertIn("Trust store persistence failed", tx.abort_reason)
        self.assertNotIn(tx.transaction_id, self.trust_store.used_operation_ids)

    def test_03_issue_receipt_binds_receipt_id_to_operation(self):
        """issue_live_receipt_for_session binds receipt_id to the operation in trust store."""
        tx = self.adapter.begin_capture_transaction(self.session_id, self.pid)
        self.adapter.read_memory(self.pid, 0x3000, 128)
        self.adapter.commit_capture_transaction(tx)

        rcpt = self.adapter.issue_live_receipt_for_session(
            session_id=self.session_id,
            pid=self.pid,
            transaction=tx,
        )
        self.assertTrue(tx.receipt_issued)

        # Verify receipt binding in trust store
        op_rec = self.trust_store.used_operation_ids[tx.transaction_id]
        self.assertEqual(op_rec.get("receipt_id"), rcpt.receipt_id)

        # Attempting to bind a conflicting receipt to the same operation is rejected
        with self.assertRaises(ValueError) as ctx:
            self.trust_store.bind_operation_receipt(tx.transaction_id, "live_rcpt_conflicting_forged")
        self.assertIn("already bound to receipt", str(ctx.exception))

    def test_04_ledger_add_record_binds_operation_and_evidence_id(self):
        """EvidenceLedger.add_record() binds operation and evidence_id in trust store."""
        tx = self.adapter.begin_capture_transaction(self.session_id, self.pid)
        self.adapter.read_memory(self.pid, 0x4000, 64)
        self.adapter.commit_capture_transaction(tx)
        rcpt = self.adapter.issue_live_receipt_for_session(
            session_id=self.session_id,
            pid=self.pid,
            transaction=tx,
        )

        ledger = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rec = EvidenceRecord(
            evidence_id="ev_op_bind_1",
            evidence_type="FIELD_OBSERVATION",
            nature="observation",
            source="runtime_collector",
            session_id=self.session_id,
            observation="Field value test",
            details={"operation_id": tx.transaction_id, "observation_digest": tx.observation_digest},
            provenance={"provenance_class": "LIVE_RUNTIME_CAPTURE", "live_capture_receipt": rcpt},
            target_identity=dict(self.adapter.mock_ident),
            snapshot_ref={"snapshot_id": rcpt.snapshot_binding, "epoch": 0},
            field_observation={"field_path": "test.field"},
        )
        ledger.add_record(rec)

        op_rec = self.trust_store.used_operation_ids[tx.transaction_id]
        self.assertIn("ev_op_bind_1", op_rec.get("evidence_ids", []))

    def test_05_reusing_operation_id_across_conflicting_session_or_identity_fails(self):
        """Reusing operation ID with conflicting session or target identity is rejected."""
        tx = self.adapter.begin_capture_transaction(self.session_id, self.pid)
        self.adapter.read_memory(self.pid, 0x5000, 32)
        self.adapter.commit_capture_transaction(tx)

        # Cross-session replay
        with self.assertRaises(ValueError) as ctx:
            self.trust_store.record_used_operation(
                op_id=tx.transaction_id,
                session_id="different_session_fake",
                pid=self.pid,
                allow_idempotent=True,
            )
        self.assertIn("Receipt replay across sessions rejected", str(ctx.exception))

        # Conflicting target identity
        with self.assertRaises(ValueError) as ctx:
            self.trust_store.record_used_operation(
                op_id=tx.transaction_id,
                session_id=self.session_id,
                pid=self.pid,
                metadata={"process_identity": "conflicting:proc:id"},
                allow_idempotent=True,
            )
        self.assertIn("Conflicting target identity", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
