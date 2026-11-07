"""Phase 2.0-A.3.12 Transaction Isolation Adversarial Regression Tests.

Verifies:
1. Concurrent transactions on different targets/sessions maintain strict isolation.
2. Nested transactions behave deterministically (inner scopes reads, outer resumes).
3. Unscoped physical reads are rejected from issuing live capture receipts.
4. Observation digest binds memory address; identical bytes at different addresses yield distinct digests.
5. Target identity changes (start_time, inode, executable) cause transaction commit to fail closed.
6. Repeated receipt issuance on the same committed transaction fails closed.
"""

import hashlib
import os
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from extractor.target_adapter import (
    CaptureTransaction,
    LocalTargetAdapter,
    PIDReusedError,
)
from extractor.capture_backend import LiveCaptureReceipt


class TestPhase20A312TransactionIsolation(unittest.TestCase):
    def setUp(self):
        self.session_id = "sess_a312_tx"
        self.pid = 98765
        self.process_identity = f"{self.pid}:1699999999:boot_12345"
        self.executable_identity = "/usr/bin/dynamicstate_target:45678"
        self.build_id = "a1b2c3d4e5f67890"

    def _mock_identity(self, pid: int, start_time: str = "1699999999", inode: int = 45678, exe: str = "/usr/bin/target", build_id: str = "a1b2c3d4e5f67890"):
        return {
            "pid": pid,
            "process_identity": f"{pid}:{start_time}:boot_12345",
            "start_time": start_time,
            "executable": exe,
            "executable_identity": f"{exe}:{inode}",
            "exe_inode": inode,
            "build_id": build_id,
        }

    # -------------------------------------------------------------------------
    # 1. Concurrent Transactions Isolation
    # -------------------------------------------------------------------------
    def test_01_concurrent_transactions_maintain_strict_accounting_isolation(self):
        """Concurrent transactions on different PIDs do not bleed or cross-contaminate reads."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", side_effect=lambda p: self._mock_identity(p)):
            tx1 = adapter.begin_capture_transaction("sess_1", 2001)
            tx2 = adapter.begin_capture_transaction("sess_2", 2002)

            adapter._record_physical_read(num_bytes=128, num_reads=1, data=b"X" * 128, pid=2001)
            adapter._record_physical_read(num_bytes=256, num_reads=2, data=b"Y" * 256, pid=2002)

            adapter.commit_capture_transaction(tx1)
            adapter.commit_capture_transaction(tx2)

            self.assertEqual(tx1.physical_bytes_read, 128)
            self.assertEqual(tx1.physical_reads_count, 1)
            self.assertEqual(tx2.physical_bytes_read, 256)
            self.assertEqual(tx2.physical_reads_count, 2)
            self.assertNotEqual(tx1.observation_digest, tx2.observation_digest)

    # -------------------------------------------------------------------------
    # 2. Nested Transactions Determinism
    # -------------------------------------------------------------------------
    def test_02_nested_transactions_inner_scopes_reads_and_outer_resumes(self):
        """Nested transactions scope reads to the innermost active transaction."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            with adapter.capture_transaction(self.session_id, self.pid, operation_type="diagnostic") as outer_tx:
                adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"O" * 64, pid=self.pid, address=0x1000)

                with adapter.capture_transaction(self.session_id, self.pid, operation_type="probe") as inner_tx:
                    adapter._record_physical_read(num_bytes=32, num_reads=1, data=b"I" * 32, pid=self.pid, address=0x2000)

                # Inner transaction committed cleanly
                self.assertTrue(inner_tx.committed)
                self.assertEqual(inner_tx.physical_bytes_read, 32)
                self.assertEqual(inner_tx.operation_type, "probe")

                # Outer transaction resumes and records additional reads
                adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"O" * 64, pid=self.pid, address=0x3000)

            self.assertTrue(outer_tx.committed)
            self.assertEqual(outer_tx.physical_bytes_read, 128)
            self.assertEqual(outer_tx.physical_reads_count, 2)

    # -------------------------------------------------------------------------
    # 3. Unscoped Read Rejection
    # -------------------------------------------------------------------------
    def test_03_unscoped_physical_reads_cannot_issue_live_receipt(self):
        """Physical reads made without an active capture transaction cannot issue a receipt."""
        adapter = LocalTargetAdapter()
        adapter._memory_reader = lambda p, a, s: (b"U" * s, "OBSERVED", None)
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            # Explicitly unscoped read on unpinned PID
            data, status, _ = adapter.read_unscoped(self.pid, 0x400000, 64)
            self.assertEqual(status, "OBSERVED")
            self.assertEqual(len(data), 64)
            self.assertGreater(adapter.unscoped_physical_bytes_read, 0)

            # Attempting to issue a live capture receipt without a committed transaction must fail
            with self.assertRaises(ValueError) as ctx:
                adapter.issue_live_receipt_for_session(self.session_id, self.pid)
            self.assertTrue("no physical reads" in str(ctx.exception).lower() or "explicit committed" in str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # 4. Digest Address Separation
    # -------------------------------------------------------------------------
    def test_04_observation_digest_differs_for_identical_payloads_at_different_addresses(self):
        """Different memory addresses returning identical payload bytes must never produce identical digests."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            tx1 = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=32, num_reads=1, data=b"A" * 32, pid=self.pid, address=0x1000)
            adapter.commit_capture_transaction(tx1)

            tx2 = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=32, num_reads=1, data=b"A" * 32, pid=self.pid, address=0x2000)
            adapter.commit_capture_transaction(tx2)

            self.assertNotEqual(tx1.observation_digest, tx2.observation_digest, "Address separation guarantee violated!")

    # -------------------------------------------------------------------------
    # 5. Target Identity Change Rejection
    # -------------------------------------------------------------------------
    def test_05_identity_change_during_transaction_fails_commit(self):
        """Process identity change (PID reuse / execve) during transaction aborts and raises PIDReusedError."""
        adapter = LocalTargetAdapter()
        ident_initial = self._mock_identity(self.pid, start_time="1000000", inode=1111)
        ident_tampered = self._mock_identity(self.pid, start_time="2000000", inode=1111)

        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", side_effect=[ident_initial, ident_initial, ident_tampered]):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"D" * 64, pid=self.pid)

            with self.assertRaises(PIDReusedError):
                adapter.commit_capture_transaction(tx)
            self.assertTrue(tx.aborted)

    # -------------------------------------------------------------------------
    # 6. Receipt Reuse Rejection
    # -------------------------------------------------------------------------
    def test_06_receipt_reuse_on_committed_transaction_fails_closed(self):
        """A capture transaction can mint at most one receipt; subsequent attempts fail closed."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"R" * 64, pid=self.pid)
            adapter.commit_capture_transaction(tx)

            rcpt = adapter.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx)
            self.assertIsNotNone(rcpt)
            self.assertTrue(tx.receipt_issued)

            # Second issuance attempt on same transaction must fail
            with self.assertRaises(ValueError) as ctx:
                adapter.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx)
            self.assertIn("already issued", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
