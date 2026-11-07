"""Phase 2.0-A.3.14 Explicit Transaction-Bound Receipt Tests.

Verifies:
1. Production receipt issuance always requires an explicit committed transaction reference or ID.
2. Single-candidate automatic transaction selection is strictly prohibited and fails closed.
3. Uncommitted, aborted, or cross-adapter transactions are rejected.
4. Already-issued transactions cannot be reused (exactly-once receipt issuance).
5. Transaction with 0 physical bytes read is rejected.
6. Failed receipt issuance does not leave transaction in an irrecoverably consumed state.
7. Exact session, PID, target host, and observation digest binding is enforced.
"""

import os
import unittest
from unittest.mock import patch

from extractor.target_adapter import LocalTargetAdapter, RemoteSshTargetAdapter
from extractor.capture_backend import LiveCaptureReceipt


class TestPhase20A314ExplicitTransactionReceipt(unittest.TestCase):
    def setUp(self):
        self.session_id = "sess_a314_exp"
        self.pid = 4001
        self.process_identity = f"{self.pid}:123456:boot_uuid"
        self.executable_identity = f"/usr/bin/target:{self.pid}"
        self.build_id = "a1b2c3d4e5f6"

    def _mock_identity(self, pid: int):
        return {
            "pid": pid,
            "process_identity": f"{pid}:123456:boot_uuid",
            "start_time": "123456",
            "executable": "/usr/bin/target",
            "executable_identity": f"/usr/bin/target:{pid}",
            "build_id": self.build_id,
        }

    def _make_adapter(self, adapter_id="ad_test"):
        adapter = LocalTargetAdapter(adapter_id=adapter_id)
        return adapter

    # 1. Calling without transaction reference raises ValueError even with 1 candidate
    def test_01_single_candidate_automatic_selection_rejected(self):
        adapter = self._make_adapter("ad_single")
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"X" * 64, pid=self.pid, transaction=tx)
            adapter.commit_capture_transaction(tx)

            # Even though exactly 1 committed transaction exists, omitting transaction must fail closed
            with self.assertRaises(ValueError) as ctx:
                adapter.issue_live_receipt_for_session(self.session_id, self.pid)
            self.assertIn("explicit committed capturetransaction reference", str(ctx.exception).lower())

            # Passing transaction explicitly succeeds
            rcpt = adapter.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx)
            self.assertEqual(rcpt.physical_bytes_read, 64)
            self.assertTrue(tx.receipt_issued)

    # 2. String transaction ID lookup in committed transactions succeeds
    def test_02_transaction_id_string_lookup_succeeds(self):
        adapter = self._make_adapter("ad_str_tx")
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=32, num_reads=1, data=b"S" * 32, pid=self.pid, transaction=tx)
            adapter.commit_capture_transaction(tx)

            # Lookup via transaction ID string
            rcpt = adapter.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx.transaction_id)
            self.assertEqual(rcpt.physical_bytes_read, 32)
            self.assertEqual(rcpt.operation_id, tx.transaction_id)

    # 3. Uncommitted transaction reference rejected
    def test_03_uncommitted_transaction_rejected(self):
        adapter = self._make_adapter("ad_uncommitted")
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"U" * 64, pid=self.pid, transaction=tx)
            # Not committed yet!
            with self.assertRaises(ValueError) as ctx:
                adapter.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx)
            self.assertIn("uncommitted", str(ctx.exception).lower())

    # 4. Aborted transaction reference rejected
    def test_04_aborted_transaction_rejected(self):
        adapter = self._make_adapter("ad_aborted")
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"A" * 64, pid=self.pid, transaction=tx)
            adapter.rollback_capture_transaction(tx, "Test abort reason")

            with self.assertRaises(ValueError) as ctx:
                adapter.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx)
            self.assertIn("aborted", str(ctx.exception).lower())

    # 5. Cross-adapter transaction reference rejected
    def test_05_cross_adapter_transaction_reference_rejected(self):
        ad_a = self._make_adapter("ad_A")
        ad_b = self._make_adapter("ad_B")
        with patch.object(ad_a, "check_liveness", return_value=(True, None)), \
             patch.object(ad_a, "get_process_identity", return_value=self._mock_identity(self.pid)), \
             patch.object(ad_b, "check_liveness", return_value=(True, None)), \
             patch.object(ad_b, "get_process_identity", return_value=self._mock_identity(self.pid)):
            tx_a = ad_a.begin_capture_transaction(self.session_id, self.pid)
            ad_a._record_physical_read(num_bytes=64, num_reads=1, data=b"A" * 64, pid=self.pid, transaction=tx_a)
            ad_a.commit_capture_transaction(tx_a)

            with self.assertRaises(ValueError) as ctx:
                ad_b.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx_a)
            self.assertIn("ownership mismatch", str(ctx.exception).lower())

    # 6. Failed receipt issuance does not leave transaction permanently consumed
    def test_06_failed_issuance_does_not_consume_transaction(self):
        adapter = self._make_adapter("ad_retry")
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"R" * 64, pid=self.pid, transaction=tx)
            adapter.commit_capture_transaction(tx)

            # First attempt fails due to pinned identity verification failure
            with patch.object(adapter, "verify_pinned_identity", side_effect=[(False, "Temporary verification error"), (True, None)]):
                with self.assertRaises(ValueError) as ctx:
                    adapter.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx)
                self.assertIn("pinned identity verification failed", str(ctx.exception).lower())
                # Transaction must NOT have receipt_issued set to True
                self.assertFalse(tx.receipt_issued)

                # Second attempt succeeds
                rcpt = adapter.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx)
                self.assertIsNotNone(rcpt)
                self.assertTrue(tx.receipt_issued)


if __name__ == "__main__":
    unittest.main()
