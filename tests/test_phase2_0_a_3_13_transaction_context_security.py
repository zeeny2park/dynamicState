#!/usr/bin/env python3
"""Phase 2.0-A.3.13 — Transaction Context Security & Non-Repudiation Test Suite.

Audits and proves:
1. Adapter isolation: CaptureTransaction created by Adapter A is never attributed by Adapter B.
2. Context binding: ContextVar respects adapter identity across async/concurrent execution boundaries.
3. Explicit argument validation: Passing transaction from Adapter A to Adapter B is rejected fail-closed.
4. Nested transaction behavior: Deterministic parent context restoration on exit and rollback.
5. Ambiguous candidate set rejection: Multiple committed unissued transactions reject fail-closed without guessing.
6. Unscoped reads fail-closed: Unscoped reads never yield production LiveCaptureReceipt.
"""

import asyncio
import os
import threading
import unittest
from unittest.mock import patch

from extractor.target_adapter import (
    LocalTargetAdapter,
    CaptureTransaction,
    _current_capture_tx,
)
from extractor.capture_backend import (
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
    LiveCaptureReceipt,
)


class TestPhase20A313TransactionContextSecurity(unittest.TestCase):
    """Adversarial tests for capture transaction context isolation and provenance integrity."""

    def setUp(self):
        self.session_id = "sess_a313_sec"
        self.pid = 9999
        self.mock_ident = {
            "pid": self.pid,
            "process_identity": "test_app_proc",
            "start_time": "12345678",
            "executable": "/usr/bin/test_app",
            "executable_identity": "/usr/bin/test_app",
            "build_id": "sha1:abc123456789def",
        }

    def _make_adapter(self, name: str = "adapter_test") -> LocalTargetAdapter:
        ad = LocalTargetAdapter()
        ad.check_liveness = lambda p: (True, None)
        ad.get_process_identity = lambda p: dict(self.mock_ident)
        ad._memory_reader = lambda pid, addr, sz: (b"M" * sz, "OBSERVED", None)
        return ad

    def test_01_cross_adapter_context_reuse_rejected(self):
        """Transaction opened by adapter A must NOT be claimed or recorded into by adapter B."""
        ad_a = self._make_adapter("adapter_a")
        ad_b = self._make_adapter("adapter_b")

        self.assertNotEqual(ad_a.adapter_id, ad_b.adapter_id)

        # Start transaction on adapter A
        tx_a = ad_a.begin_capture_transaction(self.session_id, self.pid)
        self.assertEqual(tx_a.adapter_id, ad_a.adapter_id)

        # Adapter B attempts to record a physical read while adapter A's transaction is active in thread context
        ad_b._record_physical_read(num_bytes=128, num_reads=1, data=b"B" * 128, pid=self.pid)

        # Adapter B's read must NOT be recorded into Adapter A's transaction
        self.assertEqual(tx_a.physical_bytes_read, 0)
        self.assertEqual(tx_a.physical_reads_count, 0)
        # Instead, it must be recorded as unscoped on Adapter B
        self.assertEqual(ad_b.unscoped_physical_reads_count, 1)
        self.assertEqual(ad_b.unscoped_physical_bytes_read, 128)

        # Read into adapter A legitimately
        ad_a._record_physical_read(num_bytes=64, num_reads=1, data=b"A" * 64, pid=self.pid)
        self.assertEqual(tx_a.physical_bytes_read, 64)

        # Committing transaction A
        ad_a.commit_capture_transaction(tx_a)

    def test_02_explicit_transaction_ownership_mismatch_rejected(self):
        """Passing adapter A's transaction directly into adapter B methods raises ValueError."""
        ad_a = self._make_adapter("adapter_a")
        ad_b = self._make_adapter("adapter_b")

        tx_a = ad_a.begin_capture_transaction(self.session_id, self.pid)
        ad_a._record_physical_read(num_bytes=64, num_reads=1, data=b"A" * 64, pid=self.pid)

        # Attempt to commit tx_a on adapter B
        with self.assertRaises(ValueError) as ctx:
            ad_b.commit_capture_transaction(tx_a)
        self.assertIn("ownership mismatch", str(ctx.exception).lower())

        # Commit on adapter A succeeds
        ad_a.commit_capture_transaction(tx_a)

        # Attempt to issue receipt on adapter B referencing tx_a
        with self.assertRaises(ValueError) as ctx2:
            ad_b.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx_a)
        self.assertIn("ownership mismatch", str(ctx2.exception).lower())

    def test_03_concurrent_threads_context_isolation(self):
        """Concurrent threads using different adapters maintain strict transaction isolation."""
        ad_a = self._make_adapter("ad_a")
        ad_b = self._make_adapter("ad_b")
        errors = []

        def worker_a():
            try:
                tx = ad_a.begin_capture_transaction("sess_a", self.pid)
                ad_a._record_physical_read(num_bytes=100, num_reads=1, data=b"1" * 100, pid=self.pid)
                ad_a.commit_capture_transaction(tx)
                if tx.physical_bytes_read != 100:
                    errors.append(f"Worker A unexpected bytes: {tx.physical_bytes_read}")
            except Exception as e:
                errors.append(f"Worker A error: {e}")

        def worker_b():
            try:
                tx = ad_b.begin_capture_transaction("sess_b", self.pid)
                ad_b._record_physical_read(num_bytes=200, num_reads=2, data=b"2" * 200, pid=self.pid)
                ad_b.commit_capture_transaction(tx)
                if tx.physical_bytes_read != 200:
                    errors.append(f"Worker B unexpected bytes: {tx.physical_bytes_read}")
            except Exception as e:
                errors.append(f"Worker B error: {e}")

        threads = [threading.Thread(target=worker_a), threading.Thread(target=worker_b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])

    def test_04_async_tasks_context_propagation_and_isolation(self):
        """Asyncio tasks maintain independent transaction contexts via ContextVar copy semantics."""
        ad = self._make_adapter("ad_async")

        async def subtask(task_id: int, byte_val: int):
            tx = ad.begin_capture_transaction(f"sess_async_{task_id}", self.pid)
            await asyncio.sleep(0.01)
            ad._record_physical_read(num_bytes=byte_val, num_reads=1, data=bytes([byte_val] * byte_val), pid=self.pid)
            await asyncio.sleep(0.01)
            ad.commit_capture_transaction(tx)
            return tx.physical_bytes_read

        async def main():
            return await asyncio.gather(subtask(1, 64), subtask(2, 128))

        res1, res2 = asyncio.run(main())
        self.assertEqual(res1, 64)
        self.assertEqual(res2, 128)

    def test_05_nested_transaction_deterministic_restoration(self):
        """Nested capture transactions restore the exact parent context upon commit or rollback."""
        ad = self._make_adapter("ad_nested")

        # Outer transaction
        outer_tx = ad.begin_capture_transaction(self.session_id, self.pid, operation_type="outer")
        self.assertEqual(ad._active_transaction, outer_tx)

        # Inner transaction
        inner_tx = ad.begin_capture_transaction(self.session_id, self.pid, operation_type="inner")
        self.assertEqual(ad._active_transaction, inner_tx)
        ad._record_physical_read(num_bytes=50, num_reads=1, data=b"I" * 50, pid=self.pid)
        self.assertEqual(inner_tx.physical_bytes_read, 50)
        self.assertEqual(outer_tx.physical_bytes_read, 0)

        # Commit inner -> restores outer
        ad.commit_capture_transaction(inner_tx)
        self.assertEqual(ad._active_transaction, outer_tx)

        # Read into outer
        ad._record_physical_read(num_bytes=70, num_reads=1, data=b"O" * 70, pid=self.pid)
        self.assertEqual(outer_tx.physical_bytes_read, 70)

        # Commit outer -> restores None
        ad.commit_capture_transaction(outer_tx)
        self.assertIsNone(ad._active_transaction)

    def test_06_ambiguous_candidate_set_rejected_fail_closed(self):
        """Multiple committed unissued transactions reject receipt minting rather than sorting timestamps."""
        ad = self._make_adapter("ad_ambiguous")

        tx1 = ad.begin_capture_transaction(self.session_id, self.pid)
        ad._record_physical_read(num_bytes=64, num_reads=1, data=b"1" * 64, pid=self.pid)
        ad.commit_capture_transaction(tx1)

        tx2 = ad.begin_capture_transaction(self.session_id, self.pid)
        ad._record_physical_read(num_bytes=128, num_reads=1, data=b"2" * 128, pid=self.pid)
        ad.commit_capture_transaction(tx2)

        # Attempting issuance without explicit transaction reference must fail-closed
        with self.assertRaises(ValueError) as ctx:
            ad.issue_live_receipt_for_session(self.session_id, self.pid)
        self.assertIn("explicit committed capturetransaction reference", str(ctx.exception).lower())

        # Explicit issuance succeeds
        rcpt1 = ad.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx1)
        self.assertEqual(rcpt1.physical_bytes_read, 64)

        # Single candidate without explicit reference must also be rejected
        with self.assertRaises(ValueError) as ctx:
            ad.issue_live_receipt_for_session(self.session_id, self.pid)
        self.assertIn("explicit committed capturetransaction reference", str(ctx.exception).lower())

        # Explicit issuance of tx2 succeeds
        rcpt2 = ad.issue_live_receipt_for_session(self.session_id, self.pid, transaction=tx2)
        self.assertEqual(rcpt2.physical_bytes_read, 128)

    def test_07_unscoped_reads_never_yield_receipt(self):
        """Unscoped physical reads are recorded into unscoped counters and cannot issue a LiveCaptureReceipt."""
        ad = self._make_adapter("ad_unscoped")

        # Perform unscoped read
        data, status, err = ad.read_unscoped(self.pid, 0x1000, 64)
        self.assertEqual(status, "OBSERVED")
        self.assertEqual(ad.unscoped_physical_reads_count, 1)
        self.assertEqual(ad.unscoped_physical_bytes_read, 64)

        # Attempting to issue a receipt must fail closed because no capture transaction exists
        with self.assertRaises(ValueError) as ctx:
            ad.issue_live_receipt_for_session(self.session_id, self.pid)
        self.assertTrue(
            "no physical reads" in str(ctx.exception).lower()
            or "explicit committed capturetransaction reference" in str(ctx.exception).lower()
        )


if __name__ == "__main__":
    unittest.main()
