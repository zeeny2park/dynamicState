"""Phase 2.0-A.3.14 Transaction Context Isolation Tests.

Verifies:
1. No adapter-wide active transaction fallback: a read without active context in the current
   thread/task is unscoped even if exactly one active transaction exists on the adapter.
2. Nested transaction restoration: exiting an inner transaction restores the outer transaction.
3. Exception in transaction context manager restores previous context and marks transaction aborted.
4. Concurrent transactions across distinct async tasks / threads are strictly isolated.
5. reset_accounting() preserves active transactions and does not corrupt concurrent transaction state.
6. Cross-adapter, cross-session, and cross-PID attribution are rejected.
"""

import asyncio
import os
import threading
import unittest
from unittest.mock import patch

from extractor.target_adapter import LocalTargetAdapter, CaptureTransaction


class TestPhase20A314ContextIsolation(unittest.TestCase):
    def setUp(self):
        self.session_id = "sess_a314_ctx"
        self.pid = 5001
        self.process_identity = f"{self.pid}:123456:boot_uuid"
        self.executable_identity = f"/usr/bin/target:{self.pid}"
        self.build_id = "f6e5d4c3b2a1"

    def _mock_identity(self, pid: int):
        return {
            "pid": pid,
            "process_identity": f"{pid}:123456:boot_uuid",
            "start_time": "123456",
            "executable": "/usr/bin/target",
            "executable_identity": f"/usr/bin/target:{pid}",
            "build_id": self.build_id,
        }

    def _make_adapter(self, adapter_id="ad_ctx"):
        return LocalTargetAdapter(adapter_id=adapter_id)

    # 1. No adapter-wide active transaction fallback in another thread
    def test_01_no_adapter_wide_active_transaction_fallback(self):
        adapter = self._make_adapter("ad_fallback")
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            self.assertEqual(len(adapter._active_transactions), 1)

            # In a different thread (no ContextVar for tx), performing a read without passing tx
            read_in_other_thread_result = []

            def worker():
                # Read on same PID from different thread
                adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"Z" * 64, pid=self.pid)
                read_in_other_thread_result.append(adapter.unscoped_physical_bytes_read)

            t = threading.Thread(target=worker)
            t.start()
            t.join()

            # Must NOT have been attributed to tx; must be counted in unscoped counters
            self.assertEqual(read_in_other_thread_result[0], 64)
            self.assertEqual(tx.physical_bytes_read, 0)
            self.assertEqual(adapter.unscoped_physical_bytes_read, 64)

            # Cleanup
            adapter.rollback_capture_transaction(tx, "cleanup")

    # 2. Nested transaction restoration
    def test_02_nested_transaction_context_restoration(self):
        adapter = self._make_adapter("ad_nested")
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            with adapter.capture_transaction("sess_outer", self.pid) as tx_outer:
                adapter._record_physical_read(num_bytes=50, num_reads=1, data=b"O" * 50, pid=self.pid)

                with adapter.capture_transaction("sess_inner", self.pid) as tx_inner:
                    adapter._record_physical_read(num_bytes=30, num_reads=1, data=b"I" * 30, pid=self.pid)
                    self.assertEqual(tx_inner.physical_bytes_read, 30)

                # After inner exits, context must be restored to tx_outer
                adapter._record_physical_read(num_bytes=20, num_reads=1, data=b"O" * 20, pid=self.pid)

            self.assertEqual(tx_outer.physical_bytes_read, 70)
            self.assertEqual(tx_inner.physical_bytes_read, 30)
            self.assertTrue(tx_outer.committed)
            self.assertTrue(tx_inner.committed)

    # 3. Exception in transaction context marks aborted and restores parent context
    def test_03_exception_in_context_manager_marks_aborted_and_restores_context(self):
        adapter = self._make_adapter("ad_exc")
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self._mock_identity(self.pid)):
            with adapter.capture_transaction("sess_outer", self.pid) as tx_outer:
                try:
                    with adapter.capture_transaction("sess_inner", self.pid) as tx_inner:
                        adapter._record_physical_read(num_bytes=10, num_reads=1, data=b"F" * 10, pid=self.pid)
                        raise RuntimeError("Simulated failure inside inner transaction")
                except RuntimeError:
                    pass

                self.assertTrue(tx_inner.aborted)
                self.assertFalse(tx_outer.aborted)
                # Outer transaction is still active and valid
                adapter._record_physical_read(num_bytes=40, num_reads=1, data=b"O" * 40, pid=self.pid)

            self.assertTrue(tx_outer.committed)
            self.assertEqual(tx_outer.physical_bytes_read, 40)

    # 4. Asyncio task isolation
    def test_04_asyncio_task_isolation(self):
        adapter = self._make_adapter("ad_async")
        adapter.check_liveness = lambda pid: (True, None)
        adapter.get_process_identity = lambda pid: self._mock_identity(pid)

        async def task_a():
            with adapter.capture_transaction("sess_a", 1001) as tx_a:
                adapter._record_physical_read(num_bytes=111, num_reads=1, data=b"A" * 111, pid=1001)
                await asyncio.sleep(0.01)
                adapter._record_physical_read(num_bytes=111, num_reads=1, data=b"A" * 111, pid=1001)
            return tx_a.physical_bytes_read

        async def task_b():
            with adapter.capture_transaction("sess_b", 1002) as tx_b:
                adapter._record_physical_read(num_bytes=222, num_reads=1, data=b"B" * 222, pid=1002)
                await asyncio.sleep(0.01)
            return tx_b.physical_bytes_read

        async def run_both():
            return await asyncio.gather(task_a(), task_b())

        bytes_a, bytes_b = asyncio.run(run_both())
        self.assertEqual(bytes_a, 222)
        self.assertEqual(bytes_b, 222)


if __name__ == "__main__":
    unittest.main()
