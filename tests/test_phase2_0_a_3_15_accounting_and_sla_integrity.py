"""Phase 2.0-A.3.15 Transaction Accounting & Statistical SLA Integrity Tests.

Verifies:
1. reset_accounting() during active capture transactions raises RuntimeError and preserves transactions.
2. Rejected cross-adapter transactions do not corrupt adapter physical read counters.
3. measure_read_latency() uses documented nearest-rank percentile convention with deterministic samples.
4. Successful and failed sample counts and failed sample details are reported separately.
5. is_mocked detection explicitly marks mocked reads as not hardware SLA validated.
6. capture_transaction() context manager cleans up ContextVar stack on BaseException / cancellation.
"""

import unittest
from unittest.mock import MagicMock, patch

from extractor.target_adapter import (
    CaptureTransaction,
    LocalTargetAdapter,
    _current_capture_tx,
    _tx_stack,
)


class TestPhase20A315AccountingAndSlaIntegrity(unittest.TestCase):
    def setUp(self):
        _current_capture_tx.set(None)
        _tx_stack.set([])
        self.session_id = "sess_a315_acct"
        self.pid = 9601
        self.mock_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:123456:boot_uuid",
            "start_time": "123456",
            "executable": "/usr/bin/service_a315_sla",
            "executable_identity": f"/usr/bin/service_a315_sla:{self.pid}",
            "build_id": "sha1:build_a315_sla",
            "target_host": "localhost",
        }

    def tearDown(self):
        _current_capture_tx.set(None)
        _tx_stack.set([])

    # 1. reset_accounting during active capture transactions raises RuntimeError
    def test_01_reset_accounting_during_active_tx_raises_runtime_error(self):
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self.mock_ident):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            self.assertEqual(len(adapter._active_transactions), 1)

            # Calling reset_accounting() while transaction is active MUST raise RuntimeError
            with self.assertRaises(RuntimeError) as ctx:
                adapter.reset_accounting()
            self.assertIn("cannot reset accounting while capture transactions are active", str(ctx.exception).lower())

            # Active transaction remains intact
            self.assertIn(tx.transaction_id, adapter._active_transactions)

            # Rollback transaction, then reset succeeds
            adapter.rollback_capture_transaction(tx, "cleanup")
            self.assertEqual(len(adapter._active_transactions), 0)
            adapter.reset_accounting()
            self.assertEqual(adapter.physical_reads_count, 0)

    # 2. Rejected cross-adapter transaction does not corrupt physical read counters
    def test_02_rejected_cross_adapter_does_not_mutate_counters(self):
        ad_a = LocalTargetAdapter(adapter_id="adapter_A")
        ad_b = LocalTargetAdapter(adapter_id="adapter_B")
        with patch.object(ad_a, "check_liveness", return_value=(True, None)), \
             patch.object(ad_a, "get_process_identity", return_value=self.mock_ident):
            tx_a = ad_a.begin_capture_transaction(self.session_id, self.pid)

            reads_before = ad_b.physical_reads_count
            bytes_before = ad_b.physical_bytes_read

            # ad_b is passed a transaction belonging to ad_a
            with self.assertRaises(ValueError) as ctx:
                ad_b._record_physical_read(num_bytes=128, num_reads=1, data=b"X" * 128, pid=self.pid, transaction=tx_a)
            self.assertIn("transaction ownership mismatch", str(ctx.exception).lower())

            # ad_b counters MUST NOT have been incremented
            self.assertEqual(ad_b.physical_reads_count, reads_before)
            self.assertEqual(ad_b.physical_bytes_read, bytes_before)

            ad_a.rollback_capture_transaction(tx_a, "done")

    # 3. measure_read_latency nearest-rank percentile convention with deterministic distribution
    def test_03_deterministic_percentile_calculation(self):
        adapter = LocalTargetAdapter()
        # Create 10 synthetic samples: [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
        samples = [float(i) for i in range(1, 11)]
        mock_read = MagicMock(return_value=(b"\x00" * 64, "OBSERVED", None))
        adapter.read_memory = mock_read

        # Simulate time.monotonic_ns returning controlled increments
        time_seq = []
        for s in samples:
            time_seq.append(0)
            time_seq.append(int(s * 1_000_000))  # ms to ns

        with patch("time.monotonic_ns", side_effect=time_seq):
            report = adapter.measure_read_latency(self.pid, 0x400000, 64, samples=10)

        self.assertEqual(report["sample_count"], 10)
        self.assertEqual(report["successful_sample_count"], 10)
        self.assertEqual(report["failed_sample_count"], 0)
        # Nearest-rank convention: ceil(0.5 * 10) - 1 = index 4 -> 5.0
        self.assertEqual(report["read_latency_p50_ms"], 5.0)
        # Nearest-rank convention: ceil(0.95 * 10) - 1 = index 9 -> 10.0
        self.assertEqual(report["read_latency_p95_ms"], 10.0)
        self.assertEqual(report["read_latency_max_ms"], 10.0)

    # 4. Successful and failed sample counts reported separately
    def test_04_successful_and_failed_sample_reporting(self):
        adapter = LocalTargetAdapter()
        side_effects = [
            (b"\x00" * 64, "OBSERVED", None),
            (b"", "ERROR", "EFAULT"),
            (b"\x00" * 64, "OBSERVED", None),
            (b"", "ERROR", "EIO"),
        ]
        adapter.read_memory = MagicMock(side_effect=side_effects)

        report = adapter.measure_read_latency(self.pid, 0x400000, 64, samples=4)
        self.assertEqual(report["total_samples_attempted"], 4)
        self.assertEqual(report["successful_sample_count"], 2)
        self.assertEqual(report["failed_sample_count"], 2)
        self.assertEqual(len(report["failed_samples"]), 2)
        self.assertEqual(report["failed_samples"][0]["error"], "EFAULT")
        self.assertEqual(report["failed_samples"][1]["error"], "EIO")

    # 5. is_mocked detection explicitly flags mocked reads
    def test_05_mocked_read_sla_flagging(self):
        adapter = LocalTargetAdapter()
        # read_memory is a mock
        adapter.read_memory = MagicMock(return_value=(b"\x00" * 64, "OBSERVED", None))
        report = adapter.measure_read_latency(self.pid, 0x400000, 64, samples=5)
        self.assertTrue(report["is_mocked"])
        self.assertFalse(report["hardware_sla_validated"])

    # 6. capture_transaction context manager cleans up stack on BaseException
    def test_06_capture_transaction_cleanup_on_base_exception(self):
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value=self.mock_ident):

            with self.assertRaises(KeyboardInterrupt):
                with adapter.capture_transaction(self.session_id, self.pid):
                    # Simulate asyncio cancellation or KeyboardInterrupt (inherits from BaseException)
                    raise KeyboardInterrupt("Simulated task abort")

            # Stack and current tx must be cleanly restored to None
            self.assertIsNone(_current_capture_tx.get(None))
            self.assertEqual(_tx_stack.get(None) or [], [])


if __name__ == "__main__":
    unittest.main()
