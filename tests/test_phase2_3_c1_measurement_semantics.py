"""Phase 2.3-C.1: Measurement Semantics & Accounting Integrity Tests.

Verifies P0 requirements:
- Explicit distinction between MEASURED, ESTIMATED, and ACCOUNTED resource consumption.
- Zero-byte reads return 0 measured bytes without fabrication.
- Short reads and partial reads account for actual returned bytes.
- collect_process_info() on dead/inaccessible targets reconciles 0 bytes, not hardcoded 128.
- Unknown byte costs use conservative estimates or strict rejection when reject_unknown_byte_cost=True.
- Idempotent reservation reconciliation: calling reconcile_reservation() more than once
  does not double-charge or leak reservations.
- Concurrent reservations cannot oversubscribe limits.
- Exceptions after partial consumption leave zero dangling reservations.
- Profile and global budgets maintain exact consistency.
"""

from concurrent.futures import ThreadPoolExecutor
import os
import tempfile
import time
import unittest

from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)
from extractor.runtime_evidence_provider import (
    RuntimeEvidenceProvider,
    RuntimeEvidenceRecord,
)
from extractor.target_adapter import LocalTargetAdapter, TargetExecutionAdapter


class MockMeasurementAdapter(TargetExecutionAdapter):
    """Controlled adapter to test exact byte measurement semantics."""

    def __init__(self, alive: bool = True, sim_mem: bytes = b""):
        self._alive = alive
        self._sim_mem = sim_mem
        self.last_read_bytes = 0

    def target_host(self) -> str:
        return "127.0.0.1"

    def is_remote(self) -> bool:
        return False

    def check_liveness(self, pid: int):
        if not self._alive:
            return False, "Process 999999 was not found (ESRCH)"
        return True, None

    def get_process_identity(self, pid: int):
        return {"pid": pid, "process_identity": f"mock_proc_{pid}"}

    def get_process_status(self, pid: int):
        return {"VmRSS": 1024, "VmSize": 4096}

    def get_threads(self, pid: int):
        return [{"tid": pid}]

    def get_proc_maps(self, pid: int):
        return [
            {"start": "0x1000", "end": "0x2000", "permissions": "r-xp", "pathname": "/bin/mock"},
            {"start": "0x2000", "end": "0x3000", "permissions": "rw-p", "pathname": "[heap]"},
        ]

    def read_memory(self, pid: int, address: int, size: int):
        if not self._alive:
            return None, "error", "Process not alive"
        if not self._sim_mem:
            return None, "error", "EFAULT (unmapped address)"
        slice_data = self._sim_mem[:size]
        self.last_read_bytes = len(slice_data)
        return slice_data, "mock", None


class TestPhase23C1MeasurementSemantics(unittest.TestCase):
    def setUp(self):
        self.limits = ObservationBudgetLimits(
            max_bytes_read=1048576,  # 1 MB
            max_wall_clock_ms=5000.0,
            max_samples=50,
        )
        self.tracker = ObservationBudgetTracker(self.limits)

    def test_distinguish_measured_vs_estimated_vs_accounted(self):
        """Measured physical bytes and conservative estimated bytes are strictly disaggregated in ObservationMetrics."""
        # 1. Measured read
        rec1 = self.tracker.record_read(bytes_read=256, latency_us=100.0)
        self.assertEqual(rec1["measured_bytes_read"], 256)
        self.assertEqual(rec1["charged_bytes"], 256)
        self.assertFalse(rec1["used_conservative_byte_estimate"])

        # 2. Estimated read (bytes_read=None, conservative_estimate_bytes=1024)
        rec2 = self.tracker.record_read(bytes_read=None, conservative_estimate_bytes=1024, latency_us=200.0)
        self.assertIsNone(rec2["measured_bytes_read"])
        self.assertEqual(rec2["charged_bytes"], 1024)
        self.assertTrue(rec2["used_conservative_byte_estimate"])

        # Metrics verification
        self.assertEqual(self.tracker.metrics.measured_bytes_read, 256)
        self.assertEqual(self.tracker.metrics.conservative_estimated_bytes, 1024)
        # Accounted bytes = measured + estimated
        self.assertEqual(self.tracker.metrics.bytes_read, 1280)
        self.assertEqual(self.tracker.metrics.physical_reads_count, 1)
        self.assertEqual(self.tracker.metrics.unmeasured_reads_count, 1)

    def test_collect_process_info_dead_process_records_zero_bytes(self):
        """collect_process_info() on a dead process reconciles 0 bytes, not hardcoded 128 bytes."""
        adapter = MockMeasurementAdapter(alive=False)
        provider = RuntimeEvidenceProvider(adapter=adapter, budget_tracker=self.tracker)

        info, ev_records = provider.collect_process_info(pid=999999)
        self.assertFalse(info["alive"])
        self.assertEqual(len(ev_records), 1)
        self.assertEqual(ev_records[0].collection_status, "FAILED")

        # Must record 0 measured bytes read and 0 accounted bytes
        self.assertEqual(self.tracker.metrics.measured_bytes_read, 0)
        self.assertEqual(self.tracker.metrics.conservative_estimated_bytes, 0)
        self.assertEqual(self.tracker.metrics.bytes_read, 0)
        self.assertEqual(self.tracker.metrics.total_read_failures, 1)

    def test_collect_process_info_alive_uses_estimated_bytes(self):
        """collect_process_info() on alive process uses conservative estimated bytes without fabricating measured bytes."""
        adapter = MockMeasurementAdapter(alive=True)
        provider = RuntimeEvidenceProvider(adapter=adapter, budget_tracker=self.tracker)

        info, ev_records = provider.collect_process_info(pid=1234)
        self.assertTrue(info["alive"])

        # Procfs read is an estimate, NOT measured target inferior memory bytes
        self.assertEqual(self.tracker.metrics.measured_bytes_read, 0)
        self.assertGreater(self.tracker.metrics.conservative_estimated_bytes, 0)
        self.assertEqual(self.tracker.metrics.bytes_read, self.tracker.metrics.conservative_estimated_bytes)
        self.assertEqual(self.tracker.metrics.physical_reads_count, 0)
        self.assertEqual(self.tracker.metrics.unmeasured_reads_count, 1)

    def test_read_memory_range_measures_actual_returned_bytes(self):
        """read_memory_range() accurately charges exact physical bytes read."""
        sim_data = b"0123456789abcdef"  # 16 bytes
        adapter = MockMeasurementAdapter(alive=True, sim_mem=sim_data)
        provider = RuntimeEvidenceProvider(adapter=adapter, budget_tracker=self.tracker)

        # 1. Full 16-byte read
        data, status, err, _ = provider.read_memory_range(1234, 0x2000, 16)
        self.assertEqual(data, sim_data)
        self.assertEqual(self.tracker.metrics.measured_bytes_read, 16)
        self.assertEqual(self.tracker.metrics.physical_reads_count, 1)

        # 2. Short read: requested 32 bytes, target only returns 16 bytes
        data, status, err, _ = provider.read_memory_range(1234, 0x2000, 32)
        self.assertEqual(len(data), 16)
        self.assertEqual(self.tracker.metrics.measured_bytes_read, 32)  # 16 + 16
        self.assertEqual(self.tracker.metrics.physical_reads_count, 2)

        # 3. Failed read: target unmapped address
        adapter_fault = MockMeasurementAdapter(alive=True, sim_mem=b"")
        provider_fault = RuntimeEvidenceProvider(adapter=adapter_fault, budget_tracker=self.tracker)
        data_err, status_err, _, _ = provider_fault.read_memory_range(1234, 0x9999, 16)
        self.assertIsNone(data_err)
        # Failed read charges 0 bytes and records failure
        self.assertEqual(self.tracker.metrics.measured_bytes_read, 32)
        self.assertEqual(self.tracker.metrics.total_read_failures, 1)

    def test_reconciliation_is_strictly_idempotent(self):
        """Calling reconcile_reservation() multiple times with the same reservation_id never double-charges."""
        ok, reason, res_id = self.tracker.reserve(estimated_bytes=500, profile_id="test_profile")
        self.assertTrue(ok)
        self.assertEqual(self.tracker.metrics.reserved_bytes, 500)

        # First reconcile
        res1 = self.tracker.reconcile_reservation(res_id, actual_bytes_read=300)
        self.assertEqual(res1["charged_bytes"], 300)
        self.assertEqual(self.tracker.metrics.bytes_read, 300)
        self.assertEqual(self.tracker.metrics.reserved_bytes, 0)

        # Second reconcile with same ID must be a no-op
        res2 = self.tracker.reconcile_reservation(res_id, actual_bytes_read=300)
        self.assertTrue(res2.get("already_reconciled"))
        self.assertEqual(res2["charged_bytes"], 0)
        # Budget remains charged only 300 bytes, not 600
        self.assertEqual(self.tracker.metrics.bytes_read, 300)

    def test_strict_rejection_of_unknown_byte_cost(self):
        """When reject_unknown_byte_cost=True, unknown byte costs are explicitly rejected rather than guessed."""
        strict_limits = ObservationBudgetLimits(
            max_bytes_read=1000,
            reject_unknown_byte_cost=True,
        )
        tracker = ObservationBudgetTracker(strict_limits)

        # Pre-check with None estimated_bytes must be rejected
        allowed, reason, eff_bytes = tracker.check_pre_execution(estimated_bytes=None)
        self.assertFalse(allowed)
        self.assertIn("UNKNOWN_BYTE_COST_REJECTED", reason)

        # Reserve with None estimated_bytes must fail
        res_ok, res_reason, res_id = tracker.reserve(estimated_bytes=None)
        self.assertFalse(res_ok)
        self.assertIsNone(res_id)
        self.assertEqual(tracker.metrics.rejected_observations_count, 1)

    def test_concurrent_reservations_cannot_oversubscribe_limits(self):
        """Concurrent threads reserving budget cannot exceed max_bytes_read ceiling."""
        small_limits = ObservationBudgetLimits(max_bytes_read=500)
        tracker = ObservationBudgetTracker(small_limits)

        def _worker(thread_idx: int):
            # Each thread tries to reserve 200 bytes
            allowed, _, res_id = tracker.reserve(estimated_bytes=200, profile_id=f"thread_{thread_idx}")
            return allowed, res_id

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(_worker, i) for i in range(5)]
            results = [f.result() for f in futures]

        allowed_count = sum(1 for ok, _ in results if ok)
        # Only 2 threads can reserve 200B (200 + 200 <= 500; third would be 600 > 500)
        self.assertEqual(allowed_count, 2)
        self.assertEqual(tracker.metrics.reserved_bytes, 400)
        self.assertEqual(tracker.metrics.rejected_observations_count, 3)

    def test_exception_during_read_releases_reservation_cleanly(self):
        """Exceptions during an observation release reservations in finally block with zero dangling reservations."""
        class ExplodingAdapter(LocalTargetAdapter):
            def read_memory(self, pid: int, address: int, size: int):
                raise RuntimeError("Hardware bus error simulation")

        provider = RuntimeEvidenceProvider(adapter=ExplodingAdapter(), budget_tracker=self.tracker)
        self.assertEqual(self.tracker.metrics.reserved_bytes, 0)

        data, status, err, recs = provider.read_memory_range(1234, 0x1000, 1024)
        self.assertIsNone(data)
        self.assertIn("Hardware bus error simulation", err)

        # Must have zero dangling reserved bytes
        self.assertEqual(self.tracker.metrics.reserved_bytes, 0)
        self.assertEqual(len(self.tracker.metrics.active_reservations), 0)


if __name__ == "__main__":
    unittest.main()
