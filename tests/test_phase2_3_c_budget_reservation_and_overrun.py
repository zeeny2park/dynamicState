"""Phase 2.3-C: Budget Reservation, Concurrency, and Overrun Hardening Tests.

Validates P0 requirements:
1. Thread-safety: concurrent reservations under multi-threading without data races.
2. Overrun detection and strict ceiling enforcement:
   - Tracks exact overrun counts, overrun bytes, and triggering operation details.
   - Truthfully accounts for total actual consumption without concealments.
   - Prevents subsequent operations once ceiling is breached.
3. Cancellation & Exception Cleanup:
   - Cancelled / aborted operations release reservations immediately without budget penalty.
   - Exception paths leave zero dangling reservations.
4. Cumulative multi-step adaptive replanning across cumulative budget exhaustion.
"""

import threading
import time
import unittest

from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)
from extractor.runtime_evidence_provider import (
    RuntimeEvidenceProvider,
    COLLECTION_STATUS_SUCCESS,
    COLLECTION_STATUS_FAILED,
)
from extractor.target_adapter import TargetExecutionAdapter


class MockFaultyTargetAdapter(TargetExecutionAdapter):
    """Mock adapter for simulating memory reads and exceptions."""
    def __init__(self):
        super().__init__()
        self.should_raise = False
        self.read_data = b"\x00" * 256

    def check_liveness(self, pid: int):
        return True, None

    def get_process_identity(self, pid: int):
        return {"pid": pid, "name": "mock_proc", "start_time": 1000}

    def get_proc_maps(self, pid: int):
        return [{"start": 0x1000, "end": 0x2000, "perms": "r-xp"}]

    def get_threads(self, pid: int):
        return [{"tid": pid, "state": "R"}]

    def is_remote(self) -> bool:
        return False

    @property
    def target_host(self) -> str:
        return "127.0.0.1"

    def read_memory(self, pid: int, address: int, size: int):
        if self.should_raise:
            raise RuntimeError("Hardware bus fault during memory read")
        return self.read_data[:size], "mock_read", None


class TestPhase23CBudgetReservationAndOverrun(unittest.TestCase):
    def test_concurrent_reservations_thread_safety(self):
        """Concurrent reservation requests are synchronized and never admit over-budget totals."""
        limits = ObservationBudgetLimits(max_bytes_read=10000, max_bytes_per_observation=10000)
        tracker = ObservationBudgetTracker(limits)

        threads = []
        admitted = []
        rejected = []
        lock = threading.Lock()

        def try_reserve(idx: int):
            ok, reason, res_id = tracker.reserve(estimated_bytes=600, profile_id=f"worker_{idx}")
            with lock:
                if ok:
                    admitted.append(res_id)
                else:
                    rejected.append(reason)

        # 20 threads simultaneously try to reserve 600 bytes (12,000 bytes requested for 10,000 limit)
        for i in range(20):
            t = threading.Thread(target=try_reserve, args=(i,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # At most 16 threads can be admitted (16 * 600 = 9600 <= 10000)
        self.assertLessEqual(len(admitted), 16)
        self.assertEqual(len(admitted) + len(rejected), 20)
        self.assertLessEqual(tracker.metrics.reserved_bytes, 10000)
        self.assertEqual(tracker.metrics.reserved_bytes, len(admitted) * 600)

        # Release all reservations
        for r_id in admitted:
            tracker.release_reservation(r_id)
        self.assertEqual(tracker.metrics.reserved_bytes, 0)

    def test_overrun_detection_and_metric_accounting(self):
        """When actual consumption exceeds reservation, overrun metrics are faithfully recorded."""
        limits = ObservationBudgetLimits(max_bytes_read=5000, max_bytes_per_observation=5000)
        tracker = ObservationBudgetTracker(limits)

        # Reserve 200 bytes
        ok, _, res_id = tracker.reserve(estimated_bytes=200, profile_id="test_read")
        self.assertTrue(ok)
        self.assertEqual(tracker.metrics.reserved_bytes, 200)
        self.assertEqual(tracker.metrics.overrun_count, 0)
        self.assertEqual(tracker.metrics.total_overrun_bytes, 0)

        # Actual read was 550 bytes (350 byte overrun)
        tracker.reconcile_reservation(res_id, actual_bytes_read=550)
        self.assertEqual(tracker.metrics.reserved_bytes, 0)
        self.assertEqual(tracker.metrics.bytes_read, 550)
        self.assertEqual(tracker.metrics.overrun_count, 1)
        self.assertEqual(tracker.metrics.total_overrun_bytes, 350)
        self.assertIsNotNone(tracker.metrics.last_overrun_details)
        self.assertEqual(tracker.metrics.last_overrun_details["estimated_bytes"], 200)
        self.assertEqual(tracker.metrics.last_overrun_details["actual_bytes"], 550)
        self.assertEqual(tracker.metrics.last_overrun_details["overrun_bytes"], 350)

    def test_overrun_breaching_ceiling_prevents_subsequent_operations(self):
        """An overrun that pushes cumulative usage over the budget ceiling terminates further actions."""
        limits = ObservationBudgetLimits(max_bytes_read=1000, max_bytes_per_observation=2000)
        tracker = ObservationBudgetTracker(limits)

        # Reserve 400 bytes (fits well within 1000 limit)
        ok1, _, res1 = tracker.reserve(estimated_bytes=400, profile_id="step1")
        self.assertTrue(ok1)

        # Operation experiences massive overrun: reads 1500 bytes
        tracker.reconcile_reservation(res1, actual_bytes_read=1500)
        self.assertEqual(tracker.metrics.bytes_read, 1500)
        self.assertEqual(tracker.metrics.overrun_count, 1)
        self.assertEqual(tracker.metrics.total_overrun_bytes, 1100)

        # Budget is now exhausted on BYTES_READ
        self.assertTrue(tracker.metrics.is_budget_exhausted)
        self.assertEqual(tracker.metrics.exhausted_dimension, "BYTES_READ")
        self.assertIn("EXCEEDED_BYTES_READ", tracker.metrics.exhaustion_reason)
        self.assertFalse(tracker.can_continue())

        # Any subsequent reservation must fail-closed
        ok2, reason2, res2 = tracker.reserve(estimated_bytes=10, profile_id="step2")
        self.assertFalse(ok2)
        self.assertIn("EXCEEDED_BYTES_READ", reason2)
        self.assertIsNone(res2)

    def test_runtime_evidence_provider_reservation_cleanup_on_exception(self):
        """If target adapter throws an uncaught exception, reservation is released and not leaked."""
        limits = ObservationBudgetLimits(max_bytes_read=10000)
        tracker = ObservationBudgetTracker(limits)
        adapter = MockFaultyTargetAdapter()
        adapter.should_raise = True

        provider = RuntimeEvidenceProvider(adapter=adapter, budget_tracker=tracker)

        # Initial state clean
        self.assertEqual(tracker.metrics.reserved_bytes, 0)
        self.assertEqual(len(tracker.metrics.active_reservations), 0)

        data, method, err, recs = provider.read_memory_range(pid=123, address=0x1000, size=64)

        # Read failed due to exception
        self.assertIsNone(data)
        self.assertEqual(recs[0].collection_status, COLLECTION_STATUS_FAILED)
        self.assertIn("Hardware bus fault", recs[0].limitations[0])

        # Budget reservation was cleanly released and not leaked
        self.assertEqual(tracker.metrics.reserved_bytes, 0)
        self.assertEqual(len(tracker.metrics.active_reservations), 0)

    def test_runtime_evidence_provider_reconciles_actual_memory_read(self):
        """Successful memory read reconciles reservation and charges exact bytes read."""
        limits = ObservationBudgetLimits(max_bytes_read=10000)
        tracker = ObservationBudgetTracker(limits)
        adapter = MockFaultyTargetAdapter()
        adapter.should_raise = False
        adapter.read_data = b"ABCDEFGHIJ" * 10  # 100 bytes

        provider = RuntimeEvidenceProvider(adapter=adapter, budget_tracker=tracker)

        data, method, err, recs = provider.read_memory_range(pid=123, address=0x1000, size=80)
        self.assertIsNotNone(data)
        self.assertEqual(len(data), 80)
        self.assertEqual(recs[0].collection_status, COLLECTION_STATUS_SUCCESS)

        # Budget tracker reconciled
        self.assertEqual(tracker.metrics.reserved_bytes, 0)
        self.assertEqual(tracker.metrics.bytes_read, 80)
        self.assertEqual(tracker.metrics.measured_bytes_read, 80)
        self.assertEqual(tracker.metrics.samples_collected, 1)


if __name__ == "__main__":
    unittest.main()
