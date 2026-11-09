"""Phase 2.3-B: Hard Resource Budget Enforcement Adversarial Test Suite.

Validates:
1. Exact-limit vs one-byte-over-limit enforcement.
2. Reservation mechanism preventing concurrent / replanned overspending.
3. Reconciliation of reservations: actual consumption charged, unused bytes released.
4. Reservation release upon cancellation without budget penalty.
5. Exact exhausted dimension identification (BYTES_READ, WALL_CLOCK, MAX_SAMPLES, CONSECUTIVE_FAILURES).
6. Cumulative multi-epoch budget survival across replanning cycles.
"""

import time
import unittest
from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)


class TestPhase23BudgetAdversarial(unittest.TestCase):
    def test_exact_limit_and_one_byte_over(self):
        """Exact budget limit succeeds; one byte over is immediately rejected."""
        limits = ObservationBudgetLimits(max_bytes_read=1000, max_bytes_per_observation=1000)
        tracker = ObservationBudgetTracker(limits)

        # 1. Exact limit pre-check: 1000 bytes
        can_exec, reason, eff = tracker.check_pre_execution(estimated_bytes=1000)
        self.assertTrue(can_exec)
        self.assertIsNone(reason)
        self.assertEqual(eff, 1000)

        # 2. One byte over limit: 1001 bytes
        can_exec_over, reason_over, eff_over = tracker.check_pre_execution(estimated_bytes=1001)
        self.assertFalse(can_exec_over)
        self.assertIn("EXCEEDED", reason_over)

    def test_reservation_prevents_concurrent_overspending(self):
        """Two operations whose individual estimates fit but collectively exceed budget are protected by reservation."""
        limits = ObservationBudgetLimits(max_bytes_read=1000, max_bytes_per_observation=1000)
        tracker = ObservationBudgetTracker(limits)

        # Operation 1 reserves 600 bytes
        ok1, reason1, res1 = tracker.reserve(estimated_bytes=600)
        self.assertTrue(ok1)
        self.assertIsNotNone(res1)
        self.assertEqual(tracker.metrics.reserved_bytes, 600)

        # Operation 2 attempts to reserve 500 bytes (600 + 500 = 1100 > 1000)
        ok2, reason2, res2 = tracker.reserve(estimated_bytes=500)
        self.assertFalse(ok2)
        self.assertIn("PRECHECK_EXCEEDED_BYTES_READ", reason2)
        self.assertIsNone(res2)

        # Operation 1 reconciles using only 400 bytes (releasing 200 unused bytes)
        rec = tracker.reconcile_reservation(res1, actual_bytes_read=400)
        self.assertEqual(tracker.metrics.reserved_bytes, 0)
        self.assertEqual(tracker.metrics.bytes_read, 400)

        # Operation 2 can now reserve 500 bytes (400 + 500 <= 1000)
        ok2_retry, reason2_retry, res2_retry = tracker.reserve(estimated_bytes=500)
        self.assertTrue(ok2_retry)
        self.assertIsNotNone(res2_retry)

    def test_reservation_release_on_cancellation(self):
        """Releasing an unexecuted reservation restores full budget without recording reads."""
        limits = ObservationBudgetLimits(max_bytes_read=500)
        tracker = ObservationBudgetTracker(limits)

        ok, reason, res_id = tracker.reserve(estimated_bytes=450)
        self.assertTrue(ok)
        self.assertEqual(tracker.metrics.reserved_bytes, 450)

        # Release reservation
        released = tracker.release_reservation(res_id)
        self.assertTrue(released)
        self.assertEqual(tracker.metrics.reserved_bytes, 0)
        self.assertEqual(tracker.metrics.bytes_read, 0)
        self.assertEqual(tracker.metrics.samples_collected, 0)

    def test_exact_exhausted_dimension_recording(self):
        """Exhausting different dimensions accurately populates metrics.exhausted_dimension."""
        # 1. BYTES_READ
        t_bytes = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=500))
        t_bytes.record_read(bytes_read=600)
        self.assertTrue(t_bytes.metrics.is_budget_exhausted)
        self.assertEqual(t_bytes.metrics.exhausted_dimension, "BYTES_READ")

        # 2. CONSECUTIVE_FAILURES
        t_fail = ObservationBudgetTracker(ObservationBudgetLimits(max_consecutive_read_failures=2))
        t_fail.record_read(bytes_read=10, is_failure=True)
        t_fail.record_read(bytes_read=10, is_failure=True)
        self.assertTrue(t_fail.metrics.is_budget_exhausted)
        self.assertEqual(t_fail.metrics.exhausted_dimension, "CONSECUTIVE_FAILURES")

        # 3. MAX_SAMPLES
        t_samp = ObservationBudgetTracker(ObservationBudgetLimits(max_samples=2))
        t_samp.record_sample()
        t_samp.record_sample()
        self.assertTrue(t_samp.metrics.is_budget_exhausted)
        self.assertEqual(t_samp.metrics.exhausted_dimension, "MAX_SAMPLES")

        # 4. WALL_CLOCK
        t_time = ObservationBudgetTracker(ObservationBudgetLimits(max_wall_clock_ms=10.0))
        time.sleep(0.015)
        t_time.check_budget()
        self.assertTrue(t_time.metrics.is_budget_exhausted)
        self.assertEqual(t_time.metrics.exhausted_dimension, "WALL_CLOCK")

    def test_cumulative_budget_survives_replanning(self):
        """Budget metrics survive across multiple planning and execution cycles without resetting."""
        limits = ObservationBudgetLimits(max_bytes_read=1000)
        tracker = ObservationBudgetTracker(limits)

        # Plan 1 execution
        tracker.record_read(bytes_read=300)
        tracker.record_sample()

        # Replanning cycle: tracker is inspected and reused
        self.assertEqual(tracker.metrics.bytes_read, 300)
        self.assertEqual(tracker.metrics.samples_collected, 1)

        # Plan 2 execution
        tracker.record_read(bytes_read=400)
        tracker.record_sample()

        self.assertEqual(tracker.metrics.bytes_read, 700)
        self.assertEqual(tracker.metrics.samples_collected, 2)
        self.assertFalse(tracker.metrics.is_budget_exhausted)

        # Plan 3 exceeds remainder
        can_exec, reason, _ = tracker.check_pre_execution(estimated_bytes=400)
        self.assertFalse(can_exec)
        self.assertIn("PRECHECK_EXCEEDED_BYTES_READ", reason)


if __name__ == "__main__":
    unittest.main()
