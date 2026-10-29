"""Unit and regression tests for Phase 16 Real-Target Validation Runner."""

import json
import os
import subprocess
import unittest
from unittest import mock

import scripts.mcp_server as mcp_srv
import scripts.validate_real_target as vrt


class TestRealTargetRunner(unittest.TestCase):
    """Verifies the correctness, isolation, and lifecycle handling of the real-target validation runner."""

    def setUp(self) -> None:
        vrt.reset_target_context(mcp_srv.runtime.watch_session_manager)

    def tearDown(self) -> None:
        vrt.reset_target_context(mcp_srv.runtime.watch_session_manager)

    def test_01_real_target_validation_end_to_end(self) -> None:
        """Verifies end-to-end real-target validation against live stripped C++ binary."""
        exit_code, summary = vrt.run_real_target_validation(
            samples=5,
            max_latency_ms=15.0,
            verbose=False,
        )

        self.assertEqual(exit_code, 0, f"Expected validation success: {summary.get('failures')}")
        self.assertEqual(summary["status"], "PASSED")
        self.assertGreaterEqual(summary["assertions_passed"], 30)

        # Target identity verification
        target = summary["target"]
        self.assertIsInstance(target["pid"], int)
        self.assertGreaterEqual(target["threads_count"], 2)
        self.assertTrue(target["load_bias"].startswith("0x"))
        self.assertTrue(target["build_id"])

        # Latency statistics verification
        latency = summary["latency_benchmark"]
        self.assertEqual(latency["sample_count"], 5)
        self.assertGreater(latency["min_ms"], 0.0)
        self.assertLessEqual(latency["median_ms"], 15.0)
        self.assertTrue(latency["within_sla"])

        # Semantic expression values
        observed = summary["observed_expressions"]
        self.assertGreaterEqual(observed["packet_count"], 100)
        self.assertIn("CONNECTED", observed["state"])
        self.assertEqual(observed["buffer_length"], 64)
        self.assertTrue(0 <= observed["retry"] <= 4)

        # Concurrent worker progress
        progress = summary["worker_progress"]
        self.assertGreater(progress["delta"], 0)
        self.assertTrue(progress["continued_execution"])

        # Non-atomic consistency metadata
        consistency = summary["consistency_metadata"]
        self.assertFalse(consistency["process_stopped"])
        self.assertFalse(consistency["is_atomic_read"])
        self.assertEqual(consistency["causal_guarantee"], "NONE")

        # Deliberate mismatch rejection
        mismatch = summary["mismatch_rejection"]
        self.assertTrue(mismatch["rejected"])
        self.assertEqual(mismatch["error_code"], "BUILD_ID_MISMATCH")

        # Verify target context was cleanly reset
        active_ctx = mcp_srv.runtime.watch_session_manager.get_active_target_context()
        self.assertIsNone(active_ctx.get("pid"), "Active target context PID must be reset to None after run")

    def test_02_latency_threshold_sla_enforcement(self) -> None:
        """Verifies that exceeding the configured SLA threshold causes an explicit test failure."""
        exit_code, summary = vrt.run_real_target_validation(
            samples=2,
            max_latency_ms=0.0001,  # Unrealistically tight threshold to guarantee violation
            verbose=False,
        )

        self.assertEqual(exit_code, 1, "Validation must exit with non-zero status on SLA violation")
        self.assertEqual(summary["status"], "FAILED")
        self.assertTrue(any("exceeded SLA threshold" in f for f in summary["failures"]))

        # Verify target context is still safely reset despite failure
        active_ctx = mcp_srv.runtime.watch_session_manager.get_active_target_context()
        self.assertIsNone(active_ctx.get("pid"), "Active target context must be reset even on failure")

    def test_03_cleanup_process_graceful_and_sigkill_escalation(self) -> None:
        """Verifies process termination closes pipes, handles SIGTERM, and escalates to SIGKILL."""
        # 1. Normal process that exits on SIGTERM
        mock_proc = mock.MagicMock(spec=subprocess.Popen)
        mock_proc.poll.side_effect = [None, 0]  # Running initially, then exited after SIGTERM
        mock_proc.stdout = mock.MagicMock()
        mock_proc.stdout.closed = False
        mock_proc.stderr = mock.MagicMock()
        mock_proc.stderr.closed = False
        mock_proc.stdin = None

        vrt.cleanup_target_process(mock_proc, terminate_timeout=0.1, kill_timeout=0.1)
        mock_proc.send_signal.assert_called_once_with(mock.ANY)
        mock_proc.kill.assert_not_called()
        mock_proc.stdout.close.assert_called_once()
        mock_proc.stderr.close.assert_called_once()

        # 2. Process refusing SIGTERM: escalates to SIGKILL
        mock_stuck = mock.MagicMock(spec=subprocess.Popen)
        mock_stuck.pid = 12345
        mock_stuck.poll.side_effect = [None, 0]
        mock_stuck.wait.side_effect = [subprocess.TimeoutExpired(cmd="test", timeout=0.1), None]
        mock_stuck.stdout = None
        mock_stuck.stderr = None
        mock_stuck.stdin = None

        vrt.cleanup_target_process(mock_stuck, terminate_timeout=0.1, kill_timeout=0.1)
        mock_stuck.kill.assert_called_once()

        # 3. Process refusing SIGKILL: raises RuntimeError
        mock_deadlocked = mock.MagicMock(spec=subprocess.Popen)
        mock_deadlocked.pid = 99999
        mock_deadlocked.poll.return_value = None
        mock_deadlocked.wait.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=0.1)
        mock_deadlocked.stdout = None
        mock_deadlocked.stderr = None
        mock_deadlocked.stdin = None

        with self.assertRaises(RuntimeError) as cm:
            vrt.cleanup_target_process(mock_deadlocked, terminate_timeout=0.1, kill_timeout=0.1)
        self.assertIn("refused to exit after SIGKILL", str(cm.exception))

    def test_04_calculate_latency_stats_distribution(self) -> None:
        """Verifies statistical calculation of min, median, p95, and SLA evaluation."""
        # Empty samples
        empty_stats = vrt.calculate_latency_stats([], threshold_ms=10.0)
        self.assertEqual(empty_stats["sample_count"], 0)
        self.assertFalse(empty_stats["within_sla"])

        # Odd count: [1.0, 2.0, 3.0, 4.0, 5.0] -> median 3.0, p95 5.0
        odd_stats = vrt.calculate_latency_stats([5.0, 1.0, 4.0, 2.0, 3.0], threshold_ms=4.0)
        self.assertEqual(odd_stats["sample_count"], 5)
        self.assertEqual(odd_stats["min_ms"], 1.0)
        self.assertEqual(odd_stats["median_ms"], 3.0)
        self.assertEqual(odd_stats["max_ms"], 5.0)
        self.assertTrue(odd_stats["within_sla"])

        # Even count: [1.0, 2.0, 3.0, 4.0] -> median 2.5
        even_stats = vrt.calculate_latency_stats([1.0, 2.0, 3.0, 4.0], threshold_ms=2.0)
        self.assertEqual(even_stats["median_ms"], 2.5)
        self.assertFalse(even_stats["within_sla"])

    def test_05_target_context_reset_safety(self) -> None:
        """Verifies that reset_target_context completely clears active context and session registry."""
        wm = mcp_srv.runtime.watch_session_manager
        with wm._lock:
            wm._active_target_context["pid"] = 99999
            wm._active_target_context["build_id"] = "deadbeef"
            wm._sessions["sess_dummy"] = mock.MagicMock()

        self.assertEqual(wm.get_active_target_context().get("pid"), 99999)
        self.assertIn("sess_dummy", wm._sessions)

        vrt.reset_target_context(wm)

        active = wm.get_active_target_context()
        self.assertIsNone(active.get("pid"))
        self.assertIsNone(active.get("build_id"))
        self.assertEqual(len(wm._sessions), 0)


if __name__ == "__main__":
    unittest.main()
