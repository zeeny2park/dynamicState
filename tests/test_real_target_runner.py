"""Unit and regression tests for Phase 17 Real-Target Validation Integrity & Failure Semantics."""

import json
import os
import subprocess
import time
import unittest
from unittest import mock

import scripts.mcp_server as mcp_srv
import scripts.validate_real_target as vrt


class TestRealTargetRunner(unittest.TestCase):
    """Verifies validation integrity, failure semantics, handshake safety, and cleanup guarantees."""

    def setUp(self) -> None:
        vrt.reset_target_context(mcp_srv.runtime.watch_session_manager)

    def tearDown(self) -> None:
        vrt.reset_target_context(mcp_srv.runtime.watch_session_manager)

    def test_01_real_target_validation_end_to_end_success(self) -> None:
        """Verifies end-to-end real-target validation against live stripped C++ binary."""
        exit_code, summary = vrt.run_real_target_validation(
            samples=5,
            max_latency_ms=15.0,
            sla_metric="median",
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
        self.assertEqual(latency["sla_metric"], "median")
        self.assertTrue(latency["within_sla"])

        # Semantic expression values
        observed = summary["observed_expressions"]
        self.assertGreaterEqual(observed["packet_count"], 100)
        self.assertIn("CONNECTED", observed["state"])
        self.assertEqual(observed["buffer_length"], 64)
        self.assertTrue(0 <= observed["retry"] <= 4)

        # Evidence distinction
        evidence = summary["evidence"]
        self.assertFalse(evidence["api_metadata"]["process_stopped"])
        self.assertGreater(evidence["worker_progress"]["delta"], 0)
        self.assertFalse(evidence["consistency_semantics"]["is_atomic_read"])
        self.assertEqual(evidence["consistency_semantics"]["causal_guarantee"], "NONE")

        # Deliberate mismatch rejection
        mismatch = summary["mismatch_rejection"]
        self.assertTrue(mismatch["rejected"])
        self.assertEqual(mismatch["error_code"], "BUILD_ID_MISMATCH")

        # Verify target context was cleanly reset
        active_ctx = mcp_srv.runtime.watch_session_manager.get_active_target_context()
        self.assertIsNone(active_ctx.get("pid"), "Active target context PID must be reset to None after run")

    def test_02_ready_handshake_missing_ready(self) -> None:
        """Verifies that target output missing 'READY: PID=' is detected and rejected promptly."""
        # Process that writes something else and exits
        proc = subprocess.Popen(
            ["python3", "-u", "-c", "import sys; print('STARTING_UP...', flush=True)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            with self.assertRaises(RuntimeError) as cm:
                vrt.read_ready_handshake(proc, timeout=1.0)
            self.assertIn("READY", str(cm.exception))
        finally:
            vrt.cleanup_target_process(proc)

    def test_03_ready_handshake_malformed_pid(self) -> None:
        """Verifies that non-integer or mismatched PIDs in the handshake are rejected."""
        # Non-integer PID
        proc1 = subprocess.Popen(
            ["python3", "-u", "-c", "print('READY: PID=not_a_number', flush=True)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            with self.assertRaises(RuntimeError) as cm:
                vrt.read_ready_handshake(proc1, timeout=1.0)
            self.assertIn("Malformed non-integer PID", str(cm.exception))
        finally:
            vrt.cleanup_target_process(proc1)

        # Mismatched PID
        proc2 = subprocess.Popen(
            ["python3", "-u", "-c", "print('READY: PID=9999999', flush=True)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            with self.assertRaises(RuntimeError) as cm:
                vrt.read_ready_handshake(proc2, timeout=1.0)
            self.assertIn("Handshake PID mismatch", str(cm.exception))
        finally:
            vrt.cleanup_target_process(proc2)

    def test_04_ready_handshake_early_exit_with_stderr(self) -> None:
        """Verifies that early target process exit captures stderr and returncode."""
        proc = subprocess.Popen(
            ["python3", "-u", "-c", "import sys; sys.stderr.write('Fatal crash\\n'); sys.exit(42)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            with self.assertRaises(RuntimeError) as cm:
                vrt.read_ready_handshake(proc, timeout=1.0)
            err_msg = str(cm.exception)
            self.assertIn("exited prematurely with returncode 42", err_msg)
            self.assertIn("Fatal crash", err_msg)
        finally:
            vrt.cleanup_target_process(proc)

    def test_05_ready_handshake_timeout_nonblocking(self) -> None:
        """Verifies that a hanging target process does not block readline() and times out promptly."""
        # Process that hangs without writing anything
        proc = subprocess.Popen(
            ["python3", "-u", "-c", "import time; time.sleep(10)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        t0 = time.time()
        try:
            with self.assertRaises(TimeoutError) as cm:
                vrt.read_ready_handshake(proc, timeout=0.2)
            elapsed = time.time() - t0
            self.assertLess(elapsed, 1.0, f"Handshake read blocked: elapsed {elapsed}s > 1.0s")
            self.assertIn("Timed out after 0.2s", str(cm.exception))
        finally:
            vrt.cleanup_target_process(proc)
            self.assertIsNotNone(proc.poll(), "Hanging child process must be terminated and reaped")

    def test_06_cleanup_process_graceful_and_sigkill_escalation(self) -> None:
        """Verifies process termination closes pipes, handles SIGTERM, and escalates to SIGKILL."""
        # 1. Normal process that exits on SIGTERM
        mock_proc = mock.MagicMock(spec=subprocess.Popen)
        mock_proc.poll.side_effect = [None, 0]
        mock_proc.stdout = mock.MagicMock()
        mock_proc.stdout.closed = False
        mock_proc.stderr = mock.MagicMock()
        mock_proc.stderr.closed = False
        mock_proc.stdin = None

        vrt.cleanup_target_process(mock_proc, terminate_timeout=0.1, kill_timeout=0.1)
        mock_proc.send_signal.assert_called_once()
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

    def test_07_cleanup_process_kill_timeout_failure(self) -> None:
        """Verifies that a process refusing SIGKILL raises a descriptive RuntimeError."""
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

    def test_08_cleanup_failure_alone_causes_failed_status_and_exit_1(self) -> None:
        """Verifies that a cleanup failure during an otherwise passing run causes FAILED status and exit code 1."""
        with mock.patch("scripts.validate_real_target.reset_target_context", side_effect=RuntimeError("injected_reset_failure")):
            exit_code, summary = vrt.run_real_target_validation(samples=2, verbose=False)

            self.assertEqual(exit_code, 1, "Cleanup failure must cause non-zero exit code")
            self.assertEqual(summary["status"], "FAILED", "Cleanup failure must flip status to FAILED")
            self.assertTrue(any("injected_reset_failure" in err for err in summary["cleanup_errors"]))
            self.assertTrue(any("injected_reset_failure" in f for f in summary["failures"]))

    def test_09_dual_failure_preserves_both_validation_and_cleanup_errors(self) -> None:
        """Verifies that when both validation and cleanup fail, both errors are preserved without masking."""
        with mock.patch("scripts.validate_real_target.reset_target_context", side_effect=RuntimeError("injected_reset_error")):
            # Trigger validation failure via SLA violation
            exit_code, summary = vrt.run_real_target_validation(
                samples=2,
                max_latency_ms=0.0001,
                verbose=False,
            )

            self.assertEqual(exit_code, 1)
            self.assertEqual(summary["status"], "FAILED")
            # Must contain both the SLA failure and the cleanup error
            sla_found = any("SLA violation" in f for f in summary["failures"])
            cleanup_found = any("injected_reset_error" in f for f in summary["failures"])
            self.assertTrue(sla_found, "Original validation error must not be masked")
            self.assertTrue(cleanup_found, "Cleanup error must be preserved alongside validation error")

    def test_10_invalid_numeric_configuration_rejection(self) -> None:
        """Verifies rejection of invalid samples, max_latency_ms, or sla_metric configuration."""
        # Non-positive samples
        code1, sum1 = vrt.run_real_target_validation(samples=0, verbose=False)
        self.assertEqual(code1, 1)
        self.assertEqual(sum1["status"], "FAILED")
        self.assertIn("Invalid samples count", sum1["failures"][0])

        # Negative max_latency_ms
        code2, sum2 = vrt.run_real_target_validation(max_latency_ms=-1.0, verbose=False)
        self.assertEqual(code2, 1)
        self.assertIn("Invalid max_latency_ms", sum2["failures"][0])

        # Invalid sla_metric
        code3, sum3 = vrt.run_real_target_validation(sla_metric="invalid_metric", verbose=False)
        self.assertEqual(code3, 1)
        self.assertIn("Invalid sla_metric", sum3["failures"][0])

    def test_11_latency_sla_violation_and_metrics(self) -> None:
        """Verifies that SLA violation correctly evaluates the specified metric (median, p95, max)."""
        # Test median SLA violation
        exit_code, summary = vrt.run_real_target_validation(
            samples=3,
            max_latency_ms=0.0001,
            sla_metric="median",
            verbose=False,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(summary["status"], "FAILED")
        self.assertTrue(any("Latency SLA violation: median" in f for f in summary["failures"]))
        self.assertFalse(summary["latency_benchmark"]["within_sla"])

        # Test p95 SLA metric configuration
        stats = vrt.calculate_latency_stats([1.0, 2.0, 10.0], threshold_ms=5.0, sla_metric="p95")
        self.assertEqual(stats["sla_metric"], "p95")
        self.assertEqual(stats["sla_value_ms"], 10.0)
        self.assertFalse(stats["within_sla"])

        # Test max SLA metric configuration
        stats_max = vrt.calculate_latency_stats([1.0, 2.0, 4.0], threshold_ms=5.0, sla_metric="max")
        self.assertEqual(stats_max["sla_metric"], "max")
        self.assertEqual(stats_max["sla_value_ms"], 4.0)
        self.assertTrue(stats_max["within_sla"])

    def test_12_calculate_latency_stats_distribution(self) -> None:
        """Verifies statistical calculation of min, median, p95, and SLA evaluation."""
        empty_stats = vrt.calculate_latency_stats([], threshold_ms=10.0)
        self.assertEqual(empty_stats["sample_count"], 0)
        self.assertFalse(empty_stats["within_sla"])

        odd_stats = vrt.calculate_latency_stats([5.0, 1.0, 4.0, 2.0, 3.0], threshold_ms=4.0)
        self.assertEqual(odd_stats["sample_count"], 5)
        self.assertEqual(odd_stats["min_ms"], 1.0)
        self.assertEqual(odd_stats["median_ms"], 3.0)
        self.assertEqual(odd_stats["max_ms"], 5.0)
        self.assertTrue(odd_stats["within_sla"])

        even_stats = vrt.calculate_latency_stats([1.0, 2.0, 3.0, 4.0], threshold_ms=2.0)
        self.assertEqual(even_stats["median_ms"], 2.5)
        self.assertFalse(even_stats["within_sla"])

    def test_13_target_context_reset_safety(self) -> None:
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

    def test_14_evidence_distinction_and_semantics(self) -> None:
        """Verifies that evidence clearly partitions API metadata, worker progress, and consistency semantics."""
        exit_code, summary = vrt.run_real_target_validation(samples=2, verbose=False)
        self.assertEqual(exit_code, 0)

        self.assertIn("evidence", summary)
        evidence = summary["evidence"]

        # 1. API metadata
        api_meta = evidence["api_metadata"]
        self.assertIs(api_meta["process_stopped"], False)
        self.assertEqual(api_meta["mechanism"], "ZERO_STOP_CONCURRENT_READ")
        self.assertIn("did not attach a debugger", api_meta["interpretation"])

        # 2. Worker progress
        worker = evidence["worker_progress"]
        self.assertGreater(worker["delta"], 0)
        self.assertTrue(worker["continued_execution"])

        # 3. Consistency semantics
        consistency = evidence["consistency_semantics"]
        self.assertEqual(consistency["level"], "NON_ATOMIC")
        self.assertIs(consistency["is_atomic_read"], False)
        self.assertEqual(consistency["causal_guarantee"], "NONE")
        self.assertIn("disclaimer", consistency)
        self.assertIn("cannot prove absolute 0.00ns pause", consistency["disclaimer"])


if __name__ == "__main__":
    unittest.main()
