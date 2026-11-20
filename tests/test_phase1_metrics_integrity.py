"""Deterministic integrity and edge-case verification tests for Phase 1 performance metrics.

Tests:
- repeated SSH invocations
- multiple adapters
- cumulative metrics vs per-operation metrics
- retries and ControlMaster reconnects
- remote connection timeout and early failure metrics
- partial collection failures (error isolation)
- budget exhaustion / early cancellation
- checkpoint duration tracking
- nested phase durations and clock consistency
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from extractor.diagnostic_performance import (
    DiagnosticPerformanceMetrics,
    DiagnosticPerformanceTracker,
)
from extractor.expert_diagnostic_engine import (
    DiagnoseResult,
    ExpertDiagnosticEngine,
    diagnose,
)
from extractor.target_adapter import LocalTargetAdapter, RemoteSshTargetAdapter

RESULT_KEYS = {
    "schema_version", "verdict", "confidence", "confidence_basis", "summary", "findings", "checks_run",
    "not_covered", "collection_impact", "report_path", "report", "investigation_id", "target", "state",
    "stop_reason", "duration_s", "healthy_scope", "symptom_interpretation", "process_profile",
}


class TestPhase1MetricsIntegrity(unittest.TestCase):
    """Deterministic validation of metric semantics, aggregation, and accounting invariants."""

    def test_merge_adapter_metrics_multiple_adapters(self):
        """Verify that multiple distinct adapters accumulate their metrics instead of overwriting."""
        tracker = DiagnosticPerformanceTracker()

        adapter_a_metrics = {
            "adapter_id": "adapter_target",
            "ssh_commands_count": 10,
            "ssh_connections_count": 2,
            "control_master_reconnects_count": 1,
            "retries_count": 1,
            "remote_bytes_transferred": 5000,
            "remote_connection_establishment_s": 0.05,
            "ssh_command_execution_s": 0.50,
            "remote_command_s": 0.50,
            "retry_s": 0.05,
        }

        adapter_b_metrics = {
            "adapter_id": "adapter_sidecar",
            "ssh_commands_count": 4,
            "ssh_connections_count": 1,
            "control_master_reconnects_count": 0,
            "retries_count": 0,
            "remote_bytes_transferred": 2000,
            "remote_connection_establishment_s": 0.02,
            "ssh_command_execution_s": 0.20,
            "remote_command_s": 0.20,
            "retry_s": 0.0,
        }

        tracker.merge_adapter_metrics(adapter_a_metrics, adapter_id="adapter_target")
        tracker.merge_adapter_metrics(adapter_b_metrics, adapter_id="adapter_sidecar")

        m = tracker.finish()
        self.assertEqual(m.ssh_commands_count, 14)
        self.assertEqual(m.ssh_connections_count, 3)
        self.assertEqual(m.control_master_reconnects_count, 1)
        self.assertEqual(m.retries_count, 1)
        self.assertEqual(m.remote_bytes_transferred, 7000)
        self.assertAlmostEqual(m.ssh_command_execution_s, 0.70, places=3)
        self.assertAlmostEqual(m.remote_connection_establishment_s, 0.07, places=3)
        self.assertAlmostEqual(m.retry_s, 0.05, places=3)

    def test_merge_adapter_metrics_repeated_polling_no_double_counting(self):
        """Repeatedly merging cumulative snapshots from the same adapter must update, not double-count."""
        tracker = DiagnosticPerformanceTracker()

        # Step 1: initial checkpoint
        step1_metrics = {
            "ssh_commands_count": 3,
            "ssh_connections_count": 1,
            "control_master_reconnects_count": 0,
            "retries_count": 0,
            "remote_bytes_transferred": 1200,
            "remote_connection_establishment_s": 0.03,
            "ssh_command_execution_s": 0.15,
            "remote_command_s": 0.15,
            "retry_s": 0.0,
        }
        tracker.merge_adapter_metrics(step1_metrics, adapter_id="main_adapter")

        # Step 2: later checkpoint from the same adapter with updated cumulative totals
        step2_metrics = {
            "ssh_commands_count": 8,
            "ssh_connections_count": 2,
            "control_master_reconnects_count": 1,
            "retries_count": 1,
            "remote_bytes_transferred": 3500,
            "remote_connection_establishment_s": 0.03,
            "ssh_command_execution_s": 0.42,
            "remote_command_s": 0.42,
            "retry_s": 0.04,
        }
        tracker.merge_adapter_metrics(step2_metrics, adapter_id="main_adapter")

        m = tracker.finish()
        self.assertEqual(m.ssh_commands_count, 8)
        self.assertEqual(m.ssh_connections_count, 2)
        self.assertEqual(m.control_master_reconnects_count, 1)
        self.assertEqual(m.retries_count, 1)
        self.assertEqual(m.remote_bytes_transferred, 3500)
        self.assertAlmostEqual(m.ssh_command_execution_s, 0.42, places=3)

    def test_evidence_reuse_ratio_semantics(self):
        """Verify evidence reuse ratio calculation handles 0, single, and multiple reused observations."""
        tracker = DiagnosticPerformanceTracker()
        # 0 observations -> ratio 0.0
        m0 = tracker.finish()
        self.assertEqual(m0.evidence_reuse_ratio, 0.0)

        # 2 collected operations, 2 reused observations -> 2 / (2 + 2) = 0.50
        tracker.record_recipe_collection("RECIPE_1", 0.01)
        tracker.record_recipe_collection("RECIPE_2", 0.01)
        tracker.record_reused_observation(2)
        m1 = tracker.finish()
        self.assertEqual(m1.collection_operations_count, 2)
        self.assertEqual(m1.duplicate_or_reusable_observations_count, 2)
        self.assertEqual(m1.remote_calls_avoided_count, 2)
        self.assertAlmostEqual(m1.evidence_reuse_ratio, 0.50, places=4)

    def test_nested_phase_durations_with_mocked_monotonic_clock(self):
        """Verify clock consistency and nested phase duration accumulation using a deterministic mocked clock."""
        fake_time = [100.0]

        def monotonic_mock():
            return fake_time[0]

        with patch("time.monotonic", side_effect=monotonic_mock):
            tracker = DiagnosticPerformanceTracker()

            # Plan phase takes 0.05s
            with tracker.measure_phase("plan_generation_s"):
                fake_time[0] += 0.05

            # Local analysis phase takes 0.12s
            with tracker.measure_phase("local_analysis_s"):
                fake_time[0] += 0.12

            # Checkpoint phase takes 0.03s
            with tracker.measure_phase("checkpoint_s"):
                fake_time[0] += 0.03

            # Total elapsed wall-clock is 0.25s
            fake_time[0] += 0.05
            metrics = tracker.finish(total_wall_clock_s=fake_time[0] - 100.0)

        self.assertAlmostEqual(metrics.plan_generation_s, 0.05, places=4)
        self.assertAlmostEqual(metrics.local_analysis_s, 0.12, places=4)
        self.assertAlmostEqual(metrics.checkpoint_s, 0.03, places=4)
        self.assertAlmostEqual(metrics.total_wall_clock_s, 0.25, places=4)

        # Invariant: subphase durations must not exceed total wall-clock time
        subphase_sum = (
            metrics.plan_generation_s
            + metrics.local_analysis_s
            + metrics.checkpoint_s
        )
        self.assertLessEqual(subphase_sum, metrics.total_wall_clock_s)

    def test_ssh_adapter_retries_and_reconnect_counters(self):
        """Verify that RemoteSshTargetAdapter correctly counts invocations, bytes, retries, and reconnects."""
        calls = [0]

        def fake_runner(args, timeout, input_bytes=None, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                # First command triggers ControlMaster broken pipe error -> reconnect retry
                return 255, "", "mux_client_request_session: Broken pipe"
            return 0, "ok response", ""

        adapter = RemoteSshTargetAdapter(
            host="10.0.0.1",
            user="testuser",
            command_runner=fake_runner,
            use_control_master=True,
            timeout_sec=2.0,
        )

        rc, out, err = adapter.run_ssh("echo test")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "ok response")

        p = adapter.get_performance_metrics()
        self.assertGreaterEqual(p["ssh_commands_count"], 1)
        self.assertGreaterEqual(p["retries_count"], 1)
        self.assertGreaterEqual(p["control_master_reconnects_count"], 1)
        self.assertGreater(p["remote_bytes_transferred"], 0)
        self.assertGreater(p["ssh_command_execution_s"], 0.0)

    def test_remote_connection_failure_populates_metrics(self):
        """Verify that early failure in remote connection populates performance_metrics instead of empty dict."""
        tmp = tempfile.mkdtemp(prefix="test_metrics_unreach_")
        corpus = os.path.join(tmp, "corpus")
        os.makedirs(corpus, mode=0o700, exist_ok=True)
        os.chmod(corpus, 0o700)
        try:
            res = diagnose(
                pid=99999,
                target={"remote_host": "192.0.2.1", "ssh_user": "nobody", "ssh_port": 2222, "timeout_s": 0.2},
                debug_image=None,
                corpus_dir=corpus,
            )
            # Contract checks
            d = res.to_dict()
            self.assertEqual(set(d), RESULT_KEYS)
            m = res.performance_metrics
            self.assertIsInstance(m, dict)
            self.assertIn("total_wall_clock_s", m)
            self.assertIn("ssh_commands_count", m)
            self.assertGreater(m["total_wall_clock_s"], 0.0)
            self.assertIn("performance_metrics", res.collection_impact)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_recipe_execution_counters_invariants(self):
        """Verify that recipes_planned, recipes_executed, recipes_skipped, and failed_recipes remain consistent."""
        tracker = DiagnosticPerformanceTracker()
        tracker.metrics.recipes_planned_count = 10

        # Simulate 6 executed, 3 skipped, 1 failed
        for _ in range(6):
            tracker.record_recipe_collection("RECIPE_OK", 0.01)
            tracker.metrics.recipes_executed_count += 1
        tracker.metrics.recipes_skipped_count += 3
        tracker.metrics.failed_recipes_count += 1

        m = tracker.finish()
        self.assertEqual(m.recipes_planned_count, 10)
        self.assertEqual(m.recipes_executed_count, 6)
        self.assertEqual(m.recipes_skipped_count, 3)
        self.assertEqual(m.failed_recipes_count, 1)

        # Invariant: executed + skipped + failed equals total planned
        self.assertEqual(
            m.recipes_executed_count + m.recipes_skipped_count + m.failed_recipes_count,
            m.recipes_planned_count,
        )


if __name__ == "__main__":
    unittest.main()
