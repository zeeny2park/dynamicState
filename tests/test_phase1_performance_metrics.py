"""Tests for Phase 1 performance measurement and baseline metrics instrumentation."""

import os
import shutil
import tempfile
import unittest

from extractor.diagnostic_performance import (
    DiagnosticPerformanceMetrics,
    DiagnosticPerformanceTracker,
)
from extractor.expert_diagnostic_engine import DiagnoseResult, ExpertDiagnosticEngine, diagnose
from extractor.target_adapter import RemoteSshTargetAdapter


class TestDiagnosticPerformanceMetrics(unittest.TestCase):
    """Test standalone metrics container and tracker behavior."""

    def test_metrics_container_initialization(self):
        m = DiagnosticPerformanceMetrics()
        d = m.to_dict()
        self.assertIn("total_wall_clock_s", d)
        self.assertIn("plan_generation_s", d)
        self.assertIn("local_analysis_s", d)
        self.assertIn("remote_command_s", d)
        self.assertIn("ssh_commands_count", d)
        self.assertIn("ssh_connections_count", d)
        self.assertIn("control_master_reconnects_count", d)
        self.assertIn("retries_count", d)
        self.assertIn("remote_bytes_transferred", d)
        self.assertIn("recipes_planned_count", d)
        self.assertIn("recipes_executed_count", d)
        self.assertIn("evidence_reuse_ratio", d)
        self.assertEqual(len(d), 40)

    def test_tracker_measures_phase_monotonic(self):
        tracker = DiagnosticPerformanceTracker()
        with tracker.measure_phase("plan_generation_s"):
            # short monotonic operation
            _ = [x * x for x in range(1000)]
        metrics = tracker.finish()
        self.assertGreater(metrics.plan_generation_s, 0.0)
        self.assertGreater(metrics.total_wall_clock_s, 0.0)

    def test_tracker_records_recipes_and_evidence(self):
        tracker = DiagnosticPerformanceTracker()
        tracker.record_recipe_collection("RECIPE_DEADLOCK", 0.05)
        tracker.record_recipe_collection("RECIPE_DEADLOCK", 0.02)
        tracker.record_evidence_normalization("DEADLOCK", 0.01, byte_size=256)
        tracker.record_reused_observation()
        tracker.record_replan()
        tracker.record_hypotheses_count(3)
        tracker.record_hypotheses_eliminated(2)

        m = tracker.finish()
        self.assertEqual(m.collection_operations_count, 2)
        self.assertEqual(m.duplicate_or_reusable_observations_count, 1)
        self.assertEqual(m.remote_calls_avoided_count, 1)
        self.assertAlmostEqual(m.evidence_reuse_ratio, 1.0 / 3.0, places=4)
        self.assertEqual(m.replans_count, 1)
        self.assertEqual(m.hypotheses_count, 3)
        self.assertEqual(m.hypotheses_eliminated_count, 2)
        self.assertEqual(m.local_bytes_processed, 256)
        self.assertAlmostEqual(m.collection_duration_per_recipe["RECIPE_DEADLOCK"], 0.07, places=4)


class TestRemoteAdapterMetrics(unittest.TestCase):
    """Test remote SSH adapter performance tracking."""

    def test_remote_ssh_metrics_recorded(self):
        calls = []

        def fake_runner(args, timeout, **kwargs):
            calls.append(list(args))
            if len(calls) == 1:
                return 255, "", "mux_client_request_session: session request failed: Broken pipe"
            return 0, "ok\n", ""

        ad = RemoteSshTargetAdapter(
            host="10.0.0.5",
            user="ops",
            command_runner=fake_runner,
            use_control_master=True,
            timeout_sec=5.0,
        )
        rc, out, err = ad.run_ssh("echo ok")
        self.assertEqual(rc, 0)
        perf = ad.get_performance_metrics()
        self.assertEqual(perf["ssh_commands_count"], 1)
        self.assertEqual(perf["retries_count"], 1)
        self.assertEqual(perf["control_master_reconnects_count"], 1)
        self.assertGreater(perf["remote_bytes_transferred"], 0)
        self.assertGreater(perf["remote_command_s"], 0.0)


class TestDiagnosisPipelineMetricsIntegration(unittest.TestCase):
    """Test end-to-end diagnosis performance metrics integration."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="phase1_perf_test_")
        self.corpus = os.path.join(self.tmp, "corpus")
        os.makedirs(self.corpus, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.corpus, 0o700)
        except OSError:
            pass

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_diagnose_populates_performance_metrics(self):
        res = diagnose(os.getpid(), symptom="general health check", corpus_dir=self.corpus, time_limit_s=1.0)
        self.assertIsInstance(res, DiagnoseResult)
        # Verify performance_metrics property exists and contains metrics
        perf = res.performance_metrics
        self.assertIsInstance(perf, dict)
        self.assertEqual(len(perf), 40)
        self.assertIn("total_wall_clock_s", perf)
        self.assertGreaterEqual(perf["total_wall_clock_s"], 0.0)
        self.assertIn("plan_generation_s", perf)
        self.assertIn("local_analysis_s", perf)
        self.assertIn("checkpoint_s", perf)
        self.assertIn("report_generation_s", perf)

        # Verify collection_impact holds performance_metrics
        self.assertIn("performance_metrics", res.collection_impact)

        # Verify contract preservation: to_dict() does not leak unexpected keys
        d = res.to_dict()
        from tests.test_imp_006_diagnose import RESULT_KEYS
        self.assertEqual(set(d), RESULT_KEYS)


if __name__ == "__main__":
    unittest.main()
