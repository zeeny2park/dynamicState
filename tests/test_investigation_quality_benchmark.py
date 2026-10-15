"""Unit and regression tests for Phase 17 Investigation Quality Benchmark."""

import json
import os
import shutil
import tempfile
import unittest

from benchmarks.investigation_quality.run_benchmark import (
    InvestigationQualityBenchmark,
    BenchmarkSummary,
)


class TestInvestigationQualityBenchmark(unittest.TestCase):
    """Verify integrity and metrics of the investigation quality benchmark suite."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_inv_qual_bench_")
        self.bench = InvestigationQualityBenchmark(output_dir=self.tmp_dir)

    def tearDown(self):
        self.bench.cleanup()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_benchmark_evaluates_all_six_scenarios(self):
        """Harness must evaluate all 6 required defect scenarios and generate reports."""
        summary = self.bench.run_all(smoke=True)

        self.assertIsInstance(summary, BenchmarkSummary)
        self.assertEqual(summary.total_scenarios, 6)

        scenario_ids = [s.scenario_id for s in summary.scenarios]
        expected_ids = [f"scenario_{i}" for i in range(1, 7)]
        self.assertEqual(scenario_ids, expected_ids)

        # 0% False Positive Causal SLA must be strictly satisfied
        self.assertTrue(summary.zero_false_positive_sla_met)
        self.assertEqual(summary.false_positive_causal_rate, 0.0)
        self.assertEqual(summary.false_causal_positives, 0)

        # High observed-fact and evidence fidelity
        self.assertGreaterEqual(summary.observed_fact_accuracy, 0.95)
        self.assertEqual(summary.mean_evidence_precision, 1.0)
        self.assertEqual(summary.mean_evidence_recall, 1.0)
        self.assertEqual(summary.overall_unsupported_claim_rate, 0.0)
        self.assertEqual(summary.uncertainty_calibration_rate, 1.0)
        self.assertGreaterEqual(summary.next_observation_usefulness_rate, 0.9)

        # Verify disk artifacts
        json_path = os.path.join(self.tmp_dir, "benchmark_results.json")
        md_path = os.path.join(self.tmp_dir, "BENCHMARK_REPORT.md")

        self.assertTrue(os.path.exists(json_path), "JSON benchmark report must exist")
        self.assertTrue(os.path.exists(md_path), "Markdown benchmark report must exist")

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["total_scenarios"], 6)
        self.assertTrue(data["zero_false_positive_sla_met"])

    def test_scenario_six_negative_control_never_promotes_causality(self):
        """Scenario 6 negative control must strictly produce True Negative and 0 False Positives."""
        s6 = self.bench._eval_scenario_6_negative_control()

        self.assertEqual(s6.scenario_id, "scenario_6")
        self.assertFalse(s6.ground_truth_is_causal)
        self.assertFalse(s6.causal_validated)
        self.assertFalse(s6.is_false_positive)
        self.assertTrue(s6.is_true_negative)


if __name__ == "__main__":
    unittest.main()
