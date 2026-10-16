"""Phase 18: Independent Investigation Benchmark & Real C++ Snapshot Evaluation Test Suite.

Verifies:
1. Ground truth corpus schema integrity, versioning, and validation error handling.
2. Independent evaluator metric computation using synthetic test outputs (TP, FP, TN, FN, precision/recall, calibration, next observations).
3. Read-only invariance of the evaluator.
4. Prevention of LLM / caller self-promotion to VALIDATED_CAUSAL_FUNCTION.
5. Separation of state-transition verification from function-causality verification.
6. Negative control invariants (zero false positives).
7. Capture quality limitations (NON_ATOMIC and PARTIAL block causal promotion).
8. Debug companion Build ID mismatch rejection and honest reporting.
9. Deterministic repeatability across multiple benchmark executions.
10. Real-runtime C++ live process capture and evaluation pipeline.
"""

import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from benchmarks.investigation_quality.evaluator import (
    AggregateMetrics,
    BenchmarkSuiteResult,
    CorpusValidationError,
    CorpusSchemaValidator,
    InvestigationEvaluator,
    ScenarioEvaluationResult,
    compute_file_sha256,
    load_ground_truth_corpus,
)
from benchmarks.investigation_quality.run_benchmark import (
    InvestigationQualityBenchmark,
    RealRuntimeExecutionHarness,
)
from extractor.debug_image import DebugImageProvider, inspect_elf
from extractor.evidence_ledger import EvidenceLedger, EvidenceRecord
from extractor.hypothesis import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    HypothesisValidator,
    InvestigationHypothesis,
    sanitize_and_disarm_llm_hypothesis,
)
from extractor.investigation import (
    ATTRIBUTION_BASIS_CALL_STACK,
    ATTRIBUTION_BASIS_EXECUTION_TRACE,
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    InvestigationFinding,
    InvestigationManager,
    InvestigationSession,
)


class TestInvestigationQualityBenchmark(unittest.TestCase):
    """Phase 18 evaluation suite covering corpus, evaluator math, and C++ evidence pipelines."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_phase18_qual_bench_")
        self.corpus = load_ground_truth_corpus()
        self.evaluator = InvestigationEvaluator(self.corpus)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_corpus_schema_and_validation(self):
        """Corpus must satisfy schema and reject malformed definitions."""
        # Canonical corpus must be valid
        self.assertIn("scenarios", self.corpus)
        self.assertGreaterEqual(len(self.corpus["scenarios"]), 6)
        CorpusSchemaValidator.validate(self.corpus)

        # 1. Missing top-level key rejected
        bad_corpus = copy.deepcopy(self.corpus)
        del bad_corpus["corpus_version"]
        with self.assertRaises(CorpusValidationError):
            CorpusSchemaValidator.validate(bad_corpus)

        # 2. Too few scenarios rejected
        bad_corpus = copy.deepcopy(self.corpus)
        bad_corpus["scenarios"] = bad_corpus["scenarios"][:3]
        with self.assertRaises(CorpusValidationError):
            CorpusSchemaValidator.validate(bad_corpus)

        # 3. Missing scenario required key rejected
        bad_corpus = copy.deepcopy(self.corpus)
        del bad_corpus["scenarios"][0]["causal_attribution"]
        with self.assertRaises(CorpusValidationError):
            CorpusSchemaValidator.validate(bad_corpus)

        # 4. Duplicate scenario_id rejected
        bad_corpus = copy.deepcopy(self.corpus)
        bad_corpus["scenarios"][1]["scenario_id"] = bad_corpus["scenarios"][0]["scenario_id"]
        with self.assertRaises(CorpusValidationError):
            CorpusSchemaValidator.validate(bad_corpus)

        # 5. Empty expected_facts rejected
        bad_corpus = copy.deepcopy(self.corpus)
        bad_corpus["scenarios"][0]["expected_facts"] = []
        with self.assertRaises(CorpusValidationError):
            CorpusSchemaValidator.validate(bad_corpus)

    def test_evaluator_synthetic_predictions_math(self):
        """Verify that evaluator computes honest metrics without hardcoded constants."""
        sc1 = self.corpus["scenarios"][0]  # Valid Transition, causal_provable = True
        sc6 = self.corpus["scenarios"][5]  # Negative Control, causal_provable = False

        # Case A: True Positive on Scenario 1
        output_tp = {
            "status": "COMPLETED",
            "observed_facts": [
                {"field_name": "worker_status", "before_value": 1, "after_value": 2, "evidence_ids": ["ev_1"]}
            ],
            "evidence_ledger": [
                {"evidence_id": "ev_1", "evidence_type": "OBJECT_STATE", "observation": "worker_status changed 1 -> 2"}
            ],
            "hypotheses": [
                {
                    "hypothesis_id": "h1",
                    "title": "worker_status transition",
                    "validation_status": "VALIDATED",
                    "confidence": "HIGH",
                    "supporting_evidence_ids": ["ev_1"],
                    "function_candidates": [
                        {"function_name": "transition_worker_state", "candidate_tier": "VALIDATED_CAUSAL_FUNCTION"}
                    ],
                    "suggested_observations": [{"question": "Observe worker_status transition"}]
                }
            ],
            "conversational_response": {"confidence": "high"},
        }

        res_tp = self.evaluator.evaluate_scenario(sc1, output_tp, "unit_fixture")
        self.assertTrue(res_tp.is_true_positive)
        self.assertFalse(res_tp.is_false_positive)
        self.assertEqual(res_tp.facts_f1, 1.0)
        self.assertEqual(res_tp.evidence_precision, 1.0)
        self.assertTrue(res_tp.uncertainty_calibrated)
        self.assertTrue(res_tp.next_observation_useful)

        # Case B: False Positive on Scenario 6 (Negative Control wrongfully promoted)
        output_fp = {
            "status": "COMPLETED",
            "observed_facts": [
                {"field_name": "unassociated_field", "before_value": 100, "after_value": 200, "evidence_ids": ["ev_6"]}
            ],
            "evidence_ledger": [
                {"evidence_id": "ev_6", "evidence_type": "OBJECT_STATE", "observation": "unassociated_field changed"}
            ],
            "hypotheses": [
                {
                    "hypothesis_id": "h6",
                    "title": "unassociated_field causal writer",
                    "validation_status": "VALIDATED",
                    "confidence": "HIGH",
                    "supporting_evidence_ids": ["ev_6"],
                    "function_candidates": [
                        {"function_name": "unrelated_helper_function", "candidate_tier": "VALIDATED_CAUSAL_FUNCTION"}
                    ]
                }
            ],
            "conversational_response": {"confidence": "high"},
        }

        res_fp = self.evaluator.evaluate_scenario(sc6, output_fp, "unit_fixture")
        self.assertTrue(res_fp.is_false_positive, "Promoting negative control must be scored as False Positive!")
        self.assertFalse(res_fp.is_true_negative)

        # Case C: True Negative on Scenario 6 (Negative Control correctly unvalidated)
        output_tn = copy.deepcopy(output_fp)
        output_tn["hypotheses"][0]["function_candidates"][0]["candidate_tier"] = "STATIC_CANDIDATE"
        output_tn["hypotheses"][0]["validation_status"] = "INCONCLUSIVE"
        output_tn["conversational_response"]["confidence"] = "low"

        res_tn = self.evaluator.evaluate_scenario(sc6, output_tn, "unit_fixture")
        self.assertTrue(res_tn.is_true_negative)
        self.assertFalse(res_tn.is_false_positive)
        self.assertTrue(res_tn.uncertainty_calibrated)

        # Case D: Partial fact matching (1 expected fact matched, 1 extraneous fact present)
        output_partial_facts = copy.deepcopy(output_tp)
        output_partial_facts["observed_facts"].append({"field_name": "extraneous_field", "before_value": 0, "after_value": 1})
        res_part = self.evaluator.evaluate_scenario(sc1, output_partial_facts, "unit_fixture")
        self.assertEqual(res_part.facts_matched, 1)
        self.assertEqual(res_part.facts_detected, 2)
        self.assertEqual(res_part.facts_precision, 0.5)
        self.assertEqual(res_part.facts_recall, 1.0)
        self.assertAlmostEqual(res_part.facts_f1, 0.6667, places=3)

    def test_evaluator_is_strictly_read_only(self):
        """Evaluator must never mutate input findings, hypotheses, or ledger."""
        sc1 = self.corpus["scenarios"][0]
        session = InvestigationSession("inv_ro", "test read only", corpus_dir=self.tmp_dir)
        ev = session.ledger.record("OBJECT_STATE", "observation", "test", "worker_status 1 -> 2", {"worker_status": 2})
        f = InvestigationFinding("f1", "fact", "title", "desc", field_name="worker_status", before_value=1, after_value=2, evidence_ids=[ev.evidence_id])
        session.findings.append(f)

        orig_findings = copy.deepcopy([f.to_dict() for f in session.findings])
        orig_ledger = copy.deepcopy([r.to_dict() for r in session.ledger.query()])

        system_output = {
            "status": "COMPLETED",
            "observed_facts": [f.to_dict() for f in session.findings],
            "evidence_ledger": [r.to_dict() for r in session.ledger.query()],
            "hypotheses": [],
            "follow_up_observations": [],
        }

        self.evaluator.evaluate_scenario(sc1, system_output, "unit_fixture")

        current_findings = [f.to_dict() for f in session.findings]
        current_ledger = [r.to_dict() for r in session.ledger.query()]

        self.assertEqual(orig_findings, current_findings, "Evaluator must not mutate findings")
        self.assertEqual(orig_ledger, current_ledger, "Evaluator must not mutate ledger")

    def test_model_cannot_self_promote_validated_causal(self):
        """Injected LLM claim of VALIDATED_CAUSAL_FUNCTION without attestation proof is disarmed."""
        session = InvestigationSession("inv_fake_causal", "disarm test", corpus_dir=self.tmp_dir)
        fake_hypo_data = {
            "hypothesis_id": "hypo_fake",
            "title": "Model claims transition_worker_state is root cause",
            "claim": "transition_worker_state caused the defect",
            "validation_status": "VALIDATED",
            "confidence": "HIGH",
            "supporting_evidence_ids": ["ev_nonexistent_fake"],
            "function_candidates": [
                {
                    "function_name": "transition_worker_state",
                    "candidate_tier": FUNCTION_TIER_VALIDATED_CAUSAL,
                    "confirmed_root_cause": True,
                }
            ]
        }

        # Deserializing through InvestigationSession.from_dict disarms fake evidence IDs and evaluates against ledger
        session_data = {
            "investigation_id": session.investigation_id,
            "goal": session.goal,
            "corpus_dir": session.corpus_dir,
            "evidence_ledger": session.ledger.to_dict(),
            "findings": [],
            "hypotheses": [fake_hypo_data],
        }
        restored = InvestigationSession.from_dict(session_data)
        h = restored.hypotheses[0]

        # Fake evidence ID was disarmed
        self.assertEqual(len(h.supporting_evidence_ids), 0)
        # Status cannot remain VALIDATED without verified proof
        self.assertNotEqual(h.validation_status, HYPOTHESIS_STATUS_VALIDATED)

    def test_verified_transition_does_not_automatically_validate_causality(self):
        """Verifying state transition without function attribution keeps candidate at STATIC_CANDIDATE."""
        session = InvestigationSession("inv_trans_only", "transition only test", corpus_dir=self.tmp_dir)
        h = InvestigationHypothesis(
            hypothesis_id="h_trans",
            title="Worker status transitioned",
            claim="worker_status changed 1 -> 2",
            investigation_id=session.investigation_id,
        )
        h.function_candidates = [
            {"function_name": "transition_worker_state", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE}
        ]

        # Proof record verifying state transition but without function attribution
        proof_eid = "ev_proof_transition"
        rec = EvidenceRecord(
            evidence_id=proof_eid,
            evidence_type="COMPARISON",
            nature="observation",
            source="investigation_observer",
            session_id=session.investigation_id,
            observation="Worker status changed 1 -> 2",
            provenance={
                "verifier_attestation": {
                    "token": session.ledger.session_secret,
                    "evidence_fingerprint": "fake_or_real",
                    "investigation_id": session.investigation_id,
                    "target_function": "transition_worker_state",
                    "function_attribution_verified": False,  # NOT verified!
                    "provenance_class": "CONTROLLED_RUNTIME_REPRODUCTION",
                }
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)
        h.supporting_evidence_ids.append(proof_eid)

        # Evaluating with deterministic_transition_verified=True but function_attribution_verified=False
        result = HypothesisValidator.evaluate(
            h,
            session.ledger,
            proof_evidence_id=proof_eid,
            deterministic_transition_verified=True,
        )

        cand = h.function_candidates[0]
        self.assertNotEqual(cand.get("candidate_tier"), FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertFalse(cand.get("confirmed_root_cause", False))

    def test_negative_control_never_promoted(self):
        """Scenario 6 negative control must strictly yield True Negative and 0% FP."""
        bench = InvestigationQualityBenchmark(output_dir=self.tmp_dir)
        try:
            res = bench._execute_unit_fixture_scenario(self.corpus["scenarios"][5], provider="none")
            self.assertEqual(res.scenario_id, "scenario_6")
            self.assertFalse(res.causal_promoted)
            self.assertFalse(res.is_false_positive)
            self.assertTrue(res.is_true_negative)
            self.assertEqual(res.candidate_tier, FUNCTION_TIER_STATIC_CANDIDATE)
        finally:
            bench.cleanup()

    def test_non_atomic_partial_capture_limits_status(self):
        """NON_ATOMIC and PARTIAL capture qualities strictly cap validation status at SUPPORTED."""
        session = InvestigationSession("inv_non_atomic", "test non atomic", corpus_dir=self.tmp_dir)
        h = InvestigationHypothesis(hypothesis_id="h_na", investigation_id=session.investigation_id, title="competing write", claim="metric mutated")
        h.function_candidates = [
            {"function_name": "competing_writer_a", "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED}
        ]

        ev_na = EvidenceRecord(
            evidence_id="ev_na_01",
            evidence_type="DIAGNOSTIC",
            nature="observation",
            source="investigation_observer",
            session_id=session.investigation_id,
            observation="Unsynchronized writes observed",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "NON_ATOMIC"},
        )
        session.ledger.add_record(ev_na)
        h.supporting_evidence_ids.append(ev_na.evidence_id)

        res = HypothesisValidator.evaluate(h, session.ledger, capture_quality={"consistency_level": "NON_ATOMIC"})
        self.assertNotEqual(res.to_status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(res.confidence, CONFIDENCE_LOW)
        self.assertNotEqual(h.function_candidates[0].get("candidate_tier"), FUNCTION_TIER_VALIDATED_CAUSAL)

    def test_mismatched_build_id_surfaced_honestly(self):
        """Mismatched debug image Build ID must be rejected by DebugImageProvider."""
        work_dir = tempfile.mkdtemp(prefix="test_build_id_mismatch_")
        try:
            bin_a = os.path.join(work_dir, "a.elf")
            bin_b = os.path.join(work_dir, "b.elf")
            src_a = os.path.join(work_dir, "a.cpp")
            src_b = os.path.join(work_dir, "b.cpp")

            with open(src_a, "w") as f: f.write("int main() { return 0; }\n")
            with open(src_b, "w") as f: f.write("int main() { return 42; }\n")

            if shutil.which("g++"):
                subprocess.run(["g++", "-g", "-Wl,--build-id=sha1", src_a, "-o", bin_a], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(["g++", "-g", "-Wl,--build-id=sha1", src_b, "-o", bin_b], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                provider = DebugImageProvider(bin_b)
                compat = provider.verify(bin_a)
                self.assertFalse(compat.compatible)
                self.assertIn("MISMATCH", compat.reason)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def test_repeat_benchmark_deterministic_stability(self):
        """Repeated runs of deterministic benchmark must produce identical aggregate metrics."""
        bench1 = InvestigationQualityBenchmark(output_dir=os.path.join(self.tmp_dir, "run1"))
        bench2 = InvestigationQualityBenchmark(output_dir=os.path.join(self.tmp_dir, "run2"))
        try:
            res1 = bench1.run_all(mode="unit_fixture", provider="none", smoke=True)
            res2 = bench2.run_all(mode="unit_fixture", provider="none", smoke=True)

            self.assertEqual(res1.corpus_hash, res2.corpus_hash)
            self.assertEqual(res1.fixture_hash, res2.fixture_hash)
            self.assertEqual(res1.zero_false_positive_sla_met, res2.zero_false_positive_sla_met)
            self.assertEqual(res1.unit_fixture_metrics.mean_fact_f1, res2.unit_fixture_metrics.mean_fact_f1)
            self.assertEqual(res1.unit_fixture_metrics.false_positive_causal_rate, res2.unit_fixture_metrics.false_positive_causal_rate)
        finally:
            bench1.cleanup()
            bench2.cleanup()

    def test_full_benchmark_suite_execution(self):
        """Run complete benchmark suite and verify report generation and 0% FP SLA."""
        bench = InvestigationQualityBenchmark(output_dir=self.tmp_dir)
        try:
            res = bench.run_all(mode="all", provider="none", smoke=True)

            self.assertIsInstance(res, BenchmarkSuiteResult)
            self.assertTrue(res.zero_false_positive_sla_met)

            # Check JSON report
            json_file = os.path.join(self.tmp_dir, "benchmark_results.json")
            self.assertTrue(os.path.exists(json_file))
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertTrue(data["zero_false_positive_sla_met"])
            self.assertEqual(data["schema_version"], "1.0.0")

            # Check Markdown report
            md_file = os.path.join(self.tmp_dir, "BENCHMARK_REPORT.md")
            self.assertTrue(os.path.exists(md_file))
            with open(md_file, "r", encoding="utf-8") as f:
                md_text = f.read()
            self.assertIn("Phase 18 Investigation Quality Benchmark Report", md_text)
            self.assertIn("0.0% FP", md_text)

            # Both Real-Runtime and Unit-Fixture must have 0 False Positives
            if res.real_runtime_metrics and res.real_runtime_metrics.completed_scenarios > 0:
                self.assertEqual(res.real_runtime_metrics.false_causal_positives, 0)
                self.assertEqual(res.real_runtime_metrics.false_positive_causal_rate, 0.0)

            if res.unit_fixture_metrics:
                self.assertEqual(res.unit_fixture_metrics.false_causal_positives, 0)
                self.assertEqual(res.unit_fixture_metrics.false_positive_causal_rate, 0.0)

        finally:
            bench.cleanup()


if __name__ == "__main__":
    unittest.main()
