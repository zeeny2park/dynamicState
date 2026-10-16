"""Phase 19: Benchmark Integrity, Real Causal Evidence Verification & Reproducible Provider Evaluation Test Suite.

Verifies:
1. Ground truth corpus schema integrity, versioning, and validation of domain contracts.
2. Independent evaluator metric computation using synthetic test outputs without hardcoded constants.
3. Read-only invariance of the evaluator across findings, evidence ledger, and attestations.
4. Prevention of LLM / caller self-promotion to VALIDATED_CAUSAL_FUNCTION without authentic proof.
5. Separation of state-transition verification from function-causality verification.
6. Reconciled negative control integrity (zero false positives, genuine unproven causal attribution).
7. Capture quality limitations (NON_ATOMIC and PARTIAL block causal promotion).
8. Debug companion Build ID mismatch rejection and honest reporting.
9. Deterministic repeatability across multiple benchmark executions.
10. Complete real-runtime C++ live process capture and evaluation pipeline.
11. Adversarial ground-truth leakage test: perturbing GT leaves system-under-test output unchanged.
12. Elimination of fabricated causal traces and rejection of synthetic attestation.
13. Prevention of vacuous perfect metric scores on empty/missing evidence and observations.
14. Truthful provider matrix reporting: unavailable providers marked UNAVAILABLE, fallbacks not disguised.
15. Repeat execution (repeat=N) actually executes N iterations and tracks variance.
16. Pipeline stage failure and bypass detection (fails cleanly without synthetic fallback).
"""

import copy
import json
import math
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
    """Phase 19 evaluation suite covering corpus, evaluator math, and C++ evidence pipelines."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_phase19_qual_bench_")
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

        # 4. Missing required domain contract documentation rejected
        bad_corpus = copy.deepcopy(self.corpus)
        del bad_corpus["scenarios"][0]["field_invariant"]
        with self.assertRaises(CorpusValidationError):
            CorpusSchemaValidator.validate(bad_corpus)

        # 5. Empty contract field rejected
        bad_corpus = copy.deepcopy(self.corpus)
        bad_corpus["scenarios"][0]["exact_mutation_source"] = "   "
        with self.assertRaises(CorpusValidationError):
            CorpusSchemaValidator.validate(bad_corpus)

        # 6. Duplicate scenario_id rejected
        bad_corpus = copy.deepcopy(self.corpus)
        bad_corpus["scenarios"][1]["scenario_id"] = bad_corpus["scenarios"][0]["scenario_id"]
        with self.assertRaises(CorpusValidationError):
            CorpusSchemaValidator.validate(bad_corpus)

        # 7. Empty expected_facts rejected
        bad_corpus = copy.deepcopy(self.corpus)
        bad_corpus["scenarios"][0]["expected_facts"] = []
        with self.assertRaises(CorpusValidationError):
            CorpusSchemaValidator.validate(bad_corpus)

    def test_evaluator_synthetic_predictions_math(self):
        """Verify that evaluator computes honest metrics without hardcoded constants."""
        sc1 = self.corpus["scenarios"][0]  # Valid Transition, causal_provable = True
        sc6 = self.corpus["scenarios"][5]  # Negative Control, causal_provable = False

        # Case A: True Positive on Scenario 1 (via synthetic self-test)
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

        res_tp = self.evaluator.evaluate_scenario(sc1, output_tp, "evaluator_self_test")
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

        res_fp = self.evaluator.evaluate_scenario(sc6, output_fp, "evaluator_self_test")
        self.assertTrue(res_fp.is_false_positive, "Promoting negative control must be scored as False Positive!")
        self.assertFalse(res_fp.is_true_negative)

        # Case C: True Negative on Scenario 6 (Negative Control correctly unvalidated)
        output_tn = copy.deepcopy(output_fp)
        output_tn["hypotheses"][0]["function_candidates"][0]["candidate_tier"] = "STATIC_CANDIDATE"
        output_tn["hypotheses"][0]["validation_status"] = "INCONCLUSIVE"
        output_tn["conversational_response"]["confidence"] = "low"

        res_tn = self.evaluator.evaluate_scenario(sc6, output_tn, "evaluator_self_test")
        self.assertTrue(res_tn.is_true_negative)
        self.assertFalse(res_tn.is_false_positive)
        self.assertTrue(res_tn.uncertainty_calibrated)

        # Case D: Partial fact matching (1 expected fact matched, 1 extraneous fact present)
        output_partial_facts = copy.deepcopy(output_tp)
        output_partial_facts["observed_facts"].append({"field_name": "extraneous_field", "before_value": 0, "after_value": 1})
        res_part = self.evaluator.evaluate_scenario(sc1, output_partial_facts, "evaluator_self_test")
        self.assertEqual(res_part.facts_matched, 1)
        self.assertEqual(res_part.facts_detected, 2)
        self.assertEqual(res_part.facts_precision, 0.5)
        self.assertEqual(res_part.facts_recall, 1.0)
        self.assertAlmostEqual(res_part.facts_f1, 0.6667, places=3)

    def test_evaluator_empty_data_metrics_no_vacuous_perfection(self):
        """Fix vacuous perfect scores: empty evidence, zero claims, or missing confidence must yield None."""
        sc1 = self.corpus["scenarios"][0]
        empty_output = {
            "status": "COMPLETED",
            "observed_facts": [],
            "evidence_ledger": [],
            "hypotheses": [],
            "follow_up_observations": [],
            "conversational_response": {},  # No confidence supplied
        }

        res = self.evaluator.evaluate_scenario(sc1, empty_output, "evaluator_self_test")
        # 1. Facts precision is None when 0 facts detected (not 1.0)
        self.assertIsNone(res.facts_precision)
        self.assertEqual(res.facts_recall, 0.0)
        self.assertIsNone(res.facts_f1)

        # 2. Evidence precision is None when 0 evidence cited (not vacuous 1.0!)
        self.assertIsNone(res.evidence_precision)

        # 3. Disarm rate is None when 0 unsupported claims exist (not vacuous 1.0!)
        self.assertIsNone(res.disarm_rate)

        # 4. Uncertainty calibration is None when confidence was never reported
        self.assertIsNone(res.confidence_score)
        self.assertIsNone(res.uncertainty_calibrated)

        # 5. Next observation usefulness is None when 0 observations proposed
        self.assertIsNone(res.next_observation_useful)
        self.assertIsNone(res.next_observation_usefulness_rate)

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

        self.evaluator.evaluate_scenario(sc1, system_output, "evaluator_self_test")

        current_findings = [f.to_dict() for f in session.findings]
        current_ledger = [r.to_dict() for r in session.ledger.query()]

        self.assertEqual(orig_findings, current_findings, "Evaluator must not mutate findings")
        self.assertEqual(orig_ledger, current_ledger, "Evaluator must not mutate ledger")

    def test_adversarial_ground_truth_leakage(self):
        """Perturbing ground-truth expected values must NOT change system-under-test outputs."""
        harness = RealRuntimeExecutionHarness(self.tmp_dir)
        compiled_ok, err = harness.compile()
        if not compiled_ok:
            self.skipTest(f"C++ compiler not available: {err}")

        # 1. Run real runtime capture for scenario 1
        ok, err, snap1, snap2, _ = harness.spawn_and_capture("MUTATE 1", "MUTATED 1")
        self.assertTrue(ok, f"Capture failed: {err}")

        # 2. Execute production pipeline on identical snapshots with authentic GT scenario
        mgr1 = InvestigationManager(corpus_dir=os.path.join(self.tmp_dir, "inv1"))
        s_info1 = mgr1.start_investigation("Leakage test", snap1, debug_image=harness.debug_companion)
        inv1 = s_info1["investigation_id"]
        mgr1.compare_observations(inv1, snap1, snap2)
        sess1 = mgr1.sessions[inv1]
        mgr1._execute_stage_synthesis(sess1)

        # 3. Create adversarial perturbed ground-truth scenario
        perturbed_sc = copy.deepcopy(self.corpus["scenarios"][0])
        perturbed_sc["expected_facts"] = [
            {"field_path": "fake_nonexistent_field", "field_name": "fake", "before_value": 999, "after_value": 888}
        ]
        perturbed_sc["causal_attribution"]["expected_causal_function"] = "fake_adversarial_function"

        # 4. Execute production pipeline on identical snapshots with perturbed GT context
        mgr2 = InvestigationManager(corpus_dir=os.path.join(self.tmp_dir, "inv2"))
        s_info2 = mgr2.start_investigation("Leakage test 2", snap1, debug_image=harness.debug_companion)
        inv2 = s_info2["investigation_id"]
        mgr2.compare_observations(inv2, snap1, snap2)
        sess2 = mgr2.sessions[inv2]
        mgr2._execute_stage_synthesis(sess2)

        # 5. System outputs MUST be semantically identical (ignoring generated UUIDs / timestamps)
        findings1 = [f.to_dict() for f in sess1.findings]
        findings2 = [f.to_dict() for f in sess2.findings]
        hypotheses1 = [h.to_dict() for h in sess1.hypotheses]
        hypotheses2 = [h.to_dict() for h in sess2.hypotheses]

        def _semantic_finding(f):
            return {
                "category": f.get("category"),
                "title": f.get("title"),
                "field_name": f.get("field_name"),
                "before_value": f.get("before_value"),
                "after_value": f.get("after_value"),
                "function_candidates": f.get("function_candidates"),
                "source_location": f.get("source_location"),
                "classification": f.get("classification"),
            }

        def _semantic_hypothesis(h):
            return {
                "title": h.get("title"),
                "claim": h.get("claim"),
                "proposed_mechanism": h.get("proposed_mechanism"),
                "function_candidates": h.get("function_candidates"),
                "validation_status": h.get("validation_status"),
                "confidence": h.get("confidence"),
                "classification": h.get("classification"),
            }

        self.assertEqual(
            [_semantic_finding(f) for f in findings1],
            [_semantic_finding(f) for f in findings2],
            "System findings must not be altered by ground-truth expectations!"
        )
        self.assertEqual(
            [_semantic_hypothesis(h) for h in hypotheses1],
            [_semantic_hypothesis(h) for h in hypotheses2],
            "System hypotheses must remain completely uninfluenced by ground-truth!"
        )

        # 6. Evaluator score changes honestly based on perturbed ground truth
        out1 = {
            "status": "COMPLETED",
            "observed_facts": findings1,
            "evidence_ledger": [r.to_dict() for r in sess1.ledger.query()],
            "hypotheses": hypotheses1,
            "follow_up_observations": [],
        }
        res_real = self.evaluator.evaluate_scenario(self.corpus["scenarios"][0], out1, "real_runtime")
        res_pert = self.evaluator.evaluate_scenario(perturbed_sc, out1, "real_runtime")

        self.assertGreater(res_real.facts_f1, 0.0)
        self.assertEqual(res_pert.facts_f1, 0.0, "Perturbed expected facts must yield 0% F1 in evaluator")

    def test_fake_causal_traces_and_claims_rejected(self):
        """Fabricated execution traces and synthetic proofs cannot promote candidate to VALIDATED_CAUSAL_FUNCTION."""
        session = InvestigationSession("inv_fake_trace", "fake trace test", corpus_dir=self.tmp_dir)
        h = InvestigationHypothesis(hypothesis_id="h1", investigation_id=session.investigation_id, title="claim", claim="desc")
        h.function_candidates = [
            {"function_name": "transition_worker_state", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE}
        ]

        # Fake diagnostic trace with caller claim
        fake_rec = EvidenceRecord(
            evidence_id="fake_ev_trace",
            evidence_type="DIAGNOSTIC",
            nature="observation",
            source="unverified_caller",  # Unverified!
            session_id=session.investigation_id,
            observation="Fake trace claiming transition_worker_state wrote worker_status",
            details={"caller_submitted": True, "trace_events": [{"function": "transition_worker_state", "event": "write"}]},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(fake_rec)
        h.supporting_evidence_ids.append(fake_rec.evidence_id)

        # Hypothesis validator must reject caller claim
        res = HypothesisValidator.evaluate(h, session.ledger)
        self.assertNotEqual(res.to_status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertNotEqual(h.function_candidates[0].get("candidate_tier"), FUNCTION_TIER_VALIDATED_CAUSAL)

    def test_reconciled_negative_control_integrity(self):
        """Scenario 6 negative control documents non-causality and strictly blocks causal promotion."""
        sc6 = self.corpus["scenarios"][5]
        self.assertEqual(sc6["scenario_id"], "scenario_6")
        self.assertIn("Negative Control", sc6["scenario_name"])
        self.assertFalse(sc6["causal_attribution"]["causal_function_provable"])
        self.assertFalse(sc6["causal_attribution"]["allow_validated_causal"])
        self.assertIn("unassociated_field", sc6["field_invariant"])

        bench = InvestigationQualityBenchmark(output_dir=self.tmp_dir)
        try:
            res = bench._execute_evaluator_self_test_scenario(sc6, provider="none")
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

    def test_repeat_execution_count_and_variability(self):
        """repeat=N must execute N independent runs and record aggregate variability."""
        bench = InvestigationQualityBenchmark(output_dir=self.tmp_dir)
        try:
            res = bench.run_all(mode="evaluator_self_test", provider="none", smoke=True, repeat=3)
            self.assertEqual(len(res.repeat_runs), 3)
            for r in res.repeat_runs:
                self.assertIn("iteration", r)
                self.assertIn("self_test_f1", r)
                self.assertEqual(r["self_test_fp_rate"], 0.0)
        finally:
            bench.cleanup()

    def test_provider_matrix_and_fallback_misreporting_prevented(self):
        """Unavailable provider must be UNAVAILABLE; fallback must be reported as FALLBACK_OCCURRED."""
        bench = InvestigationQualityBenchmark(output_dir=self.tmp_dir)
        try:
            res = bench.run_all(
                mode="evaluator_self_test",
                provider="none",
                providers=["none", "nonexistent_mock_provider"],
                smoke=True,
            )
            self.assertIn("none", res.provider_comparisons)
            self.assertIn("nonexistent_mock_provider", res.provider_comparisons)

            unavail = res.provider_comparisons["nonexistent_mock_provider"]
            self.assertEqual(unavail["status"], "UNAVAILABLE")
            self.assertEqual(unavail["completed_scenarios"], 0)
        finally:
            bench.cleanup()

    def test_artifact_stage_bypass_detection(self):
        """Failed spawn or missing binary sets stage status to FAILED rather than synthetic fallback."""
        harness = RealRuntimeExecutionHarness(self.tmp_dir)
        # Harness not compiled -> spawn_and_capture returns (False, err)
        ok, err, _, _, prov = harness.spawn_and_capture("MUTATE 1", "MUTATED 1")
        self.assertFalse(ok)
        self.assertIn("not compiled", err.lower())

    def test_false_positive_causal_sla_enforcement(self):
        """Any false positive promotion immediately fails the zero-false-positive SLA."""
        sc6 = self.corpus["scenarios"][5]
        # Fabricate an output where scenario 6 claims causal promotion
        fake_fp_output = {
            "status": "COMPLETED",
            "observed_facts": [{"field_name": "unassociated_field", "before_value": 100, "after_value": 200}],
            "evidence_ledger": [],
            "hypotheses": [
                {
                    "hypothesis_id": "h_fp",
                    "title": "Spurious attribution",
                    "function_candidates": [
                        {"function_name": "unrelated_helper_function", "candidate_tier": "VALIDATED_CAUSAL_FUNCTION"}
                    ]
                }
            ],
            "follow_up_observations": [],
        }

        res = self.evaluator.evaluate_scenario(sc6, fake_fp_output, "evaluator_self_test")
        self.assertTrue(res.is_false_positive)

        agg = self.evaluator.aggregate_metrics([res], "evaluator_self_test")
        self.assertEqual(agg.false_causal_positives, 1)
        self.assertEqual(agg.false_positive_causal_rate, 1.0)
        self.assertFalse(agg.zero_false_positive_sla_met, "SLA MUST fail when any false positive occurs!")

    def test_full_benchmark_suite_execution(self):
        """Run complete benchmark suite and verify report generation, 0% FP SLA, and track isolation."""
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
            self.assertEqual(data["schema_version"], "1.2.0")

            # Check Markdown report
            md_file = os.path.join(self.tmp_dir, "BENCHMARK_REPORT.md")
            self.assertTrue(os.path.exists(md_file))
            with open(md_file, "r", encoding="utf-8") as f:
                md_text = f.read()
            self.assertIn("Phase 20 Investigation Quality Benchmark Report", md_text)
            self.assertIn("0.0% FP", md_text)
            self.assertIn("REAL_RUNTIME_PRODUCT_PIPELINE", md_text)

            # Real-Runtime pipeline must have 0 False Positives
            if res.real_runtime_metrics and res.real_runtime_metrics.completed_scenarios > 0:
                self.assertEqual(res.real_runtime_metrics.false_causal_positives, 0)
                self.assertEqual(res.real_runtime_metrics.false_positive_causal_rate, 0.0)

            # Evaluator Self-Test must have 0 False Positives
            if res.evaluator_self_test_metrics:
                self.assertEqual(res.evaluator_self_test_metrics.false_causal_positives, 0)
                self.assertEqual(res.evaluator_self_test_metrics.false_positive_causal_rate, 0.0)

        finally:
            bench.cleanup()

    def test_track_segregation_and_self_test_cannot_pass_product_sla(self):
        """Passing evaluator self-tests must NEVER promote a failed or unevaluable real-runtime product SLA."""
        bench = InvestigationQualityBenchmark(output_dir=self.tmp_dir)
        try:
            # Evaluator self-test mode has self-tests passing, but product SLA must be NOT_EVALUABLE and False
            res = bench.run_all(mode="evaluator_self_test", provider="none", smoke=True)
            self.assertIsNotNone(res.evaluator_self_test_metrics)
            self.assertTrue(res.evaluator_self_test_metrics.zero_false_positive_sla_met)
            self.assertEqual(res.evaluator_self_test_metrics.sla_status, "PASSED")

            # Product SLA must remain NOT_EVALUABLE and False!
            self.assertFalse(res.zero_false_positive_sla_met)
            self.assertEqual(res.product_sla_status, "NOT_EVALUABLE")
            self.assertEqual(res.product_sla_details["status"], "NOT_EVALUABLE")
        finally:
            bench.cleanup()

    def test_empty_eligible_negative_denominator_yields_not_evaluable(self):
        """An empty eligible negative denominator must yield NOT_EVALUABLE / None and never pass the SLA."""
        # Scenario 1 is causal positive, no negative control included
        sc1 = self.corpus["scenarios"][0]
        output_sc1 = {
            "status": "COMPLETED",
            "observed_facts": [{"field_name": "worker_status", "before_value": 1, "after_value": 2}],
            "evidence_ledger": [],
            "hypotheses": [],
            "follow_up_observations": [],
        }
        res1 = self.evaluator.evaluate_scenario(sc1, output_sc1, "evaluator_self_test")
        agg = self.evaluator.aggregate_metrics([res1], "evaluator_self_test")

        self.assertEqual(agg.causal_negatives_ground_truth, 0)
        self.assertEqual(agg.eligible_causal_negatives, 0)
        self.assertIsNone(agg.false_positive_causal_rate)
        self.assertEqual(agg.sla_status, "NOT_EVALUABLE")
        self.assertFalse(agg.zero_false_positive_sla_met)
        self.assertIn("NOT_EVALUABLE", agg.false_positive_display)

    def test_mode_isolation_evaluator_self_test_does_not_spawn_inferior(self):
        """Mode isolation: evaluator-only mode must not compile target or launch live process."""
        bench = InvestigationQualityBenchmark(output_dir=self.tmp_dir)
        try:
            # Point runtime harness to invalid compiler to guarantee it would fail if invoked
            bench.runtime_harness.compiler = "/bin/nonexistent_compiler_xyz"
            res = bench.run_all(mode="evaluator_self_test", provider="none", smoke=True)
            self.assertIsNone(res.real_runtime_metrics)
            self.assertEqual(res.product_sla_status, "NOT_EVALUABLE")
            self.assertFalse(res.zero_false_positive_sla_met)
            self.assertIsNotNone(res.evaluator_self_test_metrics)
        finally:
            bench.cleanup()

    def test_provider_matrix_scope_and_fallback_labeling(self):
        """Provider comparison respects scenario scope and explicitly labels fallback as FALLBACK_OCCURRED."""
        bench = InvestigationQualityBenchmark(output_dir=self.tmp_dir)
        try:
            res = bench.run_all(
                mode="evaluator_self_test",
                provider="none",
                providers=["none"],
                provider_scenarios=["scenario_1", "scenario_6"],
                smoke=False,
            )
            self.assertIn("none", res.provider_comparisons)
            p_info = res.provider_comparisons["none"]
            self.assertEqual(p_info["scenarios_evaluated"], ["scenario_1", "scenario_6"])
            self.assertEqual(p_info["attempted_count"], 2)
            self.assertEqual(p_info["completed_model_responses"], 2)
            self.assertEqual(p_info["fallback_count"], 0)
            self.assertEqual(p_info["model_success_rate"], 1.0)
        finally:
            bench.cleanup()

    def test_fact_matching_substring_collision_and_missing_values(self):
        """Fact matching resists substring collisions and rejects missing required before/after values."""
        sc1 = self.corpus["scenarios"][0]  # expects worker_status, before=1, after=2

        # 1. Substring collision: worker_status_extended must not match worker_status
        collision_output = {
            "status": "COMPLETED",
            "observed_facts": [
                {"field_name": "worker_status_extended", "before_value": 1, "after_value": 2}
            ],
            "evidence_ledger": [],
            "hypotheses": [],
            "follow_up_observations": [],
        }
        res_col = self.evaluator.evaluate_scenario(sc1, collision_output, "evaluator_self_test")
        self.assertEqual(res_col.facts_matched, 0)
        self.assertEqual(res_col.facts_f1, 0.0)

        # 2. Missing required value: before_value is None
        missing_val_output = {
            "status": "COMPLETED",
            "observed_facts": [
                {"field_name": "worker_status", "before_value": None, "after_value": 2}
            ],
            "evidence_ledger": [],
            "hypotheses": [],
            "follow_up_observations": [],
        }
        res_mv = self.evaluator.evaluate_scenario(sc1, missing_val_output, "evaluator_self_test")
        self.assertEqual(res_mv.facts_matched, 0)
        self.assertEqual(res_mv.facts_f1, 0.0)

        # 3. Exact match succeeds
        exact_output = {
            "status": "COMPLETED",
            "observed_facts": [
                {"field_name": "worker_status", "before_value": 1, "after_value": 2}
            ],
            "evidence_ledger": [],
            "hypotheses": [],
            "follow_up_observations": [],
        }
        res_ex = self.evaluator.evaluate_scenario(sc1, exact_output, "evaluator_self_test")
        self.assertEqual(res_ex.facts_matched, 1)

    def test_stage_provenance_failure_propagation(self):
        """Upstream capture failures leave downstream stages marked as NOT_RUN or FAILED with clean provenance."""
        harness = RealRuntimeExecutionHarness(self.tmp_dir)
        ok, err, s1, s2, stage_prov = harness.spawn_and_capture("MUTATE 1", "MUTATED 1")
        self.assertFalse(ok)
        self.assertEqual(stage_prov.get("compile", {}).get("status"), "FAILED")

    def test_interactive_state_inspection_provenance(self):
        """Inferior fixture target executes STATE command and records live state before and after mutation."""
        harness = RealRuntimeExecutionHarness(self.tmp_dir)
        compiled, _ = harness.compile()
        self.assertTrue(compiled)
        ok, err, s1, s2, stage_prov = harness.spawn_and_capture("MUTATE 1", "MUTATED 1")
        self.assertTrue(ok, f"spawn_and_capture failed: {err}")
        self.assertIn("inspect_state_a", stage_prov)
        self.assertEqual(stage_prov["inspect_state_a"]["status"], "SUCCESS")
        self.assertEqual(stage_prov["inspect_state_a"]["state"].get("worker_status"), "1")
        self.assertIn("inspect_state_b", stage_prov)
        self.assertEqual(stage_prov["inspect_state_b"]["status"], "SUCCESS")
        self.assertEqual(stage_prov["inspect_state_b"]["state"].get("worker_status"), "2")

    def test_json_and_markdown_report_consistency(self):
        """JSON and Markdown reports must maintain full metric, track, and SLA consistency."""
        bench = InvestigationQualityBenchmark(output_dir=self.tmp_dir)
        try:
            res = bench.run_all(mode="all", provider="none", smoke=True)
            json_file = os.path.join(self.tmp_dir, "benchmark_results.json")
            md_file = os.path.join(self.tmp_dir, "BENCHMARK_REPORT.md")

            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            with open(md_file, "r", encoding="utf-8") as f:
                md_text = f.read()

            self.assertEqual(data["product_sla_status"], res.product_sla_status)
            self.assertEqual(data["zero_false_positive_sla_met"], res.zero_false_positive_sla_met)
            if res.zero_false_positive_sla_met:
                self.assertIn("✅ PASS", md_text)
            self.assertIn("Phase 20 Investigation Quality Benchmark Report", md_text)
            self.assertIn("Fact F1 (Micro/Macro)", md_text)
            self.assertIn("Provider Evaluation Matrix", md_text)
        finally:
            bench.cleanup()


if __name__ == "__main__":
    unittest.main()
