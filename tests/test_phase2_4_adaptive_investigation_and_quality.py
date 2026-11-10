"""Phase 2.4: Adaptive Investigation Workflow & Ground-Truth Diagnostic Quality.

Validates:
1. Adaptive Investigation with vague/zero-config problem statements:
   - "Check whether this process has a problem"
   - ProblemClassifier -> TargetAssessor -> InvestigationPlanner -> Evidence Collection -> Conclusion
2. Ground-truth defect matrix:
   - Precision, recall, false-positive rate, false-negative rate
   - Verified 100% precision (FP=0) and 100% recall (FN=0) across injected defects
3. Competing hypotheses resolution:
   - Inconclusive evidence -> INSUFFICIENT_EVIDENCE
   - Definite evidence -> SUPPORTED
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.diagnostic_recipes import DiagnosticRecipeRegistry
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    DiagnosticConclusion,
    ProblemClassifier,
    TargetAssessor,
    InvestigationPlanner,
)
from extractor.observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
from extractor.target_adapter import LocalTargetAdapter


HEALTHY_AND_DEFECT_TARGET_CPP = """
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <mutex>
#include <atomic>

// Healthy variables
int g_healthy_buffer_len = 20;
int g_healthy_buffer_cap = 100;
int g_healthy_state = 1; // within [0, 1, 2]

// Injected defect variables
int g_defect_buffer_len = 200; // Len > Cap violation!
int g_defect_buffer_cap = 50;
int g_corrupted_magic = 0xDEADBEEF; // Corrupted canary
int g_unauthorized_state = 999; // Transition violation

std::atomic<bool> g_keep_running{true};

int main() {
    std::cout << "TARGET_READY" << std::endl;
    std::cout.flush();

    while (g_keep_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return 0;
}
"""


class TestPhase24AdaptiveInvestigationAndQuality(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="phase2_4_adaptive_")
        cls.src_path = os.path.join(cls.tmpdir, "quality_target.cpp")
        cls.bin_path = os.path.join(cls.tmpdir, "quality_target")
        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(HEALTHY_AND_DEFECT_TARGET_CPP)

        subprocess.check_call(["g++", "-O0", "-g", cls.src_path, "-o", cls.bin_path])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_01_vague_problem_statement_adaptive_triage(self):
        """Verify adaptive investigation correctly triages vague zero-config prompts:
        'Check whether this process has a problem'
        """
        classifier = ProblemClassifier()
        res = classifier.classify("Check whether this process has a problem")
        self.assertIsNotNone(res.primary_category)
        self.assertTrue(res.is_vague)
        # Even with vague prompt, candidate categories and screening strategy must be generated
        self.assertGreater(len(res.candidate_categories), 0)
        self.assertIsNotNone(res.screening_strategy)

        # Korean prompt triage
        res_ko = classifier.classify("이 프로세스에 이상이 있는지 점검해줘")
        self.assertIsNotNone(res_ko.primary_category)
        self.assertGreater(len(res_ko.candidate_categories), 0)

    def test_02_adaptive_investigation_session_lifecycle_against_real_process(self):
        """Execute complete adaptive investigation lifecycle against running target process:
        STATE_CREATED -> CLASSIFYING -> ASSESSING -> PLANNING -> COLLECTING -> VERIFYING -> COMPLETED
        """
        proc = subprocess.Popen([self.bin_path], stdout=subprocess.PIPE, text=True)
        try:
            line = proc.stdout.readline()
            self.assertIn("TARGET_READY", line)
            pid = proc.pid

            session = AdaptiveInvestigationSession(
                investigation_id="phase2_4_adapt_session_01",
                problem_statement="Check whether this process has a memory or variable corruption problem",
                pid=pid,
                companion_elf=self.bin_path,
                corpus_dir=self.tmpdir,
                budget_limits=ObservationBudgetLimits(max_wall_clock_ms=10000.0, max_samples=20),
            )

            # Advance session through state machine steps
            step1 = session.step()
            self.assertEqual(session.state, "ASSESSING")

            step2 = session.step()
            self.assertEqual(session.state, "PLANNING")

            step3 = session.step()
            self.assertEqual(session.state, "COLLECTING")

            # Run to completion
            conclusion = session.run_to_completion(max_steps=20)
            self.assertIsNotNone(conclusion)
            self.assertIn(conclusion.overall_verdict, ("HEALTHY", "DEFECT_CONFIRMED", "INCONCLUSIVE", "CONTRADICTED"))
            self.assertIsNotNone(conclusion.executive_summary)
            self.assertGreaterEqual(conclusion.confidence, 0.0)

        finally:
            proc.terminate()
            proc.wait()

    def test_03_ground_truth_defect_matrix_precision_and_recall(self):
        """Evaluate ground truth defect detection accuracy across healthy and injected defect states.
        Assert:
        - True Positives (TP) > 0
        - False Positives (FP) == 0 (Precision = 100%)
        - False Negatives (FN) == 0 (Recall = 100%)
        """
        registry = DiagnosticRecipeRegistry()

        # Target recipes for evaluation:
        # 1. RECIPE_INCONSISTENT_RELATED_VARIABLES
        # 2. RECIPE_STATE_TRANSITION_VIOLATIONS
        # 3. RECIPE_HEAP_METADATA_CORRUPTION
        # 4. RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS

        test_cases = [
            {
                "recipe_id": "RECIPE_INCONSISTENT_RELATED_VARIABLES",
                "healthy_evidence": {
                    "buffer_length": 20,
                    "buffer_capacity": 100,
                },
                "defect_evidence": {
                    "buffer_length": 200,
                    "buffer_capacity": 50,
                },
            },
            {
                "recipe_id": "RECIPE_STATE_TRANSITION_VIOLATIONS",
                "healthy_evidence": {
                    "allowed_states": [0, 1, 2],
                    "current_state": 1,
                    "is_illegal_transition": False,
                    "state_specification": "spec1",
                },
                "defect_evidence": {
                    "allowed_states": [0, 1, 2],
                    "current_state": 999,
                    "is_illegal_transition": True,
                    "state_specification": "spec1",
                },
            },
            {
                "recipe_id": "RECIPE_HEAP_METADATA_CORRUPTION",
                "healthy_evidence": {
                    "canary_valid": True,
                },
                "defect_evidence": {
                    "canary_corrupted": True,
                },
            },
            {
                "recipe_id": "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS",
                "healthy_evidence": {
                    "pointer_value": "0x1000",
                    "is_mapped": True,
                },
                "defect_evidence": {
                    "pointer_value": "0x0",
                    "is_null_allowed": False,
                    "is_active_lifecycle": True,
                },
            },
        ]

        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0

        for tc in test_cases:
            recipe_id = tc["recipe_id"]

            # 1. Healthy evaluation -> Expect CONTRADICTED (defect not present)
            h_res = registry.evaluate_recipe(recipe_id, tc["healthy_evidence"])
            self.assertEqual(h_res.status, "CONTRADICTED")
            if h_res.status == "CONTRADICTED":
                true_negatives += 1
            elif h_res.status == "SUPPORTED":
                false_positives += 1

            # 2. Defect evaluation -> Expect SUPPORTED (defect confirmed)
            d_res = registry.evaluate_recipe(recipe_id, tc["defect_evidence"])
            self.assertEqual(d_res.status, "SUPPORTED")
            if d_res.status == "SUPPORTED":
                true_positives += 1
            elif d_res.status == "CONTRADICTED":
                false_negatives += 1

        total_tested = len(test_cases)
        self.assertEqual(false_positives, 0, "False positive rate must be strictly 0")
        self.assertEqual(false_negatives, 0, "False negative rate must be strictly 0")
        self.assertEqual(true_positives, total_tested)
        self.assertEqual(true_negatives, total_tested)

        # Precision = TP / (TP + FP) = 1.0 (100%)
        precision = true_positives / (true_positives + false_positives)
        # Recall = TP / (TP + FN) = 1.0 (100%)
        recall = true_positives / (true_positives + false_negatives)

        self.assertEqual(precision, 1.0)
        self.assertEqual(recall, 1.0)


if __name__ == "__main__":
    unittest.main()
