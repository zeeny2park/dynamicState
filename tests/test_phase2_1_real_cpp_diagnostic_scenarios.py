"""Phase 2.1 — Real C/C++ Target Diagnostic Scenarios Test Suite.

Executes end-to-end expert investigations against real running C/C++ target processes:
1. Positive Memory Corruption: Corrupted magic and invalid pointer in NULL page.
2. Positive Memory Leak: Monotonic memory accumulation in leak pool.
3. Positive Abnormal State: Variable boundary jump violation.
4. Positive Deadlock: 2 threads in inverted mutex locking order.
5. Negative Healthy Process: Healthy running worker process confirming clean status.
6. Insufficient Evidence: Stripped binary target explicitly recording diagnostic limitations.
"""

import os
import subprocess
import time
import unittest

from extractor.diagnostic_recipes import (
    CATEGORY_ABNORMAL_VARIABLE_CHANGES,
    CATEGORY_DEADLOCK_INDICATORS,
    CATEGORY_MEMORY_CORRUPTION,
    CATEGORY_MEMORY_LEAK,
)
from extractor.expert_diagnostic_engine import (
    STATE_COMPLETED,
    ExpertDiagnosticEngine,
)


class TestPhase21RealCppDiagnosticScenarios(unittest.TestCase):
    """End-to-end diagnostic scenarios on real Linux C/C++ target processes."""

    @classmethod
    def setUpClass(cls):
        cls.debug_elf = "/tmp/expert_diagnostic_debug.elf"
        cls.stripped_elf = "/tmp/expert_diagnostic_stripped.elf"
        if not os.path.exists(cls.debug_elf) or not os.path.exists(cls.stripped_elf):
            cmd = (
                "g++ -g -O0 -fno-inline -fno-omit-frame-pointer "
                "tests/fixtures/real_runtime/expert_diagnostic_scenarios.cpp "
                "-o /tmp/expert_diagnostic_debug.elf -lpthread && "
                "strip -s -o /tmp/expert_diagnostic_stripped.elf /tmp/expert_diagnostic_debug.elf"
            )
            subprocess.run(cmd, shell=True, check=True)

    def setUp(self):
        self.engine = ExpertDiagnosticEngine(corpus_dir="/tmp/phase2_1_scenario_corpus")
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            try:
                if p.stdout:
                    p.stdout.close()
                if p.stderr:
                    p.stderr.close()
                p.terminate()
                p.wait(timeout=1.0)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def _spawn_target(self, mode: str, use_debug: bool = True) -> subprocess.Popen:
        bin_path = self.debug_elf if use_debug else self.stripped_elf
        proc = subprocess.Popen([bin_path, mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.procs.append(proc)
        time.sleep(0.15)  # Allow process to initialize
        return proc

    def test_scenario_positive_memory_corruption(self):
        """Positive test: Target process with corrupted memory magic and invalid pointer."""
        proc = self._spawn_target("corrupt")
        session = self.engine.start_investigation(
            problem_statement="WorkerNode magic corrupted and wild pointer dereference at low memory address",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()
        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        self.assertEqual(session.classification_result.primary_category, CATEGORY_MEMORY_CORRUPTION)
        self.assertTrue(conclusion.confidence >= 0.70)
        self.assertTrue(len(conclusion.recommended_remediations) > 0)

    def test_scenario_positive_memory_leak(self):
        """Positive test: Target process with unbounded heap accumulation."""
        proc = self._spawn_target("leak")
        session = self.engine.start_investigation(
            problem_statement="Unbounded heap growth and memory leak accumulating in buffer pool",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()
        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        self.assertEqual(session.classification_result.primary_category, CATEGORY_MEMORY_LEAK)
        self.assertTrue(conclusion.confidence >= 0.70)

    def test_scenario_positive_abnormal_state(self):
        """Positive test: Target process with abnormal variable state jump to 999."""
        proc = self._spawn_target("abnormal_state")
        session = self.engine.start_investigation(
            problem_statement="g_worker_state jumped to unexpected boundary value 999",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()
        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        self.assertEqual(session.classification_result.primary_category, CATEGORY_ABNORMAL_VARIABLE_CHANGES)
        self.assertIn("999", session.classification_result.normalized_query)

    def test_scenario_positive_deadlock(self):
        """Positive test: Target process with circular mutex deadlock between threads."""
        proc = self._spawn_target("deadlock")
        session = self.engine.start_investigation(
            problem_statement="스레드 간 상호 락 획득 대기로 인한 데드락 및 행 발생",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()
        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        self.assertEqual(session.classification_result.primary_category, CATEGORY_DEADLOCK_INDICATORS)
        self.assertTrue(conclusion.confidence >= 0.70)

    def test_scenario_negative_healthy_process(self):
        """Negative test: Target process is running normally without defects."""
        proc = self._spawn_target("healthy")
        session = self.engine.start_investigation(
            problem_statement="General periodic health check and thread inspection",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()
        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        # Verify no anomalous fault confirmed
        self.assertIn("No abnormal runtime indicators observed", conclusion.primary_finding)

    def test_scenario_insufficient_evidence_with_stripped_binary(self):
        """Insufficient evidence test: Target process is stripped and companion ELF is omitted."""
        proc = self._spawn_target("corrupt", use_debug=False)
        session = self.engine.start_investigation(
            problem_statement="Investigate crash on stripped production binary without DWARF",
            pid=proc.pid,
            companion_elf=None,  # No companion ELF provided
        )
        session.step()  # Classify
        session.step()  # Assess
        self.assertFalse(session.target_assessment.dwarf_available)
        self.assertTrue(any("No companion ELF provided" in lim for lim in session.target_assessment.limitations))
        conclusion = session.run_to_completion()
        self.assertIsNotNone(conclusion)
        # Limitations must be explicitly reported in conclusion
        self.assertTrue(len(conclusion.diagnostic_limitations) > 0)


if __name__ == "__main__":
    unittest.main()
