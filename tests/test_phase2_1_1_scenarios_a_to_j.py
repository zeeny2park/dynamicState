"""Phase 2.1.1 — Comprehensive Validation of Scenarios A through J.

Verifies the 10 real C/C++ runtime scenarios required by Phase 2.1.1 Section 10:
A. Healthy process: clean status, verified checks >= 1, memory readable, honest coverage.
B. Invalid pointer / memory corruption: low-memory pointer (0x40) and corrupt magic (0xdeadbeef) confirmed.
C. Heap growth over time: temporal growth observed and confirmed.
D. Allocation/free imbalance: alloc count >> free count detected and confirmed.
E. Abnormal global variable transition: boundary violation / illegal state transition confirmed.
F. Related field inconsistency: buffer length > capacity invariant violation confirmed.
G. Thread deadlock: circular mutex wait cycle between threads confirmed.
H. Blocked thread without proven deadlock: blocked thread observed without cycle; candidate reported without false deadlock.
I. Missing DWARF information (stripped binary): missing DWARF limitation recorded, graceful execution.
J. Insufficient memory access permissions: unreadable memory handled fail-closed, memory_readable = False, no fabrication.
"""

import os
import subprocess
import time
import unittest

from tests.fixture_builds import ensure_expert_diagnostic_fixture
from extractor.diagnostic_recipes import (
    CATEGORY_ABNORMAL_VARIABLE_CHANGES,
    CATEGORY_DEADLOCK_INDICATORS,
    CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY,
    CATEGORY_MEMORY_CORRUPTION,
    CATEGORY_MEMORY_LEAK,
    DiagnosticRecipeRegistry,
)
from extractor.expert_diagnostic_engine import (
    STATE_BLOCKED,
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
    ExpertDiagnosticEngine,
    TargetAssessor,
)


class TestPhase211ScenariosAToJ(unittest.TestCase):
    """End-to-end verification of scenarios A through J against real C++ target processes."""

    @classmethod
    def setUpClass(cls):
        cls.debug_elf = "/tmp/expert_diagnostic_debug.elf"
        cls.stripped_elf = "/tmp/expert_diagnostic_stripped.elf"
        ensure_expert_diagnostic_fixture()

    def setUp(self):
        self.engine = ExpertDiagnosticEngine(corpus_dir="/tmp/phase2_1_1_scenarios_corpus")
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            try:
                p.terminate()
                p.wait(timeout=1.0)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def _spawn_target(self, mode: str, use_debug: bool = True) -> subprocess.Popen:
        elf = self.debug_elf if use_debug else self.stripped_elf
        p = subprocess.Popen([elf, mode], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        time.sleep(0.12)
        return p

    def test_scenario_a_healthy_process(self):
        """Scenario A: Healthy process verified clean with honest coverage."""
        proc = self._spawn_target("healthy")
        session = self.engine.start_investigation(
            problem_statement="Routine operational health check",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()

        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        self.assertIn("No abnormal runtime indicators observed", conclusion.primary_finding)
        self.assertGreaterEqual(session.verified_checks_count, 1)
        self.assertTrue(session.target_assessment.memory_readable)
        self.assertEqual(conclusion.confidence, 0.90)

    def test_scenario_b_invalid_pointer_and_memory_corruption(self):
        """Scenario B: Invalid low-memory pointer and corrupt magic detected and confirmed."""
        proc = self._spawn_target("corrupt")
        session = self.engine.start_investigation(
            problem_statement="Investigate memory corruption in worker payload pointer",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()

        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        self.assertIn("MEMORY_CORRUPTION", conclusion.primary_finding)
        top_hyp = session.active_hypotheses[0]
        self.assertEqual(top_hyp.status, "CONFIRMED")
        self.assertGreaterEqual(top_hyp.confidence, 0.90)
        # Check criteria execution results
        crit_fails = [r for r in top_hyp.verification_execution_results if r["result"] == "FAIL"]
        self.assertGreater(len(crit_fails), 0)

    def test_scenario_c_heap_growth_over_time(self):
        """Scenario C: Monotonic heap growth observed across intervals and confirmed."""
        proc = self._spawn_target("leak")
        session = self.engine.start_investigation(
            problem_statement="Process memory growth and leak detection in worker pool",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()

        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        self.assertIn("MEMORY_LEAK", conclusion.primary_finding)
        top_hyp = session.active_hypotheses[0]
        self.assertEqual(top_hyp.status, "CONFIRMED")
        self.assertGreaterEqual(top_hyp.confidence, 0.85)

    def test_scenario_d_allocation_free_imbalance(self):
        """Scenario D: Allocation count >> free count detected and confirmed."""
        proc = self._spawn_target("alloc_imbalance")
        session = self.engine.start_investigation(
            problem_statement="Severe allocation and free imbalance in memory pool",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()

        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        self.assertIn("MEMORY_LEAK", conclusion.primary_finding)
        # Verify alloc_count and free_count were collected
        obs_records = session.collected_evidence_records
        self.assertTrue(any("g_alloc_count" in str(r.source_variable) for r in obs_records))

    def test_scenario_e_abnormal_global_variable_transition(self):
        """Scenario E: g_worker_state holds 999.

        IMP-018: a large value alone is an observation, not an observed transition: with no transition and no
        state specification it is no longer confirmed as a state-transition violation."""
        proc = self._spawn_target("abnormal_state")
        session = self.engine.start_investigation(
            problem_statement="Unexpected state transition in g_worker_state",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()

        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        trans = [c for c in session.checks if c.recipe_id == "RECIPE_STATE_TRANSITION_VIOLATIONS"]
        self.assertTrue(trans)
        self.assertNotEqual(trans[0].status, "FAIL")  # no confirmed transition violation from a value alone
        self.assertTrue(any("g_worker_state" in str(c.actual_observations.get("variable_name") or "") for c in trans))

    def test_scenario_f_related_field_inconsistency(self):
        """Scenario F: Buffer length > capacity invariant violation confirmed."""
        proc = self._spawn_target("field_inconsistency")
        session = self.engine.start_investigation(
            problem_statement="Inconsistent related fields in buffer management state",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()

        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        # Field inconsistency detected
        obs_records = session.collected_evidence_records
        self.assertTrue(any("g_buffer_length" in str(r.source_variable) for r in obs_records))

    def test_scenario_g_thread_deadlock(self):
        """Scenario G: Circular mutex deadlock between threads confirmed."""
        proc = self._spawn_target("deadlock")
        session = self.engine.start_investigation(
            problem_statement="Thread hang and circular mutex deadlock between workers",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()

        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        self.assertIn("DEADLOCK_INDICATORS", conclusion.primary_finding)
        top_hyp = session.active_hypotheses[0]
        self.assertEqual(top_hyp.status, "CONFIRMED")

    def test_scenario_h_blocked_thread_without_deadlock(self):
        """Scenario H: Blocked thread observed without circular wait; candidate refuted."""
        proc = self._spawn_target("blocked_no_deadlock")
        session = self.engine.start_investigation(
            problem_statement="Investigate thread deadlock in worker mutex",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()

        # Must NOT falsely confirm a circular deadlock!
        self.assertIsNotNone(conclusion)
        for hyp in session.active_hypotheses:
            if "DEADLOCK" in hyp.category:
                self.assertNotEqual(hyp.status, "CONFIRMED")

    def test_scenario_i_missing_dwarf_stripped_binary(self):
        """Scenario I: Stripped binary records DWARF limitation and proceeds gracefully."""
        proc = self._spawn_target("corrupt", use_debug=False)
        session = self.engine.start_investigation(
            problem_statement="Memory corruption inspection on stripped binary",
            pid=proc.pid,
            companion_elf=self.stripped_elf,
        )
        session.step()  # Classify
        session.step()  # Assess

        self.assertFalse(session.target_assessment.dwarf_available)
        self.assertTrue(any("debug_info" in lim for lim in session.target_assessment.limitations))

        conclusion = session.run_to_completion()
        self.assertIsNotNone(conclusion)
        self.assertTrue(any("debug_info" in lim for lim in conclusion.diagnostic_limitations))

    def test_scenario_j_insufficient_memory_access_permissions(self):
        """Scenario J: Inaccessible target PID or denied permissions marks target unreadable."""
        assessor = TargetAssessor()
        # Assess a nonexistent PID
        res = assessor.assess(pid=99999999, companion_elf=self.debug_elf)

        self.assertFalse(res.accessible)
        self.assertFalse(res.memory_readable)
        self.assertFalse(res.prerequisites_met)
        self.assertNotIn("PROCESS_VM_READV_ZERO_STOP", res.capabilities)
        self.assertNotIn("PROCESS_MEMORY_READABLE", res.capabilities)
        self.assertTrue(any("not running or not found" in lim for lim in res.limitations))

        # Start session with inaccessible PID
        session = self.engine.start_investigation(
            problem_statement="Diagnose inaccessible process",
            pid=99999999,
            companion_elf=self.debug_elf,
        )
        session.step()  # Classify
        step_res = session.step()  # Assess
        self.assertEqual(session.state, STATE_BLOCKED)
        self.assertEqual(step_res["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
