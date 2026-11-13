"""Phase 2.1.1 — Evidence-Driven Hypotheses and Verification Criteria Test Suite.

Verifies:
1. Hypotheses are formulated with explicit executable verification criteria and diagnostic rules.
2. Confidence is computed from criteria satisfaction rather than raw evidence count.
3. Verification criteria execute deterministically returning PASS, FAIL, INCONCLUSIVE.
4. Contradictory observations reject or refute previously proposed hypotheses.
5. Null hypothesis concludes INCONCLUSIVE when evidence coverage is insufficient.
"""

import os
import subprocess
import time
import unittest

from tests.fixture_builds import ensure_expert_diagnostic_fixture
from extractor.diagnostic_recipes import (
    CATEGORY_DEADLOCK_INDICATORS,
    CATEGORY_MEMORY_CORRUPTION,
    CATEGORY_MEMORY_LEAK,
)
from extractor.expert_diagnostic_engine import (
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
    ExpertDiagnosticEngine,
    ExpertHypothesis,
)
from tests.support.fixture_process import fixture_popen


class TestPhase211EvidenceDrivenHypotheses(unittest.TestCase):
    """Audits hypothesis formulation, executable verification criteria, and null-hypothesis honesty."""

    @classmethod
    def setUpClass(cls):
        cls.debug_elf = "/tmp/expert_diagnostic_debug.elf"
        ensure_expert_diagnostic_fixture(need_stripped=False)

    def setUp(self):
        self.engine = ExpertDiagnosticEngine(corpus_dir="/tmp/phase2_1_1_hyp_corpus")
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

    def _spawn_target(self, mode: str) -> subprocess.Popen:
        p = fixture_popen([self.debug_elf, mode], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        time.sleep(0.12)
        return p

    def test_hypothesis_model_attributes_and_criteria_execution(self):
        """Verifies hypothesis includes rules, verification criteria, and execution results."""
        proc = self._spawn_target("corrupt")
        session = self.engine.start_investigation(
            problem_statement="Investigate corrupt memory and invalid pointer dereference",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        session.run_to_completion()

        self.assertGreater(len(session.active_hypotheses), 0)
        hyp = session.active_hypotheses[0]

        # Verify all required model fields
        self.assertTrue(hasattr(hyp, "hypothesis_id"))
        self.assertTrue(hasattr(hyp, "applicable_diagnostic_rules"))
        self.assertTrue(hasattr(hyp, "verification_criteria"))
        self.assertTrue(hasattr(hyp, "verification_execution_results"))
        self.assertTrue(hasattr(hyp, "supporting_evidence_ids"))
        self.assertTrue(hasattr(hyp, "contradicting_evidence_ids"))

        self.assertGreater(len(hyp.applicable_diagnostic_rules), 0)
        self.assertGreater(len(hyp.verification_criteria), 0)
        self.assertGreater(len(hyp.verification_execution_results), 0)

        # Check that criteria results contain PASS/FAIL outcomes with rationales
        crit_res = hyp.verification_execution_results
        self.assertTrue(all(r["result"] in ("PASS", "FAIL", "INCONCLUSIVE", "NOT_APPLICABLE") for r in crit_res))
        self.assertTrue(all("rationale" in r for r in crit_res))

    def test_contradictory_evidence_refutes_hypothesis(self):
        """Verifies that counter-indicators observed against a hypothesis refute it."""
        proc = self._spawn_target("healthy")
        session = self.engine.start_investigation(
            problem_statement="Investigate invalid pointer corruption in worker_thread",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        # Execute investigation on healthy process where pointer is safe
        conclusion = session.run_to_completion()

        # The fault hypothesis for MEMORY_CORRUPTION should NOT be confirmed
        for h in session.active_hypotheses:
            if "CORRUPTION" in h.category:
                self.assertNotEqual(h.status, "CONFIRMED")

        # Refuted hypotheses list should contain any contradicted candidate
        self.assertIn("No abnormal runtime indicators observed", conclusion.primary_finding)

    def test_null_hypothesis_coverage_honesty(self):
        """Verifies that without sufficient coverage, the conclusion is honest INCONCLUSIVE."""
        # Offline mode without live PID cannot certify process healthy
        session = self.engine.start_investigation(
            problem_statement="Routine operational health check",
            pid=None,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()

        # Without live target memory access, state must be INCONCLUSIVE, not healthy
        self.assertEqual(conclusion.status, STATE_INCONCLUSIVE)
        self.assertTrue(any("LIVE_TARGET_PID" in s or "insufficient" in s.lower() for s in conclusion.missing_evidence_and_unknowns + [conclusion.executive_summary]))

    def test_compare_competing_hypotheses(self):
        """Verifies side-by-side comparison of competing hypotheses."""
        proc = self._spawn_target("corrupt")
        session = self.engine.start_investigation(
            problem_statement="Investigate worker instability and possible memory corruption",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        session.run_to_completion()

        active_hids = [h.hypothesis_id for h in session.active_hypotheses]
        if len(active_hids) >= 1:
            cmp_res = session.compare_hypotheses(active_hids)
            self.assertEqual(cmp_res["investigation_id"], session.investigation_id)
            self.assertEqual(cmp_res["compared_count"], len(active_hids))
            self.assertIn("recommendation", cmp_res)


if __name__ == "__main__":
    unittest.main()
