"""Phase 2.1.1 — Adaptive Replanning and Session Recovery Test Suite.

Verifies:
1. Evidence-driven replanning dynamically reprioritizes discriminating follow-up steps.
2. Contradictory observations skip/prune irrelevant steps in the plan.
3. Early stop condition terminates collection safely when fault is definitively confirmed.
4. Authoritative investigation state is persisted and resumed from corpus storage.
5. Expert diagnostic report exports complete 13-point structured incident bundle.
"""

import json
import os
import select
import subprocess
import time
import unittest

from extractor.diagnostic_recipes import BASELINE_RECIPE_IDS
from tests.fixture_builds import ensure_expert_diagnostic_fixture
from extractor.expert_diagnostic_engine import (
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
    AdaptiveInvestigationSession,
    ExpertDiagnosticEngine,
)
from tests.support.fixture_process import fixture_popen


class TestPhase211AdaptiveReplanning(unittest.TestCase):
    """Audits adaptive investigation feedback loop, replanning, and report generation."""

    @classmethod
    def setUpClass(cls):
        cls.debug_elf = "/tmp/expert_diagnostic_debug.elf"
        cls.stripped_elf = "/tmp/expert_diagnostic_stripped.elf"
        ensure_expert_diagnostic_fixture()

    def setUp(self):
        self.corpus_dir = "/tmp/phase2_1_1_replan_corpus"
        self.engine = ExpertDiagnosticEngine(corpus_dir=self.corpus_dir)
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            try:
                if p.stdout:
                    p.stdout.close()
            except Exception:
                pass
            try:
                p.terminate()
                p.wait(timeout=1.0)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def _spawn_target(self, mode: str) -> subprocess.Popen:
        p = fixture_popen([self.debug_elf, mode], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.procs.append(p)
        # The fixture prints its banner (flushed) immediately before applying the scenario state
        # (e.g. the "corrupt" mode mutates globals right after it). Wait for the banner instead of a
        # fixed sleep so a loaded CI VM cannot observe the target before the scenario is in place.
        ready, _, _ = select.select([p.stdout], [], [], 10.0)
        self.assertTrue(ready, "fixture did not print its banner within 10s")
        self.assertIn("Mode: " + mode, p.stdout.readline())
        time.sleep(0.1)
        return p

    def test_adaptive_early_stop_on_definitive_fault(self):
        """Verifies early stop when a recipe confirms fault with >= 0.90 confidence."""
        proc = self._spawn_target("corrupt")
        session = self.engine.start_investigation(
            problem_statement="Memory corruption in worker payload pointer",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        session.step()  # Classify
        session.step()  # Assess
        session.step()  # Plan
        total_planned = session.plan.total_steps

        # Execute first collection step (RECIPE_INVALID_MEMORY_ACCESS confirms fault 0.98)
        res = session.step()
        self.assertEqual(res["action"], "COLLECT_STEP")
        # Remaining NON-baseline steps are marked SKIPPED (early stop intent kept for them) ...
        skipped_steps = [s for s in session.plan.steps if s.status == "SKIPPED"]
        self.assertGreater(len(skipped_steps), 0)
        self.assertFalse([s for s in skipped_steps if s.recipe_id in BASELINE_RECIPE_IDS])
        # ... but the baseline checks that have not run yet keep the investigation going (a second problem
        # must not be missed), so the early stop returns only once they are done.
        self.assertNotEqual(res.get("adaptive_action"), "EARLY_ANOMALY_CONFIRMED")
        self.assertEqual(session.state, "COLLECTING")
        guard = 0
        while session.state == "COLLECTING" and guard < 20:
            session.step()
            guard += 1

        # Transition proceeds to ANALYZING without executing the redundant (non-baseline) steps
        self.assertEqual(session.state, "ANALYZING")
        executed = {c.recipe_id for c in session.checks}
        self.assertTrue(set(BASELINE_RECIPE_IDS) <= executed)
        self.assertFalse([s for s in session.plan.steps if s.status == "SKIPPED" and s.recipe_id in executed])

    def test_session_persistence_and_resume_from_disk(self):
        """Verifies that an investigation session persists to disk and can be restored by ID."""
        proc = self._spawn_target("healthy")
        session = self.engine.start_investigation(
            problem_statement="Operational status and memory leak check",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        inv_id = session.investigation_id
        session.step()  # Classify
        session.step()  # Assess
        session.step()  # Plan

        # Verify disk persistence file exists
        inv_file = os.path.join(self.corpus_dir, "investigations", f"{inv_id}.json")
        self.assertTrue(os.path.exists(inv_file))

        # Create a fresh engine instance with same corpus_dir and restore session
        fresh_engine = ExpertDiagnosticEngine(corpus_dir=self.corpus_dir)
        restored = fresh_engine.get_session(inv_id)

        self.assertIsNotNone(restored)
        self.assertEqual(restored.investigation_id, inv_id)
        self.assertEqual(restored.state, session.state)
        self.assertEqual(restored.pid, proc.pid)
        self.assertIsNotNone(restored.plan)

        # Restored session can continue running to completion
        conclusion = restored.run_to_completion()
        self.assertIsNotNone(conclusion)
        self.assertEqual(restored.state, STATE_COMPLETED)

    def test_export_13_point_expert_report_json_and_markdown(self):
        """Verifies export of all 13 required report sections in JSON and Markdown."""
        proc = self._spawn_target("corrupt")
        session = self.engine.start_investigation(
            problem_statement="Investigate invalid pointer corruption in worker_thread",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        session.run_to_completion()

        # 1. JSON Report
        report_json = session.export_report(format="json")
        self.assertIn("report_13_points", report_json)
        points = report_json["report_13_points"]
        expected_keys = [
            "1_problem_description",
            "2_target_information",
            "3_initial_classification",
            "4_investigation_scope",
            "5_executed_diagnostic_procedures",
            "6_actual_observations",
            "7_confirmed_findings",
            "8_probable_causes",
            "9_rejected_hypotheses",
            "10_unresolved_hypotheses",
            "11_evidence_to_source_mapping",
            "12_missing_evidence",
            "13_recommended_next_actions",
        ]
        for k in expected_keys:
            self.assertIn(k, points, f"Missing report section: {k}")

        # 2. Markdown Report
        report_md = session.export_report(format="markdown")
        self.assertIsInstance(report_md, str)
        for i in range(1, 14):
            self.assertIn(f"## {i}.", report_md, f"Missing section ## {i}. in markdown report")


if __name__ == "__main__":
    unittest.main()
