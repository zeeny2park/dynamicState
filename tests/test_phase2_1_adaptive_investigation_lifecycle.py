"""Phase 2.1 — Adaptive Investigation Lifecycle & Session State Machine Tests.

Verifies:
1. Complete state machine transitions through explicit lifecycle states.
2. Step-by-step manual execution (`step()`) and run to completion (`run_to_completion()`).
3. Pause and resume capabilities.
4. Resumable session serialization (`to_dict()`) and reconstruction (`from_dict()`).
5. EvidenceLedger recording with immutable provenance.
"""

import os
import subprocess
import time
import unittest

from extractor.expert_diagnostic_engine import (
    STATE_ASSESSING,
    STATE_BLOCKED,
    STATE_CLASSIFYING,
    STATE_COLLECTING,
    STATE_COMPLETED,
    STATE_CREATED,
    STATE_PLANNING,
    AdaptiveInvestigationSession,
    ExpertDiagnosticEngine,
)


class TestPhase21AdaptiveInvestigationLifecycle(unittest.TestCase):
    """Test suite for investigation state machine, stepping, and resumption."""

    def setUp(self):
        self.engine = ExpertDiagnosticEngine(corpus_dir="/tmp/phase2_1_test_corpus")

    def _spawn_healthy_target(self) -> int:
        # IMP-001: an investigation only reaches COMPLETED when checks really pass, so the full
        # lifecycle runs against the matching healthy fixture process (not the test interpreter
        # paired with an unrelated companion ELF, whose checks are all INCONCLUSIVE).
        if not os.path.exists("/tmp/expert_diagnostic_debug.elf"):
            subprocess.run(
                "g++ -g -O0 -fno-inline -fno-omit-frame-pointer "
                "tests/fixtures/real_runtime/expert_diagnostic_scenarios.cpp "
                "-o /tmp/expert_diagnostic_debug.elf -lpthread",
                shell=True,
                check=True,
            )
        proc = subprocess.Popen(["/tmp/expert_diagnostic_debug.elf", "healthy"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (proc.kill(), proc.wait(timeout=5)))
        time.sleep(0.2)
        return proc.pid

    def test_step_by_step_lifecycle_execution(self):
        """Verifies step-by-step manual stepping through the full state machine."""
        session = self.engine.start_investigation(
            problem_statement="0x7fff0038 주소에서 세그폴트 및 메모리 오염 의심",
            pid=self._spawn_healthy_target(),
            companion_elf="/tmp/expert_diagnostic_debug.elf",
        )
        self.assertEqual(session.state, STATE_CREATED)

        # Step 1: Classify
        s1 = session.step()
        self.assertEqual(s1["action"], "CLASSIFY")
        self.assertEqual(session.state, STATE_ASSESSING)

        # Step 2: Assess
        s2 = session.step()
        self.assertEqual(s2["action"], "ASSESS")
        self.assertEqual(session.state, STATE_PLANNING)

        # Step 3: Plan
        s3 = session.step()
        self.assertEqual(s3["action"], "PLAN")
        self.assertEqual(session.state, STATE_COLLECTING)
        self.assertGreater(session.plan.total_steps, 0)

        # Run remaining steps to completion
        conclusion = session.run_to_completion(max_steps=20)
        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        self.assertTrue(conclusion.confidence > 0.0)
        self.assertEqual(conclusion.investigation_id, session.investigation_id)

    def test_pause_and_resume_control(self):
        """Verifies pause and resume semantics."""
        session = self.engine.start_investigation("General health check")
        session.step()  # moves to ASSESSING

        session.pause()
        self.assertTrue(session.is_paused)
        res_paused = session.step()
        self.assertEqual(res_paused["status"], "PAUSED")
        self.assertEqual(session.state, STATE_ASSESSING)

        session.resume()
        self.assertFalse(session.is_paused)
        res_resumed = session.step()
        self.assertEqual(res_resumed["action"], "ASSESS")
        self.assertEqual(session.state, STATE_PLANNING)

    def test_session_state_serialization_and_recovery(self):
        """Verifies full export and recovery of session state (crash resilience)."""
        session = self.engine.start_investigation(
            problem_statement="Mutex deadlock between worker threads",
            pid=os.getpid(),
            companion_elf="/tmp/expert_diagnostic_debug.elf",
        )
        session.step()  # Classify
        session.step()  # Assess
        session.step()  # Plan

        # Serialize to dict
        serialized = session.to_dict()
        self.assertIn("investigation_id", serialized)
        self.assertIn("plan", serialized)
        self.assertIn("timeline", serialized)

        # Restore from dict
        recovered = AdaptiveInvestigationSession.from_dict(serialized)
        self.assertEqual(recovered.investigation_id, session.investigation_id)
        self.assertEqual(recovered.state, session.state)
        self.assertEqual(len(recovered.plan.steps), len(session.plan.steps))
        self.assertEqual(len(recovered.timeline), len(session.timeline))

        # Ensure recovered session can continue execution to completion
        conclusion = recovered.run_to_completion()
        self.assertEqual(recovered.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)

    def test_blocked_terminal_state_on_inaccessible_target(self):
        """Verifies BLOCKED state when target is inaccessible and prerequisites are missing."""
        session = self.engine.start_investigation(
            problem_statement="Inaccessible PID diagnostic check",
            pid=99999999,
            companion_elf="/nonexistent/binary.elf",
        )
        session.step()  # Classify
        res_assess = session.step()  # Assess
        self.assertEqual(session.state, STATE_BLOCKED)
        self.assertEqual(res_assess["status"], "BLOCKED")
        self.assertIsNotNone(session.conclusion)
        self.assertEqual(session.conclusion.stop_reason, "TARGET_INACCESSIBLE")


if __name__ == "__main__":
    unittest.main()
