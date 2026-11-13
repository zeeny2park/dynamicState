"""Phase 2.3-B Budget Enforcement Integration Tests.

Validates:
1. Strict resource budget deduction across AdaptiveInvestigationSession and RuntimeEvidenceProvider.
2. Clean termination with STATE_BUDGET_EXHAUSTED ("BUDGET_EXHAUSTED") when bytes, samples, or wall-clock are exhausted.
3. Conclusion stop_reason recorded as "BUDGET_EXHAUSTED".
4. Cumulative budget tracking across investigation steps and replanning cycles.
5. MCP runtime_run_diagnostic_recipe budget limits enforcement.
"""

import json
import os
import subprocess
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.expert_diagnostic_engine import (
    ExpertDiagnosticEngine,
    STATE_BUDGET_EXHAUSTED,
    STATE_COMPLETED,
)
from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)
from scripts.mcp_server import runtime_run_diagnostic_recipe
from tests.support.fixture_process import fixture_popen


class TestPhase23BudgetEnforcement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        src = os.path.join(cls.tmpdir, "target.c")
        cls.bin_path = os.path.join(cls.tmpdir, "target_bin")
        with open(src, "w") as f:
            f.write("""
            #include <stdio.h>
            #include <stdlib.h>
            #include <unistd.h>
            #include <string.h>

            int g_counter = 42;
            char g_buf[1024];

            int main() {
                memset(g_buf, 0x41, sizeof(g_buf));
                while (1) {
                    g_counter++;
                    usleep(10000);
                }
                return 0;
            }
            """)
        subprocess.check_call([
            "gcc", "-O0", "-g", src, "-o", cls.bin_path
        ])

    def setUp(self):
        self.proc = fixture_popen([self.bin_path])
        time.sleep(0.05)

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=1.0)
            except Exception:
                self.proc.kill()

    def test_budget_exhaustion_on_byte_limit(self):
        """Adaptive investigation halts cleanly when byte limit is exceeded."""
        engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)
        # Limit bytes to a tiny number (e.g. 10 bytes) so first memory read exceeds it
        tracker = ObservationBudgetTracker(limits=ObservationBudgetLimits(
            max_bytes_read=10,
            max_bytes_per_observation=1024 * 1024,
            max_samples=100,
            max_wall_clock_ms=5000.0,
        ))

        session = engine.start_investigation(
            problem_statement="Investigate unexpected memory growth and invalid memory access",
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            budget_tracker=tracker,
        )

        # Run investigation to completion or budget exhaustion
        conclusion = session.run_to_completion(max_steps=10)

        self.assertEqual(session.state, STATE_BUDGET_EXHAUSTED)
        self.assertEqual(conclusion.stop_reason, "BUDGET_EXHAUSTED")
        self.assertIn("EXCEEDED_BYTES_READ", conclusion.executive_summary)
        self.assertGreater(tracker.metrics.bytes_read, 0)

    def test_budget_exhaustion_on_sample_limit(self):
        """Adaptive investigation halts cleanly when sample limit is reached."""
        engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)
        # Allow only 1 sample
        tracker = ObservationBudgetTracker(limits=ObservationBudgetLimits(
            max_bytes_read=1024 * 1024,
            max_samples=1,
            max_wall_clock_ms=5000.0,
        ))

        session = engine.start_investigation(
            problem_statement="Investigate unexpected memory growth and invalid memory access",
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            budget_tracker=tracker,
        )

        conclusion = session.run_to_completion(max_steps=10)
        self.assertEqual(session.state, STATE_BUDGET_EXHAUSTED)
        self.assertEqual(conclusion.stop_reason, "BUDGET_EXHAUSTED")
        self.assertGreaterEqual(tracker.metrics.samples_collected, 1)

    def test_mcp_recipe_budget_passthrough_and_enforcement(self):
        """MCP runtime_run_diagnostic_recipe respects budget limits and stops when exhausted."""
        res_str = runtime_run_diagnostic_recipe(
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            recipe="RECIPE_INVALID_MEMORY_ACCESS",
            max_bytes_read=5,  # Exceedingly small byte budget
        )
        res = json.loads(res_str)
        self.assertTrue(res.get("success"), f"Failed: {res}")
        self.assertEqual(res.get("state"), STATE_BUDGET_EXHAUSTED)
        self.assertEqual(res.get("stop_reason"), "BUDGET_EXHAUSTED")
        metrics = res.get("budget_metrics")
        self.assertIsNotNone(metrics)
        self.assertGreater(metrics.get("bytes_read", 0), 0)


    def test_cumulative_budget_preservation_across_steps(self):
        """Budget metrics strictly accumulate monotonically across investigation steps."""
        engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)
        tracker = ObservationBudgetTracker(limits=ObservationBudgetLimits(
            max_bytes_read=1024 * 1024,
            max_samples=100,
            max_wall_clock_ms=10000.0,
        ))

        session = engine.start_investigation(
            problem_statement="Investigate unexpected memory growth and invalid memory access",
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            budget_tracker=tracker,
        )

        session.step()  # CLASSIFY
        session.step()  # ASSESS
        session.step()  # PLAN

        initial_bytes = tracker.metrics.bytes_read
        initial_samples = tracker.metrics.samples_collected

        session.step()  # COLLECT step 1
        bytes_after_1 = tracker.metrics.bytes_read
        samples_after_1 = tracker.metrics.samples_collected

        self.assertGreaterEqual(bytes_after_1, initial_bytes)
        self.assertGreaterEqual(samples_after_1, initial_samples)

        session.step()  # COLLECT step 2
        bytes_after_2 = tracker.metrics.bytes_read
        samples_after_2 = tracker.metrics.samples_collected

        self.assertGreaterEqual(bytes_after_2, bytes_after_1)
        self.assertGreaterEqual(samples_after_2, samples_after_1)


if __name__ == "__main__":
    unittest.main()
