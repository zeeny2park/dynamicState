"""A budget stop must not throw away what the checks that ran already found.

On a loaded host a diagnosis can outlast its wall-clock budget.  The collection then stops; before this fix the
hypotheses (and so the findings) were never formed, and a check that had already found the problem (lock_convoy:
LOCK_CONTENTION FAIL, 5 of 5 samples queued) ended as "INCONCLUSIVE: no problem finding was produced"
(tests/test_lock_contention.py::test_convoy_is_degraded_not_a_fault at load ~20).  The budget is exhausted here
deterministically right after the first check that FAILs (or after the first check, for the healthy control)."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor import expert_diagnostic_engine as ede  # noqa: E402

TARGETS = os.path.join(ROOT, "benchmarks", "diagnosis_accuracy", "targets")


def _exhaust_after(predicate):
    """Wrap _step_collect_next: once ``predicate(session)`` holds after a step, mark the budget exhausted."""
    orig = ede.AdaptiveInvestigationSession._step_collect_next

    def step(self):
        out = orig(self)
        bt = self.budget_tracker
        if bt is not None and self.state != ede.STATE_BUDGET_EXHAUSTED and predicate(self):
            bt.metrics.is_budget_exhausted = True
            bt.metrics.exhaustion_reason = "EXCEEDED_WALL_CLOCK: forced by test"
        return out
    return mock.patch.object(ede.AdaptiveInvestigationSession, "_step_collect_next", step)


@unittest.skipUnless(shutil.which("gcc") and sys.platform.startswith("linux"), "gcc / Linux needed")
class TestBudgetStop(unittest.TestCase):
    def _run(self, name, symptom, predicate):
        tmp = tempfile.mkdtemp(prefix="bud_")
        self.addCleanup(shutil.rmtree, tmp, True)
        exe = os.path.join(tmp, name)
        subprocess.run(["gcc", "-g", "-O0", "-pthread", os.path.join(TARGETS, name + ".c"), "-o", exe], check=True)
        p = subprocess.Popen([exe], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        self.assertEqual(p.stdout.readline().strip(), b"READY")
        time.sleep(0.3)
        with _exhaust_after(predicate):
            return ede.diagnose(p.pid, exe, symptom, corpus_dir=tmp).to_dict()

    def test_finding_of_a_check_that_ran_survives_the_budget_stop(self):
        r = self._run("lock_convoy", "the process feels slow, check for lock problems",
                      lambda s: any(c.status == "FAIL" for c in s.checks))
        kinds = [x["kind"] for x in r["not_covered"]]
        self.assertIn("budget_exhausted", kinds)
        self.assertIn("baseline_check_not_run", kinds, "the stop must really have cut the plan")
        self.assertEqual([f["category"] for f in r["findings"]], ["LOCK_CONTENTION"], r["summary"])
        self.assertEqual(r["verdict"], "DEGRADED", r["summary"])

    def test_healthy_target_cut_by_the_budget_is_not_healthy(self):
        r = self._run("ok_contention", "the process feels slow, check for lock problems",
                      lambda s: len(s.checks) >= 1)
        self.assertIn("budget_exhausted", [x["kind"] for x in r["not_covered"]])
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["verdict"], "INCONCLUSIVE", r["summary"])


if __name__ == "__main__":
    unittest.main()
