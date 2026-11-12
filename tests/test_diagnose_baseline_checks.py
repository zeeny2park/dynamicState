"""Baseline checks always run, whatever the symptom says.

Real processes (fixtures compiled at test time, no architecture-specific code).  Verifies:
(a) the executed checks contain every baseline recipe for differently worded symptoms,
(b) a real deadlock is found with a symptom that contains none of the classifier's deadlock keywords,
(c) a spinning thread is reported in the thread/CPU category (not DEADLOCK_INDICATORS) and named,
(d) a healthy idle process yields no fault finding with any wording,
(e) a too-small budget lists the unexecuted baseline checks in not_covered,
plus planning-level checks (no process needed).
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.diagnostic_recipes import BASELINE_RECIPE_IDS, CATEGORY_DEADLOCK_INDICATORS, CATEGORY_PROCESS_INSTABILITY
from extractor.expert_diagnostic_engine import (
    InvestigationPlanner,
    ProblemClassifier,
    diagnose,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "real_runtime")

# No keyword in common, none of them a classifier keyword of the deadlock category.
SYMPTOMS = (
    "the service stopped responding",
    "this process uses a full CPU core while doing nothing useful",
    "requests are not being processed anymore",
    "",
)

SPIN_C = r"""
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
static volatile int go;
static volatile unsigned long laps;
static void *spin_loop(void *a) { (void)a; pthread_setname_np(pthread_self(), "spinner_t"); while (!go) laps++; return 0; }
int main(void) { pthread_t t; pthread_create(&t, 0, spin_loop, 0); for (;;) pause(); }
"""

IDLE_C = r"""
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
static void *idle_loop(void *a) { (void)a; pthread_setname_np(pthread_self(), "idler_t"); for (;;) usleep(200000); return 0; }
int main(void) { pthread_t t; pthread_create(&t, 0, idle_loop, 0); for (;;) pause(); }
"""


@unittest.skipUnless(shutil.which("gcc"), "gcc not available")
class TestBaselineAlwaysRuns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="baseline_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.corpus = os.path.join(cls.tmp, "corpus")
        cls.bins = {}
        for name, src in (("spin", SPIN_C), ("idle", IDLE_C)):
            c = os.path.join(cls.tmp, name + ".c")
            with open(c, "w") as fh:
                fh.write(src)
            out = os.path.join(cls.tmp, name)
            subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", c, "-o", out, "-pthread"], check=True)
            cls.bins[name] = out
        out = os.path.join(cls.tmp, "deadlock")
        subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1",
                        os.path.join(FIXTURES, "proc_thread_circular_deadlock.c"), "-o", out, "-pthread"], check=True)
        cls.bins["deadlock"] = out

    def _launch(self, name):
        proc = subprocess.Popen([self.bins[name]], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def _kill():
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()

        self.addCleanup(_kill)
        time.sleep(0.8)
        self.assertIsNone(proc.poll(), "fixture exited prematurely")
        return proc

    def _diag(self, pid, symptom, **kw):
        return diagnose(pid, corpus_dir=self.corpus, symptom=symptom, **kw)

    # (a)
    def test_a_every_baseline_recipe_executes_for_any_wording(self):
        pid = self._launch("idle").pid
        for symptom in SYMPTOMS:
            with self.subTest(symptom=symptom):
                res = self._diag(pid, symptom)
                ran = {c["recipe_id"] for c in res.checks_run}
                self.assertTrue(set(BASELINE_RECIPE_IDS) <= ran, f"missing {set(BASELINE_RECIPE_IDS) - ran}")
                self.assertTrue(res.collection_impact["zero_stop"])
                self.assertEqual(res.collection_impact["measured_stop_ms"], 0.0)

    # (b)
    def test_b_deadlock_found_with_wording_without_deadlock_keywords(self):
        kws = [k for lang in ProblemClassifier.CATEGORY_KEYWORDS[CATEGORY_DEADLOCK_INDICATORS].values() for k in lang]
        symptom = "the service stopped responding"
        self.assertFalse([k for k in kws if k in symptom], "wording must contain no deadlock keyword")
        res = self._diag(self._launch("deadlock").pid, symptom)
        dl = [f for f in res.findings if f["category"] == CATEGORY_DEADLOCK_INDICATORS]
        self.assertTrue(dl, f"no deadlock finding; verdict={res.verdict} findings={res.findings}")
        self.assertEqual(res.verdict, "CONFIRMED_FAULT")
        self.assertTrue(dl[0]["subjects"])

    # (c)
    def test_c_spinning_thread_has_thread_category_and_is_named(self):
        res = self._diag(self._launch("spin").pid, "requests are not being processed anymore")
        spin = [f for f in res.findings if "spinner_t" in f["subjects"]]
        self.assertTrue(spin, f"spinning thread not named: {res.findings}")
        for f in spin:
            self.assertEqual(f["category"], CATEGORY_PROCESS_INSTABILITY)
            self.assertNotEqual(f["category"], CATEGORY_DEADLOCK_INDICATORS)
            self.assertIn("RECIPE_THREAD_STATE_ANOMALIES", f["recipe_ids"])
        self.assertFalse([f for f in res.findings if f["category"] == CATEGORY_DEADLOCK_INDICATORS])

    # (d)
    def test_d_healthy_idle_has_no_fault_finding_with_any_wording(self):
        pid = self._launch("idle").pid
        for symptom in SYMPTOMS + ("general health check",):
            with self.subTest(symptom=symptom):
                res = self._diag(pid, symptom)
                self.assertNotIn(res.verdict, ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT"))
                self.assertEqual(res.findings, [])

    # (e)
    def test_e_budget_too_small_lists_skipped_baseline_in_not_covered(self):
        pid = self._launch("idle").pid
        res = self._diag(pid, "this process uses a full CPU core while doing nothing useful", time_limit_s=0.05)
        ran = {c["recipe_id"] for c in res.checks_run}
        missing = set(BASELINE_RECIPE_IDS) - ran
        self.assertTrue(missing, "a 50 ms budget should not fit the whole baseline")
        listed = {n["item"] for n in res.not_covered if n["kind"] == "baseline_check_not_run"}
        self.assertEqual(missing, listed)
        for n in res.not_covered:
            if n["kind"] == "baseline_check_not_run":
                self.assertTrue(n["reason"])
        self.assertNotEqual(res.verdict, "HEALTHY")


class TestBaselinePlanning(unittest.TestCase):
    """Plan shape without a process."""

    def test_plan_contains_baseline_for_any_wording_and_keeps_specific_recipes(self):
        planner = InvestigationPlanner()
        for symptom in SYMPTOMS + ("memory leak growing", "deadlock between threads", "general health check"):
            with self.subTest(symptom=symptom):
                plan = planner.create_plan(ProblemClassifier().classify(symptom), None)
                ids = [s.recipe_id for s in plan.steps]
                self.assertTrue(set(BASELINE_RECIPE_IDS) <= set(ids))
                self.assertEqual(len(ids), len(set(ids)))
        leak = [s.recipe_id for s in planner.create_plan(ProblemClassifier().classify("memory leak growing"), None).steps]
        self.assertIn("RECIPE_HEAP_GROWTH", leak)
        self.assertLess(leak.index("RECIPE_HEAP_GROWTH"), leak.index("RECIPE_THREAD_STATE_ANOMALIES"))


if __name__ == "__main__":
    unittest.main()
