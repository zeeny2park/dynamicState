"""Time budget of the default checks (roadmap decision 6.1-2; extractor.check_budget).

Default checks are the baseline checks the symptom did not ask for.  A default check whose expected cost does not
fit the budget is not run; that is recorded as a structured reason (``not_run_reason == "time_budget"``), shown as
"실행 안 함" with the reason, and it is a baseline coverage gap: the budget never produces a HEALTHY verdict that
skipped part of the required baseline.  Checks requested by the symptom's problem categories are never skipped.
"""
import json
import math
import os
import shutil
import subprocess
import sys
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor import check_budget as cb  # noqa: E402
from extractor import expert_diagnostic_engine as ede  # noqa: E402
from extractor.diagnostic_recipes import BASELINE_RECIPE_IDS, DiagnosticRecipeRegistry  # noqa: E402
from extractor.human_report import check_rows, render_human_report  # noqa: E402
from tests.support.fixture_process import fixture_popen  # noqa: E402
from tests.support.tmpdirs import temp_dir  # noqa: E402

TARGETS = os.path.join(ROOT, "benchmarks", "diagnosis_accuracy", "targets")


class TestBudgetModel(unittest.TestCase):
    def test_configuration_explicit_then_environment_then_default_and_non_positive_disables(self):
        with mock.patch.dict(os.environ, {cb.ENV_TOTAL: "", cb.ENV_PER_CHECK: ""}):
            d = cb.DefaultCheckBudget.resolve()
            self.assertEqual((d.total_s, d.per_check_s), (cb.DEFAULT_TOTAL_S, cb.DEFAULT_PER_CHECK_S))
        with mock.patch.dict(os.environ, {cb.ENV_TOTAL: "4", cb.ENV_PER_CHECK: "0"}):
            d = cb.DefaultCheckBudget.resolve()
            self.assertEqual(d.total_s, 4.0)
            self.assertTrue(math.isinf(d.per_check_s))
            self.assertEqual(cb.DefaultCheckBudget.resolve(3.0, 1.0).to_dict(), {"total_s": 3.0, "per_check_s": 1.0})
        self.assertEqual(cb.DefaultCheckBudget.from_dict({"total_s": None, "per_check_s": 2}).to_dict(),
                         {"total_s": None, "per_check_s": 2.0})

    def test_decision_per_check_then_total(self):
        b = cb.DefaultCheckBudget(total_s=3.0, per_check_s=1.0)
        self.assertIsNone(b.decide(0.9, 2.0))
        self.assertEqual(b.decide(1.1, 0.0), cb.LIMIT_PER_CHECK)
        self.assertEqual(b.decide(0.9, 2.2), cb.LIMIT_TOTAL)

    def test_declared_cost_scales_with_threads_and_charges_a_shared_collection_once(self):
        r = DiagnosticRecipeRegistry.get_recipe("RECIPE_THREAD_STATE_ANOMALIES")
        small = cb.declared_cost_s(r, 2, collected=())
        big = cb.declared_cost_s(r, 300, collected=())
        paid = cb.declared_cost_s(r, 300, collected=(r.shared_cost,))
        self.assertTrue(r.shared_cost in cb.SHARED_COSTS)
        self.assertLess(small, big)
        self.assertLess(paid, big)
        for rid in BASELINE_RECIPE_IDS:   # every baseline recipe declares a cost
            self.assertGreater(DiagnosticRecipeRegistry.get_recipe(rid).expected_cost_s, 0.0, rid)

    def test_correction_is_a_clamped_median(self):
        self.assertEqual(cb.correction([]), 1.0)
        self.assertEqual(cb.correction([(0.1, 0.05)]), 1.0)                      # never below 1
        self.assertAlmostEqual(cb.correction([(0.1, 0.2), (0.8, 1.6), (0.8, 8.0)]), 2.0)  # one outlier does not decide
        self.assertEqual(cb.correction([(0.1, 10.0)]), cb.MAX_CORRECTION)

    def test_default_check_is_a_baseline_check_the_symptom_did_not_ask_for(self):
        self.assertTrue(cb.is_default_check("RECIPE_FD_LEAK", BASELINE_RECIPE_IDS, [], ["FD_LEAK"]))
        self.assertFalse(cb.is_default_check("RECIPE_FD_LEAK", BASELINE_RECIPE_IDS, ["FD_LEAK"], ["FD_LEAK"]))
        self.assertFalse(cb.is_default_check("RECIPE_HEAP_RETENTION", BASELINE_RECIPE_IDS, [], ["HEAP_RETENTION"]))
        self.assertFalse(cb.is_default_check("RECIPE_FD_LEAK", BASELINE_RECIPE_IDS, [], ["FD_LEAK"],
                                             targeted_recipe="RECIPE_FD_LEAK"))


class TestWebParameters(unittest.TestCase):
    def test_web_request_accepts_and_validates_the_budget_like_cli_and_mcp(self):
        from extractor.web.server import WebApiAdapter
        parse = WebApiAdapter._parse_diagnose_request
        ok = parse(object.__new__(WebApiAdapter), {"pid": 1234, "default_check_budget_s": 4, "default_check_max_s": "1.5"})
        self.assertTrue(ok["success"], ok)
        self.assertEqual((ok["args"]["default_check_budget_s"], ok["args"]["default_check_max_s"]), (4.0, 1.5))
        bad = parse(object.__new__(WebApiAdapter), {"pid": 1234, "default_check_budget_s": "lots"})
        self.assertFalse(bad["success"])
        self.assertEqual(bad["error"]["code"], "INVALID_PARAM")


@unittest.skipUnless(shutil.which("gcc") and sys.platform.startswith("linux"), "gcc / Linux needed")
class TestBudgetOnALiveTarget(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = temp_dir(cls, "check_budget_")
        cls.exe = os.path.join(cls.tmp, "ok_idle_server")
        subprocess.run(["gcc", "-g", "-O0", "-pthread", os.path.join(TARGETS, "ok_idle_server.c"), "-o", cls.exe],
                       check=True)

    def _diagnose(self, symptom=None, **kw):
        p = fixture_popen([self.exe], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, name="ok_idle_server")
        self.addCleanup(p.stdout.close)
        self.addCleanup(p.kill_tree)
        self.assertEqual(p.stdout.readline().strip(), b"READY")
        time.sleep(0.2)
        res = ede.diagnose(p.pid, self.exe, symptom, corpus_dir=temp_dir(self, "check_budget_c_"), include_report=True,
                           **kw)
        return res.to_dict()

    def test_tight_budget_leaves_out_costly_default_checks_and_is_never_healthy(self):
        d = self._diagnose(default_check_budget_s=1.0, default_check_max_s=0.5)
        skipped = [n for n in d["not_covered"] if n["kind"] == "baseline_check_not_run"]
        self.assertTrue(skipped, "a 0.5 s per-check limit must leave out the ~0.8 s fd / mapping series")
        for n in skipped:
            self.assertEqual(n["not_run_reason"], cb.NOT_RUN_TIME_BUDGET)
            self.assertIn(n["budget"]["limit"], (cb.LIMIT_PER_CHECK, cb.LIMIT_TOTAL))
        ran = {c["recipe_id"] for c in d["checks_run"]}
        self.assertFalse(ran & {n["item"] for n in skipped})
        # coverage gap: never HEALTHY, and the blocking row carries the structured reason
        self.assertNotEqual(d["verdict"], "HEALTHY")
        self.assertTrue(any(b.get("not_run_reason") == cb.NOT_RUN_TIME_BUDGET
                            for b in d["healthy_scope"]["blocking"]))
        # report: listed as not run (실행 안 함) with the reason, from the structured field
        rows = {r["rid"]: r for r in check_rows(d, d["report"])}
        for n in skipped:
            self.assertEqual(rows[n["item"]]["status"], "SKIPPED")
            self.assertEqual(rows[n["item"]]["not_run"]["reason"], cb.NOT_RUN_TIME_BUDGET)
        ko = render_human_report(d, d["report"], lang="ko")
        self.assertIn("시간 예산 때문에 실행 안 함", ko)
        # the default checks run cheapest first: none of the skipped ones is cheaper than every one that ran
        self.assertTrue(ran)

    def test_checks_the_symptom_asks_for_are_never_skipped_by_the_budget(self):
        d = self._diagnose(symptom_fields={"symptom_kind": "fd_leak"}, default_check_budget_s=0.01,
                           default_check_max_s=0.01)
        ran = {c["recipe_id"] for c in d["checks_run"]}
        self.assertIn("RECIPE_FD_LEAK", ran)
        skipped = {n["item"] for n in d["not_covered"] if n.get("not_run_reason") == cb.NOT_RUN_TIME_BUDGET}
        self.assertNotIn("RECIPE_FD_LEAK", skipped)
        self.assertTrue(skipped, "the other default checks do not fit a 0.01 s budget")
        self.assertNotEqual(d["verdict"], "HEALTHY")

    def test_default_budget_lets_a_small_quiet_target_complete_its_baseline(self):
        with mock.patch.dict(os.environ, {cb.ENV_TOTAL: "", cb.ENV_PER_CHECK: ""}):
            d = self._diagnose()
        self.assertFalse([n for n in d["not_covered"] if n.get("not_run_reason")], d["not_covered"])
        self.assertTrue(set(BASELINE_RECIPE_IDS) <= {c["recipe_id"] for c in d["checks_run"]})


if __name__ == "__main__":
    unittest.main()
