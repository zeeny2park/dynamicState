"""Thread leak recipe (extractor/recipe_plugins/thread_leak.py): the rule and its presentation on synthetic data."""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor import report_registry as rr  # noqa: E402
from extractor.diagnostic_recipes import (  # noqa: E402
    BASELINE_RECIPE_IDS,
    DiagnosticRecipeRegistry,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
)
from extractor.human_report import render_human_report  # noqa: E402
from extractor.recipe_plugins import thread_leak as tl  # noqa: E402
from extractor.report_visuals import build_visual_summary  # noqa: E402

EVIL = "<script>alert(1)</script>"


def _data(series, window=0.8, groups=None, nproc=None, tmax=None, thread_sampling=True):
    d = {"thread_count_series": list(series),
         "thread_growth": {"new_threads": groups if groups is not None else [], "rlimit_nproc": nproc, "threads_max": tmax}}
    if thread_sampling:
        d["thread_sampling"] = {"window_sec": window, "status": "OK"}
    return d


def _rule(data):
    recipe = DiagnosticRecipeRegistry.get_recipe(tl.RECIPE_THREAD_LEAK)
    return tl.thread_leak_rule(recipe, data)


GROUP = [{"count": 7, "thread_name": "conn_worker", "function_name": "idle_worker", "source_location": "w.c:12"}]


class TestThreadLeakRule(unittest.TestCase):
    def test_registered_as_baseline_and_not_hidden_behind_collection_end(self):
        self.assertIn(tl.RECIPE_THREAD_LEAK, BASELINE_RECIPE_IDS)
        self.assertEqual(tuple(DiagnosticRecipeRegistry.get_recipe(tl.RECIPE_THREAD_LEAK).observations), (tl.OBS_THREAD_GROWTH,))

    def test_leak_rising_at_every_sample(self):
        r = _rule(_data([25, 28, 30, 31, 33], groups=GROUP))
        self.assertEqual(r.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(any("conn_worker" in f and "idle_worker" in f for f in r.supporting_facts))
        self.assertTrue(any("no thread limit was read" in f for f in r.supporting_facts))
        self.assertTrue(r.limitations)

    def test_flat_is_contradicted(self):
        self.assertEqual(_rule(_data([30, 30, 30, 30, 30])).status, RECIPE_STATUS_CONTRADICTED)

    def test_startup_then_flat_is_not_a_leak(self):
        r = _rule(_data([4, 8, 12, 12, 12]))                 # a pool that filled up inside the window
        self.assertNotEqual(r.status, RECIPE_STATUS_SUPPORTED)
        self.assertEqual(r.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    def test_growth_below_minimum_is_not_a_leak(self):
        self.assertNotEqual(_rule(_data([10, 10, 11, 11, 12])).status, RECIPE_STATUS_SUPPORTED)

    def test_churn_with_no_net_growth_is_not_a_leak(self):
        self.assertEqual(_rule(_data([20, 24, 19, 25, 20])).status, RECIPE_STATUS_CONTRADICTED)

    def test_too_few_samples_is_insufficient(self):
        for s in ([], [30], [10, 20, 30]):
            r = _rule(_data(s))
            self.assertEqual(r.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE, s)

    def test_limit_read_enables_near_limit_and_blocks_clearing(self):
        self.assertEqual(_rule(_data([95, 95, 95, 95], nproc=100)).status, RECIPE_STATUS_SUPPORTED)
        self.assertEqual(_rule(_data([85, 85, 85, 85], nproc=100)).status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(_rule(_data([30, 30, 30, 30], nproc=100, tmax=5000)).status, RECIPE_STATUS_CONTRADICTED)

    def test_new_thread_groups_use_the_per_thread_rows(self):
        rows = [{"name": "a", "appeared_at_sample": None, "top_function": "x"},
                {"name": "w", "appeared_at_sample": 3, "top_function": "run", "top_source_location": "f.c:1"},
                {"name": "w", "appeared_at_sample": 4, "top_function": "run", "top_source_location": "f.c:1"},
                {"name": "z", "appeared_at_sample": 5, "top_function": "", "top_source_location": ""}]
        g = tl.new_thread_groups(rows)
        self.assertEqual(g[0], {"count": 2, "thread_name": "w", "function_name": "run", "source_location": "f.c:1"})
        self.assertEqual(g[1], {"count": 1, "thread_name": "z"})


def _result(series, groups, nproc=None, tmax=None, window=0.8):
    d = _data(series, window, groups, nproc, tmax)
    f = {"category": tl.CATEGORY_THREAD_LEAK, "severity": "HIGH", "status": "PROBABLE_CAUSE", "description": "d",
         "recipe_ids": [tl.RECIPE_THREAD_LEAK], "subject_details": [{"kind": "thread_name", "name": "conn_worker"}], "observed": ["threads rising"]}
    check = {"recipe_id": tl.RECIPE_THREAD_LEAK, "status": "FAIL", "name": "Thread leak", "actual_observations": d}
    return {"verdict": "PROBABLE_FAULT", "confidence": 0.7, "findings": [f], "not_covered": [],
            "checks_run": [{"recipe_id": tl.RECIPE_THREAD_LEAK, "status": "FAIL"}], "target": {"pid": 1, "process_name": "p"},
            "report": {"section_d_detailed_inspection_results": {"checks": [check]}}}


class TestThreadLeakPresentation(unittest.TestCase):
    def test_registered_labels(self):
        self.assertEqual(rr.category_label(tl.CATEGORY_THREAD_LEAK), ("thread leak", "스레드 누수"))
        self.assertIsNotNone(rr.recipe_label(tl.RECIPE_THREAD_LEAK))

    def test_summary_text_and_picture_with_limit(self):
        evil = [{"count": 7, "thread_name": EVIL, "function_name": "idle_worker", "source_location": "w.c:12"}]
        res = _result([25, 28, 30, 31, 33], evil, nproc=1000)
        en = render_human_report(res, res["report"], "en")
        self.assertIn("33 at the last, over 0.8 s (+10.0/s)", en)
        self.assertIn("would reach it in about", en)                     # (1000 - 33) / 10 per second
        self.assertIn("idle_worker", en)
        self.assertIn("A thread pool that is still filling up", en)
        h = build_visual_summary(res, res["report"], "en")
        self.assertEqual(h.count('<circle class="dsv-pt"'), 5)
        self.assertNotIn(EVIL, h)
        self.assertIn("&lt;script&gt;", h)
        self.assertNotIn("<script", h)
        self.assertIsNone(re.search(r"\son[a-z]+\s*=", h))
        self.assertNotRegex(h, "[가-힣]")
        self.assertNotRegex(en, "[가-힣]")

    def test_not_observed_items_are_marked(self):
        res = _result([25, 28, 30, 31, 33], [])
        h = build_visual_summary(res, res["report"], "en")
        self.assertIn("No thread limit was read (not observed)", h)
        self.assertIn("Which threads are new was not observed", h)
        self.assertNotIn("would reach it in about", h)

    def test_korean(self):
        res = _result([25, 28, 30, 31, 33], GROUP, nproc=1000)
        ko = render_human_report(res, res["report"], "ko")
        self.assertIn("스레드 누수 [THREAD_LEAK]", ko)
        self.assertIn("idle_worker", ko)
        self.assertIn("스레드", build_visual_summary(res, res["report"], "ko"))


if __name__ == "__main__":
    unittest.main()
