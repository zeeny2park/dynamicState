"""IMP-013: tests of the benchmark machinery itself (ground-truth schema, scorer, runner).

Nothing here asserts an accuracy level of the real diagnoser: the real score lives in
benchmarks/diagnosis_accuracy/results/.  The scorer is exercised with fake diagnosers whose answers are
known to be wrong or known to claim everything.
"""

import os
import shutil
import unittest

from benchmarks.diagnosis_accuracy import run_benchmark as rb

GT = rb.load_ground_truth()
DEFECTS = [g for g in GT if g["kind"] != rb.HEALTHY_KIND]
SCORED_DEFECTS = [g for g in DEFECTS if rb.is_scored(g)]
UNSCORED = [g for g in GT if not rb.is_scored(g)]
HEALTHY = [g for g in GT if g["kind"] == rb.HEALTHY_KIND]


def _wrong_result(gt):
    """A diagnoser answer that is wrong for every target: fault verdict, unrelated category and names."""
    return {"verdict": "CONFIRMED_FAULT",
            "findings": [{"category": "NOT_A_REAL_CATEGORY", "status": "X", "subjects": ["zz_no_such_name", "nofile.c:1"]}],
            "not_covered": [],
            "collection_impact": {"capture_mode": "ZERO_STOP_LIVE_RUNTIME", "measured_stop_ms": 0.0, "zero_stop": True}}


def _everything_result(gt):
    """A diagnoser that claims every category with every name and every location of every target."""
    names = sorted({n for g in GT for c in rb.NAME_CLASSES for n in g["causes"][c]})
    locs = sorted({f"{os.path.basename(l['file'])}:{l['line']}" for g in GT for l in g["locations"]})
    cats = sorted({c for v in rb.KIND_CATEGORIES.values() for c in v})
    return {"verdict": "CONFIRMED_FAULT",
            "findings": [{"category": c, "status": "CONFIRMED_ROOT_CAUSE", "subjects": names + locs} for c in cats],
            "not_covered": [],
            "collection_impact": {"capture_mode": "ZERO_STOP_LIVE_RUNTIME", "measured_stop_ms": 0.0, "zero_stop": True}}


def _clean_result(gt):
    return {"verdict": "HEALTHY", "findings": [], "not_covered": [],
            "collection_impact": {"capture_mode": "ZERO_STOP_LIVE_RUNTIME", "measured_stop_ms": 0.0, "zero_stop": True}}


class TestGroundTruthFiles(unittest.TestCase):
    def test_every_ground_truth_file_is_well_formed(self):
        self.assertTrue(GT)
        for g in GT:
            with self.subTest(target=g["id"]):
                self.assertEqual(rb.validate_ground_truth(g), [])

    def test_ids_unique_and_match_filenames(self):
        ids = [g["id"] for g in GT]
        self.assertEqual(len(ids), len(set(ids)))
        for g in GT:
            self.assertTrue(os.path.isfile(os.path.join(rb.GT_DIR, g["id"] + ".json")))

    def test_corpus_composition_requirements(self):
        for kind in {g["kind"] for g in DEFECTS}:
            self.assertGreaterEqual(sum(1 for g in DEFECTS if g["kind"] == kind), 2, kind)
        self.assertGreaterEqual(len(HEALTHY), 5)
        self.assertGreaterEqual(sum(1 for g in GT if g["origin"] == "external_style"), 3)
        new_defects = [g for g in DEFECTS if g["origin"] != "project_fixture"]
        self.assertGreaterEqual(2 * sum(1 for g in new_defects if g["naming"] == "neutral"), len(new_defects))

    def test_scored_field_schema(self):
        for g in UNSCORED:
            self.assertIs(g["scored"], False)
            self.assertTrue(g["scored_reason"].strip())
            self.assertNotEqual(g["kind"], rb.HEALTHY_KIND)
        # long_stall (owner decision) and heap_retention (a degradation, not a defect: neither scoring fits)
        self.assertEqual({g["id"] for g in UNSCORED}, {"stall_pipe", "stall_sleep", "frag_sparse", "frag_worker"})
        self.assertEqual({g["kind"] for g in UNSCORED}, {"long_stall", "heap_retention"})
        base = UNSCORED[0]
        self.assertTrue(rb.validate_ground_truth({k: v for k, v in base.items() if k != "scored_reason"}))
        self.assertTrue(rb.validate_ground_truth(dict(base, scored="no")))
        self.assertTrue(rb.validate_ground_truth(dict(HEALTHY[0], scored=False, scored_reason="x")))

    def test_validator_rejects_broken_records(self):
        base = DEFECTS[0]
        bad_line = dict(base, locations=[dict(base["locations"][0], line=1)])
        self.assertTrue(rb.validate_ground_truth(bad_line))
        no_names = dict(base, causes={c: [] for c in rb.NAME_CLASSES})
        self.assertTrue(rb.validate_ground_truth(no_names))
        self.assertTrue(rb.validate_ground_truth(dict(base, kind="not_a_kind")))
        self.assertTrue(rb.validate_ground_truth({k: v for k, v in base.items() if k != "symptom"}))


class TestScorer(unittest.TestCase):
    def test_mapping_table_covers_every_defect_kind(self):
        self.assertEqual({g["kind"] for g in DEFECTS}, set(rb.KIND_CATEGORIES))

    def test_unscored_targets_do_not_change_totals(self):
        for fake in (_wrong_result, _everything_result, _clean_result):
            with self.subTest(fake=fake.__name__):
                full = rb.summarize([rb.score_result(g, fake(g)) for g in GT])
                scored_only = rb.summarize([rb.score_result(g, fake(g)) for g in GT if rb.is_scored(g)])
                self.assertEqual(full["overall"], scored_only["overall"])
                self.assertEqual(full["per_kind"], scored_only["per_kind"])
                self.assertEqual(full["per_origin"], scored_only["per_origin"])
                self.assertEqual(full["overall"]["defect_targets"], len(SCORED_DEFECTS))
                self.assertNotIn("long_stall", full["per_kind"])
                self.assertEqual([t["id"] for t in full["unscored"]["targets"]], [g["id"] for g in UNSCORED])
        # a fault verdict on an unscored target is reported but never a false positive nor a detection total
        row = rb.score_result(UNSCORED[0], _everything_result(UNSCORED[0]))
        self.assertFalse(row["scored"])
        self.assertEqual(row["verdict"], "CONFIRMED_FAULT")
        self.assertNotIn("false_positive", row)

    def test_unscored_rows_listed_under_separate_heading(self):
        rows = [rb.score_result(g, _clean_result(g)) for g in GT]
        report = {"rows": rows, "totals": rb.summarize(rows), "total_wall_s": 0}
        text = rb.format_table(report)
        head, _, tail = text.partition("unscored (informational")
        self.assertTrue(tail)
        for g in UNSCORED:
            self.assertNotIn(g["id"], head)
            self.assertIn(g["id"], tail)

    def test_all_wrong_answers_score_zero_detections_and_names(self):
        rows = [rb.score_result(g, _wrong_result(g)) for g in GT]
        o = rb.summarize(rows)["overall"]
        self.assertEqual(o["detected"], 0)
        self.assertEqual(o["name_full"] + o["name_partial"], 0)
        self.assertEqual(o["location_match"], 0)

    def test_claim_everything_has_fp_equal_to_healthy_count(self):
        rows = [rb.score_result(g, _everything_result(g)) for g in GT]
        o = rb.summarize(rows)["overall"]
        self.assertEqual(o["false_positives"], len(HEALTHY))
        self.assertEqual(o["cleared"] + o["not_cleared"], 0)
        self.assertEqual(o["detected"], len(SCORED_DEFECTS))  # allowed to be high: that is why FP is counted

    def test_clean_answers_clear_healthy_and_miss_defects(self):
        o = rb.summarize([rb.score_result(g, _clean_result(g)) for g in GT])["overall"]
        self.assertEqual((o["cleared"], o["false_positives"], o["detected"]), (len(HEALTHY), 0, 0))

    def test_always_healthy_diagnoser_false_clears_every_scored_defect(self):
        rows = [rb.score_result(g, _clean_result(g)) for g in GT]
        rep = rb.summarize(rows)
        o = rep["overall"]
        self.assertEqual(o["false_clears"], len(SCORED_DEFECTS))
        self.assertEqual(o["detected"], 0)
        self.assertEqual(sum(s["false_clears"] for s in rep["per_kind"].values()), len(SCORED_DEFECTS))
        by_id = {r["id"]: r for r in rows}
        self.assertTrue(all(by_id[g["id"]]["false_clear"] for g in DEFECTS))  # flagged per row, even unscored
        self.assertEqual(sum(1 for r in rep["unscored"]["targets"] if r["false_clear"]), len(UNSCORED))
        self.assertFalse(any(r.get("false_clear") for r in rows if r["kind"] == rb.HEALTHY_KIND))

    def test_existing_fakes_have_no_false_clears(self):
        for fn in (_wrong_result, _everything_result):
            o = rb.summarize([rb.score_result(g, fn(g)) for g in GT])["overall"]
            self.assertEqual(o["false_clears"], 0)

    def test_inconclusive_on_healthy_is_not_cleared_not_fp(self):
        res = dict(_clean_result(None), verdict="INCONCLUSIVE")
        row = rb.score_result(HEALTHY[0], res)
        self.assertEqual((row["cleared"], row["not_cleared"], row["false_positive"]), (False, True, False))

    def test_fault_verdict_without_matching_category_is_not_a_detection(self):
        g = DEFECTS[0]
        row = rb.score_result(g, _wrong_result(g))
        self.assertFalse(row["detected"])

    def test_names_are_exact_and_case_sensitive(self):
        g = next(x for x in DEFECTS if x["causes"]["locks"])
        cat = sorted(rb.KIND_CATEGORIES[g["kind"]])[0]
        res = _clean_result(g)
        res["findings"] = [{"category": cat, "subjects": [n.upper() for n in g["causes"]["locks"]]}]
        self.assertEqual(rb.score_result(g, res)["name_match"], "none")
        res["findings"][0]["subjects"] = [g["causes"]["locks"][0]]
        self.assertEqual(rb.score_result(g, res)["name_match"], "partial")
        res["findings"][0]["subjects"] = list(g["causes"]["locks"]) + list(g["causes"]["threads"])
        self.assertEqual(rb.score_result(g, res)["name_match"], "full")

    def test_function_only_match_is_partial(self):
        g = next(x for x in DEFECTS if x["causes"]["variables"] and x["causes"]["functions"])
        cat = sorted(rb.KIND_CATEGORIES[g["kind"]])[0]
        res = _clean_result(g)
        res["findings"] = [{"category": cat, "subjects": list(g["causes"]["functions"])}]
        row = rb.score_result(g, res)
        self.assertEqual(row["name_match"], "partial")
        self.assertEqual(row["names_by_class"]["variables"]["found"], [])

    def test_names_only_count_from_matching_category_findings(self):
        g = DEFECTS[0]
        names = [n for c in rb.NAME_CLASSES for n in g["causes"][c]]
        res = _clean_result(g)
        res["findings"] = [{"category": "NOT_A_REAL_CATEGORY", "subjects": names}]
        self.assertEqual(rb.score_result(g, res)["name_match"], "none")

    def test_location_tolerance(self):
        g = next(x for x in DEFECTS if len(x["locations"]) == 1)
        loc = g["locations"][0]
        cat = sorted(rb.KIND_CATEGORIES[g["kind"]])[0]
        base = os.path.basename(loc["file"])
        for delta in (0, rb.LINE_TOLERANCE, -rb.LINE_TOLERANCE, rb.LINE_TOLERANCE + 1, -rb.LINE_TOLERANCE - 1):
            res = _clean_result(g)
            res["findings"] = [{"category": cat, "subjects": [f"{base}:{loc['line'] + delta}"]}]
            self.assertEqual(rb.score_result(g, res)["location_match"], abs(delta) <= rb.LINE_TOLERANCE, delta)

    def test_wrong_file_same_line_is_no_location_match(self):
        g = DEFECTS[0]
        cat = sorted(rb.KIND_CATEGORIES[g["kind"]])[0]
        res = _clean_result(g)
        res["findings"] = [{"category": cat, "subjects": [f"other_file.c:{g['locations'][0]['line']}"]}]
        self.assertFalse(rb.score_result(g, res)["location_match"])

    def test_non_zero_stop_is_flagged(self):
        g = HEALTHY[0]
        res = _clean_result(g)
        res["collection_impact"] = {"capture_mode": "STOP_THE_WORLD", "measured_stop_ms": 12.0, "zero_stop": False}
        self.assertTrue(rb.score_result(g, res)["non_zero_stop"])
        self.assertFalse(rb.score_result(g, _clean_result(g))["non_zero_stop"])

    def test_error_row(self):
        row = rb.score_result(DEFECTS[0], None, "RuntimeError: boom")
        self.assertEqual(row["error"], "RuntimeError: boom")
        self.assertFalse(row["detected"])


@unittest.skipUnless(shutil.which("gcc"), "gcc not available")
class TestRunnerWithFakeDiagnosers(unittest.TestCase):
    """Full build/launch/READY/kill path on three small targets with fake diagnosers (not the real one)."""

    IDS = ("deadlock_pipeline", "ok_idle_server", "spin_flag")

    @classmethod
    def setUpClass(cls):
        cls.targets = [g for g in GT if g["id"] in cls.IDS]

    def _children_gone(self, calls):
        for pid in calls:
            self.assertFalse(os.path.exists(f"/proc/{pid}") and open(f"/proc/{pid}/stat").read().split()[2] != "Z",
                             f"target {pid} still alive")

    def test_all_wrong_fake(self):
        calls = []

        def fake(pid, image, symptom, corpus):
            calls.append(pid)
            self.assertTrue(os.path.isfile(image))
            return _wrong_result(None)

        rep = rb.run_all(self.targets, fake)
        self.assertEqual(len(calls), len(self.targets))  # exactly one call per target
        o = rep["totals"]["overall"]
        self.assertEqual((o["detected"], o["name_full"], o["name_partial"]), (0, 0, 0))
        self.assertEqual(o["errors"], 0)
        self._children_gone(calls)

    def test_claim_everything_fake(self):
        rep = rb.run_all(self.targets, lambda *a: _everything_result(None))
        o = rep["totals"]["overall"]
        self.assertEqual(o["false_positives"], sum(1 for g in self.targets if g["kind"] == rb.HEALTHY_KIND))

    def test_diagnose_exception_becomes_error_row(self):
        def boom(*a):
            raise ValueError("fake crash")
        rep = rb.run_all(self.targets[:1], boom)
        self.assertIn("ValueError", rep["rows"][0]["error"])
        self.assertEqual(rep["totals"]["overall"]["errors"], 1)

    def test_report_has_environment_and_rows(self):
        rep = rb.run_all(self.targets[:1], lambda *a: _clean_result(None))
        for key in ("commit", "arch", "kernel", "glibc", "python", "compiler"):
            self.assertTrue(rep["environment"][key], key)
        for key in ("verdict", "finding_categories", "subjects", "not_covered_kinds", "wall_s", "capture_mode",
                    "measured_stop_ms"):
            self.assertIn(key, rep["rows"][0])

    def test_symptom_passed_is_from_ground_truth(self):
        seen = {}
        rb.run_all(self.targets[:1], lambda pid, img, sym, c: seen.setdefault("s", sym) and _clean_result(None))
        self.assertEqual(seen["s"], self.targets[0]["symptom"])


if __name__ == "__main__":
    unittest.main()
