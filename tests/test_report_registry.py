"""A recipe definition file can register how its diagnosis is presented (extractor/report_registry.py)."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor import report_registry as rr  # noqa: E402
from extractor.healthy_verdict import _registered_scope_label  # noqa: E402
from extractor.human_report import render_human_report  # noqa: E402
from extractor.report_visuals import build_visual_summary, code, esc  # noqa: E402

EVIL = "<script>alert(1)</script>"
CAT, RID = "TEST_ONLY_CATEGORY", "RECIPE_TEST_ONLY"


def _result(category=CAT, fu=None):
    f = {"category": category, "severity": "HIGH", "status": "PROBABLE_CAUSE", "description": "d",
         "recipe_ids": [RID], "subject_details": [{"kind": "resource", "name": "thing"}], "observed": ["seen"]}
    check = {"recipe_id": RID, "status": "FAIL", "name": "Test only", "actual_observations": {"fd_usage": fu} if fu else {}}
    return {"verdict": "PROBABLE_FAULT", "confidence": 0.7, "findings": [f], "not_covered": [],
            "checks_run": [{"recipe_id": RID, "status": "FAIL"}], "target": {"pid": 1, "process_name": "p"},
            "report": {"section_d_detailed_inspection_results": {"checks": [check]}}}


class TestReportRegistry(unittest.TestCase):
    def setUp(self):
        self._saved = [dict(d) for d in (rr.CATEGORY_LABELS, rr.RECIPE_LABELS, rr.FINDING_TEXT, rr.FINDING_VIZ)]

    def tearDown(self):
        for d, saved in zip((rr.CATEGORY_LABELS, rr.RECIPE_LABELS, rr.FINDING_TEXT, rr.FINDING_VIZ), self._saved):
            d.clear()
            d.update(saved)

    def test_unregistered_category_uses_generic_presentation(self):
        res = _result()
        self.assertIn("`TEST_ONLY_CATEGORY`", render_human_report(res, res["report"], "en"))
        h = build_visual_summary(res, res["report"], "en")
        self.assertIn("Finding 1: TEST_ONLY_CATEGORY", h)
        self.assertIn("Test only", h)                                   # check name from the record

    def test_registered_presentation_is_used_in_summary_checklist_and_picture(self):
        rr.register_category(CAT, "a test problem", "시험용 문제")
        rr.register_recipe_label(RID, "OTHER", "Test check", "시험 검사", "looks for the test problem", "시험용 문제를 찾음")
        rr.register_finding_text(CAT, lambda ctx, f, report: {"lines": [("custom line", "맞춤 문장")[ctx.i]]})
        rr.register_finding_viz(CAT, lambda lx, f, report, uid: f'<p class="x-viz">{esc(f["observed"][0])} {code(uid)}</p>')
        res = _result()
        ko = render_human_report(res, res["report"], "ko")
        self.assertIn("시험용 문제 [TEST_ONLY_CATEGORY]", ko)
        self.assertIn("맞춤 문장", ko)
        h = build_visual_summary(res, res["report"], "ko")
        self.assertIn("시험용 문제", h)
        self.assertIn("시험 검사", h)
        self.assertIn("시험용 문제를 찾음", h)
        self.assertIn('<p class="x-viz">seen <code>f1</code></p>', h)
        self.assertEqual(_registered_scope_label(RID), ("looks for the test problem", "시험용 문제를 찾음"))

    def test_a_failing_renderer_falls_back(self):
        def boom(*a, **k):
            raise RuntimeError("x")
        rr.register_finding_text(CAT, boom)
        rr.register_finding_viz(CAT, boom)
        res = _result()
        self.assertIn("`TEST_ONLY_CATEGORY`", render_human_report(res, res["report"], "en"))
        self.assertIn("Finding 1", build_visual_summary(res, res["report"], "en"))
        rr.register_finding_text(CAT, lambda *a: {"lines": []})         # nothing to say -> generic text
        self.assertIn("`thing`", render_human_report(res, res["report"], "en"))

    def test_group_is_validated(self):
        with self.assertRaises(ValueError):
            rr.register_recipe_label(RID, "NOPE", "a", "b", "c", "d")

    def test_fd_leak_registers_itself_from_its_own_file(self):
        self.assertEqual(rr.category_label("FD_LEAK"), ("file descriptor leak", "파일 디스크립터 누수"))
        self.assertIsNotNone(rr.recipe_label("RECIPE_FD_LEAK"))
        fu = {"samples": [{"t_s": 0.0, "open_fds": 50}, {"t_s": 0.4, "open_fds": 58}, {"t_s": 0.8, "open_fds": 66}],
              "fd_limit": 1024, "new_fd_targets": [{"fd_target": EVIL, "count": 16}], "open_fds_by_kind": {EVIL: 64, "file": 2}}
        res = _result("FD_LEAK", fu)
        res["findings"][0]["recipe_ids"] = ["RECIPE_FD_LEAK"]
        res["report"]["section_d_detailed_inspection_results"]["checks"][0]["recipe_id"] = "RECIPE_FD_LEAK"
        en = render_human_report(res, res["report"], "en")
        self.assertIn("rose from 50 to 66 in 0.8 s (20.0/s)", en)
        self.assertIn("reached in about 48 s", en)                       # (1024 - 66) / 20 per second
        h = build_visual_summary(res, res["report"], "en")
        self.assertEqual(h.count('<circle class="dsv-pt"'), 3)
        self.assertNotIn(EVIL, h)
        self.assertIn("&lt;script&gt;", h)
        self.assertNotIn("<script", h)
        self.assertNotRegex(build_visual_summary(res, res["report"], "en"), "[가-힣]")


if __name__ == "__main__":
    unittest.main()
