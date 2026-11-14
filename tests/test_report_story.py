"""The competing causes (inside each finding) and the time-ordered course of the diagnosis (after the checks) in the
reader-facing body of every report: Markdown, HTML and the web UI's view, from the same data (``extractor.report_story``).

Pinned: outcome words only (no figure, no score), the causes shown only when there is more than one, at most five
visible rows, the timeline in time order with the engine's own offsets, durations and observation windows, the
established section order untouched (the causes live in the findings part, the course in the checks part), the same
facts in Markdown / HTML / web view / result JSON, Korean and English.
"""
import copy
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from extractor import report_story as rs  # noqa: E402
from extractor.human_report import REPORT_SECTION_ORDER, check_rows, compose  # noqa: E402
from extractor.web.ui.view import build_view  # noqa: E402
from test_korean_report_language import _load, english_sentences  # noqa: E402
from test_report_outline import _full, _render_dict, _md_h2  # noqa: E402

_NO_FIGURE = re.compile(r"\d+\s*%|confidence|신뢰|점수|score", re.I)


def _cand(hid, title, status, rules, **kw):
    c = {"hypothesis_id": hid, "category": "MEMORY_CORRUPTION", "title": title, "domain": "MEMORY_INTEGRITY", "status": status,
         "applicable_diagnostic_rules": rules, "supporting_observations": [], "contradicting_observations": [],
         "verdict_source": {}}
    c.update(kw)
    return c


def _with_candidates(name, cands):
    d = copy.deepcopy(_full(name))
    d["report"]["section_f_competing_hypotheses"]["competing_candidates"] = cands
    return d


class TestCompetingCauses(unittest.TestCase):
    def setUp(self):
        self.base = _full("overflow_ring")
        self.rows = check_rows(self.base, self.base["report"])
        self.passed = next(r["rid"] for r in self.rows if r["status"] == "PASS")
        self.failed = next(r["rid"] for r in self.rows if r["status"] == "FAIL")

    def _causes(self, cands, lang="ko"):
        d = copy.deepcopy(self.base)
        d["report"]["section_f_competing_hypotheses"]["competing_candidates"] = cands
        return rs.competing_causes(lang, d, d["report"], check_rows(d, d["report"]))

    def test_outcome_words_and_what_decided_each(self):
        cands = [_cand("A", "Out-of-Bounds Heap Buffer Write", "CONFIRMED", [self.failed]),
                 _cand("B", "Duplicate Memory Release (Double Free)", "REFUTED", [self.passed]),
                 _cand("C", "Dangling Pointer Dereference (Use-After-Free)", "INCONCLUSIVE", ["RECIPE_NOT_A_CHECK"])]
        item = self._causes(cands)[0]
        by = {c["id"]: c for c in item["causes"]}
        self.assertEqual([by[k]["outcome_word"] for k in "ABC"], ["지지됨", "배제됨", "판단 불가"])
        self.assertEqual(by["A"]["recipe_id"], self.failed)             # decided by the check that found a problem
        self.assertEqual(by["B"]["recipe_id"], self.passed)             # ruled out by the check that passed
        self.assertEqual(by["C"]["evidence"], "관련 검사가 실행되지 않음")
        self.assertEqual(by["A"]["cause"], "힙 버퍼 범위를 넘어선 쓰기")      # plain words, not the engine's title
        self.assertEqual([c["outcome"] for c in item["causes"]], ["supported", "ruled_out", "undecided"])
        en = self._causes(cands, "en")[0]["causes"]
        self.assertEqual([c["outcome_word"] for c in en], ["supported", "ruled out", "undecided"])
        self.assertEqual(en[2]["evidence"], "the related check was not run")

    def test_only_with_more_than_one_candidate(self):
        self.assertEqual(self._causes([_cand("A", "Out-of-Bounds Heap Buffer Write", "CONFIRMED", [self.failed])]), [])
        self.assertEqual(self._causes([]), [])

    def test_a_second_finding_with_the_same_causes_points_to_the_first(self):
        d = copy.deepcopy(self.base)
        d["findings"].append(copy.deepcopy(d["findings"][0]))
        d["report"]["section_f_competing_hypotheses"]["competing_candidates"] = [
            _cand("A", "Out-of-Bounds Heap Buffer Write", "CONFIRMED", [self.failed]),
            _cand("B", "Duplicate Memory Release (Double Free)", "REFUTED", [self.passed])]
        items = rs.competing_causes("ko", d, d["report"], check_rows(d, d["report"]))
        self.assertEqual([(i["finding"], i["same_as"]) for i in items], [(1, None), (2, 1)])
        self.assertEqual(items[1]["causes"], [])
        self.assertIn("발견 1과 같은 원인", "\n".join(rs.competing_markdown("ko", items[1])))

    def test_at_most_five_rows_visible_the_rest_behind_a_disclosure(self):
        cands = [_cand(f"H{n}", "Out-of-Bounds Heap Buffer Write", "INCONCLUSIVE", []) for n in range(8)]
        item = self._causes(cands)[0]
        h = rs.competing_html("ko", item, 1)
        head, _, rest = h.partition('<details class="collapsible collapsible-plain dsv-more">')
        self.assertEqual(head.count("<tr data-outcome"), 5)
        self.assertEqual(rest.count("<tr data-outcome"), 3)
        self.assertIn("원인 3개 더 보기", rest)

    def test_no_figure_or_score_in_the_reader_facing_text(self):
        cands = [_cand("A", "Out-of-Bounds Heap Buffer Write", "CONFIRMED", [self.failed], confidence=0.85),
                 _cand("B", "Duplicate Memory Release (Double Free)", "REFUTED", [self.passed], confidence=0.1)]
        item = self._causes(cands)[0]
        text = "\n".join(rs.competing_markdown("ko", item)) + rs.competing_html("ko", item, 1)
        self.assertIsNone(_NO_FIGURE.search(re.sub(r"<[^>]+>", " ", text)), text)
        self.assertNotIn("confidence", str(item["causes"]))


class TestReports(unittest.TestCase):
    def test_causes_are_in_the_finding_in_every_output_and_language(self):
        for lang, head, words in (("ko", "검토한 다른 원인", ("지지됨", "배제됨", "판단 불가")),
                                  ("en", "Other causes considered", ("supported", "ruled out", "undecided"))):
            r = _render_dict(_full("overflow_ring"), lang)
            md, html = r["report_markdown"], r["report_html"]
            f0, f1 = md.index("\n## "), md.index("\n## 5") if "\n## 5" in md else len(md)
            self.assertEqual(md.count(f"**{head}**"), 1)
            findings_part = md[md.index("\n## 4"):md.index("\n## 5")]
            self.assertIn(f"**{head}**", findings_part)            # inside the findings section, not a new section
            self.assertEqual(html.count('class="dsv-causes"'), 1)
            self.assertIn(head, html[html.index('id="dsv-findings"'):html.index('id="dsv-checks"')])
            self.assertEqual(len(r["competing_causes"]), 1)
            self.assertTrue(r["competing_causes"][0]["causes"])
            if lang == "ko":
                self.assertEqual(english_sentences(md.split("\n## 4")[1].split("\n## 5")[0]), [])
            self.assertTrue(any(w in md for w in words))

    def test_section_order_is_unchanged(self):
        self.assertEqual(REPORT_SECTION_ORDER, ("conclusion", "tiles", "target", "profile", "findings", "checks",
                                                "not_examined", "next", "hypothesis", "method", "reproducibility", "reference"))
        for lang in ("ko", "en"):
            r = _render_dict(_full("overflow_ring"), lang)
            heads = _md_h2(r["report_markdown"])
            self.assertEqual(len(heads), len(set(heads)))
            html = r["report_html"]
            ids = [html.index(f'id="{i}"') for i in ("dsv-findings", "dsv-checks", "sec-not-examined", "sec-next")]
            self.assertEqual(ids, sorted(ids))

    def test_the_course_is_after_the_checks_in_time_order_with_engine_times(self):
        for name in ("deadlock_circular", "leak_lru_cache", "overflow_ring", "ok_idle_server"):
            for lang, head in (("ko", "### 진행 순서"), ("en", "### Course of the diagnosis")):
                r = _render_dict(_load(name), lang)
                md, tl = r["report_markdown"], r["investigation_timeline"]
                self.assertEqual(md.count(head), 1, (name, lang))
                checks_at = md.index("\n## 5" if "\n## 5" in md else "\n## 4")
                self.assertGreater(md.index(head), checks_at)
                self.assertLess(md.index(head), md.index("\n## ", md.index(head)))     # still inside the checks section
                kinds = [s["kind"] for s in tl["steps"]]
                self.assertEqual(kinds[0], "symptom")
                self.assertEqual(kinds[-1], "verdict")
                self.assertTrue(tl["timed"])
                ts = [s["t"] for s in tl["steps"]]
                self.assertEqual(ts, sorted(ts), (name, lang))
                self.assertEqual(r["verdict"], tl["steps"][-1]["verdict"])
                self.assertEqual(r["html_timeline_ok"] if False else r["report_html"].count('id="dsv-timeline"'), 1)

    def test_a_growth_check_shows_its_observation_window(self):
        r = _render_dict(_load("leak_lru_cache"), "ko")
        steps = [s for s in r["investigation_timeline"]["steps"] if s.get("window")]
        self.assertTrue(steps)
        self.assertTrue(all(s["window"]["seconds"] > 0 for s in steps))
        self.assertRegex(r["report_markdown"], r"관측 구간 [\d.]+초")

    def test_more_than_eight_steps_fold_into_one_line_with_a_disclosure(self):
        r = _render_dict(_load("leak_lru_cache"), "ko")
        tl = r["investigation_timeline"]
        self.assertTrue(tl["folded"])
        self.assertLessEqual(len(tl["steps"]), rs.MAX_TIMELINE_STEPS + 1)
        group = next(s for s in tl["steps"] if s["kind"] == "group")
        self.assertGreaterEqual(len(group["items"]), 2)
        html = r["report_html"]
        self.assertIn('<details class="collapsible collapsible-plain"><summary>' + group["text"].replace("&", "&amp;"), html)
        # a short course shows every step
        small = _render_dict(_load("request_threads"), "ko")["investigation_timeline"]
        self.assertFalse(small["folded"])

    def test_no_figure_or_score_in_the_course(self):
        for lang in ("ko", "en"):
            r = _render_dict(_load("deadlock_circular"), lang)
            text = "\n".join(rs.timeline_markdown(lang, r["investigation_timeline"]))
            self.assertIsNone(_NO_FIGURE.search(text), text)

    def test_korean_text_has_no_untranslated_engine_sentence(self):
        for name in ("deadlock_circular", "leak_lru_cache", "overflow_ring", "mapgrow_slabs", "spin_flag"):
            r = _render_dict(_load(name), "ko")
            self.assertEqual(english_sentences("\n".join(rs.timeline_markdown("ko", r["investigation_timeline"]))), [], name)

    def test_web_view_carries_the_same_two_parts(self):
        d = _full("overflow_ring")
        for lang in ("ko", "en"):
            view = build_view(d, lang)
            comp = compose(d, d["report"], lang)
            self.assertEqual(view["timeline_html"], rs.timeline_html(lang, comp["timeline"]))
            self.assertIn('id="dsv-timeline"', view["timeline_html"])
            self.assertIn('class="dsv-causes"', view["findings"][0]["body_html"])
            self.assertIn(rs._t(lang, "cc_head"), view["findings"][0]["body_html"])

    def test_html_uses_theme_classes_and_no_colour_values(self):
        r = _render_dict(_full("overflow_ring"), "ko")
        frag = re.findall(r'(?s)<div class="dsv-causes".*?</table></div>|<div class="dsv-timeline".*?</ol>', r["report_html"])
        self.assertTrue(frag)
        for f in frag:
            self.assertIsNone(re.search(r"#[0-9a-fA-F]{3,6}\b|rgb\(|hsl\(|style=", f), f)


if __name__ == "__main__":
    unittest.main()
