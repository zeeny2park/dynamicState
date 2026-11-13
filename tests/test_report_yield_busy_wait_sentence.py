"""A yield-polling busy wait judged from dispatch counts must not be described with its (host-load dependent) CPU share."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor.human_report import _Ctx, _render_thread  # noqa: E402
from tests.test_korean_report_language import english_sentences  # noqa: E402


def _report(**row):
    r = {"name": "spinner", "tid": 77, "top_function": "poll_flag", "top_source_location": "spin.c:12",
         "runnable_fraction": 1.0, "cpu_share_pct": 0.0, "cpu_share": 0.0}
    r.update(row)
    return {"section_d_detailed_inspection_results": {"checks": [
        {"recipe_id": "R1", "actual_observations": {"runaway_threads": [r]}}]}}


def _render(lang, **row):
    out = _render_thread(_Ctx(lang), {"recipe_ids": ["R1"], "subjects": []}, _report(**row))
    return "\n".join(out["lines"])


DISP = dict(judgement_basis="schedstat_runnable_fraction_dispatches", cpu_dispatches=1432)


class YieldBusyWaitSentence(unittest.TestCase):
    def test_english_states_what_was_observed_not_a_cpu_share(self):
        for exact in (False, True):
            extra = dict(DISP, top_source_line_exact=exact, top_source_text="while (!flag) sched_yield();")
            text = _render("en", **extra)
            self.assertNotIn("CPU 0", text)
            self.assertNotIn("used 0", text)
            self.assertIn("runnable for 100% of the window", text)
            self.assertIn("put on a CPU 1432 times", text)
            self.assertIn("never blocked", text)
            self.assertIn("top frame stayed the same", text)
            self.assertIn("poll_flag", text)

    def test_korean_has_no_english_sentence_and_no_cpu_share(self):
        for exact in (False, True):
            text = _render("ko", **dict(DISP, top_source_line_exact=exact, top_source_text="while (!flag) sched_yield();"))
            self.assertIn("1432", text)
            self.assertNotIn("0%", text.replace("100%", ""))
            self.assertEqual(english_sentences(text), [])

    def test_other_bases_keep_their_sentence(self):
        text = _render("en", judgement_basis="schedstat_runnable_fraction", cpu_share_pct=97.0)
        self.assertIn("used 97.0% of a CPU", text)


if __name__ == "__main__":
    unittest.main()
