"""A Korean report must not contain English sentences written by the engine.

Fixtures (``tests/fixtures/ko_report/*.json.gz``) are real ``diagnose()`` results of the diagnosis-accuracy benchmark
targets on AArch64 glibc (one per defect kind plus healthy and inconclusive controls), trimmed of bulk that no
presentation reads.  Each is rendered with ``export_incident_report(language="ko")`` (diagnose() is replaced by the saved
result) and three parts of the body are checked: the plain-language summary, the Markdown incident report and the
HTML visual part (headline, finding cards with pictures, check list).

What the detector exempts (an English *sentence* is a run of at least ``MIN_WORDS`` plain ASCII words):
  * inline code: text in backticks (Markdown) or ``<code>`` (HTML) - symbol names, paths, addresses, flags;
  * ``<script>`` / ``<style>`` and every HTML tag and attribute;
  * any token that is not a plain lower- or mixed-case ASCII word: identifiers with ``_`` / ``.`` / ``/`` / digits /
    ``:``, hexadecimal and numbers, ALL-CAPS tokens (status words, recipe ids, acronyms such as ASan, RSS, tid);
  * words shorter than two letters.
A run of fewer than ``MIN_WORDS`` words (``tcache bin``, ``struct node``) is a technical term, not a sentence.

Known gap, not checked here: the collapsed "detailed report (sections A-I)" block of the HTML report
(``DiagnosticReport.to_html``) is an English engineering appendix with raw record dumps; it has no localisation yet.
"""
import gzip
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import extractor.expert_diagnostic_engine as ede  # noqa: E402
from extractor.human_report import ko_text  # noqa: E402
from extractor.incident_report import export_incident_report  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures", "ko_report")
MIN_WORDS = 3
_WORD = re.compile(r"[A-Za-z][A-Za-z'\-]+")


def _plain_text(html_or_md: str) -> str:
    s = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html_or_md)
    s = re.sub(r"(?is)<code\b.*?</code>", " ", s)
    s = re.sub(r"(?is)<svg\b.*?</svg>", lambda m: " ".join(re.findall(r">([^<>]+)<", m.group(0))), s)
    s = re.sub(r"(?i)<br\s*/?>|</(p|li|div|h\d|tr|summary|small|b|strong|span|td|th|dd|dt)>", "\n", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    s = s.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("&quot;", '"').replace("&#x27;", "'")
    return re.sub(r"`[^`]*`", " ", s)


def english_sentences(text: str, min_words: int = MIN_WORDS):
    """Runs of at least ``min_words`` plain English words in ``text`` (see the module docstring for the exemptions)."""
    found = []
    for line in _plain_text(text).splitlines():
        run = []
        for tok in line.split():
            core = tok.strip("()[]{}\"'.,;:!?*|")
            word = bool(_WORD.fullmatch(core)) and not core.isupper() and len(core) >= 2
            if word:
                run.append(core)
                continue
            if len(run) >= min_words:
                found.append(" ".join(run))
            run = []
        if len(run) >= min_words:
            found.append(" ".join(run))
    return found


def _load(name):
    with gzip.open(os.path.join(FIXTURES, name + ".json.gz"), "rt", encoding="utf-8") as f:
        return json.load(f)


class _Saved:
    def __init__(self, d):
        self.d = d

    def to_dict(self):
        return json.loads(json.dumps(self.d))


def _render(name, lang):
    saved = _load(name)
    original = ede.diagnose
    ede.diagnose = lambda *a, **k: _Saved(saved)
    try:
        out = export_incident_report(pid=1234, language=lang)
    finally:
        ede.diagnose = original
    html = out["report_html"]
    body = html[html.find("<body>"):]
    visual = body[:body.find('<details class="dsv-detail"')]
    return out, visual


NAMES = sorted(f[:-8] for f in os.listdir(FIXTURES) if f.endswith(".json.gz"))


class TestDetector(unittest.TestCase):
    def test_flags_sentences_and_exempts_identifiers(self):
        self.assertTrue(english_sentences("the pointer was freed twice"))
        self.assertTrue(english_sentences("<p>Wait-for graph is complete and acyclic</p>"))
        self.assertEqual(english_sentences("`the pointer was freed twice` and <code>some code here now</code>"), [])
        self.assertEqual(english_sentences("g_sessions[1] at 0xac82cace52d0 in /tmp/a_b.c:12 RECIPE_DOUBLE_FREE ASan"), [])
        self.assertEqual(english_sentences("tcache bin 2 해제된 블록 struct node"), [])      # a technical term
        self.assertEqual(english_sentences("<style>.a b c d e f</style><script>if a b c d</script>"), [])


class TestKoreanReportHasNoEnglishSentences(unittest.TestCase):
    def test_fixture_set_covers_the_defect_kinds_and_controls(self):
        for n in ("overflow_ring", "uaf_jobq", "dfree_outbox", "leak_lru_cache", "deadlock_circular", "spin_flag",
                  "mapgrow_slabs", "orphan_lock_cfg", "self_deadlock_state", "ok_scenario_a", "ok_idle_server"):
            self.assertIn(n, NAMES)

    def test_no_english_sentence_in_the_body(self):
        problems = []
        for name in NAMES:
            out, visual = _render(name, "ko")
            for part, text in (("summary", out["human_summary"]), ("markdown", out["report_markdown"]),
                               ("visual", visual)):
                for s in english_sentences(text):
                    problems.append(f"{name} [{part}]: {s}")
        self.assertEqual(problems, [], "English sentences in a Korean report:\n" + "\n".join(sorted(set(problems))[:40]))

    def test_english_report_is_still_english(self):
        out, _ = _render("overflow_ring", "en")
        self.assertIn("is a heap buffer with 72 usable bytes", out["human_summary"])
        self.assertIn("## 1. Target Identity & Zero-Stop Telemetry", out["report_markdown"])

    def test_verdicts_are_the_saved_ones(self):
        for name in NAMES:
            saved = _load(name)
            for lang in ("en", "ko"):
                out, _ = _render(name, lang)
                self.assertEqual(out["diagnosis"]["verdict"], saved["verdict"])


class TestKoText(unittest.TestCase):
    def test_translates_known_shapes_and_leaves_the_rest(self):
        self.assertEqual(ko_text("Lock ownership verified clean", 0), "Lock ownership verified clean")
        self.assertEqual(ko_text("Lock ownership verified clean", 1), "락 소유 관계에 이상이 없음을 확인")
        self.assertEqual(ko_text("something the table does not know", 1), "something the table does not know")
        self.assertIn("2.48초", ko_text("dangling pointer: cur points to freed chunk 0x2d0 (size 64, fastbin 2 (chunk size 64) of "
                                       "arena 0), stable over 2.48 s; no write into it was observed (candidate: a use is not "
                                       "proven)", 1))

    def test_fragments_keep_numbers_and_identifiers(self):
        s = ko_text("3 mutex(es) inspected in 2 samples: no thread waits for a mutex it owns itself", 1)
        self.assertIn("뮤텍스 3개", s)
        self.assertIn("샘플 2회", s)


if __name__ == "__main__":
    unittest.main()
