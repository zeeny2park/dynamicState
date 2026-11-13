"""The common outline of every report (human summary, Markdown incident report, HTML incident report).

Rendered from the saved diagnose results in ``tests/fixtures/ko_report`` (every defect kind, two healthy targets,
an inconclusive one) and, for the detailed records, from two full saved reports in ``tests/fixtures/report_detail``
(sections A-I with the competing hypotheses and the evidence index that the ko_report fixtures leave out).

What is pinned:
* the same sections in the same order in Markdown and HTML, in English and Korean, for every verdict kind;
* one numbering scheme, one ``#`` title, no skipped heading level;
* a check id never stands alone: in the reader-facing text it is in code font, after the check's name;
* the check counts are the same in the hero, the scope sentence, the check list and the Markdown groups;
* a healthy report stays short (bound below);
* the detailed records are attached per part: a finding's / a check's block holds only its own records, nothing of
  ``DiagnosticReport.to_html`` is lost, and no single block holds the whole report.
"""
import copy
import gzip
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

import extractor.expert_diagnostic_engine as ede  # noqa: E402
from extractor.diagnostic_report import DiagnosticReport  # noqa: E402
from extractor.human_report import check_counts, check_rows, compose, render_human_report  # noqa: E402
from extractor.incident_report import export_incident_report  # noqa: E402
from test_korean_report_language import NAMES, _load, _Saved, without_detail  # noqa: E402

DETAIL_FIXTURES = os.path.join(ROOT, "tests", "fixtures", "report_detail")
KINDS = {"CONFIRMED_FAULT": "overflow_ring", "PROBABLE_FAULT": "uaf_jobq", "DEGRADED": "lock_convoy",
         "HEALTHY": "ok_idle_server", "INCONCLUSIVE": "request_threads"}
DETAIL_BODY = re.compile(r'(?s)<div class="dsv-detail-body[^"]*"[^>]*>(.*?)</div><!--/dsv-detail-body-->')


def _render_dict(d, lang, **kw):
    original = ede.diagnose
    ede.diagnose = lambda *a, **k: _Saved(d)
    try:
        return export_incident_report(pid=1234, language=lang, **kw)
    finally:
        ede.diagnose = original


def _full(name):
    """The saved diagnose result of ``name`` with its full detailed report (sections A-I) instead of the trimmed one."""
    d = copy.deepcopy(_load(name))
    with gzip.open(os.path.join(DETAIL_FIXTURES, name + ".report.json.gz"), "rt", encoding="utf-8") as f:
        d["report"] = json.load(f)
    return d


def _md_h2(md):
    return re.findall(r"^## (.+)$", md, re.M)


def _html_h2(html):
    """Section titles of the HTML report: the banner's (visually hidden) title and each card's title."""
    return [re.sub(r"<[^>]+>", "", h) for h in re.findall(r'<h2 class="(?:sr-only|card-title)">(.*?)</h2>', without_detail(html))]


def _titles(md_h2):
    return [h.split(". ", 1)[1] for h in md_h2]


def _text(html):
    """Visible text of the reader-facing HTML (detail bodies, style, tags removed; <code> kept as backticks)."""
    s = without_detail(html)
    s = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", s)
    s = re.sub(r"(?is)<code>(.*?)</code>", lambda m: "`" + m.group(1) + "`", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    return s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#x27;", "'")


class TestOutline(unittest.TestCase):
    def test_fixtures_cover_every_verdict_kind(self):
        for v, name in KINDS.items():
            self.assertEqual(_load(name)["verdict"], v, name)

    def test_same_sections_in_markdown_and_html_and_in_both_languages(self):
        for name in NAMES:
            keys = {}
            for lang in ("en", "ko"):
                out = _render_dict(_load(name), lang)
                md, html = _md_h2(out["report_markdown"]), _html_h2(out["report_html"])
                self.assertEqual(_titles(md), html, (name, lang))     # the HTML cards carry no numbers
                # the summary is the same outline without the incident-only parts (hypothesis, reproducibility)
                titles = lambda hs: [h.split(". ", 1)[1] for h in hs]  # noqa: E731
                incident_only = ("Reproducibility", "재현 정보", "The hypothesis you asked to check", "요청한 가설 검증")
                self.assertEqual(titles(_md_h2(out["human_summary"])),
                                 [t for t in titles(md) if t not in incident_only], (name, lang))
                comp = compose(_load(name), _load(name)["report"], lang)
                keys[lang] = [s["key"] for s in comp["sections"]]
            self.assertEqual(keys["en"], keys["ko"], name)

    def test_each_verdict_kind_states_the_verdict_in_words_first(self):
        words = {"CONFIRMED_FAULT": ("confirmed fault", "확인된 결함"), "PROBABLE_FAULT": ("probable fault", "결함 추정"),
                 "DEGRADED": ("degraded, not a fault", "성능 저하 (결함 아님)"),
                 "HEALTHY": ("healthy within the checked scope", "점검한 범위 안에서 정상"),
                 "INCONCLUSIVE": ("could not decide", "판단 불가")}
        for v, name in KINDS.items():
            for i, lang in enumerate(("en", "ko")):
                md = _render_dict(_load(name), lang)["report_markdown"]
                first = md.split("## 1.")[1].split("\n## ")[0].strip().splitlines()
                self.assertTrue(first[2].startswith("**"), (v, lang))
                self.assertIn(words[v][i], first[2], (v, lang))
                self.assertIn(f"`{v}`", first[2])
                # the findings section exists exactly when there is a finding (no section only to say "nothing")
                self.assertEqual(any("발견된 문제" in h or "What was found" in h for h in _md_h2(md)),
                                 bool(_load(name)["findings"]), (v, lang))

    def test_headings_are_numbered_once_and_correctly_nested(self):
        for name in NAMES:
            for lang in ("en", "ko"):
                out = _render_dict(_load(name), lang)
                md = out["report_markdown"]
                levels = [len(m) for m in re.findall(r"^(#+) ", re.sub(r"(?s)```.*?```", "", md), re.M)]
                self.assertEqual(levels[0], 1)
                self.assertEqual(levels.count(1), 1, (name, lang))
                for a, b in zip(levels, levels[1:]):
                    self.assertLessEqual(b - a, 1, (name, lang, levels))
                nums = [int(h.split(".")[0]) for h in _md_h2(md)]
                self.assertEqual(nums, list(range(1, len(nums) + 1)), (name, lang))
                self.assertFalse(re.search(r"^#{3,} \d+\.", md, re.M), "a second numbering scheme")
                html = without_detail(out["report_html"])
                hl = [int(x) for x in re.findall(r"<h([1-6])\b", re.sub(r"(?is)<style\b.*?</style>", "", html))]
                self.assertEqual(hl.count(1), 1)
                for a, b in zip(hl, hl[1:]):
                    self.assertLessEqual(b - a, 1, (name, lang, hl))

    def test_ids_never_stand_alone_in_the_reader_facing_text(self):
        internal = ("CONFIRMED_ROOT_CAUSE", "PROBABLE_CAUSE", "diagnosing_process_cpu", "Health Score", "건강 점수",
                    "신뢰도", "Confidence")
        for name in NAMES:
            for lang in ("en", "ko"):
                out = _render_dict(_load(name), lang)
                md = out["report_markdown"]
                reader_md = md.split("### Where the detail is")[0].split("### 상세 기록의 위치")[0]
                for text in (reader_md, _text(out["report_html"])):
                    for x in internal:
                        self.assertNotIn(x, text, (name, lang, x))
                for m in re.finditer(r"RECIPE_[A-Z0-9_]+", reader_md):
                    before = reader_md[max(0, m.start() - 3):m.start()]
                    self.assertIn(before, (" (`", "'(`"), (name, lang, reader_md[max(0, m.start() - 60):m.end() + 2]))
                text = _text(out["report_html"])
                for m in re.finditer(r"RECIPE_[A-Z0-9_]+", text):
                    self.assertEqual(text[m.start() - 1], "`", (name, lang, text[max(0, m.start() - 60):m.end()]))

    def test_check_counts_agree_in_every_view(self):
        for name in NAMES:
            d = _load(name)
            rows = check_rows(d, d["report"])
            c = check_counts(rows)
            self.assertEqual(c["run"], len(d["checks_run"]), name)          # "run" is what the result says ran
            self.assertEqual(c["run"] + c["not_run"], len(rows))
            for lang in ("en", "ko"):
                out = _render_dict(d, lang)
                html, md = out["report_html"], out["report_markdown"]
                tile = re.search(r'<div class="card tile"><div class="k">[^<]+</div><div class="v">(\d+)</div>', html)
                self.assertEqual(int(tile.group(1)), c["run"], (name, lang))
                for text in (md, _text(html)):
                    sent = re.search(r"(\d+) checks ran: (\d+) found a problem, (\d+) could not judge and (\d+) passed"
                                     if lang == "en" else
                                     r"검사 (\d+)개를 실행했습니다. 이상 발견 (\d+)개, 판단 불가 (\d+)개, 통과 (\d+)개", text)
                    self.assertEqual(tuple(int(x) for x in sent.groups()),
                                     (c["run"], c["found"], c["undecided"], c["clean"]), (name, lang))
                for g, n in (("FAIL", c["found"]), ("INCONCLUSIVE", c["undecided"]), ("PASS", c["clean"]),
                             ("SKIPPED", c["not_run"])):
                    self.assertEqual(html.count(f'<details class="dsv-ck dsv-s-{g}" data-status="{g}"'), n, (name, g))
                groups = {int(x) for x in re.findall(r"^### [^\n(]+\((\d+)\)$", md, re.M)}
                self.assertTrue({x for x in (c["found"], c["undecided"], c["clean"], c["not_run"]) if x} <= groups)

    def test_healthy_report_is_short(self):
        # Bound: the healthy Markdown was 120 lines / about 1000 words before (each check listed three times).  Now
        # each thing is said once: the conclusion with the four figures, the target card (7 lines), the 30 checks
        # named once in grouped lines, what was not examined, one advice line, the method block, the short
        # reproducibility facts (the per-check table is in the HTML detail and the opt-in appendix) and the glossary:
        # the whole body <= 100 lines and <= 800 words in Korean / 950 in English (English runs ~20 % more words).
        for name in ("ok_idle_server", "ok_scenario_a"):
            for lang, words in (("ko", 800), ("en", 950)):
                md = _render_dict(_load(name), lang)["report_markdown"]
                self.assertLessEqual(len(md.splitlines()), 100, (name, lang))
                self.assertLessEqual(len(md.split()), words, (name, lang))

    def test_healthy_report_says_what_the_verdict_covers_and_what_was_not_checked(self):
        d = _load("ok_idle_server")
        for lang, covers, outside in (("en", "What the healthy verdict covers", "data races"),
                                      ("ko", "정상 판정이 다루는 범위", "데이터 레이스")):
            md = _render_dict(d, lang)["report_markdown"]
            concl = md.split("## 1.")[1].split("\n## ")[0]
            self.assertIn(outside, concl)                      # named in the conclusion (docs/HEALTHY_VERDICT.md)
            checks = re.split(r"(?m)^## \d+\. (?:Checks|검사)$", md)[1].split("\n## ")[0]
            self.assertIn(covers, checks)                      # stated with the checks it rests on
            not_examined = re.split(r"(?m)^## \d+\. (?:Not examined|확인하지 못한 것)$", md)[1].split("\n## ")[0]
            self.assertIn(outside, not_examined)

    def test_symptom_not_understood_note_is_in_the_conclusion(self):
        d = copy.deepcopy(_load("overflow_ring"))
        d["symptom_interpretation"] = {"understood": False, "reason": "no_match"}
        for lang, word in (("en", "not understood specifically"), ("ko", "구체적으로 이해하지 못했습니다")):
            out = _render_dict(d, lang)
            self.assertIn(word, out["report_markdown"].split("## 2.")[0])
            self.assertIn(word, _text(out["report_html"]))

    def test_numbers_have_units_and_no_false_precision(self):
        out = _render_dict(_load("overflow_ring"), "en")
        ci = _load("overflow_ring")["collection_impact"]
        md = out["report_markdown"]
        self.assertIn(f"{ci['bytes_read'] / 1024:.0f} KB", md)
        self.assertIn(f"{ci['wall_clock_ms'] / 1000:.1f} s", md)
        self.assertNotIn(str(ci["wall_clock_ms"]), md)
        self.assertNotRegex(md, r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+")    # no raw ISO timestamps with microseconds


class TestDetailPerPart(unittest.TestCase):
    @staticmethod
    def _blocks(html):
        return {m.group(1): m.group(2) for m in re.finditer(
            r'(?s)<details class="collapsible dsv-detail" id="([^"]+)"><summary>.*?</summary><div class="dsv-detail-body[^"]*"[^>]*>(.*?)'
            r'</div><!--/dsv-detail-body-->', html)}

    def test_nothing_of_the_detailed_report_is_lost(self):
        idre = re.compile(r"\b(?:ev_[0-9a-z_]+|HYP_\d+|FND_\d+|SYM_ev_[0-9a-z]+|CHK_[A-Z0-9_]+|RECIPE_[A-Z0-9_]+|inv_[0-9a-f]+)\b")
        for name in ("overflow_ring", "ok_idle_server"):
            d = _full(name)
            whole = DiagnosticReport.from_dict(d["report"]).to_html()
            out = _render_dict(d, "ko")
            page = out["report_html"]
            missing = set(idre.findall(whole)) - set(idre.findall(page))
            self.assertEqual(missing, set(), name)
            a = d["report"]["section_a_executive_summary"]
            for s in (a["verdict_rationale"], d["report"]["section_c_diagnostic_strategy"]["methodology_selection_reason"]):
                self.assertIn(s[:60].replace("'", "&#x27;").replace('"', "&quot;"), page)

    def test_no_block_holds_the_whole_report(self):
        for name in ("overflow_ring", "ok_idle_server"):
            blocks = self._blocks(_render_dict(_full(name), "en")["report_html"])
            self.assertGreaterEqual(len(blocks), 10)
            total = sum(len(b) for b in blocks.values())
            for k, b in blocks.items():
                letters = len(set(re.findall(r"<h4>([A-I])\. ", b)))
                self.assertLessEqual(letters, 3, k)
                self.assertLess(len(b), 0.6 * total, k)

    def test_finding_and_check_blocks_hold_only_their_own_records(self):
        d = _full("overflow_ring")
        rep = d["report"]
        # a second finding on another check, supported by an evidence record of that check
        ev2 = next(e["evidence_id"] for e in rep["section_g_evidence_and_provenance"]["evidence_records"]
                   if e["evidence_id"] not in d["findings"][0]["evidence_ids"])
        d["findings"].append({"category": "INVALID_DOUBLE_FREE", "severity": "HIGH", "status": "PROBABLE_CAUSE",
                              "description": "x", "subjects": ["p"], "subject_details": [{"kind": "variable", "name": "p"}],
                              "recipe_ids": ["RECIPE_DOUBLE_FREE"], "evidence_ids": [ev2]})
        blocks = self._blocks(_render_dict(d, "ko")["report_html"])
        f1, f2 = blocks["finding-1-detail"], blocks["finding-2-detail"]
        ev1 = d["findings"][0]["evidence_ids"][0]
        self.assertIn(ev1, f1)
        self.assertNotIn(ev2, f1)
        self.assertIn(ev2, f2)
        self.assertNotIn(ev1, f2)
        self.assertIn("FND_001", f1)
        self.assertNotIn("FND_001", f2)
        checks = [c for c in rep["section_d_detailed_inspection_results"]["checks"]]
        for key, body in blocks.items():
            m = re.fullmatch(r"check-(RECIPE_[A-Z0-9_]+)-detail", key)
            if not m:
                continue
            rid = m.group(1)
            own = [c["check_id"] for c in checks if c["recipe_id"] == rid]
            for c in checks:
                if c["recipe_id"] != rid:
                    self.assertNotIn(f'id="detail-chk-{c["check_id"]}"', body, (rid, c["check_id"]))
            for cid in own:
                self.assertIn(f'id="detail-chk-{cid}"', body)

    def test_each_record_is_rendered_once(self):
        html = _render_dict(_full("overflow_ring"), "en")["report_html"]
        ids = re.findall(r'id="(detail-(?:chk|ev|hyp|fnd)-[^"]+)"', html)
        self.assertEqual(len(ids), len(set(ids)))

    def test_markdown_points_to_the_detail_and_can_append_it_by_part(self):
        d = _full("overflow_ring")
        md = _render_dict(d, "ko")["report_markdown"]
        self.assertIn("#finding-1-detail", md)
        self.assertNotIn("Executive Summary", md)
        self.assertNotIn("ev_2d049b8f827b", md)
        full = _render_dict(d, "ko", markdown_detail=True)["report_markdown"]
        tail = full.split("## 보고서 부분별 상세 기록 (영문)")[1]
        self.assertIn("### 발견 1", tail)
        self.assertIn("ev_2d049b8f827b", tail.split("### 발견 1")[1].split("\n### ")[0])
        self.assertIn("### 검사 힙 메타데이터 무결성", tail)


class TestHumanSummary(unittest.TestCase):
    def test_summary_is_the_same_outline_without_incident_only_parts(self):
        d = _load("overflow_ring")
        s = render_human_report(d, d["report"], "en")
        self.assertEqual(_md_h2(s), ["1. Conclusion", "2. Target", "3. What was found", "4. Checks", "5. Not examined",
                                     "6. What to do next", "7. How the diagnosis was done and what it cost the target",
                                     "8. Reference"])


class TestDesignSystem(unittest.TestCase):
    """The report HTML against the checklist of docs/ui-redesign/DESIGN_SYSTEM_KO.md section 5 and its card order."""

    CASES = ("overflow_ring", "uaf_jobq", "lock_convoy", "ok_idle_server", "request_threads", "deadlock_circular")
    # the former group labels of the outline (an engine sentence such as "힙 메타데이터에 이상 없음" is not a status label)
    OLD_WORDS = ("판단하지 못함", "이상 없음 (", "실행하지 않음", "came back clean", "Clean (", "Could not decide")

    def _pages(self):
        for name in self.CASES:
            for lang in ("en", "ko"):
                yield name, lang, _render_dict(_load(name), lang)

    def test_card_order_is_the_exported_order(self):
        from extractor.human_report import REPORT_SECTION_ORDER, SECTION_ORDER
        from extractor.report_visuals import _SEC_ID
        self.assertEqual(REPORT_SECTION_ORDER[:7], ("conclusion", "tiles", "target", "findings", "checks",
                                                    "not_examined", "next"))   # the design system's order
        self.assertEqual(SECTION_ORDER, tuple(k for k in REPORT_SECTION_ORDER if k != "tiles"))
        for name, lang, out in self._pages():
            html = out["report_html"]
            ids = {v: k for k, v in _SEC_ID.items()}
            found = [ids[i] for i in re.findall(r'<(?:section|div) class="(?:card|tiles)[^"]*" id="([^"]+)"', html) if i in ids]
            self.assertEqual(found, [k for k in REPORT_SECTION_ORDER if k in found], (name, lang, found))
            self.assertEqual(found[:3], ["conclusion", "tiles", "target"], (name, lang))
            self.assertIn('class="card masthead"', html.split('id="sec-conclusion"')[0])   # the masthead comes first
            keys = [s["key"] for s in compose(_load(name), _load(name)["report"], lang)["sections"]]
            self.assertEqual(keys, [k for k in SECTION_ORDER if k in keys])

    def test_no_external_url_and_no_colour_outside_the_token_block(self):
        for name, lang, out in self._pages():
            html = out["report_html"]
            self.assertNotRegex(html, r"https?://", (name, lang))
            theme = re.search(r'(?s)<style id="ds-theme">.*?</style>', html)
            self.assertTrue(theme, "the shared theme is inlined")
            rest = html.replace(theme.group(0), "")
            self.assertEqual(re.findall(r"#[0-9a-fA-F]{3,8}\b(?![\w-])", re.sub(r'(?s)href="#[^"]*"', "", rest)), [], (name, lang))
            self.assertNotRegex(rest, r"\b(?:rgba?|hsla?|oklch)\(", (name, lang))

    def test_only_the_four_status_words(self):
        for name, lang, out in self._pages():
            text = _text(out["report_html"]) + out["report_markdown"]
            for w in self.OLD_WORDS:
                self.assertNotIn(w, text, (name, lang, w))
            words = re.findall(r'<details class="dsv-ck dsv-s-(\w+)"', out["report_html"])
            self.assertTrue(set(words) <= {"FAIL", "INCONCLUSIVE", "PASS", "SKIPPED"})
            for g, (en, ko) in (("FAIL", ("Found a problem", "이상 발견")), ("INCONCLUSIVE", ("Could not judge", "판단 불가")),
                                ("PASS", ("Passed", "통과")), ("SKIPPED", ("Not run", "실행 안 함"))):
                if g in words:
                    self.assertIn(en if lang == "en" else ko, text, (name, lang, g))

    def test_no_card_inside_a_card(self):
        for name, lang, out in self._pages():
            body = without_detail(out["report_html"])
            # between a card's opening tag and its end there is no other card opening tag
            cards = [m.start() for m in re.finditer(r'<(?:section|div|header) class="card[ "]', body)]
            ends = []
            for start in cards:
                tag = re.match(r"<(\w+)", body[start:]).group(1)
                d, i = 0, start
                for m in re.finditer(r"<(/?)" + tag + r"\b", body[start:]):
                    d += -1 if m.group(1) else 1
                    if d == 0:
                        ends.append(start + m.start())
                        break
            for start, end in zip(cards, ends):
                inner = body[start + 1:end]
                self.assertNotRegex(inner, r'<(?:section|div|header) class="card[ "]', (name, lang, body[start:start + 80]))

    def test_dark_mode_follows_the_os_and_a_dark_class(self):
        html = _render_dict(_load("overflow_ring"), "ko")["report_html"]
        self.assertIn("prefers-color-scheme: dark", html)
        self.assertIn(".dark {", html)
        self.assertIn("@media print", html)

    def test_english_collapsible_labels_are_english(self):
        html = _render_dict(_load("overflow_ring"), "en")["report_html"]
        self.assertIn('content: "Show"', html)
        self.assertNotRegex(html, "[가-힣]")              # nothing Korean in an English report, styles included


if __name__ == "__main__":
    unittest.main()
