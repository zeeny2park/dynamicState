"""The new web UI (extractor/web/ui): the design system's mechanical checklist (docs/ui-redesign/DESIGN_SYSTEM_KO.md
section 5), the server-built fragments are inert HTML, the final screen against the report built from the same result,
and the JS unit tests (node; skipped with a message when node is not installed).

Run: python3 -m unittest tests.test_web_ui
"""
import copy
import gzip
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "extractor", "web", "ui")
FILES = ("index.html", "ui.css", "ui.js")
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "ko_report")
NODE = shutil.which("node")
NO_NODE = "node is not installed: the UI's JavaScript is not exercised"
_COLOUR = re.compile(r"#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?|oklch|oklab|lab|lch|hwb)\(|\b(?:white|black)\b(?!-)")


def _read(name):
    with open(os.path.join(UI, name), encoding="utf-8") as fh:
        return fh.read()


def _strip_comments(src):
    return re.sub(r"/\*.*?\*/", "", src, flags=re.S)


def _fixtures():
    out = {}
    for f in sorted(os.listdir(FIXTURES)):
        if f.endswith(".json.gz"):
            with gzip.open(os.path.join(FIXTURES, f), "rt", encoding="utf-8") as fh:
                out[f[:-8]] = json.load(fh)
    return out


def _str_table():
    out = subprocess.run([NODE, "-e", "process.stdout.write(JSON.stringify(require(process.argv[1]).STR))",
                          os.path.join(UI, "ui.js")], capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout)


class TestChecklist(unittest.TestCase):
    """DESIGN_SYSTEM_KO.md section 5, the items a machine can check."""

    def test_no_external_url(self):
        for name in FILES + ("theme.css",):
            with self.subTest(name):
                src = _read(name)
                self.assertNotRegex(src, r"https?://", "an absolute URL (CDN, web font, link) fails on an air-gapped network")
                self.assertNotRegex(src, r"""(?:src|href)\s*=\s*["']//""")
                self.assertNotIn("@import", src)
                self.assertNotIn("@font-face", src)
                self.assertNotIn("url(", _strip_comments(src).replace("url(#", ""))

    def test_relative_urls_only(self):
        """The demo is served under /dynamicstate/: every URL the page uses must be relative."""
        for name in FILES:
            with self.subTest(name):
                src = _read(name)
                self.assertNotRegex(src, r"""(?:src|href|action)\s*=\s*["']/""")
                self.assertNotRegex(src, r"""["'`]/(?:api|legacy|replay|static)\b""")

    def test_no_raw_colour_outside_the_token_file(self):
        for name in FILES:
            with self.subTest(name):
                src = _strip_comments(_read(name))
                if name == "index.html":
                    src = re.sub(r"<script>.*?</script>", "", src, flags=re.S)
                self.assertEqual([m.group(0) for m in _COLOUR.finditer(src)], [], f"use var(--token) in {name}")

    def test_theme_colours_only_in_token_definitions(self):
        """In theme.css a colour literal may appear only as the value of a custom property (a token)."""
        for line in _strip_comments(_read("theme.css")).splitlines():
            rest = re.sub(r"--[\w-]+\s*:\s*[^;]+;", "", line)
            self.assertIsNone(_COLOUR.search(rest), line)

    def test_report_css_has_no_colour_values(self):
        """The static report's own stylesheet uses tokens only; the pictures take the theme through the bridge."""
        from extractor import report_visuals as rv
        self.assertEqual([m.group(0) for m in _COLOUR.finditer(_strip_comments(rv._CSS))], [])
        self.assertNotIn(".dsv-svgbox {", rv._CSS, "picture rules live in theme.css")
        self.assertIn(".dsv-svgbox {", _read("theme.css"))
        self.assertIn(".dsv-r16:checked", _read("theme.css"), "the stepping rules cover report_visuals._MAX_STEPS")
        self.assertEqual(rv._MAX_STEPS, 16)

    def test_theme_is_language_neutral(self):
        """The Collapsible labels follow :lang() in the theme; the file itself has no Hangul (English reports inline it)."""
        css = _read("theme.css")
        self.assertIsNone(re.search(r"[가-힣]", css))
        self.assertIn('content: "Show"', css)
        self.assertIn(":lang(ko) > summary::after", css)

    def test_dsv_bridge_block_intact(self):
        css = _read("theme.css")
        m = re.search(r"\.dsv \{([^}]*)\}", css)
        self.assertIsNotNone(m)
        for var in ("--bg", "--panel", "--ink", "--mute", "--line", "--soft", "--bad", "--bad-bg", "--warn", "--warn-bg",
                    "--good", "--good-bg", "--unk", "--unk-bg", "--buf", "--buf-line", "--hdr", "--accent"):
            self.assertRegex(m.group(1), re.escape(var) + r"\s*:\s*var\(--", var)

    def test_one_theme_file(self):
        """The mock and the report read the canonical theme.css; there is no second copy to drift."""
        from extractor import report_visuals as rv
        self.assertFalse(os.path.exists(os.path.join(ROOT, "docs", "ui-redesign", "mock", "theme.css")))
        for page in ("index.html", "design-system.html"):
            with open(os.path.join(ROOT, "docs", "ui-redesign", "mock", page), encoding="utf-8") as fh:
                self.assertIn('href="../../../extractor/web/ui/theme.css"', fh.read(), page)
        self.assertIn('href="theme.css"', _read("index.html"))
        self.assertEqual(os.path.realpath(rv.theme_path()), os.path.realpath(os.path.join(UI, "theme.css")))

    def test_no_confidence_tile_no_chat_no_verdict_word_table(self):
        js, html = _read("ui.js"), _read("index.html")
        for w in ("신뢰도", "health_score", "confidence"):
            self.assertNotIn(w, js + html)
        self.assertNotIn("chat", (js + html).lower())
        self.assertNotRegex(js, r"\bv_(?:HEALTHY|CONFIRMED_FAULT)\b", "verdict words come from the server")

    @unittest.skipUnless(NODE, NO_NODE)
    def test_status_vocabulary_four_words(self):
        """Four check outcomes, the same word / colour / icon everywhere (DESIGN_SYSTEM_KO.md 1, 5)."""
        s = _str_table()
        keys = ("FAIL", "INCONCLUSIVE", "PASS", "SKIPPED")
        self.assertEqual([s["ko"][f"st_{k}"] for k in keys], ["이상 발견", "판단 불가", "통과", "실행 안 함"])
        self.assertEqual([s["en"][f"st_{k}"] for k in keys], ["Found a problem", "Could not judge", "Passed", "Not run"])
        js = _read("ui.js")
        self.assertIn('var ICON = { FAIL: "✖", INCONCLUSIVE: "?", PASS: "✔", SKIPPED: "–"', js)
        self.assertIn('var TONE = { FAIL: "fail", INCONCLUSIVE: "warn", PASS: "pass", SKIPPED: "skip" }', js)
        tones = set(re.findall(r"tone-([a-zA-Z_]+)", js + _read("ui.css")))
        self.assertLessEqual(tones, {"fail", "warn", "pass", "skip", "info"})
        self.assertEqual(s["ko"]["not_in_mode_h"], "무정지 진단으로는 답할 수 없어 점검하지 않음")
        self.assertNotEqual(s["ko"]["not_planned_h"], s["ko"]["not_in_mode_h"])

    @unittest.skipUnless(NODE, NO_NODE)
    def test_status_words_are_the_reports(self):
        """The UI's four words are the report's (report_visuals ck_*): one vocabulary."""
        from extractor.report_visuals import _L
        s = _str_table()
        for k in ("FAIL", "INCONCLUSIVE", "PASS", "SKIPPED"):
            self.assertEqual(s["en"][f"st_{k}"], _L[f"ck_{k}"][0], k)
            self.assertEqual(s["ko"][f"st_{k}"], _L[f"ck_{k}"][1], k)


# ---------------------------------------------------------------------------------------------- server fragments
_UNSAFE = re.compile(r"<\s*(?:script|iframe|object|embed|link|meta|base|form)\b|<[^>]*\son[a-z]+\s*=|<[^>]*=\s*[\"']?\s*javascript:",
                     re.I)


def _html_strings(view):
    out = [view["conclusion_html"], view["scope_html"], view["not_examined_html"], view["next_html"]]
    out += view["symptom_html"]
    out += [f["body_html"] for f in view["findings"]] + [f["heading_html"] for f in view["findings"]]
    out += [c["detail_html"] for c in view["checks"]]
    return out


class TestServerFragments(unittest.TestCase):
    """The view's HTML fragments go into the page as HTML (ui.js morph): they must be inert, and every value in them
    must be escaped, even when the target's own strings (names, symbols, interpretations) are hostile."""

    def test_fragments_of_every_fixture_are_inert(self):
        from extractor.web.ui.view import build_view
        for name, res in _fixtures().items():
            for lang in ("ko", "en"):
                with self.subTest(name=name, lang=lang):
                    v = build_view(res, lang)
                    for h in _html_strings(v):
                        self.assertIsNone(_UNSAFE.search(h or ""), (name, lang, (h or "")[:200]))

    def test_hostile_strings_are_escaped(self):
        from extractor.web.ui.view import build_view
        evil = '<img src=x onerror="alert(1)"><script>alert(2)</script>javascript:alert(3)'
        res = copy.deepcopy(_fixtures()["deadlock_circular"])
        res["target"]["process_name"] = evil
        for c in res["checks_run"]:
            c["name"] = evil
        for f in res["findings"]:
            f["description"] = evil
            f["observed"] = [evil]
            f["subjects"] = [evil]
            f["subject_details"] = [{"kind": "thread_name", "name": evil}, {"kind": "function", "name": evil}]
        for c in (res["report"].get("section_d_detailed_inspection_results") or {}).get("checks") or []:
            c["technical_interpretation"] = evil
            c["limitations"] = [evil]
        for lang in ("ko", "en"):
            v = build_view(res, lang)
            for h in _html_strings(v):
                self.assertNotIn("<img", h or "")
                self.assertNotIn("<script", h or "")
                self.assertIsNone(_UNSAFE.search(h or ""), (h or "")[:300])

    def test_plain_fields_are_text(self):
        """Fields the UI escapes itself are plain text (no markup to double-escape or to trust)."""
        from extractor.web.ui.view import build_view
        v = build_view(_fixtures()["deadlock_circular"], "ko")
        for c in v["checks"]:
            self.assertNotIn("<", c["name"] + c["domain"] + c["line"])
        self.assertNotIn("<", v["verdict_word"] + v["verdict_meaning"])


# ---------------------------------------------------------------------------------------------- final screen = report
class TestFinalScreen(unittest.TestCase):
    @unittest.skipUnless(NODE, NO_NODE)
    def test_final_screen_shows_what_the_report_shows(self):
        from extractor.human_report import T, compose
        from extractor.web.ui.replay_gen import events_from_result, normalise
        fixtures = _fixtures()
        expected = {}
        with tempfile.TemporaryDirectory(prefix="ds_ui_") as tmp:
            for name, raw in fixtures.items():
                res = normalise(raw)
                with open(os.path.join(tmp, f"{name}.json"), "w", encoding="utf-8") as fh:
                    json.dump({"events": events_from_result(res), "request": {}}, fh)
                expected[name] = {lang: compose(res, res.get("report"), lang) for lang in ("ko", "en")}
            out = subprocess.run([NODE, os.path.join(ROOT, "tests", "web_ui", "render_check.js")]
                                 + [os.path.join(tmp, f"{n}.json") for n in fixtures], capture_output=True, text=True,
                                 timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        shown = json.loads(out.stdout)
        self.assertEqual(set(shown), set(fixtures))
        for name in fixtures:
            for i, lang in enumerate(("en", "ko")):
                with self.subTest(name=name, lang=lang):
                    comp, got = expected[name][lang], shown[name][lang]
                    c = comp["counts"]
                    word = T[f"v_{comp['verdict'] if 'v_' + comp['verdict'] in T else 'INCONCLUSIVE'}"][i]
                    self.assertTrue(got["verdict_badge"].endswith(word), got["verdict_badge"])
                    self.assertEqual(got["findings"], len(comp["blocks"]))
                    self.assertEqual(got["checks_tile"], str(c["run"]))
                    self.assertEqual(got["counts"], [c["found"], c["undecided"], c["clean"], c["not_run"]])
                    self.assertEqual(got["rows_fail"], c["found"])
                    self.assertFalse(got["bad"])

    def test_view_for_every_fixture_both_languages(self):
        from extractor.web.ui.view import build_view
        for name, res in _fixtures().items():
            for lang in ("ko", "en"):
                with self.subTest(name=name, lang=lang):
                    v = build_view(res, lang)
                    self.assertTrue(v["verdict_word"] and v["checks"])
                    self.assertTrue(all(c["name"] and c["name"] != c["rid"] for c in v["checks"] if c["kind"] == "run"))
                    self.assertEqual(len(v["findings"]), len(res["findings"]))
                    for fv in v["findings"]:
                        self.assertTrue(fv["body_html"])
                        self.assertNotIn('class="finding"', fv["body_html"])

    def test_replay_files_are_current(self):
        """The committed replays match what replay_gen makes now (regenerate: python3 -m extractor.web.ui.replay_gen)."""
        from extractor.web.ui.replay_gen import REPLAYS, events_from_result, normalise
        for name, (path, request, _what) in REPLAYS.items():
            with self.subTest(name):
                with gzip.open(os.path.join(ROOT, path), "rt", encoding="utf-8") as fh:
                    res = normalise(json.load(fh))
                with open(os.path.join(UI, "replay", name + ".json"), encoding="utf-8") as fh:
                    doc = json.load(fh)
                fresh = events_from_result(res, request, report_url=f"replay/{name}.report.{{lang}}.html")
                self.assertEqual([e["type"] for e in doc["events"]], [e["type"] for e in fresh])
                self.assertEqual(json.loads(json.dumps(fresh[-1]["data"]["view"])), doc["events"][-1]["data"]["view"])
                with open(os.path.join(UI, "replay", f"{name}.report.ko.html"), encoding="utf-8") as fh:
                    page = fh.read()
                self.assertIn('id="reproducibility', page)
                self.assertIn('id="ds-theme"', page)


class TestLiveEventExtras(unittest.TestCase):
    """The fields the server adds to live events for the UI (API_CONTRACT.md 6), from the report code."""

    def test_check_line_matches_the_report_check_list(self):
        from extractor.web.ui.view import build_view, check_line
        res = _fixtures()["deadlock_circular"]
        checks = {c["recipe_id"]: c for c in res["report"]["section_d_detailed_inspection_results"]["checks"]}
        for lang in ("ko", "en"):
            v = build_view(res, lang)
            for row in v["checks"]:
                if row["kind"] == "run" and row["status"] in ("FAIL", "PASS") and row["rid"] in checks:
                    with self.subTest(rid=row["rid"], lang=lang):
                        self.assertEqual(check_line(checks[row["rid"]])[lang], row["line"])

    def test_plan_exclusions_split_like_the_report(self):
        from extractor.diagnostic_recipes import DiagnosticRecipeRegistry
        from extractor.web.ui.view import plan_exclusions
        out = plan_exclusions(DiagnosticRecipeRegistry, ["RECIPE_HEAP_GROWTH"])
        ids = [r["recipe_id"] for r in out["not_planned"] + out["not_in_mode"]]
        self.assertNotIn("RECIPE_HEAP_GROWTH", ids)
        self.assertIn("RECIPE_USE_AFTER_FREE", [r["recipe_id"] for r in out["not_in_mode"]])
        for r in out["not_in_mode"]:
            self.assertTrue(r["capability"] and r["capability_label"]["ko"] and r["name"]["ko"])

    def test_verdict_words_and_headline(self):
        from extractor.human_report import T
        from extractor.web.ui.view import headline, verdict_words
        self.assertEqual(verdict_words("HEALTHY"), {"en": T["v_HEALTHY"][0], "ko": T["v_HEALTHY"][1]})
        self.assertEqual(verdict_words("nonsense")["en"], T["v_INCONCLUSIVE"][0])
        self.assertTrue(headline(_fixtures()["deadlock_circular"])["ko"])
        self.assertEqual(headline({"findings": []}), {"en": "", "ko": ""})


# ---------------------------------------------------------------------------------------------- JS unit tests
class TestJavaScript(unittest.TestCase):
    @unittest.skipUnless(NODE, NO_NODE)
    def test_js_unit_tests(self):
        out = subprocess.run([NODE, "--test", os.path.join(ROOT, "tests", "web_ui", "ui.test.js")],
                             capture_output=True, text=True, timeout=300)
        self.assertEqual(out.returncode, 0, out.stdout[-4000:] + out.stderr[-2000:])
        self.assertRegex(out.stdout, r"ℹ pass \d+")
        self.assertIn("ℹ fail 0", out.stdout)


if __name__ == "__main__":
    unittest.main()
