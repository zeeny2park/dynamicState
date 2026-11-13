"""The new web UI (extractor/web/ui): the design system's mechanical checklist (docs/ui-redesign/DESIGN_SYSTEM_KO.md
section 5), the final screen against the report built from the same result, and the JS unit tests (node)."""
import gzip
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "extractor", "web", "ui")
FILES = ("index.html", "ui.css", "ui.js")
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "ko_report")
NODE = shutil.which("node")


def _read(name):
    with open(os.path.join(UI, name), encoding="utf-8") as fh:
        return fh.read()


def _strip_comments(src):
    return re.sub(r"/\*.*?\*/", "", src, flags=re.S)


# ---------------------------------------------------------------------------------------------- checklist
@pytest.mark.parametrize("name", FILES + ("theme.css",))
def test_no_external_url(name):
    src = _read(name)
    assert not re.search(r"https?://", src), "an absolute URL (CDN, web font, link) would fail on an air-gapped network"
    assert not re.search(r"""(?:src|href)\s*=\s*["']//""", src), "protocol-relative URL"
    assert "@import" not in src and "@font-face" not in src
    assert "url(" not in _strip_comments(src).replace("url(#", ""), "no external resources from CSS"


@pytest.mark.parametrize("name", FILES)
def test_relative_urls_only(name):
    """The demo is served under /dynamicstate/: every URL the page uses must be relative."""
    src = _read(name)
    assert not re.search(r"""(?:src|href|action)\s*=\s*["']/""", src)
    assert not re.search(r"""["'`]/(?:api|legacy|replay|static)\b""", src)


_COLOUR = re.compile(r"#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?|oklch|oklab|lab|lch|hwb)\(|\b(?:white|black)\b(?!-)")


@pytest.mark.parametrize("name", FILES)
def test_no_raw_colour_outside_the_token_file(name):
    src = _strip_comments(_read(name))
    if name == "index.html":
        src = re.sub(r"<script>.*?</script>", "", src, flags=re.S)
    hits = [m.group(0) for m in _COLOUR.finditer(src)]
    assert not hits, f"raw colour values in {name}: {hits[:5]}; use var(--token)"


def test_theme_colours_only_in_token_definitions():
    """In theme.css a colour literal may appear only as the value of a custom property (a token)."""
    for line in _strip_comments(_read("theme.css")).splitlines():
        rest = re.sub(r"--[\w-]+\s*:\s*[^;]+;", "", line)
        assert not _COLOUR.search(rest), line


def test_dsv_bridge_block_intact():
    """The report renderer's private variables stay mapped onto the shared tokens (the report inlines theme.css)."""
    css = _read("theme.css")
    m = re.search(r"\.dsv \{([^}]*)\}", css)
    assert m
    for var in ("--bg", "--panel", "--ink", "--mute", "--line", "--soft", "--bad", "--bad-bg", "--warn", "--warn-bg",
                "--good", "--good-bg", "--unk", "--unk-bg", "--buf", "--buf-line", "--hdr", "--accent"):
        assert re.search(re.escape(var) + r"\s*:\s*var\(--", m.group(1)), var


def test_one_theme_file():
    """The mock reads the canonical theme.css; there is no second copy to drift."""
    assert not os.path.exists(os.path.join(ROOT, "docs", "ui-redesign", "mock", "theme.css"))
    for page in ("index.html", "design-system.html"):
        with open(os.path.join(ROOT, "docs", "ui-redesign", "mock", page), encoding="utf-8") as fh:
            assert 'href="../../../extractor/web/ui/theme.css"' in fh.read(), page
    assert 'href="theme.css"' in _read("index.html")


def _str_table():
    out = subprocess.run([NODE, "-e", "process.stdout.write(JSON.stringify(require(process.argv[1]).STR))",
                          os.path.join(UI, "ui.js")], capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout)


@pytest.mark.skipif(not NODE, reason="node is not installed")
def test_status_vocabulary_four_words():
    """Four check outcomes, the same word / colour / icon everywhere (DESIGN_SYSTEM_KO.md 1, 5)."""
    s = _str_table()
    assert [s["ko"][f"st_{k}"] for k in ("FAIL", "INCONCLUSIVE", "PASS", "SKIPPED")] == ["이상 발견", "판단 불가", "통과", "실행 안 함"]
    assert [s["en"][f"st_{k}"] for k in ("FAIL", "INCONCLUSIVE", "PASS", "SKIPPED")] == ["Problem found", "Inconclusive", "Pass", "Not run"]
    js = _read("ui.js")
    assert 'var ICON = { FAIL: "✖", INCONCLUSIVE: "?", PASS: "✔", SKIPPED: "–"' in js
    assert 'var TONE = { FAIL: "fail", INCONCLUSIVE: "warn", PASS: "pass", SKIPPED: "skip" }' in js
    tones = set(re.findall(r"tone-([a-zA-Z_]+)", js + _read("ui.css")))
    assert tones <= {"fail", "warn", "pass", "skip", "info"}, tones
    # the not-in-mode sub-group has its own words, never "not selected"
    assert s["ko"]["not_in_mode_h"] == "무정지 진단으로는 답할 수 없어 점검하지 않음"
    assert s["ko"]["not_planned_h"] != s["ko"]["not_in_mode_h"]


@pytest.mark.skipif(not NODE, reason="node is not installed")
def test_verdict_words_are_the_reports():
    from extractor.human_report import T
    s = _str_table()
    for code in ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT", "DEGRADED", "HEALTHY", "INCONCLUSIVE", "ABORTED"):
        assert s["en"][f"v_{code}"] == T[f"v_{code}"][0]
        assert s["ko"][f"v_{code}"] == T[f"v_{code}"][1]


def test_no_confidence_tile_and_no_chat():
    js, html = _read("ui.js"), _read("index.html")
    for w in ("신뢰도", "health_score", "confidence"):
        assert w not in js and w not in html
    assert "chat" not in (js + html).lower()


# ---------------------------------------------------------------------------------------------- final screen = report
@pytest.mark.skipif(not NODE, reason="node is not installed")
def test_final_screen_shows_what_the_report_shows(tmp_path):
    from extractor.human_report import T, compose
    from extractor.web.ui.replay_gen import events_from_result, normalise
    expected = {}
    names = sorted(f[:-8] for f in os.listdir(FIXTURES) if f.endswith(".json.gz"))
    for name in names:
        with gzip.open(os.path.join(FIXTURES, name + ".json.gz"), "rt", encoding="utf-8") as fh:
            res = normalise(json.load(fh))
        (tmp_path / f"{name}.json").write_text(json.dumps({"events": events_from_result(res), "request": {}}),
                                               encoding="utf-8")
        expected[name] = {lang: compose(res, res.get("report"), lang) for lang in ("ko", "en")}
    out = subprocess.run([NODE, os.path.join(ROOT, "tests", "web_ui", "render_check.js")]
                         + [str(tmp_path / f"{n}.json") for n in names], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    shown = json.loads(out.stdout)
    assert set(shown) == set(names)
    for name in names:
        for i, lang in enumerate(("en", "ko")):
            comp, got = expected[name][lang], shown[name][lang]
            c = comp["counts"]
            word = T[f"v_{comp['verdict'] if 'v_' + comp['verdict'] in T else 'INCONCLUSIVE'}"][i]
            assert got["verdict_badge"].endswith(word), (name, lang, got["verdict_badge"])
            assert got["findings"] == len(comp["blocks"]), (name, lang)
            assert got["checks_tile"] == str(c["run"]), (name, lang)
            assert got["counts"] == [c["found"], c["undecided"], c["clean"], c["not_run"]], (name, lang)
            assert got["rows_fail"] == c["found"], (name, lang)
            assert not got["bad"], (name, lang)


def test_view_for_every_fixture_both_languages():
    from extractor.web.ui.view import build_view
    for f in sorted(os.listdir(FIXTURES)):
        with gzip.open(os.path.join(FIXTURES, f), "rt", encoding="utf-8") as fh:
            res = json.load(fh)
        for lang in ("ko", "en"):
            v = build_view(res, lang)
            assert v["verdict_word"] and v["checks"]
            assert all(c["name"] and c["name"] != c["rid"] for c in v["checks"] if c["kind"] == "run"), f
            assert len(v["findings"]) == len(res["findings"])
            for fv in v["findings"]:
                assert fv["body_html"] and not fv["body_html"].startswith("<section"), f


def test_replay_files_are_current():
    """The committed replays match what replay_gen makes from the fixtures (regenerate: python3 -m extractor.web.ui.replay_gen)."""
    from extractor.web.ui.replay_gen import REPLAYS, events_from_result, normalise
    for name, (path, request, _what) in REPLAYS.items():
        with gzip.open(os.path.join(ROOT, path), "rt", encoding="utf-8") as fh:
            res = normalise(json.load(fh))
        with open(os.path.join(UI, "replay", name + ".json"), encoding="utf-8") as fh:
            doc = json.load(fh)
        fresh = events_from_result(res, request, report_url=f"replay/{name}.report.{{lang}}.html")
        assert [e["type"] for e in doc["events"]] == [e["type"] for e in fresh], name
        assert json.loads(json.dumps(fresh[-1]["data"]["view"])) == doc["events"][-1]["data"]["view"], name


# ---------------------------------------------------------------------------------------------- JS unit tests
@pytest.mark.skipif(not NODE, reason="node is not installed")
def test_js_unit_tests():
    out = subprocess.run([NODE, "--test", os.path.join(ROOT, "tests", "web_ui", "ui.test.js")],
                         capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stdout[-4000:] + out.stderr[-2000:]
