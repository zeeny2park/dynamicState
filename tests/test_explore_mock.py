"""Mechanical self-checks for the exploration mock (docs/ui-redesign/mock/explore.*): no absolute URL, no raw colour
outside theme.css, the standalone single-file build is reproducible from the sources and has no relative fetches.
The JS is syntax-checked with node when node is installed.

Run: python3 -m unittest tests.test_explore_mock
"""
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOCK = os.path.join(ROOT, "docs", "ui-redesign", "mock")
FILES = ("explore.html", "explore.css", "explore.js", "explore-data.js")
NODE = shutil.which("node")
# the same pattern as tests/test_web_ui.py (the live UI's checklist)
_COLOUR = re.compile(r"#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?|oklch|oklab|lab|lch|hwb)\(|\b(?:white|black)\b(?!-)")


def _read(name):
    with open(os.path.join(MOCK, name), encoding="utf-8") as fh:
        return fh.read()


def _strip_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$|(?<=[;{}),\s])//[^\n\"']*$", "", src)


def _builder():
    spec = importlib.util.spec_from_file_location("explore_build", os.path.join(MOCK, "build_standalone.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestExploreMock(unittest.TestCase):

    def test_no_absolute_url(self):
        for name in FILES:
            with self.subTest(name):
                src = _read(name)
                self.assertNotRegex(src, r"https?://", "the mock must open on an air-gapped network")
                self.assertNotRegex(src, r"""(?:src|href)\s*=\s*["']//""")
                self.assertNotIn("@import", src)
                self.assertNotIn("@font-face", src)

    def test_no_raw_colour_outside_theme(self):
        for name in FILES:
            with self.subTest(name):
                src = _strip_comments(_read(name))
                if name == "explore-data.js":
                    src = re.sub(r'"[^"\n]*"', '""', src)   # hex addresses and byte strings in the canned data are not colours
                    src = re.sub(r"\b0x[0-9a-fA-F]+\b", "0", src)
                if name == "explore.js":
                    src = re.sub(r'"#[\w-]+"', '""', src)    # in-page anchors such as "#observe"
                found = [m.group(0) for m in _COLOUR.finditer(src)]
                self.assertEqual(found, [], "use var(--token) in " + name)

    def test_loads_the_shared_theme(self):
        html = _read("explore.html")
        self.assertIn('href="../../../extractor/web/ui/theme.css"', html)
        self.assertIn('href="explore.css"', html)

    def test_new_components_use_tokens(self):
        css = _read("explore.css")
        for sel in (".spark", ".pool", ".hex", ".pc.s1", ".pc.s5"):
            self.assertIn(sel, css)
        for n in range(1, 6):
            self.assertIn("var(--chart-%d)" % n, css)

    def test_standalone_is_reproducible(self):
        b = _builder()
        first, second = b.build(), b.build()
        self.assertEqual(first, second, "the build must not depend on time or order")
        self.assertNotRegex(first, r"""(?:href|src)="(?!#)[^"]+\"""", "no relative fetch may remain")
        self.assertNotRegex(first, r"https?://")
        for src in b.sources():
            self.assertTrue(os.path.exists(src), src)
        self.assertIn("inlined: theme.css", first)
        self.assertIn("inlined: explore.js", first)
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "x.html")
            self.assertEqual(b.main(["--out", out]), 0)
            with open(out, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), first)
        dist = b.DEFAULT_OUT
        if os.path.exists(dist):
            with open(dist, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), first, "dist/explore.standalone.html is stale: rerun build_standalone.py")

    @unittest.skipUnless(NODE, "node is not installed: the mock's JavaScript is not syntax-checked")
    def test_js_parses_and_data_is_complete(self):
        for name in ("explore.js", "explore-data.js"):
            with self.subTest(name):
                r = subprocess.run([NODE, "--check", os.path.join(MOCK, name)], capture_output=True, text=True, timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr)
        script = ("require(process.argv[1]); const D = globalThis.EXPLORE_DATA; const out = {};"
                  "for (const id of D.ORDER) { const c = D.CASES[id]; out[id] = [c.stages.length, !!c.profile, c.checks.length]; }"
                  "process.stdout.write(JSON.stringify(out));")
        r = subprocess.run([NODE, "-e", script, os.path.join(MOCK, "explore-data.js")], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        import json
        cases = json.loads(r.stdout)
        self.assertEqual(sorted(cases), sorted(["healthy", "deadlock", "overflow", "threads300", "pool", "nodebug"]))
        for cid, (stages, has_profile, nchecks) in cases.items():
            self.assertGreaterEqual(stages, 4, cid)
            self.assertTrue(has_profile, cid)
            self.assertGreater(nchecks, 0, cid)


if __name__ == "__main__":
    unittest.main()
