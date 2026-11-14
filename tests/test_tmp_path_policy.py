"""Policy: a test never writes to a hard-coded ``/tmp/...`` path.

Fixed shared paths leak between runs (a 1.6 GB ``/tmp/phase2_1_1_scenarios_corpus`` filled the host disk) and make
concurrent runs interfere.  Use ``tempfile.TemporaryDirectory`` / ``tests.support.tmpdirs.temp_dir`` instead.

Flagged: a string literal starting with ``/tmp/`` (or equal to ``/tmp``) that is passed as a keyword argument or
assigned to a name that denotes a directory or output (corpus, dir, out, output, workspace, work, cache, home).
Not flagged: fake path strings used as inputs/expectations (``/tmp/app``), and the race-free shared fixture
builds declared in ``tests/fixture_builds.py`` (``*.elf`` / built targets), which are read-mostly build caches.
"""
import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN = ("tests", "benchmarks", "scripts")
NAME = re.compile(r"(corpus|dir|out|output|workspace|work|cache|home)", re.I)
SHARED_FIXTURE = re.compile(r"\.(elf|cpp|so|debug)$|_(debug|stripped)$")

# (file, line text) -> reason.  Each entry is a deliberate, documented exception.
ALLOWED = {
    ("tests/test_phase16_cli_security_and_truthfulness.py", '"HOME": "/tmp/test_home"'):
        "env value checked for scrubbing; nothing is written there",
    ("scripts/qemu_matrix/guest.py", 'self.workdir = "/tmp"'):
        "work directory on the emulated board, not on this host",
}


def _is_tmp(node) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and \
        (node.value.startswith("/tmp/") or node.value == "/tmp")


def _sites():
    for top in SCAN:
        for root, _dirs, files in os.walk(os.path.join(ROOT, top)):
            for name in files:
                if not name.endswith(".py") or name == "test_tmp_path_policy.py":
                    continue
                path = os.path.join(root, name)
                rel = os.path.relpath(path, ROOT)
                with open(path, encoding="utf-8") as fh:
                    src = fh.read()
                lines = src.split("\n")
                tree = ast.parse(src)
                for node in ast.walk(tree):
                    hits = []
                    if isinstance(node, ast.keyword) and node.arg and NAME.search(node.arg) and _is_tmp(node.value):
                        hits.append(node.value)
                    elif isinstance(node, ast.Assign) and _is_tmp(node.value):
                        for t in node.targets:
                            tn = t.attr if isinstance(t, ast.Attribute) else getattr(t, "id", "")
                            if NAME.search(tn):
                                hits.append(node.value)
                    elif isinstance(node, ast.Dict):
                        for k, v in zip(node.keys, node.values):
                            if isinstance(k, ast.Constant) and isinstance(k.value, str) and NAME.search(k.value) and _is_tmp(v):
                                hits.append(v)
                    for h in hits:
                        if SHARED_FIXTURE.search(h.value):
                            continue
                        yield rel, h.lineno, lines[h.lineno - 1].strip()


class TmpPathPolicyTests(unittest.TestCase):
    def test_no_hardcoded_tmp_output_paths(self):
        bad = [f"{rel}:{ln}  {text}" for rel, ln, text in _sites()
               if not any(rel == a and frag in text for (a, frag) in ALLOWED)]
        self.assertEqual(bad, [], "use tempfile.TemporaryDirectory / tests.support.tmpdirs.temp_dir, not a fixed /tmp path")

    def test_allowlist_has_no_stale_entries(self):
        present = [(rel, text) for rel, _ln, text in _sites()]
        stale = [(a, frag) for (a, frag) in ALLOWED if not any(r == a and frag in t for r, t in present)]
        self.assertEqual(stale, [], "remove allowlist entries that no longer match a hard-coded path")

    def test_detector_flags_a_corpus_path(self):
        node = ast.parse('Engine(corpus_dir="/tmp/x_corpus")').body[0].value.keywords[0]
        self.assertTrue(NAME.search(node.arg) and _is_tmp(node.value))


if __name__ == "__main__":
    unittest.main()
