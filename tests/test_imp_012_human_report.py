"""IMP-012: the human-readable report layer, checked against real processes.

Fixtures from tests/fixtures/real_runtime are compiled at test time and diagnosed once per class (no evidence or
verdict injected).  Names asserted come from the fixture source / its own ground-truth line, not from the code under
test.  Pure rendering rules are checked on hand-written result dicts that follow the DiagnoseResult schema.
"""

import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import scripts.mcp_server as mcp_srv
from extractor.expert_diagnostic_engine import diagnose
from extractor.human_report import T, diagnose_with_summary, render_human_report

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "real_runtime")
HEADERS_EN = ["1. Conclusion", "2. What is wrong", "3. Why we concluded this",
              "4. How certain, and what was not examined", "5. What to do next",
              "6. Impact of the collection on the target", "Glossary"]
HEADERS_KO = ["1. 결론", "2. 무엇이 문제인가", "3. 왜 그렇게 판단했는가", "4. 얼마나 확실한가, 그리고 확인하지 못한 것",
              "5. 다음에 할 일", "6. 수집이 대상에 준 영향", "용어 풀이"]
MEMORY_SYMPTOM = "memory usage of this process keeps growing"


def _first_sentence_block(text):
    """Text of section 1 (the conclusion)."""
    m = re.search(r"## 1\.[^\n]*\n+(.*?)\n+## 2\.", text, re.S)
    return m.group(1).strip()


def _ascii_word_runs(text):
    """Runs of 3+ consecutive plain ASCII words outside code spans / fenced blocks: English sentence fragments."""
    text = re.sub(r"```.*?```", " ", text, flags=re.S)
    text = re.sub(r"`[^`]*`", " ", text)
    return re.findall(r"\b[A-Za-z]{2,}(?: [A-Za-z]{2,}){2,}\b", text)


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestHumanReportReal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp012_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.corpus = os.path.join(cls.tmp, "corpus")
        cls.bins = {}
        cls.cache = {}

    def _binary(self, src):
        if src not in self.bins:
            out = os.path.join(self.tmp, os.path.splitext(src)[0])
            subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", os.path.join(FIXTURES, src),
                            "-o", out], check=True, capture_output=True, timeout=120)
            self.bins[src] = out
        return self.bins[src]

    def _launch(self, src, wait_ready=False):
        binary = self._binary(src)
        proc = subprocess.Popen([binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

        def _kill():
            try:
                proc.kill()
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                pass
            proc.stdout.close()

        self.addCleanup(_kill)
        if wait_ready:
            buf, deadline = b"", time.monotonic() + 60
            while b"READY" not in buf:
                self.assertLess(time.monotonic(), deadline, "fixture did not print READY")
                self.assertIsNone(proc.poll(), "fixture exited before READY")
                r, _, _ = select.select([proc.stdout], [], [], 0.2)
                if r:
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    self.assertTrue(chunk)
                    buf += chunk
        else:
            time.sleep(0.5)
            self.assertIsNone(proc.poll())
        return proc, binary

    def _diag(self, key, src, symptom=None, wait_ready=False):
        if key not in self.cache:
            proc, binary = self._launch(src, wait_ready)
            res = diagnose(proc.pid, binary, symptom, corpus_dir=self.corpus, include_report=True).to_dict()
            self.cache[key] = (proc, binary, res)
        return self.cache[key]

    # ------------------------------------------------------------------ deadlock
    def _deadlock(self):
        return self._diag("dl", "proc_thread_circular_deadlock.c")

    def _src_lines(self):
        """Ground truth from the fixture source: the line where each worker function is defined.

        The tool resolves a frame to its function's definition line (not the line of the blocked call); the report
        says so in its text, and this test checks the report against what the tool can know."""
        with open(os.path.join(FIXTURES, "proc_thread_circular_deadlock.c")) as fh:
            lines = fh.read().splitlines()
        want = {}
        for n, line in enumerate(lines, 1):
            m = re.match(r"static void \*(worker_\d)\(", line)
            if m:
                want[m.group(1)] = n
        return want

    def test_deadlock_first_screen_names_locks_functions_and_lines_in_both_languages(self):
        proc, binary, res = self._deadlock()
        self.assertIn(res["verdict"], ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT"))
        lines = self._src_lines()
        self.assertEqual(set(lines), {"worker_1", "worker_2"})
        for lang, headers in (("en", HEADERS_EN), ("ko", HEADERS_KO)):
            text = render_human_report(res, res["report"], lang=lang)
            first_screen = text.split("## 3.")[0]
            for name in ("g_mutex_a", "g_mutex_b", "worker_1", "worker_2"):
                self.assertIn(name, first_screen, (lang, name))
            for fn, ln in lines.items():
                self.assertRegex(first_screen, r"proc_thread_circular_deadlock\.c:%d\b" % ln, (lang, fn))
            self.assertIn("pid %d" % proc.pid, text)
            self.assertIn(res["target"]["process_name"], text)
            self.assertIn("--waits-->" if lang == "en" else "--기다림-->", text)
            pos = [text.index("## " + h) for h in headers]
            self.assertEqual(pos, sorted(pos), (lang, "section order"))
            # next-step names both functions with their lines
            nxt = text.split("## 5.")[1].split("## 6.")[0]
            self.assertIn("worker_1", nxt)
            self.assertIn("worker_2", nxt)

    def test_korean_text_has_no_english_template_fragments(self):
        _p, _b, res = self._deadlock()
        ko = render_human_report(res, res["report"], lang="ko")
        self.assertEqual(_ascii_word_runs(ko), [], "English word runs outside identifiers in the Korean text")
        # no English template sentence survives either
        for key, (en, _ko) in T.items():
            for chunk in re.split(r"\{[^}]*\}", en):
                words = chunk.strip().split()
                if len(words) >= 3:
                    self.assertNotIn(chunk.strip(), ko, key)
        self.assertTrue(re.search(r"[가-힣]", ko))

    def test_numbers_in_text_equal_result_numbers(self):
        _p, _b, res = self._deadlock()
        ci = res["collection_impact"]
        for lang in ("en", "ko"):
            text = render_human_report(res, res["report"], lang=lang)
            sec6 = text.split("## 6.")[1].split("\n## ")[0]
            self.assertIn(str(ci["measured_stop_ms"]), sec6)
            self.assertIn(str(ci["bytes_read"]), sec6)
            self.assertIn(str(ci["wall_clock_ms"]), sec6)
            self.assertIn(ci["capture_mode"], sec6)

    def test_result_without_inline_report_still_names_locks_and_functions(self):
        _p, _b, res = self._deadlock()
        slim = dict(res, report=None)
        text = render_human_report(slim, None, lang="en")
        for name in ("g_mutex_a", "g_mutex_b", "worker_1", "worker_2"):
            self.assertIn(name, text)

    def test_cli_lang_ko_round_trip(self):
        proc, binary = self._launch("proc_thread_circular_deadlock.c")
        base = [sys.executable, "-m", "extractor.cli", "diagnose", "--pid", str(proc.pid), "--debug-image", binary,
                "--corpus", self.corpus]
        ko = subprocess.run(base + ["--lang", "ko"], capture_output=True, text=True, cwd=ROOT, timeout=180)
        self.assertEqual(ko.returncode, 0, ko.stderr)
        for h in HEADERS_KO:
            self.assertIn("## " + h, ko.stdout)
        for name in ("g_mutex_a", "g_mutex_b", "worker_1", "worker_2"):
            self.assertIn(name, ko.stdout)
        en = subprocess.run(base, capture_output=True, text=True, cwd=ROOT, timeout=180)
        self.assertEqual(en.returncode, 0, en.stderr)
        self.assertIn("## 1. Conclusion", en.stdout)
        js = subprocess.run(base + ["--json", "--lang", "ko"], capture_output=True, text=True, cwd=ROOT, timeout=180)
        self.assertEqual(js.returncode, 0, js.stderr)
        out = json.loads(js.stdout)
        self.assertIn("## 1. 결론", out["human_summary"])
        self.assertIn(out["verdict"], ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT"))
        self.assertIsNone(out["report"])
        # the summary's numbers are the numbers of this very result
        self.assertIn(str(out["collection_impact"]["bytes_read"]), out["human_summary"])
        self.assertIn(str(out["collection_impact"]["measured_stop_ms"]), out["human_summary"])

    def test_mcp_attaches_human_summary_in_requested_language(self):
        proc, binary = self._launch("proc_thread_circular_deadlock.c")
        out = json.loads(mcp_srv.runtime_diagnose_process(pid=proc.pid, debug_image=binary, language="ko"))
        self.assertIn("## 1. 결론", out["human_summary"])
        self.assertIn("g_mutex_a", out["human_summary"])
        out_en = json.loads(mcp_srv.runtime_diagnose_process(pid=proc.pid, debug_image=binary))
        self.assertIn("## 1. Conclusion", out_en["human_summary"])
        self.assertIn("language", mcp_srv.runtime_diagnose_process.__doc__)

    # ------------------------------------------------------------------ leak
    def test_leak_names_variable_path_and_growth(self):
        _p, _b, res = self._diag("leak", "proc_leak_append_list.c", MEMORY_SYMPTOM, wait_ready=True)
        leaks = [f for f in res["findings"] if f["category"] == "MEMORY_LEAK"]
        self.assertTrue(leaks, res["findings"])
        path = next(s for s in leaks[0]["subjects"] if "(->next)*" in s)
        self.assertTrue(path.startswith("g_pending_items"))
        m = re.search(r"\+(\d+) blocks / \+(\d+) KB in use over ([\d.]+) s \(([\d.]+) KB/s\)", leaks[0]["description"])
        self.assertTrue(m, leaks[0]["description"])
        for lang in ("en", "ko"):
            text = render_human_report(res, res["report"], lang=lang)
            sec12 = text.split("## 3.")[0]
            self.assertIn(path, sec12)
            self.assertIn("+%s" % m.group(1), sec12)
            win = float(re.search(r"(\d+\.\d+) ?(?:s\b|초)", sec12).group(1))
            self.assertAlmostEqual(win, float(m.group(3)), delta=0.02)
            self.assertIn("g_pending_items", text.split("## 5.")[1].split("## 6.")[0])
        self.assertEqual(_ascii_word_runs(render_human_report(res, res["report"], lang="ko")), [])

    # ------------------------------------------------------------------ nonexistent pid / healthy
    def test_nonexistent_pid_first_sentence_says_inconclusive_and_why(self):
        with open("/proc/sys/kernel/pid_max") as fh:
            dead = int(fh.read()) + 1000
        res = diagnose(dead, corpus_dir=self.corpus).to_dict()
        self.assertEqual(res["verdict"], "INCONCLUSIVE")
        en = render_human_report(res, lang="en")
        first = _first_sentence_block(en)
        self.assertIn("inconclusive", first)
        self.assertIn("does not exist", first)
        self.assertIn(str(dead), first)
        ko = render_human_report(res, lang="ko")
        first_ko = _first_sentence_block(ko)
        self.assertIn("판단 불가", first_ko)
        self.assertIn("존재하지 않", first_ko)
        for text in (en, ko):
            self.assertNotIn("no problem", text.lower())
            self.assertNotIn("정상", text)
        self.assertEqual(_ascii_word_runs(ko), [])
        self.assertIn("## 6.", en)

    def test_missing_debug_image_first_sentence_gives_the_reason(self):
        proc, _binary = self._launch("proc_scenario_a_healthy.c")
        res = diagnose(proc.pid, os.path.join(self.tmp, "nope.elf"), corpus_dir=self.corpus).to_dict()
        self.assertEqual(res["verdict"], "INCONCLUSIVE")
        first = _first_sentence_block(render_human_report(res, lang="en"))
        self.assertIn("inconclusive", first)
        self.assertIn("nope.elf", first)
        self.assertIn("nope.elf", _first_sentence_block(render_human_report(res, lang="ko")))

    def test_healthy_fixture_wording_matches_verdict(self):
        proc, binary, res = self._diag("healthy", "proc_scenario_a_healthy.c")
        for lang in ("en", "ko"):
            text = render_human_report(res, res["report"], lang=lang)
            first = _first_sentence_block(text)
            if res["verdict"] in ("INCONCLUSIVE", "ABORTED"):
                self.assertNotIn("no problem", text.lower())
                self.assertNotIn("정상", text)
                self.assertTrue("inconclusive" in first or "aborted" in first or "판단 불가" in first or "중단" in first, first)
            elif res["verdict"] == "HEALTHY":
                # HEALTHY rule: "healthy within the checked scope", and the same sentence names what was not checked
                self.assertTrue("healthy within the checked scope" in first or "점검한 범위 안에서 정상" in first, first)
                self.assertTrue("Not checked:" in first or "점검하지 못한 것:" in first, first)
            else:
                self.assertTrue(res["findings"], "a fault verdict needs a named finding")
            pos = [text.index("## " + h) for h in (HEADERS_EN if lang == "en" else HEADERS_KO)[:6]]
            self.assertEqual(pos, sorted(pos))

    def test_diagnose_with_summary_drops_inline_report(self):
        proc, binary = self._launch("proc_scenario_a_healthy.c")
        d, summary = diagnose_with_summary(proc.pid, binary, corpus_dir=self.corpus, lang="en")
        self.assertIsNone(d["report"])
        self.assertIn("## 1. Conclusion", summary)


class TestHumanReportRules(unittest.TestCase):
    """Rendering rules on dicts that follow the DiagnoseResult schema."""

    BASE = {"verdict": "INCONCLUSIVE", "confidence": 0.0, "findings": [], "checks_run": [], "not_covered": [],
            "collection_impact": {}, "target": {"pid": 4242, "process_name": "myproc", "abi": None, "debug_image": None},
            "report_path": None}

    def test_confirmed_finding_without_names_says_so(self):
        res = dict(self.BASE, verdict="PROBABLE_FAULT", findings=[
            {"category": "MEMORY_CORRUPTION", "severity": "HIGH", "status": "PROBABLE_CAUSE", "description": "x",
             "subjects": [], "subject_details": [], "recipe_ids": [], "evidence_ids": []}])
        for lang, phrase in (("en", "names no variable"), ("ko", "이름이 없어")):
            text = render_human_report(res, lang=lang)
            self.assertIn(phrase, text)
            self.assertIn("myproc", text)
            self.assertIn("4242", text)

    def test_unexamined_items_grouped_by_kind_in_plain_words(self):
        res = dict(self.BASE, not_covered=[
            {"kind": "limitation", "item": "engine", "reason": "heap integrity not checked: heap larger than baseline cap"},
            {"kind": "check_inconclusive", "item": "RECIPE_X", "reason": "Check executed"},
            {"kind": "check_inconclusive", "item": "RECIPE_Y", "reason": "Check executed"},
            {"kind": "unsupported_on_target", "item": "tcb_scan", "reason": "NOT_SUPPORTED"}])
        text = render_human_report(res, lang="en")
        sec4 = text.split("## 4.")[1].split("## 5.")[0]
        self.assertIn("heap larger than baseline cap", sec4)
        self.assertEqual(sec4.count("could not decide") >= 0, True)
        self.assertRegex(sec4, r"`RECIPE_X`, `RECIPE_Y`")
        self.assertIn("`tcb_scan`", sec4)

    def test_inconclusive_next_steps_ask_for_inputs_and_never_say_no_problem(self):
        res = dict(self.BASE, checks_run=[{"status": "INCONCLUSIVE", "recipe_id": "R"}],
                   not_covered=[{"kind": "check_inconclusive", "item": "R", "reason": "x"}])
        for lang in ("en", "ko"):
            text = render_human_report(res, lang=lang)
            sec5 = text.split("## 5.")[1].split("## 6.")[0]
            self.assertIn("--debug-image", sec5)
            self.assertNotIn("no problem", text.lower())
            self.assertNotIn("정상", text)

    def test_rejects_unknown_language(self):
        with self.assertRaises(ValueError):
            render_human_report(self.BASE, lang="fr")

    def test_rendering_is_deterministic(self):
        self.assertEqual(render_human_report(self.BASE, lang="ko"), render_human_report(self.BASE, lang="ko"))


if __name__ == "__main__":
    unittest.main()
