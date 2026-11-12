"""The plain-language summary leads the standalone HTML incident report (real deadlock process, both languages)."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import scripts.mcp_server as mcp_srv
from extractor.human_report import conclusion_sentence, markdown_to_html
from extractor.incident_report import export_incident_report

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "tests", "fixtures", "real_runtime", "proc_thread_circular_deadlock.c")
EVIL = "<script>alert(1)</script>"


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class TestMarkdownToHtml(unittest.TestCase):
    def test_subset_and_escaping(self):
        out = markdown_to_html("# T <b>\n\npara `a<b` and **bold**\n\n- x\n- y\n\n1. one\n\n```\nA --waits--> <B>\n```\n")
        self.assertIn("<h1>T &lt;b&gt;</h1>", out)
        self.assertIn("<code>a&lt;b</code>", out)
        self.assertIn("<strong>bold</strong>", out)
        self.assertIn("<ul>", out)
        self.assertIn("<ol>", out)
        self.assertIn("<pre><code>A --waits--&gt; &lt;B&gt;</code></pre>", out)
        self.assertNotIn("<B>", out)


@unittest.skipUnless(shutil.which("gcc"), "gcc not available")
class TestIncidentHtml(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="inchtml_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.binary = os.path.join(cls.tmp, "dl")
        subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", SRC, "-o", cls.binary],
                       check=True, capture_output=True, timeout=120)
        cls.proc = subprocess.Popen([cls.binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    stdin=subprocess.DEVNULL)
        cls.addClassCleanup(cls._kill)
        time.sleep(0.7)
        assert cls.proc.poll() is None
        cls.corpus = os.path.join(cls.tmp, "corpus")

    @classmethod
    def _kill(cls):
        cls.proc.kill()
        cls.proc.wait(timeout=10)

    def _check_html(self, h, lang):
        self.assertNotRegex(h, r"""(?:src|href)\s*=\s*["']?https?://""")
        a = h.index("A. Executive Summary")
        pre = h[:a]
        self.assertIn('id="human-summary"', pre)
        self.assertIn('lang="%s"' % lang, pre)
        for name in ("g_mutex_a", "g_mutex_b"):
            self.assertIn(name, pre)
        self.assertIn("<pre><code>", pre)
        self.assertIn("--waits-->".replace(">", "&gt;") if lang == "en" else "--기다림--&gt;", pre)
        self.assertIn("prefers-color-scheme", pre)
        self.assertIn("monospace", pre)
        return pre

    def test_ko_html_leads_with_korean_conclusion(self):
        out = export_incident_report(title="t " + EVIL, pid=self.proc.pid, companion_elf_path=self.binary,
                                     corpus_dir=self.corpus, symptom=EVIL, language="ko",
                                     output_path=os.path.join(self.tmp, "ko.md"),
                                     report_html_path=os.path.join(self.tmp, "ko.html"))
        h = _read(out["saved_html_path"])
        pre = self._check_html(h, "ko")
        concl = conclusion_sentence(out["human_summary"])
        self.assertRegex(concl, "g_mutex_a")
        self.assertRegex(concl, "g_mutex_b")
        self.assertRegex(concl, "[가-힣]")
        self.assertIn(concl.replace("`", "").split("`")[0][:12], re.sub(r"</?code>", "", pre))
        self.assertIn("확인된 문제", pre)
        self.assertNotIn(EVIL, h)
        self.assertIn("t &lt;script&gt;", h)
        self.assertIn("## 1. 결론", _read(out["saved_path"]))
        self.assertIn(out["verdict"], out["llm_next_step_hint"])
        self.assertNotIn("Health Score", out["llm_next_step_hint"])
        self.assertIn("g_mutex_a", out["llm_next_step_hint"])
        self.assertIn("health_score", out)

    def test_en_html_is_english(self):
        out = export_incident_report(pid=self.proc.pid, companion_elf_path=self.binary, corpus_dir=self.corpus)
        pre = self._check_html(out["report_html"], "en")
        self.assertIn("1. Conclusion", pre)
        self.assertNotRegex(pre, "[가-힣]")
        self.assertEqual(out["language"], "en")
        with self.assertRaises(ValueError):
            export_incident_report(pid=self.proc.pid, language="fr")

    def test_cli_lang_ko_report_html_round_trip(self):
        html_path = os.path.join(self.tmp, "cli.html")
        md_path = os.path.join(self.tmp, "cli.md")
        r = subprocess.run([sys.executable, "-m", "extractor.cli", "export-report", "--pid", str(self.proc.pid),
                            "--debug-image", self.binary, "--corpus", self.corpus, "--lang", "ko",
                            "--report-html", html_path, "-o", md_path],
                           capture_output=True, text=True, cwd=ROOT, timeout=240)
        self.assertEqual(r.returncode, 0, r.stderr)
        h = _read(html_path)
        self._check_html(h, "ko")
        self.assertIn("## 1. 결론", _read(md_path))

    def test_mcp_language_parameter(self):
        out = json.loads(mcp_srv.runtime_export_incident_report(pid=self.proc.pid, companion_elf=self.binary,
                                                                language="ko"))
        self.assertTrue(out["success"], out)
        self.assertEqual(out["language"], "ko")
        self.assertIn("## 1. 결론", out["human_summary"])
        self.assertIn("language", mcp_srv.runtime_export_incident_report.__doc__)

    def test_web_language_field(self):
        import extractor.web.server as ws
        cls = next(c for c in vars(ws).values() if isinstance(c, type) and hasattr(c, "export_incident_report_api"))
        inst = cls.__new__(cls)
        from extractor.watch_session import WatchSessionManager
        inst.watch_manager = WatchSessionManager(corpus_dir=self.corpus)
        res = inst.export_incident_report_api({"pid": self.proc.pid, "debug_image": self.binary, "language": "ko"})
        self.assertTrue(res["success"], res)
        self.assertIn("## 1. 결론", res["data"]["human_summary"])
        bad = inst.export_incident_report_api({"pid": self.proc.pid, "language": "xx"})
        self.assertFalse(bad["success"])


if __name__ == "__main__":
    unittest.main()
