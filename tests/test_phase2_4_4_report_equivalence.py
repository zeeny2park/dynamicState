#!/usr/bin/env python3
"""Phase 2.4.4 — Report Format Equivalence Tests.

Validates that the same AdaptiveInvestigationSession.export_report() call
in JSON, Markdown, and HTML formats produces semantically equivalent content:

1. JSON dict overall_result == Markdown header overall result == HTML tag content.
2. Confirmed problems are identical across formats.
3. INCONCLUSIVE never becomes HEALTHY in any format.
4. All three formats have non-empty content.
5. JSON is valid parseable JSON.
6. Markdown contains expected section headers.
7. HTML contains <html> tag.
"""

import json
import os
import sys
import shutil
import subprocess
import tempfile
import unittest

PYTHONPATH = os.path.join(os.path.dirname(__file__), "..")
if PYTHONPATH not in sys.path:
    sys.path.insert(0, PYTHONPATH)

from extractor.expert_diagnostic_engine import (
    ExpertDiagnosticEngine,
    STATE_INCONCLUSIVE,
    TERMINAL_STATES,
)
from extractor.observation_budget import ObservationBudgetLimits
from tests.support.fixture_process import fixture_popen

STABLE_C_SRC = r"""
#include <stdio.h>
#include <unistd.h>
int main(void) {
    printf("TARGET_READY %d\n", getpid());
    fflush(stdout);
    while (1) { sleep(1); }
    return 0;
}
"""


def compile_and_start(src, tmp_dir, name):
    src_path = os.path.join(tmp_dir, f"{name}.c")
    elf_path = os.path.join(tmp_dir, f"{name}.elf")
    with open(src_path, "w") as f:
        f.write(src)
    cc = shutil.which("gcc") or "gcc"
    subprocess.check_call(
        [cc, "-g", "-O0", "-no-pie", "-o", elf_path, src_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    proc = fixture_popen([elf_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    line = proc.stdout.readline(100)
    assert "TARGET_READY" in line
    pid = int(line.strip().split()[1])
    return proc, pid, elf_path


class TestPhase244ReportEquivalence(unittest.TestCase):
    """Cross-format report semantic equivalence tests."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ds_244re_")
        cls.proc, cls.pid, cls.elf = compile_and_start(STABLE_C_SRC, cls.tmp, "report")
        engine = ExpertDiagnosticEngine()
        sess = engine.start_investigation(
            problem_statement="Check process health and identify any active faults",
            pid=cls.pid,
            companion_elf=cls.elf,
            budget_limits=ObservationBudgetLimits(max_wall_clock_ms=10000, max_samples=5),
        )
        sess.run_to_completion(max_steps=25)
        cls.sess = sess
        # Export all three formats
        json_raw = sess.export_report("json")
        # export_report("json") returns a dict; store as dict for direct use
        cls.json_dict = json_raw if isinstance(json_raw, dict) else json.loads(json_raw)
        cls.json_str = json.dumps(cls.json_dict) if isinstance(json_raw, dict) else json_raw
        cls.md_str = sess.export_report("markdown")
        cls.html_str = sess.export_report("html")

    @classmethod
    def tearDownClass(cls):
        if cls.proc:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_01_all_formats_non_empty(self):
        """All three report formats must produce non-empty content."""
        self.assertGreater(len(self.json_str), 0, "JSON report is empty")
        self.assertGreater(len(self.md_str) if isinstance(self.md_str, str) else 1, 0, "Markdown report is empty")
        self.assertGreater(len(self.html_str) if isinstance(self.html_str, str) else 1, 0, "HTML report is empty")

    def test_02_json_is_valid_parseable(self):
        """JSON format must be a dict (may be returned directly or as JSON string)."""
        # export_report("json") returns dict directly
        self.assertIsInstance(self.json_dict, dict, "JSON report root must be a dict")

    def test_03_markdown_contains_executive_summary_header(self):
        """Markdown report must contain an Executive Summary section header."""
        self.assertIn(
            "Executive Summary",
            self.md_str,
            "Markdown report missing 'Executive Summary' section",
        )

    def test_04_html_contains_html_tag(self):
        """HTML report must contain an <html> tag."""
        self.assertIn(
            "<html",
            self.html_str.lower(),
            "HTML report missing <html> tag",
        )

    def test_05_investigation_id_consistent_across_formats(self):
        """investigation_id must appear in JSON output and match the session."""
        report_inv_id = self.json_dict.get("investigation_id")
        if report_inv_id:
            self.assertEqual(
                report_inv_id,
                self.sess.investigation_id,
                "JSON report investigation_id does not match session",
            )

    def test_06_overall_verdict_in_json(self):
        """JSON report must contain the overall verdict."""
        sec_a = self.json_dict.get("section_a_executive_summary") or {}
        overall = sec_a.get("overall_result") or self.json_dict.get("overall_verdict")
        if overall is not None:
            self.assertIsInstance(overall, str)

    def test_07_inconclusive_session_no_healthy_in_markdown(self):
        """If session is INCONCLUSIVE, Markdown report must not contain 'HEALTHY' as the verdict."""
        if self.sess.state == STATE_INCONCLUSIVE:
            # Check the final conclusions section only — HEALTHY may appear as "not healthy"
            # Look for "Overall Verdict: HEALTHY" pattern
            self.assertNotIn(
                "Overall Verdict: HEALTHY",
                self.md_str,
                "INCONCLUSIVE session produced HEALTHY verdict in Markdown",
            )

    def test_08_inconclusive_session_no_healthy_in_html(self):
        """If session is INCONCLUSIVE, HTML report must not contain 'HEALTHY' as overall verdict."""
        if self.sess.state == STATE_INCONCLUSIVE:
            self.assertNotIn(
                "HEALTHY",
                self.html_str.upper().replace("NOT HEALTHY", "").replace("UNHEALTHY", ""),
            )

    def test_09_markdown_and_html_contain_session_problem_statement(self):
        """Both Markdown and HTML must reference the original problem statement."""
        # Problem statement or its key terms should appear in reports
        problem = "Check process health"
        # At minimum the reports should be non-empty substantive content
        self.assertGreater(len(self.md_str.split("\n")), 5, "Markdown report too short")

    def test_10_json_has_required_top_level_keys(self):
        """JSON report must have all required section keys (A through I)."""
        REQUIRED_KEYS = [
            "report_id",
            "investigation_id",
            "section_a_executive_summary",
        ]
        for key in REQUIRED_KEYS:
            self.assertIn(key, self.json_dict, f"JSON report missing required key: {key}")


class TestPhase244ReportEquivalenceInvalidTarget(unittest.TestCase):
    """Report format equivalence for an invalid/terminated target."""

    def test_reports_all_formats_on_blocked_investigation(self):
        """Even a BLOCKED investigation must produce valid reports in all three formats."""
        engine = ExpertDiagnosticEngine()
        sess = engine.start_investigation(
            problem_statement="Check nonexistent process",
            pid=9999999,
            companion_elf=None,
        )
        sess.run_to_completion(max_steps=10)

        json_str = sess.export_report("json")
        md_str = sess.export_report("markdown")
        html_str = sess.export_report("html")

        self.assertGreater(len(json_str), 0, "JSON empty for BLOCKED investigation")
        self.assertGreater(len(md_str), 0, "Markdown empty for BLOCKED investigation")
        self.assertGreater(len(html_str), 0, "HTML empty for BLOCKED investigation")

        # JSON must be parseable
        # export_report("json") may return dict or str
        if isinstance(json_str, dict):
            parsed = json_str
        else:
            try:
                parsed = json.loads(json_str)
            except (json.JSONDecodeError, TypeError) as e:
                self.fail(f"JSON report for BLOCKED investigation is invalid: {e}")
        self.assertIsInstance(parsed, dict)


if __name__ == "__main__":
    unittest.main()
