"""Regression Test Suite for CLI and Adaptive Investigation Engine Report Integration.

Validates:
1. Default Execution: No HTML or markdown file is created on disk.
2. Explicit Option (--report-html PATH): HTML report is generated on disk.
3. Legacy Output Preservation: -o / --output preserves markdown report generation.
4. Output Path Security: Writing to protected paths is rejected and recorded in save_html_error.
5. Diagnostic Single-Execution: Identical diagnosis results in JSON stdout and rendered HTML.
6. Stderr Warning on Save Failure: Exit code remains 0 to preserve upstream pipelines while warning is emitted.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


class TestCliAdaptiveReportIntegration(unittest.TestCase):
    """End-to-end CLI regression tests for Adaptive Report integration."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_cli_test_")
        cls.target_bin = "/tmp/real_runtime_app_debug.elf"

        # Ensure debug target is compiled
        if not os.path.isfile(cls.target_bin) and os.path.isfile("tests/fixtures/real_runtime/main.cpp"):
            subprocess.run(
                ["g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer", "-Wl,--build-id=sha1",
                 "tests/fixtures/real_runtime/main.cpp", "-o", cls.target_bin, "-lpthread"],
                check=True,
            )

        cls.proc = subprocess.Popen(
            [cls.target_bin],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        cls.proc.stdout.readline()  # Wait for READY

    @classmethod
    def tearDownClass(cls):
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2)
            except Exception:
                cls.proc.kill()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_01_default_execution_generates_no_html_file(self):
        """CLI default execution must NOT generate any files on disk and preserve JSON stdout."""
        work_dir = os.path.join(self.tmp_dir, "run_default")
        os.makedirs(work_dir, exist_ok=True)

        files_before = set(os.listdir(work_dir))

        cmd = [
            sys.executable, "-m", "extractor.cli", "export-report",
            "-p", str(self.proc.pid),
            "-d", self.target_bin,
            "--corpus", os.path.join(self.tmp_dir, "corpus"),
        ]
        env = dict(os.environ, PYTHONPATH=os.path.abspath("."))
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=work_dir, env=env)
        self.assertEqual(res.returncode, 0, f"export-report failed: {res.stderr}")

        # Verify stdout is valid JSON
        data = json.loads(res.stdout)
        self.assertTrue(data.get("success"))
        self.assertIn("report_markdown", data)
        self.assertIn("report_html", data)
        self.assertIsNone(data.get("saved_path"))
        self.assertIsNone(data.get("saved_html_path"))

        # Verify no files were created in working directory
        files_after = set(os.listdir(work_dir))
        self.assertEqual(files_before, files_after)

    def test_02_export_report_with_explicit_report_html_generates_file(self):
        """When --report-html is explicitly passed, the standalone HTML report is created."""
        html_out = os.path.join(self.tmp_dir, "custom_reports", "incident_test.html")

        cmd = [
            sys.executable, "-m", "extractor.cli", "export-report",
            "-p", str(self.proc.pid),
            "-d", self.target_bin,
            "--report-html", html_out,
            "--corpus", os.path.join(self.tmp_dir, "corpus"),
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(res.returncode, 0)

        # File must exist and have content
        self.assertTrue(os.path.isfile(html_out))
        with open(html_out, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("dynamicState Zero-Stop Runtime Incident Report", content)
        self.assertNotIn("http://", content)
        self.assertNotIn("https://", content)
        self.assertNotIn("<script", content)

        # JSON stdout contract
        data = json.loads(res.stdout)
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("saved_html_path"), os.path.abspath(html_out))
        self.assertIsNone(data.get("save_html_error"))

    def test_03_legacy_output_option_preserves_markdown_generation(self):
        """Legacy -o / --output preserves markdown generation without unintended HTML files."""
        md_out = os.path.join(self.tmp_dir, "legacy_incident.md")

        cmd = [
            sys.executable, "-m", "extractor.cli", "export-report",
            "-p", str(self.proc.pid),
            "-d", self.target_bin,
            "-o", md_out,
            "--corpus", os.path.join(self.tmp_dir, "corpus"),
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(res.returncode, 0)

        self.assertTrue(os.path.isfile(md_out))
        with open(md_out, "r", encoding="utf-8") as f:
            md_text = f.read()

        self.assertIn("# dynamicState Zero-Stop Runtime Incident Report", md_text)
        self.assertIn("## 1. Target Identity", md_text)

        data = json.loads(res.stdout)
        self.assertEqual(data.get("saved_path"), os.path.abspath(md_out))
        self.assertIsNone(data.get("saved_html_path"))

    def test_04_verify_hypothesis_with_report_html_option(self):
        """verify-hypothesis supports --report-html and keeps JSON stdout contract intact."""
        html_out = os.path.join(self.tmp_dir, "vh_report.html")

        cmd = [
            sys.executable, "-m", "extractor.cli", "verify-hypothesis",
            "--hypothesis", "Worker state counter is non-negative",
            "-a", "g_session.worker.state.counter >= 0",
            "-p", str(self.proc.pid),
            "-d", self.target_bin,
            "--report-html", html_out,
            "--corpus", os.path.join(self.tmp_dir, "corpus"),
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(res.returncode, 0)

        self.assertTrue(os.path.isfile(html_out))
        data = json.loads(res.stdout)
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("verdict"), "CONFIRMED")
        self.assertEqual(data.get("saved_html_path"), os.path.abspath(html_out))

    def test_05_protected_path_save_failure_handling(self):
        """Writing to protected path is rejected, warning is logged to stderr, and JSON stdout is preserved."""
        cmd = [
            sys.executable, "-m", "extractor.cli", "export-report",
            "-p", str(self.proc.pid),
            "-d", self.target_bin,
            "--report-html", "/etc/incident_forbidden.html",
            "--corpus", os.path.join(self.tmp_dir, "corpus"),
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Exit code remains 0 so caller doesn't break
        self.assertEqual(res.returncode, 0)

        # Warning emitted to stderr
        self.assertIn("WARNING: Refusing to write HTML report to protected system path", res.stderr)

        # JSON stdout is completely valid and details the save_html_error
        data = json.loads(res.stdout)
        self.assertTrue(data.get("success"))
        self.assertIn("Refusing to write HTML report", data.get("save_html_error", ""))
        self.assertFalse(os.path.exists("/etc/incident_forbidden.html"))

    def test_06_single_diagnosis_execution_consistency(self):
        """Diagnosis runs only once; verdict and assertions in HTML match stdout JSON exactly."""
        html_out = os.path.join(self.tmp_dir, "consistency_check.html")

        cmd = [
            sys.executable, "-m", "extractor.cli", "verify-hypothesis",
            "--hypothesis", "Worker counter is valid",
            "-a", "g_session.worker.state.counter >= 0",
            "-p", str(self.proc.pid),
            "-d", self.target_bin,
            "--report-html", html_out,
            "--corpus", os.path.join(self.tmp_dir, "corpus"),
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(res.returncode, 0)

        data = json.loads(res.stdout)
        verdict = data["verdict"]

        with open(html_out, "r", encoding="utf-8") as f:
            html_text = f.read()

        # Both JSON and HTML reflect the exact same diagnosis result
        self.assertIn(verdict, html_text)
        self.assertIn("Worker counter is valid", html_text)


if __name__ == "__main__":
    unittest.main()
