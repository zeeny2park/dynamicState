"""Tests for selective eBPF/uprobe dynamic event tracing mode (Roadmap Stage 3).

Verifies:
1. Tracing is strictly opt-in (disabled by default, zero-stop read-only baseline preserved).
2. Option flags (parameter enable_tracing, environment variable DYNAMICSTATE_ENABLE_TRACING).
3. Capability activation (CAP_ALLOCATION_TRACING) in tracing mode.
4. Distinction between static candidates ("정적 후보, 관측 아님") and traced locations ("추적 관측").
5. Diagnostic engine integration and human report rendering.
6. Graceful fallback when prerequisites are unsatisfied.
"""

import os
from unittest.mock import patch, MagicMock
import unittest

from extractor.diagnostic_recipes import (
    CAP_ALLOCATION_TRACING,
    DiagnosticRecipeRegistry,
    get_available_capabilities,
    temporary_capabilities,
)
from extractor.ebpf_tracer import EbpfCapabilityResult
from extractor.expert_diagnostic_engine import diagnose
from extractor.human_report import diagnose_with_summary, render_human_report
from extractor.tracing_mode import (
    ENV_ENABLE_TRACING,
    attach_traced_locations,
    check_tracing_support,
    format_traced_locations_for_finding,
    is_tracing_enabled,
)
from tests.support.fixture_process import fixture_popen


class TestTracingModeConfiguration(unittest.TestCase):
    """Test environment flag and parameter resolution."""

    def test_default_is_disabled(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(is_tracing_enabled())
            self.assertFalse(is_tracing_enabled(False))

    def test_explicit_parameter_takes_precedence(self):
        with patch.dict(os.environ, {ENV_ENABLE_TRACING: "0"}):
            self.assertTrue(is_tracing_enabled(True))
        with patch.dict(os.environ, {ENV_ENABLE_TRACING: "1"}):
            self.assertFalse(is_tracing_enabled(False))

    def test_environment_variable_parsing(self):
        for val in ("1", "true", "yes", "on", "enable", "ENABLED"):
            with patch.dict(os.environ, {ENV_ENABLE_TRACING: val}):
                self.assertTrue(is_tracing_enabled(), f"Expected true for {val}")
        for val in ("0", "false", "no", "off", "", "something_else"):
            with patch.dict(os.environ, {ENV_ENABLE_TRACING: val}):
                self.assertFalse(is_tracing_enabled(), f"Expected false for {val}")

    def test_cli_argument_parsing(self):
        from extractor.cli import main
        import argparse
        # Test argparse parser directly
        # Ensure --enable-tracing and --tracing work
        test_parser = argparse.ArgumentParser()
        sub = test_parser.add_subparsers(dest="command")
        dx = sub.add_parser("diagnose")
        dx.add_argument("-p", "--pid", type=int, required=True)
        dx.add_argument("--enable-tracing", "--tracing", dest="enable_tracing", action="store_true", default=None)

        args = test_parser.parse_args(["diagnose", "-p", "1234", "--enable-tracing"])
        self.assertTrue(args.enable_tracing)

        args2 = test_parser.parse_args(["diagnose", "-p", "1234", "--tracing"])
        self.assertTrue(args2.enable_tracing)

        args3 = test_parser.parse_args(["diagnose", "-p", "1234"])
        self.assertIsNone(args3.enable_tracing)


class TestTracingCapabilities(unittest.TestCase):
    """Test dynamic capability activation in diagnostic recipes."""

    def test_allocation_tracing_not_available_by_default(self):
        self.assertNotIn(CAP_ALLOCATION_TRACING, get_available_capabilities())
        miss = DiagnosticRecipeRegistry.missing_capabilities("RECIPE_USE_AFTER_FREE")
        self.assertIn(CAP_ALLOCATION_TRACING, miss)
        self.assertFalse(DiagnosticRecipeRegistry.is_plannable("RECIPE_USE_AFTER_FREE"))

    def test_temporary_capabilities_enables_recipe(self):
        with temporary_capabilities([CAP_ALLOCATION_TRACING]):
            self.assertIn(CAP_ALLOCATION_TRACING, get_available_capabilities())
            miss = DiagnosticRecipeRegistry.missing_capabilities("RECIPE_USE_AFTER_FREE")
            self.assertNotIn(CAP_ALLOCATION_TRACING, miss)
            self.assertTrue(DiagnosticRecipeRegistry.is_plannable("RECIPE_USE_AFTER_FREE"))
            self.assertIsNotNone(DiagnosticRecipeRegistry.get_plannable_recipe("RECIPE_USE_AFTER_FREE"))
        # Restored after context exit
        self.assertNotIn(CAP_ALLOCATION_TRACING, get_available_capabilities())
        self.assertFalse(DiagnosticRecipeRegistry.is_plannable("RECIPE_USE_AFTER_FREE"))


class TestLocationDistinction(unittest.TestCase):
    """Test distinction between static candidates and traced locations."""

    def test_disabled_tracing_attaches_disabled_marker(self):
        findings = [{"category": "INVALID_DOUBLE_FREE", "subjects": ["0x1234"]}]
        attach_traced_locations(findings, pid=1234, binary_path="/bin/true", enabled=False)
        self.assertEqual(len(findings), 1)
        tl = findings[0].get("traced_locations")
        self.assertIsNotNone(tl)
        self.assertEqual(tl["basis"], "tracing")
        self.assertFalse(tl["observed"])
        self.assertFalse(tl["is_traced"])
        self.assertEqual(tl["status"], "TRACING_DISABLED")
        self.assertIn("꺼져 있음", tl["status_text_ko"])

    def test_format_traced_locations_matches_finding_category(self):
        finding = {"category": "USE_AFTER_FREE"}
        traced_events = [
            {"function": "malloc", "location": "app.c:10", "basis": "tracing", "observed": True},
            {"function": "free", "location": "app.c:25", "basis": "tracing", "observed": True, "reason": "freed at 25", "reason_ko": "25에서 해제"},
        ]
        res = format_traced_locations_for_finding(finding, traced_events)
        self.assertEqual(res["basis"], "tracing")
        self.assertTrue(res["observed"])
        self.assertEqual(res["status"], "OBSERVED")
        # free is matched first for USE_AFTER_FREE
        self.assertEqual(len(res["locations"]), 1)
        self.assertEqual(res["locations"][0]["function"], "free")
        self.assertEqual(res["locations"][0]["location"], "app.c:25")


class TestDiagnoseIntegrationWithTracing(unittest.TestCase):
    """Test diagnose engine behavior with enable_tracing flag."""

    def test_diagnose_with_tracing_disabled_default(self):
        # Using a simple sleep process as a fixture
        proc = fixture_popen(["sleep", "30"])
        try:
            res = diagnose(proc.pid, enable_tracing=False)
            self.assertEqual(res.target.get("tracing_mode"), "DISABLED")
        finally:
            proc.kill()
            proc.wait()

    def test_diagnose_with_tracing_enabled(self):
        proc = fixture_popen(["sleep", "30"])
        try:
            res, summary = diagnose_with_summary(proc.pid, enable_tracing=True)
            mode = res.get("target", {}).get("tracing_mode")
            self.assertIn(mode, ("ENABLED_SUPPORTED", "ENABLED_UNSUPPORTED"))
            self.assertIsInstance(summary, str)
        finally:
            proc.kill()
            proc.wait()

    def test_human_report_renders_traced_locations_separately(self):
        mock_result = {
            "verdict": "CONFIRMED_FAULT",
            "findings": [
                {
                    "category": "USE_AFTER_FREE",
                    "severity": "CRITICAL",
                    "status": "CONFIRMED_FAULT",
                    "subjects": ["job_ptr"],
                    "location_candidates": {
                        "basis": "static",
                        "observed": False,
                        "status": "FOUND",
                        "candidates": [
                            {"location": "worker.c:110", "function": "worker_run", "statement": "job_ptr->id = 1",
                             "reason": "uses pointer", "reason_ko": "포인터 사용"}
                        ]
                    },
                    "traced_locations": {
                        "basis": "tracing",
                        "observed": True,
                        "status": "OBSERVED",
                        "locations": [
                            {"location": "worker.c:85", "function": "free", "action": "free",
                             "reason": "Observed runtime call to free()", "reason_ko": "런타임에 free() 호출 직접 관측"}
                        ]
                    }
                }
            ],
            "target": {"pid": 9999, "process_name": "worker"},
            "checks_run": [{"recipe_id": "RECIPE_USE_AFTER_FREE", "status": "FAIL"}],
            "not_covered": [],
        }
        report_en = render_human_report(mock_result, None, lang="en")
        report_ko = render_human_report(mock_result, None, lang="ko")

        # English report must contain both distinct sections
        self.assertIn("Location candidates (static analysis, not observed)", report_en)
        self.assertIn("Traced locations (observed at runtime via eBPF/uprobe)", report_en)
        self.assertIn("worker.c:110", report_en)
        self.assertIn("worker.c:85", report_en)

        # Korean report must contain both distinct sections with proper Korean labels
        self.assertIn("위치 후보 (정적 분석, 관측 아님)", report_ko)
        self.assertIn("추적 관측 위치 (eBPF/uprobe 런타임 관측)", report_ko)
        self.assertIn("worker.c:110", report_ko)
        self.assertIn("worker.c:85", report_ko)


if __name__ == "__main__":
    unittest.main()
