"""
tests/test_phase2_3_mcp_recipe_integration.py

Integration tests for Phase 2.3-A: MCP Diagnostic Recipe Integration (GAP-P3-01).

Verifies:
1. Legacy watch modes (instant_xray, before_after_diff, timeseries_watch) work cleanly.
2. Phase 2.1 diagnostic recipes in DiagnosticRecipeRegistry can be dispatched through runtime_run_diagnostic_recipe.
3. Structured findings, checks, and evidence records are returned.
4. Case-insensitivity and prefix normalization (e.g. 'double_free' -> 'RECIPE_DOUBLE_FREE').
5. Unknown recipe errors fail descriptively.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.diagnostic_recipes import DiagnosticRecipeRegistry
from scripts.mcp_server import runtime_run_diagnostic_recipe
from tests.support.fixture_process import fixture_popen


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class TestPhase23McpRecipeIntegration(unittest.TestCase):
    """Phase 2.3-A MCP Diagnostic Recipe Integration Test Suite."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_p23_mcp_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        os.makedirs(cls.corpus_dir, exist_ok=True)

        cls.fixture_src = os.path.join(PROJECT_ROOT, "tests", "fixtures", "real_runtime", "main.cpp")
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
            ],
            check=True,
        )
        cls.stripped_bin = os.path.join(cls.work_dir, "app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def setUp(self):
        self._procs = []
        import scripts.mcp_server as mcp_mod
        self.original_runtime = mcp_mod.runtime
        self.test_runtime = AgentRuntime(corpus_dir=self.corpus_dir)
        mcp_mod.runtime = self.test_runtime

    def tearDown(self):
        import scripts.mcp_server as mcp_mod
        mcp_mod.runtime = self.original_runtime
        for p in self._procs:
            try:
                p.kill()
                p.wait(timeout=2)
            except Exception:
                pass
            for s in (p.stdin, p.stdout, p.stderr):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _start_target(self) -> subprocess.Popen:
        p = fixture_popen(
            [self.stripped_bin],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._procs.append(p)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            line = p.stdout.readline()
            if "READY" in line:
                break
        return p

    def test_legacy_mode_instant_xray(self):
        """Legacy mode instant_xray delegates to WatchSessionManager."""
        proc = self._start_target()
        res_str = runtime_run_diagnostic_recipe(
            pid=proc.pid,
            companion_elf=self.debug_bin,
            recipe="instant_xray",
        )
        res = json.loads(res_str)
        self.assertTrue(res.get("success"), f"Expected success but got: {res}")
        self.assertEqual(res.get("recipe"), "instant_xray")
        self.assertIn("flattened_state", res)
        self.assertIn("results", res)

    def test_expert_recipe_double_free(self):
        """Phase 2.1 RECIPE_DOUBLE_FREE dispatches to ExpertDiagnosticEngine and evaluates cleanly."""
        proc = self._start_target()
        res_str = runtime_run_diagnostic_recipe(
            pid=proc.pid,
            companion_elf=self.debug_bin,
            recipe="RECIPE_DOUBLE_FREE",
        )
        res = json.loads(res_str)
        self.assertTrue(res.get("success"), f"Expected success but got: {res}")
        self.assertEqual(res.get("recipe_id"), "RECIPE_DOUBLE_FREE")
        self.assertIn("investigation_id", res)
        self.assertIn("checks", res)
        self.assertIn("evidence_records", res)

    def test_expert_recipe_case_insensitivity_and_prefix_normalization(self):
        """Recipe name without 'RECIPE_' prefix and lowercase ('use_after_free') normalizes and executes."""
        proc = self._start_target()
        res_str = runtime_run_diagnostic_recipe(
            pid=proc.pid,
            companion_elf=self.debug_bin,
            recipe="use_after_free",
        )
        res = json.loads(res_str)
        self.assertTrue(res.get("success"), f"Expected success but got: {res}")
        self.assertEqual(res.get("recipe_id"), "RECIPE_USE_AFTER_FREE")

    def test_expert_recipe_deadlock(self):
        """Phase 2.1 RECIPE_POTENTIAL_DEADLOCK_PATTERNS executes and returns structured conclusion."""
        proc = self._start_target()
        res_str = runtime_run_diagnostic_recipe(
            pid=proc.pid,
            companion_elf=self.debug_bin,
            recipe="RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
        )
        res = json.loads(res_str)
        self.assertTrue(res.get("success"), f"Expected success but got: {res}")
        self.assertEqual(res.get("recipe_id"), "RECIPE_POTENTIAL_DEADLOCK_PATTERNS")
        self.assertEqual(res.get("domain"), "CONCURRENCY")

    def test_all_22_recipes_execute_meaningfully(self):
        """All 22 DiagnosticRecipeRegistry recipes can be executed through MCP and return structured results."""
        proc = self._start_target()
        from extractor.diagnostic_recipes import BUILTIN_RECIPE_IDS
        recipe_ids = list(BUILTIN_RECIPE_IDS)  # IMP-018: plugins add recipes
        self.assertEqual(len(recipe_ids), 22, f"Expected 22 recipes, got {len(recipe_ids)}")

        for rid in recipe_ids:
            res_str = runtime_run_diagnostic_recipe(
                pid=proc.pid,
                companion_elf=self.debug_bin,
                recipe=rid,
            )
            res = json.loads(res_str)
            self.assertTrue(res.get("success"), f"Recipe {rid} failed: {res}")
            self.assertEqual(res.get("recipe_id"), rid)
            self.assertIn("domain", res)
            self.assertIn("category", res)
            self.assertIn("checks", res)
            self.assertIn("conclusion", res)
            self.assertIn(res.get("status"), ["PASS", "FAIL", "NOT_APPLICABLE", "INCONCLUSIVE", "COMPLETED", "BUDGET_EXHAUSTED"])

    def test_unknown_recipe_fails_descriptively(self):
        """Unknown recipe name produces a clear error."""
        proc = self._start_target()
        res_str = runtime_run_diagnostic_recipe(
            pid=proc.pid,
            companion_elf=self.debug_bin,
            recipe="NON_EXISTENT_MAGIC_RECIPE",
        )
        res = json.loads(res_str)
        self.assertFalse(res.get("success"))
        self.assertIn("Unknown diagnostic recipe", res.get("error", ""))


if __name__ == "__main__":
    unittest.main()
