"""Phase 34 (Phase 3 Roadmap) Test Suite:
1. Golden Baseline save, list, and live drift comparison (Web API + MCP).
2. Guided Diagnostic Recipes: Instant State X-Ray and Before/After State Diff.
3. Guided Diagnostic Recipe: Auto Time-Series Watch classifying active vs stuck variables.
4. Web UI Scenario Launchpad, Smart Watch Chips, and Golden Baseline HTML/JS integration.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from extractor.agent_runtime import AgentRuntime
from extractor.watch_session import WatchSessionManager
from extractor.web.server import WebApiAdapter
import scripts.mcp_server as mcp_srv


class TestPhase34ScenarioRecipesAndGoldenBaseline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_p34_")
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

    def tearDown(self):
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

    def _start_target(self, bin_path: str) -> subprocess.Popen:
        p = subprocess.Popen(
            [bin_path],
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

    def test_01_golden_baseline_save_list_and_live_drift_comparison(self):
        """Verify saving a Golden Baseline and comparing live mutated process state against it."""
        proc = self._start_target(self.stripped_bin)
        rt = AgentRuntime(corpus_dir=self.corpus_dir)
        web = WebApiAdapter(rt)

        # 1. Save Golden Baseline while in initial healthy state
        save_res = web.save_golden_baseline_api({
            "pid": proc.pid,
            "companion_elf": self.debug_bin,
            "label": "Healthy_Boot_State",
            "expressions": [
                "g_session.worker.state",
                "g_heap_state->counter",
                "g_node_a.value",
            ],
        })
        self.assertTrue(save_res["success"], f"Save failed: {save_res}")
        baseline_id = save_res["data"]["baseline_id"]
        self.assertEqual(save_res["data"]["label"], "Healthy_Boot_State")
        self.assertEqual(save_res["data"]["flattened_values"]["g_session.worker.state.counter"], 42)
        self.assertEqual(save_res["data"]["flattened_values"]["g_heap_state->counter"], 99)

        # 2. List Golden Baselines
        list_res = web.list_golden_baselines_api()
        self.assertTrue(list_res["success"])
        ids = [b["baseline_id"] for b in list_res["data"]["baselines"]]
        self.assertIn(baseline_id, ids)

        # 3. Mutate live process
        proc.stdin.write("MUTATE\n")
        proc.stdin.flush()
        while True:
            l = proc.stdout.readline()
            if "MUTATED" in l or not l:
                break

        # 4. Compare live process against Golden Baseline via Web API and MCP
        cmp_res = web.compare_golden_baseline_api({
            "baseline_id": baseline_id,
            "pid": proc.pid,
            "companion_elf": self.debug_bin,
        })
        self.assertTrue(cmp_res["success"], f"Compare failed: {cmp_res}")
        cmp_data = cmp_res["data"]
        self.assertEqual(cmp_data["stop_duration_ms"], 0.0)
        changed = {c["path"]: c for c in cmp_data["changed"]}
        unchanged = {u["path"]: u for u in cmp_data["unchanged"]}

        self.assertIn("g_session.worker.state.counter", changed)
        self.assertEqual(changed["g_session.worker.state.counter"]["golden_value"], 42)
        self.assertEqual(changed["g_session.worker.state.counter"]["live_value"], 100)
        self.assertEqual(changed["g_session.worker.state.counter"]["delta"], 58)
        self.assertIn("g_node_a.value", changed)
        self.assertEqual(changed["g_node_a.value"]["live_value"], 999)
        self.assertIn("g_heap_state->counter", unchanged)
        self.assertEqual(unchanged["g_heap_state->counter"]["value"], 99)

    def test_02_diagnostic_recipe_instant_xray_and_before_after_diff(self):
        """Verify Instant X-Ray and Before/After Diff diagnostic recipes via MCP and Web API."""
        proc = self._start_target(self.stripped_bin)
        old_rt = mcp_srv.runtime
        mcp_srv.runtime = AgentRuntime(corpus_dir=self.corpus_dir)
        try:
            # 1. Instant X-Ray with auto-selected DWARF expressions
            xray_raw = mcp_srv.runtime_run_diagnostic_recipe(
                pid=proc.pid,
                companion_elf=self.debug_bin,
                recipe="instant_xray",
            )
            xray = json.loads(xray_raw)
            self.assertTrue(xray["success"], f"X-Ray failed: {xray}")
            self.assertEqual(xray["recipe"], "instant_xray")
            self.assertEqual(xray["stop_duration_ms"], 0.0)
            self.assertGreater(len(xray["results"]), 0)

            # 2. Before/After Diff recipe across live mutation
            def _trigger_mut():
                time.sleep(0.12)
                try:
                    proc.stdin.write("MUTATE\n")
                    proc.stdin.flush()
                except Exception:
                    pass

            th = threading.Thread(target=_trigger_mut, daemon=True)
            th.start()
            diff_raw = mcp_srv.runtime_run_diagnostic_recipe(
                pid=proc.pid,
                companion_elf=self.debug_bin,
                recipe="before_after_diff",
                expressions=["g_session.worker.state", "g_heap_state->counter"],
                duration_ms=300,
            )
            th.join(timeout=1.0)
            diff_data = json.loads(diff_raw)
            self.assertTrue(diff_data["success"])
            changed_paths = {c["path"]: (c["before"], c["after"]) for c in diff_data["changed"]}
            self.assertEqual(changed_paths.get("g_session.worker.state.counter"), (42, 100))
        finally:
            mcp_srv.runtime = old_rt

    def test_03_diagnostic_recipe_timeseries_watch_active_vs_stuck(self):
        """Verify timeseries_watch recipe distinguishes actively incrementing variables from stuck/static state."""
        proc = self._start_target(self.stripped_bin)
        mgr = WatchSessionManager(corpus_dir=self.corpus_dir)

        res = mgr.run_diagnostic_recipe(
            recipe="timeseries_watch",
            pid=proc.pid,
            companion_elf_path=self.debug_bin,
            expressions=[
                "g_heartbeat",
                "g_thread_a.counter",
                "g_session.worker.state.counter",
                "g_heap_state->counter",
            ],
            duration_ms=400,
            interval_ms=100,
        )
        self.assertEqual(res["recipe"], "timeseries_watch")
        self.assertGreaterEqual(res["samples_captured"], 3)
        active_names = {a["name"] for a in res["active_variables"]}
        stuck_names = {s["name"] for s in res["stuck_variables"]}

        # g_heartbeat and g_thread_a.counter continuously increment in worker threads
        self.assertTrue("g_heartbeat" in active_names or "g_thread_a.counter" in active_names)
        # g_session.worker.state.counter and g_heap_state->counter stay fixed without MUTATE command
        self.assertIn("g_session.worker.state.counter", stuck_names)
        self.assertIn("g_heap_state->counter", stuck_names)

    def test_04_phase3_web_ui_elements_and_routes(self):
        """Verify Phase 3 UI elements exist in index.html."""
        html_path = os.path.join(PROJECT_ROOT, "extractor", "web", "static", "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        for el_id in (
            "te-smart-watch-chips-card",
            "te-smart-watch-chips",
            "scenario-recipes-launchpad",
            "btn-recipe-instant-xray",
            "btn-recipe-before-after",
            "btn-recipe-auto-watch",
            "scenario-recipe-output",
            "card-golden-baseline",
            "input-golden-baseline-label",
            "btn-save-golden-baseline",
            "select-golden-baseline",
            "btn-compare-golden-baseline",
            "golden-baseline-diff-output",
        ):
            self.assertIn(f'id="{el_id}"', html, f"Missing Phase 3 UI element #{el_id}")


if __name__ == "__main__":
    unittest.main()
