"""Regression tests for pstack-inspired Problem-Specific Playbook Router & Investigation Loop
across Core Playbooks, TrackingLedger Loop State Machine, MCP, CLI, and Web UI API.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

try:
    import pytest
    pytestmark = pytest.mark.unit
except ImportError:  # pragma: no cover
    pass
import urllib.request

import scripts.mcp_server as mcp_srv
from extractor.diagnostic_playbooks import PLAYBOOKS, list_playbooks, select_playbook
from extractor.state_intelligence import build_inconclusive_drilldown
from extractor.tracking_ledger import (
    GLOBAL_TRACKING_LEDGER,
    TrackingLedgerStore,
    enrich_tool_response,
)


class TestPlaybookRouter(unittest.TestCase):
    def test_all_six_playbooks_and_markdown_files_exist(self):
        pbs = list_playbooks("en")
        self.assertEqual(len(pbs), 6)
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for pb in pbs:
            md_path = os.path.join(root, pb["markdown_file"])
            self.assertTrue(os.path.isfile(md_path), f"Missing playbook markdown: {md_path}")
            self.assertTrue(pb["exit_predicate"])
            self.assertGreaterEqual(len(pb["steps"]), 3)

    def test_select_playbook_routes_by_symptom_and_recipes(self):
        self.assertEqual(select_playbook(symptom="RSS memory leak growing")["playbook_id"], "memory-leak-and-growth")
        self.assertEqual(select_playbook(symptom="tcache double free segfault")["playbook_id"], "heap-corruption-and-uaf")
        self.assertEqual(select_playbook(symptom="프로세스 데드락 락 경합 멈춤", lang="ko")["playbook_id"], "hang-deadlock-and-contention")
        self.assertEqual(select_playbook(symptom="EMFILE socket fd leak")["playbook_id"], "fd-and-ipc-stall")
        self.assertEqual(select_playbook(symptom="unexpected variable state machine flag")["playbook_id"], "state-and-variable-bug")
        self.assertEqual(select_playbook(symptom="intermittent spike under load")["playbook_id"], "intermittent-temporal-bug")

        # Recipe-driven routing (no symptom text)
        sel = select_playbook(
            diagnose_result={"checks_run": [{"recipe_id": "RECIPE_FD_LEAK", "status": "INCONCLUSIVE"}]}
        )
        self.assertEqual(sel["playbook_id"], "fd-and-ipc-stall")

    def test_inconclusive_drilldown_attaches_recommended_playbook(self):
        dd = build_inconclusive_drilldown(
            {
                "target": {"pid": 4242, "debug_image": "/usr/bin/worker"},
                "verdict": "INCONCLUSIVE",
                "checks_run": [{"recipe_id": "RECIPE_LOCK_CONTENTION", "status": "INCONCLUSIVE"}],
            },
            coverage={"verdict": "INCONCLUSIVE", "detail": {"blocking_gaps": [], "policy_skipped": []}},
        )
        self.assertIn("recommended_playbook", dd)
        self.assertEqual(dd["recommended_playbook"]["playbook_id"], "hang-deadlock-and-contention")


class TestPlaybookLoopStateMachine(unittest.TestCase):
    def test_plateau_triggers_pivot_then_source_bridge_meets_exit_predicate(self):
        store = TrackingLedgerStore()
        pb = select_playbook(symptom="memory leak")
        ledger = store.get_or_create("local:7777")
        ls0 = ledger.activate_playbook(pb, max_iterations=6)
        self.assertEqual(ls0["playbook_id"], "memory-leak-and-growth")
        self.assertEqual(ls0["predicate_status"], "OPEN")
        self.assertEqual(ls0["iteration"], 0)

        # Iter 1: empty heap_leak_candidates -> 1st plateau (still OPEN)
        r1 = enrich_tool_response(
            "runtime_heap_leak_candidates",
            {"success": True, "candidates": []},
            pid=7777,
            companion_elf="/usr/bin/app",
            ledger_store=store,
            now=10.0,
        )
        self.assertEqual(r1["tracking_context"]["loop_state"]["predicate_status"], "OPEN")
        self.assertEqual(r1["tracking_context"]["loop_state"]["consecutive_plateaus"], 1)

        # Iter 2: empty scan_heap_objects -> 2nd consecutive plateau -> PIVOT_REQUIRED with concrete pivot_recommendation
        r2 = enrich_tool_response(
            "runtime_scan_heap_objects",
            {"success": True, "objects": []},
            pid=7777,
            companion_elf="/usr/bin/app",
            ledger_store=store,
            now=15.0,
        )
        ls2 = r2["tracking_context"]["loop_state"]
        self.assertEqual(ls2["predicate_status"], "PIVOT_REQUIRED")
        self.assertIsNotNone(ls2["pivot_recommendation"])
        self.assertEqual(len(ls2["decision_log"]), 2)

        # Iter 3: correlate_source_and_state yields code_anchors -> MET!
        r3 = enrich_tool_response(
            "runtime_correlate_source_and_state",
            {"success": True, "verdict": "FAULT", "findings": [{"recipe_id": "RECIPE_HEAP_GROWTH", "status": "SUPPORTED", "severity": "HIGH"}], "correlations": [{"file": "src/cache.cpp", "line": 120, "variable_path": "g_cache"}]},
            pid=7777,
            companion_elf="/usr/bin/app",
            ledger_store=store,
            now=20.0,
        )
        ls3 = r3["tracking_context"]["loop_state"]
        self.assertEqual(ls3["predicate_status"], "MET")
        self.assertEqual(ls3["consecutive_plateaus"], 0)

    def test_hard_block_and_max_iterations_escape_hatches(self):
        store = TrackingLedgerStore()
        ledger = store.get_or_create("local:7778")
        ledger.activate_playbook(select_playbook(symptom="deadlock"), max_iterations=2)

        # Hard permission block -> BLOCKED
        rb = enrich_tool_response(
            "runtime_eval_memory_path",
            {"success": False, "error": "Permission denied: /proc/7778/mem"},
            pid=7778,
            ledger_store=store,
            now=1.0,
        )
        self.assertEqual(rb["tracking_context"]["loop_state"]["predicate_status"], "BLOCKED")

        # Max iterations reached -> EXHAUSTED
        ledger2 = store.get_or_create("local:7779")
        ledger2.activate_playbook(select_playbook(symptom="deadlock"), max_iterations=2)
        enrich_tool_response("runtime_trace_ipc_pipeline", {"success": True, "peers": []}, pid=7779, ledger_store=store, now=1.0)
        rx = enrich_tool_response("runtime_scan_heap_objects", {"success": True, "objects": []}, pid=7779, ledger_store=store, now=2.0)
        self.assertEqual(rx["tracking_context"]["loop_state"]["predicate_status"], "EXHAUSTED")


class TestMcpCliAndWebPlaybookIntegration(unittest.TestCase):
    def test_mcp_runtime_get_playbook_front_door_router(self):
        GLOBAL_TRACKING_LEDGER.clear()
        # Backward-compatible zero-arg call
        pb0 = json.loads(mcp_srv.runtime_get_playbook())
        self.assertTrue(pb0["success"])
        self.assertEqual(len(pb0["available_playbooks"]), 6)

        # Symptom + PID routing & loop activation
        pb1 = json.loads(mcp_srv.runtime_get_playbook(symptom="memory leak", pid=8888, max_iterations=5, language="ko"))
        self.assertTrue(pb1["success"])
        self.assertEqual(pb1["selected_playbook"]["playbook_id"], "memory-leak-and-growth")
        self.assertEqual(pb1["loop_state"]["playbook_id"], "memory-leak-and-growth")
        self.assertEqual(pb1["loop_state"]["max_iterations"], 5)

    def test_cli_playbook_subcommand(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run(
            [sys.executable, "-m", "extractor.cli", "playbook", "--symptom", "deadlock", "--json"],
            capture_output=True,
            text=True,
            cwd=root,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["success"])
        self.assertEqual(data["selected_playbook"]["playbook_id"], "hang-deadlock-and-contention")

        proc_list = subprocess.run(
            [sys.executable, "-m", "extractor.cli", "playbook", "--list", "--json"],
            capture_output=True,
            text=True,
            cwd=root,
            timeout=30,
        )
        self.assertEqual(proc_list.returncode, 0, proc_list.stderr)
        self.assertEqual(len(json.loads(proc_list.stdout)["playbooks"]), 6)

    def test_web_api_playbooks_and_tracking_loop_endpoints(self):
        from extractor.agent_runtime import AgentRuntime
        from extractor.web.server import DynamicStateWebServer

        GLOBAL_TRACKING_LEDGER.clear()
        srv = DynamicStateWebServer(("127.0.0.1", 0), AgentRuntime())
        port = srv.server_address[1]
        import threading
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            req1 = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/playbooks?symptom=fd+leak&pid=9999&activate=1",
                headers={"X-Session-Token": srv.session_token},
            )
            with urllib.request.urlopen(req1, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(data["success"])
            self.assertEqual(len(data["playbooks"]), 6)
            self.assertEqual(data["selected_playbook"]["playbook_id"], "fd-and-ipc-stall")
            self.assertEqual(data["loop_state"]["playbook_id"], "fd-and-ipc-stall")

            req2 = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/tracking/loop?pid=9999",
                headers={"X-Session-Token": srv.session_token},
            )
            with urllib.request.urlopen(req2, timeout=5) as resp2:
                loop_data = json.loads(resp2.read().decode("utf-8"))
            self.assertTrue(loop_data["success"])
            self.assertTrue(loop_data["active"])
            self.assertEqual(loop_data["tracking_context"]["loop_state"]["playbook_id"], "fd-and-ipc-stall")
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
