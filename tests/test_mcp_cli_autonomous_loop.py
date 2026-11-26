"""Regression tests for MCP Prompts/Resources/Autonomous Loop, Disk Ledger Persistence,
Compact Payload, Coding-Agent Handoff Brief, CI Exit Codes, and CLI `loop` / `diff-runs`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

import scripts.mcp_server as mcp_srv
from extractor.playbook_loop_runner import (
    EXIT_BLOCKED,
    EXIT_DEGRADED,
    EXIT_FAULT,
    EXIT_HEALTHY,
    EXIT_INCONCLUSIVE,
    compact_payload,
    diff_diagnostic_runs,
    render_handoff_markdown,
    run_playbook_loop,
    verdict_to_exit_code,
)
from extractor.tracking_ledger import (
    GLOBAL_TRACKING_LEDGER,
    TrackingLedgerStore,
    enrich_tool_response,
)


class TestDiskLedgerAndCompactPayload(unittest.TestCase):
    def test_disk_ledger_persistence_across_store_restarts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store1 = TrackingLedgerStore(persist_dir=tmpdir)
            enrich_tool_response(
                "runtime_symbol_search",
                {"success": True, "query": "g_missing", "symbols": []},
                pid=3100,
                companion_elf="/usr/bin/svc",
                args={"query": "g_missing"},
                ledger_store=store1,
            )
            enrich_tool_response(
                "runtime_correlate_source_and_state",
                {"success": True, "verdict": "FAULT", "findings": [{"recipe_id": "RECIPE_HEAP_GROWTH", "status": "SUPPORTED", "severity": "HIGH"}], "correlations": [{"file": "src/main.cpp", "line": 77, "function": "run"}]},
                pid=3100,
                companion_elf="/usr/bin/svc",
                ledger_store=store1,
            )

            # Brand-new store pointing at the same persist_dir should reload state seamlessly
            store2 = TrackingLedgerStore(persist_dir=tmpdir)
            reloaded = store2.get_or_create("local:3100")
            self.assertEqual(len(reloaded.decision_log), 2)
            self.assertEqual(len(reloaded.code_anchors), 1)
            self.assertEqual(reloaded.code_anchors[0]["file"], "src/main.cpp")
            self.assertEqual(reloaded.predicate_status, "MET")
            self.assertTrue(any("g_missing" in sig for sig in reloaded.dead_end_signatures))

    def test_compact_payload_truncates_large_lists_but_preserves_tracking(self):
        big = {
            "success": True,
            "verdict": "INCONCLUSIVE",
            "threads": [{"tid": i} for i in range(50)],
            "code_anchors": [{"file": "a.c", "line": 10}],
            "tracking_context": {"calls_in_session": 2},
        }
        c = compact_payload(big, max_items=5)
        self.assertEqual(len(c["threads"]), 5)
        self.assertEqual(c["threads_truncated_from"], 50)
        self.assertEqual(c["code_anchors"], [{"file": "a.c", "line": 10}])
        self.assertEqual(c["tracking_context"]["calls_in_session"], 2)


class TestAutonomousPlaybookLoopAndExitCodes(unittest.TestCase):
    def test_autonomous_loop_pivots_on_plateau_and_emits_handoff_markdown(self):
        store = TrackingLedgerStore()
        calls_seen = []

        def fake_exec(tool_name, call_args):
            calls_seen.append(tool_name)
            if tool_name in ("runtime_diagnose_process", "runtime_heap_leak_candidates"):
                return {"success": True, "verdict": "INCONCLUSIVE", "candidates": []}
            if tool_name == "runtime_scan_heap_objects":
                return {
                    "success": True,
                    "objects": [{"address": "0x555555610000", "class": "Session"}],
                    "findings": [{"file": "src/session.cpp", "line": 210, "variable_path": "g_sessions"}],
                }
            return {
                "success": True,
                "verdict": "FAULT",
                "correlations": [{"file": "src/session.cpp", "line": 210, "variable_path": "g_sessions"}],
            }

        res = run_playbook_loop(
            pid=4100,
            symptom="memory leak",
            executor=fake_exec,
            companion_elf="/usr/bin/app",
            max_iterations=5,
            time_budget_s=10.0,
            lang="ko",
            ledger_store=store,
        )
        self.assertEqual(res["playbook_id"], "memory-leak-and-growth")
        self.assertGreaterEqual(res["pivots_taken"], 1)
        self.assertIn("runtime_scan_heap_objects", calls_seen)
        self.assertTrue(res["code_anchors"])
        self.assertIn("src/session.cpp:210", res["handoff_markdown"])
        self.assertIn("결정 로그", res["handoff_markdown"])

    def test_standard_ci_exit_codes_and_fail_on_filter(self):
        self.assertEqual(verdict_to_exit_code("HEALTHY"), EXIT_HEALTHY)
        self.assertEqual(verdict_to_exit_code("FAULT"), EXIT_FAULT)
        self.assertEqual(verdict_to_exit_code("DEGRADED"), EXIT_DEGRADED)
        self.assertEqual(verdict_to_exit_code("INCONCLUSIVE"), EXIT_INCONCLUSIVE)
        self.assertEqual(verdict_to_exit_code("INCONCLUSIVE", predicate_status="BLOCKED"), EXIT_BLOCKED)
        # fail_on filter ignores non-matching severities
        self.assertEqual(verdict_to_exit_code("DEGRADED", fail_on=["fault"]), EXIT_HEALTHY)
        self.assertEqual(verdict_to_exit_code("FAULT", fail_on=["fault"]), EXIT_FAULT)

    def test_diff_diagnostic_runs_detects_regression_and_metric_deltas(self):
        before = {
            "verdict": "HEALTHY",
            "process_profile": {"summary": {"rss_kb": 50000, "open_fds": 20, "thread_count": 4}},
            "findings": [],
        }
        after = {
            "verdict": "FAULT",
            "process_profile": {"summary": {"rss_kb": 95000, "open_fds": 85, "thread_count": 4}},
            "findings": [{"recipe_id": "RECIPE_FD_LEAK", "summary": "FDs growing +65"}],
        }
        diff = diff_diagnostic_runs(before, after)
        self.assertTrue(diff["regressed"])
        self.assertTrue(diff["verdict_changed"])
        self.assertEqual(diff["metric_deltas"]["rss_kb"]["delta"], 45000)
        self.assertEqual(diff["metric_deltas"]["open_fds"]["delta"], 65)
        self.assertEqual(len(diff["new_findings"]), 1)


class TestMcpPromptsResourcesAndCliCommands(unittest.TestCase):
    def test_mcp_prompts_and_resources(self):
        GLOBAL_TRACKING_LEDGER.clear()
        enrich_tool_response(
            "runtime_correlate_source_and_state",
            {"success": True, "correlations": [{"file": "src/lock.c", "line": 55, "function": "acquire"}]},
            pid=5200,
        )

        # Prompts
        txt = mcp_srv.diagnose_loop(pid="5200", symptom="deadlock")
        self.assertIn("hang-deadlock-and-contention", txt)
        self.assertIn("Exit Predicate", txt)
        self.assertIn("memory-leak-and-growth", mcp_srv.triage_leak(pid="5200"))
        self.assertIn("heap-corruption-and-uaf", mcp_srv.triage_corruption(pid="5200"))

        # Resources
        pb_res = json.loads(mcp_srv.resource_playbook("fd-and-ipc-stall"))
        self.assertEqual(pb_res["playbook_id"], "fd-and-ipc-stall")

        dl_res = json.loads(mcp_srv.resource_ledger_decision_log("local", "5200"))
        self.assertTrue(dl_res["active"])
        self.assertEqual(len(dl_res["decision_log"]), 1)

        ca_res = json.loads(mcp_srv.resource_ledger_code_anchors("local", "5200"))
        self.assertTrue(ca_res["active"])
        self.assertEqual(ca_res["code_anchors"][0]["file"], "src/lock.c")

    def test_cli_diff_runs_subcommand_and_regression_exit_code(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as tmpdir:
            bpath = os.path.join(tmpdir, "before.json")
            apath = os.path.join(tmpdir, "after.json")
            with open(bpath, "w") as f:
                json.dump({"verdict": "HEALTHY", "process_profile": {"summary": {"rss_kb": 10000}}, "findings": []}, f)
            with open(apath, "w") as f:
                json.dump(
                    {
                        "verdict": "FAULT",
                        "process_profile": {"summary": {"rss_kb": 40000}},
                        "findings": [{"recipe_id": "RECIPE_HEAP_GROWTH", "summary": "heap grew"}],
                    },
                    f,
                )
            proc = subprocess.run(
                [sys.executable, "-m", "extractor.cli", "diff-runs", bpath, apath, "--fail-on-regression", "--json"],
                capture_output=True,
                text=True,
                cwd=root,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 2)
            out = json.loads(proc.stdout)
            self.assertTrue(out["regressed"])
            self.assertEqual(out["metric_deltas"]["rss_kb"]["delta"], 30000)


if __name__ == "__main__":
    unittest.main()
