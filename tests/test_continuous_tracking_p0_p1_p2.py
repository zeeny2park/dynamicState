"""Regression tests for P0/P1/P2 continuous tracking improvements:
- P0: Cross-call Investigation Ledger & anti-looping (`already_tried` suppression)
- P0: Temporal Escalation (`runtime_capture_and_diff` & `runtime_watch_until_condition` with concrete thresholds)
- P1: Repeat-call Delta Summary (`delta_from_last_call` for callstacks, heap leaks, eval_memory_path)
- P1: Coding-agent Source-Code Bridge (`code_anchors` & `runtime_correlate_source_and_state` chaining)
- P1: Failure/Empty-result Self-Recovery (`recovery_actions`)
- P2: MCP Tool-Surface Tiering (`MCP_TOOL_TIERS`, `get_mcp_tool_tiers`, `runtime_get_playbook`)
"""

from __future__ import annotations

import json
import unittest

import scripts.mcp_server as mcp_srv
from extractor import agent_skill
from extractor.state_intelligence import (
    build_inconclusive_drilldown,
    build_narrow_tool_next_steps,
    build_suggested_actions,
)
from extractor.tracking_ledger import (
    TrackingLedgerStore,
    build_recovery_actions,
    enrich_tool_response,
    extract_code_anchors,
)


class TestTrackingLedgerAndDelta(unittest.TestCase):
    def test_cross_call_ledger_and_anti_looping_suppression(self):
        store = TrackingLedgerStore()
        # Call 1: symbol search for 'mutex lock queue state' returns 0 symbols (dead-end)
        r1 = enrich_tool_response(
            "runtime_symbol_search",
            {"success": True, "query": "mutex lock queue state", "symbols": []},
            pid=7001,
            companion_elf="/usr/bin/app",
            args={"query": "mutex lock queue state"},
            ledger_store=store,
            now=100.0,
        )
        self.assertEqual(r1["tracking_context"]["calls_in_session"], 1)
        self.assertEqual(r1["tracking_context"]["dead_end_calls_suppressed_ready"], 1)
        # Should include self-recovery actions for empty symbol search
        rec_tools = [a["mcp_tool"] for a in r1.get("recovery_actions") or []]
        self.assertIn("runtime_symbol_search", rec_tools)  # fast_only=True retry
        self.assertIn("runtime_scan_heap_objects", rec_tools)

        # Call 2: thread callstacks sees lock waiter -> normally recommends runtime_symbol_search(query="mutex lock queue state")
        # Ledger must suppress that exact dead-end signature!
        r2 = enrich_tool_response(
            "runtime_inspect_thread_callstack_and_locks",
            {
                "success": True,
                "threads": [
                    {
                        "tid": 7002,
                        "state": "S",
                        "syscall": "futex",
                        "waiting_on_lock": True,
                        "lock_addr": "0x601040",
                        "frames": [{"function": "queue_pop", "source_location": "src/queue.c:88"}],
                    }
                ],
            },
            pid=7001,
            companion_elf="/usr/bin/app",
            ledger_store=store,
            now=105.0,
        )
        self.assertEqual(r2["tracking_context"]["calls_in_session"], 2)
        self.assertTrue(r2.get("suppressed_repeat_actions"))
        self.assertTrue(any("runtime_symbol_search" in s for s in r2["suppressed_repeat_actions"]))
        # Code anchors extracted from frame
        self.assertTrue(r2.get("code_anchors"))
        self.assertEqual(r2["code_anchors"][0]["file"], "src/queue.c")
        self.assertEqual(r2["code_anchors"][0]["line"], 88)

    def test_repeat_call_delta_for_threads_heap_and_eval(self):
        store = TrackingLedgerStore()
        # Thread callstacks Call 1
        enrich_tool_response(
            "runtime_inspect_thread_callstack_and_locks",
            {
                "success": True,
                "threads": [
                    {"tid": 10, "state": "S", "syscall": "futex", "waiting_on_lock": True, "lock_addr": "0x100", "frames": [{"function": "lock_a"}]},
                    {"tid": 11, "state": "S", "syscall": "epoll_wait", "waiting_on_lock": False, "frames": [{"function": "net_loop"}]},
                ],
            },
            pid=8001,
            ledger_store=store,
            now=10.0,
        )
        # Thread callstacks Call 2 (12s later): tid 10 still stuck on same lock, tid 11 progressed, tid 12 spawned
        r2 = enrich_tool_response(
            "runtime_inspect_thread_callstack_and_locks",
            {
                "success": True,
                "threads": [
                    {"tid": 10, "state": "S", "syscall": "futex", "waiting_on_lock": True, "lock_addr": "0x100", "frames": [{"function": "lock_a"}]},
                    {"tid": 11, "state": "R", "syscall": "", "waiting_on_lock": False, "frames": [{"function": "handle_req"}]},
                    {"tid": 12, "state": "R", "syscall": "", "waiting_on_lock": False, "frames": [{"function": "worker"}]},
                ],
            },
            pid=8001,
            ledger_store=store,
            now=22.0,
        )
        delta = r2["delta_from_last_call"]
        self.assertEqual(delta["elapsed_s"], 12.0)
        self.assertEqual(delta["stuck_count"], 1)
        self.assertEqual(delta["stuck_threads"][0]["tid"], 10)
        self.assertIn(11, delta["progressed_tids"])
        self.assertIn(12, delta["new_tids"])

        # Heap leak candidates Call 1 & Call 2
        enrich_tool_response(
            "runtime_heap_leak_candidates",
            {"success": True, "candidates": [{"chunk_size": 4096, "count": 10}]},
            pid=8001,
            ledger_store=store,
            now=30.0,
        )
        rh2 = enrich_tool_response(
            "runtime_heap_leak_candidates",
            {"success": True, "candidates": [{"chunk_size": 4096, "count": 45}]},
            pid=8001,
            ledger_store=store,
            now=40.0,
        )
        hdelta = rh2["delta_from_last_call"]
        self.assertEqual(hdelta["growing_size_classes"][0]["chunk_size"], 4096)
        self.assertEqual(hdelta["growing_size_classes"][0]["count_delta"], 35)

        # Eval memory path Call 1 & Call 2
        enrich_tool_response(
            "runtime_eval_memory_path",
            {"success": True, "results": {"g_queue.size": {"value": 100}, "g_flag": {"value": 1}}},
            pid=8001,
            ledger_store=store,
            now=50.0,
        )
        re2 = enrich_tool_response(
            "runtime_eval_memory_path",
            {"success": True, "results": {"g_queue.size": {"value": 250}, "g_flag": {"value": 1}}},
            pid=8001,
            ledger_store=store,
            now=55.0,
        )
        edelta = re2["delta_from_last_call"]
        self.assertEqual(len(edelta["changed_expressions"]), 1)
        self.assertEqual(edelta["changed_expressions"][0]["expression"], "g_queue.size")
        self.assertEqual(edelta["unchanged_expressions"], ["g_flag"])


class TestTemporalEscalationAndRecovery(unittest.TestCase):
    def test_inconclusive_temporal_recipe_escalates_to_diff_and_condition_watch(self):
        coverage = {
            "verdict": "INCONCLUSIVE",
            "verdict_qualifier": "NO_FAULT_LIMITED_OBSERVATION",
            "qualifier_label_en": "Partial observation",
            "qualifier_label_ko": "부분 관측",
            "one_liner_en": "1 check undecided",
            "one_liner_ko": "1개 검사 판정 불가",
            "detail": {"blocking_gaps": [], "policy_skipped": [], "undecided": ["RECIPE_HEAP_RETENTION"], "failed": []},
        }
        profile = {"summary": {"rss_kb": 100000, "open_fds": 42, "thread_count": 8}}
        result = {
            "target": {"pid": 9001, "debug_image": "/usr/bin/server"},
            "verdict": "INCONCLUSIVE",
            "checks_run": [{"recipe_id": "RECIPE_HEAP_RETENTION", "status": "INCONCLUSIVE"}],
        }
        actions = build_suggested_actions(result, profile=profile, coverage=coverage)
        tools = [a["mcp_tool"] for a in actions]
        self.assertIn("runtime_capture_and_diff", tools)
        self.assertIn("runtime_watch_until_condition", tools)

        diff_act = next(a for a in actions if a["mcp_tool"] == "runtime_capture_and_diff")
        self.assertEqual(diff_act["mcp_args"]["wait_ms"], 5000)

        watch_act = next(a for a in actions if a["mcp_tool"] == "runtime_watch_until_condition")
        self.assertEqual(watch_act["mcp_args"]["timeout_ms"], 30000)
        self.assertIn("rss_kb > 115000", watch_act["mcp_args"]["condition"])

        dd = build_inconclusive_drilldown(result, profile=profile, coverage=coverage, suggested_actions=actions)
        self.assertTrue(any(c["cause_code"] == "temporal_window_too_short" for c in dd["causes"]))

    def test_source_code_bridge_chaining_and_error_recovery(self):
        # eval_memory_path -> runtime_correlate_source_and_state + runtime_capture_and_diff
        steps = build_narrow_tool_next_steps(
            "runtime_eval_memory_path",
            {"results": {"g_state.mode": {"value": 3}}},
            pid=9001,
            companion_elf="/usr/bin/server",
        )
        tools = [s["mcp_tool"] for s in steps]
        self.assertEqual(tools[0], "runtime_correlate_source_and_state")
        self.assertIn("runtime_capture_and_diff", tools)

        # Error recovery on failed eval_memory_path
        rec = build_recovery_actions(
            "runtime_eval_memory_path",
            {"success": False, "error": "member 'bad_field' not found in struct Cache"},
            pid=9001,
            companion_elf="/usr/bin/server",
            args={"expressions": ["g_cache->bad_field"]},
        )
        rec_tools = [a["mcp_tool"] for a in rec]
        self.assertIn("runtime_symbol_search", rec_tools)
        self.assertIn("runtime_coerce_expression", rec_tools)
        sym_act = next(a for a in rec if a["mcp_tool"] == "runtime_symbol_search")
        self.assertEqual(sym_act["mcp_args"]["query"], "g_cache")

        # Permission denied recovery
        perm_rec = build_recovery_actions(
            "runtime_eval_memory_path",
            {"success": False, "error": "Permission denied: /proc/9001/mem"},
            pid=9001,
        )
        self.assertEqual(perm_rec[0]["mcp_tool"], "runtime_get_capabilities")

    def test_code_anchors_extracted_across_multiple_tool_formats(self):
        anchors = extract_code_anchors(
            "runtime_heap_owner_lookup",
            {"results": [{"referrers": [{"variable_path": "g_pool.items", "decl_file": "src/pool.cpp", "decl_line": 42}]}]},
        )
        self.assertEqual(len(anchors), 1)
        self.assertEqual(anchors[0]["file"], "src/pool.cpp")
        self.assertEqual(anchors[0]["line"], 42)
        self.assertEqual(anchors[0]["variable_path"], "g_pool.items")


class TestMcpToolSurfaceTiering(unittest.TestCase):
    def test_tool_tiers_and_playbook_integration(self):
        tiers = mcp_srv.get_mcp_tool_tiers("core")
        self.assertEqual(tiers["active_profile"], "core")
        self.assertGreaterEqual(tiers["core_tool_count"], 14)
        self.assertIn("TIER0_ENTRY", tiers["tiers"])
        self.assertIn("TIER1_NARROWING", tiers["tiers"])
        self.assertIn("TIER2_DEEP_INSPECT", tiers["tiers"])
        self.assertIn("TIER3_TEMPORAL_WATCH", tiers["tiers"])

        pb = json.loads(mcp_srv.runtime_get_playbook())
        self.assertTrue(pb["success"])
        self.assertIn("tool_tiers", pb)
        self.assertIn("TIER0_ENTRY", pb["tool_tiers"]["tiers"])

        body = agent_skill.skill_body("mcp")
        self.assertIn("Continuous Tracking & Tool Tiers", body)
        self.assertIn("delta_from_last_call", body)
        self.assertIn("code_anchors", body)
        self.assertIn("recovery_actions", body)


if __name__ == "__main__":
    unittest.main()
