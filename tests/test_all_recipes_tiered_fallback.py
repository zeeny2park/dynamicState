"""Regression tests for all-recipe tiered fallbacks, partial-sampled reuse across
double_free / use_after_free / heap_retention, partial signals in fd_leak /
lock_contention / mapping_growth / thread_leak, and cross-tool chaining.
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

from extractor.diagnostic_recipes import (
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipeRegistry,
)
from extractor.healthy_verdict import (
    _double_free_cap_scope_limit,
    _uaf_cap_scope_limit,
)
from extractor.heap_walker import HeapWalkResult, STATUS_PARTIAL
from extractor.recipe_plugins.double_free import (
    OBS_FREE_LIST_REPEATS,
    run_double_free,
)
from extractor.recipe_plugins.heap_retention import OBS_HEAP_RETENTION
from extractor.recipe_plugins.use_after_free import OBS_FREED_MEMORY_USE
from extractor.state_intelligence import (
    build_inconclusive_drilldown,
    build_narrow_tool_next_steps,
    build_suggested_actions,
)
from extractor.uaf_detection import run_uaf


class TestHeapPluginTieredFallbacks(unittest.TestCase):
    def _sampled_integrity(self, *, with_double_free_cycle: bool = False):
        anoms = (
            [
                {
                    "kind": "tcache_cycle_double_free",
                    "arena_index": 0,
                    "bin": 1,
                    "address": "0x555555600300",
                    "description": "tcache bin 1 in arena 0 has cycle/duplicate at 0x555555600300",
                }
            ]
            if with_double_free_cycle
            else []
        )
        sm = {
            "tier": "TIER2_BOUNDED_SAMPLING",
            "sampled_arenas": 2,
            "tcache_entries_checked": 24,
            "fastbin_entries_checked": 10,
            "boundary_chunks_checked": 48,
            "chunks_sampled": 48,
            "anomalies_detected": anoms,
        }
        integrity = {
            "mode": "baseline",
            "heap": {
                "status": "SAMPLED_DEFECTS_FOUND" if with_double_free_cycle else "PARTIAL_SAMPLED",
                "not_checked_reason": "above_baseline_cap",
                "sampling_tier": "TIER2_BOUNDED_SAMPLING",
                "sampling_summary": sm,
                "defects": [],
            },
            "limitations": ["full heap walk skipped; Tier-2 bounded sampling ran"],
        }
        walk = HeapWalkResult(status=STATUS_PARTIAL, sampling_metadata=sm)
        return integrity, {"walk": walk, "walker": None, "analyzer": None, "sampled": True}

    def test_double_free_reuses_tier2_sample_and_detects_cycle(self):
        integrity, objs = self._sampled_integrity(with_double_free_cycle=True)
        rec = run_double_free(None, 1234, None, objs, integrity)
        self.assertEqual(rec["status"], "SAMPLED_DEFECTS_FOUND")
        self.assertEqual(rec["sampling_tier"], "TIER2_BOUNDED_SAMPLING")
        self.assertEqual(len(rec["findings"]), 1)
        self.assertEqual(rec["findings"][0]["free_list"], "tcache")

        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_DOUBLE_FREE", {OBS_FREE_LIST_REPEATS: rec})
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)

    def test_double_free_clean_tier2_sample_is_conservative_and_healthy_compatible(self):
        integrity, objs = self._sampled_integrity(with_double_free_cycle=False)
        rec = run_double_free(None, 1234, None, objs, integrity)
        self.assertEqual(rec["status"], "PARTIAL_SAMPLED")
        self.assertEqual(rec["heap_not_checked_reason"], "above_baseline_cap")

        # Conservative HEALTHY scope check must accept PARTIAL_SAMPLED
        chk = SimpleNamespace(actual_observations={OBS_FREE_LIST_REPEATS: rec})
        self.assertIsNotNone(_double_free_cap_scope_limit(chk))

        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_DOUBLE_FREE", {OBS_FREE_LIST_REPEATS: rec})
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertTrue(res.details.get("tiered_fallback_applied"))
        self.assertEqual(res.details.get("next_fallback_tool"), "runtime_heap_leak_candidates")
        self.assertIn("runtime_heap_leak_candidates", res.recommended_action)

    def test_uaf_clean_tier2_sample_is_conservative_and_healthy_compatible(self):
        integrity, objs = self._sampled_integrity(with_double_free_cycle=False)
        rec = run_uaf(None, 1234, None, objs, integrity)
        self.assertEqual(rec["status"], "PARTIAL_SAMPLED")
        self.assertEqual(rec["sampling_tier"], "TIER2_BOUNDED_SAMPLING")
        self.assertEqual(rec["heap_not_checked_reason"], "above_baseline_cap")

        chk = SimpleNamespace(
            actual_observations={
                OBS_FREED_MEMORY_USE: rec,
                "memory_integrity": integrity,
            }
        )
        self.assertIsNotNone(_uaf_cap_scope_limit(chk))

        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_FREED_MEMORY_USE", {OBS_FREED_MEMORY_USE: rec})
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertTrue(res.details.get("tiered_fallback_applied"))
        self.assertEqual(res.details.get("sampling_tier"), "TIER2_BOUNDED_SAMPLING")
        self.assertIn("runtime_symbol_search", res.recommended_action)

    def test_heap_retention_partial_sampled_rule(self):
        hr = {
            "status": "PARTIAL_SAMPLED",
            "reason": "heap (64.0 MiB) above the walk cap of this check (32 MiB)",
            "sampling_tier": "TIER2_BOUNDED_SAMPLING",
            "sampling_summary": {
                "sampled_arenas": 2,
                "tcache_entries_checked": 16,
                "fastbin_entries_checked": 8,
            },
            "totals": {"system_mem": 64 * 1024 * 1024, "in_use_bytes": 0, "free_bytes": 0, "top_bytes": 0},
            "arenas": [{"index": 0, "is_main": True, "system_mem": 64 * 1024 * 1024}],
            "limitations": ["heap retention: heap (64.0 MiB) above the walk cap"],
        }
        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_HEAP_RETENTION", {OBS_HEAP_RETENTION: hr})
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertTrue(res.details.get("tiered_fallback_applied"))
        self.assertEqual(res.details.get("sampling_tier"), "TIER2_BOUNDED_SAMPLING")
        self.assertIn("runtime_heap_leak_candidates", res.recommended_action)


class TestOtherPluginRecipesPartialSignalsAndLadders(unittest.TestCase):
    def test_fd_leak_inconclusive_emits_ipc_fallback_and_partial_signals(self):
        obs = {
            "fd_usage": {
                "samples": [
                    {"t_s": 0.0, "open_fds": 100},
                    {"t_s": 0.5, "open_fds": 102},
                    {"t_s": 1.0, "open_fds": 101},
                ],
                "fd_limit": 1024,
                "new_fd_targets": [{"count": 2, "fd_target": "socket:[12345]"}],
            }
        }
        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_FD_LEAK", obs)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(res.details.get("next_fallback_tool"), "runtime_trace_ipc_pipeline")
        self.assertIn("socket:[12345]", res.recommended_action)
        self.assertEqual(res.details["fallback_ladder"][0]["tool"], "runtime_trace_ipc_pipeline")

    def test_lock_contention_inconclusive_emits_lock_name_and_callstack_tool(self):
        obs = {
            "lock_contention": {
                "samples": 6,
                "window_s": 1.2,
                "mutexes": [
                    {
                        "lock_name": "g_queue_mutex",
                        "queued_fraction": 0.45,
                        "samples_queued": 2,
                        "max_waiters": 3,
                        "mean_waiters": 2.0,
                        "owner_tids": [4242, 4243],
                        "owner_changed": True,
                        "owner_progressed": True,
                        "owner_gone": False,
                        "owner_where": [],
                    }
                ],
            }
        }
        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_LOCK_CONTENTION", obs)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(res.details.get("next_fallback_tool"), "runtime_inspect_thread_callstack_and_locks")
        self.assertIn("g_queue_mutex", res.recommended_action)

    def test_mapping_growth_inconclusive_emits_partial_ranges(self):
        obs = {
            "mapping_growth": {
                "samples": [{"t_s": 0.0, "rss_kb": 40000}, {"t_s": 1.0, "rss_kb": 40200}],
                "steps": [{"net_outside_kb": 128}],
                "outside_growth_kb": 128,
                "rss_growth_kb": 200,
                "malloc_growth_kb": 0,
                "grown_mappings": [{"start": "0x7f1000000000", "end": "0x7f1000200000", "added_kb": 128, "size_kb": 2048}],
            }
        }
        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_MAPPING_GROWTH", obs)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(res.details.get("next_fallback_tool"), "runtime_heap_leak_candidates")
        self.assertIn("0x7f1000000000", res.recommended_action)

    def test_thread_leak_inconclusive_emits_new_thread_names(self):
        obs = {
            "thread_count_series": [10, 12, 11, 13],
            "thread_sampling": {"window_sec": 1.0},
            "thread_growth": {
                "new_threads": [{"count": 2, "thread_name": "rpc-worker"}],
            },
        }
        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_THREAD_LEAK", obs)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(res.details.get("next_fallback_tool"), "runtime_inspect_thread_callstack_and_locks")
        self.assertIn("rpc-worker", res.recommended_action)
        self.assertEqual(res.details["fallback_ladder"][0]["tool"], "runtime_inspect_thread_callstack_and_locks")

    def test_variable_state_recipe_ladder_starts_with_symbol_search(self):
        res = DiagnosticRecipeRegistry.evaluate_recipe(
            "RECIPE_STATE_TRANSITION_VIOLATIONS",
            {"prerequisites_missing": True, "missing_prerequisites": ["dwarf_symbols_available"]},
            prerequisites_met=False,
        )
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(res.details["fallback_ladder"][0]["tool"], "runtime_symbol_search")
        self.assertEqual(res.details["fallback_ladder"][1]["tool"], "runtime_eval_memory_path")


class TestExpandedCrossToolChaining(unittest.TestCase):
    def test_fd_leak_inconclusive_drilldown_recommends_ipc_pipeline(self):
        coverage = {
            "verdict": "INCONCLUSIVE",
            "verdict_qualifier": "NO_FAULT_LIMITED_OBSERVATION",
            "qualifier_label_en": "Partial observation",
            "qualifier_label_ko": "부분 관측",
            "one_liner_en": "1 check undecided",
            "one_liner_ko": "1개 검사 판정 불가",
            "detail": {"blocking_gaps": [], "policy_skipped": [], "undecided": ["RECIPE_FD_LEAK"], "failed": []},
        }
        result = {
            "target": {"pid": 5151, "debug_image": "/usr/local/bin/proxy"},
            "verdict": "INCONCLUSIVE",
            "checks_run": [{"recipe_id": "RECIPE_FD_LEAK", "status": "INCONCLUSIVE"}],
        }
        actions = build_suggested_actions(result, coverage=coverage)
        self.assertTrue(any(a["mcp_tool"] == "runtime_trace_ipc_pipeline" for a in actions))
        dd = build_inconclusive_drilldown(result, coverage=coverage, suggested_actions=actions)
        self.assertTrue(dd["should_continue"])
        self.assertTrue(any(c["cause_code"] == "inconclusive_fd_ipc_checks" for c in dd["causes"]))

    def test_narrow_tool_chaining_for_ipc_symbol_search_and_heap_owner(self):
        ipc_next = build_narrow_tool_next_steps(
            "runtime_trace_ipc_pipeline",
            {"peer_processes": [{"pid": 6262, "comm": "backend"}]},
            pid=5151,
            companion_elf="/usr/local/bin/proxy",
        )
        self.assertEqual(ipc_next[0]["mcp_tool"], "runtime_inspect_thread_callstack_and_locks")

        sym_next = build_narrow_tool_next_steps(
            "runtime_symbol_search",
            {"symbols": [{"name": "g_conn_pool"}, {"name": "g_active_fds"}]},
            pid=5151,
            companion_elf="/usr/local/bin/proxy",
        )
        self.assertEqual(sym_next[0]["mcp_tool"], "runtime_eval_memory_path")
        self.assertEqual(sym_next[0]["mcp_args"]["expressions"], ["g_conn_pool", "g_active_fds"])

        owner_next = build_narrow_tool_next_steps(
            "runtime_heap_owner_lookup",
            {"results": [{"referrers": [{"variable_path": "g_cache.entries"}]}]},
            pid=5151,
            companion_elf="/usr/local/bin/proxy",
        )
        self.assertEqual(owner_next[0]["mcp_tool"], "runtime_eval_memory_path")
        self.assertEqual(owner_next[0]["mcp_args"]["expressions"], ["g_cache.entries"])


if __name__ == "__main__":
    unittest.main()
