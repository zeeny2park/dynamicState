"""Regression tests for Tier-2 heap sampling, multi-tier recipe fallback,
INCONCLUSIVE drill-down directives, and MCP cross-tool scope-narrowing chaining.
"""

from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace
from unittest import mock

from extractor import agent_skill
from extractor.diagnostic_recipes import (
    CATEGORY_MEMORY_CORRUPTION,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipeRegistry,
)
from extractor.healthy_verdict import _heap_cap_scope_limit
from extractor.heap_walker import (
    HeapWalkResult,
    HeapWalker,
    STATUS_PARTIAL,
    layout_for_version,
)
from extractor.memory_integrity import IntegrityConfig, run_integrity
from extractor.observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
from extractor.state_intelligence import (
    build_agent_summary,
    build_inconclusive_drilldown,
    build_narrow_tool_next_steps,
    build_suggested_actions,
)


class _FakeLargeHeapAdapter:
    """Minimal adapter stub simulating a 64 MiB heap with synthetic memory."""

    def __init__(self, mem_blobs=None):
        self.mem_blobs = dict(mem_blobs or {})

    def get_proc_maps(self, pid: int):
        # 64 MiB [heap] mapping — exceeds both 8 MiB baseline cap and ~48-50 MiB byte budget
        return [
            {
                "start": "555555600000",
                "end": "555559600000",
                "start_int": 0x555555600000,
                "end_int": 0x555559600000,
                "permissions": "rw-p",
                "perms": "rw-p",
                "offset": 0,
                "pathname": "[heap]",
            },
            {
                "start": "7ffffffde000",
                "end": "7ffffffff000",
                "start_int": 0x7FFFFFFDE000,
                "end_int": 0x7FFFFFFFF000,
                "permissions": "rw-p",
                "perms": "rw-p",
                "offset": 0,
                "pathname": "[stack]",
            },
        ]

    read_proc_maps = get_proc_maps

    def read_memory(self, pid: int, address: int, size: int) -> bytes:
        for base, buf in self.mem_blobs.items():
            if base <= address and address + size <= base + len(buf):
                off = address - base
                return buf[off : off + size]
        return b""

    def read_memory_batch(self, pid: int, ranges):
        out = []
        for addr, size in ranges:
            data = self.read_memory(pid, int(addr), int(size))
            out.append((data, None) if data else (None, 'unmapped'))
        return out

    def list_threads(self, pid: int):
        return [pid]

    def get_thread_registers(self, pid: int, tid: int):
        return {"rsp": 0x7FFFFFFFE000}


class TestTieredHeapSampling(unittest.TestCase):
    def test_large_heap_triggers_tier2_sampling_clean(self):
        """A >50 MiB heap should run Tier-2 bounded sampling instead of skipping blindly."""
        adapter = _FakeLargeHeapAdapter()
        cfg = IntegrityConfig(
            baseline_heap_cap_bytes=8 * 1024 * 1024,
            tiered_sampling_enabled=True,
        )
        # Remaining byte budget 10 MiB (< 64 MiB heap) forces the >50MB/budget-cap branch
        budget = ObservationBudgetTracker(
            ObservationBudgetLimits(max_bytes_read=10 * 1024 * 1024, max_wall_clock_ms=60000.0)
        )
        fake_walk = HeapWalkResult(
            status=STATUS_PARTIAL,
            message="Tier-2 bounded heap sample checked 2 arena(s), 16 tcache + 8 fastbin + 64 head chunk(s), 0 anomaly(ies)",
            stats={"wall_ms": 12.5, "bytes_read": 32768},
            sampling_metadata={
                "tier": "TIER2_BOUNDED_SAMPLING",
                "sampled_arenas": 2,
                "tcache_entries_checked": 16,
                "fastbin_entries_checked": 8,
                "boundary_chunks_checked": 64,
                "chunks_sampled": 64,
                "anomalies_detected": [],
            },
        )
        with mock.patch.object(HeapWalker, "walk_sampled", return_value=fake_walk) as m_sampled:
            rec = run_integrity(adapter, 1234, None, cfg, budget=budget, full_reason="heap_corruption")

        m_sampled.assert_called_once()
        heap = rec["heap"]
        self.assertEqual(heap["sampling_tier"], "TIER2_BOUNDED_SAMPLING")
        self.assertEqual(heap["status"], "PARTIAL_SAMPLED")
        self.assertTrue(heap["full_walk_skipped"])
        self.assertEqual(heap["not_checked_reason"], "byte_budget")
        self.assertEqual(heap["sampling_summary"]["sampled_arenas"], 2)
        self.assertEqual(heap["sampling_summary"]["tcache_entries_checked"], 16)
        self.assertEqual(heap["sampling_summary"]["fastbin_entries_checked"], 8)

    def test_large_heap_tier2_sampling_surfaces_sampled_defects(self):
        """Tier-2 sampling anomalies (e.g. fastbin cycle) must surface as SAMPLED_DEFECTS_FOUND."""
        adapter = _FakeLargeHeapAdapter()
        cfg = IntegrityConfig(
            baseline_heap_cap_bytes=8 * 1024 * 1024,
            tiered_sampling_enabled=True,
        )
        fake_walk = HeapWalkResult(
            status=STATUS_PARTIAL,
            message="Tier-2 bounded heap sample checked 1 arena(s), 4 tcache + 5 fastbin + 12 head chunk(s), 1 anomaly(ies)",
            stats={"wall_ms": 9.1, "bytes_read": 16384},
            sampling_metadata={
                "tier": "TIER2_BOUNDED_SAMPLING",
                "sampled_arenas": 1,
                "tcache_entries_checked": 4,
                "fastbin_entries_checked": 5,
                "boundary_chunks_checked": 12,
                "chunks_sampled": 12,
                "anomalies_detected": [
                    {
                        "kind": "fastbin_cycle_double_free",
                        "arena_index": 0,
                        "bin": 2,
                        "address": "0x555555600400",
                        "description": "fastbin 2 in arena 0 has cycle/double-free at 0x555555600400",
                    }
                ],
            },
        )
        with mock.patch.object(HeapWalker, "walk_sampled", return_value=fake_walk):
            rec = run_integrity(adapter, 1234, None, cfg, budget=None, full_reason=None)

        heap = rec["heap"]
        self.assertEqual(heap["sampling_tier"], "TIER2_BOUNDED_SAMPLING")
        self.assertEqual(heap["status"], "SAMPLED_DEFECTS_FOUND")
        self.assertEqual(len(heap["defects"]), 1)
        self.assertIn("fastbin_cycle", heap["defects"][0]["kind"])
        self.assertIn("fastbin 2", heap["defects"][0]["description"])

    def test_healthy_verdict_accepts_partial_sampled_scope_limit(self):
        """PARTIAL_SAMPLED must be recognized as a conservative baseline scope limit, not a failure."""
        check = SimpleNamespace(
            actual_observations={
                "memory_integrity": {
                    "mode": "baseline",
                    "heap": {
                        "status": "PARTIAL_SAMPLED",
                        "not_checked_reason": "above_baseline_cap",
                        "sampling_tier": "TIER2_BOUNDED_SAMPLING",
                        "estimated_heap_bytes": 64 * 1024 * 1024,
                        "baseline_cap_bytes": 8 * 1024 * 1024,
                    },
                    "globals": {"status": "COMPLETED", "candidates": []},
                    "stacks": {"status": "COMPLETED", "warnings": []},
                }
            }
        )
        scope = _heap_cap_scope_limit(check)
        self.assertIsNotNone(scope)
        self.assertEqual(scope["kind"], "integrity_not_checked")

    def test_walk_sampled_detects_fastbin_and_tcache_cycles_directly(self):
        """Exercise HeapWalker.walk_sampled() directly on synthetic malloc_state + fastbin + tcache bytes."""
        layout = layout_for_version((2, 35))
        heap_base = 0x555555600000
        buf = bytearray(0x4000)

        # Chunk 0: tcache_perthread_struct (size == layout.tcache_chunk_size | PREV_INUSE)
        struct.pack_into("<QQ", buf, 0x0, 0, layout.tcache_chunk_size | 1)
        # counts[0] = 2 (uint16_t array at offset 0 of tcache struct -> heap_base + 16)
        struct.pack_into("<H", buf, 16, 2)
        # entries[0] at 16 + layout.tcache_entries_off -> points to user ptr heap_base + 0x310
        tc_entry_ptr = heap_base + 0x310
        struct.pack_into("<Q", buf, 16 + layout.tcache_entries_off, tc_entry_ptr)
        # Chunk at 0x300 (size == layout.min_chunk | 1 = 0x21), user data at 0x310 holds safe-linked self-pointer
        struct.pack_into("<QQ", buf, 0x300, 0, layout.min_chunk | 1)
        struct.pack_into("<Q", buf, 0x310, tc_entry_ptr ^ (tc_entry_ptr >> 12))

        # Fastbin[2] chunk at 0x400 (expected size = layout.min_chunk + 2 * layout.malloc_alignment = 0x40)
        fb_chunk = heap_base + 0x400
        fb_size = layout.min_chunk + 2 * layout.malloc_alignment
        fb_fd_loc = fb_chunk + 16
        struct.pack_into("<QQ", buf, 0x400, 0, fb_size | 1)
        struct.pack_into("<Q", buf, 0x410, fb_chunk ^ (fb_fd_loc >> 12))

        # Top chunk at 0x500
        top_chunk = heap_base + 0x500
        struct.pack_into("<QQ", buf, 0x500, 0, 0x3B01)

        # Synthetic malloc_state at 0x7f0000001000
        arena_addr = 0x7F0000001000
        arena_buf = bytearray(layout.ms_size)
        struct.pack_into("<Q", arena_buf, layout.ms["fastbinsY"] + 2 * 8, fb_chunk)
        struct.pack_into("<Q", arena_buf, layout.ms["top"], top_chunk)
        struct.pack_into("<Q", arena_buf, layout.ms["next"], arena_addr)
        struct.pack_into("<Q", arena_buf, layout.ms["system_mem"], 0x4000000)

        adapter = _FakeLargeHeapAdapter(
            mem_blobs={
                heap_base: bytes(buf),
                arena_addr: bytes(arena_buf),
            }
        )
        walker = HeapWalker(adapter, 1234, use_libc_debug_info=False)
        fake_abi = SimpleNamespace(
            libc_version="2.35",
            arch="x86_64",
            pointer_size=8,
            to_dict=lambda: {"libc_version": "2.35", "arch": "x86_64"},
        )
        walker.abi = fake_abi

        with (
            mock.patch.object(walker, "_gate", return_value=None),
            mock.patch.object(walker, "_locate_main_arena", return_value=(arena_addr, layout, {"method": "test"})),
            mock.patch.object(walker, "_validate_arena_struct", return_value=True),
            mock.patch("extractor.heap_walker.check_support", return_value=SimpleNamespace(to_dict=lambda: {"supported": True})),
        ):
            res = walker.walk_sampled(
                max_arenas=2,
                max_tcache_entries=32,
                max_fastbin_entries=32,
                max_chunks_per_arena=32,
                max_segment_bytes=0x4000,
            )

        sm = res.sampling_metadata
        self.assertIsNotNone(sm)
        self.assertEqual(sm["tier"], "TIER2_BOUNDED_SAMPLING")
        self.assertGreaterEqual(sm["sampled_arenas"], 1)
        self.assertGreaterEqual(sm["fastbin_entries_checked"], 1)
        self.assertGreaterEqual(sm["tcache_entries_checked"], 1)
        anomalies = sm["anomalies_detected"]
        kinds = {a.get("kind") for a in anomalies}
        self.assertTrue(any("fastbin" in str(k) for k in kinds), f"Expected fastbin anomaly, got {anomalies}")
        self.assertTrue(any("tcache" in str(k) for k in kinds), f"Expected tcache anomaly, got {anomalies}")


class TestRecipeTieredFallback(unittest.TestCase):
    def test_heap_corruption_recipe_partial_sampled_stays_conservative_with_fallback(self):
        """PARTIAL_SAMPLED must not falsely return CONTRADICTED; it must attach Tier-2 fallback guidance."""
        obs = {
            "memory_integrity": {
                "mode": "baseline",
                "limitations": ["full heap walk skipped (byte_budget); Tier-2 bounded sampling ran"],
                "heap": {
                    "status": "PARTIAL_SAMPLED",
                    "not_checked_reason": "byte_budget",
                    "sampling_tier": "TIER2_BOUNDED_SAMPLING",
                    "sampling_summary": {
                        "sampled_arenas": 2,
                        "tcache_entries_checked": 32,
                        "fastbin_entries_checked": 12,
                        "chunks_sampled": 128,
                    },
                    "defects": [],
                },
                "globals": {"status": "NOT_RUN", "candidates": []},
                "stacks": {"status": "COMPLETED", "warnings": []},
            }
        }
        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_HEAP_METADATA_CORRUPTION", obs)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertTrue(res.details.get("tiered_fallback_applied"))
        self.assertEqual(res.details.get("sampling_tier"), "TIER2_BOUNDED_SAMPLING")
        self.assertEqual(res.details.get("next_fallback_tool"), "runtime_heap_leak_candidates")
        self.assertIn("runtime_heap_leak_candidates", res.recommended_action)
        self.assertTrue(res.details.get("fallback_ladder"))

    def test_heap_corruption_recipe_sampled_defects_found_is_supported(self):
        """SAMPLED_DEFECTS_FOUND from Tier-2 sampling must mark RECIPE_HEAP_METADATA_CORRUPTION SUPPORTED."""
        obs = {
            "memory_integrity": {
                "mode": "baseline",
                "limitations": [],
                "heap": {
                    "status": "SAMPLED_DEFECTS_FOUND",
                    "sampling_tier": "TIER2_BOUNDED_SAMPLING",
                    "sampling_summary": {"sampled_arenas": 1, "fastbin_entries_checked": 4},
                    "defects": [
                        {
                            "kind": "fastbin_cycle_double_free",
                            "status": "probable",
                            "description": "fastbin 2 cycle detected at 0x555555600400",
                        }
                    ],
                },
                "globals": {"status": "NOT_RUN", "candidates": []},
                "stacks": {"status": "COMPLETED", "warnings": []},
            }
        }
        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_HEAP_METADATA_CORRUPTION", obs)
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertEqual(res.details.get("finding_category"), CATEGORY_MEMORY_CORRUPTION)
        self.assertEqual(res.details.get("sampling_tier"), "TIER2_BOUNDED_SAMPLING")

    def test_generic_inconclusive_recipe_receives_category_fallback_ladder(self):
        """Any inconclusive recipe gets a category-matched multi-tier fallback ladder."""
        res = DiagnosticRecipeRegistry.evaluate_recipe(
            "RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
            {"prerequisites_missing": True, "missing_prerequisites": ["thread_stacks"]},
            prerequisites_met=False,
        )
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        ladder = res.details.get("fallback_ladder") or []
        self.assertGreaterEqual(len(ladder), 2)
        self.assertEqual(ladder[0]["tool"], "runtime_inspect_thread_callstack_and_locks")


class TestInconclusiveDrilldownAndChaining(unittest.TestCase):
    def _sample_inconclusive_result(self, *, large_heap_sampled=False, target_unreadable=False):
        coverage = {
            "verdict": "INCONCLUSIVE",
            "verdict_qualifier": "NO_FAULT_LIMITED_OBSERVATION",
            "qualifier_label_en": "Partial observation",
            "qualifier_label_ko": "부분 관측",
            "one_liner_en": "2 checks undecided",
            "one_liner_ko": "2개 검사 판정 불가",
            "detail": {
                "blocking_gaps": (
                    [{"kind": "target_unreadable", "item": "pid 4242", "reason": "Permission denied: /proc/4242/mem"}]
                    if target_unreadable
                    else []
                ),
                "policy_skipped": (
                    [{"kind": "integrity_not_checked", "item": "heap_integrity", "reason": "heap exceeded cap"}]
                    if large_heap_sampled
                    else []
                ),
                "undecided": ["RECIPE_HEAP_METADATA_CORRUPTION", "RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
                "failed": [],
            },
        }
        result = {
            "target": {
                "pid": 4242,
                "debug_image": "/usr/local/bin/worker",
            },
            "verdict": "INCONCLUSIVE",
            "checks_run": [
                {
                    "recipe_id": "RECIPE_HEAP_METADATA_CORRUPTION",
                    "status": "INCONCLUSIVE",
                },
                {
                    "recipe_id": "RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
                    "status": "INCONCLUSIVE",
                },
            ],
            "not_covered": [
                {"kind": "long_wait_not_judged", "tid": 4243},
            ],
        }
        return result, coverage

    def test_inconclusive_drilldown_directs_agent_to_continue_with_concrete_ladder(self):
        result, coverage = self._sample_inconclusive_result(large_heap_sampled=True)
        actions = build_suggested_actions(result, coverage=coverage)
        self.assertTrue(actions)
        # High-priority INCONCLUSIVE drilldown actions must be sorted to the top
        self.assertEqual(actions[0]["priority"], "high")
        self.assertTrue(actions[0]["validation"]["valid"])

        dd = build_inconclusive_drilldown(result, coverage=coverage, suggested_actions=actions)
        self.assertTrue(dd["should_continue"])
        self.assertIn("DO NOT STOP", dd["agent_directive"])
        cause_codes = {c["cause_code"] for c in dd["causes"]}
        self.assertIn("large_heap_tiered_sampling", cause_codes)
        self.assertTrue(dd["scope_narrowing_ladder"])

        # Large-heap cause must point to runtime_heap_leak_candidates -> runtime_heap_owner_lookup
        heap_cause = next(c for c in dd["causes"] if c["cause_code"] == "large_heap_tiered_sampling")
        self.assertEqual(heap_cause["next_tool"], "runtime_heap_leak_candidates")
        self.assertEqual(heap_cause["next_hop_tool"], "runtime_heap_owner_lookup")

        summary = build_agent_summary(result, coverage=coverage, suggested_actions=actions)
        self.assertIn("inconclusive_drilldown", summary)
        self.assertTrue(summary["inconclusive_drilldown"]["should_continue"])
        self.assertIsNotNone(summary["top_action"])

    def test_target_unreadable_sets_should_continue_false(self):
        result, coverage = self._sample_inconclusive_result(target_unreadable=True)
        dd = build_inconclusive_drilldown(result, coverage=coverage)
        self.assertFalse(dd["should_continue"])
        self.assertTrue(any(c["cause_code"] == "target_access_blocked" for c in dd["causes"]))

    def test_narrow_tool_chaining_heap_leak_candidates_with_and_without_addresses(self):
        with_cands = build_narrow_tool_next_steps(
            "runtime_heap_leak_candidates",
            {
                "candidates": [
                    {"address": "0x555555612000", "size": 4096},
                    {"address": "0x555555624000", "size": 4096},
                ]
            },
            pid=4242,
            companion_elf="/usr/local/bin/worker",
        )
        self.assertTrue(with_cands)
        self.assertEqual(with_cands[0]["mcp_tool"], "runtime_heap_owner_lookup")
        self.assertEqual(with_cands[0]["mcp_args"]["addresses"], ["0x555555612000", "0x555555624000"])
        self.assertTrue(with_cands[0]["validation"]["valid"])

        without_cands = build_narrow_tool_next_steps(
            "runtime_heap_leak_candidates",
            {"candidates": []},
            pid=4242,
        )
        self.assertTrue(without_cands)
        self.assertEqual(without_cands[0]["mcp_tool"], "runtime_explain_process_behavior")

    def test_narrow_tool_chaining_thread_callstacks_locks_and_io(self):
        lock_steps = build_narrow_tool_next_steps(
            "runtime_inspect_thread_callstack_and_locks",
            {
                "threads": [
                    {"tid": 4243, "waiting_on_lock": True, "syscall": "futex"},
                    {"tid": 4244, "waiting_on_lock": False, "syscall": "epoll_wait"},
                ]
            },
            pid=4242,
            companion_elf="/usr/local/bin/worker",
        )
        tools = [s["mcp_tool"] for s in lock_steps]
        self.assertIn("runtime_symbol_search", tools)
        self.assertIn("runtime_trace_ipc_pipeline", tools)

    def test_mcp_skill_playbook_contains_scope_narrowing_protocol(self):
        body = agent_skill.skill_body("mcp")
        self.assertIn("DO NOT STOP AT ONE CALL", body)
        self.assertIn("inconclusive_drilldown", body)
        self.assertIn("large_heap_tiered_sampling", body)
        self.assertIn("runtime_heap_leak_candidates", body)


if __name__ == "__main__":
    unittest.main()
