"""Regression tests for Diagnostic Intelligence Correctness & Baseline Closure.

Covers:
1. Baseline Identity: cross-host same process_name, local vs remote, missing build_id,
   process_name-only (WEAK), insufficient identity (UNKNOWN), arch mismatch, and
   explicit baseline file target mismatch refusing diff generation.
2. Coverage Classification: PASS + execution error never downgraded to NO_FAULT,
   incomplete coverage never masquerading as full HEALTHY, strict separation of
   NO_FAULT_LIMITED_OBSERVATION vs BLOCKED_EXECUTION vs BLOCKED_TARGET_ACCESS.
3. Baseline Persistence: concurrent saves without lost updates, corrupted index.json
   auto-recovery, incomplete snapshot filtering, unsafe investigation_id sanitization,
   real file pruning on retention cap, and non-fatal save failure.
4. Baseline Intelligence: added/removed containers, container trend, thread role/state
   distribution changes, liveness transition, finding recurrence, and sustained RSS
   growth (REGRESSION) vs single-point spike (DRIFT).
5. Suggested Action Validation: MCP tool registry introspection, exact parameter names
   and types (companion_elf, expressions), placeholder/remote-tracing blocking, and
   cost/risk/evidence/approval metadata.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from extractor.diagnosis_baseline import (  # noqa: E402
    compare_diagnosis_baseline,
    evaluate_target_identity_match,
    extract_baseline_snapshot,
    resolve_diagnosis_baseline,
    sanitize_investigation_id,
    save_diagnosis_baseline,
)
from extractor.state_intelligence import (  # noqa: E402
    build_suggested_actions,
    classify_coverage,
    get_mcp_tool_registry,
    validate_suggested_action,
)


def _mk_result(inv_id: str, *, host=None, build_id="bid_aaa", binary_path="/opt/svc/app",
               process_name="app", arch="x86_64", verdict="HEALTHY", findings=None) -> dict:
    return {
        "investigation_id": inv_id,
        "verdict": verdict,
        "confidence": 0.9,
        "target": {
            "pid": 1234,
            "host": host,
            "build_id": build_id,
            "binary_path": binary_path,
            "process_name": process_name,
            "abi": {"architecture": arch},
        },
        "findings": list(findings or []),
        "checks_run": [{"recipe_id": "RECIPE_FD_LEAK", "status": "PASS"}],
        "not_covered": [],
        "healthy_scope": {"healthy": verdict == "HEALTHY", "checked": [], "not_checked": [], "blocking": []},
    }


def _mk_profile(*, rss_kb=50000, rss_series=None, fds=100, containers=None,
                roles=None, liveness_status="ACTIVE", cpu_ms=100.0, switches=200, io=50) -> dict:
    mem = {"rss": {"v": rss_kb}}
    if rss_series is not None:
        mem["rss_series"] = {"v": rss_series}
    if containers is not None:
        mem["containers"] = [{"variable": k, "size": v} for k, v in containers.items()]
    role_groups = roles if roles is not None else [
        {"role": "worker", "state": "sleeping", "count": 4, "cpu_time_ms_delta": 80.0},
        {"role": "main", "state": "waiting", "count": 1, "cpu_time_ms_delta": 20.0},
    ]
    return {
        "available": True,
        "summary": {"rss_kb": rss_kb, "threads": sum(r["count"] for r in role_groups), "fds": fds},
        "memory": mem,
        "resources": {"fds": {"v": fds, "limit": 1024, "series": [fds, fds]}},
        "threads": {"count": {"v": sum(r["count"] for r in role_groups)}, "role_groups": role_groups},
        "liveness": {
            "status": liveness_status,
            "window_s": 10.0,
            "cpu_time_ms_delta": cpu_ms,
            "total_switches_delta": switches,
            "io_syscalls_delta": io,
        },
    }


class TestBaselineIdentityClosure(unittest.TestCase):
    def test_cross_host_same_process_name_is_mismatch_and_never_auto_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            r_host_a = _mk_result("inv_host_a", host="10.0.0.10", process_name="worker", binary_path="/usr/bin/worker", build_id="abc")
            save_diagnosis_baseline(tmp, r_host_a, _mk_profile())

            # Different remote host with identical process_name/binary/build_id -> MISMATCH
            res_b = resolve_diagnosis_baseline(
                tmp, "latest", host="10.0.0.20", process_name="worker", binary_path="/usr/bin/worker", build_id="abc"
            )
            self.assertFalse(res_b["found"])
            self.assertEqual(res_b["identity_match"]["status"], "MISMATCH")

            # Local host (None) vs remote host (10.0.0.10) -> MISMATCH
            res_local = resolve_diagnosis_baseline(
                tmp, "latest", host=None, process_name="worker", binary_path="/usr/bin/worker", build_id="abc"
            )
            self.assertFalse(res_local["found"])
            self.assertEqual(res_local["identity_match"]["status"], "MISMATCH")

    def test_process_name_only_is_weak_and_never_auto_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            r_weak = _mk_result("inv_weak", host=None, build_id=None, binary_path=None, process_name="server")
            save_diagnosis_baseline(tmp, r_weak, _mk_profile())

            res = resolve_diagnosis_baseline(tmp, "latest", host=None, build_id=None, binary_path=None, process_name="server")
            self.assertFalse(res["found"])
            self.assertEqual(res["identity_match"]["status"], "WEAK")

    def test_missing_build_id_with_matching_binary_path_is_exact_or_compatible(self):
        m = evaluate_target_identity_match(
            {"host": "local", "binary_path": "/opt/app", "process_name": "app", "build_id": None},
            {"host": "local", "binary_path": "/opt/app", "process_name": "app", "build_id": None},
        )
        self.assertEqual(m["status"], "EXACT")
        self.assertTrue(m["auto_selectable"])

    def test_insufficient_identity_is_unknown_and_arch_mismatch_is_mismatch(self):
        u = evaluate_target_identity_match({"host": "local"}, {"host": "local"})
        self.assertEqual(u["status"], "UNKNOWN")
        self.assertFalse(u["auto_selectable"])

        arch_m = evaluate_target_identity_match(
            {"host": "local", "binary_path": "/opt/app", "arch": "x86_64"},
            {"host": "local", "binary_path": "/opt/app", "arch": "aarch64"},
        )
        self.assertEqual(arch_m["status"], "MISMATCH")
        self.assertFalse(arch_m["auto_selectable"])

    def test_explicit_file_target_mismatch_refuses_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            r_a = _mk_result("inv_file_a", host="10.0.0.1", binary_path="/opt/a", build_id="bid_a", process_name="a")
            saved_path = save_diagnosis_baseline(tmp, r_a, _mk_profile())
            self.assertIsNotNone(saved_path)

            resolved = resolve_diagnosis_baseline(
                tmp, saved_path, host="10.0.0.2", binary_path="/opt/b", build_id="bid_b", process_name="b"
            )
            self.assertFalse(resolved["found"])
            self.assertEqual(resolved["identity_match"]["status"], "MISMATCH")

            # Direct compare_diagnosis_baseline also refuses MISMATCH
            snap_a = extract_baseline_snapshot(r_a, _mk_profile())
            snap_b = extract_baseline_snapshot(
                _mk_result("inv_file_b", host="10.0.0.2", binary_path="/opt/b", build_id="bid_b", process_name="b"),
                _mk_profile(),
            )
            diff = compare_diagnosis_baseline(snap_b, snap_a)
            self.assertFalse(diff["available"])
            self.assertEqual(diff["identity_match"]["status"], "MISMATCH")


class TestCoverageClassificationClosure(unittest.TestCase):
    def test_partial_pass_never_masks_execution_error(self):
        res = {
            "verdict": "INCONCLUSIVE",
            "checks_run": [
                {"recipe_id": "RECIPE_FD_LEAK", "status": "PASS"},
                {"recipe_id": "RECIPE_THREAD_STATE_ANOMALIES", "status": "PASS"},
                {"recipe_id": "RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "status": "ERROR"},
            ],
            "not_covered": [
                {"kind": "stage_failed", "item": "lock_graph", "reason": "unwinder crashed"},
            ],
            "healthy_scope": {"healthy": False, "blocking": [{"kind": "stage_failed", "item": "lock_graph", "reason": "unwinder crashed"}]},
        }
        cov = classify_coverage(res)
        self.assertEqual(cov["verdict_qualifier"], "BLOCKED_EXECUTION")

    def test_incomplete_coverage_cannot_masquerade_as_full_healthy(self):
        spoofed = {
            "verdict": "HEALTHY",
            "checks_run": [
                {"recipe_id": "RECIPE_FD_LEAK", "status": "PASS"},
                {"recipe_id": "RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "status": "ERROR"},
            ],
            "not_covered": [{"kind": "budget_exhausted", "item": "budget", "reason": "wall clock exceeded"}],
            "healthy_scope": {"healthy": True, "blocking": []},
        }
        cov = classify_coverage(spoofed)
        self.assertEqual(cov["verdict_qualifier"], "INCONSISTENT_HEALTHY_CLAIM")

    def test_policy_only_budget_skip_is_no_fault_limited_observation(self):
        res = {
            "verdict": "INCONCLUSIVE",
            "checks_run": [{"recipe_id": "RECIPE_FD_LEAK", "status": "PASS"}],
            "not_covered": [
                {"kind": "baseline_check_not_run", "item": "RECIPE_HEAP_METADATA_CORRUPTION",
                 "not_run_reason": "default_check_time_budget", "reason": "time budget"},
            ],
            "healthy_scope": {
                "healthy": False,
                "blocking": [
                    {"kind": "baseline_check_missing", "item": "RECIPE_HEAP_METADATA_CORRUPTION",
                     "not_run_reason": "default_check_time_budget", "reason": "time budget"},
                ],
            },
        }
        cov = classify_coverage(res)
        self.assertEqual(cov["verdict_qualifier"], "NO_FAULT_LIMITED_OBSERVATION")


class TestBaselinePersistenceDurability(unittest.TestCase):
    def test_concurrent_saves_no_lost_updates_and_retention_prunes_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            def _save_one(i: int):
                r = _mk_result(f"inv_conc_{i:03d}")
                return save_diagnosis_baseline(tmp, r, _mk_profile(rss_kb=50000 + i * 10), max_entries=50)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                paths = list(ex.map(_save_one, range(12)))
            self.assertTrue(all(p and os.path.isfile(p) for p in paths))

            with open(os.path.join(tmp, "baselines", "index.json"), "r", encoding="utf-8") as fh:
                idx = json.load(fh)
            self.assertEqual(len(idx), 12)

            # Retention cap = 5 actually deletes evicted .baseline.json files
            save_diagnosis_baseline(tmp, _mk_result("inv_conc_099"), _mk_profile(), max_entries=5)
            files = [f for f in os.listdir(os.path.join(tmp, "baselines")) if f.endswith(".baseline.json")]
            self.assertEqual(len(files), 5)

    def test_corrupted_index_recovery_and_incomplete_snapshot_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            save_diagnosis_baseline(tmp, _mk_result("inv_good_1"), _mk_profile())
            bdir = os.path.join(tmp, "baselines")
            # Write an incomplete/corrupt snapshot file
            with open(os.path.join(bdir, "inv_corrupt.baseline.json"), "w", encoding="utf-8") as fh:
                fh.write('{"partial": true')
            # Corrupt index.json
            with open(os.path.join(bdir, "index.json"), "w", encoding="utf-8") as fh:
                fh.write("{not valid json")

            res = resolve_diagnosis_baseline(
                tmp, "latest", host=None, build_id="bid_aaa", binary_path="/opt/svc/app", process_name="app"
            )
            self.assertTrue(res["found"])
            self.assertEqual(res["baseline"]["investigation_id"], "inv_good_1")

    def test_unsafe_investigation_id_sanitized_and_save_error_non_fatal(self):
        self.assertIsNone(sanitize_investigation_id("../../etc/passwd"))
        self.assertIsNone(sanitize_investigation_id("foo/bar"))
        self.assertEqual(sanitize_investigation_id("inv_ok-1.2"), "inv_ok-1.2")

        with tempfile.TemporaryDirectory() as tmp:
            # Passing a file as corpus_dir triggers OSError -> must return None, never raise
            blocker_file = os.path.join(tmp, "not_a_dir")
            with open(blocker_file, "w", encoding="utf-8") as fh:
                fh.write("x")
            self.assertIsNone(save_diagnosis_baseline(blocker_file, _mk_result("inv_x"), _mk_profile()))


class TestBaselineIntelligenceTrends(unittest.TestCase):
    def test_sustained_rss_growth_vs_single_point_spike_and_structural_diffs(self):
        base_r = _mk_result("inv_base", findings=[{"category": "LOCK_CONTENTION"}])
        base_p = _mk_profile(
            rss_kb=50000, rss_series=[50000, 50000],
            containers={"g_cache": 100, "g_old_map": 50},
            roles=[{"role": "worker", "state": "sleeping", "count": 6, "cpu_time_ms_delta": 80.0}],
            liveness_status="ACTIVE",
        )
        base_snap = extract_baseline_snapshot(base_r, base_p)

        # Case A: Single-point RSS jump (+50%) with flat in-window series and no findings -> DRIFT (not REGRESSION)
        spike_r = _mk_result("inv_spike", findings=[])
        spike_p = _mk_profile(
            rss_kb=75000, rss_series=[75000, 75000],
            containers={"g_cache": 110, "g_new_queue": 30},
            roles=[
                {"role": "worker", "state": "sleeping", "count": 7, "cpu_time_ms_delta": 90.0},
                {"role": "reaper", "state": "waiting", "count": 1, "cpu_time_ms_delta": 5.0},
            ],
            liveness_status="QUIET",
        )
        spike_snap = extract_baseline_snapshot(spike_r, spike_p)
        diff_spike = compare_diagnosis_baseline(spike_snap, base_snap)
        self.assertTrue(diff_spike["available"])
        self.assertEqual(diff_spike["regression_status"], "DRIFT")
        self.assertIn("rss_kb", diff_spike["single_point_spikes"])
        self.assertEqual([c["variable"] for c in diff_spike["added_containers"]], ["g_new_queue"])
        self.assertEqual([c["variable"] for c in diff_spike["removed_containers"]], ["g_old_map"])
        self.assertTrue(len(diff_spike["thread_role_diffs"]) >= 2)
        self.assertEqual(diff_spike["liveness_transition"], {"baseline": "ACTIVE", "current": "QUIET"})

        # Case B: Sustained RSS growth (monotonic rising in-window series + +50%) -> REGRESSION
        sustained_p = _mk_profile(rss_kb=75000, rss_series=[65000, 70000, 75000])
        sustained_snap = extract_baseline_snapshot(_mk_result("inv_sust"), sustained_p)
        diff_sust = compare_diagnosis_baseline(sustained_snap, base_snap)
        self.assertEqual(diff_sust["regression_status"], "REGRESSION")
        self.assertIn("rss_kb", diff_sust["sustained_regressions"])

        # Case C: Recurring finding -> REGRESSION with recurring_findings populated
        rec_snap = extract_baseline_snapshot(_mk_result("inv_rec", findings=[{"category": "LOCK_CONTENTION"}]), base_p)
        diff_rec = compare_diagnosis_baseline(rec_snap, base_snap)
        self.assertEqual(diff_rec["regression_status"], "REGRESSION")
        self.assertIn("LOCK_CONTENTION", diff_rec["recurring_findings"])


class TestSuggestedActionMcpValidation(unittest.TestCase):
    def test_all_generated_actions_match_mcp_registry_and_block_invalid_preconditions(self):
        reg = get_mcp_tool_registry()
        self.assertIn("runtime_diagnose_process", reg)
        self.assertIn("runtime_heap_leak_candidates", reg)
        self.assertIn("runtime_inspect_thread_callstack_and_locks", reg)
        self.assertIn("runtime_eval_memory_path", reg)

        res = _mk_result("inv_act", host="10.0.0.5")
        res["target"]["debug_image"] = "/host/app.debug"
        res["target"]["ssh_user"] = "root"
        res["not_covered"] = [
            {"kind": "unsupported_in_mode", "item": "RECIPE_USE_AFTER_FREE", "capability": "DYNAMIC_EVENT_TRACING", "reason": "tracing"},
        ]
        res["healthy_scope"]["not_checked"] = [
            {"kind": "integrity_not_checked", "item": "heap_integrity", "reason": "above cap"},
        ]
        notable = [
            {"id": "watch_lock_contention:mu", "category": "locks", "subject": "mu"},
            {"id": "watch_container_capacity:g_vec", "category": "memory", "subject": "g_vec", "title_en": "over"},
        ]
        actions = build_suggested_actions(res, None, _mk_profile(), None, notable, None)
        self.assertGreaterEqual(len(actions), 4)

        for a in actions:
            # Every generated action must have valid MCP tool & exact valid param names/types
            self.assertTrue(a["validation"]["valid"], (a["id"], a["validation"]))
            self.assertIn("estimated_cost", a)
            self.assertIn("expected_evidence", a)
            self.assertIn("risk_level", a)
            self.assertIn("requires_user_approval", a)

            # Check narrow tools use companion_elf (never debug_image) and expressions (list)
            if a["mcp_tool"] in ("runtime_heap_leak_candidates", "runtime_inspect_thread_callstack_and_locks", "runtime_eval_memory_path"):
                self.assertNotIn("debug_image", a["mcp_args"])
                self.assertEqual(a["mcp_args"].get("companion_elf"), "/host/app.debug")
            if a["mcp_tool"] == "runtime_eval_memory_path":
                self.assertEqual(a["mcp_args"].get("expressions"), ["g_vec"])

            # Remote tracing must be marked non-executable with explicit blocked_reason
            if a["id"] == "enable_selective_tracing":
                self.assertFalse(a["executable"])
                self.assertIn("blocked_reason", a)

        # Explicitly test unknown tool / wrong arg rejection
        bad = validate_suggested_action({"mcp_tool": "nonexistent_tool", "mcp_args": {"pid": 1}})
        self.assertFalse(bad["executable"])
        self.assertFalse(bad["validation"]["valid"])


if __name__ == "__main__":
    unittest.main()
