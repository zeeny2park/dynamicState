"""Deterministic regression and integration tests for:
DynamicState — Autonomous Investigation Completeness & Exit Predicate Closure.

Covers all 12 required scenarios plus severity-aware run comparison and full CI exit-code matrix.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest

try:
    import pytest
    pytestmark = pytest.mark.unit
except ImportError:  # pragma: no cover
    pass
from unittest import mock

import scripts.mcp_server as mcp_srv
from extractor.diagnostic_playbooks import select_playbook
from extractor.playbook_loop_runner import (
    EXIT_BLOCKED,
    EXIT_DEGRADED,
    EXIT_FAULT,
    EXIT_HEALTHY,
    EXIT_INCONCLUSIVE,
    diff_diagnostic_runs,
    run_playbook_loop,
    verdict_to_exit_code,
)
from extractor.tracking_ledger import (
    GLOBAL_TRACKING_LEDGER,
    TrackingLedgerStore,
    enrich_tool_response,
    make_target_key,
)


class _DeterministicClock:
    """Zero-sleep deterministic monotonic clock for timing & budget tests."""

    def __init__(self, start: float = 1000.0):
        self.t = float(start)

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> float:
        self.t += float(seconds)
        return self.t


class TestInvestigationBudgetAndCompleteness(unittest.TestCase):
    def test_1_large_investigation_exceeds_four_iterations_without_premature_cap(self):
        """1. Large investigation requiring >4 iterations runs to completion (and explicit >10 is not clamped)."""
        store = TrackingLedgerStore()
        calls = []

        def fake_exec(tool_name, args):
            calls.append(tool_name)
            # Only validate root cause on iteration 6 (after 5 steps/pivots)
            if len(calls) < 6:
                return {"success": True, "verdict": "INCONCLUSIVE", "candidates": []}
            return {
                "success": True,
                "verdict": "FAULT",
                "findings": [{"recipe_id": "RECIPE_HEAP_GROWTH", "status": "SUPPORTED", "severity": "HIGH"}],
                "correlations": [{"file": "src/cache.cpp", "line": 312, "variable_path": "g_cache.entries"}],
            }

        res = run_playbook_loop(
            pid=1001,
            symptom="memory leak",
            executor=fake_exec,
            companion_elf="/usr/bin/app",
            # No max_iterations passed (default None -> unbounded)
            ledger_store=store,
        )
        self.assertGreater(res["iterations_run"], 4)
        self.assertEqual(res["iterations_run"], 6)
        self.assertEqual(res["final_status"], "MET")
        self.assertEqual(res["hypothesis_status"], "SUPPORTED")
        self.assertIsNone(res["max_iterations"])

        # Explicit max_iterations > 10 must NOT be clamped to 10
        ledger = store.get_or_create("local:1002")
        ls = ledger.activate_playbook(select_playbook(symptom="memory leak"), max_iterations=15)
        self.assertEqual(ls["max_iterations"], 15)

    def test_2_investigation_longer_than_20s_completes_without_explicit_time_limit(self):
        """2. Investigation taking >20s (e.g. 55s) with time_budget_s=None completes without premature timeout."""
        clk = _DeterministicClock(100.0)
        store = TrackingLedgerStore()
        step_n = [0]

        def fake_exec(tool_name, args):
            step_n[0] += 1
            clk.advance(15.0)  # 15s per tool -> >20s after step 2
            if step_n[0] < 4:
                return {"success": True, "verdict": "INCONCLUSIVE"}
            return {
                "success": True,
                "verdict": "FAULT",
                "findings": [{"recipe_id": "RECIPE_LOCK_CONTENTION", "status": "SUPPORTED", "severity": "HIGH"}],
                "correlations": [{"file": "src/worker.c", "line": 88, "function": "work_loop"}],
            }

        res = run_playbook_loop(
            pid=1003,
            symptom="deadlock hang",
            executor=fake_exec,
            companion_elf="/usr/bin/worker",
            time_budget_s=None,
            ledger_store=store,
            clock=clk,
        )
        self.assertGreater(res["elapsed_s"], 20.0)
        self.assertEqual(res["elapsed_s"], 60.0)
        self.assertEqual(res["final_status"], "MET")
        self.assertIsNone(res["timing"]["time_budget_s"])

    def test_3_explicit_time_budget_exhaustion_retains_partial_evidence(self):
        """3. Explicit time_budget_s stops cleanly on exhaustion while preserving partial evidence."""
        clk = _DeterministicClock(200.0)
        store = TrackingLedgerStore()

        def fake_exec(tool_name, args):
            clk.advance(6.0)
            return {
                "success": True,
                "verdict": "INCONCLUSIVE",
                "threads": [
                    {"tid": 1004, "state": "S", "syscall": "futex", "frames": [{"function": "wait_q", "source_location": "src/q.c:44"}]}
                ],
            }

        res = run_playbook_loop(
            pid=1004,
            symptom="deadlock",
            executor=fake_exec,
            companion_elf="/usr/bin/q",
            time_budget_s=10.0,
            ledger_store=store,
            clock=clk,
        )
        self.assertEqual(res["final_status"], "EXHAUSTED")
        self.assertEqual(res["iterations_run"], 2)  # 6s + 6s = 12s >= 10s
        self.assertTrue(res["partial_evidence_preserved"])
        self.assertTrue(any(a.get("file") == "src/q.c" for a in res["code_anchors"]))
        self.assertEqual(res["exit_code"], EXIT_INCONCLUSIVE)

    def test_4_single_slow_tool_exceeding_nominal_budget_is_accounted_and_preserved(self):
        """4. One slow tool (25s) exceeding nominal time_budget_s=10s still preserves its results and tracks duration."""
        clk = _DeterministicClock(300.0)
        store = TrackingLedgerStore()

        def slow_exec(tool_name, args):
            clk.advance(25.0)
            return {
                "success": True,
                "verdict": "INCONCLUSIVE",
                "symbols": [{"name": "g_pool", "decl_file": "src/pool.c", "decl_line": 19}],
            }

        res = run_playbook_loop(
            pid=1005,
            symptom="variable state bug",
            executor=slow_exec,
            companion_elf="/usr/bin/pool",
            time_budget_s=10.0,
            ledger_store=store,
            clock=clk,
        )
        self.assertEqual(res["iterations_run"], 1)
        self.assertEqual(res["final_status"], "EXHAUSTED")
        self.assertTrue(res["timing"]["budget_exceeded_during_tool"])
        self.assertEqual(res["timing"]["longest_tool_s"], 25.0)
        self.assertEqual(res["timing"]["total_elapsed_s"], 25.0)
        self.assertTrue(any(a.get("symbol") == "g_pool" for a in res["code_anchors"]))

    def test_5_exception_from_one_tool_does_not_abort_overall_investigation(self):
        """5. Exception in one tool is isolated and recorded; subsequent tools still complete investigation."""
        store = TrackingLedgerStore()
        calls = []

        def flaky_exec(tool_name, args):
            calls.append(tool_name)
            if len(calls) == 1:
                raise RuntimeError("transient dwarf parse hiccup")
            return {
                "success": True,
                "verdict": "FAULT",
                "findings": [{"recipe_id": "RECIPE_FD_LEAK", "status": "SUPPORTED", "severity": "HIGH"}],
                "correlations": [{"file": "src/net.c", "line": 102, "function": "accept_conn"}],
            }

        res = run_playbook_loop(
            pid=1006,
            symptom="fd leak",
            executor=flaky_exec,
            companion_elf="/usr/bin/net",
            ledger_store=store,
        )
        self.assertEqual(len(res["tool_errors"]), 1)
        self.assertIn("transient dwarf parse hiccup", res["tool_errors"][0]["error"])
        self.assertEqual(res["final_status"], "MET")
        self.assertEqual(res["hypothesis_status"], "SUPPORTED")
        self.assertGreaterEqual(len(calls), 2)


class TestExitPredicateAndCiExitCodes(unittest.TestCase):
    def test_6_source_anchor_discovery_alone_never_triggers_false_met(self):
        """6. Arbitrary code anchors from runtime_correlate_source_and_state must NOT mark investigation MET."""
        store = TrackingLedgerStore()
        ledger = store.get_or_create("local:2001")
        ledger.activate_playbook(select_playbook(symptom="memory leak"))

        r = enrich_tool_response(
            "runtime_correlate_source_and_state",
            {
                "success": True,
                "correlations": [{"file": "src/main.c", "line": 10, "function": "main"}],
            },
            pid=2001,
            companion_elf="/usr/bin/app",
            ledger_store=store,
        )
        ls = r["tracking_context"]["loop_state"]
        self.assertNotEqual(ls["predicate_status"], "MET")
        self.assertEqual(ls["predicate_status"], "OPEN")
        self.assertEqual(ls["hypothesis_status"], "INCONCLUSIVE")
        self.assertFalse(ls["exit_predicate_evaluation"]["satisfied"])

    def test_7_actual_exit_predicate_satisfaction_supported_and_contradicted(self):
        """7. Actual exit predicate satisfaction works for both SUPPORTED fault+anchor and validated HEALTHY refutation."""
        # Case A: state-and-variable-bug requires direct eval + source anchor + validation
        store = TrackingLedgerStore()
        ledger = store.get_or_create("local:2002")
        ledger.activate_playbook(select_playbook(symptom="unexpected variable state bug"))

        # Step 1: direct eval alone -> still OPEN (no validation/anchor yet)
        enrich_tool_response(
            "runtime_eval_memory_path",
            {"success": True, "results": {"g_mode": {"value": 99}}},
            pid=2002,
            companion_elf="/usr/bin/app",
            ledger_store=store,
        )
        self.assertEqual(ledger.predicate_status, "OPEN")

        # Step 2: validated FAULT + source correlation anchor -> MET (SUPPORTED)
        enrich_tool_response(
            "runtime_correlate_source_and_state",
            {
                "success": True,
                "verdict": "FAULT",
                "findings": [{"recipe_id": "RECIPE_STATE_TRANSITION_VIOLATIONS", "status": "SUPPORTED", "severity": "HIGH"}],
                "correlations": [{"file": "src/fsm.c", "line": 75, "variable_path": "g_mode"}],
            },
            pid=2002,
            companion_elf="/usr/bin/app",
            ledger_store=store,
        )
        self.assertEqual(ledger.predicate_status, "MET")
        self.assertEqual(ledger.hypothesis_status, "SUPPORTED")
        self.assertTrue(ledger.exit_predicate_evaluation["satisfied"])

        # Case B: Validated HEALTHY with full coverage -> MET (CONTRADICTED)
        ledger2 = store.get_or_create("local:2003")
        ledger2.activate_playbook(select_playbook(symptom="heap corruption"))
        enrich_tool_response(
            "runtime_diagnose_process",
            {
                "success": True,
                "verdict": "HEALTHY",
                "agent_summary": {"verdict_qualifier": "NO_FAULT_FULL_OBSERVATION"},
                "memory_integrity": {"heap": {"status": "COMPLETED", "full_walk_skipped": False}},
            },
            pid=2003,
            ledger_store=store,
        )
        self.assertEqual(ledger2.predicate_status, "MET")
        self.assertEqual(ledger2.hypothesis_status, "CONTRADICTED")

        # Case C: HEALTHY with PARTIAL_SAMPLED / limited observation must NOT prematurely satisfy heap-corruption predicate
        ledger3 = store.get_or_create("local:2004")
        ledger3.activate_playbook(select_playbook(symptom="heap corruption"))
        enrich_tool_response(
            "runtime_diagnose_process",
            {
                "success": True,
                "verdict": "HEALTHY",
                "agent_summary": {"verdict_qualifier": "NO_FAULT_LIMITED_OBSERVATION"},
                "memory_integrity": {"heap": {"status": "PARTIAL_SAMPLED", "full_walk_skipped": True}},
            },
            pid=2004,
            ledger_store=store,
        )
        self.assertNotEqual(ledger3.predicate_status, "MET")

    def test_8_healthy_plus_exhausted_and_full_exit_code_matrix(self):
        """8. HEALTHY + EXHAUSTED must NEVER return exit code 0; test full verdict x final_status matrix."""
        self.assertEqual(verdict_to_exit_code("HEALTHY", predicate_status="EXHAUSTED"), EXIT_INCONCLUSIVE)
        self.assertEqual(verdict_to_exit_code("HEALTHY", predicate_status="OPEN"), EXIT_INCONCLUSIVE)
        self.assertEqual(verdict_to_exit_code("HEALTHY", predicate_status="PIVOT_REQUIRED"), EXIT_INCONCLUSIVE)
        self.assertEqual(verdict_to_exit_code("HEALTHY", predicate_status="MET"), EXIT_HEALTHY)
        self.assertEqual(verdict_to_exit_code("HEALTHY", predicate_status=None), EXIT_HEALTHY)
        self.assertEqual(verdict_to_exit_code("HEALTHY", predicate_status="BLOCKED"), EXIT_BLOCKED)

        self.assertEqual(verdict_to_exit_code("FAULT", predicate_status="MET"), EXIT_FAULT)
        self.assertEqual(verdict_to_exit_code("FAULT", predicate_status="EXHAUSTED"), EXIT_FAULT)
        self.assertEqual(verdict_to_exit_code("DEGRADED", predicate_status="MET"), EXIT_DEGRADED)
        self.assertEqual(verdict_to_exit_code("INCONCLUSIVE", predicate_status="EXHAUSTED"), EXIT_INCONCLUSIVE)
        self.assertEqual(verdict_to_exit_code("INCONCLUSIVE", predicate_status="BLOCKED"), EXIT_BLOCKED)
        self.assertNotEqual(EXIT_BLOCKED, EXIT_INCONCLUSIVE)

        # --fail-on consistency
        self.assertEqual(
            verdict_to_exit_code("HEALTHY", predicate_status="EXHAUSTED", fail_on=["fault"]),
            EXIT_HEALTHY,
        )
        self.assertEqual(
            verdict_to_exit_code("HEALTHY", predicate_status="EXHAUSTED", fail_on=["inconclusive"]),
            EXIT_INCONCLUSIVE,
        )
        self.assertEqual(
            verdict_to_exit_code("INCONCLUSIVE", predicate_status="BLOCKED", fail_on=["blocked"]),
            EXIT_BLOCKED,
        )


class TestLedgerPersistenceResourcesAndConcurrency(unittest.TestCase):
    def test_9_and_10_ledger_recovery_and_mcp_resource_read_after_restart(self):
        """9 & 10. After MCP server restart (in-memory clear), MCP Resources recover persisted decision_log & code_anchors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.dict(os.environ, {"DYNAMICSTATE_LEDGER_DIR": tmpdir}):
                GLOBAL_TRACKING_LEDGER.clear()
                enrich_tool_response(
                    "runtime_diagnose_process",
                    {
                        "success": True,
                        "verdict": "FAULT",
                        "findings": [{"recipe_id": "RECIPE_FD_LEAK", "status": "SUPPORTED", "severity": "HIGH"}],
                    },
                    pid=3001,
                )
                enrich_tool_response(
                    "runtime_correlate_source_and_state",
                    {"success": True, "correlations": [{"file": "src/sock.c", "line": 42, "function": "open_sock"}]},
                    pid=3001,
                )

                # Simulate full MCP server restart: wipe all in-memory ledgers
                GLOBAL_TRACKING_LEDGER.clear()
                self.assertEqual(len(GLOBAL_TRACKING_LEDGER._ledgers), 0)

                # MCP Resource reads must transparently recover from disk!
                dl = json.loads(mcp_srv.resource_ledger_decision_log("local", "3001"))
                self.assertTrue(dl["active"])
                self.assertEqual(len(dl["decision_log"]), 2)
                self.assertEqual(dl["predicate_status"], "MET")

                ca = json.loads(mcp_srv.resource_ledger_code_anchors("local", "3001"))
                self.assertTrue(ca["active"])
                self.assertEqual(ca["code_anchors"][0]["file"], "src/sock.c")
                self.assertEqual(ca["code_anchors"][0]["line"], 42)

                # Stale in-memory instance must not clobber newer disk state
                stale_store = TrackingLedgerStore(persist_dir=tmpdir)
                stale_ledger = stale_store.get_or_create("local:3001")
                # Simulate another worker advancing disk state
                newer_store = TrackingLedgerStore(persist_dir=tmpdir)
                enrich_tool_response(
                    "runtime_eval_memory_path",
                    {"success": True, "results": {"g_fd_count": {"value": 999, "decl_file": "src/sock.c", "decl_line": 9}}},
                    pid=3001,
                    ledger_store=newer_store,
                )
                # Saving stale_ledger must merge newer disk anchors/revision rather than overwriting them
                stale_store.save("local:3001")
                verify_store = TrackingLedgerStore(persist_dir=tmpdir)
                recovered = verify_store.get("local:3001")
                self.assertIsNotNone(recovered)
                files_lines = {(a.get("file"), a.get("line")) for a in recovered.code_anchors}
                self.assertIn(("src/sock.c", 42), files_lines)
                self.assertIn(("src/sock.c", 9), files_lines)

    def test_11_concurrent_ledger_persistence(self):
        """11. Concurrent threads persisting to the same ledger directory never corrupt JSON or raise errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = TrackingLedgerStore(persist_dir=tmpdir)
            errors = []

            def worker(idx: int):
                try:
                    for j in range(6):
                        enrich_tool_response(
                            "runtime_correlate_source_and_state",
                            {"success": True, "correlations": [{"file": f"src/f{idx}.c", "line": j + 1}]},
                            pid=4000,
                            ledger_store=store,
                        )
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(errors, [])
            fresh = TrackingLedgerStore(persist_dir=tmpdir)
            rec = fresh.get("local:4000")
            self.assertIsNotNone(rec)
            self.assertGreaterEqual(len(rec.code_anchors), 4)

    def test_12_local_and_remote_target_separation_and_collision_safe_paths(self):
        """12. Local vs remote targets (and punctuation-similar keys) remain strictly separated on disk and in memory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = TrackingLedgerStore(persist_dir=tmpdir)
            enrich_tool_response(
                "runtime_correlate_source_and_state",
                {"success": True, "correlations": [{"file": "local_only.c", "line": 1}]},
                pid=5000,
                remote_target=None,
                ledger_store=store,
            )
            enrich_tool_response(
                "runtime_correlate_source_and_state",
                {"success": True, "correlations": [{"file": "remote_only.c", "line": 2}]},
                pid=5000,
                remote_target={"remote_host": "prod-1", "ssh_port": 22},
                ledger_store=store,
            )
            enrich_tool_response(
                "runtime_correlate_source_and_state",
                {"success": True, "correlations": [{"file": "remote_port.c", "line": 3}]},
                pid=5000,
                remote_target={"remote_host": "prod-1", "ssh_port": 2222},
                ledger_store=store,
            )

            k_local = make_target_key(5000, None)
            k_r1 = make_target_key(5000, {"remote_host": "prod-1", "ssh_port": 22})
            k_r2 = make_target_key(5000, {"remote_host": "prod-1", "ssh_port": 2222})
            self.assertEqual(len({k_local, k_r1, k_r2}), 3)

            # Collision-safe filenames even for keys that sanitize to the same prefix
            p_a = store._ledger_path("host:1:100")
            p_b = store._ledger_path("host_1:100")
            self.assertNotEqual(p_a, p_b)

            fresh = TrackingLedgerStore(persist_dir=tmpdir)
            self.assertEqual(fresh.get(k_local).code_anchors[0]["file"], "local_only.c")
            self.assertEqual(fresh.get(k_r1).code_anchors[0]["file"], "remote_only.c")
            self.assertEqual(fresh.get(k_r2).code_anchors[0]["file"], "remote_port.c")


class TestRunComparisonSeverityCorrectness(unittest.TestCase):
    def test_info_finding_and_ungrounded_rss_change_are_not_false_regressions(self):
        before = {
            "verdict": "HEALTHY",
            "process_profile": {"summary": {"rss_kb": 50000}},  # open_fds & thread_count missing
            "findings": [{"recipe_id": "RECIPE_LOCK_CONTENTION", "severity": "WARNING", "summary": "mild wait"}],
        }
        after = {
            "verdict": "HEALTHY",
            "process_profile": {"summary": {"rss_kb": 80000}},  # +30MB alone without fault/verdict change
            "findings": [
                {"recipe_id": "RECIPE_LOCK_CONTENTION", "severity": "WARNING", "summary": "mild wait"},
                {"recipe_id": "RECIPE_HEAP_RETENTION", "severity": "INFO", "non_fault": True, "summary": "allocator cache"},
            ],
        }
        diff = diff_diagnostic_runs(before, after)
        self.assertFalse(diff["regressed"])
        self.assertEqual(diff["metric_deltas"]["rss_kb"]["status"], "measured")
        self.assertEqual(diff["metric_deltas"]["rss_kb"]["delta"], 30000)
        self.assertEqual(diff["metric_deltas"]["open_fds"]["status"], "unknown")
        self.assertIsNone(diff["metric_deltas"]["open_fds"]["delta"])
        self.assertEqual(diff["metric_deltas"]["thread_count"]["status"], "unknown")

    def test_severity_escalation_on_persistent_finding_is_flagged_as_regression(self):
        before = {
            "verdict": "DEGRADED",
            "findings": [{"recipe_id": "RECIPE_LOCK_CONTENTION", "severity": "WARNING", "summary": "wait"}],
        }
        after = {
            "verdict": "DEGRADED",
            "findings": [{"recipe_id": "RECIPE_LOCK_CONTENTION", "severity": "HIGH", "summary": "severe stall"}],
        }
        diff = diff_diagnostic_runs(before, after)
        self.assertTrue(diff["regressed"])
        self.assertEqual(len(diff["severity_changes"]), 1)
        self.assertTrue(diff["severity_changes"][0]["escalated"])
        self.assertEqual(diff["severity_changes"][0]["before_severity"], "WARNING")
        self.assertEqual(diff["severity_changes"][0]["after_severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
