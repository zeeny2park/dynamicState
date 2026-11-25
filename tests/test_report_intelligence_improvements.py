"""Tests for report state intelligence, coverage taxonomy, liveness proof,
baseline regression comparison, and LLM-agent actionable follow-ups."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from extractor.diagnosis_baseline import (  # noqa: E402
    compare_diagnosis_baseline,
    extract_baseline_snapshot,
    load_diagnosis_baseline,
    save_diagnosis_baseline,
)
from extractor.human_report import compose, render_human_report  # noqa: E402
from extractor.process_profile import build_process_profile  # noqa: E402
from extractor.profile_render import profile_html, profile_lines  # noqa: E402
from extractor.state_intelligence import (  # noqa: E402
    build_agent_summary,
    build_suggested_actions,
    classify_coverage,
    extract_notable_observations,
)


def _sample_report_with_activity() -> dict:
    return {
        "section_b_target_context": {
            "pid": 4242,
            "target_process_name": "edge_worker",
            "binary_path": "/opt/app/edge_worker",
            "observation_duration_sec": 44.6,
        },
        "section_d_detailed_inspection_results": {"checks": [
            {
                "recipe_id": "RECIPE_THREAD_STATE_ANOMALIES",
                "status": "PASS",
                "actual_observations": {
                    "thread_sampling": {"window_sec": 44.6, "samples_collected": 20, "clk_tck": 100},
                    "thread_summary": [
                        {
                            "tid": 4242, "name": "main", "states": ["S"] * 10, "syscall": "epoll_wait",
                            "cpu_ticks_delta": 12, "cpu_time_ms_delta": 120.0, "cpu_share": 0.003,
                            "voluntary_switches_delta": 140, "involuntary_switches_delta": 2,
                            "io_syscalls_delta": 88, "cpu_dispatches": 142, "sched_run_ms_delta": 118.5,
                            "top_function": "event_loop", "top_source_location": "main.cpp:42",
                        },
                        {
                            "tid": 4243, "name": "worker-0", "states": ["S", "R"] * 5, "syscall": "futex",
                            "cpu_ticks_delta": 35, "cpu_time_ms_delta": 350.0, "cpu_share": 0.008,
                            "voluntary_switches_delta": 210, "involuntary_switches_delta": 15,
                            "io_syscalls_delta": 40, "cpu_dispatches": 225, "sched_run_ms_delta": 340.0,
                            "top_function": "process_job", "top_source_location": "worker.cpp:91",
                        },
                        {
                            "tid": 4244, "name": "worker-1", "states": ["S", "R"] * 5, "syscall": "futex",
                            "cpu_ticks_delta": 30, "cpu_time_ms_delta": 300.0, "cpu_share": 0.007,
                            "voluntary_switches_delta": 195, "involuntary_switches_delta": 12,
                            "io_syscalls_delta": 35, "cpu_dispatches": 207, "sched_run_ms_delta": 295.0,
                            "top_function": "process_job", "top_source_location": "worker.cpp:91",
                        },
                    ],
                },
            },
            {
                "recipe_id": "RECIPE_FD_LEAK",
                "status": "PASS",
                "actual_observations": {
                    "fd_usage": {
                        "fd_limit": 1024,
                        "samples": [
                            {"t_s": 0.0, "open_fds": 620},
                            {"t_s": 44.6, "open_fds": 624},
                        ],
                        "open_fds_by_kind": {"socket": 580, "pipe": 12, "file": 32},
                        "new_fd_targets": ["socket:[9911]"],
                    },
                },
            },
            {
                "recipe_id": "RECIPE_LOCK_CONTENTION",
                "status": "PASS",
                "actual_observations": {
                    "lock_contention": {
                        "samples": 10,
                        "window_s": 44.6,
                        "mutexes": [
                            {"name": "g_queue_mu", "samples_queued": 2, "max_waiters": 2},
                        ],
                    },
                },
            },
            {
                "recipe_id": "RECIPE_PROCESS_MEMORY_GROWTH",
                "status": "PASS",
                "actual_observations": {
                    "rss_kb_series": [40960, 42400, 43520],
                    "rss_kb": 43520,
                },
            },
        ]},
    }


def _sample_result(verdict: str = "HEALTHY") -> dict:
    return {
        "verdict": verdict,
        "confidence": 0.85,
        "investigation_id": "inv_test_001",
        "target": {
            "pid": 4242,
            "process_name": "edge_worker",
            "binary_path": "/opt/app/edge_worker",
            "debug_image": "/opt/app/edge_worker.debug",
            "build_id": "deadbeef1234",
        },
        "findings": [],
        "checks_run": [
            {"recipe_id": "RECIPE_THREAD_STATE_ANOMALIES", "status": "PASS"},
            {"recipe_id": "RECIPE_FD_LEAK", "status": "PASS"},
            {"recipe_id": "RECIPE_LOCK_CONTENTION", "status": "PASS"},
            {"recipe_id": "RECIPE_PROCESS_MEMORY_GROWTH", "status": "PASS"},
        ],
        "not_covered": [
            {"kind": "recipes_not_planned", "item": "RECIPE_STATE_TRANSITION_VIOLATIONS", "reason": "not selected"},
            {"kind": "unsupported_in_mode", "item": "RECIPE_USE_AFTER_FREE", "capability": "DYNAMIC_EVENT_TRACING",
             "reason": "needs dynamic event tracing"},
        ],
        "healthy_scope": {
            "healthy": verdict == "HEALTHY",
            "checked": [{"recipe_id": "RECIPE_THREAD_STATE_ANOMALIES", "what": "threads", "what_ko": "스레드"}],
            "not_checked": [
                {"kind": "integrity_not_checked", "item": "heap_integrity",
                 "label": "heap integrity (above baseline cap)", "label_ko": "힙 무결성 (기본 상한 초과)",
                 "reason": "heap larger than baseline cap"},
                {"kind": "outside_baseline", "item": "outside_baseline",
                 "label": "data races and logic errors", "label_ko": "데이터 레이스, 논리 오류",
                 "reason": "not covered by any baseline check"},
            ],
            "blocking": [],
        },
        "collection_impact": {"measured_stop_ms": 0.0, "zero_stop": True, "bytes_read": 16384, "samples_collected": 20},
        "duration_s": 45.1,
    }


class TestReportIntelligenceImprovements(unittest.TestCase):
    def test_liveness_deltas_and_thread_role_groups(self):
        rep = _sample_report_with_activity()
        res = _sample_result("HEALTHY")
        prof = build_process_profile(res, rep)
        self.assertTrue(prof["available"])
        liv = prof.get("liveness")
        self.assertIsInstance(liv, dict)
        self.assertEqual(liv["status"], "ACTIVE")
        self.assertAlmostEqual(liv["window_s"], 44.6, places=1)
        self.assertAlmostEqual(liv["cpu_time_ms_delta"], 770.0, places=1)
        self.assertEqual(liv["voluntary_switches_delta"], 545)
        self.assertEqual(liv["involuntary_switches_delta"], 29)
        self.assertEqual(liv["total_switches_delta"], 574)
        self.assertEqual(liv["io_syscalls_delta"], 163)
        self.assertEqual(liv["active_threads"], 3)
        self.assertEqual(liv["fd_activity"]["delta"], 4)
        self.assertEqual(liv["fd_activity"]["by_kind"]["socket"], 580)

        # Role grouping merges worker-0 and worker-1 into role "worker"
        roles = {g["role"]: g for g in prof["threads"]["role_groups"]}
        self.assertIn("worker", roles)
        self.assertEqual(roles["worker"]["count"], 2)
        self.assertAlmostEqual(roles["worker"]["cpu_time_ms_delta"], 650.0, places=1)

        # Both Markdown and HTML render liveness in EN & KO
        for lang in ("en", "ko"):
            md = "\n".join(profile_lines(prof, lang))
            html = profile_html(prof, lang)
            self.assertIn("44.6", md)
            self.assertIn("770.0", md)
            self.assertIn("worker", md)
            self.assertIn("44.6", html)

    def test_notable_observations_watchlist(self):
        rep = _sample_report_with_activity()
        res = _sample_result("HEALTHY")
        prof = build_process_profile(res, rep)
        notable = extract_notable_observations(res, rep, prof)
        ids = {n["id"] for n in notable}
        self.assertIn("watch_fd_utilization", ids)
        self.assertIn("watch_lock_contention:g_queue_mu", ids)
        self.assertIn("watch_large_heap_uncapped", ids)

    def test_coverage_taxonomy_separates_policy_mode_and_inherent_limits(self):
        res = _sample_result("HEALTHY")
        cov = classify_coverage(res)
        self.assertEqual(cov["verdict_qualifier"], "LIMITED_OBSERVATION")
        self.assertGreaterEqual(cov["counts"]["policy_skipped"], 2)
        self.assertGreaterEqual(cov["counts"]["mode_or_target_unsupported"], 1)
        self.assertEqual(cov["counts"]["blocking_gaps"], 0)
        self.assertTrue(any(x["kind"] == "outside_baseline" for x in cov["detail"]["inherent_limits"]))

        # INCONCLUSIVE with passed checks and no access block -> NO_FAULT_LIMITED_OBSERVATION
        res_inc = _sample_result("INCONCLUSIVE")
        res_inc["healthy_scope"]["healthy"] = False
        res_inc["healthy_scope"]["blocking"] = [
            {"kind": "baseline_check_missing", "item": "RECIPE_FD_LEAK",
             "not_run_reason": "default_check_time_budget", "reason": "time budget"}
        ]
        cov_inc = classify_coverage(res_inc)
        self.assertEqual(cov_inc["verdict_qualifier"], "NO_FAULT_LIMITED_OBSERVATION")

        # INCONCLUSIVE with missing_debug_image -> BLOCKED_TARGET_ACCESS
        res_blk = _sample_result("INCONCLUSIVE")
        res_blk["checks_run"] = []
        res_blk["not_covered"] = [{"kind": "missing_debug_image", "item": "/opt/app.elf", "reason": "not found"}]
        cov_blk = classify_coverage(res_blk)
        self.assertEqual(cov_blk["verdict_qualifier"], "BLOCKED_TARGET_ACCESS")

    def test_baseline_save_load_and_regression_diff(self):
        rep1 = _sample_report_with_activity()
        res1 = _sample_result("HEALTHY")
        prof1 = build_process_profile(res1, rep1)
        notable1 = extract_notable_observations(res1, rep1, prof1)

        with tempfile.TemporaryDirectory() as tmp:
            saved = save_diagnosis_baseline(tmp, res1, prof1, notable1)
            self.assertIsNotNone(saved)
            self.assertTrue(os.path.isfile(saved))

            loaded = load_diagnosis_baseline(
                tmp, "latest",
                process_name="edge_worker", build_id="deadbeef1234",
                exclude_investigation_id="inv_test_002",
            )
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["investigation_id"], "inv_test_001")

            # Simulate a regression run: RSS +50% and FD +50%
            snap2 = extract_baseline_snapshot(res1, prof1, notable1)
            snap2["investigation_id"] = "inv_test_002"
            snap2["metrics"]["rss_kb"] = int((snap2["metrics"]["rss_kb"] or 40000) * 1.5)
            snap2["metrics"]["fds"] = 940
            snap2["notable_ids"] = sorted(set(snap2["notable_ids"]) | {"watch_cpu_preemption"})

            diff = compare_diagnosis_baseline(snap2, loaded)
            self.assertTrue(diff["available"])
            self.assertEqual(diff["regression_status"], "REGRESSION")
            self.assertIn("watch_cpu_preemption", diff["new_notable"])
            self.assertIn("회귀 감지", diff["summary_ko"])
            self.assertIn("REGRESSION", diff["summary_en"])

            # Verify rendering in human report
            res2 = dict(res1, investigation_id="inv_test_002", baseline_diff=diff)
            md_ko = render_human_report(res2, rep1, lang="ko")
            self.assertIn("기준선 비교", md_ko)
            self.assertIn("회귀 감지", md_ko)

    def test_llm_agent_summary_and_executable_suggested_actions(self):
        rep = _sample_report_with_activity()
        res = _sample_result("HEALTHY")
        res["target"]["remote_host"] = "10.0.0.5"
        res["target"]["ssh_user"] = "root"
        prof = build_process_profile(res, rep)
        notable = extract_notable_observations(res, rep, prof)
        cov = classify_coverage(res, rep)
        actions = build_suggested_actions(res, rep, prof, cov, notable, None)

        action_ids = {a["id"] for a in actions}
        self.assertIn("full_heap_walk", action_ids)
        self.assertIn("enable_selective_tracing", action_ids)
        self.assertIn("inspect_callstacks_and_locks", action_ids)
        self.assertIn("compare_with_baseline", action_ids)

        heap_act = next(a for a in actions if a["id"] == "full_heap_walk")
        self.assertEqual(heap_act["mcp_tool"], "runtime_heap_leak_candidates")
        self.assertEqual(heap_act["mcp_args"]["pid"], 4242)
        self.assertEqual(heap_act["mcp_args"]["remote_host"], "10.0.0.5")
        self.assertIn("--host 10.0.0.5", heap_act["cli_command"])

        # Agent summary must NOT contain defensive outside_baseline boilerplate
        agent_ko = build_agent_summary(res, prof, cov, notable, None, actions, lang="ko")
        self.assertNotIn("데이터 레이스", agent_ko["headline"])
        self.assertEqual(agent_ko["verdict_qualifier"], "LIMITED_OBSERVATION")
        self.assertIsNotNone(agent_ko["liveness_brief"])
        self.assertIn("44.6", agent_ko["liveness_brief"])
        self.assertGreater(agent_ko["notable_count"], 0)
        self.assertIsNotNone(agent_ko["top_action"])

        comp = compose(res, rep, lang="ko")
        self.assertIn("agent_summary", comp)
        self.assertIn("suggested_actions", comp)
        self.assertIn("coverage", comp)


if __name__ == "__main__":
    unittest.main()
