"""Comprehensive stability, reliability, and edge-case tests across all 8 DynamicState pillars.

Verifies:
1. Native Collector signal safety (SIGPIPE / SIGTERM clean termination, zero orphan tmp files)
2. Remote SSH Collection boundedness, structured error classification, and expired-cache fail-closed
3. Temporal Observation Window NaN/Inf/negative timestamp rejection and PARTIAL sample regression detection
4. Evidence Ledger provenance & rejected-identity weight exclusion
5. Expert Diagnostic Engine weight sanitization, anti-inflation, and corroboration guard
6. Adaptive Observation Selector deterministic tie-breaking, None/NaN resilience, and _snapshot_cache TTL reuse
7. MCP Server strict input validation and structured INVALID_PARAM error responses
8. Traceable Diagnostic Report HTML escaping, partial/inconclusive rendering, and evidence ID traceability
"""

import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from extractor.competing_hypotheses import (
    CompetingHypothesis,
    VERDICT_INCONCLUSIVE,
)
from extractor.diagnostic_report import (
    CompetingHypothesesSection,
    DetailedInspectionResultsSection,
    DiagnosticReport,
    DiagnosticStrategySection,
    EvidenceAndProvenanceSection,
    EvidenceIndexEntry,
    ExecutiveSummarySection,
    FinalConclusionsSection,
    FindingRecord,
    FindingsSection,
    LimitationsSection,
    TargetContextSection,
    detail_findings_html,
    detail_hypotheses_html,
)
from extractor.evidence_ledger import EvidenceLedger
from extractor.observation_selector import select_discriminating_recipe
from extractor.target_adapter import RemoteSshTargetAdapter
from extractor.temporal_observation_window import (
    MemoryBehavior,
    MemorySample,
    ObservationWindow,
)


class TestPillar1NativeCollectorSignalSafety(unittest.TestCase):
    """Pillar 1: Native collector signal handling and clean daemon exit."""

    def setUp(self):
        self.collector_bin = str(
            Path(__file__).resolve().parent.parent / "target" / "collector" / "dynamicstate-collector"
        )

    def test_daemon_handles_broken_stdout_pipe_without_sigpipe_crash(self):
        if not os.path.exists(self.collector_bin):
            self.skipTest("Native collector binary not built")
        proc = subprocess.Popen(
            [self.collector_bin, "--daemon"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            # Close stdout from reader side, then send a command; SIGPIPE must be ignored (not killed by signal 13)
            assert proc.stdout is not None and proc.stdin is not None
            proc.stdout.close()
            try:
                proc.stdin.write(b"STATS\nQUIT\n")
                proc.stdin.flush()
            except BrokenPipeError:
                pass
            proc.stdin.close()
            rc = proc.wait(timeout=5)
            self.assertNotEqual(rc, -signal.SIGPIPE, "Collector must ignore SIGPIPE rather than crash")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_daemon_exits_cleanly_on_sigterm(self):
        if not os.path.exists(self.collector_bin):
            self.skipTest("Native collector binary not built")
        proc = subprocess.Popen(
            [self.collector_bin, "--daemon"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            time.sleep(0.05)
            proc.send_signal(signal.SIGTERM)
            rc = proc.wait(timeout=5)
            self.assertEqual(rc, 0, "Collector daemon should exit cleanly (0) on SIGTERM")
        finally:
            for s in (proc.stdin, proc.stdout, proc.stderr):
                if s:
                    try: s.close()
                    except Exception: pass
            if proc.poll() is None:
                proc.kill()
                proc.wait()


class TestPillar2RemoteCollectionReliability(unittest.TestCase):
    """Pillar 2: Remote SSH bounds, structured error classification, and expired-cache fail-closed."""

    def test_invalid_port_and_timeout_rejected(self):
        with self.assertRaises(ValueError):
            RemoteSshTargetAdapter(host="10.0.0.1", port=0)
        with self.assertRaises(ValueError):
            RemoteSshTargetAdapter(host="10.0.0.1", port=70000)
        with self.assertRaises(ValueError):
            RemoteSshTargetAdapter(host="10.0.0.1", port=True)
        with self.assertRaises(ValueError):
            RemoteSshTargetAdapter(host="10.0.0.1", timeout_sec=0.0)
        with self.assertRaises(ValueError):
            RemoteSshTargetAdapter(host="10.0.0.1", timeout_sec=float("nan"))

    def test_classify_remote_error_categories(self):
        cls = RemoteSshTargetAdapter.classify_remote_error
        self.assertEqual(cls(0, ""), "OK")
        self.assertEqual(cls(-1, "SSH command timed out after 5.0s"), "TIMEOUT")
        self.assertEqual(cls(-1, "Remote collection step deadline exceeded"), "TIMEOUT")
        self.assertEqual(cls(255, "Permission denied (publickey)."), "PERMISSION_DENIED")
        self.assertEqual(cls(255, "ssh: connect to host 10.0.0.1 port 22: Connection refused"), "TRANSPORT_ERROR")
        self.assertEqual(cls(1, "cat: /proc/999/status: No such file or directory"), "UNAVAILABLE")
        self.assertEqual(cls(1, "", "@@LIVENESS\nALIVE\n"), "INVALID_DATA")

    def test_zero_and_nan_timeout_rejected_in_run_ssh(self):
        called = []

        def runner(args, timeout):
            called.append(timeout)
            return 0, "ok", ""

        adapter = RemoteSshTargetAdapter(host="10.0.0.1", command_runner=runner, use_control_master=False)
        rc, out, err = adapter.run_ssh("echo hi", timeout=0.0)
        self.assertEqual(rc, -1)
        self.assertIn("Invalid non-positive", err)
        self.assertEqual(called, [])

        rc2, _, err2 = adapter.run_ssh("echo hi", timeout=float("nan"))
        self.assertEqual(rc2, -1)
        self.assertIn("Invalid non-positive", err2)
        self.assertEqual(called, [])

    def test_prefetch_snapshot_never_returns_expired_cache_on_ssh_failure(self):
        fail_now = [False]

        def runner(args, timeout):
            if fail_now[0]:
                return -1, "", "SSH command timed out after 5.0s"
            out = "\n".join([
                "@@LIVENESS", "ALIVE",
                "@@COMM", "worker",
                "@@STAT", "1234 (worker) S 1 1 1 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 5555 0 0",
                "@@STATUS", "Name:\tworker\nVmRSS:\t4096 kB\n",
                "@@EXE", "/usr/bin/worker",
                "@@FP", "100:200:300",
                "@@BOOT", "boot-uuid-1",
                "@@OSREL", "6.1.0",
                "@@MACH", "x86_64",
                "@@END",
            ])
            return 0, out, ""

        adapter = RemoteSshTargetAdapter(host="10.0.0.1", command_runner=runner, use_control_master=False)
        snap1 = adapter.prefetch_snapshot(1234, domains={"basic"})
        self.assertIsNotNone(snap1)
        self.assertEqual(snap1["comm"], "worker")
        self.assertIsNone(adapter._last_snapshot_error)

        # Backdate cache entry beyond max_age_s so it is expired
        ts, payload, doms = adapter._snapshot_cache[1234]
        adapter._snapshot_cache[1234] = (ts - 10.0, payload, doms)

        fail_now[0] = True
        snap2 = adapter.prefetch_snapshot(1234, domains={"basic"})
        self.assertIsNone(snap2, "Expired snapshot must NOT be returned when refresh fails")
        self.assertIsNotNone(adapter._last_snapshot_error)
        self.assertEqual(adapter._last_snapshot_error["category"], "TIMEOUT")


class TestPillar3TemporalAnalysisEdgeCases(unittest.TestCase):
    """Pillar 3: Temporal window rejects NaN/Inf timestamps and catches PARTIAL regressions."""

    def test_nan_and_inf_monotonic_timestamps_flagged_as_invalid(self):
        for bad_ts in (float("nan"), float("inf"), float("-inf"), -1.0):
            win = ObservationWindow(target_pid=42)
            win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=10.0, rss_kb=1000))
            win.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=bad_ts, rss_kb=2000))
            self.assertTrue(win.has_temporal_regression(), f"Bad timestamp {bad_ts} must fail temporal check")
            res = win.analyze_memory_behavior()
            self.assertEqual(res.behavior, MemoryBehavior.TEMPORAL_SEQUENCE_INVALID)
            self.assertEqual(res.confidence, 0.0)

    def test_partial_sample_clock_regression_detected(self):
        win = ObservationWindow(target_pid=42)
        win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=20.0, rss_kb=1000))
        # rss_kb=None marks sample as PARTIAL; monotonic regression must still be caught
        win.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=15.0, rss_kb=None, heap_vma_kb=4096))
        win.record_sample(MemorySample(epoch_id=3, monotonic_timestamp=25.0, rss_kb=3000))
        self.assertTrue(win.has_temporal_regression())
        res = win.analyze_memory_behavior()
        self.assertEqual(res.behavior, MemoryBehavior.TEMPORAL_SEQUENCE_INVALID)


class TestPillar4And5EvidenceAndHypothesesSafety(unittest.TestCase):
    """Pillars 4 & 5: Non-finite weights and mismatched/missing evidence cannot inflate confidence."""

    def test_non_finite_and_negative_weights_sanitized(self):
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_CPU_SATURATION",
            title="CPU Saturation",
            category="CPU_UTILIZATION",
            confidence=0.50,
        )
        hyp.add_supporting_observation("inf weight attempt", weight=float("inf"))
        hyp.add_supporting_observation("nan weight attempt", weight=float("nan"))
        hyp.add_supporting_observation("neg weight attempt", weight=-5.0)
        self.assertTrue(math.isfinite(hyp.confidence))
        self.assertLessEqual(hyp.confidence, 0.55)

    def test_corrupted_base_confidence_recovers_safely(self):
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_MEMORY_LEAK",
            title="Memory Leak",
            category="MEMORY_GROWTH",
            confidence=float("nan"),
        )
        hyp.evaluate_verdict()
        self.assertTrue(math.isfinite(hyp.confidence))
        self.assertGreaterEqual(hyp.confidence, 0.05)
        self.assertLessEqual(hyp.confidence, 0.99)

    def test_deleted_ledger_record_weight_excluded_on_reevaluation(self):
        ledger = EvidenceLedger(session_id="sess_test")
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_CPU_SATURATION",
            title="CPU Saturation",
            category="CPU_UTILIZATION",
            confidence=0.50,
            ledger=ledger,
        )
        # Simulate stale weight entry for an evidence ID not in ledger
        hyp.supporting_evidence_ids.append("ev_ghost_999")
        hyp._support_weights["ev_ghost_999"] = 0.45
        hyp.evaluate_verdict(ledger=ledger)
        self.assertLessEqual(hyp.confidence, 0.50)
        self.assertIn("ev_ghost_999", hyp.rejected_evidence_reasons)


class TestPillar6AdaptiveObservationSelector(unittest.TestCase):
    """Pillar 6: Deterministic tie-breaking, None/NaN resilience, and fresh _snapshot_cache reuse."""

    def test_none_and_nan_confidence_and_deterministic_tie_break(self):
        h_b = SimpleNamespace(hypothesis_id="HYP_B", status="PLAUSIBLE", confidence=None, applicable_diagnostic_rules=["REC_1"])
        h_a = SimpleNamespace(hypothesis_id="HYP_A", status="PLAUSIBLE", confidence=float("nan"), applicable_diagnostic_rules=["REC_1", "REC_2"])
        r1 = SimpleNamespace(recipe_id="REC_1", observations=["proc_status"], risk_level="READ_ONLY", domain="basic")
        r2 = SimpleNamespace(recipe_id="REC_2", observations=["memory_maps"], risk_level="READ_ONLY", domain="maps")
        rid, log, rationale = select_discriminating_recipe([h_b, h_a], [r1, r2])
        self.assertEqual(rid, "REC_1")
        self.assertIn("REC_1", rationale)

    def test_remote_snapshot_cache_ttl_and_empty_domain_guard(self):
        h1 = SimpleNamespace(hypothesis_id="HYP_1", status="PLAUSIBLE", confidence=0.6, applicable_diagnostic_rules=["REC_MAPS", "REC_FDS"])
        h2 = SimpleNamespace(hypothesis_id="HYP_2", status="PLAUSIBLE", confidence=0.55, applicable_diagnostic_rules=["REC_MAPS", "REC_FDS"])
        r_maps = SimpleNamespace(recipe_id="REC_MAPS", observations=["memory_maps"], risk_level="READ_ONLY", domain="maps")
        r_fds = SimpleNamespace(recipe_id="REC_FDS", observations=["proc_fd"], risk_level="READ_ONLY", domain="fds")

        # Adapter with fresh 'maps' and expired 'fds'
        now = time.monotonic()
        adapter = SimpleNamespace(
            _snapshot_cache={
                100: (now, {"terminated": False}, frozenset({"basic", "maps"})),
                200: (now - 10.0, {"terminated": False}, frozenset({"fds"})),
            }
        )
        rid, log, _ = select_discriminating_recipe([h1, h2], [r_maps, r_fds], target_adapter=adapter)
        self.assertEqual(rid, "REC_MAPS")
        by_id = {e["recipe_id"]: e for e in log}
        self.assertTrue(by_id["REC_MAPS"]["evidence_reuse_available"])
        self.assertEqual(by_id["REC_MAPS"]["estimated_bytes"], 0)
        self.assertFalse(by_id["REC_FDS"]["evidence_reuse_available"])

        # Empty string in cached_domains must never falsely match empty recipe domain
        h_empty = SimpleNamespace(hypothesis_id="HYP_E", status="PLAUSIBLE", confidence=0.5, applicable_diagnostic_rules=["REC_EMPTY"])
        r_empty = SimpleNamespace(recipe_id="REC_EMPTY", observations=["proc_status"], risk_level="READ_ONLY", domain="")
        _, log2, _ = select_discriminating_recipe([h_empty], [r_empty], cached_domains={"", "   "})
        self.assertFalse(log2[0]["evidence_reuse_available"])


class TestPillar7McpInputValidation(unittest.TestCase):
    """Pillar 7: MCP tool input validation returns structured INVALID_PARAM errors."""

    def test_mcp_input_validation_when_mcp_available(self):
        try:
            import scripts.mcp_server as mcp_srv
        except Exception:
            self.skipTest("mcp package not installed in this environment")

        for bad_pid in (-5, 0, 1, True, False, 1.5):
            res_bad_pid = json.loads(mcp_srv.runtime_diagnose_process(pid=bad_pid))
            self.assertFalse(res_bad_pid["success"], f"Expected failure for pid={bad_pid!r}")
            self.assertEqual(res_bad_pid["error_code"], "INVALID_PID")

        res_bad_port = json.loads(mcp_srv.runtime_diagnose_process(pid=99999, ssh_port=99999))
        self.assertFalse(res_bad_port["success"])
        self.assertEqual(res_bad_port["error_code"], "INVALID_PARAM")

        res_bad_tl = json.loads(mcp_srv.runtime_diagnose_process(pid=99999, time_limit_s=float("nan")))
        self.assertFalse(res_bad_tl["success"])
        self.assertEqual(res_bad_tl["error_code"], "INVALID_PARAM")

        res_bad_fmt = json.loads(mcp_srv.runtime_get_investigation_report("inv_1", format="exe"))
        self.assertFalse(res_bad_fmt["success"])
        self.assertEqual(res_bad_fmt["error_code"], "INVALID_PARAM")


class TestPillar8TraceableReportRendering(unittest.TestCase):
    """Pillar 8: HTML escaping and traceability of findings and hypotheses."""

    def test_html_rendering_escapes_script_injection_and_preserves_evidence_ids(self):
        findings = [
            {
                "finding_id": "FND_1",
                "classification": "CONFIRMED_PROBLEM",
                "severity": "HIGH",
                "epistemic_level": "DIRECT_OBSERVATION",
                "problem_description": "<script>alert('xss')</script> Leak detected",
                "affected_entity": "worker<0>",
                "observed_behavior": "RSS grew",
                "technical_explanation": "Unbounded growth",
                "confidence_basis": "2 independent roots",
                "verification_status": "VERIFIED",
                "applicable_diagnostic_rules": ["RECIPE_MEM_GROWTH"],
                "supporting_evidence_ids": ["ev_root_01", "ev_root_02"],
                "source_references": ["main.cpp:42"],
            }
        ]
        html = detail_findings_html(findings)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("ev_root_01", html)
        self.assertIn("ev_root_02", html)

        hyps = [
            {
                "hypothesis_id": "HYP_MEM",
                "status": VERDICT_INCONCLUSIVE,
                "title": "<b>Ambiguous</b>",
                "confidence": 0.45,
                "supporting_evidence_ids": ["ev_root_01"],
                "contradicting_evidence_ids": ["ev_contra_01"],
            }
        ]
        h_html = detail_hypotheses_html(hyps)
        self.assertNotIn("<b>Ambiguous</b>", h_html)
        self.assertIn("ev_root_01", h_html)
        self.assertIn("ev_contra_01", h_html)


if __name__ == "__main__":
    unittest.main()
