"""Phase 2.0-A.3.1: Adaptive Investigation Real-Process Validation & Closure Test Suite.

Proves:
1. Scenario A: Healthy Real Process -> NO_ISSUE_DETECTED_WITHIN_SCOPE (with verified live receipt)
   or bounded INCONCLUSIVE (unverified provenance), with zero false-positive anomaly alarms.
2. Scenario B: Suspicious Growing Memory State -> Identifies growth candidate, forms competing hypotheses,
   selects temporal multi-sample observation, verifies growth, and reports suspicion backed by runtime
   observation without falsely claiming universal leak.
3. Scenario C: Thread Contention / Lock Stall -> Selects concurrency observations, narrows investigation,
   identifies relevant waiter thread and mutex, distinguishes blocking from proven circular deadlock.
4. Scenario D: Insufficient Evidence / Stripped Target -> Fails closed with INCONCLUSIVE, clearly documenting
   missing capabilities in uninspected scope.
5. ReadOnlyTargetAdapter capability boundary strictly guards target process against mutation.
6. Multi-dimensional budget enforcement halts investigation cleanly on limit reached.
7. Vague user goal ("Please check whether this process has any problems.") handles full lifecycle
   autonomously with auto-discovery from /proc/<pid>/exe.
8. Standalone zero-CDN HTML and JSON reporting with audit ledger and scope bounding.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from extractor.adaptive_engine import (
    STATE_BUDGET_EXHAUSTED,
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
    AdaptiveInvestigationEngine,
)
from extractor.debug_image import inspect_elf
from extractor.evidence_adapter import (
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.evidence_ledger import (
    CaptureSigningAuthority,
    CaptureVerificationAuthority,
    issue_live_capture_receipt,
)
from extractor.observation_budget import ObservationBudgetLimits
from extractor.target_adapter import LocalTargetAdapter, ReadOnlyTargetAdapter
from extractor.verdict_engine import (
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    DIAG_PARTIALLY_CONFIRMED,
    DIAG_SUSPECTED,
    STOP_ALL_HYPOTHESES_REFUTED,
    STOP_BUDGET_EXHAUSTED,
    STOP_CAPABILITY_UNAVAILABLE,
    STOP_SUFFICIENT_EVIDENCE,
)


class TestPhase20A3RealProcessInvestigation(unittest.TestCase):
    """Real running Linux process test suite for Phase 2.0-A.3.1 Adaptive Investigation."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="phase20_a3_real_test_")
        cls.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")

        # Binaries to compile
        cls.bin_a = os.path.join(cls.tmp_dir, "proc_scenario_a")
        cls.bin_b = os.path.join(cls.tmp_dir, "proc_scenario_b")
        cls.bin_c = os.path.join(cls.tmp_dir, "proc_scenario_c")
        cls.bin_d = os.path.join(cls.tmp_dir, "proc_scenario_d")

        src_a = os.path.join(cls.fixtures_dir, "proc_scenario_a_healthy.c")
        src_b = os.path.join(cls.fixtures_dir, "proc_scenario_b_growing_mem.c")
        src_c = os.path.join(cls.fixtures_dir, "proc_scenario_c_thread_contention.c")
        src_d = os.path.join(cls.fixtures_dir, "proc_scenario_d_stripped.c")

        subprocess.run(["gcc", "-g", "-O0", src_a, "-o", cls.bin_a, "-pthread"], check=True)
        subprocess.run(["gcc", "-g", "-O0", src_b, "-o", cls.bin_b, "-pthread"], check=True)
        subprocess.run(["gcc", "-g", "-O0", src_c, "-o", cls.bin_c, "-pthread"], check=True)
        subprocess.run(["gcc", "-O2", "-s", "-Wl,--strip-all", src_d, "-o", cls.bin_d, "-pthread"], check=True)

        cls.signing_secret = "phase20_a3_test_signing_secret_32b!"
        cls.signer = CaptureSigningAuthority("k_test", cls.signing_secret)
        cls.verifier = CaptureVerificationAuthority({"k_test": cls.signing_secret})

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _create_verified_receipt(self, pid: int, exe_path: str, session_id: str):
        ident = inspect_elf(exe_path)
        return issue_live_capture_receipt(
            session_id=session_id,
            pid=pid,
            executable_path=exe_path,
            build_id=ident.build_id,
            process_start_time="12345",
            manifest_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            signer=self.signer,
            key_id="k_test",
        )

    # -------------------------------------------------------------------------
    # Scenario A: Real Healthy Process
    # -------------------------------------------------------------------------
    def test_01_scenario_a_healthy_process_within_scope(self):
        """Scenario A: Healthy multi-threaded process produces NO_ISSUE_DETECTED_WITHIN_SCOPE
        when verified, and bounded INCONCLUSIVE when unverified, with NO false positive alarms."""
        proc = subprocess.Popen([self.bin_a])
        try:
            time.sleep(0.1)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            # Part 1: With authentic verified LiveCaptureReceipt -> NO_ISSUE_DETECTED_WITHIN_SCOPE
            sess_id = f"sess_a_{pid}"
            rcpt = self._create_verified_receipt(pid, self.bin_a, sess_id)
            res_live = engine.investigate_process_health(
                goal="이 프로세스에 문제가 있는지 검사해주세요.",
                pid=pid,
                companion_elf_path=self.bin_a,
                capture_receipt=rcpt,
                verification_authority=self.verifier,
                session_id=sess_id,
            )

            self.assertTrue(res_live["success"])
            self.assertEqual(res_live["lifecycle_state"], STATE_COMPLETED)
            self.assertEqual(res_live["verdict"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
            self.assertEqual(res_live["final_diagnosis"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
            self.assertIn("insp_locks", res_live["executed_profiles"])
            self.assertIn("insp_memory_maps", res_live["executed_profiles"])
            self.assertGreater(res_live["confidence_score"], 0.70)
            self.assertIn("UNINSPECTED_SCOPE_EXCLUDED", res_live["limitations"])

            # Part 2: Without receipt (unverified imported) -> bounded INCONCLUSIVE
            res_unver = engine.investigate_process_health(
                goal="Please check whether this process has any problems.",
                pid=pid,
                companion_elf_path=self.bin_a,
            )
            self.assertTrue(res_unver["success"])
            self.assertEqual(res_unver["verdict"], DIAG_INCONCLUSIVE)
            self.assertIn("UNVERIFIED_PROVENANCE_CANNOT_PROVE_HEALTH", res_unver["limitations"])

        finally:
            proc.terminate()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario B: Suspicious Growing Memory State
    # -------------------------------------------------------------------------
    def test_02_scenario_b_growing_memory_competing_hypotheses_and_discrimination(self):
        """Scenario B: Continuous memory expansion triggers memory growth candidate,
        forms competing hypotheses (leak vs workload buffering), selects cheapest safe
        temporal observation, verifies growth, and produces bounded SUSPECTED verdict."""
        proc = subprocess.Popen([self.bin_b])
        try:
            time.sleep(0.1)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            res = engine.investigate_process_health(
                goal="이 프로세스에 메모리 문제가 있는지 검사해주세요.",
                pid=pid,
                companion_elf_path=self.bin_b,
            )

            self.assertTrue(res["success"])
            self.assertIn(res["verdict"], (DIAG_SUSPECTED, DIAG_PARTIALLY_CONFIRMED))
            self.assertIn("insp_memory_maps", res["executed_profiles"])
            self.assertIn("insp_temporal_diff", res["executed_profiles"])

            # Verify competing hypotheses were generated
            hypos = res["competing_hypotheses"]
            self.assertGreaterEqual(len(hypos), 2)
            leak_h = next((h for h in hypos if "leak" in h["title"].lower()), None)
            work_h = next((h for h in hypos if "workload" in h["title"].lower() or "caching" in h["title"].lower()), None)

            self.assertIsNotNone(leak_h, "Expected memory leak hypothesis")
            self.assertIsNotNone(work_h, "Expected benign workload hypothesis")

            # Leak hypothesis supported by temporal growth; workload contradicted
            self.assertEqual(leak_h["validation_status"], "SUPPORTED")
            self.assertEqual(work_h["validation_status"], "CONTRADICTED")
            self.assertGreater(leak_h["confidence_score"], work_h["confidence_score"])

            # Honest bounded reporting: memory growth cannot be confirmed leak without application semantics
            self.assertNotEqual(res["verdict"], "CONFIRMED", "Memory growth alone must not be certified CONFIRMED leak")

        finally:
            proc.terminate()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario C: Real Thread Contention / Lock Stall
    # -------------------------------------------------------------------------
    def test_03_scenario_c_thread_contention_and_stall_discrimination(self):
        """Scenario C: Thread contention in futex wait triggers suspicious thread triage,
        forms competing hypotheses (lock contention vs normal idle wait), executes follow-up
        concurrency observation, and identifies stalled waiter thread and mutex."""
        proc = subprocess.Popen([self.bin_c])
        try:
            time.sleep(0.1)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            res = engine.investigate_process_health(
                goal="Please check whether any thread has lock problems.",
                pid=pid,
                companion_elf_path=self.bin_c,
            )

            self.assertTrue(res["success"])
            self.assertIn(res["verdict"], (DIAG_SUSPECTED, DIAG_PARTIALLY_CONFIRMED))
            self.assertIn("insp_locks", res["executed_profiles"])
            self.assertIn("insp_frame_locals", res["executed_profiles"])

            hypos = res["competing_hypotheses"]
            self.assertGreaterEqual(len(hypos), 2)

            # Find hypothesis for the blocked waiter thread
            contended_h = next(
                (h for h in hypos if "blocked on contended lock" in h["title"].lower() and h["validation_status"] == "SUPPORTED"),
                None,
            )
            self.assertIsNotNone(contended_h, "Expected supported lock contention hypothesis for waiter thread")
            self.assertGreaterEqual(contended_h["confidence_score"], 0.65)

            # Contended lock is distinct from proven circular deadlock
            self.assertNotIn("DEADLOCK_CONFIRMED", res["final_diagnosis"])

        finally:
            proc.terminate()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario D: Stripped / Restricted Target -> INCONCLUSIVE
    # -------------------------------------------------------------------------
    def test_04_scenario_d_stripped_binary_fails_closed_inconclusive(self):
        """Scenario D: Stripped binary lacking DWARF symbols fails closed with INCONCLUSIVE,
        explicitly documenting unavailable capabilities in uninspected scope."""
        proc = subprocess.Popen([self.bin_d])
        try:
            time.sleep(0.1)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            res = engine.investigate_process_health(
                goal="Check if stripped process has any problems.",
                pid=pid,
                companion_elf_path=self.bin_d,
            )

            self.assertTrue(res["success"])
            self.assertEqual(res["verdict"], DIAG_INCONCLUSIVE)
            self.assertEqual(res["lifecycle_state"], STATE_INCONCLUSIVE)

            # Verify uninspected scope records DWARF limitation
            uninspected = res["uninspected_scope"]
            self.assertIn("dwarf_symbols_available", uninspected["unavailable_capabilities"])
            self.assertIn("proc_scenario_d", uninspected["unavailable_capabilities"]["dwarf_symbols_available"])

        finally:
            proc.terminate()
            proc.wait()

    # -------------------------------------------------------------------------
    # ReadOnlyTargetAdapter Capability Boundary Enforcement
    # -------------------------------------------------------------------------
    def test_05_read_only_adapter_boundary_blocks_mutation(self):
        """ReadOnlyTargetAdapter strictly blocks target mutation and unauthorized attributes."""
        adapter = ReadOnlyTargetAdapter(LocalTargetAdapter())
        self.assertFalse(adapter.is_remote())
        self.assertIsNotNone(adapter.target_host())

        # Permitted read-only methods work
        alive, _ = adapter.check_liveness(os.getpid())
        self.assertTrue(alive)

        # Mutating methods and unauthorized attributes raise PermissionError
        with self.assertRaises(PermissionError):
            _ = adapter.write_memory
        with self.assertRaises(PermissionError):
            _ = adapter.execute_command
        with self.assertRaises(PermissionError):
            adapter.arbitrary_attribute = 123

    # -------------------------------------------------------------------------
    # Multi-Dimensional Budget Enforcement on Real Target
    # -------------------------------------------------------------------------
    def test_06_budget_exhaustion_on_real_target(self):
        """Observation budget tracker halts investigation when byte or sample ceiling is reached."""
        proc = subprocess.Popen([self.bin_b])
        try:
            time.sleep(0.1)
            pid = proc.pid

            # Severely constrained budget: 1 sample and 256 bytes max
            tiny_limits = ObservationBudgetLimits(
                max_bytes_read=256,
                max_samples=1,
                max_wall_clock_ms=200.0,
            )
            engine = AdaptiveInvestigationEngine(default_limits=tiny_limits)
            res = engine.investigate_process_health(
                goal="Health check with tiny budget.",
                pid=pid,
                companion_elf_path=self.bin_b,
                budget_limits=tiny_limits,
            )

            self.assertTrue(res["success"])
            self.assertEqual(res["lifecycle_state"], STATE_BUDGET_EXHAUSTED)
            self.assertEqual(res["stop_reason"], STOP_BUDGET_EXHAUSTED)
            b_usage = res["budget_usage"]
            self.assertTrue(
                b_usage["metrics"]["rejected_observations_count"] > 0
                or b_usage["metrics"]["is_budget_exhausted"]
                or not b_usage["budget_ok"]
            )

        finally:
            proc.terminate()
            proc.wait()

    # -------------------------------------------------------------------------
    # Autonomous Vague Request Handling & Auto-Discovery
    # -------------------------------------------------------------------------
    def test_07_autonomous_vague_request_handling_without_elf_path(self):
        """Handles vague user request 'Please check whether this process has any problems'
        with PID only; autonomously discovers binary via /proc/<pid>/exe and completes loop."""
        proc = subprocess.Popen([self.bin_a])
        try:
            time.sleep(0.1)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            # Pass PID only, companion_elf_path empty
            res = engine.investigate_process_health(
                goal="Please check whether this process has any problems.",
                pid=pid,
                companion_elf_path="",
            )

            self.assertTrue(res["success"])
            self.assertIn("insp_locks", res["executed_profiles"])
            self.assertIn("insp_memory_maps", res["executed_profiles"])
            # Proves /proc/<pid>/exe was auto-discovered
            self.assertEqual(res["target_identity"]["pid"], pid)
            self.assertTrue(res["target_identity"]["companion_elf"].endswith("proc_scenario_a"))
            self.assertTrue(res["target_identity"]["has_dwarf_info"])

        finally:
            proc.terminate()
            proc.wait()

    # -------------------------------------------------------------------------
    # Standalone Zero-CDN HTML and JSON Reporting
    # -------------------------------------------------------------------------
    def test_08_auditable_zero_cdn_report_generation(self):
        """Investigation produces complete, self-contained HTML and JSON reports
        with no external network dependencies, full ledger, and audit trail."""
        proc = subprocess.Popen([self.bin_c])
        try:
            time.sleep(0.1)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            res = engine.investigate_process_health(
                goal="Audit process health and generate zero-CDN report.",
                pid=pid,
                companion_elf_path=self.bin_c,
            )

            self.assertTrue(res["success"])
            html_rep = res.get("report_html", "")
            json_rep = res.get("report_json", "")

            # Zero-CDN invariant: no external scripts or stylesheets
            self.assertNotIn("http://", html_rep)
            self.assertNotIn("https://", html_rep)
            self.assertIn("<!DOCTYPE html>", html_rep)
            self.assertIn("dynamicState Process Health Investigation", html_rep)

            # JSON report invariant
            self.assertIn('"final_diagnosis":', json_rep)
            self.assertIn('"confidence_score":', json_rep)

            # Ledger integrity
            self.assertGreater(res["evidence_ledger_count"], 0)
            self.assertEqual(len(res["evidence_ledger"]["records"]), res["evidence_ledger_count"])

        finally:
            proc.terminate()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
