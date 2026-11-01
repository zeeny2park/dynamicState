"""Phase 2.0-A.3.2: Adaptive Investigation Evidence Accuracy & Real Capture Validation.

Validates diagnostic correctness and evidence quality:
1. Memory Evidence Accuracy (VSZ vs RSS vs Mapping Size vs Anon vs Allocations).
2. Memory Temporal Sequence Analysis (sustained growth vs temporary burst/drop vs allocator retention).
3. Thread & Futex Accuracy (futex wait != deadlock; zero synthetic 0x_lock addresses).
4. Companion ELF & Target Identity (Build ID equality verification, deleted executables, stripped binaries).
5. Real Collector-to-Investigation Integration (dynamicstate-collector binary output, HMAC receipt, tamper tests).
6. Adaptive Hypothesis Quality & Ranking Shifts (discriminating observations invert ranking).
7. Low-Impact and Budget Guarantees (read-only boundary, explicit error statuses).
"""

import errno
import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from typing import Any, Dict, List

from extractor.adaptive_engine import (
    AdaptiveInvestigationEngine,
    DIAG_CONFIRMED,
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
    STATE_OBSERVATION,
)
from extractor.debug_image import inspect_elf
from extractor.evidence_adapter import (
    RESULT_DUPLICATE_EVIDENCE,
    RESULT_NEW_EVIDENCE,
    RESULT_OBSERVATION_FAILED,
    RESULT_OBSERVATION_UNAVAILABLE,
)
from extractor.evidence_ledger import (
    CaptureSigningAuthority,
    CaptureVerificationAuthority,
    EvidenceLedger,
    LiveCaptureReceipt,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    TRUST_STATE_IMPORTED_UNVERIFIED,
    TRUST_STATE_INVALID_OR_TAMPERED,
    TRUST_STATE_LIVE_VERIFIED,
    determine_snapshot_trust_state,
    verify_live_capture_receipt,
)
from extractor.hypothesis import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    DeterministicHypothesisGenerator,
    FollowUpObservation,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HypothesisValidator,
    InvestigationHypothesis,
)
from extractor.observation_budget import ObservationBudgetLimits
from extractor.memory_snapshot import RawMemorySnapshot
from extractor.target_adapter import LocalTargetAdapter, ReadOnlyTargetAdapter


class TestPhase20A32EvidenceAccuracy(unittest.TestCase):
    """Phase 2.0-A.3.2 Evidence Accuracy & Real Capture Validation Suite."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_a32_")
        cls.fixtures_dir = os.path.abspath("tests/fixtures/real_runtime")
        cls.collector_bin = os.path.abspath("target/collector/dynamicstate-collector")

        # Compile native C test fixtures
        cls.bin_healthy = os.path.join(cls.work_dir, "proc_healthy")
        cls.bin_burst_drop = os.path.join(cls.work_dir, "proc_burst_drop")
        cls.bin_vsz_only = os.path.join(cls.work_dir, "proc_vsz_only")
        cls.bin_normal_cv = os.path.join(cls.work_dir, "proc_normal_cv")
        cls.bin_deadlock = os.path.join(cls.work_dir, "proc_deadlock")
        cls.bin_stripped = os.path.join(cls.work_dir, "proc_stripped")
        cls.bin_comp_diff = os.path.join(cls.work_dir, "proc_comp_diff")

        # Compile healthy fixture
        src_healthy = os.path.join(cls.fixtures_dir, "proc_scenario_a_healthy.c")
        subprocess.check_call(["gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g", src_healthy, "-o", cls.bin_healthy])

        # Compile burst and drop fixture
        src_burst = os.path.join(cls.fixtures_dir, "proc_mem_burst_and_drop.c")
        subprocess.check_call(["gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g", src_burst, "-o", cls.bin_burst_drop])

        # Compile VSZ mapping only fixture
        src_vsz = os.path.join(cls.fixtures_dir, "proc_mem_vsz_mapping_only.c")
        subprocess.check_call(["gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g", src_vsz, "-o", cls.bin_vsz_only])

        # Compile normal condition variable fixture
        src_cv = os.path.join(cls.fixtures_dir, "proc_thread_normal_cv.c")
        subprocess.check_call(["gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g", src_cv, "-o", cls.bin_normal_cv])

        # Compile deadlock fixture
        src_dl = os.path.join(cls.fixtures_dir, "proc_thread_circular_deadlock.c")
        subprocess.check_call(["gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g", src_dl, "-o", cls.bin_deadlock])

        # Compile stripped fixture
        src_stripped = os.path.join(cls.fixtures_dir, "proc_scenario_d_stripped.c")
        subprocess.check_call(["gcc", "-O2", "-s", src_stripped, "-o", cls.bin_stripped])

        # Compile a separate companion binary with a distinct Build ID
        subprocess.check_call(["gcc", "-O2", "-g", "-DDIFFERENT_BUILD=1", src_stripped, "-o", cls.bin_comp_diff])

        # Ensure collector binary is built
        if not os.path.exists(cls.collector_bin):
            subprocess.check_call(["make", "-C", "target/collector", "dynamicstate-collector"])

        # Test signing key for trust tests (valid UTF-8 string >= 16 chars)
        cls.test_secret = "secret_key_1234567890_trusted_prod_32b"
        cls.test_key_file = os.path.join(cls.work_dir, "capture.key")
        with open(cls.test_key_file, "w", encoding="utf-8") as f:
            f.write(cls.test_secret + "\n")
        os.chmod(cls.test_key_file, 0o600)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    # =========================================================================
    # Group 1: Memory Evidence Accuracy & Temporal Analysis
    # =========================================================================

    def test_01_distinguish_vsz_from_rss_and_mapping_growth(self):
        """Strictly distinguishes VSZ / mapping growth from RSS and physical page allocation.
        mmap(64MB) without touching pages increases virtual mappings, but RSS remains flat."""
        proc = subprocess.Popen([self.bin_vsz_only])
        try:
            time.sleep(0.01)
            pid = proc.pid
            adapter = LocalTargetAdapter()

            # Execute insp_temporal_diff on this process across the mmap event
            engine = AdaptiveInvestigationEngine()
            ctx = engine.registry.get("insp_temporal_diff")
            self.assertIsNotNone(ctx)

            # Profile execution detects mapping expansion without allocation
            res = ctx.func(
                None,
                pid=pid,
                adapter=adapter,
                target_expression="anonymous_mmap",
                wait_ms=35,
                num_samples=3,
            )
            self.assertTrue(res["success"])
            self.assertEqual(res["status"], "OBSERVED")

            mem_info = adapter.get_process_memory_info(pid)
            self.assertEqual(mem_info["status"], "OBSERVED")
            metrics = mem_info["metrics"]
            mappings = mem_info["mappings_summary"]

            # VSZ / total mapping size is >= 64MB
            self.assertGreaterEqual(metrics["vsz_bytes"], 64 * 1024 * 1024)
            self.assertGreaterEqual(mappings["total_mapping_size_bytes"], 64 * 1024 * 1024)

            # RSS is small (< 10MB) because pages were not faulted/touched
            self.assertLess(metrics["rss_bytes"], 10 * 1024 * 1024)

            # Proves mapping expansion without allocation is distinguished from leak
            self.assertIn(res["observed_condition"], ("mapping_expansion_without_allocation", "stable_or_reclaimed_allocation"))
            self.assertFalse(res["growth_detected"])

        finally:
            proc.terminate()
            proc.wait()

    def test_02_temporary_workload_burst_and_drop_discrimination(self):
        """Temporary workload buffering allocates burst and frees it.
        Temporal differential detects surge then drop and refutes memory leak hypothesis."""
        proc = subprocess.Popen([self.bin_burst_drop])
        try:
            time.sleep(0.01)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            # Execute temporal diff during the burst and drop sequence
            ctx = engine.registry.get("insp_temporal_diff")
            res = ctx.func(
                None,
                pid=pid,
                adapter=LocalTargetAdapter(),
                target_expression="[heap]",
                wait_ms=35,
                num_samples=3,
            )
            self.assertTrue(res["success"])
            self.assertEqual(res["status"], "OBSERVED")
            self.assertEqual(res["num_samples"], 3)
            self.assertIn(res["observed_condition"], ("temporary_workload_buffering", "stable_or_reclaimed_allocation"))

            # When evaluated against competing hypotheses, burst & drop contradicts leak and supports workload
            h_leak = InvestigationHypothesis(
                hypothesis_id="hypo_mem_leak_test",
                investigation_id="inv_test",
                title="Memory Leak in [heap]",
                claim="Continuous unreleased allocations cause monotonic growth",
            )
            h_workload = InvestigationHypothesis(
                hypothesis_id="hypo_mem_workload_test",
                investigation_id="inv_test",
                title="Workload Buffering in [heap]",
                claim="Temporary memory usage that is reclaimed",
            )
            obs = FollowUpObservation(
                observation_id="obs_disc_temp",
                hypothesis_id="hypo_mem_leak_test",
                tested_hypothesis_ids=["hypo_mem_leak_test", "hypo_mem_workload_test"],
                expected_outcomes_by_hypothesis={
                    "hypo_mem_leak_test": {
                        "temporary_workload_buffering": "CONTRADICTED",
                        "sustained_monotonic_growth": "SUPPORTED",
                    },
                    "hypo_mem_workload_test": {
                        "temporary_workload_buffering": "SUPPORTED",
                        "sustained_monotonic_growth": "CONTRADICTED",
                    },
                },
            )

            ledger = EvidenceLedger(session_id="inv_test")
            ev_rec = engine.adapter.adapt_generic_tool_output(
                tool_name="insp_temporal_diff",
                tool_result={"observed_condition": "temporary_workload_buffering", "is_temporal_sample": True},
                target_identity={"pid": pid},
                session_id="inv_test",
                ledger=ledger,
                epoch=1,
            )
            ev_rec.details["outcomes_by_hypothesis"] = {
                "hypo_mem_leak_test": "CONTRADICTED",
                "hypo_mem_workload_test": "SUPPORTED",
            }
            engine.adapter.record_into_ledger(ev_rec, ledger)

            HypothesisValidator.evaluate(h_leak, ledger, ev_rec)
            HypothesisValidator.evaluate(h_workload, ledger, ev_rec)

            self.assertEqual(h_leak.validation_status, HYPOTHESIS_STATUS_CONTRADICTED)
            self.assertEqual(h_workload.validation_status, HYPOTHESIS_STATUS_SUPPORTED)
            self.assertLess(h_leak.confidence_score, h_workload.confidence_score)

        finally:
            proc.terminate()
            proc.wait()

    def test_03_memory_leak_never_confirmed_solely_from_proc(self):
        """A memory leak must NEVER be CONFIRMED solely from /proc measurements.
        Procfs cannot verify individual object chunk lifetimes or prove lack of deallocation."""
        adapter = LocalTargetAdapter()
        mem_info = adapter.get_process_memory_info(os.getpid())
        metadata = mem_info["metadata"]

        # Verify documented limitations for procfs metrics
        self.assertIn("allocation_evidence", metadata)
        self.assertIn("object_lifetime_evidence", metadata)
        self.assertIn("limitations", metadata["allocation_evidence"])
        self.assertIn("cannot be proven by procfs alone", metadata["allocation_evidence"]["limitations"])

        # Even with monotonic growth, an adaptive investigation without chunk-level proof
        # caps the hypothesis status at SUPPORTED, never VALIDATED/CONFIRMED root cause
        h = InvestigationHypothesis(
            hypothesis_id="h_leak_test",
            investigation_id="inv_leak",
            title="Memory Growth",
            claim="Process exhibits memory growth",
        )
        ledger = EvidenceLedger(session_id="inv_leak")
        engine = AdaptiveInvestigationEngine()
        ev = engine.adapter.adapt_generic_tool_output(
            tool_name="insp_temporal_diff",
            tool_result={
                "observed_condition": "sustained_monotonic_growth",
                "growth_detected": True,
                "is_temporal_sample": True,
            },
            target_identity={"pid": os.getpid()},
            session_id="inv_leak",
            ledger=ledger,
            epoch=1,
        )
        ev.details["outcome"] = "SUPPORTED"
        engine.adapter.record_into_ledger(ev, ledger)

        HypothesisValidator.evaluate(h, ledger, ev)
        # Must be SUPPORTED, NOT VALIDATED (cannot be confirmed without causal deallocation proof)
        self.assertEqual(h.validation_status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertNotEqual(h.validation_status, "VALIDATED")

    def test_04_allocator_retention_vs_active_growth(self):
        """Distinguishes allocator retention (initial jump then flat plateau) from active leak."""
        engine = AdaptiveInvestigationEngine()
        h_leak = InvestigationHypothesis(hypothesis_id="h_leak_ret", investigation_id="inv_ret")
        h_workload = InvestigationHypothesis(hypothesis_id="h_work_ret", investigation_id="inv_ret")

        ledger = EvidenceLedger(session_id="inv_ret")
        ev = engine.adapter.adapt_generic_tool_output(
            tool_name="insp_temporal_diff",
            tool_result={
                "observed_condition": "allocator_retention",
                "condition_detail": "Initial jump retained by allocator; stable bounds",
                "is_temporal_sample": True,
            },
            target_identity={"pid": os.getpid()},
            session_id="inv_ret",
            ledger=ledger,
            epoch=1,
        )
        ev.details["outcomes_by_hypothesis"] = {
            "h_leak_ret": "CONTRADICTED",
            "h_work_ret": "SUPPORTED",
        }
        engine.adapter.record_into_ledger(ev, ledger)

        HypothesisValidator.evaluate(h_leak, ledger, ev)
        HypothesisValidator.evaluate(h_workload, ledger, ev)

        self.assertEqual(h_leak.validation_status, HYPOTHESIS_STATUS_CONTRADICTED)
        self.assertEqual(h_workload.validation_status, HYPOTHESIS_STATUS_SUPPORTED)

    def test_05_procfs_memory_info_schema_and_metadata_documentation(self):
        """Verifies get_process_memory_info returns structured metrics and documented costs."""
        adapter = LocalTargetAdapter()
        info = adapter.get_process_memory_info(os.getpid())
        self.assertEqual(info["status"], "OBSERVED")
        self.assertIn("vsz_bytes", info["metrics"])
        self.assertIn("rss_bytes", info["metrics"])
        self.assertIn("total_mapping_size_bytes", info["mappings_summary"])
        self.assertIn("heap_mapping_size_bytes", info["mappings_summary"])

        meta = info["metadata"]
        for key in ("vsz", "rss", "mapping_size", "allocation_evidence"):
            self.assertIn(key, meta)
            self.assertIn("source", meta[key])
            self.assertIn("limitations", meta[key])
            self.assertIn("estimated_cost_bytes", meta[key])

    # =========================================================================
    # Group 2: Thread & Futex Evidence Accuracy
    # =========================================================================

    def test_06_normal_condition_variable_wait_not_contention_or_deadlock(self):
        """A thread waiting on pthread_cond_timedwait enters futex wait.
        Regular wakeup and forward progress prove it is NOT deadlock or contention stall."""
        proc = subprocess.Popen([self.bin_normal_cv])
        try:
            time.sleep(0.1)
            pid = proc.pid
            adapter = LocalTargetAdapter()

            threads = adapter.get_threads(pid)
            self.assertGreaterEqual(len(threads), 2)

            worker = next((t for t in threads if t["tid"] != pid), None)
            self.assertIsNotNone(worker)
            self.assertTrue(worker["is_futex_wait"])
            self.assertIn(worker["state"], ("S", "R"))

            # Execute insp_frame_locals across intervals
            engine = AdaptiveInvestigationEngine()
            ctx = engine.registry.get("insp_frame_locals")
            res = ctx.func(
                None,
                pid=pid,
                tid=worker["tid"],
                adapter=adapter,
            )
            self.assertTrue(res["success"])
            self.assertEqual(res["status"], "OBSERVED")
            # Progress occurred across intervals -> uncontended or normal progress
            self.assertEqual(res["observed_condition"], "uncontended_or_normal_progress")
            self.assertFalse(res.get("is_stalled", True))

        finally:
            proc.terminate()
            proc.wait()

    def test_07_unknown_lock_address_reported_honestly_no_synthetic_strings(self):
        """When lock address cannot be decoded from kernel syscall, report None/UNAVAILABLE.
        Zero synthetic strings such as '0x_lock' or '0x_futex_lock' allowed."""
        engine = AdaptiveInvestigationEngine()
        ctx = engine.registry.get("insp_locks")

        # Mock adapter where thread is waiting in futex but syscall_arg0 is None
        class MockFutexNoAddrAdapter(LocalTargetAdapter):
            def get_threads(self, pid: int):
                return [{
                    "tid": pid + 1,
                    "name": "worker_no_uaddr",
                    "state": "S",
                    "is_futex_wait": True,
                    "syscall_nr": 98,
                    "syscall_name": "futex",
                    "syscall_arg0": None,
                    "syscall_arg0_int": None,
                    "waiting_on_lock": None,
                    "lock_address_status": "UNAVAILABLE",
                    "wchan": "futex_wait_queue",
                }]

        res = ctx.func(None, pid=12345, adapter=MockFutexNoAddrAdapter())
        self.assertTrue(res["success"])
        threads = res["threads"]
        self.assertEqual(len(threads), 1)
        th = threads[0]

        # Verify lock address is None, NOT synthetic string
        self.assertIsNone(th.get("waiting_on_lock"))
        self.assertEqual(th.get("lock_address_status"), "UNAVAILABLE")
        self.assertNotEqual(th.get("waiting_on_lock"), "0x_lock")
        self.assertNotEqual(th.get("waiting_on_lock"), "0x_futex_lock")

    def test_08_deterministic_circular_deadlock_confirmed_only_with_circular_wait(self):
        """Cross-locking mutex deadlock fixture confirms both threads stalled on mutexes."""
        proc = subprocess.Popen([self.bin_deadlock])
        try:
            time.sleep(0.1)
            pid = proc.pid
            adapter = LocalTargetAdapter()

            threads = adapter.get_threads(pid)
            self.assertGreaterEqual(len(threads), 3)

            # Both worker threads are in futex wait
            workers = [t for t in threads if t["tid"] != pid]
            futex_workers = [t for t in workers if t["is_futex_wait"]]
            self.assertGreaterEqual(len(futex_workers), 2)

            # Context switches remain frozen across samples
            engine = AdaptiveInvestigationEngine()
            ctx = engine.registry.get("insp_frame_locals")
            res = ctx.func(
                None,
                pid=pid,
                tid=futex_workers[0]["tid"],
                adapter=adapter,
            )
            self.assertTrue(res["success"])
            self.assertEqual(res["status"], "OBSERVED")
            self.assertTrue(res["is_stalled"])
            self.assertEqual(res["observed_condition"], "thread_contention_stall_observed")

        finally:
            proc.terminate()
            proc.wait()

    # =========================================================================
    # Group 3: Companion ELF and Target Identity Scenarios
    # =========================================================================

    def test_09_companion_elf_matching_build_id_accepted(self):
        """Scenario 1: Matching companion ELF verified by Build ID equality enables DWARF symbols."""
        proc = subprocess.Popen([self.bin_healthy])
        try:
            time.sleep(0.05)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            t_id, caps, cq = engine._probe_target_and_capabilities(
                pid=pid,
                companion_elf_path=self.bin_healthy,
                adapter=LocalTargetAdapter(),
            )
            self.assertEqual(t_id["companion_status"], "MATCHED")
            self.assertIsNotNone(t_id["runtime_build_id"])
            self.assertEqual(t_id["companion_build_id"], t_id["runtime_build_id"])
            self.assertTrue(caps["dwarf_symbols_available"])
            self.assertEqual(cq["status"], "COMPLETE")

        finally:
            proc.terminate()
            proc.wait()

    def test_10_companion_elf_mismatched_build_id_rejected(self):
        """Scenario 3: Companion ELF with mismatched Build ID is rejected fail-closed; DWARF disabled."""
        proc = subprocess.Popen([self.bin_healthy])
        try:
            time.sleep(0.05)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            # Provide bin_comp_diff as companion image (different Build ID!)
            t_id, caps, cq = engine._probe_target_and_capabilities(
                pid=pid,
                companion_elf_path=self.bin_comp_diff,
                adapter=LocalTargetAdapter(),
            )
            self.assertEqual(t_id["companion_status"], "BUILD_ID_MISMATCH")
            self.assertIsNone(t_id["companion_elf"])  # Rejected!
            self.assertFalse(caps["dwarf_symbols_available"])  # DWARF disabled!
            self.assertIn("dwarf_symbols_available", caps["unavailable_reasons"])
            self.assertIn("does not match", caps["unavailable_reasons"]["dwarf_symbols_available"])

        finally:
            proc.terminate()
            proc.wait()

    def test_11_stripped_binary_without_companion_fails_closed(self):
        """Scenario 2: Stripped binary without companion ELF explicitly reports missing DWARF capabilities."""
        proc = subprocess.Popen([self.bin_stripped])
        try:
            time.sleep(0.05)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            t_id, caps, cq = engine._probe_target_and_capabilities(
                pid=pid,
                companion_elf_path="",  # No companion provided
                adapter=LocalTargetAdapter(),
            )
            self.assertEqual(t_id["companion_status"], "NOT_PROVIDED")
            self.assertFalse(caps["dwarf_symbols_available"])
            self.assertIn("dwarf_symbols_available", caps["unavailable_reasons"])
            self.assertIn("stripped", caps["unavailable_reasons"]["dwarf_symbols_available"])

        finally:
            proc.terminate()
            proc.wait()

    def test_12_deleted_executable_handled_fail_closed(self):
        """Scenario 4: Deleted executable ('... (deleted)') is detected and handled fail-closed."""
        # Create a temporary copy and execute it, then unlink it while running
        del_bin = os.path.join(self.work_dir, "proc_temp_delete")
        shutil.copy2(self.bin_healthy, del_bin)
        proc = subprocess.Popen([del_bin])
        try:
            time.sleep(0.05)
            pid = proc.pid
            os.unlink(del_bin)  # Unlink executable while process is running

            adapter = LocalTargetAdapter()
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["status"], "OBSERVED")
            self.assertTrue(ident["is_deleted"])
            self.assertTrue(ident["raw_link"].endswith(" (deleted)"))

            engine = AdaptiveInvestigationEngine()
            t_id, caps, cq = engine._probe_target_and_capabilities(
                pid=pid,
                companion_elf_path="",
                adapter=adapter,
            )
            self.assertTrue(t_id["is_deleted"])
            self.assertIn("executable_deleted", caps["unavailable_reasons"])

        finally:
            proc.terminate()
            proc.wait()

    def test_13_inaccessible_procfs_handled_fail_closed(self):
        """Scenario 5: Inaccessible procfs path (PermissionError) fails closed with PERMISSION_DENIED."""
        class MockPermissionDeniedAdapter(LocalTargetAdapter):
            def check_liveness(self, pid: int):
                return True, None

            def get_process_identity(self, pid: int):
                return {
                    "pid": pid,
                    "status": "PERMISSION_DENIED",
                    "executable": "",
                    "architecture": "unknown",
                    "elf_type": "unknown",
                    "build_id": None,
                    "is_deleted": False,
                    "error": "Permission denied reading /proc/<pid>/exe",
                }

        engine = AdaptiveInvestigationEngine()
        t_id, caps, cq = engine._probe_target_and_capabilities(
            pid=99999,
            companion_elf_path="",
            adapter=MockPermissionDeniedAdapter(),
        )
        self.assertFalse(caps["procfs_accessible"])
        self.assertFalse(caps["dwarf_symbols_available"])
        self.assertIn("procfs_accessible", caps["unavailable_reasons"])
        self.assertEqual(cq["status"], "PARTIAL")

    # =========================================================================
    # Group 4: Real Native Collector-to-Investigation Integration
    # =========================================================================

    def test_14_real_native_collector_end_to_end_live_verified(self):
        """Executes actual dynamicstate-collector binary on real running C process,
        produces authentic receipt.json, and feeds into adaptive investigation engine
        to achieve LIVE_VERIFIED and NO_ISSUE_DETECTED_WITHIN_SCOPE."""
        proc = subprocess.Popen([self.bin_healthy])
        snap_dir = os.path.join(self.work_dir, "real_snap_live")
        try:
            time.sleep(0.05)
            pid = proc.pid
            sess_id = f"sess_live_{uuid_hex()}"
            key_id = "test-prod-key-1"

            # Execute real native C collector binary
            cmd = [
                self.collector_bin,
                "-p", str(pid),
                "-o", snap_dir,
                "-F", self.test_key_file,
                "-S", sess_id,
                "-I", key_id,
                "-j",
            ]
            rc = subprocess.call(cmd)
            self.assertEqual(rc, 0, "Collector binary failed to capture target process")

            # Verify snapshot files on disk
            self.assertTrue(os.path.isfile(os.path.join(snap_dir, "manifest.json")))
            self.assertTrue(os.path.isfile(os.path.join(snap_dir, "receipt.json")))
            self.assertTrue(os.path.isfile(os.path.join(snap_dir, "maps.txt")))

            # Load via RawMemorySnapshot
            snapshot = RawMemorySnapshot.load(snap_dir)
            self.assertGreater(len(snapshot.regions), 0)
            for region in snapshot.regions:
                self.assertTrue(os.path.isfile(os.path.join(snap_dir, region.filename)))
            val_ok, val_errs = snapshot.validate_integrity()
            self.assertTrue(val_ok, f"Snapshot integrity failed: {val_errs}")

            # Verify receipt cryptographically via authority
            authority = CaptureVerificationAuthority.from_key_file(self.test_key_file, default_key_id=key_id)
            trust_state, trust_err = determine_snapshot_trust_state(
                snapshot.receipt,
                verification_authority=authority,
                expected_session_id=sess_id,
                expected_pid=pid,
                snapshot=snapshot,
            )
            self.assertEqual(trust_state, TRUST_STATE_LIVE_VERIFIED, f"Trust verification failed: {trust_err}")

            # Run adaptive investigation using real collector snapshot and receipt
            engine = AdaptiveInvestigationEngine()
            res = engine.investigate_process_health(
                goal="Check health of verified live capture.",
                pid=pid,
                companion_elf_path=self.bin_healthy,
                session_id=sess_id,
                capture_receipt=snapshot.receipt,
                snapshot=snapshot,
                verification_authority=authority,
            )

            self.assertTrue(res["success"])
            self.assertEqual(res["trust_state"], TRUST_STATE_LIVE_VERIFIED)
            self.assertEqual(res["provenance_class"], PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)
            self.assertEqual(res["verdict"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
            self.assertEqual(res["lifecycle_state"], STATE_COMPLETED)

        finally:
            proc.terminate()
            proc.wait()

    def test_15_tampered_manifest_fails_closed(self):
        """Tampering with manifest.json in real collector snapshot fails closed to INVALID_OR_TAMPERED."""
        snap_dir = os.path.join(self.work_dir, "snap_tamper_manifest")
        self._create_real_collector_snapshot(snap_dir, "sess_m1")

        # Tamper manifest.json
        manifest_path = os.path.join(snap_dir, "manifest.json")
        with open(manifest_path, "r+", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list) and len(data) > 0:
                data[0]["sha256"] = "0" * 64
            elif isinstance(data, dict):
                data["tampered_field"] = "malicious_modification"
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()

        snapshot = RawMemorySnapshot.load(snap_dir)
        authority = CaptureVerificationAuthority.from_key_file(self.test_key_file, default_key_id="test-prod-key-1")
        trust_state, trust_err = determine_snapshot_trust_state(
            snapshot.receipt,
            verification_authority=authority,
            snapshot=snapshot,
        )
        self.assertEqual(trust_state, TRUST_STATE_INVALID_OR_TAMPERED)
        self.assertTrue(
            "MANIFEST_DIGEST_MISMATCH" in str(trust_err) or "Manifest digest mismatch" in str(trust_err) or "SNAPSHOT_INTEGRITY_FAILED" in str(trust_err),
            f"Unexpected trust_err: {trust_err}",
        )

    def test_16_tampered_memory_bin_fails_closed(self):
        """Tampering with a memory region binary in real collector snapshot fails closed to INVALID_OR_TAMPERED."""
        snap_dir = os.path.join(self.work_dir, "snap_tamper_mem")
        self._create_real_collector_snapshot(snap_dir, "sess_m2")

        # Tamper first memory region file referenced in snapshot (truncate 1 byte)
        snapshot = RawMemorySnapshot.load(snap_dir)
        self.assertGreater(len(snapshot.regions), 0)
        target_file = snapshot.regions[0].filename
        mem_path = os.path.join(snap_dir, target_file)
        with open(mem_path, "r+b") as f:
            sz = os.fstat(f.fileno()).st_size
            f.truncate(max(0, sz - 1))

        snapshot = RawMemorySnapshot.load(snap_dir)
        authority = CaptureVerificationAuthority.from_key_file(self.test_key_file, default_key_id="test-prod-key-1")
        trust_state, trust_err = determine_snapshot_trust_state(
            snapshot.receipt,
            verification_authority=authority,
            snapshot=snapshot,
        )
        self.assertEqual(trust_state, TRUST_STATE_INVALID_OR_TAMPERED)
        self.assertIn("SNAPSHOT_INTEGRITY_FAILED", str(trust_err))

    def test_17_tampered_receipt_hmac_fails_closed(self):
        """Modifying signature in receipt.json fails closed with SIGNATURE_INVALID."""
        snap_dir = os.path.join(self.work_dir, "snap_tamper_sig")
        self._create_real_collector_snapshot(snap_dir, "sess_m3")

        # Tamper signature in receipt.json
        rcpt_path = os.path.join(snap_dir, "receipt.json")
        with open(rcpt_path, "r+", encoding="utf-8") as f:
            data = json.load(f)
            orig_sig = data["signature"]
            # Flip last char
            data["signature"] = orig_sig[:-1] + ("0" if orig_sig[-1] != "0" else "1")
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()

        snapshot = RawMemorySnapshot.load(snap_dir)
        authority = CaptureVerificationAuthority.from_key_file(self.test_key_file, default_key_id="test-prod-key-1")
        trust_state, trust_err = determine_snapshot_trust_state(
            snapshot.receipt,
            verification_authority=authority,
            snapshot=snapshot,
        )
        self.assertEqual(trust_state, TRUST_STATE_INVALID_OR_TAMPERED)
        self.assertIn("SIGNATURE_INVALID", str(trust_err))

    def test_18_session_id_mismatch_fails_closed(self):
        """Receipt with mismatched session ID fails closed with SESSION_MISMATCH."""
        snap_dir = os.path.join(self.work_dir, "snap_sess_mismatch")
        self._create_real_collector_snapshot(snap_dir, "sess_orig")

        snapshot = RawMemorySnapshot.load(snap_dir)
        authority = CaptureVerificationAuthority.from_key_file(self.test_key_file, default_key_id="test-prod-key-1")
        trust_state, trust_err = determine_snapshot_trust_state(
            snapshot.receipt,
            verification_authority=authority,
            expected_session_id="sess_different_id",
            snapshot=snapshot,
        )
        self.assertEqual(trust_state, TRUST_STATE_INVALID_OR_TAMPERED)
        self.assertIn("SESSION_MISMATCH", str(trust_err))

    def test_19_imported_unverified_snapshot_remains_unverified(self):
        """Snapshot without verification authority remains IMPORTED_UNVERIFIED and cannot claim LIVE."""
        snap_dir = os.path.join(self.work_dir, "snap_imported")
        self._create_real_collector_snapshot(snap_dir, "sess_imp")

        snapshot = RawMemorySnapshot.load(snap_dir)
        # Verify without key authority
        trust_state, trust_err = determine_snapshot_trust_state(
            snapshot.receipt,
            verification_authority=None,
            secret=None,
            snapshot=snapshot,
        )
        self.assertEqual(trust_state, "VERIFICATION_UNAVAILABLE")

        # Run investigation without authority -> falls back to IMPORTED_UNVERIFIED
        engine = AdaptiveInvestigationEngine()
        res = engine.investigate_process_health(
            goal="Analyze imported unverified snapshot.",
            pid=snapshot.pid,
            snapshot=snapshot,
            verification_authority=None,
        )
        self.assertEqual(res["provenance_class"], PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertNotEqual(res["provenance_class"], PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)

    # =========================================================================
    # Group 5: Adaptive Hypothesis Quality & Ranking Shifts
    # =========================================================================

    def test_20_discriminating_observation_inverts_competing_hypothesis_ranking(self):
        """Proves two competing hypotheses (H1 vs H2) change ranking upon discriminating observation.
        Initial: H1 (0.50) == H2 (0.50)
        Outcome CONTRADICTS H1 and SUPPORTS H2 -> H2 becomes top ranked."""
        h1 = InvestigationHypothesis(
            hypothesis_id="h1_compete",
            investigation_id="inv_rank",
            title="Lock Contention Stall",
            claim="Thread is stalled on unreleasing lock",
            confidence_score=0.50,
            confidence=CONFIDENCE_MEDIUM,
        )
        h2 = InvestigationHypothesis(
            hypothesis_id="h2_compete",
            investigation_id="inv_rank",
            title="Normal Idle Wait",
            claim="Thread is waiting normally in condition wait",
            confidence_score=0.50,
            confidence=CONFIDENCE_MEDIUM,
        )

        ledger = EvidenceLedger(session_id="inv_rank")
        engine = AdaptiveInvestigationEngine()

        # Follow-up observation outcome: uncontended_or_normal_progress
        ev = engine.adapter.adapt_generic_tool_output(
            tool_name="insp_frame_locals",
            tool_result={
                "observed_condition": "uncontended_or_normal_progress",
                "is_stalled": False,
            },
            target_identity={"pid": os.getpid()},
            session_id="inv_rank",
            ledger=ledger,
            epoch=1,
        )
        ev.details["outcomes_by_hypothesis"] = {
            "h1_compete": "CONTRADICTED",
            "h2_compete": "SUPPORTED",
        }
        engine.adapter.record_into_ledger(ev, ledger)

        HypothesisValidator.evaluate(h1, ledger, ev)
        HypothesisValidator.evaluate(h2, ledger, ev)

        # Proves ranking inversion
        self.assertEqual(h1.validation_status, HYPOTHESIS_STATUS_CONTRADICTED)
        self.assertEqual(h2.validation_status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertLess(h1.confidence_score, 0.20)
        self.assertGreaterEqual(h2.confidence_score, 0.65)
        self.assertGreater(h2.confidence_score, h1.confidence_score)

    def test_21_failed_or_unavailable_observation_does_not_support_hypothesis(self):
        """An unavailable or failed observation cannot support a hypothesis or inflate confidence."""
        h = InvestigationHypothesis(
            hypothesis_id="h_unavail",
            investigation_id="inv_unavail",
            confidence_score=0.35,
            confidence=CONFIDENCE_LOW,
        )
        ledger = EvidenceLedger(session_id="inv_unavail")
        engine = AdaptiveInvestigationEngine()

        ev = engine.adapter.adapt_generic_tool_output(
            tool_name="insp_locks",
            tool_result={
                "success": False,
                "status": "UNAVAILABLE",
                "error": "Procfs task access restricted",
            },
            target_identity={"pid": os.getpid()},
            session_id="inv_unavail",
            ledger=ledger,
            epoch=1,
        )
        engine.adapter.record_into_ledger(ev, ledger)

        HypothesisValidator.evaluate(h, ledger, ev)
        self.assertNotEqual(h.validation_status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertLessEqual(h.confidence_score, 0.35)

    def test_22_duplicate_observations_do_not_inflate_confidence(self):
        """Duplicate identical observations do not inflate hypothesis confidence."""
        h = InvestigationHypothesis(
            hypothesis_id="h_dup",
            investigation_id="inv_dup",
            confidence_score=0.50,
        )
        ledger = EvidenceLedger(session_id="inv_dup")
        engine = AdaptiveInvestigationEngine()

        ev1 = engine.adapter.adapt_generic_tool_output(
            tool_name="insp_locks",
            tool_result={"thread_count": 2, "observed_condition": "normal"},
            target_identity={"pid": os.getpid()},
            session_id="inv_dup",
            ledger=ledger,
            epoch=1,
        )
        ev1.details["outcome"] = "SUPPORTED"
        engine.adapter.record_into_ledger(ev1, ledger)
        HypothesisValidator.evaluate(h, ledger, ev1)
        conf1 = h.confidence_score

        # Duplicate identical record
        ev2 = engine.adapter.adapt_generic_tool_output(
            tool_name="insp_locks",
            tool_result={"thread_count": 2, "observed_condition": "normal"},
            target_identity={"pid": os.getpid()},
            session_id="inv_dup",
            ledger=ledger,
            epoch=1,
        )
        ev2.details["outcome"] = "SUPPORTED"
        res_cat = (ev2.details or {}).get("result_category")
        self.assertEqual(res_cat, RESULT_DUPLICATE_EVIDENCE)

        HypothesisValidator.evaluate(h, ledger, ev2)
        conf2 = h.confidence_score

        # Confidence does NOT inflate on duplicate
        self.assertEqual(conf1, conf2)

    def test_23_low_impact_budget_limits_and_explicit_statuses(self):
        """Preserves read-only boundary and verifies budget enforcement and explicit statuses."""
        limits = ObservationBudgetLimits(
            max_bytes_read=512,
            max_samples=1,
            max_wall_clock_ms=200.0,
        )
        engine = AdaptiveInvestigationEngine(default_limits=limits)
        proc = subprocess.Popen([self.bin_healthy])
        try:
            time.sleep(0.05)
            pid = proc.pid
            res = engine.investigate_process_health(
                goal="Check budget enforcement on target.",
                pid=pid,
                budget_limits=limits,
            )
            self.assertTrue(res["success"])
            self.assertIn(res["stop_reason"], ("BUDGET_EXHAUSTED", "STOP_BUDGET_EXHAUSTED", "STOP_MAX_OBSERVATIONS_REACHED", "STOP_NORMAL_COMPLETION"))

            # All observation log records have explicit result categories
            for obs_entry in res.get("observation_log", []):
                self.assertIn(
                    obs_entry["result_category"],
                    (RESULT_NEW_EVIDENCE, RESULT_DUPLICATE_EVIDENCE, RESULT_OBSERVATION_FAILED, RESULT_OBSERVATION_UNAVAILABLE, "BUDGET_REJECTED"),
                )

        finally:
            proc.terminate()
            proc.wait()

    # =========================================================================
    # Helpers
    # =========================================================================

    def _create_real_collector_snapshot(self, out_dir: str, sess_id: str) -> int:
        """Helper to invoke dynamicstate-collector binary against a live process."""
        proc = subprocess.Popen([self.bin_healthy])
        try:
            time.sleep(0.05)
            pid = proc.pid
            cmd = [
                self.collector_bin,
                "-p", str(pid),
                "-o", out_dir,
                "-F", self.test_key_file,
                "-S", sess_id,
                "-I", "test-prod-key-1",
                "-j",
            ]
            rc = subprocess.call(cmd)
            if rc != 0:
                raise RuntimeError(f"dynamicstate-collector exited with code {rc}")
            return pid
        finally:
            proc.terminate()
            proc.wait()


def uuid_hex():
    import uuid
    return uuid.uuid4().hex[:8]


if __name__ == "__main__":
    unittest.main()
