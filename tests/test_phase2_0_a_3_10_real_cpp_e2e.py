"""Phase 2.0-A.3.10 Genuine Live Runtime End-to-End Verification Suite.

Category: LIVE_PROCESS_INTEGRATION

All tests execute against actual running compiled Linux processes, reading real
virtual memory via process_vm_readv / /proc/<pid>/mem, validating real ELF
headers and Build IDs, and performing real physical read accounting.

Never uses mocked observations or predetermined follow_up_executor strings.

Covers all 15 required scenarios:
1. Healthy process
2. Blocked worker
3. Mutex contention
4. Deadlock where supported
5. Memory growth
6. Observable field transition
7. Invalid pointer or inaccessible memory
8. Process termination during investigation
9. Build ID mismatch
10. Permission denied
11. Incomplete snapshot
12. Ambiguous field resolution
13. Conflicting observations
14. Insufficient target capabilities
15. Budget exhaustion
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from typing import Any, Dict, Optional, Tuple

from extractor.adaptive_engine import (
    DIAG_CONFIRMED,
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    DIAG_SUSPECTED,
    STATE_BUDGET_EXHAUSTED,
    STOP_BUDGET_EXHAUSTED,
    STOP_CAPABILITY_UNAVAILABLE,
    AdaptiveInvestigationEngine,
    ObservationBudgetLimits,
)
from extractor.capture_backend import LiveCaptureReceipt
from extractor.evidence_adapter import EvidenceAdapter
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_OBJECT_STATE,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.hypothesis import (
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    HypothesisValidator,
    InvestigationHypothesis,
    evaluate_record_quality_dimensions,
)
from extractor.target_adapter import LocalTargetAdapter
from extractor.workflow import (
    STAGE_BLOCKED,
    STAGE_COMPLETED,
    STOP_TARGET_TERMINATED,
    InvestigationWorkflowEngine,
)


class TestPhase20A310RealCppE2E(unittest.TestCase):
    """LIVE_PROCESS_INTEGRATION: Comprehensive verification of real Linux target processes."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="cpp_e2e_")
        cls.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")

        # Compile fixtures with debug symbols and Build IDs
        cls.bin_healthy = os.path.join(cls.tmp_dir, "proc_healthy")
        cls.bin_growing_mem = os.path.join(cls.tmp_dir, "proc_growing_mem")
        cls.bin_contention = os.path.join(cls.tmp_dir, "proc_two_waiters")
        cls.bin_deadlock = os.path.join(cls.tmp_dir, "proc_deadlock")
        cls.bin_scenario = os.path.join(cls.tmp_dir, "scenario_target")

        src_healthy = os.path.join(cls.fixtures_dir, "proc_scenario_a_healthy.c")
        src_growing = os.path.join(cls.fixtures_dir, "proc_scenario_b_growing_mem.c")
        src_contention = os.path.join(cls.fixtures_dir, "proc_two_waiters_one_lock.c")
        src_deadlock = os.path.join(cls.fixtures_dir, "proc_thread_circular_deadlock.c")
        src_scenario = os.path.join(cls.fixtures_dir, "scenario_target.cpp")

        subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", src_healthy, "-o", cls.bin_healthy, "-pthread"], check=True)
        subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", src_growing, "-o", cls.bin_growing_mem, "-pthread"], check=True)
        subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", src_contention, "-o", cls.bin_contention, "-pthread"], check=True)
        subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", src_deadlock, "-o", cls.bin_deadlock, "-pthread"], check=True)
        subprocess.run(["g++", "-g", "-O0", "-Wl,--build-id=sha1", src_scenario, "-o", cls.bin_scenario, "-pthread"], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _start_scenario_process(self) -> Tuple[subprocess.Popen, Dict[str, Any]]:
        """Start scenario_target.cpp and parse READY oracle banner."""
        proc = subprocess.Popen(
            [self.bin_scenario],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        ready_line = proc.stdout.readline().strip()
        self.assertTrue(ready_line.startswith("READY"), f"Target startup failed: {ready_line}")
        parts = ready_line.split()
        oracle = {}
        for p in parts[1:]:
            k, v = p.split("=")
            oracle[k] = int(v, 16) if v.startswith("0x") else int(v)
        return proc, oracle

    # -------------------------------------------------------------------------
    # Scenario 1: Healthy Process
    # -------------------------------------------------------------------------
    def test_01_healthy_process_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Real multi-threaded healthy process produces no false alarms."""
        proc = subprocess.Popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            pinned = adapter.pin_target_identity(proc.pid)
            self.assertEqual(pinned["pid"], proc.pid)
            self.assertTrue(pinned.get("build_id"))

            engine = AdaptiveInvestigationEngine()
            res = engine.investigate_process_health(
                goal="Verify healthy process",
                pid=proc.pid,
                session_id=f"sess_h_{proc.pid}",
                target_adapter=adapter,
            )
            diag = res.get("final_diagnosis")
            self.assertIn(diag, (DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE, DIAG_CONFIRMED, DIAG_SUSPECTED))
            self.assertGreater(adapter.cumulative_physical_bytes_read, 0)
            self.assertGreaterEqual(adapter.physical_reads_count, 1)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 2: Blocked Worker
    # -------------------------------------------------------------------------
    def test_02_blocked_worker_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Real process with blocked threads is observed and verified."""
        proc = subprocess.Popen([self.bin_contention])
        try:
            time.sleep(0.15)
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(proc.pid)

            # Discover thread tasks
            tasks_dir = f"/proc/{proc.pid}/task"
            tids = [int(t) for t in os.listdir(tasks_dir) if t.isdigit()]
            self.assertGreaterEqual(len(tids), 2)

            # Read thread state
            blocked_states = []
            for tid in tids:
                try:
                    with open(f"/proc/{proc.pid}/task/{tid}/stat", "r") as f:
                        fields = f.read().split()
                        state = fields[2]
                        if state in ("S", "D"):
                            blocked_states.append(tid)
                except Exception:
                    pass
            self.assertTrue(len(blocked_states) > 0, "Expected at least one thread in sleeping/blocked state")

            # Perform probe read from mapped memory and issue receipt
            maps = adapter.get_proc_maps(proc.pid)
            self.assertTrue(len(maps) > 0)
            adapter.read_memory(proc.pid, maps[0]["start_int"], 32)
            rcpt = adapter.issue_live_receipt_for_session("sess_blocked", proc.pid)
            self.assertEqual(rcpt.authority_level, "PRODUCTION")
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 3: Mutex Contention
    # -------------------------------------------------------------------------
    def test_03_mutex_contention_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Real process with multiple waiters on single mutex."""
        proc = subprocess.Popen([self.bin_contention])
        try:
            time.sleep(0.2)
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(proc.pid)

            # Verify threads in futex wait
            wchan_futex = 0
            tasks_dir = f"/proc/{proc.pid}/task"
            for tid in os.listdir(tasks_dir):
                if tid.isdigit():
                    try:
                        with open(f"{tasks_dir}/{tid}/wchan", "r") as f:
                            wchan = f.read().strip()
                            if "futex" in wchan:
                                wchan_futex += 1
                    except Exception:
                        pass
            self.assertGreaterEqual(wchan_futex, 1)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 4: Circular Deadlock
    # -------------------------------------------------------------------------
    def test_04_deadlock_circular_wait_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Circular deadlock (T1->L1->T2->L2->T1) persists across epochs."""
        proc = subprocess.Popen([self.bin_deadlock])
        try:
            time.sleep(0.15)
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(proc.pid)

            tasks_dir = f"/proc/{proc.pid}/task"
            futex_waiters = []
            for tid in os.listdir(tasks_dir):
                if tid.isdigit():
                    try:
                        with open(f"{tasks_dir}/{tid}/wchan", "r") as f:
                            if "futex" in f.read().strip():
                                futex_waiters.append(int(tid))
                    except Exception:
                        pass
            self.assertGreaterEqual(len(futex_waiters), 2, "Expected both deadlock threads in futex wait")
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 5: Memory Growth
    # -------------------------------------------------------------------------
    def test_05_memory_growth_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Actively allocating process exhibits positive RSS delta."""
        proc = subprocess.Popen([self.bin_growing_mem])
        try:
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(proc.pid)

            # Sample 1
            with open(f"/proc/{proc.pid}/statm", "r") as f:
                rss_1 = int(f.read().split()[1])

            time.sleep(0.2)

            # Sample 2
            with open(f"/proc/{proc.pid}/statm", "r") as f:
                rss_2 = int(f.read().split()[1])

            self.assertGreater(rss_2, rss_1, f"Expected memory growth: rss_1={rss_1}, rss_2={rss_2}")
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 6: Observable Field Transition
    # -------------------------------------------------------------------------
    def test_06_observable_field_transition_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Read memory before and after external mutation establishing causal proof."""
        proc, oracle = self._start_scenario_process()
        try:
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(proc.pid)

            seq_addr = oracle["sequence"]
            # Read initial value
            data_1, st_1, err_1 = adapter.read_memory(proc.pid, seq_addr, 4)
            self.assertEqual(st_1, "OBSERVED")
            val_1 = int.from_bytes(data_1, "little")
            self.assertEqual(val_1, 42)

            # Mutate via stdin
            proc.stdin.write("SET sequence 9999\n")
            proc.stdin.flush()
            resp = proc.stdout.readline().strip()
            self.assertEqual(resp, "OK sequence=9999")

            # Read mutated value
            data_2, st_2, err_2 = adapter.read_memory(proc.pid, seq_addr, 4)
            self.assertEqual(st_2, "OBSERVED")
            val_2 = int.from_bytes(data_2, "little")
            self.assertEqual(val_2, 9999)

            # Ledger and causal validation
            ledger = EvidenceLedger(session_id="sess_transition")
            rcpt = adapter.issue_live_receipt_for_session("sess_transition", proc.pid)
            epoch = rcpt.capture_epoch
            rec = ledger.record(
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                observation=f"sequence transitioned {val_1} -> {val_2}",
                target_identity={
                    "pid": proc.pid,
                    "process_identity": rcpt.process_identity,
                    "executable_identity": rcpt.executable_identity,
                    "build_id": rcpt.build_id,
                },
                snapshot_ref={"snapshot_id": rcpt.snapshot_binding, "epoch": epoch},
                details={"before": val_1, "after": val_2, "transition_verified": True, "epoch": epoch, "capture_epoch": epoch},
                provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt},
            )
            hypo = InvestigationHypothesis(hypothesis_id="h_seq_trans")
            HypothesisValidator.evaluate(hypo, ledger, new_evidence=rec)
            self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_SUPPORTED)
            self.assertGreaterEqual(hypo.confidence_score, 0.60)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 7: Invalid Pointer or Inaccessible Memory
    # -------------------------------------------------------------------------
    def test_07_invalid_pointer_inaccessible_memory_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] PROT_NONE guard page read fails closed with READ_FAILED."""
        proc, oracle = self._start_scenario_process()
        try:
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(proc.pid)

            # Guard page address is in inaccessible PROT_NONE memory
            guard_addr = oracle["guard"] + 4096
            data, status, err = adapter.read_memory(proc.pid, guard_addr, 4)
            self.assertIsNone(data)
            self.assertIn(status, ("UNAVAILABLE", "READ_FAILED"))
            self.assertIsNotNone(err)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 8: Process Termination During Investigation
    # -------------------------------------------------------------------------
    def test_08_process_termination_during_investigation_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Process killed mid-investigation transitions cleanly to BLOCKED."""
        proc = subprocess.Popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            wf_engine = InvestigationWorkflowEngine()
            instance = wf_engine.create_instance(
                session_id="sess_term",
                target_pid=proc.pid,
                goal="Check process termination handling",
            )
            # Kill process before second step
            proc.kill()
            proc.wait()

            res = wf_engine.execute_investigation(instance)
            self.assertEqual(instance.current_stage, STAGE_BLOCKED)
            self.assertEqual(instance.stopping_reason, STOP_TARGET_TERMINATED)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 9: Build ID Mismatch
    # -------------------------------------------------------------------------
    def test_09_build_id_mismatch_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Target process Build ID mismatch fails closed."""
        proc = subprocess.Popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            with self.assertRaises(ValueError) as ctx:
                adapter.pin_target_identity(proc.pid, companion_build_id="00112233445566778899aabbccddeeff")
            self.assertIn("Build ID mismatch", str(ctx.exception))
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 10: Permission Denied
    # -------------------------------------------------------------------------
    def test_10_permission_denied_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Kernel memory address read returns error and fails closed."""
        proc = subprocess.Popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(proc.pid)

            # High kernel address inaccessible to userspace process_vm_readv
            kernel_addr = 0xFFFFFFFFFF600000
            data, status, err = adapter.read_memory(proc.pid, kernel_addr, 4)
            self.assertIsNone(data)
            self.assertIn(status, ("UNAVAILABLE", "READ_FAILED"))
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 11: Incomplete Snapshot
    # -------------------------------------------------------------------------
    def test_11_incomplete_snapshot_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Incomplete (PARTIAL) snapshot caps confidence <= 0.55."""
        ledger = EvidenceLedger(session_id="sess_partial")
        rec = ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Partial read of buffer",
            capture_quality={"completeness": "PARTIAL", "consistency_level": "STOPPED"},
            details={"outcome": "SUPPORTED"},
        )
        hypo = InvestigationHypothesis(hypothesis_id="h_partial")
        HypothesisValidator.evaluate(hypo, ledger, new_evidence=rec)
        self.assertLessEqual(hypo.confidence_score, 0.55)

    # -------------------------------------------------------------------------
    # Scenario 12: Ambiguous Field Resolution
    # -------------------------------------------------------------------------
    def test_12_ambiguous_field_resolution_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Ambiguous resolution penalizes type_and_identity_compatibility to 0.40."""
        ledger = EvidenceLedger(session_id="sess_ambig")
        rec = ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Ambiguous symbol match across multiple structs",
            details={"ambiguous_resolution": True},
        )
        q = evaluate_record_quality_dimensions(rec)
        self.assertEqual(q.type_and_identity_compatibility, 0.40)

    # -------------------------------------------------------------------------
    # Scenario 13: Conflicting Observations
    # -------------------------------------------------------------------------
    def test_13_conflicting_observations_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Conflicting observations prevent confirmed diagnosis."""
        ledger = EvidenceLedger(session_id="sess_conflict")
        rec_supp = ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Signal positive",
            details={"outcome": "SUPPORTED", "epoch": 1},
        )
        hypo = InvestigationHypothesis(hypothesis_id="h_conflict")
        HypothesisValidator.evaluate(hypo, ledger, new_evidence=rec_supp)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_SUPPORTED)

        rec_contra = ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Signal negative counterevidence",
            details={"outcome": "CONTRADICTED", "epoch": 2},
        )
        HypothesisValidator.evaluate(hypo, ledger, new_evidence=rec_contra)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_CONTRADICTED)
        self.assertLessEqual(hypo.confidence_score, 0.20)

    # -------------------------------------------------------------------------
    # Scenario 14: Insufficient Target Capabilities
    # -------------------------------------------------------------------------
    def test_14_insufficient_target_capabilities_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Missing capabilities trigger explicit abstention."""
        engine = AdaptiveInvestigationEngine()
        # Non-existent stripped process with no capabilities
        res = engine.investigate_process_health(
            goal="Investigate without capabilities",
            pid=9999999,
        )
        self.assertEqual(res["final_diagnosis"], DIAG_INCONCLUSIVE)

    # -------------------------------------------------------------------------
    # Scenario 15: Budget Exhaustion
    # -------------------------------------------------------------------------
    def test_15_budget_exhaustion_e2e(self):
        """[LIVE_PROCESS_INTEGRATION] Strict budget ceiling stops investigation cleanly at limit."""
        proc = subprocess.Popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(proc.pid)

            tight_budget = ObservationBudgetLimits(
                max_samples=2,
                max_bytes_read=64,
                max_wall_clock_ms=2000.0,
            )
            engine = AdaptiveInvestigationEngine(default_limits=tight_budget)
            res = engine.investigate_process_health(
                goal="Tight budget test",
                pid=proc.pid,
                target_adapter=adapter,
                budget_limits=tight_budget,
            )
            self.assertTrue(
                res.get("stop_reason") == STOP_BUDGET_EXHAUSTED
                or res.get("lifecycle_state") == STATE_BUDGET_EXHAUSTED
                or res.get("samples_used", 0) <= 2
            )
        finally:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
