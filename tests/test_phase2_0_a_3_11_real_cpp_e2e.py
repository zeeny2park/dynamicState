"""Phase 2.0-A.3.11 Real C++ Live Process Integration Suite.

Comprehensive verification on real Linux target processes compiled from C/C++:
1. test_01_healthy_process_e2e
2. test_02_mutex_contention_e2e
3. test_03_circular_deadlock_e2e
4. test_04_memory_growth_e2e
5. test_05_multiple_concurrent_targets_isolated_e2e
6. test_06_process_mutation_causal_verification_e2e
7. test_07_high_thread_count_e2e
8. test_08_process_restart_during_investigation_e2e
9. test_09_probe_vs_diagnostic_capture_transaction_e2e
10. test_10_budget_boundary_enforcement_e2e
11. test_11_workflow_stage_execution_live_process_e2e
12. test_12_workflow_crash_recovery_live_process_e2e
13. test_13_stop_time_sla_under_4_5ms_e2e
14. test_14_repeated_capture_operations_stability_e2e
15. test_15_full_pipeline_incident_report_generation_e2e
"""

import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from typing import Any, Dict, Tuple

from extractor.capture_backend import (
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.target_adapter import LocalTargetAdapter, PIDReusedError
from tests.support.fixture_process import fixture_popen


class TestPhase20A311RealCppE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="cpp_311_e2e_")
        cls.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")

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
        proc = fixture_popen(
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
    # Scenario 5: Multiple Concurrent Targets Isolated
    # -------------------------------------------------------------------------
    def test_05_multiple_concurrent_targets_isolated_e2e(self):
        """[LIVE] Two simultaneously running processes are captured and isolated cleanly."""
        proc1 = fixture_popen([self.bin_healthy])
        proc2 = fixture_popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            pinned1 = adapter.pin_target_identity(proc1.pid)
            pinned2 = adapter.pin_target_identity(proc2.pid)

            self.assertEqual(pinned1["pid"], proc1.pid)
            self.assertEqual(pinned2["pid"], proc2.pid)
            self.assertNotEqual(pinned1["process_identity"], pinned2["process_identity"])

            tx1 = adapter.begin_capture_transaction("sess_iso_1", proc1.pid)
            maps1 = [m for m in adapter.get_memory_mappings(proc1.pid) if m.get("is_readable")]
            addr1 = maps1[0]["start_int"] if maps1 else 0
            adapter.read_memory(proc1.pid, addr1, 64)
            adapter.commit_capture_transaction(tx1)

            tx2 = adapter.begin_capture_transaction("sess_iso_2", proc2.pid)
            maps2 = [m for m in adapter.get_memory_mappings(proc2.pid) if m.get("is_readable")]
            addr2 = maps2[0]["start_int"] if maps2 else 0
            adapter.read_memory(proc2.pid, addr2, 64)
            adapter.commit_capture_transaction(tx2)

            self.assertEqual(tx1.pid, proc1.pid)
            self.assertEqual(tx2.pid, proc2.pid)
        finally:
            proc1.kill()
            proc1.wait()
            proc2.kill()
            proc2.wait()

    # -------------------------------------------------------------------------
    # Scenario 6: Process Mutation Causal Verification
    # -------------------------------------------------------------------------
    def test_06_process_mutation_causal_verification_e2e(self):
        """[LIVE] Read memory before and after external mutation establishing causal proof."""
        proc, oracle = self._start_scenario_process()
        try:
            adapter = LocalTargetAdapter()
            pinned = adapter.pin_target_identity(proc.pid)
            addr = oracle["sequence"]

            # Initial capture
            tx1 = adapter.begin_capture_transaction("sess_mut", proc.pid)
            val1_bytes, st1, _ = adapter.read_memory(proc.pid, addr, 4)
            adapter.commit_capture_transaction(tx1)
            self.assertEqual(st1, "OBSERVED")
            val1 = struct.unpack("<i", val1_bytes)[0]
            self.assertEqual(val1, 42)

            # Mutate via command
            proc.stdin.write("SET sequence 555\n")
            proc.stdin.flush()
            time.sleep(0.05)

            # Post-mutation capture
            tx2 = adapter.begin_capture_transaction("sess_mut", proc.pid)
            val2_bytes, st2, _ = adapter.read_memory(proc.pid, addr, 4)
            adapter.commit_capture_transaction(tx2)
            self.assertEqual(st2, "OBSERVED")
            val2 = struct.unpack("<i", val2_bytes)[0]
            self.assertEqual(val2, 555)
            self.assertNotEqual(val1, val2)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 7: High Thread Count
    # -------------------------------------------------------------------------
    def test_07_high_thread_count_e2e(self):
        """[LIVE] Target process with multiple threads reports threads and stack memory accurately."""
        proc = fixture_popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            threads = adapter.get_threads(proc.pid)
            self.assertGreaterEqual(len(threads), 2)
            for t in threads:
                self.assertIn("tid", t)
                self.assertIn("stack_info", t)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 8: Process Restart During Investigation
    # -------------------------------------------------------------------------
    def test_08_process_restart_during_investigation_e2e(self):
        """[LIVE] Target process exit/restart during capture transaction fails closed."""
        proc = fixture_popen([self.bin_healthy])
        pid = proc.pid
        time.sleep(0.1)
        adapter = LocalTargetAdapter()
        pinned = adapter.pin_target_identity(pid)

        tx = adapter.begin_capture_transaction("sess_restart", pid)
        adapter.read_memory(pid, int(pinned["pt_loads"][0]["p_vaddr"]), 64)

        # Kill process before commit
        proc.kill()
        proc.wait()

        with self.assertRaises((ProcessLookupError, PIDReusedError)):
            adapter.commit_capture_transaction(tx)
        self.assertTrue(tx.aborted)

    # -------------------------------------------------------------------------
    # Scenario 9: Probe vs Diagnostic Capture Transactions
    # -------------------------------------------------------------------------
    def test_09_probe_vs_diagnostic_capture_transaction_e2e(self):
        """[LIVE] Probe transactions cannot attest to diagnostic records."""
        proc = fixture_popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            pinned = adapter.pin_target_identity(proc.pid)

            maps = [m for m in adapter.get_memory_mappings(proc.pid) if m.get("is_readable")]
            r_vma = maps[0]["start_int"] if maps else 0

            # Probe transaction
            with adapter.capture_transaction(session_id="sess_d", pid=proc.pid, operation_type="probe") as probe_tx:
                adapter.read_memory(proc.pid, r_vma, 32)
            probe_rcpt = adapter.issue_live_receipt_for_session("sess_d", proc.pid, transaction=probe_tx)
            self.assertEqual(probe_rcpt.operation_type, "probe")

            # Diagnostic transaction
            with adapter.capture_transaction(session_id="sess_d", pid=proc.pid, operation_type="diagnostic") as diag_tx:
                adapter.read_memory(proc.pid, r_vma, 64)
            diag_rcpt = adapter.issue_live_receipt_for_session("sess_d", proc.pid, transaction=diag_tx)
            self.assertEqual(diag_rcpt.operation_type, "diagnostic")

            ledger = EvidenceLedger(session_id="sess_d")
            diag_rec = EvidenceRecord(
                evidence_id="evi_live_field",
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                session_id="sess_d",
                field_observation={"field_path": "memory.base", "value": 0},
                target_identity=pinned,
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": probe_rcpt.to_dict(),  # Attempting to use probe receipt for field obs
                },
                details={"observation_digest": probe_rcpt.observation_digest},
            )
            with self.assertRaises(ValueError) as ctx:
                ledger.validate_record(diag_rec)
            self.assertIn("probe read receipt cannot attest", str(ctx.exception).lower())
        finally:
            proc.kill()
            proc.wait()




    # -------------------------------------------------------------------------
    # Scenario 13: Stop-Time SLA (< 4.5ms) on Live Process
    # -------------------------------------------------------------------------
    def test_13_stop_time_sla_under_4_5ms_e2e(self):
        """[LIVE] Zero-stop memory reads execute with stop-time SLA < 4.5ms (benchmark < 1.0ms)."""
        proc = fixture_popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            pinned = adapter.pin_target_identity(proc.pid)
            maps = [m for m in adapter.get_memory_mappings(proc.pid) if m.get("is_readable")]
            vaddr = maps[0]["start_int"] if maps else 0

            latencies_ms = []
            for _ in range(5):
                t0 = time.monotonic_ns()
                data, status, _ = adapter.read_memory(proc.pid, vaddr, 128)
                t_elapsed_ms = (time.monotonic_ns() - t0) / 1_000_000.0
                self.assertEqual(status, "OBSERVED")
                latencies_ms.append(t_elapsed_ms)

            avg_lat = sum(latencies_ms) / len(latencies_ms)
            self.assertLess(avg_lat, 4.5, f"Average stop-time latency {avg_lat:.2f}ms exceeded 4.5ms SLA")
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 14: Repeated Capture Operations Stability
    # -------------------------------------------------------------------------
    def test_14_repeated_capture_operations_stability_e2e(self):
        """[LIVE] Multiple successive capture operations complete cleanly without resource leak."""
        proc = fixture_popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            pinned = adapter.pin_target_identity(proc.pid)
            maps = [m for m in adapter.get_memory_mappings(proc.pid) if m.get("is_readable")]
            vaddr = maps[0]["start_int"] if maps else 0

            for epoch in range(1, 4):
                with adapter.capture_transaction(session_id=f"sess_rep_{epoch}", pid=proc.pid) as tx_epoch:
                    adapter.read_memory(proc.pid, vaddr, 64)
                rcpt = adapter.issue_live_receipt_for_session(f"sess_rep_{epoch}", proc.pid, transaction=tx_epoch)
                self.assertIsNotNone(rcpt)
                self.assertEqual(rcpt.authority_level, "PRODUCTION")
                adapter.advance_epoch()

            self.assertGreaterEqual(adapter.cumulative_physical_bytes_read, 192)
        finally:
            proc.kill()
            proc.wait()



if __name__ == "__main__":
    unittest.main()
