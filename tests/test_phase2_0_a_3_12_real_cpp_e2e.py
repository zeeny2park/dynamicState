"""Phase 2.0-A.3.12 Real C/C++ Live Process Integration Suite.

Comprehensive end-to-end verification against real Linux processes compiled from C/C++ fixtures:
1. test_01_healthy_process_e2e
2. test_02_mutex_contention_e2e
3. test_03_circular_deadlock_e2e
4. test_04_memory_growth_e2e
5. test_05_live_target_transaction_isolation_e2e
6. test_06_process_mutation_causal_verification_e2e
7. test_07_live_workflow_recovery_and_resume_e2e
8. test_08_live_pid_reuse_detection_on_resume_e2e
9. test_09_stop_time_sla_under_4_5ms_e2e
10. test_10_full_live_incident_report_generation_e2e
"""

import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from typing import Any, Dict, Tuple

from extractor.evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    PIDReusedError,
    TargetIdentityChangedError,
)
from tests.support.fixture_process import fixture_popen


class TestPhase20A312RealCppE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="cpp_312_e2e_")
        cls.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")

        cls.bin_healthy = os.path.join(cls.tmp_dir, "proc_scenario_a_healthy")
        cls.bin_growing_mem = os.path.join(cls.tmp_dir, "proc_scenario_b_growth")
        cls.bin_contention = os.path.join(cls.tmp_dir, "proc_contention")
        cls.bin_deadlock = os.path.join(cls.tmp_dir, "proc_deadlock")
        cls.bin_mutation = os.path.join(cls.tmp_dir, "proc_mutation")

        src_healthy = os.path.join(cls.fixtures_dir, "proc_scenario_a_healthy.c")
        src_growing = os.path.join(cls.fixtures_dir, "proc_scenario_b_growing_mem.c")
        src_contention = os.path.join(cls.fixtures_dir, "proc_two_waiters_one_lock.c")
        src_deadlock = os.path.join(cls.fixtures_dir, "proc_thread_circular_deadlock.c")
        src_mutation = os.path.join(cls.fixtures_dir, "scenario_target.cpp")

        subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", src_healthy, "-o", cls.bin_healthy, "-pthread"], check=True)
        subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", src_growing, "-o", cls.bin_growing_mem, "-pthread"], check=True)
        subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", src_contention, "-o", cls.bin_contention, "-pthread"], check=True)
        subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", src_deadlock, "-o", cls.bin_deadlock, "-pthread"], check=True)
        subprocess.run(["g++", "-g", "-O0", "-Wl,--build-id=sha1", src_mutation, "-o", cls.bin_mutation, "-pthread"], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _start_mutation_process(self) -> Tuple[subprocess.Popen, Dict[str, Any]]:
        proc = fixture_popen(
            [self.bin_mutation],
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
    # Scenario 4: Memory Growth E2E
    # -------------------------------------------------------------------------
    def test_04_memory_growth_e2e(self):
        """Real process allocating heap memory across epochs is observed with LiveCaptureReceipt."""
        proc = fixture_popen([self.bin_growing_mem])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(proc.pid)

            with adapter.capture_transaction(session_id="sess_growth", pid=proc.pid, operation_type="diagnostic") as tx:
                maps = [m for m in adapter.get_memory_mappings(proc.pid) if m.get("is_readable")]
                vaddr = maps[0]["start_int"] if maps else 0
                raw_bytes, status, _ = adapter.read_memory(proc.pid, vaddr, 64)
                self.assertEqual(status, "OBSERVED")
                self.assertEqual(len(raw_bytes), 64)

            rcpt = adapter.issue_live_receipt_for_session("sess_growth", proc.pid, transaction=tx)
            self.assertIsNotNone(rcpt)
            self.assertEqual(rcpt.authority_level, "PRODUCTION")
            self.assertEqual(rcpt.pid, proc.pid)
        finally:
            if proc.stdin:
                proc.stdin.close()
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 5: Live Target Transaction Isolation E2E
    # -------------------------------------------------------------------------
    def test_05_live_target_transaction_isolation_e2e(self):
        """Two concurrent live processes have strictly isolated transactions, accounting, and digests."""
        proc1 = fixture_popen([self.bin_healthy])
        proc2 = fixture_popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            pinned1 = adapter.pin_target_identity(proc1.pid)
            pinned2 = adapter.pin_target_identity(proc2.pid)

            self.assertNotEqual(proc1.pid, proc2.pid)
            self.assertNotEqual(pinned1["process_identity"], pinned2["process_identity"])

            tx1 = adapter.begin_capture_transaction("sess_iso_1", proc1.pid, operation_type="diagnostic")
            maps1 = [m for m in adapter.get_memory_mappings(proc1.pid) if m.get("is_readable")]
            addr1 = maps1[0]["start_int"] if maps1 else 0
            adapter.read_memory(proc1.pid, addr1, 64)
            adapter.commit_capture_transaction(tx1)

            tx2 = adapter.begin_capture_transaction("sess_iso_2", proc2.pid, operation_type="diagnostic")
            maps2 = [m for m in adapter.get_memory_mappings(proc2.pid) if m.get("is_readable")]
            addr2 = maps2[0]["start_int"] if maps2 else 0
            adapter.read_memory(proc2.pid, addr2, 64)
            adapter.commit_capture_transaction(tx2)

            # Isolated accounting
            self.assertEqual(tx1.physical_bytes_read, 64)
            self.assertEqual(tx2.physical_bytes_read, 64)
            self.assertNotEqual(tx1.transaction_id, tx2.transaction_id)
            self.assertNotEqual(tx1.observation_digest, tx2.observation_digest)

            # Unscoped reads fail closed
            adapter.read_unscoped(proc1.pid, addr1, 32)
            self.assertEqual(adapter.unscoped_physical_reads_count, 1)
            # Unscoped read does not contaminate any transaction
            self.assertEqual(tx1.physical_reads_count, 1)
        finally:
            proc1.kill()
            proc1.wait()
            proc2.kill()
            proc2.wait()

    # -------------------------------------------------------------------------
    # Scenario 6: Process Mutation Causal Verification E2E
    # -------------------------------------------------------------------------
    def test_06_process_mutation_causal_verification_e2e(self):
        """Pre- and post-mutation observation establishes genuine causal proof on live process."""
        proc, oracle = self._start_mutation_process()
        try:
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(proc.pid)
            seq_addr = oracle["sequence"]

            # 1. Initial read
            with adapter.capture_transaction("sess_mut", proc.pid, operation_type="diagnostic") as tx1:
                val1_bytes, st1, _ = adapter.read_memory(proc.pid, seq_addr, 4)
            rcpt1 = adapter.issue_live_receipt_for_session("sess_mut", proc.pid, transaction=tx1)
            self.assertEqual(st1, "OBSERVED")
            val1 = struct.unpack("<I", val1_bytes)[0]
            self.assertEqual(val1, 42)

            # 2. Mutate state via stdin
            proc.stdin.write("SET sequence 9999\n")
            proc.stdin.flush()
            time.sleep(0.05)

            # 3. Post-mutation read
            with adapter.capture_transaction("sess_mut", proc.pid, operation_type="diagnostic") as tx2:
                val2_bytes, st2, _ = adapter.read_memory(proc.pid, seq_addr, 4)
            rcpt2 = adapter.issue_live_receipt_for_session("sess_mut", proc.pid, transaction=tx2)
            self.assertEqual(st2, "OBSERVED")
            val2 = struct.unpack("<I", val2_bytes)[0]
            self.assertEqual(val2, 9999)

            # Verify causal difference
            self.assertNotEqual(val1, val2)
            self.assertNotEqual(rcpt1.observation_digest, rcpt2.observation_digest)

            # 4. Record comparison evidence record into EvidenceLedger
            ledger = EvidenceLedger(session_id="sess_mut")
            target_id = {
                "pid": proc.pid,
                "process_identity": rcpt1.process_identity,
                "executable_identity": rcpt1.executable_identity,
                "build_id": rcpt1.build_id,
            }
            rec1 = EvidenceRecord(
                evidence_id="ev_mut_before",
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation=f"Initial sequence state: {val1}",
                provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt1.to_dict()},
                target_identity=target_id,
                details={"value": val1, "address": hex(seq_addr)},
                session_id="sess_mut",
            )
            rec2 = EvidenceRecord(
                evidence_id="ev_mut_after",
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation=f"Mutated sequence state: {val2}",
                provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt2.to_dict()},
                target_identity=target_id,
                details={"value": val2, "address": hex(seq_addr)},
                session_id="sess_mut",
            )
            ledger.add_record(rec1)
            ledger.add_record(rec2)

            comp_rec = EvidenceRecord(
                evidence_id="ev_mut_comp",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                observation=f"State transition observed: {val1} -> {val2}",
                provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt2.to_dict()},
                target_identity=target_id,
                details={
                    "derived_from": [rec1.evidence_id, rec2.evidence_id],
                    "before_evidence_id": rec1.evidence_id,
                    "after_evidence_id": rec2.evidence_id,
                    "delta": val2 - val1,
                },
                session_id="sess_mut",
            )
            ledger.add_record(comp_rec)
            self.assertEqual(len(ledger.records), 3)
        finally:
            if proc.stdin:
                proc.stdin.close()
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            proc.kill()
            proc.wait()



    # -------------------------------------------------------------------------
    # Scenario 9: Stop-Time SLA Under 4.5ms E2E
    # -------------------------------------------------------------------------
    def test_09_stop_time_sla_under_4_5ms_e2e(self):
        """Live physical memory read stop-time latency strictly satisfies < 4.5ms SLA."""
        proc = fixture_popen([self.bin_healthy])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            adapter.pin_target_identity(proc.pid)
            maps = [m for m in adapter.get_memory_mappings(proc.pid) if m.get("is_readable")]
            vaddr = maps[0]["start_int"] if maps else 0

            latencies_ms = []
            for _ in range(10):
                t0 = time.monotonic_ns()
                data, status, _ = adapter.read_memory(proc.pid, vaddr, 128)
                t_elapsed_ms = (time.monotonic_ns() - t0) / 1_000_000.0
                self.assertEqual(status, "OBSERVED")
                latencies_ms.append(t_elapsed_ms)

            avg_lat = sum(latencies_ms) / len(latencies_ms)
            max_lat = max(latencies_ms)
            self.assertLess(avg_lat, 4.5, f"Average stop-time latency {avg_lat:.2f}ms exceeded 4.5ms SLA")
            self.assertLess(max_lat, 4.5, f"Peak stop-time latency {max_lat:.2f}ms exceeded 4.5ms SLA")
        finally:
            if proc.stdin:
                proc.stdin.close()
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            proc.kill()
            proc.wait()



if __name__ == "__main__":
    unittest.main()
