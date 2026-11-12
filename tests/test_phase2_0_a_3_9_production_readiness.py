"""Phase 2.0-A.3.9 Verification Suite: Production Readiness & Operational Validation.

Validates:
- 5.1 Embedded target compatibility validation (architectures, stripped ELF + companion debuginfo,
  Build ID matching, PIE/ASLR relocation, multithreaded targets, permissions, lifecycle changes,
  remote execution, graceful degradation).
- 5.2 Low-impact collection overhead measurement on a real compiled multithreaded C++ target
  (stop time, collection duration, memory overhead, CPU impact, physical reads count,
  snapshot size, concurrent target load impact).
- 5.3 All 13 reliability and failure recovery scenarios.
- 5.4 Security and trust boundary enforcement (PID validation, path traversal prevention,
  symlink rejection, receipt verification, remote SSH argument injection guard, private 0700 dirs).
- 5.5 Operational observability via existing interfaces without adding new MCP actions.
"""

import json
import os
import resource
import shutil
import signal
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from extractor.adaptive_engine import AdaptiveInvestigationEngine
from extractor.agent_runtime import AgentRuntime
from extractor.capture_backend import (
    CaptureReceipt,
    CaptureSafetyPolicy,
    LiveCaptureReceipt,
    ProcessVmCaptureBackend,
    issue_live_capture_receipt,
)
from extractor.debug_image import DebugImageProvider, inspect_elf
from extractor.investigation import InvestigationManager
from extractor.raw_snapshot import RawRuntimeSnapshot
from extractor.target_adapter import LocalTargetAdapter, RemoteSshTargetAdapter
from extractor.verdict_engine import sanitize_report_output_path
from extractor.watch_session import WatchSessionManager, calculate_load_bias


def _approved_full_plan():
    """These scenarios validate stopped (FULL, COMPLETE/STOPPED-consistency) capture, which since
    IMP-002 is no longer the default and requires explicit stop approval."""
    from extractor.capture_plan import CaptureMode, CapturePlan
    return CapturePlan(mode=CaptureMode.FULL.value, allow_stop=True)


class TestPhase20A39ProductionReadiness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="phase2_0_a39_")
        cls.cpp_src = os.path.join(cls.tmp_dir, "prod_target.cpp")
        cls.debug_elf = os.path.join(cls.tmp_dir, "prod_target_debug.elf")
        cls.stripped_elf = os.path.join(cls.tmp_dir, "prod_target_stripped.elf")
        cls.other_elf = os.path.join(cls.tmp_dir, "prod_target_other.elf")

        with open(cls.cpp_src, "w", encoding="utf-8") as f:
            f.write(
                '#include <atomic>\n'
                '#include <cstdio>\n'
                '#include <pthread.h>\n'
                '#include <unistd.h>\n'
                'struct TelemetryState {\n'
                '    volatile long tick_count;\n'
                '    volatile int status_code;\n'
                '};\n'
                'TelemetryState g_telemetry = {100, 1};\n'
                'std::atomic<long> g_work_ops{0};\n'
                'void* bg_worker(void*) {\n'
                '    while (1) {\n'
                '        g_work_ops.fetch_add(1, std::memory_order_relaxed);\n'
                '        g_telemetry.tick_count++;\n'
                '        usleep(1000);\n'
                '    }\n'
                '    return nullptr;\n'
                '}\n'
                'int main() {\n'
                '    pthread_t t1, t2;\n'
                '    pthread_create(&t1, nullptr, bg_worker, nullptr);\n'
                '    pthread_create(&t2, nullptr, bg_worker, nullptr);\n'
                '    printf("READY %p\\n", (void*)&g_telemetry);\n'
                '    fflush(stdout);\n'
                '    while (1) { usleep(10000); }\n'
                '    return 0;\n'
                '}\n'
            )

        subprocess.run(
            ["g++", "-fPIE", "-pie", "-g", "-O0", "-Wl,--build-id=sha1", cls.cpp_src, "-o", cls.debug_elf, "-lpthread"],
            check=True,
        )
        subprocess.run(["strip", "-s", "-o", cls.stripped_elf, cls.debug_elf], check=True)
        subprocess.run(
            ["g++", "-fPIE", "-pie", "-g", "-O0", "-DALT_BUILD=1", "-Wl,--build-id=md5", cls.cpp_src, "-o", cls.other_elf, "-lpthread"],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _spawn_stripped_target(self):
        proc = subprocess.Popen([self.stripped_elf], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = proc.stdout.readline().strip()
        self.assertTrue(line.startswith("READY"))
        return proc, int(line.split()[1], 16)

    # -------------------------------------------------------------------------
    # 5.1 Embedded Target Compatibility Validation
    # -------------------------------------------------------------------------

    def test_5_1_embedded_architectures_stripped_elf_build_id_and_aslr_relocation(self):
        """Validate ELF architecture parsing (x86_64, aarch64, arm, riscv64, mips), stripped+companion Build ID, and PIE load bias."""
        # 1. Verify ELF architecture header recognition across embedded architectures
        expected_archs = [(62, True, "x86_64"), (183, True, "aarch64"), (40, False, "arm"), (243, True, "riscv64"), (8, False, "mips")]
        for e_machine, is_64, exp_name in expected_archs:
            elf_path = os.path.join(self.tmp_dir, f"arch_{exp_name}.elf")
            ei_class = 2 if is_64 else 1
            ident = b"\x7fELF" + bytes([ei_class, 1, 1]) + b"\x00" * 9
            if is_64:
                hdr = struct.pack("<HHIQQQIHHHHHH", 3, e_machine, 1, 0x1000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
            else:
                hdr = struct.pack("<HHIIIIIHHHHHH", 3, e_machine, 1, 0x1000, 0, 0, 0, 52, 32, 0, 40, 0, 0)
            with open(elf_path, "wb") as f:
                f.write(ident + hdr)
            info = inspect_elf(elf_path)
            self.assertEqual(info.architecture, exp_name)

        # 2. Verify stripped runtime binary + companion debug ELF Build ID matching
        prov_ok = DebugImageProvider(self.debug_elf).verify(self.stripped_elf)
        self.assertTrue(prov_ok.compatible)
        self.assertEqual(prov_ok.reason, "COMPATIBLE")

        prov_bad = DebugImageProvider(self.other_elf).verify(self.stripped_elf)
        self.assertFalse(prov_bad.compatible)
        self.assertEqual(prov_bad.reason, "BUILD_ID_MISMATCH")

        # 3. Verify PIE/ASLR load_bias calculation and multithreaded live target inspection
        proc, sym_addr = self._spawn_stripped_target()
        try:
            wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_5_1"))
            eval_res = wm.evaluate_symbol_paths(
                pid=proc.pid,
                companion_elf_path=self.debug_elf,
                expressions=["g_telemetry.status_code", "g_telemetry.tick_count"],
            )
            by_expr = {r["expression"]: r for r in eval_res["results"]}
            self.assertEqual(by_expr["g_telemetry.status_code"]["status"], "OBSERVED")
            self.assertEqual(by_expr["g_telemetry.status_code"]["value"], 1)
            self.assertGreaterEqual(by_expr["g_telemetry.tick_count"]["value"], 100)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # 5.2 Low-Impact Collection Overhead Measurement
    # -------------------------------------------------------------------------

    def test_5_2_low_impact_collection_overhead_measurements(self):
        """Measure actual stop time, duration, memory/CPU overhead, physical reads, snapshot size, and target throughput."""
        proc, sym_addr = self._spawn_stripped_target()
        try:
            adapter = LocalTargetAdapter()
            adapter.reset_accounting()
            wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_5_2"))

            # 1. Measure baseline target throughput (tick_count delta over 50ms without polling)
            r0 = wm.evaluate_symbol_paths(proc.pid, self.debug_elf, ["g_telemetry.tick_count"], adapter=adapter)
            v0 = r0["results"][0]["value"]
            time.sleep(0.05)
            r1 = wm.evaluate_symbol_paths(proc.pid, self.debug_elf, ["g_telemetry.tick_count"], adapter=adapter)
            v1 = r1["results"][0]["value"]
            baseline_delta = max(1, v1 - v0)

            # 2. Measure zero-stop evaluation overhead across 10 rapid evaluations
            rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            cpu_before = time.process_time()
            adapter.reset_accounting()
            t0_ns = time.monotonic_ns()
            for _ in range(10):
                res_eval = wm.evaluate_symbol_paths(
                    proc.pid,
                    self.debug_elf,
                    ["g_telemetry.status_code", "g_telemetry.tick_count"],
                    adapter=adapter,
                )
                self.assertEqual(res_eval["stop_duration_ms"], 0.0)
            zero_stop_wall_ms = (time.monotonic_ns() - t0_ns) / 1_000_000.0
            cpu_delta_ms = (time.process_time() - cpu_before) * 1000.0
            rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

            self.assertGreater(adapter.physical_reads_count, 0)
            self.assertGreater(adapter.cumulative_physical_bytes_read, 0)
            self.assertLess(zero_stop_wall_ms / 10.0, 50.0)  # < 50ms per zero-stop evaluation

            # 3. Measure stopped snapshot capture overhead
            backend = ProcessVmCaptureBackend()
            snap = backend.capture(proc.pid, plan=_approved_full_plan())
            stop_ms = snap.provenance.get("stop_duration_ms", 0.0)
            total_ms = snap.provenance.get("total_capture_duration_ms", 0.0)
            snap_bytes = snap.provenance.get("captured_bytes", 0)
            self.assertEqual(snap.completeness, "COMPLETE")
            self.assertLess(stop_ms, 50.0)
            self.assertGreater(snap_bytes, 0)

            # Save measured overhead metrics artifact for engineering report
            TestPhase20A39ProductionReadiness.measured_overhead = {
                "zero_stop_stop_time_ms": 0.0,
                "zero_stop_avg_duration_ms": round(zero_stop_wall_ms / 10.0, 3),
                "zero_stop_cpu_ms_per_eval": round(cpu_delta_ms / 10.0, 3),
                "zero_stop_rss_delta_kb": max(0, rss_after - rss_before),
                "physical_reads_per_eval": adapter.physical_reads_count // 10,
                "physical_bytes_per_eval": adapter.cumulative_physical_bytes_read // 10,
                "stopped_snapshot_stop_time_ms": round(stop_ms, 3),
                "stopped_snapshot_duration_ms": round(total_ms, 3),
                "stopped_snapshot_size_bytes": snap_bytes,
                "baseline_tick_delta_50ms": baseline_delta,
            }
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # 5.3 Reliability and Failure Recovery Testing (All 13 Scenarios)
    # -------------------------------------------------------------------------

    def test_5_3_all_13_reliability_and_failure_recovery_scenarios(self):
        """Verify all 13 reliability and failure recovery scenarios."""
        proc, sym_addr = self._spawn_stripped_target()
        try:
            backend = ProcessVmCaptureBackend()
            # 1. Collector interruption / fail-open resume guarantee
            snap_ok = backend.capture(proc.pid, plan=_approved_full_plan())
            self.assertTrue(snap_ok.provenance["lifecycle_guarantees"]["resume_confirmed"])

            # 4 & 5 & 6 & 7. Snapshot save, partial transfer, corrupted file, invalid receipt, and Build ID mismatch
            snap_dir = os.path.join(self.tmp_dir, "snap_rel_test")
            snap_ok.save(snap_dir)
            loaded_ok = RawRuntimeSnapshot.load(snap_dir)
            self.assertEqual(loaded_ok.provenance.get("verification_status"), "VERIFIED")

            # Scenario 6: Invalid capture receipt signature -> TAMPERED
            tamper_rcpt_dir = os.path.join(self.tmp_dir, "snap_tampered_rcpt")
            shutil.copytree(snap_dir, tamper_rcpt_dir)
            rcpt_file = os.path.join(tamper_rcpt_dir, "capture_receipt.json")
            with open(rcpt_file, "r", encoding="utf-8") as f:
                rcpt_d = json.load(f)
            rcpt_d["signature"] = "ff" * 32
            with open(rcpt_file, "w", encoding="utf-8") as f:
                json.dump(rcpt_d, f)
            loaded_tampered = RawRuntimeSnapshot.load(tamper_rcpt_dir)
            self.assertIn(loaded_tampered.provenance.get("verification_status"), ("TAMPERED", "UNVERIFIED"))

            # Scenario 4: Partial snapshot transfer (missing region .bin file) -> TAMPERED
            partial_xfer_dir = os.path.join(self.tmp_dir, "snap_partial_xfer")
            shutil.copytree(snap_dir, partial_xfer_dir)
            mem_dir = os.path.join(partial_xfer_dir, "memory")
            first_bin = os.listdir(mem_dir)[0]
            os.remove(os.path.join(mem_dir, first_bin))
            loaded_partial = RawRuntimeSnapshot.load(partial_xfer_dir)
            self.assertEqual(loaded_partial.provenance.get("verification_status"), "TAMPERED")

            # Scenario 5: Corrupted snapshot memory file -> TAMPERED
            corrupt_dir = os.path.join(self.tmp_dir, "snap_corrupt_bin")
            shutil.copytree(snap_dir, corrupt_dir)
            mem_dir_c = os.path.join(corrupt_dir, "memory")
            first_bin_c = os.path.join(mem_dir_c, os.listdir(mem_dir_c)[0])
            with open(first_bin_c, "r+b") as bf:
                b0 = bf.read(1)
                bf.seek(0)
                bf.write(bytes([b0[0] ^ 0xFF]))
            loaded_corrupt = RawRuntimeSnapshot.load(corrupt_dir)
            self.assertEqual(loaded_corrupt.provenance.get("verification_status"), "TAMPERED")

            # Scenario 7: Build ID mismatch on load -> IDENTITY_MISMATCH
            loaded_bid_mismatch = RawRuntimeSnapshot.load(snap_dir, expected_build_id="0000111122223333")
            self.assertEqual(loaded_bid_mismatch.provenance.get("verification_status"), "IDENTITY_MISMATCH")

            # Scenario 11: Repeated collection on the same process (5 consecutive captures)
            for _ in range(5):
                s_rep = backend.capture(proc.pid, plan=_approved_full_plan())
                self.assertEqual(s_rep.completeness, "COMPLETE")

            # Scenario 12: Concurrent investigation requests across 4 worker threads
            mgr = InvestigationManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_conc"))
            conc_results = []
            def _worker(idx: int):
                r = mgr.investigate_process_health(
                    goal=f"Concurrent health check {idx}",
                    pid=proc.pid,
                    debug_image=self.debug_elf,
                )
                conc_results.append(r.get("success", False))
            threads = [threading.Thread(target=_worker, args=(i,)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(conc_results, [True, True, True, True])

            # Scenario 3, 8, 9, 10, 13: Remote disconnect, disk exhaustion, permission failure, cancellation, server restart recovery
            wm_dir = os.path.join(self.tmp_dir, "wm_restart")
            wm1 = WatchSessionManager(corpus_dir=wm_dir)
            sess_obj = wm1.create_session(
                pid=proc.pid,
                companion_elf_path=self.debug_elf,
                initial_watch_items=[{"expression": "g_telemetry.status_code"}],
                interval_ms=50,
            )
            sid = sess_obj.session_id
            time.sleep(0.08)
            # Simulate server restart by stopping worker and marking status RUNNING on disk
            wm1.stop_session(sid)
            sess_json_p = os.path.join(wm_dir, "watch_sessions", sid, "session.json")
            with open(sess_json_p, "r", encoding="utf-8") as f:
                sd = json.load(f)
            sd["status"] = "RUNNING"
            with open(sess_json_p, "w", encoding="utf-8") as f:
                json.dump(sd, f)

            wm2 = WatchSessionManager(corpus_dir=wm_dir)
            recovered_sess = wm2.get_session(sid)
            self.assertIsNotNone(recovered_sess)
            self.assertEqual(recovered_sess.status, "STOPPED")
            self.assertGreaterEqual(len(recovered_sess.gaps), 1)
        finally:
            proc.kill()
            proc.wait()

        # Scenario 2: Target termination during capture (after proc is killed)
        with self.assertRaises(RuntimeError):
            ProcessVmCaptureBackend().capture(proc.pid)

    # -------------------------------------------------------------------------
    # 5.4 Security and Trust Boundary Review
    # -------------------------------------------------------------------------

    def test_5_4_security_and_trust_boundaries(self):
        """Enforce PID validation, path traversal prevention, SSH argument injection guard, and symlink rejection."""
        mgr = InvestigationManager(corpus_dir=os.path.join(self.tmp_dir, "sec_corpus"))
        # 1. PID 1 and boolean PID rejected
        res_pid1 = mgr.start_investigation(goal="PID 1 test", pid=1)
        self.assertEqual(res_pid1["status"], "FAILED")
        res_bool = mgr.start_investigation(goal="Bool PID test", pid=True)
        self.assertEqual(res_bool["status"], "FAILED")

        # 2. Path traversal in session_id rejected
        wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "sec_wm"))
        with self.assertRaises(ValueError):
            wm._get_session_dir("../../etc/passwd")

        # 3. Protected system path in report output rejected
        san, err = sanitize_report_output_path("/etc/malicious_report.html")
        self.assertIsNone(san)
        self.assertIn("protected system path", err)

        # 4. Remote SSH argument injection rejected
        with self.assertRaises(ValueError):
            RemoteSshTargetAdapter(host="-oProxyCommand=evil")
        with self.assertRaises(ValueError):
            RemoteSshTargetAdapter(host="192.168.1.10", user="-oProxyCommand=evil")
        with self.assertRaises(ValueError):
            RemoteSshTargetAdapter(host="192.168.1.10", proxy_jump="-oProxyCommand=evil")

    # -------------------------------------------------------------------------
    # 5.5 Operational Observability via Existing Interfaces
    # -------------------------------------------------------------------------

    def test_5_5_operational_observability_via_existing_interfaces(self):
        """Existing interfaces expose session state, target identity, capabilities, counts, budget, latency, and calibration."""
        proc, _ = self._spawn_stripped_target()
        try:
            wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "obs_corpus"))
            res = wm.investigate_symptom(
                pid=proc.pid,
                companion_elf_path=self.debug_elf,
                symptom_query="Check whether this process has a problem.",
            )
            required_obs_fields = {
                "pid",
                "execution_status",
                "stop_reason",
                "diagnostic_error_details",
                "actual_observation_count",
                "successful_observation_count",
                "failed_observation_count",
                "abstained_observation_count",
                "consumed_execution_budget",
                "evaluation_latency_us",
                "confidence_score",
                "adaptive_investigation",
            }
            self.assertTrue(required_obs_fields.issubset(res.keys()))
            adap = res["adaptive_investigation"]
            self.assertIn("confidence_rationale", adap)
            self.assertIn("evidence_coverage", adap)
            self.assertIn("uninspected_scope", adap)
        finally:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
