#!/usr/bin/env python3
"""Phase 2.0-A.3.13 — SLA Measurement & Latency Correctness Test Suite.

Audits and proves:
1. Monotonic timing: measure_read_latency collects empirical read samples using monotonic clock.
2. Statistical distribution: Reports sample count, p50, p95, max, and sla_4_5ms_satisfied.
3. Suspension separation: Distinguishes physical memory read latency from process suspension time.
4. Non-intrusive truthfulness: Zero-stop kernel reads report target_suspension_applicable=False and process_suspension_time_ms=None.
5. End-to-end live process verification: Validates SLA distribution against a live C++ process.
"""

import os
import subprocess
import time
import unittest

from tests.fixture_builds import ensure_real_runtime_app_debug
from extractor.target_adapter import LocalTargetAdapter


class TestPhase20A313SlaMeasurement(unittest.TestCase):
    """Audits SLA latency measurement correctness and separation of process suspension."""

    @classmethod
    def setUpClass(cls):
        cls.bin_path = ensure_real_runtime_app_debug()

    def setUp(self):
        self.proc = subprocess.Popen(
            [self.bin_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        ready_line = self.proc.stdout.readline()
        self.assertTrue(ready_line.startswith("READY"), f"Target process failed READY handshake: {ready_line}")
        time.sleep(0.05)
        self.adapter = LocalTargetAdapter()

    def tearDown(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()

    def test_01_measure_read_latency_statistical_metrics(self):
        """measure_read_latency computes valid samples, p50, p95, max, and SLA satisfaction."""
        maps = [m for m in self.adapter.get_proc_maps(self.proc.pid) if m.get("is_readable")]
        self.assertGreater(len(maps), 0, "No readable memory mappings found in target")
        test_addr = maps[0]["start_int"]

        report = self.adapter.measure_read_latency(
            pid=self.proc.pid,
            address=test_addr,
            size=64,
            samples=20,
        )

        self.assertEqual(report["samples_collected"], 20)
        self.assertGreater(report["read_latency_p50_ms"], 0.0)
        self.assertGreaterEqual(report["read_latency_p95_ms"], report["read_latency_p50_ms"])
        self.assertGreaterEqual(report["read_latency_max_ms"], report["read_latency_p95_ms"])
        self.assertIn("sla_4_5ms_satisfied", report)
        self.assertIsInstance(report["sla_4_5ms_satisfied"], bool)

    def test_02_suspension_time_explicitly_separated_from_read_latency(self):
        """Zero-stop concurrent reads distinguish read latency from suspension time (non-applicable)."""
        maps = [m for m in self.adapter.get_proc_maps(self.proc.pid) if m.get("is_readable")]
        test_addr = maps[0]["start_int"]

        report = self.adapter.measure_read_latency(
            pid=self.proc.pid,
            address=test_addr,
            size=128,
            samples=10,
        )

        # Process suspension must be explicitly reported as non-applicable
        self.assertIs(report["target_suspension_applicable"], False)
        self.assertIsNone(report["process_suspension_time_ms"])
        self.assertEqual(report["measurement_method"], "monotonic_ns_user_space")
        self.assertIn("zero-stop", report["suspension_explanation"].lower())
        self.assertIn("was not suspended", report["suspension_explanation"].lower())

    def test_03_zero_stop_reads_satisfy_sla_under_normal_operation(self):
        """Local memory reads via process_vm_readv comfortably complete within 4.5ms SLA."""
        maps = [m for m in self.adapter.get_proc_maps(self.proc.pid) if m.get("is_readable")]
        test_addr = maps[0]["start_int"]

        report = self.adapter.measure_read_latency(
            pid=self.proc.pid,
            address=test_addr,
            size=64,
            samples=25,
        )

        # On Linux with process_vm_readv, 64-byte local read p50 is typically < 0.2ms
        self.assertLess(report["read_latency_p50_ms"], 1.0)
        self.assertTrue(report["sla_4_5ms_satisfied"], f"Expected SLA satisfied (<4.5ms), got max: {report['read_latency_max_ms']}ms")


if __name__ == "__main__":
    unittest.main()
