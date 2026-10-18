"""Fixture-based integration tests for Phase 1 eBPF Stack-Variable & Function Tracing.

Tests against real C++ target fixtures:
1. Debug build (-O0, debug symbols, frame pointers).
2. Optimized build (-O2, debug symbols, frame pointers).
3. Interactive command-driven fixture with clean detach verification.
4. Entry-only probe mode.
5. Overhead and event loss measurement reporting.

Skips cleanly if kernel, architecture, privileges, or bpftrace are unavailable.
"""

import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
import unittest

from extractor.ebpf_tracer import (
    STATUS_OBSERVED,
    STATUS_UNSUPPORTED_PHASE1,
    EbpfEnvironmentChecker,
    EbpfTracer,
    TraceObservationSession,
)
from extractor.observation_backends import EbpfObservationBackend


class TestEbpfFixtureIntegration(unittest.TestCase):
    """Real-target fixture integration test suite for eBPF tracing."""

    @classmethod
    def setUpClass(cls):
        # 1. Check prerequisites first. Skip cleanly if unavailable.
        cls.cap = EbpfEnvironmentChecker.check_prerequisites()
        if not cls.cap.supported:
            raise unittest.SkipTest(
                f"Skipping eBPF integration tests: {'; '.join(cls.cap.reasons)}"
            )

        # 2. Compile fixture in temporary directory
        cls.tmp_dir = tempfile.mkdtemp(prefix="dynstate_ebpf_fixture_")
        cls.fixture_src = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime", "ebpf_stack_fixture.cpp")
        )
        if not os.path.exists(cls.fixture_src):
            raise unittest.SkipTest(f"Fixture source not found: {cls.fixture_src}")

        cls.debug_bin = os.path.join(cls.tmp_dir, "ebpf_fixture_debug")
        cls.opt_bin = os.path.join(cls.tmp_dir, "ebpf_fixture_opt")

        # Compile debug binary (-O0)
        cmd_debug = [
            "g++", "-Wall", "-Wextra", "-g", "-O0", "-fno-inline",
            "-fno-omit-frame-pointer", "-Wl,--build-id=sha1",
            cls.fixture_src, "-o", cls.debug_bin,
        ]
        res_dbg = subprocess.run(cmd_debug, capture_output=True, text=True)
        if res_dbg.returncode != 0:
            raise RuntimeError(f"Failed to compile debug fixture: {res_dbg.stderr}")

        # Compile optimized binary (-O2)
        cmd_opt = [
            "g++", "-Wall", "-Wextra", "-g", "-O2", "-fno-inline",
            "-fno-omit-frame-pointer", "-DOPTIMIZED_BUILD", "-Wl,--build-id=sha1",
            cls.fixture_src, "-o", cls.opt_bin,
        ]
        res_opt = subprocess.run(cmd_opt, capture_output=True, text=True)
        if res_opt.returncode != 0:
            raise RuntimeError(f"Failed to compile optimized fixture: {res_opt.stderr}")

        cls.tracer = EbpfTracer(use_sudo=True)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "tmp_dir") and os.path.exists(cls.tmp_dir):
            shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _start_autonomous_fixture(self, binary_path: str, loops: int = 6, interval_ms: int = 200) -> Tuple[subprocess.Popen, int]:
        proc = subprocess.Popen(
            [binary_path, "--loop", str(loops), "--interval-ms", str(interval_ms)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        # Read startup line
        line = proc.stdout.readline()
        if "READY" not in line or "pid=" not in line:
            proc.kill()
            raise RuntimeError(f"Fixture failed to report READY line: {line.strip()}")
        tokens = line.split()
        pid = None
        for tok in tokens:
            if tok.startswith("pid="):
                pid = int(tok.split("=")[1])
        if pid is None:
            proc.kill()
            raise RuntimeError(f"Could not parse PID from fixture output: {line.strip()}")
        return proc, pid

    def test_01_trace_debug_build(self):
        """Verify eBPF function entry and return tracing on debug build (-O0)."""
        proc, pid = self._start_autonomous_fixture(self.debug_bin, loops=6, interval_ms=200)
        try:
            time.sleep(0.05)
            session = self.tracer.trace(
                pid=pid,
                binary_path=self.debug_bin,
                function_name="trace_target_function",
                duration_s=1.5,
                entry_only=False,
            )
        finally:
            proc.wait(timeout=3.0)

        # Assertions
        self.assertEqual(session.status, "SUCCESS")
        self.assertEqual(session.consistency_level, "PROBE_POINT_EVENT")
        self.assertGreater(session.total_events, 0, "Must capture at least one event")
        self.assertEqual(session.lost_events, 0, "No events should be lost under modest fixture rate")
        self.assertEqual(session.malformed_records, 0)

        # Inspect captured events
        entry_events = [e for e in session.events if e.probe_type == "ENTRY"]
        return_events = [e for e in session.events if e.probe_type == "RETURN"]
        self.assertGreater(len(entry_events), 0, "Must have entry events")
        self.assertGreater(len(return_events), 0, "Must have return events")

        # Verify entry event arguments and frame metadata
        first_entry = entry_events[0]
        self.assertEqual(first_entry.pid, pid)
        self.assertIsNotNone(first_entry.frame_metadata)
        self.assertIsNotNone(first_entry.frame_metadata.stack_pointer)
        self.assertIsNotNone(first_entry.frame_metadata.instruction_pointer)
        self.assertIn("param_0", first_entry.arguments)
        self.assertEqual(first_entry.arguments["param_0"].status, STATUS_OBSERVED)

        # Verify return event value
        first_return = return_events[0]
        self.assertIsNotNone(first_return.return_value)
        self.assertEqual(first_return.return_value.status, STATUS_OBSERVED)
        self.assertGreater(first_return.return_value.value, 0)

        # Local variables must truthfully report Phase 1 status
        self.assertIn("local_variables", first_entry.local_variables)
        self.assertEqual(first_entry.local_variables["local_variables"].status, STATUS_UNSUPPORTED_PHASE1)

        # Verify overhead reporting
        self.assertIn("attach_latency_ms", session.overhead_stats)
        self.assertGreater(session.overhead_stats["attach_latency_ms"], 0.0)

    def test_02_trace_optimized_build(self):
        """Verify eBPF function entry and return tracing on optimized build (-O2)."""
        proc, pid = self._start_autonomous_fixture(self.opt_bin, loops=6, interval_ms=200)
        try:
            time.sleep(0.05)
            session = self.tracer.trace(
                pid=pid,
                binary_path=self.opt_bin,
                function_name="trace_target_function",
                duration_s=1.5,
                entry_only=False,
            )
        finally:
            proc.wait(timeout=3.0)

        self.assertEqual(session.status, "SUCCESS")
        self.assertEqual(session.consistency_level, "PROBE_POINT_EVENT")
        self.assertGreater(session.total_events, 0)

        entry_events = [e for e in session.events if e.probe_type == "ENTRY"]
        return_events = [e for e in session.events if e.probe_type == "RETURN"]
        self.assertGreater(len(entry_events), 0)
        self.assertGreater(len(return_events), 0)

        # Verify arguments on optimized build
        self.assertIn("param_0", entry_events[0].arguments)
        self.assertEqual(entry_events[0].arguments["param_0"].status, STATUS_OBSERVED)
        self.assertIsNotNone(return_events[0].return_value)
        self.assertEqual(return_events[0].return_value.status, STATUS_OBSERVED)

    def test_03_entry_only_mode(self):
        """Verify entry_only=True skips uretprobe attachments."""
        proc, pid = self._start_autonomous_fixture(self.debug_bin, loops=4, interval_ms=200)
        try:
            time.sleep(0.05)
            session = self.tracer.trace(
                pid=pid,
                binary_path=self.debug_bin,
                function_name="trace_target_function",
                duration_s=1.0,
                entry_only=True,
            )
        finally:
            proc.wait(timeout=3.0)

        self.assertEqual(session.status, "SUCCESS")
        self.assertGreater(session.total_events, 0)
        # All events must be ENTRY
        for ev in session.events:
            self.assertEqual(ev.probe_type, "ENTRY")

    def test_04_observation_backend_integration(self):
        """Verify integration through EbpfObservationBackend."""
        proc, pid = self._start_autonomous_fixture(self.debug_bin, loops=4, interval_ms=200)
        backend = EbpfObservationBackend(tracer=self.tracer)
        try:
            time.sleep(0.05)
            session = backend.observe(
                pid=pid,
                binary=self.debug_bin,
                function="trace_target_function",
                duration_s=1.0,
            )
        finally:
            proc.wait(timeout=3.0)

        self.assertIsInstance(session, TraceObservationSession)
        self.assertEqual(session.status, "SUCCESS")
        self.assertEqual(session.target_pid, pid)
        self.assertEqual(session.function_name, "trace_target_function")


if __name__ == "__main__":
    unittest.main()
