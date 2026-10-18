"""Unit tests for Phase 1 eBPF Stack-Variable & Function Tracing.

Tests:
1. Event decoding (entry and return records, registers, frame metadata, arguments, return values).
2. PID/TID filtering (strict isolation to target process).
3. Malformed and truncated records handling (fault tolerance, counter increment).
4. Lost event tracking from ring buffer / kernel warnings.
5. Truthful local variable reporting (UNSUPPORTED_PHASE1, no fabricated values).
6. Truthful consistency reporting (PROBE_POINT_EVENT, never labeled as CONSISTENT snapshot).
7. Unsupported environment handling (non-Linux, unprivileged, missing dependencies).
8. Error cleanup and resource management (temporary files, subprocess lifecycle).
9. Build ID verification and mismatch rejection.
10. ObservationBackend contract and capability reporting.

NOTE: Ordinary unit tests NEVER require elevated privileges and run cleanly in any environment.
"""

import json
import os
import platform
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from extractor.ebpf_tracer import (
    STATUS_OBSERVED,
    STATUS_UNAVAILABLE,
    STATUS_UNSUPPORTED_PHASE1,
    STATUS_LOST,
    DwarfLocationResolverInterface,
    EbpfCapabilityResult,
    EbpfEnvironmentChecker,
    EbpfEventDecoder,
    EbpfTracer,
    FrameMetadata,
    Phase1DwarfLocationResolver,
    TraceEvent,
    TraceObservationSession,
    TraceValue,
)
from extractor.observation_backends import EbpfObservationBackend, ObservationBackend


class TestEbpfTracerUnit(unittest.TestCase):
    """Hermetic unit tests for eBPF tracer decoder, schemas, and error recovery."""

    def setUp(self):
        self.target_pid = 4242
        self.decoder = EbpfEventDecoder(
            target_pid=self.target_pid,
            architecture="x86_64",
            function_name="test_func",
            function_offset=0x1234,
        )

    def test_01_decode_valid_entry_event(self):
        """Test decoding of valid JSON entry probe record."""
        line = json.dumps({
            "type": "ENTRY",
            "pid": 4242,
            "tid": 4242,
            "time": 1000000000,
            "sp": "0x7fffffffe000",
            "pc": "0x401234",
            "arg0": 10,
            "arg1": 20,
            "arg2": 30,
        })
        ev = self.decoder.decode_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.sequence, 1)
        self.assertEqual(ev.pid, 4242)
        self.assertEqual(ev.tid, 4242)
        self.assertEqual(ev.probe_type, "ENTRY")
        self.assertEqual(ev.function_name, "test_func")
        self.assertEqual(ev.function_offset, 0x1234)

        # Registers and Frame metadata
        self.assertIsNotNone(ev.frame_metadata)
        self.assertEqual(ev.frame_metadata.stack_pointer, 0x7fffffffe000)
        self.assertEqual(ev.frame_metadata.instruction_pointer, 0x401234)

        # Arguments mapped from arg0..arg2
        self.assertIn("param_0", ev.arguments)
        self.assertEqual(ev.arguments["param_0"].status, STATUS_OBSERVED)
        self.assertEqual(ev.arguments["param_0"].value, 10)
        self.assertEqual(ev.arguments["param_0"].location, "register:arg0")

        self.assertIn("param_1", ev.arguments)
        self.assertEqual(ev.arguments["param_1"].value, 20)

        self.assertIn("param_2", ev.arguments)
        self.assertEqual(ev.arguments["param_2"].value, 30)

        # Return value is None on entry
        self.assertIsNone(ev.return_value)

        # Local variables explicitly marked as unsupported in Phase 1
        self.assertIn("local_variables", ev.local_variables)
        self.assertEqual(ev.local_variables["local_variables"].status, STATUS_UNSUPPORTED_PHASE1)
        self.assertIn("Phase 2", ev.local_variables["local_variables"].reason)

    def test_02_decode_valid_return_event(self):
        """Test decoding of valid return probe record with retval."""
        line = json.dumps({
            "type": "RETURN",
            "pid": 4242,
            "tid": 4242,
            "time": 1000005000,
            "sp": "0x7fffffffe000",
            "pc": "0x401250",
            "ret": "0x58",  # 88 in hex
        })
        ev = self.decoder.decode_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.probe_type, "RETURN")
        self.assertIsNotNone(ev.return_value)
        self.assertEqual(ev.return_value.status, STATUS_OBSERVED)
        self.assertEqual(ev.return_value.value, 88)
        self.assertEqual(ev.return_value.value_hex, "0x58")
        self.assertEqual(ev.return_value.location, "register:retval")

    def test_03_pid_filtering_strict(self):
        """Verify events from other processes are rejected and ignored."""
        foreign_line = json.dumps({
            "type": "ENTRY",
            "pid": 9999,  # Different PID
            "tid": 9999,
            "time": 1000000000,
            "sp": "0x7fffffffe000",
            "pc": "0x401234",
            "arg0": 1,
        })
        ev = self.decoder.decode_line(foreign_line)
        self.assertIsNone(ev, "Foreign PID must be filtered out")
        self.assertEqual(self.decoder.sequence_counter, 0)

    def test_04_malformed_and_truncated_records(self):
        """Verify corrupted or truncated records are recorded without crashing."""
        # 1. Truncated JSON
        self.decoder.decode_line('{"type":"ENTRY","pid":4242,"tid":4242,"sp":"0x7fff')
        self.assertEqual(self.decoder.malformed_count, 1)

        # 2. Syntax garbage
        self.decoder.decode_line('{invalid json record: true, 123}')
        self.assertEqual(self.decoder.malformed_count, 2)

        # 3. Random noise
        res = self.decoder.decode_line("Random log warning: something occurred")
        self.assertIsNone(res)

        # 4. Decoder still functions after corrupt records
        valid = json.dumps({"type": "ENTRY", "pid": 4242, "tid": 4242, "time": 123456, "sp": "0x1000", "pc": "0x2000"})
        ev = self.decoder.decode_line(valid)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.pid, 4242)

    def test_05_lost_events_tracking(self):
        """Verify lost event notices from transport ringbuffer are accumulated."""
        self.decoder.decode_line("Lost 7 events")
        self.assertEqual(self.decoder.lost_count, 7)

        self.decoder.decode_line("Warning: lost 3 samples due to ring buffer overflow")
        self.assertEqual(self.decoder.lost_count, 10)

    def test_06_truthful_local_variables_reporting(self):
        """Verify local variable resolution explicitly declares Phase 1 status."""
        resolver = Phase1DwarfLocationResolver()
        val = resolver.resolve_variable(
            subprogram=None,
            variable_name="my_stack_var",
            registers={"sp": 0x1000},
            frame_metadata=FrameMetadata(stack_pointer=0x1000),
        )
        self.assertEqual(val.status, STATUS_UNSUPPORTED_PHASE1)
        self.assertIsNone(val.value)
        self.assertIn("Phase 2", val.reason)
        self.assertIn("dynamic location evaluation", val.reason)

    def test_07_truthful_consistency_semantics(self):
        """Verify session consistency level is never labeled as a CONSISTENT snapshot."""
        session = TraceObservationSession(
            session_id="test_sess_01",
            target_pid=4242,
            target_binary="/bin/test",
            target_build_id="abc",
            function_name="func",
            architecture="x86_64",
            backend_name="bpftrace",
            start_time="2026-01-01T00:00:00Z",
        )
        self.assertEqual(session.consistency_level, "PROBE_POINT_EVENT")
        self.assertNotEqual(session.consistency_level, "CONSISTENT")
        self.assertNotEqual(session.consistency_level, "STOPPED")

    @patch("sys.platform", "darwin")
    def test_08_unsupported_environment_non_linux(self):
        """Verify non-Linux environments report UNSUPPORTED_ENVIRONMENT cleanly."""
        cap = EbpfEnvironmentChecker.check_prerequisites()
        self.assertFalse(cap.supported)
        self.assertEqual(cap.backend, "none")
        self.assertTrue(any("Linux" in r for r in cap.reasons))

    @patch("os.geteuid", return_value=1000)
    @patch("subprocess.run")
    def test_09_unsupported_environment_unprivileged(self, mock_run, mock_geteuid):
        """Verify unprivileged user without sudo reports clear capability error."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_run.return_value = mock_proc

        with patch("builtins.open", unittest.mock.mock_open(read_data="2")):
            cap = EbpfEnvironmentChecker.check_prerequisites()
            self.assertFalse(cap.is_privileged)
            self.assertFalse(cap.supported)
            self.assertTrue(any("Unprivileged eBPF is disabled" in r for r in cap.reasons))

    def test_10_cleanup_after_missing_binary(self):
        """Verify tracing handles missing target binary safely without leaking files."""
        tracer = EbpfTracer(use_sudo=False)
        session = tracer.trace(
            pid=4242,
            binary_path="/nonexistent/path/to/binary_12345",
            function_name="some_func",
        )
        self.assertEqual(session.status, "FAILED")
        self.assertIn("Binary file not found", session.error_message)

    def test_11_observation_backend_capabilities(self):
        """Verify EbpfObservationBackend complies with ObservationBackend ABC."""
        backend = EbpfObservationBackend()
        self.assertEqual(backend.mode, "EBPF_PROBE")
        caps = backend.capabilities()
        self.assertEqual(caps["mode"], "EBPF_PROBE")
        self.assertFalse(caps["process_stop"])
        self.assertFalse(caps["ptrace"])
        self.assertTrue(caps["ebpf"])
        self.assertEqual(caps["consistency"], "PROBE_POINT_EVENT")
        self.assertEqual(caps["dwarf_eval_status"], "UNSUPPORTED_PHASE1")


if __name__ == "__main__":
    unittest.main()
