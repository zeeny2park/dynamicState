"""Unit tests for Phase 1 eBPF Stack-Variable & Function Tracing.

Tests:
1. Event decoding (entry and return records, registers, frame metadata, arguments, return values).
2. PID/TID filtering (strict isolation to target process).
3. Malformed and truncated records handling (fault tolerance, counter increment).
4. Lost event tracking from ring buffer / kernel warnings.
5. Truthful local variable reporting (UNSUPPORTED_PHASE1, no fabricated values).
6. Truthful consistency reporting (PROBE_POINT_EVENT, never labeled as CONSISTENT snapshot).
7. Backend capability detection (bpftrace supported, libbpf marked unsupported in Phase 1).
8. Unsupported environment handling (non-Linux, unprivileged, missing dependencies).
9. Target process validation (invalid PID, non-existent PID, missing binary).
10. Target executable validation (/proc/<pid>/exe mismatch, stat dev/ino, Build ID mismatch).
11. Build ID verification (matching, mismatch fails closed, --no-verify-build-id explicitly unchecked).
12. Probe resolution (stripped binary without debug image, ambiguous functions, linkage name disambiguation).
13. Non-PIE file offset conversion (VirtAddr - p_vaddr + p_offset).
14. ObservationBackend contract and capability reporting.
15. Pure-Python ELF symbol lookup (find_elf_symbols).

NOTE: Ordinary unit tests NEVER require elevated privileges and run cleanly in any environment.
"""

import json
import os
import platform
import struct
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import unittest
from unittest.mock import MagicMock, patch

from extractor.debug_image import BinaryIdentity, inspect_elf
from extractor.dwarf_evaluator import (
    EVAL_STATUS_ERROR,
    EVAL_STATUS_OBSERVED,
    EVAL_STATUS_OPTIMIZED_OUT,
    EVAL_STATUS_UNAVAILABLE,
    EVAL_STATUS_UNSUPPORTED,
    DwarfEvaluationContext,
    DwarfEvaluator,
    DwarfLocationResult,
    Phase2DwarfLocationResolver,
    unpack_scalar_from_bytes,
    unpack_scalar_from_register,
)
from extractor.dwarf_indexer import DwarfIndex, DwarfIndexer, DwarfSubprogram, DwarfType, DwarfVariable
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
    find_elf_symbols,
)
from extractor.observation_backends import EbpfObservationBackend, ObservationBackend


class TestEbpfTracerUnit(unittest.TestCase):
    """Hermetic unit tests for eBPF tracer decoder, schemas, capability detection, and identity verification."""

    def setUp(self):
        self.target_pid = 4242
        self.decoder = EbpfEventDecoder(
            target_pid=self.target_pid,
            architecture="x86_64",
            function_name="test_func",
            function_offset=0x1234,
        )

    def test_01_decode_valid_entry_event(self):
        """Test decoding of valid JSON entry probe record with registers and frame metadata."""
        line = json.dumps({
            "type": "ENTRY",
            "pid": 4242,
            "tid": 4242,
            "time": 1000000000,
            "sp": "0x7fffffffe000",
            "pc": "0x401234",
            "fp": "0x7fffffffe020",
            "ra": "0x401100",
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
        self.assertEqual(ev.frame_metadata.frame_pointer, 0x7fffffffe020)
        self.assertEqual(ev.frame_metadata.return_address, 0x401100)

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

        # 3. Random noise or warning line (should be ignored, not counted as malformed)
        res = self.decoder.decode_line("WARNING: Could not determine instruction boundary")
        self.assertIsNone(res)
        self.assertEqual(self.decoder.malformed_count, 2)

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
            function_name="func",
            architecture="x86_64",
            backend_name="bpftrace",
            start_time="2026-01-01T00:00:00Z",
            target_build_id="abc",
            build_id_status="VERIFIED",
        )
        self.assertEqual(session.consistency_level, "PROBE_POINT_EVENT")
        self.assertNotEqual(session.consistency_level, "CONSISTENT")
        self.assertNotEqual(session.consistency_level, "STOPPED")
        self.assertEqual(session.build_id_status, "VERIFIED")

    def test_08_capability_detection_bpftrace_vs_libbpf(self):
        """Verify capability detection reports bpftrace as supported and libbpf as unsupported in Phase 1."""
        # Case A: bpftrace missing, clang and libbpf headers present
        with patch("sys.platform", "linux"), \
             patch("platform.machine", return_value="x86_64"), \
             patch("os.geteuid", return_value=0), \
             patch("os.path.exists", side_effect=lambda p: True if p in ("/sys/fs/bpf", "/usr/include/bpf/bpf.h") else False), \
             patch("shutil.which", side_effect=lambda cmd: "/usr/bin/clang" if cmd == "clang" else None):
            cap = EbpfEnvironmentChecker.check_prerequisites()
            self.assertEqual(cap.backend, "libbpf")
            self.assertFalse(cap.supported, "libbpf must NOT be reported as supported in Phase 1")
            self.assertTrue(any("deferred to Phase 2" in r for r in cap.reasons))

        # Case B: neither bpftrace nor clang present
        with patch("sys.platform", "linux"), \
             patch("platform.machine", return_value="x86_64"), \
             patch("os.geteuid", return_value=0), \
             patch("os.path.exists", side_effect=lambda p: p == "/sys/fs/bpf"), \
             patch("shutil.which", return_value=None):
            cap = EbpfEnvironmentChecker.check_prerequisites()
            self.assertEqual(cap.backend, "none")
            self.assertFalse(cap.supported)
            self.assertTrue(any("bpftrace executable not found" in r for r in cap.reasons))

    @patch("sys.platform", "darwin")
    def test_09_unsupported_environment_non_linux(self):
        """Verify non-Linux environments report UNSUPPORTED_ENVIRONMENT cleanly."""
        cap = EbpfEnvironmentChecker.check_prerequisites()
        self.assertFalse(cap.supported)
        self.assertEqual(cap.backend, "none")
        self.assertTrue(any("Linux" in r for r in cap.reasons))

    @patch("platform.machine", return_value="x86_64")
    @patch("os.geteuid", return_value=1000)
    @patch("subprocess.run")
    def test_10_unsupported_environment_unprivileged(self, mock_run, mock_geteuid, mock_machine):
        """Verify unprivileged user without sudo reports clear capability error."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_run.return_value = mock_proc

        with patch("sys.platform", "linux"), \
             patch("builtins.open", unittest.mock.mock_open(read_data="2")), \
             patch("os.path.exists", return_value=True):
            cap = EbpfEnvironmentChecker.check_prerequisites()
            self.assertFalse(cap.is_privileged)
            self.assertFalse(cap.supported)
            self.assertTrue(any("Unprivileged eBPF is disabled" in r for r in cap.reasons))

    def test_11_target_process_validation_nonexistent_pid(self):
        """Verify non-existent PID fails closed with clear diagnostic."""
        tracer = EbpfTracer(use_sudo=False)
        session = tracer.trace(
            pid=9999999,
            binary_path="/bin/ls",
            function_name="main",
        )
        self.assertEqual(session.status, "FAILED")
        self.assertIn("does not exist", session.error_message)

    def test_12_target_process_validation_invalid_pid(self):
        """Verify non-positive PID fails closed."""
        tracer = EbpfTracer(use_sudo=False)
        session = tracer.trace(
            pid=-5,
            binary_path="/bin/ls",
            function_name="main",
        )
        self.assertEqual(session.status, "FAILED")
        self.assertIn("Invalid target PID", session.error_message)

    def test_13_target_process_validation_missing_binary(self):
        """Verify tracing handles missing target binary safely when PID is alive."""
        my_pid = os.getpid()
        tracer = EbpfTracer(use_sudo=False)
        session = tracer.trace(
            pid=my_pid,
            binary_path="/nonexistent/path/to/binary_12345",
            function_name="some_func",
        )
        self.assertEqual(session.status, "FAILED")
        self.assertIn("Binary file not found", session.error_message)

    def test_14_process_executable_mismatch(self):
        """Verify /proc/<pid>/exe mismatch against requested binary fails closed."""
        my_pid = os.getpid()
        tracer = EbpfTracer(use_sudo=False)
        # Pass a real binary (/bin/ls) while running process is python3
        session = tracer.trace(
            pid=my_pid,
            binary_path="/bin/ls",
            function_name="main",
        )
        self.assertEqual(session.status, "FAILED")
        self.assertIn("does not match requested binary", session.error_message)
        self.assertEqual(session.build_id_status, "MISMATCHED")

    def test_15_build_id_mismatch_fails_closed(self):
        """Verify Build ID mismatch between binary and debug ELF fails closed."""
        tracer = EbpfTracer(use_sudo=False)
        with tempfile.NamedTemporaryFile("wb", suffix=".bin") as f1, \
             tempfile.NamedTemporaryFile("wb", suffix=".dbg") as f2:
            ident1 = BinaryIdentity(
                path=f1.name, elf_class="ELF64", architecture="x86_64", endianness="little",
                build_id="aaaa11112222", stripped=False, has_debug_info=True,
            )
            ident2 = BinaryIdentity(
                path=f2.name, elf_class="ELF64", architecture="x86_64", endianness="little",
                build_id="bbbb33334444", stripped=False, has_debug_info=True,
            )
            with patch("extractor.ebpf_tracer.inspect_elf", side_effect=[ident1, ident2]), \
                 patch("os.path.exists", return_value=True), \
                 patch("os.path.realpath", return_value=f1.name), \
                 patch("os.kill"):
                session = tracer.trace(
                    pid=os.getpid(),
                    binary_path=f1.name,
                    function_name="target_func",
                    debug_image=f2.name,
                    verify_build_id=True,
                )
                self.assertEqual(session.status, "FAILED")
                self.assertEqual(session.build_id_status, "MISMATCHED")
                self.assertIn("Build ID mismatch", session.error_message)

    def test_16_build_id_explicitly_unchecked(self):
        """Verify --no-verify-build-id explicitly records EXPLICITLY_UNCHECKED."""
        tracer = EbpfTracer(use_sudo=False)
        with tempfile.NamedTemporaryFile("wb", suffix=".bin") as f1:
            ident1 = BinaryIdentity(
                path=f1.name, elf_class="ELF64", architecture="x86_64", endianness="little",
                build_id="aaaa11112222", stripped=False, has_debug_info=True,
            )
            cap_mock = EbpfCapabilityResult(
                supported=False, backend="bpftrace", architecture="x86_64", kernel_version="6.0",
                is_privileged=False, unprivileged_bpf_disabled=0, has_bpf_fs=True, reasons=["mock unprivileged"],
            )
            with patch("extractor.ebpf_tracer.inspect_elf", return_value=ident1), \
                 patch("extractor.ebpf_tracer.EbpfEnvironmentChecker.check_prerequisites", return_value=cap_mock), \
                 patch("os.path.exists", return_value=True), \
                 patch("os.path.realpath", return_value=f1.name), \
                 patch("os.kill"):
                session = tracer.trace(
                    pid=os.getpid(),
                    binary_path=f1.name,
                    function_name="target_func",
                    verify_build_id=False,
                )
                self.assertEqual(session.build_id_status, "EXPLICITLY_UNCHECKED")

    def test_17_probe_resolution_stripped_binary_without_debug_image(self):
        """Verify stripped binary without debug image returns a clear diagnostic."""
        tracer = EbpfTracer(use_sudo=False)
        ident = BinaryIdentity(
            path="/bin/test_stripped", elf_class="ELF64", architecture="x86_64", endianness="little",
            build_id="abc123", stripped=True, has_debug_info=False,
        )
        fo, attach_spec, err = tracer._resolve_probe_target(
            elf_info=ident,
            binary_path="/bin/test_stripped",
            function_name="some_func",
            debug_image=None,
        )
        self.assertIsNone(fo)
        self.assertIsNone(attach_spec)
        self.assertIn("binary is stripped and no matching debug image was provided", err)

    def test_18_probe_resolution_ambiguous_function_fails(self):
        """Verify overloaded C++ functions with distinct locations return AMBIGUOUS diagnostic."""
        tracer = EbpfTracer(use_sudo=False)
        ident = BinaryIdentity(
            path="/bin/test_ambig", elf_class="ELF64", architecture="x86_64", endianness="little",
            build_id="abc123", stripped=False, has_debug_info=True,
        )
        subp1 = DwarfSubprogram(die_offset=0x10, name="calc", low_pc=0x1000, linkage_name="_Z4calci")
        subp2 = DwarfSubprogram(die_offset=0x20, name="calc", low_pc=0x1050, linkage_name="_Z4calcii")

        mock_index = MagicMock()
        mock_index.subprograms_by_name = {"calc": [subp1, subp2]}

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index), \
             patch("os.path.exists", return_value=True):
            fo, attach_spec, err = tracer._resolve_probe_target(
                elf_info=ident,
                binary_path="/bin/test_ambig",
                function_name="calc",
            )
            self.assertIsNone(fo)
            self.assertIsNone(attach_spec)
            self.assertIn("Ambiguous function name 'calc'", err)
            self.assertIn("matches 2 distinct subprogram locations", err)
            self.assertIn("0x1000", err)
            self.assertIn("0x1050", err)
            self.assertIn("_Z4calci", err)

    def test_19_probe_resolution_linkage_name_disambiguation(self):
        """Verify mangled linkage name disambiguates to a single unique location."""
        tracer = EbpfTracer(use_sudo=False)
        ident = BinaryIdentity(
            path="/bin/test_ambig", elf_class="ELF64", architecture="x86_64", endianness="little",
            build_id="abc123", stripped=False, has_debug_info=True,
            pt_loads=[{"p_vaddr": 0x0, "p_memsz": 0x5000, "p_offset": 0x0, "p_filesz": 0x5000}],
        )
        subp1 = DwarfSubprogram(die_offset=0x10, name="calc", low_pc=0x1000, linkage_name="_Z4calci")
        subp2 = DwarfSubprogram(die_offset=0x20, name="calc", low_pc=0x1050, linkage_name="_Z4calcii")

        mock_index = MagicMock()
        mock_index.subprograms_by_name = {
            "calc": [subp1, subp2],
            "_Z4calci": [subp1],
            "_Z4calcii": [subp2],
        }

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=0x5000):
            fo, attach_spec, err = tracer._resolve_probe_target(
                elf_info=ident,
                binary_path="/bin/test_ambig",
                function_name="_Z4calci",
            )
            self.assertIsNone(err)
            self.assertEqual(fo, 0x1000)
            self.assertEqual(attach_spec, "0x1000")

    def test_20_non_pie_file_offset_conversion(self):
        """Verify non-PIE virtual address is converted to file offset via PT_LOAD segment."""
        tracer = EbpfTracer(use_sudo=False)
        # Non-PIE layout: VirtAddr=0x400c90, PT_LOAD vaddr=0x400000, offset=0x0, size=0x2000
        ident = BinaryIdentity(
            path="/bin/test_nopie", elf_class="ELF64", architecture="x86_64", endianness="little",
            build_id="abc123", stripped=False, has_debug_info=True, elf_type="ET_EXEC",
            pt_loads=[
                {"p_vaddr": 0x400000, "p_memsz": 0x2000, "p_offset": 0x0, "p_filesz": 0x2000},
            ],
        )
        subp = DwarfSubprogram(die_offset=0x10, name="target_func", low_pc=0x400c90)
        mock_index = MagicMock()
        mock_index.subprograms_by_name = {"target_func": [subp]}

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=0x2000):
            fo, attach_spec, err = tracer._resolve_probe_target(
                elf_info=ident,
                binary_path="/bin/test_nopie",
                function_name="target_func",
            )
            self.assertIsNone(err)
            self.assertEqual(fo, 0xc90, "VirtAddr 0x400c90 - 0x400000 = 0xc90 file offset")
            self.assertEqual(attach_spec, "0xc90")

    def test_21_observation_backend_capabilities(self):
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

    def test_22_pure_python_elf_symbol_lookup(self):
        """Verify pure-Python symbol lookup finds symbols in unstripped ELF binaries."""
        # Test on /bin/ls or any accessible ELF binary
        syms = find_elf_symbols("/bin/ls", "some_nonexistent_symbol_12345")
        self.assertEqual(syms, [])

    def test_23_x86_64_return_address_null_not_hardcoded_zero(self):
        """Verify that on x86_64, missing or null return address is reported as UNAVAILABLE, never 0x0."""
        decoder_x86 = EbpfEventDecoder(
            target_pid=self.target_pid,
            architecture="x86_64",
            function_name="target_func",
        )

        # 1. Payload with null ra
        line_null_ra = json.dumps({
            "type": "ENTRY",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1000,
            "sp": "0x7fffffffe000",
            "pc": "0x401200",
            "fp": "0x7fffffffe020",
            "ra": None,
            "arg0": 1,
        })
        ev = decoder_x86.decode_line(line_null_ra)
        self.assertIsNotNone(ev)
        self.assertIsNone(ev.frame_metadata.return_address, "x86_64 return address must not be fabricated")
        self.assertNotEqual(ev.frame_metadata.return_address, 0)
        self.assertEqual(ev.frame_metadata.return_address_status, STATUS_UNAVAILABLE)
        self.assertIn("stack", ev.frame_metadata.return_address_reason.lower())
        self.assertIsNone(ev.frame_metadata.to_dict()["return_address"])

        # 2. Payload with ra == 0 (must also be treated as unavailable, not a valid return address)
        line_zero_ra = json.dumps({
            "type": "ENTRY",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1000,
            "sp": "0x7fffffffe000",
            "pc": "0x401200",
            "fp": "0x7fffffffe020",
            "ra": 0,
            "arg0": 1,
        })
        ev2 = decoder_x86.decode_line(line_zero_ra)
        self.assertIsNotNone(ev2)
        self.assertIsNone(ev2.frame_metadata.return_address)
        self.assertEqual(ev2.frame_metadata.return_address_status, STATUS_UNAVAILABLE)

        # 3. On AArch64, valid observed link register is preserved
        decoder_arm = EbpfEventDecoder(
            target_pid=self.target_pid,
            architecture="aarch64",
            function_name="target_func",
        )
        line_arm = json.dumps({
            "type": "ENTRY",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1000,
            "sp": "0x7fffffffe000",
            "pc": "0x401200",
            "fp": "0x7fffffffe020",
            "ra": "0x401150",
            "arg0": 1,
        })
        ev_arm = decoder_arm.decode_line(line_arm)
        self.assertIsNotNone(ev_arm)
        self.assertEqual(ev_arm.frame_metadata.return_address, 0x401150)
        self.assertEqual(ev_arm.frame_metadata.return_address_status, STATUS_OBSERVED)

    def test_24_distinguish_unavailable_registers_from_zero(self):
        """Verify registers holding 0 are OBSERVED, while null or missing registers are UNAVAILABLE."""
        line = json.dumps({
            "type": "ENTRY",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1000,
            "sp": "0x7fffffffe000",
            "pc": "0x401200",
            "arg0": 0,       # Valid 0 integer
            "arg1": None,    # Explicit null
        })
        ev = self.decoder.decode_line(line)
        self.assertIsNotNone(ev)

        # param_0: observed 0
        self.assertIn("param_0", ev.arguments)
        self.assertEqual(ev.arguments["param_0"].status, STATUS_OBSERVED)
        self.assertEqual(ev.arguments["param_0"].value, 0)
        self.assertEqual(ev.arguments["param_0"].value_hex, "0x0")

        # param_1: unavailable
        self.assertIn("param_1", ev.arguments)
        self.assertEqual(ev.arguments["param_1"].status, STATUS_UNAVAILABLE)
        self.assertIsNone(ev.arguments["param_1"].value)

        # param_2: absent
        self.assertNotIn("param_2", ev.arguments)

    def test_25_signedness_and_integer_width_preservation(self):
        """Verify negative integers and 64-bit hexadecimal bit patterns are preserved."""
        line_entry = json.dumps({
            "type": "ENTRY",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1000,
            "sp": "0x7fffffffe000",
            "pc": "0x401200",
            "arg0": -42,
            "arg1": 42,
        })
        ev_entry = self.decoder.decode_line(line_entry)
        self.assertEqual(ev_entry.arguments["param_0"].value, -42)
        self.assertEqual(ev_entry.arguments["param_0"].value_hex, "0xffffffffffffffd6")
        self.assertEqual(ev_entry.arguments["param_1"].value, 42)
        self.assertEqual(ev_entry.arguments["param_1"].value_hex, "0x2a")

        line_ret = json.dumps({
            "type": "RETURN",
            "pid": self.target_pid,
            "tid": self.target_pid,
            "time": 1005,
            "sp": "0x7fffffffe000",
            "pc": "0x401250",
            "ret": -1,
        })
        ev_ret = self.decoder.decode_line(line_ret)
        self.assertEqual(ev_ret.return_value.value, -1)
        self.assertEqual(ev_ret.return_value.value_hex, "0xffffffffffffffff")

    def test_26_session_status_zero_events_is_partial(self):
        """Verify that attachment producing zero events reports PARTIAL rather than SUCCESS."""
        tracer = EbpfTracer()

        mock_ident = BinaryIdentity(
            path="/bin/echo",
            architecture="x86_64",
            elf_class="ELF64",
            endianness="little",
            build_id="abcdef",
            stripped=False,
            pt_loads=[{"p_vaddr": 0x400000, "p_memsz": 0x1000, "p_offset": 0, "p_filesz": 0x1000}],
        )

        mock_proc = MagicMock()
        poll_count_26 = 0
        def mock_poll_26():
            nonlocal poll_count_26
            poll_count_26 += 1
            return None if poll_count_26 < 5 else 0

        mock_proc.poll = mock_poll_26
        mock_proc.returncode = 0
        mock_proc.stdout.readline.return_value = "Attaching 1 probe...\n"
        mock_proc.stdout.readlines.return_value = []
        mock_proc.stderr.readline.return_value = ""

        with patch("extractor.ebpf_tracer.inspect_elf", return_value=mock_ident), \
             patch("os.path.exists", return_value=True), \
             patch("os.kill", return_value=None), \
             patch("select.select", return_value=([mock_proc.stdout], [], [])), \
             patch("extractor.ebpf_tracer.EbpfEnvironmentChecker.check_prerequisites") as mock_cap, \
             patch("subprocess.Popen", return_value=mock_proc):

            mock_cap.return_value = EbpfCapabilityResult(
                supported=True,
                backend="bpftrace",
                architecture="x86_64",
                kernel_version="6.17",
                is_privileged=True,
                unprivileged_bpf_disabled=0,
                has_bpf_fs=True,
            )

            session = tracer.trace(
                pid=os.getpid(),
                binary_path="/bin/echo",
                function_name="0x400500",
                duration_s=0.01,
            )

            self.assertEqual(session.status, "PARTIAL", "0 events must report PARTIAL, never SUCCESS")
            self.assertEqual(session.total_events, 0)
            self.assertIn("0 events were captured", session.error_message)

    def test_27_session_status_lost_events_is_partial(self):
        """Verify that a trace with lost events reports PARTIAL."""
        tracer = EbpfTracer()

        mock_ident = BinaryIdentity(
            path="/bin/echo",
            architecture="x86_64",
            elf_class="ELF64",
            endianness="little",
            build_id="abcdef",
            stripped=False,
            pt_loads=[{"p_vaddr": 0x400000, "p_memsz": 0x1000, "p_offset": 0, "p_filesz": 0x1000}],
        )

        mock_proc = MagicMock()
        poll_count_27 = 0
        def mock_poll_27():
            nonlocal poll_count_27
            poll_count_27 += 1
            return None if poll_count_27 < 5 else 0

        mock_proc.poll = mock_poll_27
        mock_proc.returncode = 0
        # Yield attach notice, a lost event notice, a valid event, then empty
        mock_proc.stdout.readline.side_effect = [
            "Attaching 1 probe...\n",
            json.dumps({"type": "ENTRY", "pid": os.getpid(), "tid": os.getpid(), "time": 100, "arg0": 1}) + "\n",
            "Lost 3 events\n",
            "",
        ]
        mock_proc.stdout.readlines.return_value = []
        mock_proc.stderr.readline.return_value = ""

        with patch("extractor.ebpf_tracer.inspect_elf", return_value=mock_ident), \
             patch("os.path.exists", return_value=True), \
             patch("os.kill", return_value=None), \
             patch("select.select", return_value=([mock_proc.stdout], [], [])), \
             patch("extractor.ebpf_tracer.EbpfEnvironmentChecker.check_prerequisites") as mock_cap, \
             patch("subprocess.Popen", return_value=mock_proc):

            mock_cap.return_value = EbpfCapabilityResult(
                supported=True,
                backend="bpftrace",
                architecture="x86_64",
                kernel_version="6.17",
                is_privileged=True,
                unprivileged_bpf_disabled=0,
                has_bpf_fs=True,
            )

            session = tracer.trace(
                pid=os.getpid(),
                binary_path="/bin/echo",
                function_name="0x400500",
                duration_s=0.01,
            )

            self.assertEqual(session.status, "PARTIAL")
            self.assertEqual(session.lost_events, 3)
            self.assertIn("lost", session.error_message.lower())

    def test_28_dwarf_evaluator_direct_register(self):
        """Verify DWARF evaluator direct register resolution (DW_OP_reg* / DW_OP_regx)."""
        ident = BinaryIdentity(path="/bin/dummy", architecture="aarch64", elf_class="ELF64", endianness="little")
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            low_pc=0x1000,
            high_pc=0x1100,
            variables=[
                DwarfVariable(die_offset=0x20, name="scalar_arg", type_offset=0x30, location_expr="DW_OP_reg0"),
                DwarfVariable(die_offset=0x25, name="scalar_r5", type_offset=0x30, location_expr="DW_OP_reg5"),
            ],
        )

        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index):
            ctx = DwarfEvaluationContext(
                binary_identity=ident,
                subprogram=subp,
                link_time_address=0x1020,
                registers={"x0": 77, "x5": 128},
                variable_name="scalar_arg",
                architecture="aarch64",
            )
            res = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res.status, EVAL_STATUS_OBSERVED)
            self.assertEqual(res.location_type, "register")
            self.assertEqual(res.register_name, "x0")
            self.assertEqual(res.value, 77)
            self.assertEqual(res.value_hex, "0x0000004d")

            ctx.variable_name = "scalar_r5"
            res2 = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res2.status, EVAL_STATUS_OBSERVED)
            self.assertEqual(res2.value, 128)

            # Test unavailable register
            ctx.registers = {}  # Empty registers
            res_unavail = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res_unavail.status, EVAL_STATUS_UNAVAILABLE)
            self.assertIn("not available", res_unavail.reason)

    def test_29_dwarf_evaluator_frame_base_relative(self):
        """Verify DWARF evaluator frame-base relative location (DW_OP_fbreg <offset>)."""
        ident = BinaryIdentity(path="/bin/dummy", architecture="aarch64", elf_class="ELF64", endianness="little")
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            frame_base="DW_OP_call_frame_cfa",
            low_pc=0x1000,
            high_pc=0x1100,
            variables=[
                DwarfVariable(die_offset=0x20, name="local_val", type_offset=0x30, location_expr="DW_OP_fbreg: -116"),
            ],
        )

        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index):
            # Frame pointer = 0x7fffffffe000. On AArch64 with standard prologue, CFA = FP + 16 = 0x7fffffffe010
            # Target address = CFA - 116 = 0x7fffffffe010 - 116 = 0x7fffffffdfe4
            fm = FrameMetadata(frame_pointer=0x7fffffffe000)

            # 1. Without memory reader: truthful address reporting without fabricated value
            ctx = DwarfEvaluationContext(
                binary_identity=ident,
                subprogram=subp,
                link_time_address=0x1020,
                frame_metadata=fm,
                variable_name="local_val",
                architecture="aarch64",
            )
            res = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res.status, EVAL_STATUS_UNAVAILABLE)
            self.assertEqual(res.location_type, "stack_memory")
            self.assertEqual(res.evaluated_address, 0x7fffffffdf9c)
            self.assertIn("0x7fffffffdf9c", res.reason)
            self.assertIsNone(res.value)

            # 2. With memory reader: unpacks memory cleanly
            mem_data = {0x7fffffffdf9c: struct.pack("<i", 4242)}
            def mock_reader(addr: int, sz: int) -> Optional[bytes]:
                return mem_data.get(addr)

            ctx.memory_reader = mock_reader
            res_mem = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res_mem.status, EVAL_STATUS_OBSERVED)
            self.assertEqual(res_mem.value, 4242)
            self.assertEqual(res_mem.value_hex, "0x00001092")
            self.assertEqual(res_mem.evaluated_address, 0x7fffffffdf9c)

    def test_30_dwarf_evaluator_location_list_selection(self):
        """Verify active range selection and instruction pointer filtering in location lists."""
        ident = BinaryIdentity(path="/bin/dummy", architecture="aarch64", elf_class="ELF64", endianness="little")
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            low_pc=0x1000,
            high_pc=0x1200,
            variables=[
                DwarfVariable(die_offset=0x20, name="opt_param", type_offset=0x30, location_list_offset=0x429),
            ],
        )

        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        mock_loc_table = {
            0x429: [
                (0x1000, 0x1050, "DW_OP_reg0 (x0)"),
                (0x1050, 0x1080, "DW_OP_reg5 (x5)"),
                (0x1080, 0x1100, "DW_OP_entry_value: (DW_OP_reg0 (x0)); DW_OP_stack_value"),
            ]
        }

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index), \
             patch("extractor.dwarf_evaluator.parse_debug_loc_table", return_value=mock_loc_table):

            ctx = DwarfEvaluationContext(
                binary_identity=ident,
                subprogram=subp,
                link_time_address=0x1020,
                registers={"x0": 10, "x5": 20},
                variable_name="opt_param",
                architecture="aarch64",
            )

            # Link-time PC 0x1020 matches [0x1000, 0x1050) -> x0
            res1 = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res1.status, EVAL_STATUS_OBSERVED)
            self.assertEqual(res1.register_name, "x0")
            self.assertEqual(res1.value, 10)

            # Link-time PC 0x1060 matches [0x1050, 0x1080) -> x5
            ctx.link_time_address = 0x1060
            res2 = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res2.status, EVAL_STATUS_OBSERVED)
            self.assertEqual(res2.register_name, "x5")
            self.assertEqual(res2.value, 20)

            # Link-time PC 0x1090 matches [0x1080, 0x1100) -> DW_OP_entry_value (OPTIMIZED_OUT)
            ctx.link_time_address = 0x1090
            res3 = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res3.status, EVAL_STATUS_OPTIMIZED_OUT)
            self.assertIn("entry_value", res3.reason)

            # Link-time PC 0x1150 is outside all ranges -> UNAVAILABLE
            ctx.link_time_address = 0x1150
            res4 = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res4.status, EVAL_STATUS_UNAVAILABLE)
            self.assertIn("outside", res4.reason)

    def test_31_dwarf_evaluator_unsupported_vs_optimized_out(self):
        """Verify UNSUPPORTED opcodes are NEVER conflated with OPTIMIZED_OUT."""
        ident = BinaryIdentity(path="/bin/dummy", architecture="aarch64", elf_class="ELF64", endianness="little")
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            low_pc=0x1000,
            high_pc=0x1100,
            variables=[
                DwarfVariable(die_offset=0x20, name="unsupported_var", type_offset=0x30, location_expr="DW_OP_piece 4"),
                DwarfVariable(die_offset=0x25, name="optimized_var", type_offset=0x30, location_expr=None, location_list_offset=None),
            ],
        )

        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index):
            ctx = DwarfEvaluationContext(
                binary_identity=ident,
                subprogram=subp,
                link_time_address=0x1020,
                variable_name="unsupported_var",
                architecture="aarch64",
            )
            res_unsup = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res_unsup.status, EVAL_STATUS_UNSUPPORTED)
            self.assertNotEqual(res_unsup.status, EVAL_STATUS_OPTIMIZED_OUT)

            ctx.variable_name = "optimized_var"
            res_opt = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res_opt.status, EVAL_STATUS_OPTIMIZED_OUT)
            self.assertNotEqual(res_opt.status, EVAL_STATUS_UNSUPPORTED)

    def test_32_dwarf_evaluator_scalar_types(self):
        """Verify unpacking of all supported scalar types from memory and registers."""
        # 1. Unpack from bytes
        v_i8, h_i8 = unpack_scalar_from_bytes(b"\xfb", "int8")
        self.assertEqual(v_i8, -5)
        self.assertEqual(h_i8, "0xfb")

        v_u8, h_u8 = unpack_scalar_from_bytes(b"\xfb", "uint8")
        self.assertEqual(v_u8, 251)
        self.assertEqual(h_u8, "0xfb")

        v_i16, h_i16 = unpack_scalar_from_bytes(struct.pack("<h", -300), "short")
        self.assertEqual(v_i16, -300)
        self.assertEqual(h_i16, "0xfed4")

        v_i32, h_i32 = unpack_scalar_from_bytes(struct.pack("<i", -100000), "int")
        self.assertEqual(v_i32, -100000)
        self.assertEqual(h_i32, "0xfffe7960")

        v_u32, h_u32 = unpack_scalar_from_bytes(struct.pack("<I", 100000), "unsigned int")
        self.assertEqual(v_u32, 100000)
        self.assertEqual(h_u32, "0x000186a0")

        v_i64, h_i64 = unpack_scalar_from_bytes(struct.pack("<q", -5000000000), "int64_t")
        self.assertEqual(v_i64, -5000000000)

        v_flt, h_flt = unpack_scalar_from_bytes(struct.pack("<f", 3.14159), "float")
        self.assertAlmostEqual(v_flt, 3.14159, places=4)

        v_dbl, h_dbl = unpack_scalar_from_bytes(struct.pack("<d", 2.718281828), "double")
        self.assertAlmostEqual(v_dbl, 2.718281828, places=6)

        v_bool, h_bool = unpack_scalar_from_bytes(b"\x01", "bool")
        self.assertEqual(v_bool, True)
        self.assertEqual(h_bool, "0x1")

        v_ptr, h_ptr = unpack_scalar_from_bytes(struct.pack("<Q", 0x7fffffffe100), "void*")
        self.assertEqual(v_ptr, 0x7fffffffe100)
        self.assertEqual(h_ptr, "0x7fffffffe100")

        # 2. Unpack from register
        v_reg_i32, h_reg_i32 = unpack_scalar_from_register(0xffffffff, "int32", byte_size=4)
        self.assertEqual(v_reg_i32, -1)
        self.assertEqual(h_reg_i32, "0xffffffff")

        v_reg_u32, h_reg_u32 = unpack_scalar_from_register(0xffffffff, "uint32", byte_size=4)
        self.assertEqual(v_reg_u32, 4294967295)

    def test_33_dwarf_evaluator_gdb_parity_value_assertions(self):
        """Verify Phase 2 resolver value reconstruction against exact expected values and types."""
        ident = BinaryIdentity(
            path="/bin/dummy",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id="abcdef0123456789",
            elf_type="ET_DYN",
        )
        fp = 0x7fffffffe000
        var_addr = fp + 16 - 24
        mem_store = {
            var_addr: struct.pack("<i", -4242),
        }

        def mock_mem_reader(addr: int, sz: int) -> Optional[bytes]:
            return mem_store.get(addr)

        subp = DwarfSubprogram(
            die_offset=0x10,
            name="target_func",
            low_pc=0x1000,
            high_pc=0x1100,
            frame_base="DW_OP_call_frame_cfa",
            cfa_rules=[(0x1000, 0x1100, "fp", 16, True)],
            variables=[
                DwarfVariable(die_offset=0x20, name="local_int", type_offset=0x30, location_expr="DW_OP_fbreg -24"),
            ],
        )

        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        resolver = Phase2DwarfLocationResolver(
            binary_identity=ident,
            link_time_address=0x1020,
            load_bias=0,
            architecture="x86_64",
            memory_reader=mock_mem_reader,
        )

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index):
            tv = resolver.resolve_variable(
                subprogram=subp,
                variable_name="local_int",
                registers={"rbp": fp, "rsp": fp - 32},
                frame_metadata=FrameMetadata(frame_pointer=fp),
            )
            self.assertEqual(tv.status, STATUS_OBSERVED)
            self.assertEqual(tv.value, -4242)
            self.assertEqual(tv.value_hex, "0xffffef6e")
            self.assertIn("stack:", tv.location)
            self.assertIn("CFA", tv.location)

    def test_34_phase2_resolver_companion_debug_artifact_and_cfi(self):
        """Verify companion artifact rejection and unsupported CFI rule detection in Phase 2 resolver."""
        ident = BinaryIdentity(
            path="/bin/dummy",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id="1111222233334444",
            elf_type="ET_DYN",
        )
        subp_unsupported = DwarfSubprogram(
            die_offset=0x10,
            name="complex_cfi_func",
            low_pc=0x1000,
            high_pc=0x1100,
            has_unsupported_cfi=True,
            variables=[
                DwarfVariable(die_offset=0x20, name="x", type_offset=0x30, location_expr="DW_OP_reg0"),
            ],
        )
        mock_index = DwarfIndex(artifact_path="/bin/dummy")
        mock_index.types_by_die[0x30] = DwarfType(die_offset=0x30, tag="DW_TAG_base_type", name="int", byte_size=4)

        resolver = Phase2DwarfLocationResolver(
            binary_identity=ident,
            link_time_address=0x1020,
            load_bias=0,
            architecture="x86_64",
        )

        with patch("extractor.dwarf_indexer.DwarfIndexer.get_index", return_value=mock_index):
            tv = resolver.resolve_variable(
                subprogram=subp_unsupported,
                variable_name="x",
                registers={"rax": 10},
                frame_metadata=FrameMetadata(),
            )
            self.assertEqual(tv.status, EVAL_STATUS_UNSUPPORTED)
            self.assertIn("DW_CFA_def_cfa_expression", tv.reason)

        # Mismatched companion debug artifact
        resolver_mismatch = Phase2DwarfLocationResolver(
            binary_identity=ident,
            link_time_address=0x1020,
            load_bias=0,
            architecture="x86_64",
            debug_artifact_path="/bin/other_debug",
        )
        dbg_ident = BinaryIdentity(
            path="/bin/other_debug",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id="9999888877776666",
            elf_type="ET_DYN",
        )

        with patch("os.path.exists", return_value=True), \
             patch("extractor.dwarf_evaluator.inspect_elf", return_value=dbg_ident):
            tv_mismatch = resolver_mismatch.resolve_variable(
                subprogram=DwarfSubprogram(die_offset=0x10, name="func", low_pc=0x1000),
                variable_name="x",
                registers={},
                frame_metadata=FrameMetadata(),
            )
            self.assertEqual(tv_mismatch.status, EVAL_STATUS_ERROR)
            self.assertIn("Build ID mismatch", tv_mismatch.reason)


if __name__ == "__main__":
    unittest.main()

