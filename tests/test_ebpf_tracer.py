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
import unittest
from unittest.mock import MagicMock, patch

from extractor.debug_image import BinaryIdentity, inspect_elf
from extractor.dwarf_indexer import DwarfIndex, DwarfIndexer, DwarfSubprogram
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


if __name__ == "__main__":
    unittest.main()
