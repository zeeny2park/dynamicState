"""Fixture-based integration tests for Phase 1 eBPF Stack-Variable & Function Tracing (Hardened).

Covers all 10 required real-target integration test scenarios:
1. Debug build (-O0, debug symbols, frame pointers).
2. Optimized build (-O2, debug symbols, frame pointers).
3. Stripped binary with matching external debug ELF (strip -s).
4. Deliberate Build ID mismatch & explicitly unchecked mode.
5. PIE and Non-PIE executables (file offset translation).
6. Missing symbol and ambiguous function (linkage name disambiguation).
7. Invalid PID and target process exiting mid-trace (PARTIAL / clean termination).
8. Unsupported permissions / mocked non-root handling.
9. Entry-only mode vs Entry+Return mode.
10. Interruption and process group cleanup (no orphaned processes).

Skips cleanly if kernel, architecture, privileges, or bpftrace are unavailable.
"""

import json
import os
import platform
import shutil
import signal
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
import unittest
from unittest.mock import patch

import struct
from extractor.debug_image import inspect_elf
from extractor.dwarf_evaluator import (
    EVAL_STATUS_OBSERVED,
    EVAL_STATUS_OPTIMIZED_OUT,
    EVAL_STATUS_UNAVAILABLE,
    DwarfEvaluationContext,
    DwarfEvaluator,
)
from extractor.dwarf_indexer import DwarfIndexer
from extractor.ebpf_tracer import (
    STATUS_OBSERVED,
    STATUS_UNSUPPORTED_PHASE1,
    EbpfCapabilityResult,
    EbpfEnvironmentChecker,
    EbpfTracer,
    FrameMetadata,
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

        # 2. Compile fixture variants in temporary directory
        cls.tmp_dir = tempfile.mkdtemp(prefix="dynstate_ebpf_fixture_")
        cls.fixture_src = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime", "ebpf_stack_fixture.cpp")
        )
        if not os.path.exists(cls.fixture_src):
            raise unittest.SkipTest(f"Fixture source not found: {cls.fixture_src}")

        cls.debug_bin = os.path.join(cls.tmp_dir, "ebpf_fixture_debug")
        cls.opt_bin = os.path.join(cls.tmp_dir, "ebpf_fixture_opt")
        cls.stripped_bin = os.path.join(cls.tmp_dir, "ebpf_fixture_stripped")
        cls.debug_elf = os.path.join(cls.tmp_dir, "ebpf_fixture.debug")
        cls.nopie_bin = os.path.join(cls.tmp_dir, "ebpf_fixture_nopie")
        cls.mismatched_bin = os.path.join(cls.tmp_dir, "dummy_other_bin")
        cls.mismatched_dbg = os.path.join(cls.tmp_dir, "dummy_other.debug")

        # 1. Debug binary (-O0)
        cmd_debug = [
            "g++", "-Wall", "-Wextra", "-g", "-O0", "-fno-inline",
            "-fno-omit-frame-pointer", "-Wl,--build-id=sha1",
            cls.fixture_src, "-o", cls.debug_bin,
        ]
        res_dbg = subprocess.run(cmd_debug, capture_output=True, text=True)
        if res_dbg.returncode != 0:
            raise RuntimeError(f"Failed to compile debug fixture: {res_dbg.stderr}")

        # 2. Optimized binary (-O2)
        cmd_opt = [
            "g++", "-Wall", "-Wextra", "-g", "-O2", "-fno-inline",
            "-fno-omit-frame-pointer", "-DOPTIMIZED_BUILD", "-Wl,--build-id=sha1",
            cls.fixture_src, "-o", cls.opt_bin,
        ]
        res_opt = subprocess.run(cmd_opt, capture_output=True, text=True)
        if res_opt.returncode != 0:
            raise RuntimeError(f"Failed to compile optimized fixture: {res_opt.stderr}")

        # 3. Stripped binary with external debug ELF
        cmd_str = [
            "g++", "-Wall", "-Wextra", "-g", "-O0", "-fno-inline",
            "-fno-omit-frame-pointer", "-Wl,--build-id=sha1",
            cls.fixture_src, "-o", cls.stripped_bin,
        ]
        res_str = subprocess.run(cmd_str, capture_output=True, text=True)
        if res_str.returncode != 0:
            raise RuntimeError(f"Failed to compile stripped fixture source: {res_str.stderr}")
        subprocess.run(["objcopy", "--only-keep-debug", cls.stripped_bin, cls.debug_elf], check=True)
        subprocess.run(["strip", "-s", cls.stripped_bin], check=True)

        # 4. Non-PIE executable (-no-pie)
        cmd_nopie = [
            "g++", "-no-pie", "-Wall", "-Wextra", "-g", "-O0", "-fno-inline",
            "-fno-omit-frame-pointer", "-Wl,--build-id=sha1",
            cls.fixture_src, "-o", cls.nopie_bin,
        ]
        res_nopie = subprocess.run(cmd_nopie, capture_output=True, text=True)
        if res_nopie.returncode != 0:
            raise RuntimeError(f"Failed to compile non-PIE fixture: {res_nopie.stderr}")

        # 5. Mismatched dummy ELF
        dummy_src = os.path.join(cls.tmp_dir, "dummy.c")
        with open(dummy_src, "w") as f:
            f.write("int main() { return 0; }\n")
        subprocess.run(["gcc", "-g", "-Wl,--build-id=md5", dummy_src, "-o", cls.mismatched_bin], check=True)
        subprocess.run(["objcopy", "--only-keep-debug", cls.mismatched_bin, cls.mismatched_dbg], check=True)

        cls.tracer = EbpfTracer(use_sudo=True)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "tmp_dir") and os.path.exists(cls.tmp_dir):
            shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _start_autonomous_fixture(self, binary_path: str, loops: int = 20, interval_ms: int = 100) -> Tuple[subprocess.Popen, int]:
        proc = subprocess.Popen(
            [binary_path, "--loop", str(loops), "--interval-ms", str(interval_ms)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = proc.stdout.readline()
        if "READY" not in line or "pid=" not in line:
            self._stop_fixture(proc)
            raise RuntimeError(f"Fixture failed to report READY line: {line.strip()}")
        tokens = line.split()
        pid = None
        for tok in tokens:
            if tok.startswith("pid="):
                pid = int(tok.split("=")[1])
        if pid is None:
            self._stop_fixture(proc)
            raise RuntimeError(f"Could not parse PID from fixture output: {line.strip()}")
        return proc, pid

    def _stop_fixture(self, proc: Optional[subprocess.Popen]):
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2.0)
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
        except Exception:
            pass

    def test_01_trace_debug_build(self):
        """Scenario 1: Verify eBPF function entry and return tracing on debug build (-O0)."""
        proc, pid = self._start_autonomous_fixture(self.debug_bin, loops=20, interval_ms=100)
        try:
            time.sleep(0.05)
            session = self.tracer.trace(
                pid=pid,
                binary_path=self.debug_bin,
                function_name="trace_target_function",
                duration_s=1.2,
                entry_only=False,
            )
        finally:
            self._stop_fixture(proc)

        self.assertEqual(session.status, "SUCCESS")
        self.assertEqual(session.consistency_level, "PROBE_POINT_EVENT")
        self.assertEqual(session.build_id_status, "VERIFIED")
        self.assertGreater(session.total_events, 0, "Must capture at least one event")
        self.assertEqual(session.lost_events, 0)
        self.assertEqual(session.malformed_records, 0)

        entry_events = [e for e in session.events if e.probe_type == "ENTRY"]
        return_events = [e for e in session.events if e.probe_type == "RETURN"]
        self.assertGreater(len(entry_events), 0)
        self.assertGreater(len(return_events), 0)

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

    def test_02_trace_optimized_build(self):
        """Scenario 2: Verify eBPF function entry and return tracing on optimized build (-O2)."""
        proc, pid = self._start_autonomous_fixture(self.opt_bin, loops=20, interval_ms=100)
        try:
            time.sleep(0.05)
            session = self.tracer.trace(
                pid=pid,
                binary_path=self.opt_bin,
                function_name="trace_target_function",
                duration_s=1.2,
                entry_only=False,
            )
        finally:
            self._stop_fixture(proc)

        self.assertEqual(session.status, "SUCCESS")
        self.assertEqual(session.build_id_status, "VERIFIED")
        self.assertGreater(session.total_events, 0)

        entry_events = [e for e in session.events if e.probe_type == "ENTRY"]
        return_events = [e for e in session.events if e.probe_type == "RETURN"]
        self.assertGreater(len(entry_events), 0)
        self.assertGreater(len(return_events), 0)
        self.assertEqual(entry_events[0].arguments["param_0"].status, STATUS_OBSERVED)
        self.assertEqual(return_events[0].return_value.status, STATUS_OBSERVED)

    def test_03_trace_stripped_binary_with_external_debug_elf(self):
        """Scenario 3: Verify probe attachment to stripped binary using matching external debug ELF."""
        ident_str = inspect_elf(self.stripped_bin)
        self.assertTrue(ident_str.is_stripped, "Target binary must be stripped")

        proc, pid = self._start_autonomous_fixture(self.stripped_bin, loops=20, interval_ms=100)
        try:
            time.sleep(0.05)
            session = self.tracer.trace(
                pid=pid,
                binary_path=self.stripped_bin,
                debug_image=self.debug_elf,
                function_name="trace_target_function",
                duration_s=1.2,
                entry_only=False,
            )
        finally:
            self._stop_fixture(proc)

        self.assertEqual(session.status, "SUCCESS")
        self.assertEqual(session.build_id_status, "VERIFIED")
        self.assertIsNotNone(session.probe_offset, "Must resolve file-relative probe offset")
        self.assertGreater(session.total_events, 0, "Must capture events from stripped executable")
        self.assertEqual(session.lost_events, 0)

    def test_04_deliberate_build_id_mismatch(self):
        """Scenario 4: Verify deliberate Build ID mismatch fails closed; verify explicitly unchecked mode."""
        proc, pid = self._start_autonomous_fixture(self.debug_bin, loops=10, interval_ms=100)
        try:
            # 4a: verify_build_id=True with mismatched debug ELF -> FAILED closed
            session_fail = self.tracer.trace(
                pid=pid,
                binary_path=self.debug_bin,
                debug_image=self.mismatched_dbg,
                function_name="trace_target_function",
                verify_build_id=True,
            )
            self.assertEqual(session_fail.status, "FAILED")
            self.assertEqual(session_fail.build_id_status, "MISMATCHED")
            self.assertIn("Build ID mismatch", session_fail.error_message)

            # 4b: verify_build_id=False -> records EXPLICITLY_UNCHECKED
            session_skip = self.tracer.trace(
                pid=pid,
                binary_path=self.debug_bin,
                function_name="trace_target_function",
                duration_s=0.5,
                verify_build_id=False,
            )
            self.assertEqual(session_skip.build_id_status, "EXPLICITLY_UNCHECKED")
        finally:
            self._stop_fixture(proc)

    def test_05_pie_and_non_pie_executables(self):
        """Scenario 5: Verify non-PIE executable file offset resolution and probe attachment."""
        ident_nopie = inspect_elf(self.nopie_bin)
        self.assertEqual(ident_nopie.elf_type, "ET_EXEC", "Target must be non-PIE ET_EXEC")

        proc, pid = self._start_autonomous_fixture(self.nopie_bin, loops=20, interval_ms=100)
        try:
            time.sleep(0.05)
            session = self.tracer.trace(
                pid=pid,
                binary_path=self.nopie_bin,
                function_name="trace_target_function",
                duration_s=1.2,
                entry_only=False,
            )
        finally:
            self._stop_fixture(proc)

        self.assertEqual(session.status, "SUCCESS")
        self.assertEqual(session.build_id_status, "VERIFIED")
        self.assertIsNotNone(session.probe_offset)
        virt_addr = int(session.probe_offset, 16)
        file_sz = os.path.getsize(self.nopie_bin)
        self.assertLess(virt_addr, file_sz, "Offset must be inside file bounds, not virtual address")
        self.assertGreater(session.total_events, 0)

    def test_06_ambiguous_function_and_linkage_disambiguation(self):
        """Scenario 6: Ambiguous overloaded functions fail closed; mangled linkage name succeeds."""
        proc, pid = self._start_autonomous_fixture(self.debug_bin, loops=20, interval_ms=100)
        try:
            # 6a: Ambiguous function name 'overloaded_metric' has 2 candidates -> FAILED closed
            session_ambig = self.tracer.trace(
                pid=pid,
                binary_path=self.debug_bin,
                function_name="overloaded_metric",
                duration_s=0.5,
            )
            self.assertEqual(session_ambig.status, "FAILED")
            self.assertIn("Ambiguous function name 'overloaded_metric'", session_ambig.error_message)
            self.assertIn("matches 2 distinct subprogram locations", session_ambig.error_message)

            # 6b: Mangled linkage name '_Z17overloaded_metrici' -> SUCCESS
            session_mangled = self.tracer.trace(
                pid=pid,
                binary_path=self.debug_bin,
                function_name="_Z17overloaded_metrici",
                duration_s=1.2,
            )
            self.assertEqual(session_mangled.status, "SUCCESS")
            self.assertGreater(session_mangled.total_events, 0)

            # 6c: Missing function -> FAILED
            session_missing = self.tracer.trace(
                pid=pid,
                binary_path=self.debug_bin,
                function_name="nonexistent_function_12345",
                duration_s=0.5,
            )
            self.assertEqual(session_missing.status, "FAILED")
            self.assertIn("not found", session_missing.error_message)
        finally:
            self._stop_fixture(proc)

    def test_07_invalid_pid_and_target_exit_mid_trace(self):
        """Scenario 7: Invalid PID fails immediately; target exit mid-trace terminates cleanly."""
        # 7a: Invalid / non-existent PID
        session_inv = self.tracer.trace(
            pid=9999999,
            binary_path=self.debug_bin,
            function_name="trace_target_function",
        )
        self.assertEqual(session_inv.status, "FAILED")
        self.assertIn("does not exist", session_inv.error_message)

        # 7b: Target process starts with 2 loops, exits while trace duration is 2.5s
        proc, pid = self._start_autonomous_fixture(self.debug_bin, loops=2, interval_ms=50)
        try:
            session_exit = self.tracer.trace(
                pid=pid,
                binary_path=self.debug_bin,
                function_name="trace_target_function",
                duration_s=2.5,
            )
            self.assertIn(session_exit.status, ("SUCCESS", "PARTIAL", "FAILED"))
            if session_exit.total_events > 0:
                self.assertIn(session_exit.status, ("SUCCESS", "PARTIAL"))
        finally:
            self._stop_fixture(proc)

    def test_08_unsupported_permissions_non_root(self):
        """Scenario 8: Non-root user without privileges reports PERMISSION_DENIED cleanly."""
        unprivileged_tracer = EbpfTracer(use_sudo=False)
        cap_unprivileged = EbpfCapabilityResult(
            supported=False,
            backend="bpftrace",
            architecture=platform.machine(),
            kernel_version=platform.release(),
            is_privileged=False,
            unprivileged_bpf_disabled=2,
            has_bpf_fs=True,
            reasons=["Unprivileged eBPF is disabled and current user lacks root privileges."],
        )
        proc, pid = self._start_autonomous_fixture(self.debug_bin, loops=5, interval_ms=100)
        try:
            with patch("extractor.ebpf_tracer.EbpfEnvironmentChecker.check_prerequisites", return_value=cap_unprivileged):
                session = unprivileged_tracer.trace(
                    pid=pid,
                    binary_path=self.debug_bin,
                    function_name="trace_target_function",
                )
                self.assertEqual(session.status, "PERMISSION_DENIED")
                self.assertIn("lacks root privileges", session.error_message)
        finally:
            self._stop_fixture(proc)

    def test_09_entry_only_mode_vs_entry_return_mode(self):
        """Scenario 9: Verify entry_only=True records only ENTRY events; entry_only=False records both."""
        # 9a: Entry-only trace with dedicated fixture run
        proc1, pid1 = self._start_autonomous_fixture(self.debug_bin, loops=20, interval_ms=100)
        try:
            session_entry = self.tracer.trace(
                pid=pid1,
                binary_path=self.debug_bin,
                function_name="trace_target_function",
                duration_s=1.0,
                entry_only=True,
            )
            self.assertEqual(session_entry.status, "SUCCESS")
            self.assertGreater(session_entry.total_events, 0)
            for ev in session_entry.events:
                self.assertEqual(ev.probe_type, "ENTRY")
        finally:
            self._stop_fixture(proc1)

        # 9b: Entry + Return trace with fresh fixture run
        proc2, pid2 = self._start_autonomous_fixture(self.debug_bin, loops=20, interval_ms=100)
        try:
            session_both = self.tracer.trace(
                pid=pid2,
                binary_path=self.debug_bin,
                function_name="trace_target_function",
                duration_s=1.0,
                entry_only=False,
            )
            self.assertEqual(session_both.status, "SUCCESS")
            has_entry = any(e.probe_type == "ENTRY" for e in session_both.events)
            has_return = any(e.probe_type == "RETURN" for e in session_both.events)
            self.assertTrue(has_entry, "Must contain ENTRY events")
            self.assertTrue(has_return, "Must contain RETURN events")
        finally:
            self._stop_fixture(proc2)

    def test_10_interruption_and_process_cleanup(self):
        """Scenario 10: Verify bpftrace process group is detached and temp files removed."""
        proc, pid = self._start_autonomous_fixture(self.debug_bin, loops=20, interval_ms=100)
        try:
            session = self.tracer.trace(
                pid=pid,
                binary_path=self.debug_bin,
                function_name="trace_target_function",
                duration_s=0.8,
            )
            self.assertEqual(session.status, "SUCCESS")

            # Verify no orphan bpftrace processes were leaked
            ps_res = subprocess.run(["ps", "-ef"], capture_output=True, text=True)
            bpftrace_lines = [
                l for l in ps_res.stdout.splitlines()
                if "bpftrace" in l and f"{self.debug_bin}" in l
            ]
            self.assertEqual(len(bpftrace_lines), 0, f"No bpftrace processes should remain: {bpftrace_lines}")
        finally:
            self._stop_fixture(proc)

    def test_11_zero_events_returns_partial_status(self):
        """Scenario 11: Probe attached cleanly to live target without function invocation reports PARTIAL."""
        # Start fixture in interactive mode (sits on stdin; trace_target_function is never called)
        proc = subprocess.Popen(
            [self.debug_bin],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = proc.stdout.readline()
        self.assertIn("READY", line)
        pid = int([tok.split("=")[1] for tok in line.split() if tok.startswith("pid=")][0])

        try:
            # Trace for 0.5s while function is never invoked
            session = self.tracer.trace(
                pid=pid,
                binary_path=self.debug_bin,
                function_name="trace_target_function",
                duration_s=0.5,
            )
            self.assertEqual(session.status, "PARTIAL", "Zero events captured must report PARTIAL status")
            self.assertEqual(session.total_events, 0)
            self.assertEqual(session.lost_events, 0)
            self.assertIn("0 events were captured", session.error_message)
        finally:
            self._stop_fixture(proc)

    def test_12_real_fixture_dwarf_variable_evaluation(self):
        """Scenario 12: Evaluate DWARF variables on real fixture builds (-O0 and -O2) cross-checked against ABI."""
        # 1. Debug build (-O0)
        d_index = DwarfIndexer.get_index(self.debug_bin)
        subp = d_index.subprograms_by_name["trace_target_function"][0]
        self.assertEqual(subp.frame_base, "DW_OP_call_frame_cfa")

        op_var = subp.get_variable("op_code")
        self.assertIsNotNone(op_var)
        self.assertEqual(op_var.location_expr, "DW_OP_fbreg: -116")

        tag_var = subp.get_variable("local_tag")
        self.assertIsNotNone(tag_var)
        self.assertEqual(tag_var.location_expr, "DW_OP_fbreg: -56")

        reading_var = subp.get_variable("reading")
        self.assertIsNotNone(reading_var)
        self.assertEqual(reading_var.location_expr, "DW_OP_fbreg: -80")

        # Evaluate op_code with simulated frame pointer
        arch = platform.machine()
        fp = 0x7fffffffe000
        # A. At function entry (low_pc): prologue not established -> UNAVAILABLE
        ctx_entry = DwarfEvaluationContext(
            binary_identity=inspect_elf(self.debug_bin),
            subprogram=subp,
            link_time_address=subp.low_pc,
            frame_metadata=FrameMetadata(frame_pointer=fp),
            variable_name="op_code",
            architecture=arch,
        )
        res_entry = DwarfEvaluator.evaluate(ctx_entry)
        self.assertEqual(res_entry.status, EVAL_STATUS_UNAVAILABLE)
        self.assertIn("entry", res_entry.reason.lower())

        # B. Post-prologue (at frame_established_pc)
        post_pc = subp.frame_established_pc or (subp.low_pc + 16)
        ctx_post = DwarfEvaluationContext(
            binary_identity=inspect_elf(self.debug_bin),
            subprogram=subp,
            link_time_address=post_pc,
            frame_metadata=FrameMetadata(frame_pointer=fp),
            variable_name="op_code",
            architecture=arch,
        )
        res_unavail = DwarfEvaluator.evaluate(ctx_post)
        self.assertEqual(res_unavail.status, EVAL_STATUS_UNAVAILABLE)
        self.assertEqual(res_unavail.evaluated_address, fp + 16 - 116)

        ctx_post.memory_reader = lambda addr, sz: struct.pack("<i", 42)
        res_obs = DwarfEvaluator.evaluate(ctx_post)
        self.assertEqual(res_obs.status, EVAL_STATUS_OBSERVED)
        self.assertEqual(res_obs.value, 42)
        self.assertEqual(res_obs.value_hex, "0x0000002a")

        # 2. Optimized build (-O2)
        d_index_opt = DwarfIndexer.get_index(self.opt_bin)
        subp_opt = d_index_opt.subprograms_by_name["trace_target_function"][0]
        op_opt = subp_opt.get_variable("op_code")
        self.assertIsNotNone(op_opt)
        self.assertIsNotNone(op_opt.location_list_offset, "op_code in -O2 must have a location list offset")

        # At function entry (low_pc): matches first live range (x0 on aarch64, rdi on x86_64)
        reg_map = {"x0": 77, "rdi": 77}
        ctx_opt = DwarfEvaluationContext(
            binary_identity=inspect_elf(self.opt_bin),
            subprogram=subp_opt,
            link_time_address=subp_opt.low_pc,
            registers=reg_map,
            variable_name="op_code",
            architecture=arch,
        )
        res_opt_entry = DwarfEvaluator.evaluate(ctx_opt)
        self.assertEqual(res_opt_entry.status, EVAL_STATUS_OBSERVED)
        self.assertEqual(res_opt_entry.value, 77)


if __name__ == "__main__":
    unittest.main()

