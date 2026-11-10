#!/usr/bin/env python3
"""Phase 2.4.1 — Remote Identity Fail-Closed & Multi-Architecture Negative Tests.

Validates:
1. Remote SSH Target Identity Fail-Closed Security:
   - Empty or unreadable boot_id fails closed on pin_target_identity.
   - Strict distinction between PID_REUSED and IDENTITY_UNAVAILABLE on memory reads.
   - Robust /proc/<pid>/stat parsing with nested parentheses in comm.
   - Remote reboot detection (boot_id change) triggers PID_REUSED.
   - SSH timeout / network drop handling without unhandled exceptions.
2. Multi-Architecture Negatives & Boundary Cases:
   - Corrupted ELF magic / malformed ELF headers (ELFInspectionError).
   - Mismatched GNU Build ID between target and companion ELF.
   - .gnu_debuglink CRC-32 checksum mismatch rejection.
   - Missing separate debug info files safely handled.
   - Strict architectural distinction between native ARM64 execution and cross-compiled ELF analysis.
"""

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib
from typing import Any, Dict, List, Optional, Tuple

from extractor.target_adapter import (
    LocalTargetAdapter,
    PIDReusedError,
    RemoteSshTargetAdapter,
)
from extractor.debug_artifacts import DebugArtifactProvider, compute_gnu_debuglink_crc
from extractor.debug_image import ELFInspectionError, inspect_elf
from extractor.modules import RuntimeModule


class MockRemoteAdapter(RemoteSshTargetAdapter):
    """RemoteSshTargetAdapter test harness with mockable SSH command responses."""

    def __init__(self, host: str = "mock-remote-host"):
        super().__init__(host=host, user="root", port=22)
        self.cmd_responses: Dict[str, Tuple[int, str, str]] = {}
        self.cmd_log: List[str] = []

    def set_cmd_response(self, cmd_prefix: str, rc: int, stdout: str, stderr: str = ""):
        self.cmd_responses[cmd_prefix] = (rc, stdout, stderr)

    def run_ssh(self, cmd: str, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        self.cmd_log.append(cmd)
        for prefix, resp in self.cmd_responses.items():
            if prefix in cmd:
                return resp
        return 0, "", ""


class TestPhase241RemoteIdentityAndArchNegatives(unittest.TestCase):
    """Phase 2.4.1 Remote Identity Fail-Closed & Multi-Architecture Negative Test Suite."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="ds_phase2_4_1_neg_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. Remote Target Identity Fail-Closed Tests
    # -------------------------------------------------------------------------

    def test_01_empty_boot_id_fails_closed_on_pin(self):
        """When remote host returns empty boot_id, pin_target_identity fails closed."""
        adapter = MockRemoteAdapter()
        adapter.set_cmd_response("kill -0 1234", 0, "")
        stat_line = "1234 (testapp) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 54321 1000 200"
        adapter.set_cmd_response("cat /proc/1234/stat", 0, stat_line)
        adapter.set_cmd_response("readlink -f /proc/1234/exe", 0, "/usr/bin/testapp\n")
        # Empty boot_id
        adapter.set_cmd_response("cat /proc/sys/kernel/random/boot_id", 0, "\n")

        ident = adapter.get_process_identity(1234)
        self.assertEqual(ident["boot_id"], "")

        # Pinned identity must fail closed with PIDReusedError
        with self.assertRaises(PIDReusedError) as ctx:
            adapter.pin_target_identity(1234)
        self.assertIn("boot_id", str(ctx.exception))

    def test_02_unreadable_boot_id_fails_closed_on_pin(self):
        """When /proc/sys/kernel/random/boot_id is unreadable (rc!=0), boot_id is empty and pin fails."""
        adapter = MockRemoteAdapter()
        adapter.set_cmd_response("kill -0 1234", 0, "")
        stat_line = "1234 (testapp) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 54321 1000 200"
        adapter.set_cmd_response("cat /proc/1234/stat", 0, stat_line)
        adapter.set_cmd_response("readlink -f /proc/1234/exe", 0, "/usr/bin/testapp\n")
        # Command fails (e.g. Permission Denied)
        adapter.set_cmd_response("cat /proc/sys/kernel/random/boot_id", 1, "", "Permission denied")

        ident = adapter.get_process_identity(1234)
        self.assertEqual(ident["boot_id"], "")

        with self.assertRaises(PIDReusedError) as ctx:
            adapter.pin_target_identity(1234)
        self.assertIn("boot_id", str(ctx.exception))

    def test_03_distinguish_pid_reused_from_identity_unavailable_on_read(self):
        """Memory read returns PID_REUSED when identity changed, IDENTITY_UNAVAILABLE when missing."""
        adapter = MockRemoteAdapter()
        # Initial healthy pinned identity
        adapter._pinned_identities[500] = {
            "pid": 500,
            "start_time": "12345",
            "boot_id": "initial-boot-uuid",
            "executable": "/usr/bin/daemon",
        }

        # Case A: Process terminated or unreadable (stat returns empty) -> IDENTITY_UNAVAILABLE
        adapter.set_cmd_response("cat /proc/500/stat", 1, "", "No such process")
        adapter.set_cmd_response("cat /proc/sys/kernel/random/boot_id", 0, "initial-boot-uuid\n")
        adapter.set_cmd_response("readlink -f /proc/500/exe", 1, "", "No such process")

        ok_pin, pin_err = adapter.verify_pinned_identity(500)
        self.assertFalse(ok_pin)
        self.assertIn("IDENTITY_UNAVAILABLE", pin_err)

        data, status, err = adapter.read_memory(500, 0x1000, 16)
        self.assertIsNone(data)
        self.assertEqual(status, "IDENTITY_UNAVAILABLE")

        batch_res = adapter.read_memory_batch(500, [(0x1000, 16)])
        self.assertEqual(batch_res[0][1], "IDENTITY_UNAVAILABLE")

        # Case B: PID reused by another process (different start_time) -> PID_REUSED
        stat_reused = "500 (newdaemon) S 1 500 500 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 99999 1000 200"
        adapter.set_cmd_response("cat /proc/500/stat", 0, stat_reused)
        adapter.set_cmd_response("readlink -f /proc/500/exe", 0, "/usr/bin/daemon\n")
        adapter.set_cmd_response("cat /proc/sys/kernel/random/boot_id", 0, "initial-boot-uuid\n")

        ok_pin2, pin_err2 = adapter.verify_pinned_identity(500)
        self.assertFalse(ok_pin2)
        self.assertIn("PID_REUSED", pin_err2)

        data2, status2, err2 = adapter.read_memory(500, 0x1000, 16)
        self.assertIsNone(data2)
        self.assertEqual(status2, "PID_REUSED")

        batch_res2 = adapter.read_memory_batch(500, [(0x1000, 16)])
        self.assertEqual(batch_res2[0][1], "PID_REUSED")

    def test_04_remote_reboot_triggers_pid_reused(self):
        """When remote host reboots, boot_id changes, triggering PID_REUSED."""
        adapter = MockRemoteAdapter()
        adapter._pinned_identities[600] = {
            "pid": 600,
            "start_time": "12345",
            "boot_id": "pre-reboot-uuid-1111",
            "executable": "/usr/bin/daemon",
        }

        # Target PID exists post-reboot with same start_time, but boot_id changed
        stat_post = "600 (daemon) S 1 600 600 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 12345 1000 200"
        adapter.set_cmd_response("cat /proc/600/stat", 0, stat_post)
        adapter.set_cmd_response("readlink -f /proc/600/exe", 0, "/usr/bin/daemon\n")
        adapter.set_cmd_response("cat /proc/sys/kernel/random/boot_id", 0, "post-reboot-uuid-2222\n")

        ok_pin, pin_err = adapter.verify_pinned_identity(600)
        self.assertFalse(ok_pin)
        self.assertIn("PID_REUSED", pin_err)
        self.assertIn("boot_id", pin_err)

        data, status, _ = adapter.read_memory(600, 0x2000, 32)
        self.assertEqual(status, "PID_REUSED")

    def test_05_proc_stat_nested_parentheses_robust_parsing(self):
        """Processes with nested parentheses in comm name are parsed accurately for start_time."""
        adapter = MockRemoteAdapter()
        # Process name containing multiple nested parentheses
        nested_comm_stat = (
            "700 (worker (nested) [core] (v2)) S 1 700 700 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 778899 1000 200"
        )
        adapter.set_cmd_response("cat /proc/700/stat", 0, nested_comm_stat)
        adapter.set_cmd_response("cat /proc/sys/kernel/random/boot_id", 0, "test-boot-uuid\n")
        adapter.set_cmd_response("readlink -f /proc/700/exe", 0, "/usr/bin/worker\n")

        ident = adapter.get_process_identity(700)
        self.assertEqual(ident["start_time"], "778899")
        self.assertEqual(ident["boot_id"], "test-boot-uuid")

        # Pinned identity verification succeeds
        adapter.pin_target_identity(700)
        ok_pin, _ = adapter.verify_pinned_identity(700)
        self.assertTrue(ok_pin)

    def test_06_ssh_timeout_and_network_interruption_fails_safely(self):
        """SSH network drops or command timeouts return UNAVAILABLE without unhandled exceptions."""
        adapter = MockRemoteAdapter()
        adapter._pinned_identities[800] = {
            "pid": 800,
            "start_time": "12345",
            "boot_id": "test-boot-uuid",
            "executable": "/usr/bin/worker",
        }
        # Process is alive and identity matches pinned identity
        adapter.set_cmd_response("cat /proc/800/stat", 0, "800 (worker) S 1 800 800 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 12345 1000 200")
        adapter.set_cmd_response("cat /proc/sys/kernel/random/boot_id", 0, "test-boot-uuid\n")
        adapter.set_cmd_response("readlink -f /proc/800/exe", 0, "/usr/bin/worker\n")
        # Simulate network drop during memory read
        adapter.set_cmd_response("dd if=/proc/800/mem", -1, "", "ssh: connect to host mock-remote-host port 22: Connection timed out")

        data, status, err = adapter.read_memory(800, 0x4000, 64)
        self.assertIsNone(data)
        self.assertEqual(status, "UNAVAILABLE")
        self.assertIn("Connection timed out", err)

    # -------------------------------------------------------------------------
    # 2. Multi-Architecture Negatives & Split DWARF Boundary Cases
    # -------------------------------------------------------------------------

    def test_07_corrupted_elf_header_rejected_safely(self):
        """Corrupted ELF header with bad magic bytes raises ELFInspectionError."""
        corrupted_elf = os.path.join(self.tmp_dir, "corrupted.elf")
        with open(corrupted_elf, "wb") as f:
            f.write(b"\x7fBAD\x02\x01\x01\x00" + b"\x00" * 56)

        with self.assertRaises(ELFInspectionError) as ctx:
            inspect_elf(corrupted_elf)
        self.assertIn("Invalid ELF magic", str(ctx.exception))

    def test_08_gnu_debuglink_crc_mismatch_detected(self):
        """Mismatched CRC32 checksum in .gnu_debuglink causes DWARF resolution failure."""
        main_binary = os.path.join(self.tmp_dir, "main_app")
        debug_binary = os.path.join(self.tmp_dir, "main_app.debug")

        with open(debug_binary, "wb") as f:
            f.write(b"REAL_DEBUG_CONTENT_FOR_CRC_TEST_1234567890")

        wrong_crc = 0xDEADBEEF
        actual_crc = compute_gnu_debuglink_crc(debug_binary)
        self.assertNotEqual(wrong_crc, actual_crc)

        provider = DebugArtifactProvider(search_paths=[self.tmp_dir])

        # A. Module with mismatched CRC -> Rejected (returns None)
        mod_mismatched = RuntimeModule(
            module_id="main",
            path=main_binary,
            runtime_base=0x400000,
            runtime_end=0x401000,
            load_bias=0,
            build_id=None,
            debuglink={"filename": "main_app.debug", "crc": wrong_crc},
        )
        resolved_bad = provider.find_debug_artifact(mod_mismatched)
        self.assertIsNone(resolved_bad)

        # B. Module with matching CRC -> Accepted
        mod_valid = RuntimeModule(
            module_id="main",
            path=main_binary,
            runtime_base=0x400000,
            runtime_end=0x401000,
            load_bias=0,
            build_id=None,
            debuglink={"filename": "main_app.debug", "crc": actual_crc},
        )
        resolved_good = provider.find_debug_artifact(mod_valid)
        self.assertIsNotNone(resolved_good)
        self.assertEqual(os.path.abspath(resolved_good), os.path.abspath(debug_binary))

    def test_09_build_id_mismatch_fails_pinning(self):
        """Build ID mismatch between running process and companion ELF raises ValueError."""
        adapter = LocalTargetAdapter()
        adapter.get_process_identity = lambda p: {
            "pid": p,
            "start_time": "1234",
            "boot_id": "test_boot",
            "executable": "/usr/bin/target",
            "build_id": "target_build_id_aaaaaaaa",
        }
        # Companion ELF specifies different build ID
        with self.assertRaises(ValueError) as ctx:
            adapter.pin_target_identity(999, companion_build_id="companion_build_id_bbbbbbbb")
        self.assertIn("Build ID mismatch", str(ctx.exception))

    def test_10_missing_debuglink_artifact_handled_gracefully(self):
        """When companion debuglink points to missing file, provider returns None without crashing."""
        provider = DebugArtifactProvider(search_paths=[self.tmp_dir])
        mod_missing = RuntimeModule(
            module_id="missing",
            path=os.path.join(self.tmp_dir, "missing_main"),
            runtime_base=0x400000,
            runtime_end=0x401000,
            load_bias=0,
            build_id=None,
            debuglink={"filename": "non_existent_debug_file.debug", "crc": 0x12345678},
        )
        resolved = provider.find_debug_artifact(mod_missing)
        self.assertIsNone(resolved)

    def test_11_cross_compiled_elf_architecture_classification(self):
        """Cross-compiled x86_64 and ARM32 ELFs are recognized by inspect_elf without host execution."""
        x86_cc = shutil.which("x86_64-linux-gnu-gcc") or shutil.which("x86_64-linux-gnu-gcc-13")
        arm_cc = shutil.which("arm-linux-gnueabihf-gcc") or shutil.which("arm-linux-gnueabihf-gcc-13")

        if x86_cc:
            src = os.path.join(self.tmp_dir, "test_x86.c")
            out = os.path.join(self.tmp_dir, "test_x86.elf")
            with open(src, "w") as f:
                f.write("int main(void) { return 0; }\n")
            res = subprocess.run([x86_cc, "-no-pie", "-o", out, src], capture_output=True)
            if res.returncode == 0:
                ident_x86 = inspect_elf(out)
                self.assertEqual(ident_x86.architecture, "x86_64")
                self.assertEqual(ident_x86.elf_class, "ELF64")

        if arm_cc:
            src32 = os.path.join(self.tmp_dir, "test_arm.c")
            out32 = os.path.join(self.tmp_dir, "test_arm.elf")
            with open(src32, "w") as f:
                f.write("int main(void) { return 0; }\n")
            res = subprocess.run([arm_cc, "-no-pie", "-o", out32, src32], capture_output=True)
            if res.returncode == 0:
                ident_arm = inspect_elf(out32)
                self.assertEqual(ident_arm.architecture, "arm")
                self.assertEqual(ident_arm.elf_class, "ELF32")


if __name__ == "__main__":
    unittest.main()
