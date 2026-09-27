#!/usr/bin/env python3
"""Unit tests for ObservationBackend and module-aware memory reader (Phase 5.2)."""

import os
import shutil
import tempfile
import unittest
from typing import Dict, Any

from extractor.memory_capture import MemoryCapture
from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
from extractor.modules import RuntimeModule
from extractor.observation_backends import (
    GDBObservationBackend,
    LowImpactObservationBackend,
)
from extractor.offline_analyzer import SnapshotMemoryReader


class TestObservationBackends(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="ds_test_obs_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_gdb_backend_capabilities(self):
        backend = GDBObservationBackend(controller=None)
        self.assertEqual(backend.mode, "CONSISTENT")
        caps = backend.capabilities()
        self.assertTrue(caps["process_stop"])
        self.assertTrue(caps["ptrace"])
        self.assertTrue(caps["typed_mutation"])
        self.assertTrue(caps["checkpoint_restore"])
        self.assertEqual(caps["consistency"], "STOPPED")

    def test_low_impact_backend_safety_contract(self):
        backend = LowImpactObservationBackend()
        self.assertEqual(backend.mode, "LOW_IMPACT")
        caps = backend.capabilities()
        self.assertFalse(caps["process_stop"])
        self.assertFalse(caps["ptrace"])
        self.assertFalse(caps["sigstop"])
        self.assertFalse(caps["sigcont"])
        self.assertFalse(caps["gdb_attached"])
        self.assertFalse(caps["typed_mutation"])
        self.assertFalse(caps["checkpoint_restore"])
        self.assertFalse(caps["execution_context"])
        self.assertEqual(caps["consistency"], "NON_ATOMIC")
        self.assertTrue(caps["module_discovery"])
        self.assertTrue(caps["build_id_verification"])

    def test_snapshot_memory_reader_module_methods(self):
        # Create dummy region file
        mem_dir = os.path.join(self.tmp_dir, "memory")
        os.makedirs(mem_dir, exist_ok=True)
        r_file = os.path.join(mem_dir, "region_main.bin")
        with open(r_file, "wb") as f:
            f.write(b"MAIN_MODULE_DATA")

        cap_reg = CapturedRegion(
            region_id="R000001",
            start=0x555555554000,
            end=0x555555558000,
            size=0x4000,
            permissions="r-xp",
            category="code",
            pathname="/app/bin",
            requested=0x4000,
            captured=16,
            status="COMPLETE",
            filename="memory/region_main.bin",
        )

        mod = RuntimeModule(
            module_id="main",
            path="/app/bin",
            runtime_base=0x555555554000,
            runtime_end=0x555555558000,
            load_bias=0x555555554000,
            build_id=None,
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            is_main_executable=True,
        )

        raw_snap = RawMemorySnapshot(
            snapshot_id="SNAP_TEST_MODULES",
            pid=12345,
            binary="/app/bin",
            timestamp_ns=1000,
            output_dir=self.tmp_dir,
            regions=[cap_reg],
            maps=[{"start_addr": 0x555555554000, "end_addr": 0x555555558000, "pathname": "/app/bin"}],
            modules=[mod.to_dict()],
        )

        reader = SnapshotMemoryReader(raw_snap)

        # 1. module_for_address
        resolved_mod = reader.module_for_address(0x555555555000)
        self.assertIsNotNone(resolved_mod)
        self.assertEqual(resolved_mod.module_id, "main")
        self.assertIsNone(reader.module_for_address(0x1000))

        # 2. runtime_to_elf
        trans = reader.runtime_to_elf(0x555555555234)
        self.assertIsNotNone(trans)
        m, elf_addr = trans
        self.assertEqual(m.module_id, "main")
        self.assertEqual(elf_addr, 0x1234)

        # 3. elf_to_runtime
        runtime_addr = reader.elf_to_runtime(mod, 0x1234)
        self.assertEqual(runtime_addr, 0x555555555234)

        # 4. region_for_address
        reg = reader.region_for_address(0x555555554004)
        self.assertIsNotNone(reg)
        self.assertEqual(reg.region_id, "R000001")
        self.assertIsNone(reader.region_for_address(0x1000))

    def test_process_exit_handling(self):
        # 1. Test mid-capture exit (ESRCH simulated during region read)
        capturer = MemoryCapture()
        # Mock fn_vm_readv to return -1 with errno 3 (ESRCH)
        def mock_readv(pid, l_iov, liovcnt, r_iov, riovcnt, flags):
            import ctypes
            ctypes.set_errno(3)  # ESRCH
            return -1

        # Use current running process for initial /proc/<pid> validation
        import os
        import unittest.mock as mock

        with mock.patch.object(capturer._libc, "process_vm_readv", side_effect=mock_readv):
            snap = capturer.capture(pid=os.getpid(), output_dir=self.tmp_dir, max_bytes=4096)
            self.assertEqual(snap.status, "PROCESS_EXITED")
            self.assertEqual(snap.regions_captured, 0)
            self.assertTrue(len(snap.regions) > 0)
            self.assertEqual(snap.regions[0].status, "FAILED")
            self.assertEqual(snap.regions[0].error, "ESRCH_PROCESS_EXITED")

        # 2. Test AgentRuntime error code on non-existent process
        from extractor.agent_runtime import AgentRuntime
        runtime = AgentRuntime()
        res = runtime.capture_memory_snapshot(pid=9999999)
        self.assertFalse(res.success)
        self.assertEqual(res.error.get("code"), "PROCESS_EXITED")


if __name__ == "__main__":
    unittest.main()
