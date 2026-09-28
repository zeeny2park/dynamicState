#!/usr/bin/env python3
"""Regression and audit verification tests for Phase 5.2 hardening."""

import json
import os
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from extractor.agent_runtime import AgentRuntime
from extractor.debug_artifacts import DebugArtifactProvider
from extractor.debug_image import DebugImageProvider
from extractor.debug_info import GdbDebugInfoProvider
from extractor.memory_capture import MemoryCapture
from extractor.memory_maps import MemoryMapProvider
from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
from extractor.modules import LoadBiasResolutionError, ModuleAddressResolver, RuntimeModule, discover_modules
from extractor.offline_analyzer import OfflineMemoryAnalyzer, SnapshotMemoryReader


class Phase52AuditHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="ds_audit_test_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_audit_001_unresolved_load_bias_raises_error(self):
        """AUDIT-001: Ensure no silent fallback occurs when load bias is UNRESOLVED."""
        mod = RuntimeModule(
            module_id="mod_test",
            path="/nonexistent/libfoo.so",
            runtime_base=0x7fff0000,
            runtime_end=0x7fff1000,
            load_bias=None,
            build_id=None,
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            is_main_executable=False,
            load_bias_status="UNRESOLVED",
        )
        self.assertEqual(mod.load_bias_status, "UNRESOLVED")
        self.assertIsNone(mod.load_bias)
        self.assertFalse(mod.contains_elf_address(0x100))

        # Resolving addresses must explicitly raise LoadBiasResolutionError
        with self.assertRaises(LoadBiasResolutionError):
            ModuleAddressResolver.resolve_runtime_address(mod, 0x100)

        with self.assertRaises(LoadBiasResolutionError):
            ModuleAddressResolver.resolve_elf_address(mod, 0x7fff0100)

        # Serialized dict must carry load_bias_status and None load_bias
        d = mod.to_dict()
        self.assertIsNone(d["load_bias"])
        self.assertEqual(d["load_bias_status"], "UNRESOLVED")

        # Roundtrip through from_dict
        restored = RuntimeModule.from_dict(d)
        self.assertEqual(restored.load_bias_status, "UNRESOLVED")
        self.assertIsNone(restored.load_bias)

    def test_audit_002_process_identity_verification_and_pid_recycling(self):
        """AUDIT-002: Verify process identity checks guard against PID reuse race."""
        capturer = MemoryCapture()

        # Check get_process_identity on current running process
        ident = capturer.get_process_identity(os.getpid())
        self.assertIsNotNone(ident)
        self.assertEqual(ident[0], os.getpid())
        self.assertIsInstance(ident[1], int)  # starttime
        self.assertIsInstance(ident[2], int)  # inode

        # Simulate PID recycling: identity changes after maps inspection
        original_ident = (os.getpid(), 100, 200)
        recycled_ident = (os.getpid(), 500, 600)  # different starttime/inode

        ident_calls = [original_ident, recycled_ident, recycled_ident]
        with mock.patch.object(capturer, "get_process_identity", side_effect=lambda pid: ident_calls.pop(0) if ident_calls else recycled_ident):
            snap = capturer.capture(pid=os.getpid(), output_dir=self.tmp_dir, max_bytes=4096)
            self.assertEqual(snap.status, "PROCESS_EXITED")

    def test_audit_003_gdb_batch_invocation_path_with_spaces(self):
        """AUDIT-003: Verify GDB offline provider executes correctly even if path contains spaces."""
        # Create a directory path containing spaces
        spaced_dir = os.path.join(self.tmp_dir, "path with spaces")
        os.makedirs(spaced_dir, exist_ok=True)
        spaced_bin = os.path.join(spaced_dir, "test_binary")

        # Copy /bin/ls to spaced_bin
        shutil.copy2("/bin/ls", spaced_bin)

        # Initialize GdbDebugInfoProvider on the spaced binary path
        provider = GdbDebugInfoProvider(spaced_bin)
        # Should not throw any argument splitting or file-not-found error
        symbols = provider.get_symbols()
        self.assertIsInstance(symbols, list)

    def test_audit_004_partial_memory_read_vs_struct_size(self):
        """AUDIT-004: Struct whose declared size extends beyond captured memory is marked PARTIAL."""
        analyzer = OfflineMemoryAnalyzer()

        mem_dir = os.path.join(self.tmp_dir, "memory")
        os.makedirs(mem_dir, exist_ok=True)

        # Region with 16 bytes captured
        with open(os.path.join(mem_dir, "reg1.bin"), "wb") as f:
            f.write(struct.pack("<II", 10, 20) + b"\x00" * 8)

        cap_reg = CapturedRegion(
            region_id="R000001",
            start=0x1000,
            end=0x1010,
            size=0x10,
            permissions="rw-p",
            category="global",
            pathname="/tmp/app",
            requested=0x10,
            captured=0x10,
            status="COMPLETE",
            filename="memory/reg1.bin",
        )

        mod_main = RuntimeModule(
            module_id="main",
            path="/tmp/app",
            runtime_base=0x1000,
            runtime_end=0x1010,
            load_bias=0x1000,
            build_id="TEST_ID",
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            is_main_executable=True,
            load_bias_status="RESOLVED",
        )

        raw_snap = RawMemorySnapshot(
            snapshot_id="SNAP_AUDIT_004",
            pid=1111,
            binary="/tmp/app",
            timestamp_ns=1000,
            output_dir=self.tmp_dir,
            regions=[cap_reg],
            maps=[{"start_addr": 0x1000, "end_addr": 0x1010, "category": "global", "pathname": "/tmp/app"}],
            modules=[mod_main.to_dict()],
        )

        # Struct has sizeof 64, but fields only declare first 8 bytes.
        # Since struct_size (64) exceeds readable bytes (16), obj.availability must be PARTIAL.
        sym_context = {
            "symbols": [
                {"name": "big_struct", "type": "BigStruct", "address": 0x0}
            ],
            "types": {
                "BigStruct": {
                    "name": "BigStruct",
                    "code": "aggregate",
                    "sizeof": 64,
                    "fields": [
                        {"name": "f1", "type": "uint32_t", "offset": 0, "sizeof": 4},
                        {"name": "f2", "type": "uint32_t", "offset": 4, "sizeof": 4},
                    ]
                }
            }
        }

        class MockDbg:
            path = "/tmp/app"
            def verify(self, b):
                class C:
                    compatible = True
                return C()

        snap = analyzer.analyze(
            memory_snapshot=raw_snap,
            debug_image=MockDbg(),
            optional_symbol_context=sym_context,
        )

        self.assertEqual(len(snap.persistent.objects), 1)
        obj = snap.persistent.objects[0]
        self.assertEqual(obj.availability, "PARTIAL")

    def test_audit_005_provenance_contains_runtime_binary_build_id(self):
        """AUDIT-005: Offline analyzer provenance metadata includes runtime_binary build_id."""
        analyzer = OfflineMemoryAnalyzer()

        mem_dir = os.path.join(self.tmp_dir, "memory")
        os.makedirs(mem_dir, exist_ok=True)
        with open(os.path.join(mem_dir, "reg_empty.bin"), "wb") as f:
            f.write(b"\x00" * 16)

        cap_reg = CapturedRegion(
            region_id="R000001",
            start=0x1000,
            end=0x1010,
            size=0x10,
            permissions="rw-p",
            category="global",
            pathname="/tmp/app",
            requested=0x10,
            captured=0x10,
            status="COMPLETE",
            filename="memory/reg_empty.bin",
        )

        mod_main = RuntimeModule(
            module_id="main",
            path="/tmp/app",
            runtime_base=0x1000,
            runtime_end=0x1010,
            load_bias=0x1000,
            build_id="DEADBEEF1234",
            build_id_status="VERIFIED",
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            is_main_executable=True,
            load_bias_status="RESOLVED",
        )

        raw_snap = RawMemorySnapshot(
            snapshot_id="SNAP_AUDIT_005",
            pid=1111,
            binary="/tmp/app",
            timestamp_ns=1000,
            output_dir=self.tmp_dir,
            regions=[cap_reg],
            maps=[{"start_addr": 0x1000, "end_addr": 0x1010, "category": "global", "pathname": "/tmp/app"}],
            modules=[mod_main.to_dict()],
        )

        class MockDbg:
            path = "/tmp/app"
            def verify(self, b):
                class C:
                    compatible = True
                return C()

        snap = analyzer.analyze(
            memory_snapshot=raw_snap,
            debug_image=MockDbg(),
            optional_symbol_context={"symbols": [], "types": {}},
        )

        prov = snap.provenance
        self.assertIn("runtime_binary", prov)
        self.assertEqual(prov["runtime_binary"]["build_id"], "DEADBEEF1234")
        self.assertEqual(prov["runtime_binary"]["build_id_status"], "VERIFIED")

    def test_audit_006_context_schema_supports_low_impact_execution(self):
        """AUDIT-006: protocol/context.schema.json validates null thread_id and frame_level."""
        schema_path = os.path.join(os.path.dirname(__file__), "..", "protocol", "context.schema.json")
        with open(schema_path, "r") as f:
            schema = json.load(f)

        # Validate that thread_id and frame_level allow null
        exec_props = schema["properties"]["execution"]["properties"]
        self.assertIn("null", exec_props["thread_id"]["type"])
        self.assertIn("null", exec_props["frame_level"]["type"])
        self.assertIn("availability", exec_props)
        self.assertIn("reason", exec_props)

    def test_audit_008_agent_runtime_mutation_candidates_in_low_impact(self):
        """AUDIT-008: list_mutation_candidates returns CAPABILITY_UNSUPPORTED in LOW_IMPACT mode."""
        runtime = AgentRuntime()
        runtime.observation_mode = "LOW_IMPACT"

        res = runtime.list_mutation_candidates()
        self.assertFalse(res.success)
        self.assertEqual(res.error.get("code"), "CAPABILITY_UNSUPPORTED")
        self.assertIn("LOW_IMPACT", res.error.get("message", ""))

    def test_audit_009_memory_maps_resilience_to_malformed_lines(self):
        """AUDIT-009: /proc/<pid>/maps skips corrupted line without discarding remaining lines."""
        fake_maps_content = """00400000-00401000 r-xp 00000000 08:01 12345 /bin/app
CORRUPT_LINE_WITHOUT_HYPHEN_OR_VALID_HEX
00600000-00601000 rw-p 00001000 08:01 12345 /bin/app
"""
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("builtins.open", mock.mock_open(read_data=fake_maps_content)):
                provider = MemoryMapProvider(pid=12345)
                regions = provider.get_regions()
                # Should have parsed the 2 valid regions and ignored the corrupted one
                self.assertEqual(len(regions), 2)
                self.assertEqual(regions[0].start, 0x00400000)
                self.assertEqual(regions[1].start, 0x00600000)


if __name__ == "__main__":
    unittest.main()
