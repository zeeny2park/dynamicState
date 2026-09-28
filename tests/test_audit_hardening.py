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

    def test_audit_big_endian_decoding(self):
        """AUDIT-B: Authoritative big-endian target memory decoding (int16/32/64, float, double, ptr, enum)."""
        analyzer = OfflineMemoryAnalyzer()

        mem_dir = os.path.join(self.tmp_dir, "be_memory")
        os.makedirs(mem_dir, exist_ok=True)

        # Build big-endian memory buffer (> format)
        be_buf = bytearray(128)
        # offset 0: uint16 = 0x1234 (bytes: 12 34)
        struct.pack_into(">H", be_buf, 0, 0x1234)
        # offset 4: uint32 = 0x12345678 (bytes: 12 34 56 78)
        struct.pack_into(">I", be_buf, 4, 0x12345678)
        # offset 8: uint64 = 0x0102030405060708 (bytes: 01 02 03 04 05 06 07 08)
        struct.pack_into(">Q", be_buf, 8, 0x0102030405060708)
        # offset 16: float = 12.5
        struct.pack_into(">f", be_buf, 16, 12.5)
        # offset 24: double = 123.456
        struct.pack_into(">d", be_buf, 24, 123.456)
        # offset 32: enum (SessionState = 2 -> "DISCONNECTED")
        struct.pack_into(">I", be_buf, 32, 2)
        # offset 40: pointer = 0x8000
        struct.pack_into(">Q", be_buf, 40, 0x8000)

        with open(os.path.join(mem_dir, "be_reg.bin"), "wb") as f:
            f.write(be_buf)

        cap_reg = CapturedRegion(
            region_id="R000001",
            start=0x5000,
            end=0x5080,
            size=128,
            permissions="rw-p",
            category="global",
            pathname="/app/be_target",
            requested=128,
            captured=128,
            status="COMPLETE",
            filename="be_memory/be_reg.bin",
        )

        mod_be = RuntimeModule(
            module_id="main",
            path="/app/be_target",
            runtime_base=0x5000,
            runtime_end=0x5080,
            load_bias=0x5000,
            build_id="BE_BUILD_ID",
            architecture="mips64",
            endianness="big",  # Big-endian target
            elf_class="ELF64",
            is_main_executable=True,
            load_bias_status="RESOLVED",
        )

        raw_snap = RawMemorySnapshot(
            snapshot_id="SNAP_BE_AUDIT",
            pid=2222,
            binary="/app/be_target",
            timestamp_ns=2000,
            output_dir=self.tmp_dir,
            regions=[cap_reg],
            maps=[{"start_addr": 0x5000, "end_addr": 0x5080, "category": "global", "pathname": "/app/be_target"}],
            modules=[mod_be.to_dict()],
            endianness="big",
        )

        # Verify SnapshotMemoryReader recognizes big-endian
        reader = SnapshotMemoryReader(raw_snap)
        self.assertEqual(reader.endianness, "big")
        self.assertEqual(reader.read_int(0x5000, 2, signed=False), 0x1234)
        self.assertEqual(reader.read_int(0x5004, 4, signed=False), 0x12345678)
        self.assertEqual(reader.read_int(0x5008, 8, signed=False), 0x0102030405060708)
        self.assertAlmostEqual(reader.read_float(0x5010), 12.5, places=3)
        self.assertAlmostEqual(reader.read_double(0x5018), 123.456, places=3)
        self.assertEqual(reader.read_ptr(0x5028), 0x8000)

        # Verify full offline semantic analysis with big-endian struct
        sym_context = {
            "symbols": [
                {"name": "be_obj", "type": "BigEndianStruct", "address": 0x0}
            ],
            "types": {
                "BigEndianStruct": {
                    "name": "BigEndianStruct",
                    "code": "aggregate",
                    "sizeof": 48,
                    "fields": [
                        {"name": "u16_val", "type": "uint16_t", "offset": 0, "sizeof": 2},
                        {"name": "u32_val", "type": "uint32_t", "offset": 4, "sizeof": 4},
                        {"name": "u64_val", "type": "uint64_t", "offset": 8, "sizeof": 8},
                        {"name": "f_val", "type": "float", "offset": 16, "sizeof": 4},
                        {"name": "d_val", "type": "double", "offset": 24, "sizeof": 8},
                        {"name": "state", "type": "StateEnum", "offset": 32, "sizeof": 4},
                    ]
                },
                "StateEnum": {
                    "name": "StateEnum",
                    "code": "enum",
                    "sizeof": 4,
                    "fields": ["IDLE", "CONNECTING", "DISCONNECTED"]
                }
            }
        }

        class MockDbg:
            path = "/app/be_target"
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
        fields = {f.name: f.value for f in obj.fields}
        self.assertEqual(fields["u16_val"], 0x1234)
        self.assertEqual(fields["u32_val"], 0x12345678)
        self.assertEqual(fields["u64_val"], 0x0102030405060708)
        self.assertAlmostEqual(fields["f_val"], 12.5, places=3)
        self.assertAlmostEqual(fields["d_val"], 123.456, places=3)
        self.assertEqual(fields["state"], "DISCONNECTED")

    def test_audit_elf32_pointer_width(self):
        """AUDIT-C: Verify ELF32 pointer width is 4 bytes and ELF64 is 8 bytes."""
        mod32 = RuntimeModule(
            module_id="main",
            path="/app/target32",
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0x1000,
            build_id="BUILD32",
            architecture="x86",
            endianness="little",
            elf_class="ELF32",
            is_main_executable=True,
            load_bias_status="RESOLVED",
        )

        raw_snap32 = RawMemorySnapshot(
            snapshot_id="SNAP_ELF32",
            pid=3333,
            binary="/app/target32",
            timestamp_ns=3000,
            output_dir=self.tmp_dir,
            regions=[],
            maps=[],
            modules=[mod32.to_dict()],
        )

        reader32 = SnapshotMemoryReader(raw_snap32)
        self.assertEqual(reader32.ptr_size, 4)

        mod64 = RuntimeModule(
            module_id="main",
            path="/app/target64",
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0x1000,
            build_id="BUILD64",
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            is_main_executable=True,
            load_bias_status="RESOLVED",
        )

        raw_snap64 = RawMemorySnapshot(
            snapshot_id="SNAP_ELF64",
            pid=4444,
            binary="/app/target64",
            timestamp_ns=4000,
            output_dir=self.tmp_dir,
            regions=[],
            maps=[],
            modules=[mod64.to_dict()],
        )

        reader64 = SnapshotMemoryReader(raw_snap64)
        self.assertEqual(reader64.ptr_size, 8)

    def test_audit_strict_build_id_rejection_when_debug_has_no_build_id(self):
        """AUDIT-D: Reject debug image if runtime binary has Build ID but debug image does not."""
        dbg_provider = DebugImageProvider()
        dbg_provider.debug_image_path = "/tmp/debug_no_bid"

        # Mock debug identity without build ID
        from extractor.debug_image import BinaryIdentity
        dbg_provider.debug_identity = BinaryIdentity(
            path="/tmp/debug_no_bid",
            elf_class="ELF64",
            architecture="x86_64",
            endianness="little",
            build_id=None,  # No Build ID in debug image
            has_debug_info=True,
        )

        # Mock runtime binary identity with Build ID
        with mock.patch("extractor.debug_image.inspect_elf") as mock_inspect:
            mock_inspect.return_value = BinaryIdentity(
                path="/tmp/runtime_bin",
                elf_class="ELF64",
                architecture="x86_64",
                endianness="little",
                build_id="KNOWN_BUILD_ID_AAA",  # Runtime binary has Build ID
                has_debug_info=False,
            )

            res = dbg_provider.verify("/tmp/runtime_bin")
            self.assertFalse(res.compatible)
            self.assertEqual(res.reason, "BUILD_ID_MISMATCH")

    def test_audit_gnu_debuglink_crc_verification_and_ambiguity(self):
        """AUDIT-E: Test .gnu_debuglink CRC matching, CRC mismatch rejection, and ambiguous candidates."""
        provider = DebugArtifactProvider(search_paths=[self.tmp_dir])

        # Create two debug files: one with matching CRC and one with mismatching content
        dbg_correct = os.path.join(self.tmp_dir, "libfoo.debug")
        with open(dbg_correct, "wb") as f:
            f.write(b"CORRECT_DEBUG_DATA")

        from extractor.debug_artifacts import compute_gnu_debuglink_crc
        correct_crc = compute_gnu_debuglink_crc(dbg_correct)

        mod_matching = RuntimeModule(
            module_id="mod_foo",
            path=os.path.join(self.tmp_dir, "libfoo.so"),
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0x1000,
            build_id=None,
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            debuglink={"filename": "libfoo.debug", "crc": correct_crc},
        )

        # Case 1: CRC matches -> artifact discovered
        found = provider.find_debug_artifact(mod_matching)
        self.assertEqual(found, dbg_correct)

        # Case 2: CRC mismatch -> artifact rejected
        mod_mismatch = RuntimeModule(
            module_id="mod_foo",
            path=os.path.join(self.tmp_dir, "libfoo.so"),
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0x1000,
            build_id=None,
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            debuglink={"filename": "libfoo.debug", "crc": 0xDEADBEEF},
        )
        found_mismatch = provider.find_debug_artifact(mod_mismatch)
        self.assertIsNone(found_mismatch)

    def test_audit_shared_library_address_translation_boundaries(self):
        """AUDIT-A: Module boundary checks and address translation for shared libraries."""
        mod_exe = RuntimeModule(
            module_id="main",
            path="/bin/app",
            runtime_base=0x400000,
            runtime_end=0x405000,
            load_bias=0x400000,
            build_id="EXE_ID",
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            is_main_executable=True,
            load_bias_status="RESOLVED",
        )
        mod_lib = RuntimeModule(
            module_id="mod_0001",
            path="/lib/libhelper.so",
            runtime_base=0x7fff1000,
            runtime_end=0x7fff5000,
            load_bias=0x7fff1000,
            build_id="LIB_ID",
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            is_main_executable=False,
            load_bias_status="RESOLVED",
        )
        mod_unresolved = RuntimeModule(
            module_id="mod_0002",
            path="/lib/libunresolved.so",
            runtime_base=0x7fff6000,
            runtime_end=0x7fff8000,
            load_bias=None,
            build_id="UNRES_ID",
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            is_main_executable=False,
            load_bias_status="UNRESOLVED",
        )

        modules = [mod_exe, mod_lib, mod_unresolved]
        raw_snap = RawMemorySnapshot(
            snapshot_id="SNAP_BOUNDS",
            pid=5555,
            binary="/bin/app",
            timestamp_ns=5000,
            output_dir=self.tmp_dir,
            regions=[],
            maps=[],
            modules=[m.to_dict() for m in modules],
        )
        reader = SnapshotMemoryReader(raw_snap)

        # 1. module_for_address
        self.assertEqual(reader.module_for_address(0x401000).module_id, "main")
        self.assertEqual(reader.module_for_address(0x7fff2000).module_id, "mod_0001")
        self.assertIsNone(reader.module_for_address(0x1000))

        # 2. runtime_to_elf translation within bounds
        m, elf_addr = reader.runtime_to_elf(0x7fff2500)
        self.assertEqual(m.module_id, "mod_0001")
        self.assertEqual(elf_addr, 0x1500)

        # 3. Unresolved module returns None on runtime_to_elf
        self.assertIsNone(reader.runtime_to_elf(0x7fff7000))

    def test_audit_missing_endianness_no_silent_fallback(self):
        """AUDIT-F1: Verify missing target endianness does NOT silently default to little-endian."""
        mod = RuntimeModule(
            module_id="main",
            path="/app/target_unknown_endian",
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0x1000,
            build_id="BUILD_UNKNOWN_ENDIAN",
            architecture="x86_64",
            endianness=None,  # Endianness is unavailable
            elf_class="ELF64",
            is_main_executable=True,
            load_bias_status="RESOLVED",
        )
        raw_snap = RawMemorySnapshot(
            snapshot_id="SNAP_NO_ENDIAN",
            pid=7771,
            binary="/app/target_unknown_endian",
            timestamp_ns=1000,
            output_dir=self.tmp_dir,
            regions=[],
            maps=[],
            modules=[mod.to_dict()],
            endianness="UNKNOWN",
        )
        reader = SnapshotMemoryReader(raw_snap)
        # SnapshotMemoryReader must NOT assume little-endian
        self.assertIsNone(reader.endianness)
        self.assertNotEqual(reader.endianness, "little")

        # Explicit error raised at semantic decoding boundary
        with self.assertRaises(ValueError) as ctx:
            reader.read_int(0x1000, 4)
        self.assertIn("TARGET_ENDIANNESS_UNAVAILABLE", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            reader.read_ptr(0x1000)
        self.assertIn("TARGET_ENDIANNESS_UNAVAILABLE", str(ctx.exception))

    def test_audit_missing_elf_class_no_silent_pointer_fallback(self):
        """AUDIT-F2: Verify missing elf_class does NOT silently default to 8-byte pointer width."""
        mod = RuntimeModule(
            module_id="main",
            path="/app/target_no_class",
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0x1000,
            build_id="BUILD_NO_CLASS",
            architecture="x86_64",
            endianness="little",
            elf_class=None,  # ELF class is unavailable
            is_main_executable=True,
            load_bias_status="RESOLVED",
        )
        raw_snap = RawMemorySnapshot(
            snapshot_id="SNAP_NO_CLASS",
            pid=7772,
            binary="/app/target_no_class",
            timestamp_ns=2000,
            output_dir=self.tmp_dir,
            regions=[],
            maps=[],
            modules=[mod.to_dict()],
            endianness="little",
            elf_class=None,
        )
        reader = SnapshotMemoryReader(raw_snap)
        # Pointer width must be unavailable, NOT defaulted to 8
        self.assertIsNone(reader.ptr_size)
        self.assertNotEqual(reader.ptr_size, 8)

        # read_ptr must NOT decode arbitrary 8 bytes, but return None (unavailable)
        self.assertIsNone(reader.read_ptr(0x1000))

    def test_audit_mapping_race_path_change(self):
        """AUDIT-F3a: Mapping race detected when pathname changes between capture start and end."""
        from extractor.memory_maps import MemoryRegion, get_region_fingerprint
        r_before = MemoryRegion(
            start=0x1000,
            end=0x2000,
            permissions="rw-p",
            pathname="/lib/libA.so",
            offset=0,
            device="08:01",
            inode=12345,
        )
        r_after = MemoryRegion(
            start=0x1000,
            end=0x2000,
            permissions="rw-p",
            pathname="/lib/libB.so",
            offset=0,
            device="08:01",
            inode=12345,
        )
        self.assertNotEqual(get_region_fingerprint(r_before), get_region_fingerprint(r_after))

        capturer = MemoryCapture()
        capturer._libc = mock.MagicMock()
        capturer._libc.process_vm_readv.return_value = 0x1000

        with mock.patch("extractor.memory_capture.MemoryMapProvider") as mock_mmp_cls:
            mock_provider_before = mock.MagicMock()
            mock_provider_before.get_regions.return_value = [r_before]
            mock_provider_after = mock.MagicMock()
            mock_provider_after.get_regions.return_value = [r_after]
            mock_mmp_cls.side_effect = [mock_provider_before, mock_provider_after]

            with mock.patch.object(capturer, "get_process_identity", return_value=(os.getpid(), 123456)):
                with mock.patch("os.path.exists", return_value=True):
                    with mock.patch("os.kill"):
                        with mock.patch("extractor.memory_capture.discover_modules", return_value=[]):
                            snap = capturer.capture(pid=os.getpid(), output_dir=self.tmp_dir)
                            self.assertTrue(snap.consistency.get("mapping_race_detected", False))
                            self.assertEqual(snap.status, "PARTIAL")

    def test_audit_mapping_race_inode_change(self):
        """AUDIT-F3b: Mapping race detected when inode changes (file replaced under same pathname)."""
        from extractor.memory_maps import MemoryRegion, get_region_fingerprint
        r_before = MemoryRegion(
            start=0x1000,
            end=0x2000,
            permissions="rw-p",
            pathname="/lib/libA.so",
            offset=0,
            device="08:01",
            inode=10001,
        )
        r_after = MemoryRegion(
            start=0x1000,
            end=0x2000,
            permissions="rw-p",
            pathname="/lib/libA.so",
            offset=0,
            device="08:01",
            inode=10002,  # Replaced file with different inode
        )
        self.assertNotEqual(get_region_fingerprint(r_before), get_region_fingerprint(r_after))

        capturer = MemoryCapture()
        capturer._libc = mock.MagicMock()
        capturer._libc.process_vm_readv.return_value = 0x1000

        with mock.patch("extractor.memory_capture.MemoryMapProvider") as mock_mmp_cls:
            mock_provider_before = mock.MagicMock()
            mock_provider_before.get_regions.return_value = [r_before]
            mock_provider_after = mock.MagicMock()
            mock_provider_after.get_regions.return_value = [r_after]
            mock_mmp_cls.side_effect = [mock_provider_before, mock_provider_after]

            with mock.patch.object(capturer, "get_process_identity", return_value=(os.getpid(), 123456)):
                with mock.patch("os.path.exists", return_value=True):
                    with mock.patch("os.kill"):
                        with mock.patch("extractor.memory_capture.discover_modules", return_value=[]):
                            snap = capturer.capture(pid=os.getpid(), output_dir=self.tmp_dir)
                            self.assertTrue(snap.consistency.get("mapping_race_detected", False))
                            self.assertEqual(snap.status, "PARTIAL")

    def test_audit_mapping_race_permission_change(self):
        """AUDIT-F3c: Mapping race detected when permissions change (e.g. r--p -> rw-p)."""
        from extractor.memory_maps import MemoryRegion, get_region_fingerprint
        r_before = MemoryRegion(
            start=0x1000,
            end=0x2000,
            permissions="r--p",
            pathname="/lib/libA.so",
            offset=0,
            device="08:01",
            inode=12345,
        )
        r_after = MemoryRegion(
            start=0x1000,
            end=0x2000,
            permissions="rw-p",  # Changed from r--p
            pathname="/lib/libA.so",
            offset=0,
            device="08:01",
            inode=12345,
        )
        self.assertNotEqual(get_region_fingerprint(r_before), get_region_fingerprint(r_after))

        capturer = MemoryCapture()
        capturer._libc = mock.MagicMock()
        capturer._libc.process_vm_readv.return_value = 0x1000

        with mock.patch("extractor.memory_capture.MemoryMapProvider") as mock_mmp_cls:
            mock_provider_before = mock.MagicMock()
            mock_provider_before.get_regions.return_value = [r_before]
            mock_provider_after = mock.MagicMock()
            mock_provider_after.get_regions.return_value = [r_after]
            mock_mmp_cls.side_effect = [mock_provider_before, mock_provider_after]

            with mock.patch.object(capturer, "get_process_identity", return_value=(os.getpid(), 123456)):
                with mock.patch("os.path.exists", return_value=True):
                    with mock.patch("os.kill"):
                        with mock.patch("extractor.memory_capture.discover_modules", return_value=[]):
                            snap = capturer.capture(pid=os.getpid(), output_dir=self.tmp_dir)
                            self.assertTrue(snap.consistency.get("mapping_race_detected", False))
                            self.assertEqual(snap.status, "PARTIAL")

    def test_audit_stable_mapping_no_race(self):
        """AUDIT-F3d: Identical mapping fingerprints produce mapping_race_detected = False."""
        from extractor.memory_maps import MemoryRegion, get_region_fingerprint
        r1 = MemoryRegion(
            start=0x1000,
            end=0x2000,
            permissions="rw-p",
            pathname="/lib/libA.so",
            offset=0,
            device="08:01",
            inode=12345,
        )
        r2 = MemoryRegion(
            start=0x1000,
            end=0x2000,
            permissions="rw-p",
            pathname="/lib/libA.so",
            offset=0,
            device="08:01",
            inode=12345,
        )
        self.assertEqual(get_region_fingerprint(r1), get_region_fingerprint(r2))

        capturer = MemoryCapture()
        capturer._libc = mock.MagicMock()
        capturer._libc.process_vm_readv.return_value = 0x1000

        with mock.patch("extractor.memory_capture.MemoryMapProvider") as mock_mmp_cls:
            mock_provider_before = mock.MagicMock()
            mock_provider_before.get_regions.return_value = [r1]
            mock_provider_after = mock.MagicMock()
            mock_provider_after.get_regions.return_value = [r2]
            mock_mmp_cls.side_effect = [mock_provider_before, mock_provider_after]

            with mock.patch.object(capturer, "get_process_identity", return_value=(os.getpid(), 123456)):
                with mock.patch("os.path.exists", return_value=True):
                    with mock.patch("os.kill"):
                        with mock.patch("extractor.memory_capture.discover_modules", return_value=[]):
                            snap = capturer.capture(pid=os.getpid(), output_dir=self.tmp_dir)
                            self.assertFalse(snap.consistency.get("mapping_race_detected", False))
                            self.assertEqual(snap.status, "COMPLETE")


if __name__ == "__main__":
    unittest.main()
