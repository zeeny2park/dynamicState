#!/usr/bin/env python3
"""Unit tests for DebugArtifactProvider and debug provenance verification in Phase 5.2."""

import os
import shutil
import tempfile
import unittest
import zlib
from typing import Dict, Any

from extractor.debug_artifacts import (
    DebugArtifactProvider,
    compute_gnu_debuglink_crc,
)
from extractor.debug_image import BinaryIdentity, CompatibilityResult
from extractor.debug_info import (
    DebugInfoProvider,
    GdbDebugInfoProvider,
    NativeDwarfDebugInfoProvider,
)
from extractor.modules import RuntimeModule


class TestDebugArtifacts(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="ds_test_dbg_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_compute_gnu_debuglink_crc(self):
        test_file = os.path.join(self.tmp_dir, "test.bin")
        data = b"Hello, GNU Debuglink CRC verification!"
        with open(test_file, "wb") as f:
            f.write(data)

        expected_crc = zlib.crc32(data) & 0xFFFFFFFF
        actual_crc = compute_gnu_debuglink_crc(test_file)
        self.assertEqual(actual_crc, expected_crc)

    def test_explicit_registration_precedence(self):
        provider = DebugArtifactProvider(search_paths=[self.tmp_dir])
        fake_dbg = os.path.join(self.tmp_dir, "explicit.debug")
        with open(fake_dbg, "wb") as f:
            f.write(b"debug content")

        mod = RuntimeModule(
            module_id="main",
            path="/usr/bin/app",
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0,
            build_id="0123456789abcdef",
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            is_main_executable=True,
        )

        provider.register("main", fake_dbg)
        found = provider.find_debug_artifact(mod)
        self.assertEqual(found, os.path.abspath(fake_dbg))

    def test_build_id_lookup(self):
        # Setup .build-id/01/23456789abcdef.debug in search path
        build_id = "0123456789abcdef"
        bid_dir = os.path.join(self.tmp_dir, ".build-id", "01")
        os.makedirs(bid_dir, exist_ok=True)
        target_dbg = os.path.join(bid_dir, "23456789abcdef.debug")
        with open(target_dbg, "wb") as f:
            f.write(b"elf debug")

        provider = DebugArtifactProvider(search_paths=[self.tmp_dir])
        mod = RuntimeModule(
            module_id="mod_0001",
            path="/lib/libtest.so",
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0,
            build_id=build_id,
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
        )

        found = provider.find_debug_artifact(mod)
        self.assertEqual(found, os.path.abspath(target_dbg))

    def test_debuglink_crc_match_and_mismatch(self):
        # Create a debug file
        dbg_path = os.path.join(self.tmp_dir, "app.debug")
        dbg_content = b"DWARF debug symbols for app"
        with open(dbg_path, "wb") as f:
            f.write(dbg_content)

        crc_good = zlib.crc32(dbg_content) & 0xFFFFFFFF
        crc_bad = (crc_good + 1) & 0xFFFFFFFF

        provider = DebugArtifactProvider(search_paths=[self.tmp_dir])

        # Test with matching CRC
        mod_good = RuntimeModule(
            module_id="main",
            path=os.path.join(self.tmp_dir, "app"),
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0,
            build_id=None,
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            debuglink={"filename": "app.debug", "crc": crc_good},
        )
        found = provider.find_debug_artifact(mod_good)
        self.assertEqual(found, os.path.abspath(dbg_path))

        # Test with mismatched CRC -> should not be selected
        mod_bad = RuntimeModule(
            module_id="main",
            path=os.path.join(self.tmp_dir, "app"),
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0,
            build_id=None,
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            debuglink={"filename": "app.debug", "crc": crc_bad},
        )
        found_bad = provider.find_debug_artifact(mod_bad)
        self.assertIsNone(found_bad)

    def test_verify_build_id_mismatch(self):
        provider = DebugArtifactProvider()

        # Mock get_ident on provider to avoid creating full ELF files
        fake_dbg = os.path.join(self.tmp_dir, "mismatch.debug")
        with open(fake_dbg, "wb") as f:
            f.write(b"data")

        provider._ident_cache[os.path.abspath(fake_dbg)] = BinaryIdentity(
            path=fake_dbg,
            architecture="aarch64",
            endianness="little",
            elf_class="ELF64",
            build_id="bad0000000000000",
            has_debug_info=True,
        )

        mod = RuntimeModule(
            module_id="main",
            path="/bin/app",
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0,
            build_id="good111111111111",
            architecture="aarch64",
            endianness="little",
            elf_class="ELF64",
        )

        compat = provider.verify(mod, fake_dbg)
        self.assertFalse(compat.compatible)
        self.assertEqual(compat.reason, "DEBUG_IMAGE_MISMATCH")

    def test_verify_stripped_debug_image(self):
        provider = DebugArtifactProvider()

        fake_dbg = os.path.join(self.tmp_dir, "stripped.debug")
        with open(fake_dbg, "wb") as f:
            f.write(b"data")

        provider._ident_cache[os.path.abspath(fake_dbg)] = BinaryIdentity(
            path=fake_dbg,
            architecture="aarch64",
            endianness="little",
            elf_class="ELF64",
            build_id="good111111111111",
            has_debug_info=False,  # Stripped!
        )

        mod = RuntimeModule(
            module_id="main",
            path="/bin/app",
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0,
            build_id="good111111111111",
            architecture="aarch64",
            endianness="little",
            elf_class="ELF64",
        )

        compat = provider.verify(mod, fake_dbg)
        self.assertFalse(compat.compatible)
        self.assertEqual(compat.reason, "DEBUG_IMAGE_STRIPPED")

    def test_native_dwarf_debug_info_provider_stub(self):
        provider = NativeDwarfDebugInfoProvider()
        mod = RuntimeModule(
            module_id="main",
            path="/bin/app",
            runtime_base=0x1000,
            runtime_end=0x2000,
            load_bias=0,
            build_id=None,
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
        )
        with self.assertRaises(NotImplementedError):
            provider.load(mod, "/bin/app.debug")


if __name__ == "__main__":
    unittest.main()
