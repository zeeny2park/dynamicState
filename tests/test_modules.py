#!/usr/bin/env python3
"""Unit tests for RuntimeModule and ModuleAddressResolver in Phase 5.2."""

import sys
import unittest
from typing import Dict, Any, List

from extractor.debug_image import BinaryIdentity
from extractor.modules import (
    RuntimeModule,
    ModuleAddressResolver,
    LoadBiasResolutionError,
    discover_modules,
)


class TestRuntimeModule(unittest.TestCase):
    def test_runtime_module_serialization(self):
        mod = RuntimeModule(
            module_id="main",
            path="/usr/bin/sample",
            runtime_base=0x555555554000,
            runtime_end=0x555555558000,
            load_bias=0x555555554000,
            build_id="abcdef123456",
            architecture="aarch64",
            endianness="little",
            elf_class="ELF64",
            is_main_executable=True,
            build_id_status="VERIFIED",
            debuglink="sample.debug",
            elf_type="ET_DYN",
            entry_point=0x1040,
            pt_loads=[
                {"p_offset": 0, "p_vaddr": 0, "p_filesz": 0x1000, "p_memsz": 0x1000, "p_flags": 5, "p_align": 0x1000}
            ],
        )

        d = mod.to_dict()
        self.assertEqual(d["module_id"], "main")
        self.assertEqual(d["runtime_base"], "0x555555554000")
        self.assertEqual(d["load_bias"], "0x555555554000")
        self.assertTrue(d["is_main_executable"])
        self.assertEqual(d["build_id"], "abcdef123456")

        reconstructed = RuntimeModule.from_dict(d)
        self.assertEqual(reconstructed.module_id, mod.module_id)
        self.assertEqual(reconstructed.runtime_base, mod.runtime_base)
        self.assertEqual(reconstructed.load_bias, mod.load_bias)
        self.assertEqual(reconstructed.build_id, mod.build_id)
        self.assertEqual(reconstructed.elf_type, mod.elf_type)

    def test_address_containment(self):
        mod = RuntimeModule(
            module_id="main",
            path="/bin/app",
            runtime_base=0x1000,
            runtime_end=0x3000,
            load_bias=0x1000,
            build_id=None,
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
        )
        self.assertTrue(mod.contains_runtime_address(0x1000))
        self.assertTrue(mod.contains_runtime_address(0x2500))
        self.assertFalse(mod.contains_runtime_address(0x0fff))
        self.assertFalse(mod.contains_runtime_address(0x3000))

        self.assertTrue(mod.contains_elf_address(0x0))
        self.assertTrue(mod.contains_elf_address(0x1500))
        self.assertFalse(mod.contains_elf_address(0x2000))


class TestModuleAddressResolver(unittest.TestCase):
    def test_calculate_load_bias_non_pie(self):
        # Non-PIE: ET_EXEC where p_vaddr = 0x400000, runtime mapping = 0x400000 -> load_bias = 0
        elf_info = BinaryIdentity(
            path="/bin/non_pie_bin",
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            elf_type="ET_EXEC",
            pt_loads=[
                {"p_offset": 0, "p_vaddr": 0x400000, "p_filesz": 0x2000, "p_memsz": 0x2000, "p_flags": 5, "p_align": 0x1000},
                {"p_offset": 0x2000, "p_vaddr": 0x402000, "p_filesz": 0x1000, "p_memsz": 0x1000, "p_flags": 6, "p_align": 0x1000},
            ],
        )
        mappings = [
            {"start_addr": 0x400000, "end_addr": 0x402000, "offset": 0, "pathname": "/bin/non_pie_bin"},
            {"start_addr": 0x402000, "end_addr": 0x403000, "offset": 0x2000, "pathname": "/bin/non_pie_bin"},
        ]

        load_bias = ModuleAddressResolver.calculate_load_bias(mappings, elf_info)
        self.assertEqual(load_bias, 0)

    def test_calculate_load_bias_pie_aslr(self):
        # PIE: ET_DYN where p_vaddr = 0x0, runtime mapping = 0x555555554000 -> load_bias = 0x555555554000
        elf_info = BinaryIdentity(
            path="/bin/pie_bin",
            architecture="aarch64",
            endianness="little",
            elf_class="ELF64",
            elf_type="ET_DYN",
            pt_loads=[
                {"p_offset": 0, "p_vaddr": 0x0, "p_filesz": 0x3000, "p_memsz": 0x3000, "p_flags": 5, "p_align": 0x1000},
                {"p_offset": 0x3000, "p_vaddr": 0x3000, "p_filesz": 0x1000, "p_memsz": 0x1000, "p_flags": 6, "p_align": 0x1000},
            ],
        )
        mappings = [
            {"start_addr": 0x555555554000, "end_addr": 0x555555557000, "offset": 0, "pathname": "/bin/pie_bin"},
            {"start_addr": 0x555555557000, "end_addr": 0x555555558000, "offset": 0x3000, "pathname": "/bin/pie_bin"},
        ]

        load_bias = ModuleAddressResolver.calculate_load_bias(mappings, elf_info)
        self.assertEqual(load_bias, 0x555555554000)

    def test_calculate_load_bias_shared_library(self):
        # Shared library: ET_DYN loaded at high address
        elf_info = BinaryIdentity(
            path="/lib/libexample.so",
            architecture="aarch64",
            endianness="little",
            elf_class="ELF64",
            elf_type="ET_DYN",
            pt_loads=[
                {"p_offset": 0, "p_vaddr": 0x0, "p_filesz": 0x10000, "p_memsz": 0x10000, "p_flags": 5, "p_align": 0x10000},
            ],
        )
        mappings = [
            {"start_addr": 0x7ffff7f00000, "end_addr": 0x7ffff7f10000, "offset": 0, "pathname": "/lib/libexample.so"},
        ]

        load_bias = ModuleAddressResolver.calculate_load_bias(mappings, elf_info)
        self.assertEqual(load_bias, 0x7ffff7f00000)

    def test_calculate_load_bias_missing_pt_loads_raises(self):
        elf_info = BinaryIdentity(
            path="/bin/broken",
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
            pt_loads=[],
        )
        mappings = [{"start_addr": 0x1000, "end_addr": 0x2000, "offset": 0}]
        with self.assertRaises(LoadBiasResolutionError):
            ModuleAddressResolver.calculate_load_bias(mappings, elf_info)

    def test_resolve_address_bidirectional(self):
        mod = RuntimeModule(
            module_id="main",
            path="/bin/app",
            runtime_base=0x555555554000,
            runtime_end=0x555555560000,
            load_bias=0x555555554000,
            build_id=None,
            architecture="x86_64",
            endianness="little",
            elf_class="ELF64",
        )

        elf_addr = 0x1234
        runtime_addr = ModuleAddressResolver.resolve_runtime_address(mod, elf_addr)
        self.assertEqual(runtime_addr, 0x555555554000 + 0x1234)

        reversed_elf_addr = ModuleAddressResolver.resolve_elf_address(mod, runtime_addr)
        self.assertEqual(reversed_elf_addr, elf_addr)


class TestDiscoverModules(unittest.TestCase):
    def test_discover_modules_synthetic_mappings(self):
        regions = [
            {"start_addr": 0x400000, "end_addr": 0x402000, "permissions": "r-xp", "pathname": "/opt/app/my_bin", "offset": 0},
            {"start_addr": 0x402000, "end_addr": 0x403000, "permissions": "rw-p", "pathname": "/opt/app/my_bin", "offset": 0x2000},
            {"start_addr": 0x7f0000, "end_addr": 0x7f5000, "permissions": "r-xp", "pathname": "/usr/lib/libutils.so.1", "offset": 0},
            {"start_addr": 0x800000, "end_addr": 0x850000, "permissions": "rw-p", "pathname": "[heap]", "offset": 0},
            {"start_addr": 0x7ff00000, "end_addr": 0x7ff20000, "permissions": "rw-p", "pathname": "[stack]", "offset": 0},
            {"start_addr": 0x600000, "end_addr": 0x601000, "permissions": "r--p", "pathname": "/usr/share/locale/en.mo", "offset": 0},
        ]

        modules = discover_modules(pid=1234, regions=regions, main_binary="/opt/app/my_bin")
        self.assertEqual(len(modules), 2)

        main_mod = modules[0]
        self.assertTrue(main_mod.is_main_executable)
        self.assertEqual(main_mod.module_id, "main")
        self.assertEqual(main_mod.path, "/opt/app/my_bin")
        self.assertEqual(main_mod.runtime_base, 0x400000)
        self.assertEqual(main_mod.runtime_end, 0x403000)

        shlib_mod = modules[1]
        self.assertFalse(shlib_mod.is_main_executable)
        self.assertEqual(shlib_mod.module_id, "mod_0001")
        self.assertEqual(shlib_mod.path, "/usr/lib/libutils.so.1")
        self.assertEqual(shlib_mod.runtime_base, 0x7f0000)
        self.assertEqual(shlib_mod.runtime_end, 0x7f5000)

    def test_discover_modules_live_python_process(self):
        # Test against current running python executable
        import os
        from extractor.memory_maps import MemoryMapProvider

        maps = MemoryMapProvider(os.getpid()).get_regions()
        modules = discover_modules(pid=os.getpid(), regions=maps, main_binary=sys.executable)
        self.assertTrue(len(modules) >= 1)
        main_mod = modules[0]
        self.assertTrue(main_mod.is_main_executable)
        self.assertEqual(main_mod.module_id, "main")
        self.assertIsNotNone(main_mod.elf_type)
        self.assertIn(main_mod.elf_type, ("ET_EXEC", "ET_DYN"))
        self.assertIn(main_mod.build_id_status, ("VERIFIED", "NOT_AVAILABLE"))


if __name__ == "__main__":
    unittest.main()
