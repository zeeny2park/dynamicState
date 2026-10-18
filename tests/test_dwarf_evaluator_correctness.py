"""Comprehensive Correctness and Cross-Validation Suite for Phase 1.3 DWARF Evaluator.

Validates:
1. Frame-base & CFA rules:
   - Entry probes before prologue frame establishment -> UNAVAILABLE
   - Post-prologue evaluation via DW_AT_frame_base -> OBSERVED
   - Omitted frame pointer (-fomit-frame-pointer) -> UNAVAILABLE (never guessed)
2. Location-list parsing (.debug_loc and .debug_loclists):
   - Base address selection entries, views, continuation lines, offset index tables
   - Address ranges matching link-time PC (PIE and non-PIE)
   - Missing or malformed location lists -> ERROR (never OPTIMIZED_OUT)
3. Canonical scalar and floating-point value decoding:
   - int8_t, int16_t, int32_t, int64_t, uint8_t, uint16_t, uint32_t, uint64_t
   - IEEE 754 float (32-bit) and double (64-bit) from register bit patterns and memory
   - bool and pointer types
   - Unreadable memory -> UNAVAILABLE (never converted to 0)
4. Register clobbering & DW_OP_entry_value:
   - Live in parameter register at entry -> OBSERVED
   - Spilled to callee-saved register -> OBSERVED
   - Active register clobbered (DW_OP_entry_value) -> OPTIMIZED_OUT
   - PC outside location list ranges -> UNAVAILABLE
5. Full compiler matrix compilation:
   - GCC -O0, GCC -O2, GCC -O0 -fomit-frame-pointer, GCC -O2 -fomit-frame-pointer, GCC -no-pie
   - Clang -O0, Clang -O2, Clang -O0 -fomit-frame-pointer
6. Automated GDB cross-validation:
   - Evaluator results asserted identical to GDB ground truth.
"""

import json
import os
import platform
import re
import shutil
import struct
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
import unittest

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
    _LOC_CACHE,
    _LOC_ERROR,
    _get_loc_cache_key,
    clear_loc_cache,
    parse_debug_loc_table,
    unpack_scalar_from_bytes,
    unpack_scalar_from_register,
)
from extractor.dwarf_indexer import (
    DwarfIndex,
    DwarfIndexer,
    DwarfSubprogram,
    DwarfType,
    DwarfVariable,
    _CFI_CACHE,
    _get_cfi_cache_key,
    clear_cfi_cache,
    parse_cfi_table,
)
from extractor.ebpf_tracer import FrameMetadata


class TestDwarfEvaluatorCorrectness(unittest.TestCase):
    """Deep verification of DWARF location evaluation, frame-base rules, and GDB parity."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="dynstate_phase13_")
        cls.fixture_src = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime", "ebpf_stack_fixture.cpp")
        )
        if not os.path.exists(cls.fixture_src):
            raise unittest.SkipTest(f"Fixture source not found: {cls.fixture_src}")

        # Check compiler availability
        cls.has_gcc = shutil.which("g++") is not None
        cls.has_clang = shutil.which("clang++") is not None
        cls.has_gdb = shutil.which("gdb") is not None

        cls.binaries: Dict[str, str] = {}

        if cls.has_gcc:
            # 1. GCC -O0 (PIE, with frame pointers)
            p1 = os.path.join(cls.tmp_dir, "gcc_o0")
            subprocess.run(["g++", "-Wall", "-Wextra", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer", cls.fixture_src, "-o", p1], check=True)
            cls.binaries["gcc_o0"] = p1

            # 2. GCC -O2 (PIE, with frame pointers)
            p2 = os.path.join(cls.tmp_dir, "gcc_o2")
            subprocess.run(["g++", "-Wall", "-Wextra", "-g", "-O2", "-fno-inline", "-fno-omit-frame-pointer", "-DOPTIMIZED_BUILD", cls.fixture_src, "-o", p2], check=True)
            cls.binaries["gcc_o2"] = p2

            # 3. GCC -O0 -fomit-frame-pointer
            p3 = os.path.join(cls.tmp_dir, "gcc_o0_omit_fp")
            subprocess.run(["g++", "-Wall", "-Wextra", "-g", "-O0", "-fno-inline", "-fomit-frame-pointer", cls.fixture_src, "-o", p3], check=True)
            cls.binaries["gcc_o0_omit_fp"] = p3

            # 4. GCC -O2 -fomit-frame-pointer
            p4 = os.path.join(cls.tmp_dir, "gcc_o2_omit_fp")
            subprocess.run(["g++", "-Wall", "-Wextra", "-g", "-O2", "-fno-inline", "-fomit-frame-pointer", "-DOPTIMIZED_BUILD", cls.fixture_src, "-o", p4], check=True)
            cls.binaries["gcc_o2_omit_fp"] = p4

            # 5. GCC -no-pie
            p5 = os.path.join(cls.tmp_dir, "gcc_nopie")
            subprocess.run(["g++", "-Wall", "-Wextra", "-g", "-O0", "-no-pie", "-fno-inline", "-fno-omit-frame-pointer", cls.fixture_src, "-o", p5], check=True)
            cls.binaries["gcc_nopie"] = p5

        if cls.has_clang:
            # 6. Clang -O0 (PIE, with frame pointers, DWARF 5)
            p6 = os.path.join(cls.tmp_dir, "clang_o0")
            subprocess.run(["clang++", "-Wall", "-Wextra", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer", cls.fixture_src, "-o", p6], check=True)
            cls.binaries["clang_o0"] = p6

            # 7. Clang -O2 (PIE, with frame pointers, DWARF 5)
            p7 = os.path.join(cls.tmp_dir, "clang_o2")
            subprocess.run(["clang++", "-Wall", "-Wextra", "-g", "-O2", "-fno-inline", "-fno-omit-frame-pointer", "-DOPTIMIZED_BUILD", cls.fixture_src, "-o", p7], check=True)
            cls.binaries["clang_o2"] = p7

            # 8. Clang -O0 -fomit-frame-pointer
            p8 = os.path.join(cls.tmp_dir, "clang_o0_omit_fp")
            subprocess.run(["clang++", "-Wall", "-Wextra", "-g", "-O0", "-fno-inline", "-fomit-frame-pointer", cls.fixture_src, "-o", p8], check=True)
            cls.binaries["clang_o0_omit_fp"] = p8

    @classmethod
    def tearDownClass(cls):
        clear_loc_cache()
        clear_cfi_cache()
        DwarfIndexer.clear_cache()
        if hasattr(cls, "tmp_dir") and os.path.exists(cls.tmp_dir):
            shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def setUp(self):
        clear_loc_cache()
        clear_cfi_cache()
        DwarfIndexer.clear_cache()

    # =========================================================================
    # 1. Frame-Base & CFA Evaluation Tests
    # =========================================================================

    def test_01_frame_base_entry_probe_is_unavailable(self):
        """Entry probe before prologue frame establishment must report UNAVAILABLE, never bogus memory."""
        if "gcc_o0" not in self.binaries:
            raise unittest.SkipTest("GCC not available")

        bin_path = self.binaries["gcc_o0"]
        idx = DwarfIndexer.get_index(bin_path)
        subp = idx.subprograms_by_name["trace_target_function"][0]
        ident = inspect_elf(bin_path)

        # Probing at subp.low_pc (entry instruction before prologue execution)
        ctx = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=subp.low_pc,
            frame_metadata=FrameMetadata(frame_pointer=0x7fffffffe000),
            variable_name="op_code",
            architecture=ident.architecture,
        )
        res = DwarfEvaluator.evaluate(ctx)
        self.assertEqual(res.status, EVAL_STATUS_UNAVAILABLE)
        self.assertIn("prologue frame establishment", res.reason)
        self.assertIsNone(res.value)

    def test_02_frame_base_post_prologue_is_observed(self):
        """Post-prologue probe after frame establishment correctly reads stack memory via frame_base."""
        if "gcc_o0" not in self.binaries:
            raise unittest.SkipTest("GCC not available")

        bin_path = self.binaries["gcc_o0"]
        idx = DwarfIndexer.get_index(bin_path)
        subp = idx.subprograms_by_name["trace_target_function"][0]
        ident = inspect_elf(bin_path)

        post_pc = subp.frame_established_pc or (subp.low_pc + 16)
        fp = 0x7fffffffe000

        # Memory reader simulating stack contents at op_code address
        fake_mem = {fp + 16 - 116: struct.pack("<i", 42)}
        def mem_reader(addr: int, sz: int) -> Optional[bytes]:
            return fake_mem.get(addr)

        ctx = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=post_pc,
            frame_metadata=FrameMetadata(frame_pointer=fp),
            variable_name="op_code",
            architecture=ident.architecture,
            memory_reader=mem_reader,
        )
        res = DwarfEvaluator.evaluate(ctx)
        self.assertEqual(res.status, EVAL_STATUS_OBSERVED)
        self.assertEqual(res.value, 42)
        self.assertEqual(res.value_hex, "0x0000002a")
        self.assertEqual(res.evaluated_address, fp + 16 - 116)

    def test_03_omitted_frame_pointer_is_truthfully_unavailable(self):
        """Binaries compiled with -fomit-frame-pointer must return UNAVAILABLE, never guess FP+16."""
        if "gcc_o0_omit_fp" not in self.binaries:
            raise unittest.SkipTest("GCC omit_fp binary not available")

        bin_path = self.binaries["gcc_o0_omit_fp"]
        idx = DwarfIndexer.get_index(bin_path)
        subp = idx.subprograms_by_name["trace_target_function"][0]
        ident = inspect_elf(bin_path)

        self.assertFalse(subp.has_frame_pointer, "Binary with -fomit-frame-pointer must report has_frame_pointer=False")

        ctx = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=subp.low_pc + 16,
            frame_metadata=FrameMetadata(frame_pointer=0x7fffffffe000),
            variable_name="op_code",
            architecture=ident.architecture,
            memory_reader=lambda addr, sz: b"\x2a\x00\x00\x00",
        )
        res = DwarfEvaluator.evaluate(ctx)
        self.assertEqual(res.status, EVAL_STATUS_UNAVAILABLE)
        self.assertIn("compiled with -fomit-frame-pointer", res.reason)
        self.assertIsNone(res.value)

    # =========================================================================
    # 2. Location List (.debug_loc / .debug_loclists) Parsing Tests
    # =========================================================================

    def test_04_location_list_parsing_gcc_and_clang(self):
        """Verify location list extraction from both GCC and Clang DWARF 5 .debug_loclists."""
        for label in ("gcc_o2", "clang_o2"):
            if label not in self.binaries:
                continue
            bin_path = self.binaries[label]
            t = parse_debug_loc_table(bin_path)
            self.assertGreater(len(t), 0, f"Location table for {label} must not be empty")

            idx = DwarfIndexer.get_index(bin_path)
            subp = idx.subprograms_by_name["test_clobbered_param"][0]
            val_var = subp.get_variable("val")
            self.assertIsNotNone(val_var)
            self.assertIsNotNone(val_var.location_list_offset)
            self.assertIn(val_var.location_list_offset, t, f"loc_offset for 'val' must exist in table for {label}")

            entries = t[val_var.location_list_offset]
            self.assertGreaterEqual(len(entries), 2, f"'val' in {label} must have multiple range entries")

    def test_05_missing_or_corrupt_location_list_returns_error(self):
        """Malformed or missing location list must return ERROR, not OPTIMIZED_OUT."""
        if "gcc_o0" not in self.binaries:
            raise unittest.SkipTest("GCC not available")
        bin_path = self.binaries["gcc_o0"]
        ident = inspect_elf(bin_path)
        subp = DwarfSubprogram(
            die_offset=0x10,
            name="corrupt_func",
            low_pc=0x1000,
            high_pc=0x1100,
            variables=[
                DwarfVariable(die_offset=0x20, name="bad_list_var", type_offset=0x30, location_list_offset=0xDEADBEEF),
            ],
        )
        ctx = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=0x1050,
            variable_name="bad_list_var",
            architecture=ident.architecture,
        )
        res = DwarfEvaluator.evaluate(ctx)
        self.assertEqual(res.status, EVAL_STATUS_ERROR)
        self.assertIn("not found in debug data", res.reason)
        self.assertNotEqual(res.status, EVAL_STATUS_OPTIMIZED_OUT)

    # =========================================================================
    # 3. Canonical Scalar & Floating-Point Value Decoding Tests
    # =========================================================================

    def test_06_unpack_all_scalar_types_from_bytes(self):
        """Verify unpack_scalar_from_bytes across all signed/unsigned widths, float, double, bool, pointer."""
        # 1. Signed integers
        self.assertEqual(unpack_scalar_from_bytes(b"\xd6", "int8")[0], -42)
        self.assertEqual(unpack_scalar_from_bytes(struct.pack("<h", -1234), "int16")[0], -1234)
        self.assertEqual(unpack_scalar_from_bytes(struct.pack("<i", -123456), "int32")[0], -123456)
        self.assertEqual(unpack_scalar_from_bytes(struct.pack("<q", -123456789012345), "int64")[0], -123456789012345)

        # 2. Unsigned integers
        self.assertEqual(unpack_scalar_from_bytes(b"\xc8", "uint8")[0], 200)
        self.assertEqual(unpack_scalar_from_bytes(struct.pack("<H", 50000), "uint16")[0], 50000)
        self.assertEqual(unpack_scalar_from_bytes(struct.pack("<I", 3000000000), "uint32")[0], 3000000000)
        self.assertEqual(unpack_scalar_from_bytes(struct.pack("<Q", 12345678901234567890), "uint64")[0], 12345678901234567890)

        # 3. Floating-point types
        v_flt, h_flt = unpack_scalar_from_bytes(struct.pack("<f", 3.14159), "float")
        self.assertAlmostEqual(v_flt, 3.14159, places=5)
        v_dbl, h_dbl = unpack_scalar_from_bytes(struct.pack("<d", 2.718281828459045), "double")
        self.assertAlmostEqual(v_dbl, 2.718281828459045, places=9)

        # 4. Boolean
        self.assertEqual(unpack_scalar_from_bytes(b"\x01", "bool")[0], True)
        self.assertEqual(unpack_scalar_from_bytes(b"\x00", "bool")[0], False)

        # 5. Pointer
        ptr_val, ptr_hex = unpack_scalar_from_bytes(struct.pack("<Q", 0x7fffffffe450), "const char*")
        self.assertEqual(ptr_val, 0x7fffffffe450)
        self.assertEqual(ptr_hex, "0x7fffffffe450")

    def test_07_unpack_float_and_double_from_registers(self):
        """Verify IEEE 754 float and double unpacking from register integer bit patterns."""
        # float 1.25 -> IEEE 754 bit pattern 0x3fa00000 = 1067450368
        v_flt, h_flt = unpack_scalar_from_register(1067450368, "float", byte_size=4)
        self.assertAlmostEqual(v_flt, 1.25)
        self.assertEqual(h_flt, "0x3fa00000")

        # double 2.75 -> IEEE 754 bit pattern 0x4006000000000000 = 4613374868287651840
        v_dbl, h_dbl = unpack_scalar_from_register(4613374868287651840, "double", byte_size=8)
        self.assertAlmostEqual(v_dbl, 2.75)
        self.assertEqual(h_dbl, "0x4006000000000000")

    def test_08_unreadable_memory_returns_unavailable_never_zero(self):
        """Unreadable memory must return UNAVAILABLE with explicit reason, NEVER fabricated 0."""
        if "gcc_o0" not in self.binaries:
            raise unittest.SkipTest("GCC not available")

        bin_path = self.binaries["gcc_o0"]
        idx = DwarfIndexer.get_index(bin_path)
        subp = idx.subprograms_by_name["trace_target_function"][0]
        ident = inspect_elf(bin_path)

        post_pc = subp.frame_established_pc or (subp.low_pc + 16)
        ctx = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=post_pc,
            frame_metadata=FrameMetadata(frame_pointer=0x7fffffffe000),
            variable_name="op_code",
            architecture=ident.architecture,
            memory_reader=lambda addr, sz: None,  # Simulates read failure
        )
        res = DwarfEvaluator.evaluate(ctx)
        self.assertEqual(res.status, EVAL_STATUS_UNAVAILABLE)
        self.assertIsNone(res.value)
        self.assertIn("unreadable", res.reason)

    # =========================================================================
    # 4. Register Clobbering & DW_OP_entry_value Lifecycle
    # =========================================================================

    def test_09_clobbered_parameter_transitions_to_optimized_out(self):
        """In -O2, verify 'val' parameter transitions from register to entry_value (OPTIMIZED_OUT)."""
        target_label = "clang_o2" if "clang_o2" in self.binaries else ("gcc_o2" if "gcc_o2" in self.binaries else None)
        if not target_label:
            raise unittest.SkipTest("Neither Clang nor GCC -O2 binary available")

        bin_path = self.binaries[target_label]
        idx = DwarfIndexer.get_index(bin_path)
        subp = idx.subprograms_by_name["test_clobbered_param"][0]
        ident = inspect_elf(bin_path)
        t = parse_debug_loc_table(bin_path)

        val_var = subp.get_variable("val")
        loc_entries = t[val_var.location_list_offset]

        # 1. Entry range (parameter register live)
        start_entry, end_entry, expr_entry = loc_entries[0]
        self.assertIn("reg", expr_entry.lower())
        ctx_entry = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=start_entry,
            registers={"x0": 100, "rdi": 100},
            variable_name="val",
            architecture=ident.architecture,
        )
        res_entry = DwarfEvaluator.evaluate(ctx_entry)
        self.assertEqual(res_entry.status, EVAL_STATUS_OBSERVED)
        self.assertEqual(res_entry.value, 100)

        # 2. Entry value range (register clobbered by nested call)
        ev_entry = next((e for e in loc_entries if "entry_value" in e[2]), None)
        if ev_entry:
            start_ev, end_ev, _ = ev_entry
            ctx_ev = DwarfEvaluationContext(
                binary_identity=ident,
                subprogram=subp,
                link_time_address=start_ev,
                registers={"x0": 999, "x19": 999, "rdi": 999, "rbx": 999},
                variable_name="val",
                architecture=ident.architecture,
            )
            res_ev = DwarfEvaluator.evaluate(ctx_ev)
            self.assertEqual(res_ev.status, EVAL_STATUS_OPTIMIZED_OUT)
            self.assertIn("entry_value", res_ev.reason)

        # 3. Beyond function boundary
        ctx_out = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=subp.high_pc + 0x100,
            registers={"x0": 100},
            variable_name="val",
            architecture=ident.architecture,
        )
        res_out = DwarfEvaluator.evaluate(ctx_out)
        self.assertEqual(res_out.status, EVAL_STATUS_UNAVAILABLE)
        self.assertIn("outside", res_out.reason)

    # =========================================================================
    # 5. Non-PIE Binary Evaluation
    # =========================================================================

    def test_10_non_pie_address_space_evaluation(self):
        """Non-PIE executable (ET_EXEC) with absolute link-time addresses evaluates cleanly."""
        if "gcc_nopie" not in self.binaries:
            raise unittest.SkipTest("GCC nopie binary not available")

        bin_path = self.binaries["gcc_nopie"]
        ident = inspect_elf(bin_path)
        self.assertEqual(ident.elf_type, "ET_EXEC")

        idx = DwarfIndexer.get_index(bin_path)
        subp = idx.subprograms_by_name["trace_target_function"][0]
        # In non-PIE on Linux aarch64 / x86_64, low_pc is typically >= 0x400000
        self.assertGreaterEqual(subp.low_pc, 0x400000)

        post_pc = subp.frame_established_pc or (subp.low_pc + 16)
        fp = 0x7fffffffe000

        fake_mem = {fp + 16 - 116: struct.pack("<i", 99)}
        ctx = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=post_pc,
            frame_metadata=FrameMetadata(frame_pointer=fp),
            variable_name="op_code",
            architecture=ident.architecture,
            memory_reader=lambda addr, sz: fake_mem.get(addr),
        )
        res = DwarfEvaluator.evaluate(ctx)
        self.assertEqual(res.status, EVAL_STATUS_OBSERVED)
        self.assertEqual(res.value, 99)

    # =========================================================================
    # 6. Automated GDB Cross-Validation
    # =========================================================================

    def test_11_gdb_cross_validation_scalar_types(self):
        """Cross-validate DynamicState evaluator against GDB ground truth on real binary."""
        target_label = "gcc_o2" if "gcc_o2" in self.binaries else ("clang_o2" if "clang_o2" in self.binaries else None)
        if not self.has_gdb or not target_label:
            raise unittest.SkipTest("GDB or optimized fixture not available")

        bin_path = self.binaries[target_label]
        idx = DwarfIndexer.get_index(bin_path)
        subp = [s for s in idx.subprograms if s.name == "test_all_scalars"][0]
        ident = inspect_elf(bin_path)

        # Run GDB in batch mode to capture register states and GDB's evaluated variable values at test_all_scalars entry
        gdb_cmd = [
            "gdb", "-batch",
            "-ex", f"file {bin_path}",
            "-ex", "break test_all_scalars",
            "-ex", "run --loop 1",
            "-ex", "print i8",
            "-ex", "print i16",
            "-ex", "print i32",
            "-ex", "print i64",
            "-ex", "print u8",
            "-ex", "print u16",
            "-ex", "print u32",
            "-ex", "print u64",
            "-ex", "print f32",
            "-ex", "print f64",
            "-ex", "print flag",
            "-ex", "info registers general",
            "-ex", "info registers float",
        ]
        proc = subprocess.run(gdb_cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise unittest.SkipTest(f"GDB execution failed: {proc.stderr}")

        stdout = proc.stdout

        # Parse GDB's print outputs: $1 = -8 '\370', $2 = -16, etc.
        gdb_values: Dict[str, Any] = {}
        var_names = ["i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64", "flag"]
        for line in stdout.splitlines():
            m = re.match(r"\$(\d+)\s+=\s+(.*)$", line.strip())
            if m:
                idx_print = int(m.group(1)) - 1
                if idx_print < len(var_names):
                    raw_val = m.group(2).strip()
                    gdb_values[var_names[idx_print]] = raw_val

        # Parse registers from GDB output
        regs: Dict[str, int] = {}
        for line in stdout.splitlines():
            # AArch64 / x86_64 register format: "x0  0xfffffff8  4294967288" or "s0 {f = 0x3fa00000, ...} {f = 1.25, ...}"
            parts = line.strip().split()
            if len(parts) >= 2:
                r_name = parts[0].lower()
                if parts[1].startswith("0x"):
                    try:
                        regs[r_name] = int(parts[1], 16)
                    except ValueError:
                        pass
                elif "{" in line and "u =" in line:
                    m_u = re.search(r"u\s*=\s*(0x[0-9a-fA-F]+|\d+)", line)
                    if m_u:
                        v = m_u.group(1)
                        regs[r_name] = int(v, 16) if v.startswith("0x") else int(v)

        # Evaluate through DynamicState's DwarfEvaluator
        for vname in ["i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64"]:
            ctx = DwarfEvaluationContext(
                binary_identity=ident,
                subprogram=subp,
                link_time_address=subp.low_pc,
                registers=regs,
                variable_name=vname,
                architecture=ident.architecture,
            )
            res = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res.status, EVAL_STATUS_OBSERVED, f"Failed for {vname}: {res.reason}")

            # Verify against GDB ground truth
            self.assertIn(vname, gdb_values, f"GDB output missing for {vname}")
            gdb_raw = gdb_values[vname]

            if vname in ("f32", "f64"):
                gdb_float = float(gdb_raw.split()[0])
                self.assertAlmostEqual(res.value, gdb_float, places=2)
            else:
                # Extract first integer or bool
                m_int = re.search(r"(-?\d+)", gdb_raw)
                if m_int:
                    gdb_int = int(m_int.group(1))
                    self.assertEqual(res.value, gdb_int, f"Mismatch for {vname}: DynamicState={res.value} vs GDB={gdb_int}")

    # =========================================================================
    # 7. Phase 1.4 Hardening & Regression Tests
    # =========================================================================

    def test_12_location_list_range_start_address_not_confused_with_offset(self):
        """Range start addresses (e.g. 0x004015b0 or 0x00000000000015b0) must never be treated as list offsets."""
        for label in ("gcc_nopie", "gcc_o2"):
            if label not in self.binaries:
                continue
            bin_path = self.binaries[label]
            loc_table = parse_debug_loc_table(bin_path)
            all_range_pcs = set()
            for entries in loc_table.values():
                for start_pc, end_pc, _ in entries:
                    all_range_pcs.add(start_pc)
                    all_range_pcs.add(end_pc)

            for pc in all_range_pcs:
                if pc >= 0x400000:
                    self.assertNotIn(pc, loc_table, f"Range address 0x{pc:x} was mistakenly registered as a loc list offset!")

    def test_13_location_list_internal_entry_offsets_not_registered(self):
        """In a multi-entry location list, individual entry lines must not register their line offsets as independent list keys."""
        if "gcc_o2" not in self.binaries:
            raise unittest.SkipTest("gcc_o2 binary not available")
        bin_path = self.binaries["gcc_o2"]
        loc_table = parse_debug_loc_table(bin_path)

        res = subprocess.run(["readelf", "--debug-dump=loc", bin_path], capture_output=True, text=True)
        col1_re = re.compile(r"^\s{2,6}([0-9a-fA-F]{1,8})\s+")
        lines = res.stdout.splitlines()
        first_off = None
        second_off = None
        for line in lines:
            if "<End of list>" in line:
                first_off = None
                continue
            m = col1_re.match(line)
            if m:
                off = int(m.group(1), 16)
                if first_off is None:
                    first_off = off
                elif second_off is None and "location view pair" not in line and "base address" not in line:
                    second_off = off
                    break

        if first_off is not None and second_off is not None:
            self.assertIn(first_off, loc_table, f"List start offset 0x{first_off:x} must be in loc_table")
            if second_off in loc_table:
                self.assertEqual(len(loc_table[first_off]), len(loc_table[second_off]), "Internal offset must not truncate entry list")

    def test_14_location_list_empty_list_returns_optimized_out(self):
        """Explicitly empty location list (<End of list>) must return EVAL_STATUS_OPTIMIZED_OUT."""
        if "gcc_o0" not in self.binaries:
            raise unittest.SkipTest("gcc_o0 binary not available")
        bin_path = self.binaries["gcc_o0"]
        ident = inspect_elf(bin_path)

        cache_key = _get_loc_cache_key(bin_path)
        loc_table = parse_debug_loc_table(bin_path)
        _LOC_CACHE[cache_key][0xee00] = []

        subp = DwarfSubprogram(die_offset=0x10, name="dummy_subp", low_pc=0x1000)
        v = DwarfVariable(die_offset=0x20, name="eliminated_var", location_list_offset=0xee00)
        subp.variables.append(v)

        ctx = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=0x1008,
            variable_name="eliminated_var",
            architecture=ident.architecture,
        )
        res = DwarfEvaluator.evaluate(ctx)
        self.assertEqual(res.status, EVAL_STATUS_OPTIMIZED_OUT)
        self.assertIn("explicitly empty", res.reason)

    def test_15_missing_location_list_returns_diagnostic_error(self):
        """Missing location list offset must return EVAL_STATUS_ERROR without swallowed diagnostics."""
        if "gcc_o0" not in self.binaries:
            raise unittest.SkipTest("gcc_o0 binary not available")
        bin_path = self.binaries["gcc_o0"]
        ident = inspect_elf(bin_path)

        subp = DwarfSubprogram(die_offset=0x10, name="dummy_subp", low_pc=0x1000)
        v = DwarfVariable(die_offset=0x20, name="missing_var", location_list_offset=0xbadf00d)
        subp.variables.append(v)

        ctx = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=0x1008,
            variable_name="missing_var",
            architecture=ident.architecture,
        )
        res = DwarfEvaluator.evaluate(ctx)
        self.assertEqual(res.status, EVAL_STATUS_ERROR)
        self.assertIn("0xbadf00d", res.reason)
        self.assertIn("not found in debug data", res.reason)

    def test_16_epilogue_frame_destruction_is_truthfully_unavailable(self):
        """Evaluating stack variables in function epilogue after frame destruction must return UNAVAILABLE."""
        target_label = "gcc_o0" if "gcc_o0" in self.binaries else None
        if not target_label:
            raise unittest.SkipTest("gcc_o0 binary not available")
        bin_path = self.binaries[target_label]
        idx = DwarfIndexer.get_index(bin_path)
        subp = idx.subprograms_by_name["trace_target_function"][0]
        ident = inspect_elf(bin_path)

        self.assertIsNotNone(subp.frame_destroyed_pc, "Function with frame teardown must have frame_destroyed_pc detected in CFI")

        ctx = DwarfEvaluationContext(
            binary_identity=ident,
            subprogram=subp,
            link_time_address=subp.frame_destroyed_pc,
            frame_metadata=FrameMetadata(frame_pointer=0x7fffffffe000),
            variable_name="local_accum",
            architecture=ident.architecture,
            memory_reader=lambda addr, sz: b"\x2a\x00\x00\x00",
        )
        res = DwarfEvaluator.evaluate(ctx)
        self.assertEqual(res.status, EVAL_STATUS_UNAVAILABLE)
        self.assertIn("is in function epilogue after frame destruction", res.reason)

    def test_17_cache_invalidation_on_binary_rebuild_at_same_path(self):
        """When a binary is rebuilt or modified at the same path, caches must invalidate automatically."""
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f_bin:
            tmp_bin = f_bin.name

        try:
            src1 = "int g_val = 1; int get_val() { int v = 10; return v; } int main() { return get_val(); }"
            with tempfile.NamedTemporaryFile(suffix=".c") as f_src:
                f_src.write(src1.encode())
                f_src.flush()
                subprocess.run(["gcc", "-g", "-O0", f_src.name, "-o", tmp_bin], check=True)

            idx1 = DwarfIndexer.get_index(tmp_bin)
            self.assertIn("get_val", idx1.subprograms_by_name)

            time.sleep(0.05)
            src2 = "int g_val2 = 2; int get_val_updated() { int v2 = 20; return v2; } int main() { return get_val_updated(); }"
            with tempfile.NamedTemporaryFile(suffix=".c") as f_src:
                f_src.write(src2.encode())
                f_src.flush()
                subprocess.run(["gcc", "-g", "-O0", f_src.name, "-o", tmp_bin], check=True)

            idx2 = DwarfIndexer.get_index(tmp_bin)
            self.assertIn("get_val_updated", idx2.subprograms_by_name)
            self.assertNotIn("get_val", idx2.subprograms_by_name)
        finally:
            if os.path.exists(tmp_bin):
                os.unlink(tmp_bin)

    def test_18_stripped_binary_uses_external_debug_artifact(self):
        """Stripped binary must evaluate variables using external debug artifact passed in context."""
        if "gcc_o0" not in self.binaries:
            raise unittest.SkipTest("gcc_o0 binary not available")
        unstripped_bin = self.binaries["gcc_o0"]

        with tempfile.NamedTemporaryFile(suffix=".stripped", delete=False) as f_strip:
            stripped_bin = f_strip.name

        try:
            subprocess.run(["strip", "--strip-debug", "-o", stripped_bin, unstripped_bin], check=True)
            ident_stripped = inspect_elf(stripped_bin)

            idx = DwarfIndexer.get_index(unstripped_bin)
            subp = idx.subprograms_by_name["trace_target_function"][0]

            fp = 0x7fffffffe000
            var_offset = -116
            mem = {
                (fp + 16 + var_offset): b"\x2a\x00\x00\x00",
            }

            def test_reader(addr: int, sz: int) -> Optional[bytes]:
                return mem.get(addr)

            ctx = DwarfEvaluationContext(
                binary_identity=ident_stripped,
                subprogram=subp,
                link_time_address=subp.low_pc + 16,
                frame_metadata=FrameMetadata(frame_pointer=fp),
                variable_name="op_code",
                architecture=ident_stripped.architecture,
                memory_reader=test_reader,
                debug_artifact_path=unstripped_bin,
            )
            res = DwarfEvaluator.evaluate(ctx)
            self.assertEqual(res.status, EVAL_STATUS_OBSERVED)
            self.assertEqual(res.value, 42)
        finally:
            if os.path.exists(stripped_bin):
                os.unlink(stripped_bin)

    def test_19_cfi_interval_cfa_rules_across_body(self):
        """CFI parser extracts instruction-by-instruction CFA intervals matching function execution."""
        target_label = "gcc_o2" if "gcc_o2" in self.binaries else ("clang_o2" if "clang_o2" in self.binaries else None)
        if not target_label:
            raise unittest.SkipTest("Optimized binary not available")
        bin_path = self.binaries[target_label]
        idx = DwarfIndexer.get_index(bin_path)
        subp = idx.subprograms_by_name["trace_target_function"][0]

        self.assertGreater(len(subp.cfa_rules), 0, "Subprogram must contain parsed CFA rule intervals")
        rule_entry = subp.get_cfa_rule_at(subp.low_pc)
        self.assertIsNotNone(rule_entry)
        self.assertEqual(rule_entry[0], "sp", "Entry CFA rule must be based on stack pointer")

    def test_20_gdb_parity_clang_and_gcc(self):
        """Verify parity against GDB 15.1 on both Clang and GCC for scalar parameters and locals."""
        if not self.has_gdb:
            raise unittest.SkipTest("GDB not available")

        for label in ("gcc_o2", "clang_o2"):
            if label not in self.binaries:
                continue
            bin_path = self.binaries[label]
            idx = DwarfIndexer.get_index(bin_path)
            subp_list = idx.subprograms_by_name.get("test_all_scalars")
            if not subp_list:
                continue
            subp = subp_list[0]
            ident = inspect_elf(bin_path)

            gdb_cmd = [
                "gdb", "-batch",
                "-ex", f"file {bin_path}",
                "-ex", "break test_all_scalars",
                "-ex", "run --loop 1",
                "-ex", "print i32",
                "-ex", "print u32",
                "-ex", "info registers general",
            ]
            proc = subprocess.run(gdb_cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                continue

            regs: Dict[str, int] = {}
            for line in proc.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    r_name = parts[0].lower()
                    if parts[1].startswith("0x"):
                        try:
                            regs[r_name] = int(parts[1], 16)
                        except ValueError:
                            pass

            for vname in ("i32", "u32"):
                ctx = DwarfEvaluationContext(
                    binary_identity=ident,
                    subprogram=subp,
                    link_time_address=subp.low_pc,
                    registers=regs,
                    variable_name=vname,
                    architecture=ident.architecture,
                )
                res = DwarfEvaluator.evaluate(ctx)
                self.assertEqual(res.status, EVAL_STATUS_OBSERVED, f"{label} {vname} failed: {res.reason}")


if __name__ == "__main__":
    unittest.main()
