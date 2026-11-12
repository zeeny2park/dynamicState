"""Binary (section-bytes) location-list reader: independent of the readelf version.

Reproducer: clang 14 (Ubuntu 22.04 runner) emits DWARF 5 DW_FORM_loclistx, which binutils 2.38 cannot decode
("Warning: Unrecognized form: 0x22"), so readelf-text scraping finds no lists.  The checked-in fixture is an
x86_64 executable linked from clang 14 output (tests/fixtures/dwarf/loclist_clobbered.c, -O2 -g, DWARF 5).
"""
import os
import shutil
import subprocess
import tempfile
import unittest

from extractor.dwarf_evaluator import clear_loc_cache, parse_debug_loc_table
from extractor.dwarf_indexer import DwarfIndexer
from extractor.dwarf_loclists_binary import read_location_lists

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE_DIR = os.path.join(HERE, "fixtures", "dwarf")
CLANG14_ELF = os.path.join(FIXTURE_DIR, "clang14_x86_64_loclistx.elf")
SRC = os.path.join(FIXTURE_DIR, "loclist_clobbered.c")


class TestBinaryLocationListsFixture(unittest.TestCase):
    def test_loclistx_lists_are_read_from_section_bytes(self):
        d = read_location_lists(CLANG14_ELF)
        self.assertEqual(len(d.table), 4)
        self.assertEqual(len(d.by_die), 4)
        exprs = [e for entries in d.table.values() for (_s, _e, e) in entries]
        # 'val' arrives in rdi and is then kept in a callee-saved register, finally only as an entry value.
        self.assertIn("DW_OP_reg5 (rdi)", exprs)
        self.assertIn("DW_OP_reg3 (rbx)", exprs)
        self.assertIn("DW_OP_entry_value: (DW_OP_reg5 (rdi)); DW_OP_stack_value", exprs)
        for entries in d.table.values():
            for start, end, _expr in entries:
                self.assertLess(start, end)
                self.assertGreaterEqual(start, 0x400000)  # linked address, i.e. addrx / base address resolved

    def test_parse_debug_loc_table_and_indexer_use_them(self):
        clear_loc_cache()
        table = parse_debug_loc_table(CLANG14_ELF)
        self.assertGreater(len(table), 0)
        idx = DwarfIndexer.get_index(CLANG14_ELF)
        subp = idx.subprograms_by_name["clobbered"][0]
        val = subp.get_variable("val")
        self.assertIsNotNone(val)
        self.assertIsNotNone(val.location_list_offset)
        self.assertIn(val.location_list_offset, table)
        entries = table[val.location_list_offset]
        self.assertEqual(entries[0][0], subp.low_pc)
        self.assertIn("rdi", entries[0][2])
        self.assertTrue(any("entry_value" in e[2] for e in entries))

    def test_garbage_input_returns_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".bin") as f:
            f.write(b"not an elf")
            f.flush()
            d = read_location_lists(f.name)
        self.assertEqual(d.table, {})
        self.assertEqual(d.by_die, {})


class TestBinaryVsReadelfParity(unittest.TestCase):
    """Where the installed readelf can decode a list, the binary reader must agree on ranges and expressions."""

    def _check(self, compiler, flags):
        if shutil.which(compiler) is None or shutil.which("readelf") is None:
            self.skipTest(f"{compiler} not available")
        with tempfile.TemporaryDirectory(prefix="dynstate_loclists_") as tmp:
            out = os.path.join(tmp, "a.out")
            r = subprocess.run([compiler, "-g", "-O2", *flags, SRC, "-o", out, "-nostartfiles",
                                "-Wl,-e,clobbered", "-Wl,--unresolved-symbols=ignore-all"],
                               capture_output=True, text=True)
            if r.returncode != 0:
                self.skipTest(f"cannot link fixture with {compiler}: {r.stderr[-200:]}")
            clear_loc_cache()
            d = read_location_lists(out)
            self.assertGreater(len(d.table), 0)
            self.assertGreater(len(d.by_die), 0)
            text = parse_debug_loc_table(out)
            shared = [k for k in d.table if k in text]
            for k in shared:
                self.assertEqual([(s, e) for s, e, _ in d.table[k]], [(s, e) for s, e, _ in text[k]], hex(k))
                for (_, _, mine), (_, _, theirs) in zip(d.table[k], text[k]):
                    # same register/op mnemonics modulo readelf's cosmetic suffixes
                    self.assertEqual(mine.split(" ")[0], theirs.split(" ")[0])
            # every list the binary reader found is present in the evaluator's table (readelf or fallback)
            for k in d.table:
                self.assertIn(k, text)

    def test_gcc_dwarf5(self):
        self._check("gcc", ["-gdwarf-5"])

    def test_gcc_dwarf4(self):
        self._check("gcc", ["-gdwarf-4"])

    def test_clang_dwarf5(self):
        self._check("clang", ["-gdwarf-5"])


if __name__ == "__main__":
    unittest.main()
