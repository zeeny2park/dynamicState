"""DW_AT_decl_file is an index into the file table of the DIE's own compilation unit.

With one merged table (last unit wins) every function and variable of a multi-file program was attributed to a file
of the last unit: definitions reported in the wrong file, and the static location candidates read the wrong source.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

from extractor.dwarf_indexer import DwarfIndexer

A_C = """#include "shared.h"
int a_state;
static int a_helper(int x) { return x + shared_value; }
int a_entry(int x)
{
    return a_helper(x) + a_state;
}
"""
B_C = """#include "shared.h"
int shared_value = 3;
int b_state;
int b_entry(int x)
{
    b_state += x;
    return b_state;
}
int a_entry(int x);
int main(void) { return a_entry(1) + b_entry(2) > 100; }
"""
SHARED_H = """extern int shared_value;
static inline int shared_twice(int v) { return 2 * v; }
"""


@unittest.skipUnless(shutil.which("gcc") and shutil.which("readelf"), "gcc/readelf not available")
class TestMultiUnitDeclFile(unittest.TestCase):
    def test_functions_and_variables_keep_their_own_file(self):
        tmp = tempfile.mkdtemp(prefix="dwmcu_")
        self.addCleanup(shutil.rmtree, tmp, True)
        for name, text in (("a.c", A_C), ("b.c", B_C), ("shared.h", SHARED_H)):
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                out = os.path.join(tmp, "prog" + opt)
                subprocess.run(["gcc", "-g", opt, "a.c", "b.c", "-o", out], cwd=tmp, check=True)
                idx = DwarfIndexer.get_index(out, use_disk_cache=False)
                files = {}
                for sp in idx.subprograms:
                    if sp.name in ("a_entry", "a_helper", "b_entry", "main") and sp.decl_file and not sp.is_declaration:
                        files.setdefault(sp.name, set()).add(os.path.basename(sp.decl_file))
                self.assertEqual(files.get("a_entry"), {"a.c"}, files)
                self.assertEqual(files.get("b_entry"), {"b.c"}, files)
                self.assertEqual(files.get("main"), {"b.c"}, files)
                if "a_helper" in files:
                    self.assertEqual(files["a_helper"], {"a.c"}, files)
                vars_ = {v.name: os.path.basename(v.decl_file or "") for v in idx.global_variables
                         if v.name in ("a_state", "b_state") and not v.is_declaration}
                self.assertEqual(vars_, {"a_state": "a.c", "b_state": "b.c"})


if __name__ == "__main__":
    unittest.main()
