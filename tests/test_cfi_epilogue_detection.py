"""frame_destroyed_pc (CFI epilogue) detection for x86_64 and aarch64 objects.

x86_64 `pop %rbp; ret` is encoded as `DW_CFA_def_cfa: r7 (rsp) ofs 8` with no DW_CFA_restore, aarch64
`ldp x29, x30, [sp], #n; ret` as DW_CFA_restore + def_cfa_offset 0.  Both mean "the CFA rule is back to the CIE
entry state after the frame was set up".  Expected values are derived from `readelf --debug-dump=frames-interp`
rows of the same object, so the test does not hard-code compiler output.
"""
import os
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

from extractor.dwarf_indexer import parse_cfi_table

SIMPLE = "int g(int);\nint simple(int a){ int x = a; x += g(a); return x; }\n"
# early return: gcc/clang -O2 wrap the early epilogue in DW_CFA_remember_state / DW_CFA_restore_state
EARLY = "int g(int);\nint early(int a){ if (a < 0) return g(a)+1; int x = g(a); return x*3+g(x); }\n"

_ROW = re.compile(r"^([0-9a-f]{16})\s+(\S+)")


def _interp_rows(obj):
    out = subprocess.run(["readelf", "--debug-dump=frames-interp", obj], capture_output=True, text=True).stdout
    fdes, cur = [], None
    for line in out.splitlines():
        if " FDE " in line:
            cur = []
            fdes.append(cur)
        elif cur is not None:
            m = _ROW.match(line)
            if m:
                cur.append((int(m.group(1), 16), m.group(2)))
    return fdes


def _expected_destroyed_pc(rows):
    """The frame is gone where the last row's CFA is the entry rule again after having changed."""
    if len(rows) > 1 and rows[-1][1] == rows[0][1]:
        return rows[-1][0]
    return None


class TestCfiEpilogueDetection(unittest.TestCase):
    def _compile_and_check(self, cmd, arch, source, flags):
        exe = cmd[0]
        if shutil.which(exe) is None or shutil.which("readelf") is None:
            self.skipTest(f"{exe} not available")
        with tempfile.TemporaryDirectory(prefix="dynstate_cfi_") as tmp:
            src = os.path.join(tmp, "t.c")
            obj = os.path.join(tmp, "t.o")
            with open(src, "w") as f:
                f.write(source)
            r = subprocess.run(cmd + ["-g", "-fno-omit-frame-pointer", *flags, "-c", src, "-o", obj],
                               capture_output=True, text=True)
            if r.returncode != 0:
                self.skipTest(f"cannot compile with {' '.join(cmd)}: {r.stderr[-200:]}")
            fdes = _interp_rows(obj)
            self.assertEqual(len(fdes), 1)
            expected = _expected_destroyed_pc(fdes[0])
            if arch == "x86_64":
                self.assertIsNotNone(expected, "fixture must contain a frame teardown")
            # (older aarch64 clang emits no epilogue CFI at all: then readelf shows no teardown and neither may we)
            table = parse_cfi_table(obj, arch)
            self.assertEqual(len(table), 1)
            fde = next(iter(table.values()))
            self.assertIsNotNone(fde["frame_established_pc"])
            self.assertEqual(fde["frame_destroyed_pc"], expected)
            if expected is not None:
                self.assertGreater(expected, fde["frame_established_pc"])
            return fde

    # ---- x86_64 objects (cross compilers; readelf reads foreign ELF) ----
    def test_x86_64_gcc_o0(self):
        self._compile_and_check(["x86_64-linux-gnu-gcc"], "x86_64", SIMPLE, ["-O0"])

    def test_x86_64_gcc_o2(self):
        self._compile_and_check(["x86_64-linux-gnu-gcc"], "x86_64", SIMPLE, ["-O2"])

    def test_x86_64_gcc_o2_early_return_uses_final_epilogue(self):
        fde = self._compile_and_check(["x86_64-linux-gnu-gcc"], "x86_64", EARLY, ["-O2"])
        # the early-return epilogue sits inside DW_CFA_remember_state/restore_state and must not win
        self.assertGreater(fde["frame_destroyed_pc"], fde["high_pc"] // 2)

    def test_x86_64_clang_o0(self):
        self._compile_and_check(["clang", "--target=x86_64-linux-gnu"], "x86_64", SIMPLE, ["-O0"])

    def test_x86_64_clang_o2(self):
        self._compile_and_check(["clang", "--target=x86_64-linux-gnu"], "x86_64", SIMPLE, ["-O2"])

    def test_x86_64_clang_o2_early_return(self):
        self._compile_and_check(["clang", "--target=x86_64-linux-gnu"], "x86_64", EARLY, ["-O2"])

    # ---- native objects (aarch64 on the dev host, x86_64 on the CI runner) ----
    def _native_arch(self):
        m = platform.machine()
        return "aarch64" if m in ("aarch64", "arm64") else "x86_64"

    def test_native_gcc_o0(self):
        self._compile_and_check(["gcc"], self._native_arch(), SIMPLE, ["-O0"])

    def test_native_gcc_o2(self):
        self._compile_and_check(["gcc"], self._native_arch(), SIMPLE, ["-O2"])

    def test_native_gcc_o2_early_return(self):
        self._compile_and_check(["gcc"], self._native_arch(), EARLY, ["-O2"])

    def test_native_clang_o0(self):
        self._compile_and_check(["clang"], self._native_arch(), SIMPLE, ["-O0"])

    def test_native_clang_o2(self):
        self._compile_and_check(["clang"], self._native_arch(), SIMPLE, ["-O2"])


class TestCfiNoFramePointerHasNoEpilogue(unittest.TestCase):
    def test_leaf_without_frame_pointer(self):
        if shutil.which("x86_64-linux-gnu-gcc") is None:
            self.skipTest("x86_64-linux-gnu-gcc not available")
        with tempfile.TemporaryDirectory(prefix="dynstate_cfi_") as tmp:
            src = os.path.join(tmp, "t.c")
            obj = os.path.join(tmp, "t.o")
            with open(src, "w") as f:
                f.write("int leaf(int a){ return a * 3 + 1; }\n")
            subprocess.run(["x86_64-linux-gnu-gcc", "-g", "-O2", "-fomit-frame-pointer", "-c", src, "-o", obj],
                           check=True)
            fde = next(iter(parse_cfi_table(obj, "x86_64").values()))
            self.assertIsNone(fde["frame_established_pc"])
            self.assertIsNone(fde["frame_destroyed_pc"])


if __name__ == "__main__":
    unittest.main()
