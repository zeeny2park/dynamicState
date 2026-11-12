"""IMP-011: CFI-based call stacks (local part: blocked-thread CFI unwinding, labelled scan fallback,
labelled running-thread samples, CFA-based frame locals, per-architecture handling).

Three layers:

1. ``TestCfaProgramOracle`` - the DW_CFA interpreter in extractor/cfi_unwinder.py is compared row by row
   with ``readelf --debug-dump=frames-interp`` for the native fixtures, the native libc and, when an
   x86_64 cross compiler is installed, x86_64 objects and the x86_64 libc (not executed: table check).
2. ``TestSyntheticX86Unwind`` - x86_64 fixtures are cross-compiled (-O0 and -O2 -fomit-frame-pointer)
   and a stack snapshot is synthesised from their real CFI with stale decoy frame records everywhere;
   the unwinder must return the exact chain from a futex-wait leaf to main (x86 code is not executed).
3. ``TestRealProcessCfiUnwind`` - REAL processes of the native architecture (fixtures compiled at test
   time with gcc -g -O0 and -g -O2 -fomit-frame-pointer, plus builds whose middle functions have no CFI):
   ground-truth call stacks, estimated marking, futex syscall name, frame parameters/locals, running
   thread labelling and unwinding cost.
"""

import os
import platform
import re
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from extractor.cfi_unwinder import (
    CfiUnwinder,
    ElfImage,
    R_OFFSET,
    R_REGISTER,
    R_SAME,
    R_UNDEFINED,
    R_VAL_OFFSET,
    UNWIND_CFI,
    UNWIND_CFI_AFTER_SCAN,
    UNWIND_FRAME_POINTER,
    UNWIND_REGISTERS,
    UNWIND_RUNNING,
    UNWIND_SCAN,
    decode_call_before,
    load_elf_image,
    make_unwinder_for_process,
    parse_proc_syscall,
)
from extractor.dwarf_indexer import DwarfIndexer
from extractor.target_abi import (
    FEATURE_CFI_UNWIND,
    FEATURE_FRAME_LAYOUT,
    LIBC_GLIBC,
    SUPPORT_NOT_SUPPORTED_ON_TARGET,
    SUPPORT_SUPPORTED,
    DETECTION_DETECTED,
    TargetABI,
    check_support,
)
from extractor.target_adapter import LocalTargetAdapter
from extractor.watch_session import WatchSessionManager

_NATIVE = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(
    platform.machine().lower()
)
_GCC = shutil.which("gcc")
_READELF = shutil.which("readelf")
_X86_CC = shutil.which("x86_64-linux-gnu-gcc") or (shutil.which("gcc") if _NATIVE == "x86_64" else None)
_FUTEX_NR = {"x86_64": 202, "aarch64": 98}

# --------------------------------------------------------------------------------------------
# Fixture sources
# --------------------------------------------------------------------------------------------
# main -> level_a -> level_b -> level_c -> level_d -> pthread_mutex_lock (blocks in futex).
# Before the chain runs, imp011_decoy_deep() recurses 24 levels deeper than the real chain and
# returns, leaving stale-but-plausible frame records / return addresses below main's stack pointer;
# level_d keeps an uninitialised 512-byte buffer that still holds them, inside a LIVE frame.
REAL_MAIN_SRC = r"""
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#define NOIPA __attribute__((noipa))

pthread_mutex_t g_imp011_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int g_holder_ready = 0;
volatile long g_sink = 0;

long imp011_level_b(int b_param);

NOIPA long imp011_decoy_deep(int n, long acc) {
    volatile char pad[200];
    pad[0] = (char)n;
    if (n > 0) acc += imp011_decoy_deep(n - 1, acc + pad[0]);
    g_sink += acc;
    return acc + 1;
}

NOIPA long imp011_level_d(int d_param) {
    volatile char scratch[512];     /* uninitialised on purpose: holds the decoy chain's stale frames */
    volatile int d_local = 4444;
    scratch[0] = (char)d_param;
    pthread_mutex_lock(&g_imp011_mutex);   /* blocks: the holder thread owns the mutex */
    g_sink += d_local + scratch[0];
    return g_sink;
}

NOIPA long imp011_level_a(int a_param) {
    volatile int a_local = 1111;
    long r = imp011_level_b(a_param + 1);
    g_sink += a_local;
    return r + a_local;
}

NOIPA void *imp011_holder(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_imp011_mutex);
    g_holder_ready = 1;
    for (;;) pause();
    return 0;
}

NOIPA long imp011_spin_step(long v) { return v + 1; }

NOIPA long imp011_spin_outer(long v) {   /* non-leaf: keeps its return address on the stack */
    for (int i = 0; i < 1000; i++) v = imp011_spin_step(v);
    return v;
}

NOIPA void *imp011_spinner(void *arg) {
    (void)arg;
    long v = 0;
    for (;;) { v = imp011_spin_outer(v); g_sink = v; }
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    pthread_t th;
    pthread_create(&th, 0, imp011_holder, 0);
    if (argc > 1) pthread_create(&th, 0, imp011_spinner, 0);
    while (!g_holder_ready) usleep(1000);
    imp011_decoy_deep(24, argc);
    printf("READY\n");
    fflush(stdout);
    long r = imp011_level_a(1000);
    printf("%ld\n", r);
    return 0;
}
"""

# level_b / level_c live in their own translation unit so that they can be built without CFI.
REAL_MID_SRC = r"""
#define NOIPA __attribute__((noipa))
extern volatile long g_sink;
long imp011_level_d(int d_param);

NOIPA long imp011_level_c(int c_param) {
    volatile int c_local = 3333;
    long r = imp011_level_d(c_param + 1);
    g_sink += c_local;
    return r + c_local;
}

NOIPA long imp011_level_b(int b_param) {
    volatile int b_local = 2222;
    long r = imp011_level_c(b_param + 1);
    g_sink += b_local;
    return r + b_local;
}
"""

GROUND_TRUTH = ["imp011_level_d", "imp011_level_c", "imp011_level_b", "imp011_level_a", "main"]
KNOWN_VALUES = {
    "imp011_level_a": {"a_param": 1000, "a_local": 1111},
    "imp011_level_b": {"b_param": 1001, "b_local": 2222},
    "imp011_level_c": {"c_param": 1002, "c_local": 3333},
    "imp011_level_d": {"d_param": 1003, "d_local": 4444},
}

# x86_64 synthetic fixture (never executed): a "libc-like" wait path compiled -O2 without frame pointer
# (frame 0 is right after the `syscall` instruction, rbp is NOT saved there - like glibc's wrappers),
# then the user chain.  _start / decoys exist only so that the binary links and call sites exist.
X86_LIB_SRC = r"""
#define NOIPA __attribute__((noipa))
NOIPA long fake_futex_wait(long *uaddr, long val) {
    register long r10 __asm__("r10") = 0;
    long ret;
    __asm__ volatile ("syscall" : "=a"(ret) : "a"(202L), "D"(uaddr), "S"(128L), "d"(val), "r"(r10)
                      : "rcx", "r11", "memory");
    return ret;
}
NOIPA long fake_mutex_lock(long *m) {   /* minimal register use: rbp is never saved on this path */
    return fake_futex_wait(m, 2) + 1;
}
"""

X86_USER_SRC = r"""
#define NOIPA __attribute__((noipa))
long fake_mutex_lock(long *m);
long g_m;
volatile long g_sink;
NOIPA long imp011_decoy_deep(int n, long acc) {
    volatile char pad[200]; pad[0] = (char)n;
    if (n > 0) acc += imp011_decoy_deep(n - 1, acc + pad[0]);
    g_sink += acc; return acc + 1;
}
NOIPA long imp011_level_d(int d_param) {
    volatile char scratch[512]; volatile int d_local = 4444; scratch[0] = (char)d_param;
    long r = fake_mutex_lock(&g_m); g_sink += d_local + scratch[0] + r; return g_sink;
}
NOIPA long imp011_level_c(int p) { volatile int l = 3333; long r = imp011_level_d(p + 1); g_sink += l; return r + l; }
NOIPA long imp011_level_b(int p) { volatile int l = 2222; long r = imp011_level_c(p + 1); g_sink += l; return r + l; }
NOIPA long imp011_level_a(int p) { volatile int l = 1111; long r = imp011_level_b(p + 1); g_sink += l; return r + l; }
NOIPA int main(void) { imp011_decoy_deep(24, 1); return (int)imp011_level_a(1000); }
/* like glibc's _start: the outermost frame marks its return address undefined in CFI */
__asm__(".globl _start\n.type _start,@function\n_start:\n.cfi_startproc\n.cfi_undefined rip\n"
        "xor %ebp,%ebp\ncall main\nhlt\n.cfi_endproc\n.size _start,.-_start\n");
"""


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)


# --------------------------------------------------------------------------------------------
# readelf --debug-dump=frames-interp oracle
# --------------------------------------------------------------------------------------------
_X86_REGS = {"rax": 0, "rdx": 1, "rcx": 2, "rbx": 3, "rsi": 4, "rdi": 5, "rbp": 6, "rsp": 7,
             **{f"r{i}": i for i in range(8, 16)}, "rip": 16}
_A64_REGS = {**{f"x{i}": i for i in range(31)}, "sp": 31}


def _readelf_tables(path):
    """{fde pc_begin: [(loc, cfa_str, {reg: cell})]} parsed from readelf's interpreted frames."""
    # readelf may exit 1 on unrelated warnings (e.g. a missing separate debug file): use its output anyway
    out = subprocess.run([_READELF, "--debug-dump=frames-interp", path], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, check=False).stdout.decode("utf-8", "replace")
    tables = {}
    cur = None
    header = None
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ [0-9a-f]+ [0-9a-f]+ FDE cie=[0-9a-f]+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            cur = int(m.group(1), 16)
            tables[cur] = []
            header = None
            continue
        if re.match(r"^[0-9a-f]+ [0-9a-f]+ [0-9a-f]+ CIE", line):
            cur = None
            continue
        if cur is None:
            continue
        if line.strip().startswith("LOC"):
            header = line.split()[2:]  # after LOC CFA
            continue
        m = re.match(r"^([0-9a-f]{8,16}) +(\S+)(.*)$", line)
        if m and header is not None and "ZERO terminator" not in line:
            # DW_CFA_register cells read "r9 (r9)" / "r1 (rdx)": keep the "rN" part as one cell
            cells = [c.split(" ", 1)[0] for c in re.findall(r"r\d+ \([^)]*\)|\S+", m.group(3))]
            tables[cur].append((int(m.group(1), 16), m.group(2), dict(zip(header, cells))))
    return tables


def _cell_of(rule, names):
    if rule is None or rule[0] == R_UNDEFINED:
        return "u"
    kind, val = rule
    if kind == R_OFFSET:
        return f"c{val:+d}".replace("+", "+") if val >= 0 else f"c{val}"
    if kind == R_VAL_OFFSET:
        return f"v{val:+d}"
    if kind == R_SAME:
        return "s"
    if kind == R_REGISTER:
        return f"r{val}"  # readelf prints the DWARF register number here
    return "exp" if kind == "expression" else "vexp"


def _readelf_raw_fde_ops(path):
    """{fde pc_begin: [raw DW_CFA_* op lines]} from the plain (non-interpreted) frames dump, whose
    format is a simple op listing that is stable across binutils versions."""
    out = subprocess.run([_READELF, "--debug-dump=frames", path], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, check=False).stdout.decode("utf-8", "replace")
    ops, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ [0-9a-f]+ [0-9a-f]+ FDE cie=[0-9a-f]+ pc=([0-9a-f]+)\.\.", line)
        if m:
            cur = int(m.group(1), 16)
            ops[cur] = []
        elif re.match(r"^[0-9a-f]+ [0-9a-f]+ [0-9a-f]+ CIE", line):
            cur = None
        elif cur is not None and line.startswith("  DW_CFA_"):
            ops[cur].append(line.strip())
    return ops


def _ra_undefined_deferred_by_advance(raw_ops, ra_col):
    """True when the FDE program is `DW_CFA_advance_loc ...; DW_CFA_undefined <ra>`: per DWARF the RA is
    still the CIE rule (not undefined) at pc_begin and only becomes undefined at the advanced location
    (the `endbr64; cfi_undefined(rip)` shape of glibc's _start on CET toolchains)."""
    ops = [o for o in raw_ops if not o.startswith("DW_CFA_nop")]
    if not ops or not ops[0].startswith("DW_CFA_advance_loc"):
        return False
    return any(o.startswith("DW_CFA_undefined") and re.search(rf"\br{ra_col}\b", o) for o in ops[1:])


def _compare_with_readelf(testcase, path, max_fdes=None):
    img = load_elf_image(path)
    testcase.assertIsNotNone(img, path)
    names = {v: k for k, v in (_X86_REGS if img.arch == "x86_64" else _A64_REGS).items()}
    tables = _readelf_tables(path)
    fdes = {f.pc_begin: f for f in img.all_fdes() if f.source == ".eh_frame"}
    checked_rows = 0
    raw_ops_cache = {}
    keys = sorted(tables)
    if max_fdes:
        keys = keys[:: max(1, len(keys) // max_fdes)]
    for pc_begin in keys:
        rows = tables[pc_begin]
        fde = fdes.get(pc_begin)
        testcase.assertIsNotNone(fde, f"{path}: FDE 0x{pc_begin:x} not parsed")
        for loc, cfa_s, cells in rows:
            row = img.row_at(loc, fde)[1]
            if row.cfa_expr is not None:
                mine_cfa = "exp"
            else:
                mine_cfa = f"{names.get(row.cfa_reg, row.cfa_reg)}{row.cfa_offset:+d}"
            testcase.assertEqual(mine_cfa, cfa_s, f"{path} FDE 0x{pc_begin:x} loc 0x{loc:x} CFA")
            for col, cell in cells.items():
                reg = img_reg = (16 if img.arch == "x86_64" else 30) if col == "ra" else \
                    (_X86_REGS if img.arch == "x86_64" else _A64_REGS).get(col)
                if reg is None:
                    continue
                mine = _cell_of(row.rules.get(img_reg), names)
                if mine != cell and col == "ra" and cell == "u" and loc == pc_begin:
                    # Observed with binutils 2.38 (ubuntu-22.04): readelf prints the RA column as `u` already on
                    # the FDE's first row for `advance_loc; DW_CFA_undefined ra` programs (glibc _start/libc
                    # entry points), where DWARF says the CIE rule (c-8) holds until the advanced location.
                    # Not loosened blindly: the raw op listing must prove the undefined comes after an
                    # advance_loc, and our row at that later location must be `u`.
                    raw = raw_ops_cache.setdefault("ops", _readelf_raw_fde_ops(path)).get(pc_begin, [])
                    later = [r for r in rows if r[0] > pc_begin]
                    if (_ra_undefined_deferred_by_advance(raw, img_reg)
                            and later and _cell_of(img.row_at(later[0][0], fde)[1].rules.get(img_reg), names) == "u"):
                        continue
                testcase.assertEqual(mine, cell, f"{path} FDE 0x{pc_begin:x} loc 0x{loc:x} column {col}")
            checked_rows += 1
    return checked_rows


def _libc_path(arch):
    for p in (f"/usr/lib/{arch}-linux-gnu/libc.so.6", f"/lib/{arch}-linux-gnu/libc.so.6",
              f"/usr/{arch}-linux-gnu/lib/libc.so.6"):
        if os.path.isfile(p):
            return p
    return None


@unittest.skipUnless(_GCC and _READELF, "gcc and readelf are required")
class TestCfaProgramOracle(unittest.TestCase):
    """The DW_CFA interpreter agrees with readelf on every row of real tables."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp011_oracle_")
        for name, src in (("main.c", REAL_MAIN_SRC), ("mid.c", REAL_MID_SRC), ("xlib.c", X86_LIB_SRC),
                          ("xuser.c", X86_USER_SRC)):
            with open(os.path.join(cls.tmp, name), "w", encoding="utf-8") as fh:
                fh.write(src)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _exe(self, cc, srcs, flags, link):
        tag = "_".join(f.strip("-") for f in flags)
        out = os.path.join(self.tmp, f"{os.path.basename(cc)}_{srcs[0]}_{tag}")
        _run([cc, *flags, *[os.path.join(self.tmp, s) for s in srcs], *link, "-o", out])
        return out  # linked: readelf shows relocated FDE addresses

    def test_native_executables_and_libc_match_readelf(self):
        rows = 0
        for flags in (["-g", "-O0"], ["-g", "-O2", "-fomit-frame-pointer"]):
            rows += _compare_with_readelf(self, self._exe(_GCC, ["main.c", "mid.c"], flags, ["-pthread"]))
        libc = _libc_path(platform.machine())
        if libc:
            rows += _compare_with_readelf(self, libc)  # every FDE row of the native libc
        self.assertGreater(rows, 50)

    @unittest.skipUnless(_X86_CC, "no x86_64 compiler (cross or native) installed")
    def test_x86_64_executables_and_libc_match_readelf(self):
        """NOT EXECUTED on non-x86 hosts: x86_64 tables are only interpreted and compared."""
        rows = 0
        for flags in (["-g", "-O0"], ["-g", "-O2", "-fomit-frame-pointer"]):
            rows += _compare_with_readelf(self, self._exe(_X86_CC, ["xlib.c", "xuser.c"], flags,
                                                          ["-nostdlib", "-static", "-no-pie", "-fno-pie",
                                                           "-fno-stack-protector"]))
        x86_libc = _libc_path("x86_64")
        if x86_libc:
            rows += _compare_with_readelf(self, x86_libc)
        self.assertGreater(rows, 30)

    def test_call_site_decoding(self):
        # x86_64: e8 rel32 / ff d0 (call *%rax) / 41 ff d4 (call *%r12) / ff 15 disp32 / not a call
        ra = 0x401000
        self.assertEqual(decode_call_before("x86_64", b"\x90\x90\xe8\x10\x00\x00\x00", ra), ("direct", ra + 0x10))
        self.assertEqual(decode_call_before("x86_64", b"\x90\x90\x90\x90\x90\xff\xd0", ra), ("indirect", None))
        self.assertEqual(decode_call_before("x86_64", b"\x90\x90\x90\x90\x41\xff\xd4", ra), ("indirect", None))
        self.assertEqual(decode_call_before("x86_64", b"\x90\xff\x15\x00\x10\x00\x00", ra), ("indirect", None))
        self.assertEqual(decode_call_before("x86_64", b"\x90\x90\x90\x90\x90\x90\xc3", ra), (None, None))
        # aarch64: bl -8 / blr x3 / blraaz x1 / ret
        self.assertEqual(decode_call_before("aarch64", struct.pack("<I", 0x97FFFFFE), ra), ("direct", ra - 4 - 8))
        self.assertEqual(decode_call_before("aarch64", struct.pack("<I", 0xD63F0060), ra), ("indirect", None))
        self.assertEqual(decode_call_before("aarch64", struct.pack("<I", 0xD63F083F), ra), ("indirect", None))
        self.assertEqual(decode_call_before("aarch64", struct.pack("<I", 0xD65F03C0), ra), (None, None))
        # arm (32-bit) is not decoded at all
        self.assertEqual(decode_call_before("arm", b"\x00\x00\x00\xeb", ra), (None, None))

    def test_proc_syscall_parsing(self):
        p = parse_proc_syscall("98 0xaaaa 0x80 0x2 0x0 0x0 0x0 0xffffc0de0000 0xffff12345678\n")
        self.assertEqual((p["state"], p["nr"], p["args"][0], p["sp"], p["pc"]),
                         ("blocked", 98, 0xAAAA, 0xFFFFC0DE0000, 0xFFFF12345678))
        self.assertEqual(parse_proc_syscall("running")["state"], "running")
        p = parse_proc_syscall("-1 0x7ffc0000 0x401000")
        self.assertEqual((p["state"], p["sp"], p["pc"]), ("not_in_syscall", 0x7FFC0000, 0x401000))

    def test_unsupported_architecture_goes_through_the_support_table(self):
        arm = TargetABI(status=DETECTION_DETECTED, architecture="arm", word_size=32, endianness="little",
                        libc=LIBC_GLIBC)
        for feat in (FEATURE_CFI_UNWIND, FEATURE_FRAME_LAYOUT):
            d = check_support(arm, feat)
            self.assertEqual(d.status, SUPPORT_NOT_SUPPORTED_ON_TARGET)
            self.assertIn("not supported on this target (arm/glibc", d.message)
        for arch in ("x86_64", "aarch64"):
            abi = TargetABI(status=DETECTION_DETECTED, architecture=arch, word_size=64, endianness="little",
                            libc=LIBC_GLIBC)
            self.assertEqual(check_support(abi, FEATURE_CFI_UNWIND).status, SUPPORT_SUPPORTED)
            self.assertEqual(check_support(abi, FEATURE_FRAME_LAYOUT).status, SUPPORT_SUPPORTED)
        self.assertIsNone(make_unwinder_for_process("arm", [], lambda a, n: (None, "UNAVAILABLE", None)))


# --------------------------------------------------------------------------------------------
# Synthetic x86_64 stacks built from the binaries' own CFI
# --------------------------------------------------------------------------------------------
class TestRaUndefinedAfterAdvance(unittest.TestCase):
    """`endbr64; cfi_undefined(rip)` (glibc _start on CET toolchains): the RA rule is the CIE's c-8 at
    pc_begin and `undefined` only from the advanced location - the outermost-frame marker must still hold."""

    def test_undefined_applies_from_advanced_location(self):
        cc = shutil.which("x86_64-linux-gnu-gcc") or (_GCC if platform.machine() == "x86_64" else None)
        ld = shutil.which("x86_64-linux-gnu-ld") or (shutil.which("ld") if platform.machine() == "x86_64" else None)
        if not (cc and ld and _READELF):
            self.skipTest("no x86_64 assembler/linker")
        src = (".text\n.globl _start\n_start:\n .cfi_startproc\n nop\n .cfi_endproc\n"
               ".globl f2\nf2:\n .cfi_startproc\n .byte 0xf3,0x0f,0x1e,0xfa\n .cfi_undefined rip\n"
               " xorl %ebp,%ebp\n ret\n .cfi_endproc\n")
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "s.S"), "w") as f:
                f.write(src)
            subprocess.run([cc, "-c", os.path.join(d, "s.S"), "-o", os.path.join(d, "s.o")], check=True)
            subprocess.run([ld, "-e", "_start", "-o", os.path.join(d, "s"), os.path.join(d, "s.o")], check=True)
            path = os.path.join(d, "s")
            img = load_elf_image(path)
            fde = [f for f in img.all_fdes() if f.source == ".eh_frame"][-1]
            self.assertEqual(img.row_at(fde.pc_begin, fde)[1].rules[16], (R_OFFSET, -8))
            self.assertEqual(img.row_at(fde.pc_begin + 4, fde)[1].rules[16][0], R_UNDEFINED)
            raw = _readelf_raw_fde_ops(path)[fde.pc_begin]
            self.assertTrue(_ra_undefined_deferred_by_advance(raw, 16), raw)
            self.assertFalse(_ra_undefined_deferred_by_advance(["DW_CFA_undefined: r16 (rip)"], 16))


class _FakeStack:
    def __init__(self, lo, hi):
        self.lo, self.hi = lo, hi
        self.buf = bytearray(hi - lo)
        self.reads = 0

    def put(self, addr, val):
        struct.pack_into("<Q", self.buf, addr - self.lo, val & 0xFFFFFFFFFFFFFFFF)

    def read(self, addr, size):
        self.reads += 1
        if addr < self.lo or addr + size > self.hi:
            return None, "UNAVAILABLE", "outside"
        return bytes(self.buf[addr - self.lo:addr - self.lo + size]), "OBSERVED", None


def _func(img, name):
    img._load_symbols()
    for start, size, n in img._symbols:
        if n == name:
            return start, size
    raise AssertionError(f"{name} not in {img.path}")


def _call_site_ra(img, caller, callee_start):
    start, size = _func(img, caller)
    code = img.read_vaddr(start, size)
    for i in range(len(code) - 4):
        if code[i] == 0xE8:
            tgt = start + i + 5 + struct.unpack_from("<i", code, i + 1)[0]
            if tgt == callee_start:
                return start + i + 5
    raise AssertionError(f"no call from {caller} to 0x{callee_start:x}")


def _build_x86_stack(img, chain, leaf_pc, frame_sizes, stack):
    """chain: innermost first (function names); pcs from real call sites; returns (sp0, pc0, pcs)."""
    pcs = [leaf_pc]
    for i in range(1, len(chain)):
        pcs.append(_call_site_ra(img, chain[i], _func(img, chain[i - 1])[0]))
    regs_caller = {3: 0x3333, 6: 0x0, 12: 0xC12, 13: 0xC13, 14: 0xC14, 15: 0xC15}
    cfa = stack.hi - 0x100
    sp0 = None
    for i in range(len(chain) - 1, -1, -1):
        lookup = pcs[i] if i == 0 else pcs[i] - 1
        _fde, row = img.row_at(lookup)
        ra = pcs[i + 1] if i + 1 < len(chain) else 0
        if row.rules[16][0] == R_OFFSET:  # the outermost frame (_start) has its RA undefined
            stack.put(cfa + row.rules[16][1], ra)
        regs_self = dict(regs_caller)
        for reg, (kind, off) in row.rules.items():
            if reg != 16 and kind == R_OFFSET:
                stack.put(cfa + off, regs_caller.get(reg, 0))
                regs_self[reg] = 0xDEAD0000 + reg  # clobbered after being saved
        if row.cfa_reg == 6:
            regs_self[6] = cfa - row.cfa_offset
            sp = regs_self[6] - frame_sizes.get(chain[i], 0x40)
        else:
            self_sp = cfa - row.cfa_offset
            sp = self_sp
        regs_caller = regs_self
        if i == 0:
            sp0 = sp
        cfa = sp  # the callee's CFA is this frame's SP at the call
    return sp0, pcs[0], pcs


@unittest.skipUnless(_X86_CC and _GCC, "no x86_64 compiler (cross or native) installed")
class TestSyntheticX86Unwind(unittest.TestCase):
    """x86_64 unwinding against real x86_64 CFI with synthetic memory (NOT EXECUTED on aarch64)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp011_x86_")
        for name, src in (("xlib.c", X86_LIB_SRC), ("xuser.c", X86_USER_SRC)):
            with open(os.path.join(cls.tmp, name), "w", encoding="utf-8") as fh:
                fh.write(src)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _link(self, user_flags, tag, no_cfi_user=False):
        out = os.path.join(self.tmp, f"x86_{tag}")
        lib_o = os.path.join(self.tmp, f"xlib_{tag}.o")
        user_o = os.path.join(self.tmp, f"xuser_{tag}.o")
        common = ["-fno-pie", "-fno-stack-protector"]  # -nostdlib: no __stack_chk_fail
        _run([_X86_CC, "-c", "-g", "-O2", "-fomit-frame-pointer", *common, os.path.join(self.tmp, "xlib.c"), "-o", lib_o])
        extra = ["-g0", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables"] if no_cfi_user else ["-g"]
        _run([_X86_CC, "-c", *extra, *user_flags, *common, os.path.join(self.tmp, "xuser.c"), "-o", user_o])
        _run([_X86_CC, "-nostdlib", "-static", "-no-pie", lib_o, user_o, "-o", out])
        return out

    @staticmethod
    def _image(path):
        with open(path, "rb") as fh:
            return ElfImage(path, fh.read())

    def _unwind(self, path, frame_sizes, rows_path=None):
        """``rows_path``: twin binary with CFI (identical code) used only to lay out the synthetic stack."""
        img = self._image(path)
        rows_img = self._image(rows_path) if rows_path else img
        self.assertEqual(img.arch, "x86_64")
        stack = _FakeStack(0x7FFF00000000, 0x7FFF00010000)
        # stale decoy frame records everywhere: [fake saved rbp, return address after `call decoy_deep`]
        decoy_ra = _call_site_ra(img, "imp011_decoy_deep", _func(img, "imp011_decoy_deep")[0])
        decoy_main_ra = _call_site_ra(img, "main", _func(img, "imp011_decoy_deep")[0])
        for a in range(stack.lo, stack.hi - 16, 16):
            stack.put(a, a + 0x120)
            stack.put(a + 8, decoy_ra if (a // 16) % 3 else decoy_main_ra)
        start, size = _func(img, "fake_futex_wait")
        code = img.read_vaddr(start, size)
        leaf_pc = start + code.index(b"\x0f\x05") + 2
        chain = ["fake_futex_wait", "fake_mutex_lock", "imp011_level_d", "imp011_level_c",
                 "imp011_level_b", "imp011_level_a", "main", "_start"]
        if rows_img is not img:
            for fn in chain + ["imp011_decoy_deep"]:
                if _func(img, fn) != _func(rows_img, fn):
                    self.skipTest("CFI and no-CFI builds do not have identical code layout")
        sp0, pc0, _pcs = _build_x86_stack(rows_img, chain, leaf_pc, frame_sizes, stack)
        maps = [{"start_int": s[3] & ~0xFFF, "end_int": (s[3] + s[5] + 0xFFF) & ~0xFFF,
                 "permissions": "r-xp" if s[1] & 1 else "r--p", "offset_int": s[2] & ~0xFFF, "pathname": path}
                for s in img.segments if s[0] == 1]
        maps.append({"start_int": stack.lo, "end_int": stack.hi, "permissions": "rw-p", "offset_int": 0,
                     "pathname": "[stack]"})
        uw = CfiUnwinder("x86_64", maps, stack.read)
        self.last_uw, self.last_stack = uw, stack
        res = uw.unwind_blocked(sp0, pc0)
        names = [uw.describe_pc(f["pc"], f["lookup_pc"])["elf_symbol"] for f in res["frames"]]
        return res, names, chain

    def test_running_sample_without_registers(self):
        """Same memory, but no SP/PC (as for a thread running on a CPU): the two-read sample must find
        the same chain top-down from anchors, every frame labelled running_sample_estimated."""
        for flags, tag in ((["-O2", "-fomit-frame-pointer"], "run_o2"), (["-O0"], "run_o0")):
            with self.subTest(build=tag):
                path = self._link(flags, tag)
                _res, _names, chain = self._unwind(path, {"imp011_level_d": 0x230})
                uw, stack = self.last_uw, self.last_stack
                res = uw.sample_running(stack.lo, stack.hi, settle_s=0)
                names = [uw.describe_pc(f["pc"], f["lookup_pc"])["elf_symbol"] for f in res["frames"]]
                self.assertEqual(names, chain, res["notes"])
                self.assertEqual(res["status"], "RUNNING_SAMPLE_ESTIMATED")
                self.assertTrue(res["sample_stable"])
                for f in res["frames"]:
                    self.assertEqual(f["unwind"], UNWIND_RUNNING)
                    self.assertTrue(f["estimated"])
                self.assertTrue(res["frames"][0].get("pc_is_function_entry"))

    def test_o2_omit_frame_pointer_exact_chain(self):
        path = self._link(["-O2", "-fomit-frame-pointer"], "o2")
        res, names, chain = self._unwind(path, {})
        self.assertEqual(names, chain, res)
        self.assertEqual(res["stop_reason"], "outermost_frame")
        self.assertEqual([f["unwind"] for f in res["frames"]], [UNWIND_REGISTERS] + [UNWIND_CFI] * (len(chain) - 1))
        self.assertFalse(any(f["estimated"] for f in res["frames"]))

    def test_o0_frame_pointer_inferred_through_stale_records(self):
        """-O0: CFA = rbp+16 and rbp is not published nor saved by the -O2 leaf: it is inferred from a
        call-site-validated frame record while the frame holds 512 bytes of stale decoy records."""
        path = self._link(["-O0"], "o0")
        res, names, chain = self._unwind(path, {"imp011_level_d": 0x230})
        self.assertEqual(names, chain, res)
        self.assertEqual(res["stop_reason"], "outermost_frame")
        by_name = dict(zip(names, res["frames"]))
        self.assertTrue(by_name["imp011_level_d"].get("fp_inferred"))
        self.assertEqual(by_name["imp011_level_c"]["unwind"], UNWIND_FRAME_POINTER)
        self.assertFalse(any(f["estimated"] for f in res["frames"]))

    def test_missing_fde_falls_back_to_marked_scan(self):
        """User TU without CFI at -O2: frames past the CFI-less code are marked estimated, never `cfi`."""
        twin = self._link(["-O2", "-fomit-frame-pointer"], "twin")
        path = self._link(["-O2", "-fomit-frame-pointer"], "nocfi", no_cfi_user=True)
        res, names, chain = self._unwind(path, {}, rows_path=twin)
        self.assertEqual(names, chain, res)
        first_est = next(i for i, f in enumerate(res["frames"]) if f["estimated"])
        self.assertLessEqual(first_est, 3)
        for f in res["frames"][first_est:]:
            self.assertTrue(f["estimated"])
            self.assertIn(f["unwind"], (UNWIND_SCAN, UNWIND_CFI_AFTER_SCAN))
        self.assertEqual(res["status"], "PARTIAL_ESTIMATED")
        # no decoy (stale) function may appear among the estimated frames: call targets must chain
        self.assertNotIn("imp011_decoy_deep", names)


# --------------------------------------------------------------------------------------------
# Real processes (native architecture)
# --------------------------------------------------------------------------------------------
@unittest.skipUnless(_GCC and _NATIVE in ("x86_64", "aarch64"), "native x86_64/aarch64 gcc required")
class TestRealProcessCfiUnwind(unittest.TestCase):

    BUILDS = {
        "o0": (["-O0"], False),
        "o2": (["-O2", "-fomit-frame-pointer"], False),
        "nocfi_o2": (["-O2", "-fomit-frame-pointer"], True),
        "nocfi_o0": (["-O0"], True),
    }

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp011_real_")
        for name, src in (("main.c", REAL_MAIN_SRC), ("mid.c", REAL_MID_SRC)):
            with open(os.path.join(cls.tmp, name), "w", encoding="utf-8") as fh:
                fh.write(src)
        cls.bins = {}
        for tag, (flags, no_cfi) in cls.BUILDS.items():
            main_o = os.path.join(cls.tmp, f"main_{tag}.o")
            mid_o = os.path.join(cls.tmp, f"mid_{tag}.o")
            out = os.path.join(cls.tmp, f"imp011_{tag}")
            _run([_GCC, "-c", "-g", *flags, os.path.join(cls.tmp, "main.c"), "-o", main_o])
            mid_extra = ["-g0", "-fno-asynchronous-unwind-tables", "-fno-unwind-tables"] if no_cfi else ["-g"]
            _run([_GCC, "-c", *mid_extra, *flags, os.path.join(cls.tmp, "mid.c"), "-o", mid_o])
            _run([_GCC, "-pthread", main_o, mid_o, "-o", out])
            cls.bins[tag] = out
        cls.mgr = WatchSessionManager(corpus_dir=os.path.join(cls.tmp, "corpus"))
        cls.procs = []

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            if p.poll() is None:
                p.kill()
            try:
                p.wait(timeout=3)
            except Exception:
                pass
        shutil.rmtree(cls.tmp, ignore_errors=True)
        DwarfIndexer.clear_cache()

    def _start(self, tag, spinner=False):
        p = subprocess.Popen([self.bins[tag]] + (["spin"] if spinner else []), stdout=subprocess.PIPE)
        self.procs.append(p)
        self.addCleanup(p.kill)
        self.assertEqual(p.stdout.readline().strip(), b"READY")
        deadline = time.time() + 5
        while time.time() < deadline:  # wait until the main thread really sleeps in futex
            with open(f"/proc/{p.pid}/syscall", encoding="utf-8") as fh:
                sc = fh.read().split()
            if sc and sc[0] == str(_FUTEX_NR[_NATIVE]):
                break
            time.sleep(0.01)
        return p

    def _main_thread(self, res, pid):
        return next(t for t in res["threads"] if int(t["tid"]) == pid)

    def _assert_ground_truth(self, th):
        names = [f["function_name"] for f in th["callstack"]]
        self.assertIn("imp011_level_d", names, names)
        i_d = names.index("imp011_level_d")
        i_main = names.index("main")
        self.assertEqual(names[i_d:i_main + 1], GROUND_TRUTH, names)
        # everything before level_d is the blocking libc path
        for f in th["callstack"][:i_d]:
            self.assertTrue((f.get("module") or "").startswith(("libc", "libpthread", "ld-")), f)
        self.assertFalse(any("decoy" in n for n in names), names)
        return names, i_d, i_main

    def test_a_and_c_blocked_thread_ground_truth_o0_and_o2(self):
        for tag in ("o0", "o2"):
            with self.subTest(build=tag):
                p = self._start(tag)
                res = self.mgr.inspect_thread_callstacks_and_locks(pid=p.pid, companion_elf_path=self.bins[tag],
                                                                    max_frames=32)
                self.assertEqual(res["stop_duration_ms"], 0.0)
                self.assertEqual(res["cfi_unwind_status"], SUPPORT_SUPPORTED)
                th = self._main_thread(res, p.pid)
                # criterion (c): the futex wait is named through the target's syscall table
                self.assertEqual(th["syscall"], "futex")
                self.assertEqual(th["syscall_nr"], _FUTEX_NR[_NATIVE])
                names, i_d, i_main = self._assert_ground_truth(th)
                allowed = {UNWIND_REGISTERS, UNWIND_CFI} if _NATIVE == "aarch64" else \
                    {UNWIND_REGISTERS, UNWIND_CFI, UNWIND_FRAME_POINTER}
                for f in th["callstack"]:
                    self.assertIn(f["unwind"], allowed, f)
                    self.assertFalse(f["estimated"], f)
                self.assertEqual(th["callstack"][0]["unwind"], UNWIND_REGISTERS)
                self.assertEqual(th["unwind_status"], "COMPLETE")
                cost = th["unwind_cost"]
                self.assertGreater(cost["target_reads"], 0)
                self.assertLessEqual(cost["target_bytes"], 64 * 1024)
                # the holder thread is blocked in pause() under imp011_holder
                holder = next(t for t in res["threads"] if int(t["tid"]) != p.pid)
                self.assertIn("imp011_holder", [f["function_name"] for f in holder["callstack"]])
                self.assertEqual(holder["unwind_status"], "COMPLETE")
                p.kill()

    def test_b_frames_without_cfi_are_marked_estimated(self):
        p = self._start("nocfi_o2")
        res = self.mgr.inspect_thread_callstacks_and_locks(pid=p.pid, companion_elf_path=self.bins["nocfi_o2"],
                                                            max_frames=32)
        th = self._main_thread(res, p.pid)
        names = [f["function_name"] for f in th["callstack"]]
        by_name = {f["function_name"]: f for f in th["callstack"]}
        # level_c has no FDE: its caller(s) can only come from the scan fallback
        for fn in ("imp011_level_b", "imp011_level_a"):
            self.assertIn(fn, by_name, names)
            self.assertTrue(by_name[fn]["estimated"], by_name[fn])
            self.assertIn(by_name[fn]["unwind"], (UNWIND_SCAN, UNWIND_CFI_AFTER_SCAN))
        i_first_est = next(i for i, f in enumerate(th["callstack"]) if f["estimated"])
        self.assertTrue(all(f["estimated"] for f in th["callstack"][i_first_est:]))
        self.assertTrue(all(not f["estimated"] and f["unwind"] in (UNWIND_REGISTERS, UNWIND_CFI)
                            for f in th["callstack"][:i_first_est]))
        self.assertEqual(th["unwind_status"], "PARTIAL_ESTIMATED")
        self._assert_ground_truth(th)

    def test_b_frame_pointer_tier_without_cfi_at_o0(self):
        """-O0 code keeps frame records: CFI-less frames are recovered through them, labelled frame_pointer."""
        p = self._start("nocfi_o0")
        res = self.mgr.inspect_thread_callstacks_and_locks(pid=p.pid, companion_elf_path=self.bins["nocfi_o0"],
                                                            max_frames=32)
        th = self._main_thread(res, p.pid)
        self._assert_ground_truth(th)
        by_name = {f["function_name"]: f for f in th["callstack"]}
        for fn in ("imp011_level_b", "imp011_level_a"):
            self.assertNotEqual(by_name[fn]["unwind"], UNWIND_CFI, by_name[fn])
            self.assertTrue(by_name[fn]["unwind"] == UNWIND_FRAME_POINTER or by_name[fn]["estimated"], by_name[fn])

    def test_d_parameters_and_locals_of_non_leaf_frames(self):
        p = self._start("o0")
        res = self.mgr.inspect_thread_locals_and_frame_vars(pid=p.pid, companion_elf_path=self.bins["o0"],
                                                             max_frames=16)
        self.assertEqual(res["frame_decode_status"], SUPPORT_SUPPORTED)
        th = next(t for t in res["threads"] if int(t["tid"]) == p.pid)
        frames = {f["function_name"]: f for f in th["frames"]}
        for fn, expected in KNOWN_VALUES.items():
            self.assertIn(fn, frames, list(frames))
            got = {v["name"]: v["value"] for v in frames[fn]["parameters"] + frames[fn]["locals"]}
            for k, v in expected.items():
                self.assertEqual(got.get(k), v, f"{fn}.{k}: {got}")
            self.assertFalse(frames[fn]["estimated"])
            self.assertEqual(frames[fn]["frame_base"], "DW_OP_call_frame_cfa")

    def test_running_thread_is_a_labelled_estimate(self):
        p = self._start("o0", spinner=True)
        deadline = time.time() + 5
        spin_tid = None
        while time.time() < deadline and spin_tid is None:
            for tid in os.listdir(f"/proc/{p.pid}/task"):
                try:
                    with open(f"/proc/{p.pid}/task/{tid}/syscall", encoding="utf-8") as fh:
                        if fh.read().startswith("running"):
                            spin_tid = int(tid)
                except OSError:
                    pass
            time.sleep(0.01)
        self.assertIsNotNone(spin_tid)
        res = self.mgr.inspect_thread_callstacks_and_locks(pid=p.pid, companion_elf_path=self.bins["o0"],
                                                            tid=spin_tid)
        th = res["threads"][0]
        if th["syscall"] is not None:  # it entered a syscall between the probe and the inspection
            self.skipTest("spinner thread was not running during the inspection")
        self.assertIn(th["unwind_status"], ("RUNNING_SAMPLE_ESTIMATED", "SCAN_ESTIMATED"))
        for f in th["callstack"]:
            self.assertTrue(f["estimated"], f)
            self.assertIn(f["unwind"], (UNWIND_RUNNING, UNWIND_SCAN))
        if th["unwind_status"] == "RUNNING_SAMPLE_ESTIMATED":
            names = [f["function_name"] for f in th["callstack"]]
            # imp011_spin_step is a leaf: on aarch64 its RA lives only in x30, so the innermost recoverable
            # frame is spin_outer; on x86_64 the call pushed it, so spin_step may be reported first.
            if names and names[0] == "imp011_spin_step":
                names = names[1:]
            self.assertEqual(names[:2], ["imp011_spin_outer", "imp011_spinner"], names)
            self.assertIsNotNone(th["running_sample_stable"])
            self.assertTrue(any("running on a CPU" in n for n in th["unwind_notes"]))

    def test_unwinder_reads_only_through_the_adapter_budget(self):
        p = self._start("o2")
        adapter = LocalTargetAdapter()
        seen = []
        orig = adapter.read_memory

        def spy(pid, addr, size):
            seen.append(size)
            return orig(pid, addr, size)

        adapter.read_memory = spy
        reads0, bytes0 = adapter.physical_reads_count, adapter.physical_bytes_read
        res = self.mgr.inspect_thread_callstacks_and_locks(pid=p.pid, companion_elf_path=self.bins["o2"],
                                                            adapter=adapter, tid=p.pid)
        th = res["threads"][0]
        self.assertEqual(th["unwind_status"], "COMPLETE")
        cost = th["unwind_cost"]
        # every unwinder read went through the adapter's accounted, non-stopping read path
        self.assertGreaterEqual(len(seen), cost["target_reads"])
        self.assertGreaterEqual(adapter.physical_reads_count - reads0, cost["target_reads"])
        self.assertGreaterEqual(adapter.physical_bytes_read - bytes0, cost["target_bytes"])
        self.assertLessEqual(cost["target_reads"], 8)


if __name__ == "__main__":
    unittest.main()
