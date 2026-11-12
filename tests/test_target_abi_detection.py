"""IMP-015: target ABI detection and the supported-combination table.

Test inputs by kind
-------------------
REAL    : ELF files compiled at test time (native gcc, and cross compilers when installed -
          skipped with a reason otherwise), live native processes, kernel uapi headers of the
          installed compilers (syscall table cross-check).
SYNTHETIC: ELF headers built byte-by-byte in this file (musl interpreter, big-endian, ELF32) and
          fake adapters/maps.  There is NO musl toolchain requirement; every musl case is
          synthetic and says so in its docstring.

All assertions are architecture neutral: the expected value for the native host is derived from
the build, not hard-coded, so the file runs on x86_64 and aarch64 hosts.
"""

import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from extractor.allocator_inspector import AllocatorType, detect_allocator
from extractor.dwarf_indexer import DwarfIndexer
from extractor.target_abi import (
    DETECTION_DETECTED,
    DETECTION_FAILED,
    FEATURE_ALLOCATOR_CHUNKS,
    FEATURE_FRAME_LAYOUT,
    FEATURE_MUTEX_OWNER,
    FEATURE_SYSCALL_NAMES,
    FEATURE_TCB_SCAN,
    LIBC_GLIBC,
    LIBC_MUSL,
    LIBC_UNKNOWN,
    SUPPORT_INCONCLUSIVE,
    SUPPORT_NOT_SUPPORTED_ON_TARGET,
    SUPPORT_SUPPORTED,
    SUPPORT_TABLE,
    SYSCALL_TABLES,
    TargetABI,
    check_support,
    detect_target_abi,
    parse_elf_header,
    syscall_name,
)
from extractor.target_adapter import LocalTargetAdapter, TargetExecutionAdapter
from extractor.watch_session import WatchSessionManager

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_runtime")

_NATIVE_MACHINE = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(
    platform.machine().lower()
)
_IS_X86_64 = _NATIVE_MACHINE == "x86_64"

E_MACHINE = {"x86_64": 62, "aarch64": 183, "arm": 40}


def make_elf(machine: int, bits: int = 64, little: bool = True, interp: str = None) -> bytes:
    """SYNTHETIC ELF image: header + one PT_INTERP program header (+ the path), nothing else."""
    e = "<" if little else ">"
    ehsize, phentsize = (64, 56) if bits == 64 else (52, 32)
    interp_b = (interp.encode() + b"\x00") if interp else b""
    phnum = 1 if interp else 0
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if little else 2, 1, 0]) + b"\x00" * 8
    interp_off = ehsize + phentsize * phnum
    if bits == 64:
        hdr = ident + struct.pack(e + "HHIQQQIHHHHHH", 2, machine, 1, 0, ehsize if phnum else 0, 0, 0,
                                  ehsize, phentsize, phnum, 64, 0, 0)
        ph = struct.pack(e + "IIQQQQQQ", 3, 4, interp_off, 0, 0, len(interp_b), len(interp_b), 1) if phnum else b""
    else:
        hdr = ident + struct.pack(e + "HHIIIIIHHHHHH", 2, machine, 1, 0, ehsize if phnum else 0, 0, 0,
                                  ehsize, phentsize, phnum, 40, 0, 0)
        ph = struct.pack(e + "IIIIIIII", 3, interp_off, 0, 0, len(interp_b), len(interp_b), 4, 1) if phnum else b""
    return hdr + ph + interp_b


def out_sleep_free_path(tmp):
    """Native long-running dynamic executable built by the test (no dependency on /bin/sleep)."""
    src = os.path.join(tmp, "idle.c")
    exe = os.path.join(tmp, "idle")
    if not os.path.exists(exe):
        with open(src, "w") as f:
            f.write("#include <unistd.h>\nint main(void){for(;;)pause();}\n")
        subprocess.run(["gcc", src, "-o", exe], check=True)
    return exe


def _map(path, perms="r-xp"):
    return {"pathname": path, "permissions": perms, "category": "code"}


class FakeAdapter(TargetExecutionAdapter):
    """Adapter serving an ABI from canned bytes/maps; never touches the host platform."""

    def __init__(self, exe_bytes, maps, remote=False, files=None):
        self._exe = exe_bytes
        self._maps = maps
        self._remote = remote
        self._files = files or {}

    def read_target_file(self, pid, path, max_bytes):
        if path.endswith("/exe"):
            return None if self._exe is None else self._exe[:max_bytes]
        data = self._files.get(path)
        return None if data is None else data[:max_bytes]

    def get_proc_maps(self, pid):
        return self._maps

    def check_liveness(self, pid):
        return True, None

    def get_process_identity(self, pid):
        return {}

    def get_threads(self, pid):
        return []

    def read_memory(self, pid, address, size):
        raise AssertionError("memory must not be read")

    def is_remote(self):
        return self._remote

    def target_host(self):
        return "fake-host"


class OverridingLocalAdapter(LocalTargetAdapter):
    """Real local adapter (real memory, real threads) whose ABI evidence is overridden."""

    def __init__(self, exe_bytes="real", maps="real"):
        super().__init__()
        self._o_exe = exe_bytes
        self._o_maps = maps

    def read_target_file(self, pid, path, max_bytes):
        if path.endswith("/exe") and self._o_exe != "real":
            return self._o_exe
        return super().read_target_file(pid, path, max_bytes)

    def get_proc_maps(self, pid):
        real = super().get_proc_maps(pid)
        if self._o_maps == "real":
            return real
        # keep the real VMAs (addresses, perms) but rename the libc / loader files to the synthetic ones
        out = []
        for m in real:
            m = dict(m)
            base = (m.get("pathname") or "").rsplit("/", 1)[-1]
            if base.startswith(("libc.", "libc-", "ld-linux", "ld-musl", "ld.so", "ld64.so")) or re.match(r"ld-\d", base):
                m["pathname"] = self._o_maps
            out.append(m)
        return out


# =====================================================================================
# 1. Pure table / parsing tests
# =====================================================================================
_NON_SYSCALL_NR = {"syscalls", "arch_specific_syscall", "Linux", "SYSCALL_BASE", "Linux_syscalls", "OABI_SYSCALL_BASE"}


class TestSyscallTables(unittest.TestCase):
    def test_required_futex_numbers(self):
        self.assertEqual(SYSCALL_TABLES["x86_64"][202], "futex")
        self.assertEqual(SYSCALL_TABLES["aarch64"][98], "futex")
        self.assertEqual(SYSCALL_TABLES["arm"][240], "futex")

    def test_blocking_calls_present_for_each_arch(self):
        needed = {"futex", "read", "write", "nanosleep", "clock_nanosleep", "wait4", "accept",
                  "recvfrom", "recvmsg", "ppoll", "pselect6", "epoll_pwait"}
        for arch, table in SYSCALL_TABLES.items():
            missing = needed - set(table.values())
            self.assertFalse(missing, f"{arch} lacks {missing}")
        # legacy calls that exist on x86_64 / arm only
        self.assertIn("poll", SYSCALL_TABLES["x86_64"].values())
        self.assertIn("poll", SYSCALL_TABLES["arm"].values())
        self.assertNotIn("poll", SYSCALL_TABLES["aarch64"].values())
        self.assertIn("epoll_wait", SYSCALL_TABLES["x86_64"].values())
        self.assertNotIn("epoll_wait", SYSCALL_TABLES["aarch64"].values())

    def test_same_number_means_different_calls(self):
        # 98 is futex on aarch64 but not on x86_64 / arm; read is 0 / 63 / 3
        self.assertNotEqual(SYSCALL_TABLES["x86_64"].get(98), "futex")
        self.assertNotEqual(SYSCALL_TABLES["arm"].get(98), "futex")
        self.assertEqual(
            [SYSCALL_TABLES[a].get(n) for a, n in (("x86_64", 0), ("aarch64", 63), ("arm", 3))], ["read"] * 3
        )

    def _header_numbers(self, cc):
        src = "#include <sys/syscall.h>\n"
        out = subprocess.run([cc, "-E", "-dM", "-x", "c", "-"], input=src, capture_output=True, text=True)
        if out.returncode != 0:
            return None
        nums = {}
        for m in re.finditer(r"^#define __NR(?:3264)?_(\w+) \(?(?:__NR_SYSCALL_BASE\s*\+\s*)?(\d+)\)?$", out.stdout, re.M):
            # Skip bookkeeping macros that share the __NR_ prefix but are not syscalls (e.g. __NR_syscalls is the
            # table size: 449 on Ubuntu 22.04's aarch64 headers).
            if m.group(1) in _NON_SYSCALL_NR or m.group(1).startswith(("arch_specific_syscall", "Linux", "SYSCALL_BASE")):
                continue
            nums[m.group(1)] = int(m.group(2))
        return nums or None

    def test_tables_match_kernel_headers_of_installed_compilers(self):
        """REAL: every table entry equals the number in the uapi headers of that arch's compiler."""
        compilers = {
            "x86_64": ["x86_64-linux-gnu-gcc"],
            "aarch64": ["aarch64-linux-gnu-gcc"],
            "arm": ["arm-linux-gnueabihf-gcc", "arm-linux-gnueabi-gcc"],
        }
        if _NATIVE_MACHINE:
            compilers[_NATIVE_MACHINE].append("gcc")
        checked = 0
        for arch, ccs in compilers.items():
            for cc in ccs:
                if not shutil.which(cc):
                    continue
                nums = self._header_numbers(cc)
                if not nums:
                    continue
                by_num = {}
                for name, n in nums.items():
                    by_num.setdefault(n, set()).add(name)
                compared = 0
                for n, name in SYSCALL_TABLES[arch].items():
                    if name not in nums and n not in by_num:
                        # Syscall newer than the installed kernel headers (e.g. futex_waitv=449 vs Ubuntu 22.04's
                        # 5.15 uapi): the headers define neither the name nor the number, so there is nothing to
                        # compare against - not an error. Any number the headers DO define must still match.
                        continue
                    self.assertIn(name, by_num.get(n, set()), f"{arch}: {n} is not {name} in {cc} headers")
                    compared += 1
                self.assertGreater(compared, 0, f"{arch}: no table entry could be compared with {cc} headers")
                checked += 1
                break
        if not checked:
            self.skipTest("no compiler with kernel headers available")


class TestElfParsingAndSupportTable(unittest.TestCase):
    def test_parse_synthetic_headers(self):
        p = parse_elf_header(make_elf(183, 64, True, "/lib/ld-linux-aarch64.so.1"))
        self.assertEqual((p["architecture"], p["word_size"], p["endianness"]), ("aarch64", 64, "little"))
        self.assertEqual(p["interpreter"], "/lib/ld-linux-aarch64.so.1")
        p = parse_elf_header(make_elf(40, 32, True, "/lib/ld-linux-armhf.so.3"))
        self.assertEqual((p["architecture"], p["word_size"]), ("arm", 32))
        p = parse_elf_header(make_elf(62, 64, False, None))
        self.assertEqual(p["endianness"], "big")
        self.assertIsNone(p["interpreter"])

    def test_parse_rejects_garbage(self):
        for raw in (b"", b"MZ" + b"\0" * 100, b"\x7fELF\x03\x01" + b"\0" * 60):
            with self.assertRaises(ValueError):
                parse_elf_header(raw)

    def _abi(self, arch, libc, bits=64, endian="little"):
        return TargetABI(status=DETECTION_DETECTED, architecture=arch, word_size=bits, endianness=endian, libc=libc)

    def test_table_decisions(self):
        glibc_x86 = self._abi("x86_64", LIBC_GLIBC)
        glibc_a64 = self._abi("aarch64", LIBC_GLIBC)
        musl_a64 = self._abi("aarch64", LIBC_MUSL)
        for f in (FEATURE_MUTEX_OWNER, FEATURE_ALLOCATOR_CHUNKS, FEATURE_SYSCALL_NAMES, FEATURE_TCB_SCAN, FEATURE_FRAME_LAYOUT):
            self.assertEqual(check_support(glibc_x86, f).status, SUPPORT_SUPPORTED, f)
        self.assertEqual(check_support(glibc_a64, FEATURE_MUTEX_OWNER).status, SUPPORT_SUPPORTED)
        self.assertEqual(check_support(glibc_a64, FEATURE_SYSCALL_NAMES).status, SUPPORT_SUPPORTED)
        # IMP-011: frame decoding is CFI-based now and genuinely supported on aarch64 (any libc)
        self.assertEqual(check_support(glibc_a64, FEATURE_FRAME_LAYOUT).status, SUPPORT_SUPPORTED)
        self.assertEqual(check_support(musl_a64, FEATURE_FRAME_LAYOUT).status, SUPPORT_SUPPORTED)
        # aarch64/glibc TCB discovery (TLS variant I, dtv-validated) is supported; musl and 32-bit arm are not
        self.assertEqual(check_support(glibc_a64, FEATURE_TCB_SCAN).status, SUPPORT_SUPPORTED)
        d = check_support(musl_a64, FEATURE_TCB_SCAN)
        self.assertEqual(d.status, SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertIn("not supported on this target (aarch64/musl", d.message)
        self.assertEqual(check_support(self._abi("arm", LIBC_GLIBC, 32), FEATURE_TCB_SCAN).status,
                         SUPPORT_NOT_SUPPORTED_ON_TARGET)
        d = check_support(self._abi("arm", LIBC_GLIBC, 32), FEATURE_FRAME_LAYOUT)
        self.assertEqual(d.status, SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertIn("not supported on this target (arm/glibc", d.message)
        d = check_support(musl_a64, FEATURE_MUTEX_OWNER)
        self.assertEqual(d.status, SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertIn("(aarch64/musl", d.message)
        # musl x86_64 does not get the glibc layouts either, but syscall names remain valid (kernel ABI)
        musl_x86 = self._abi("x86_64", LIBC_MUSL)
        self.assertEqual(check_support(musl_x86, FEATURE_ALLOCATOR_CHUNKS).status, SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertEqual(check_support(musl_x86, FEATURE_SYSCALL_NAMES).status, SUPPORT_SUPPORTED)
        # 32-bit arm, big endian, riscv: not in the table for layout features
        self.assertEqual(check_support(self._abi("arm", LIBC_GLIBC, 32), FEATURE_MUTEX_OWNER).status,
                         SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertEqual(check_support(self._abi("x86_64", LIBC_GLIBC, 64, "big"), FEATURE_MUTEX_OWNER).status,
                         SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertEqual(check_support(self._abi("riscv64", LIBC_GLIBC), FEATURE_SYSCALL_NAMES).status,
                         SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertIsNone(syscall_name(self._abi("riscv64", LIBC_GLIBC), 98))

    def test_unknown_libc_is_inconclusive_not_a_guess(self):
        d = check_support(self._abi("x86_64", LIBC_UNKNOWN), FEATURE_MUTEX_OWNER)
        self.assertEqual(d.status, SUPPORT_INCONCLUSIVE)

    def test_every_table_row_is_consistent(self):
        for feature, rows in SUPPORT_TABLE.items():
            for arch, libc, word, endian in rows:
                self.assertIsNotNone(arch, feature)
                if arch in SYSCALL_TABLES and feature == FEATURE_SYSCALL_NAMES:
                    self.assertTrue(SYSCALL_TABLES[arch])

    def test_syscall_name_per_target_arch(self):
        a64 = self._abi("aarch64", LIBC_GLIBC)
        x86 = self._abi("x86_64", LIBC_GLIBC)
        arm = self._abi("arm", LIBC_GLIBC, 32)
        self.assertEqual(syscall_name(a64, 98), "futex")
        self.assertEqual(syscall_name(x86, 202), "futex")
        self.assertEqual(syscall_name(arm, 240), "futex")
        self.assertEqual(syscall_name(a64, 202), "accept")          # NOT futex: numbers are per-arch
        self.assertEqual(syscall_name(x86, 99999), "syscall_99999")  # supported arch, unlisted number
        self.assertIsNone(syscall_name(None, 98))
        self.assertIsNone(syscall_name(TargetABI(), 98))


# =====================================================================================
# 2. Detection from ELF files and fake adapters
# =====================================================================================
class TestDetectionFromBinaries(unittest.TestCase):
    CROSS = [
        ("x86_64-linux-gnu-gcc", "x86_64", 64, "little"),
        ("aarch64-linux-gnu-gcc", "aarch64", 64, "little"),
        ("arm-linux-gnueabihf-gcc", "arm", 32, "little"),
    ]

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="abi_det_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.src = os.path.join(cls.tmp, "hello.c")
        with open(cls.src, "w") as f:
            f.write("#include <stdio.h>\nint main(void){puts(\"x\");return 0;}\n")

    def _build(self, cc):
        if not shutil.which(cc):
            self.skipTest(f"{cc} not installed")
        out = os.path.join(self.tmp, cc)
        r = subprocess.run([cc, self.src, "-o", out], capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest(f"{cc} cannot link a hello-world: {r.stderr.strip()[:120]}")
        return out

    def test_cross_compiled_elf_detection(self):
        """REAL cross-compiled ELF for each installed cross compiler (ELF header + PT_INTERP real;
        the mapped-libc list is the glibc loader named by that ELF, supplied through a fake adapter)."""
        ran = 0
        for cc, arch, bits, endian in self.CROSS:
            if not shutil.which(cc):
                continue
            path = self._build(cc)
            with open(path, "rb") as f:
                raw = f.read()
            interp = parse_elf_header(raw)["interpreter"]
            self.assertTrue(interp, f"{cc}: no PT_INTERP in output")
            adapter = FakeAdapter(raw, [_map("/usr/lib/libc.so.6"), _map(interp)])
            abi = detect_target_abi(adapter, 4242)
            self.assertEqual(abi.status, DETECTION_DETECTED, abi.error)
            self.assertEqual((abi.architecture, abi.word_size, abi.endianness), (arch, bits, endian), cc)
            self.assertEqual(abi.libc, LIBC_GLIBC, cc)
            self.assertEqual(abi.interpreter, interp)
            ran += 1
        if not ran:
            self.skipTest("no cross compiler installed")

    def test_native_elf_detection_matches_build(self):
        """REAL native gcc output through the real local adapter, mapped libc taken from a real process."""
        if not shutil.which("gcc"):
            self.skipTest("gcc not available")
        out = os.path.join(self.tmp, "native")
        subprocess.run(["gcc", self.src, "-o", out], check=True)
        # a still-running native process
        sleeper = subprocess.Popen([out_sleep_free_path(self.tmp)])
        self.addCleanup(lambda: (sleeper.kill(), sleeper.wait()))
        # The dynamic loader maps libc shortly after exec; wait for it so detection is not racing process start-up.
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                with open(f"/proc/{sleeper.pid}/maps") as fh:
                    if "libc" in fh.read():
                        break
            except OSError:
                pass
            time.sleep(0.01)
        abi = detect_target_abi(LocalTargetAdapter(), sleeper.pid)
        self.assertEqual(abi.status, DETECTION_DETECTED, abi.error)
        self.assertEqual(abi.word_size, struct.calcsize("P") * 8)
        self.assertEqual(abi.endianness, sys.byteorder)
        if _NATIVE_MACHINE:
            self.assertEqual(abi.architecture, _NATIVE_MACHINE)
        self.assertIn(abi.libc, (LIBC_GLIBC, LIBC_MUSL))
        if abi.libc == LIBC_GLIBC:
            self.assertRegex(abi.libc_version or "", r"^\d+\.\d+")

    def test_musl_synthetic(self):
        """SYNTHETIC: header with a musl PT_INTERP + fake maps; no musl toolchain used."""
        for arch in ("x86_64", "aarch64"):
            raw = make_elf(E_MACHINE[arch], 64, True, f"/lib/ld-musl-{arch}.so.1")
            abi = detect_target_abi(FakeAdapter(raw, [_map(f"/lib/ld-musl-{arch}.so.1")]), 1)
            self.assertEqual((abi.architecture, abi.libc), (arch, LIBC_MUSL))
            self.assertIsNone(abi.libc_version)
            d = check_support(abi, FEATURE_MUTEX_OWNER)
            self.assertEqual(d.status, SUPPORT_NOT_SUPPORTED_ON_TARGET)
            self.assertIn(f"{arch}/musl", d.message)

    def test_conflicting_libc_evidence_is_unknown(self):
        """SYNTHETIC: glibc interpreter but a musl library mapped -> not guessed."""
        raw = make_elf(62, 64, True, "/lib64/ld-linux-x86-64.so.2")
        abi = detect_target_abi(FakeAdapter(raw, [_map("/lib/libc.musl-x86_64.so.1")]), 1)
        self.assertEqual(abi.libc, LIBC_UNKNOWN)
        self.assertEqual(check_support(abi, FEATURE_MUTEX_OWNER).status, SUPPORT_INCONCLUSIVE)

    def test_static_executable_has_unknown_libc(self):
        """SYNTHETIC: no PT_INTERP and no libc mapping."""
        abi = detect_target_abi(FakeAdapter(make_elf(62, 64, True, None), [_map("/opt/app")]), 1)
        self.assertEqual(abi.status, DETECTION_DETECTED)
        self.assertEqual(abi.libc, LIBC_UNKNOWN)
        self.assertEqual(check_support(abi, FEATURE_MUTEX_OWNER).status, SUPPORT_INCONCLUSIVE)

    def test_versions_from_names_and_remote_adapter_does_not_scan_files(self):
        """SYNTHETIC: versioned glibc file name; remote adapters never bulk-read libc for a banner."""
        raw = make_elf(62, 64, True, "/lib64/ld-linux-x86-64.so.2")
        abi = detect_target_abi(FakeAdapter(raw, [_map("/lib/x86_64-linux-gnu/libc-2.31.so")]), 1)
        self.assertEqual(abi.libc_version, "2.31")
        files = {"/lib/libc.so.6": b"junk GNU C Library (X) stable release version 2.35. junk"}
        local = detect_target_abi(FakeAdapter(raw, [_map("/lib/libc.so.6")], files=files), 1)
        self.assertEqual(local.libc_version, "2.35")
        remote = detect_target_abi(FakeAdapter(raw, [_map("/lib/libc.so.6")], remote=True, files=files), 1)
        self.assertEqual(remote.libc, LIBC_GLIBC)
        self.assertIsNone(remote.libc_version)

    def test_detection_failure_makes_every_feature_inconclusive(self):
        """SYNTHETIC: adapter that cannot read the ELF header / garbage header / adapter that raises."""
        class Raising(FakeAdapter):
            def read_target_file(self, pid, path, max_bytes):
                raise OSError("boom")

        for adapter in (
            FakeAdapter(None, [_map("/lib/libc.so.6")]),
            FakeAdapter(b"not an elf at all" * 10, [_map("/lib/libc.so.6")]),
            Raising(None, []),
        ):
            abi = detect_target_abi(adapter, 1)
            self.assertEqual(abi.status, DETECTION_FAILED)
            self.assertFalse(abi.detected)
            self.assertIsNone(abi.architecture)
            for f in SUPPORT_TABLE:
                self.assertEqual(check_support(abi, f).status, SUPPORT_INCONCLUSIVE, f)
            self.assertIsNone(syscall_name(abi, 98))

    def test_adapter_without_file_access_fails_closed(self):
        class NoFile(TargetExecutionAdapter):
            def check_liveness(self, pid): return True, None
            def get_process_identity(self, pid): return {}
            def get_threads(self, pid): return []
            def read_memory(self, pid, a, s): return None, "UNAVAILABLE", "x"
            def is_remote(self): return True
            def target_host(self): return "h"
            def get_proc_maps(self, pid): return []

        self.assertEqual(detect_target_abi(NoFile(), 1).status, DETECTION_FAILED)

    def test_allocator_gate(self):
        """SYNTHETIC ABI records feeding detect_allocator()."""
        maps = [{"pathname": "/lib/x86_64-linux-gnu/libc.so.6", "permissions": "r-xp"}]
        legacy = detect_allocator(maps)
        self.assertEqual(legacy.allocator_type, AllocatorType.GLIBC_PTMALLOC)
        self.assertIsNone(legacy.support_status)
        ok = detect_allocator(maps, target_abi=TargetABI(status="DETECTED", architecture="x86_64", word_size=64,
                                                         endianness="little", libc=LIBC_GLIBC))
        self.assertEqual(ok.allocator_type, AllocatorType.GLIBC_PTMALLOC)
        self.assertEqual(ok.support_status, SUPPORT_SUPPORTED)
        arm = detect_allocator(maps, target_abi=TargetABI(status="DETECTED", architecture="arm", word_size=32,
                                                          endianness="little", libc=LIBC_GLIBC))
        self.assertEqual(arm.allocator_type, AllocatorType.UNKNOWN)
        self.assertEqual(arm.support_status, SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertIn("arm/glibc", arm.basis)
        failed = detect_allocator(maps, target_abi=TargetABI())
        self.assertEqual(failed.allocator_type, AllocatorType.UNKNOWN)
        self.assertEqual(failed.support_status, SUPPORT_INCONCLUSIVE)
        # symbol-confirmed glibc is gated the same way
        sym = detect_allocator([], symbols=["__libc_malloc"], target_abi=TargetABI(
            status="DETECTED", architecture="aarch64", word_size=64, endianness="big", libc=LIBC_GLIBC))
        self.assertEqual(sym.allocator_type, AllocatorType.UNKNOWN)

    def test_tcb_discovery_gate_reads_no_memory_on_unsupported_target(self):
        """SYNTHETIC ABI: _discover_thread_tcb_addresses must return {} without touching memory."""
        mgr = WatchSessionManager(corpus_dir=tempfile.mkdtemp(prefix="abi_tcb_"))
        self.addCleanup(shutil.rmtree, mgr.corpus_dir, True)
        maps = [{"permissions": "rw-p", "pathname": "", "start_int": 0x10000, "end_int": 0x20000}]
        for abi in (
            TargetABI(status="DETECTED", architecture="aarch64", word_size=64, endianness="little", libc=LIBC_MUSL),
            TargetABI(status="DETECTED", architecture="arm", word_size=32, endianness="little", libc=LIBC_GLIBC),
            TargetABI(status="DETECTED", architecture="x86_64", word_size=64, endianness="little", libc=LIBC_MUSL),
            TargetABI(),
        ):
            res = mgr._discover_thread_tcb_addresses(
                pid=1, target_adapter=FakeAdapter(None, []), all_mappings=maps, threads=[{"tid": 1}],
                target_abi=abi,
            )
            self.assertEqual(res, {})
        # supported combinations proceed to read memory (FakeAdapter.read_memory raises)
        for arch in ("x86_64", "aarch64"):
            with self.assertRaises(AssertionError, msg=arch):
                mgr._discover_thread_tcb_addresses(
                    pid=1, target_adapter=FakeAdapter(None, []), all_mappings=maps, threads=[{"tid": 1}],
                    target_abi=TargetABI(status="DETECTED", architecture=arch, word_size=64,
                                         endianness="little", libc=LIBC_GLIBC),
                )


# =====================================================================================
# 3. Real native processes through the production inspection path
# =====================================================================================
@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestRealProcessGating(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="abi_real_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.deadlock_bin = os.path.join(cls.tmp, "deadlock")
        subprocess.run(
            ["gcc", "-g", "-O0", "-Wl,--build-id=sha1", os.path.join(FIXTURES, "proc_thread_circular_deadlock.c"),
             "-o", cls.deadlock_bin, "-pthread"], check=True)
        cls.tls_src = os.path.join(cls.tmp, "tls.c")
        with open(cls.tls_src, "w") as f:
            f.write(
                "#include <stdio.h>\n#include <unistd.h>\n"
                "__thread int tls_value = 7;\n"
                "volatile int spin;\n"
                "__attribute__((noinline)) void inner(int tag){ volatile int loc = tag; "
                "for(;;){ spin += loc; pause(); } }\n"
                "int main(void){ printf(\"READY\\n\"); fflush(stdout); inner(4242); return 0; }\n")
        cls.tls_bin = os.path.join(cls.tmp, "tlsprog")
        subprocess.run(["gcc", "-g", "-O0", cls.tls_src, "-o", cls.tls_bin], check=True)
        DwarfIndexer.clear_cache()
        cls.mgr = WatchSessionManager(corpus_dir=os.path.join(cls.tmp, "corpus"))

    def _launch(self, path):
        proc = subprocess.Popen([path], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (proc.kill(), proc.wait(), proc.stdout.close()))
        return proc

    def _deadlocked_process(self):
        proc = self._launch(self.deadlock_bin)
        time.sleep(0.6)
        self.assertIsNone(proc.poll())
        return proc

    def _inspect(self, proc, adapter):
        return self.mgr.inspect_thread_callstacks_and_locks(
            pid=proc.pid, companion_elf_path=self.deadlock_bin, adapter=adapter)

    def _wait_for_futex_threads(self, proc, adapter):
        deadline = time.monotonic() + 5
        while True:
            res = self._inspect(proc, adapter)
            if any(t.get("syscall") == "futex" for t in res["threads"]) or time.monotonic() > deadline:
                return res
            time.sleep(0.1)

    def test_supported_native_combination_still_names_owners_and_futex(self):
        """REAL: native process, real adapter. Owners resolved, cycle found, blocked threads show 'futex'
        (this is acceptance criterion 2 on an aarch64 host and the x86_64 name on an x86_64 host)."""
        proc = self._deadlocked_process()
        res = self._wait_for_futex_threads(proc, LocalTargetAdapter())
        self.assertEqual(res["target_abi"]["status"], DETECTION_DETECTED)
        if _NATIVE_MACHINE:
            self.assertEqual(res["target_abi"]["architecture"], _NATIVE_MACHINE)
        if res["target_abi"]["libc"] != LIBC_GLIBC:
            self.skipTest("native libc is not glibc; owner decoding is (correctly) unsupported here")
        self.assertEqual(res["lock_owner_status"], SUPPORT_SUPPORTED)
        owners = [l["owner_tid"] for l in res["locks"]]
        self.assertTrue(all(o for o in owners), res["locks"])
        self.assertTrue(res["deadlock_detected"])
        futex_threads = [t for t in res["threads"] if t["syscall"] == "futex"]
        self.assertGreaterEqual(len(futex_threads), 2)
        numbers = {t["syscall_nr"] for t in futex_threads}
        self.assertEqual(numbers, {98 if _NATIVE_MACHINE == "aarch64" else 202} if _NATIVE_MACHINE else numbers)

    def _native_abi_with(self, libc_interp, libc_map):
        """Native arch/word/endianness (parsed from the real exe), but a different libc."""
        with open(f"/proc/{os.getpid()}/exe", "rb") as f:
            real = parse_elf_header(f.read(65536))
        e_machine = {"x86_64": 62, "aarch64": 183, "arm": 40}.get(real["architecture"])
        if e_machine is None:
            self.skipTest(f"native arch {real['architecture']} not covered")
        return make_elf(e_machine, real["word_size"], real["endianness"] == "little", libc_interp), libc_map

    def test_musl_target_lock_owner_unsupported_no_owner_tid(self):
        """SYNTHETIC ABI over a REAL process: header/maps say musl, memory and threads are real.
        Acceptance criterion 1: unsupported status, no owner TID, no wait-for edge, no deadlock claim."""
        proc = self._deadlocked_process()
        exe, maps = self._native_abi_with("/lib/ld-musl-x.so.1", "/lib/ld-musl-x.so.1")
        res = self._inspect(proc, OverridingLocalAdapter(exe_bytes=exe, maps=maps))
        self.assertEqual(res["target_abi"]["libc"], LIBC_MUSL)
        self.assertEqual(res["lock_owner_status"], SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertIn("not supported on this target", res["lock_owner_status_reason"])
        self.assertIn("/musl", res["lock_owner_status_reason"])
        self.assertTrue(res["locks"], "locks are still listed")
        for lock in res["locks"]:
            self.assertIsNone(lock["owner_tid"])
            self.assertIsNone(lock["is_locked"])
            self.assertEqual(lock["owner_status"], SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertEqual(res["wait_for_edges"], [])
        self.assertFalse(res["deadlock_detected"])
        self.assertEqual(res["deadlock_cycle"], [])
        for t in res["threads"]:
            self.assertIsNone((t.get("waiting_on_lock") or {}).get("held_by_tid"))

    def test_detection_failure_makes_lock_check_inconclusive(self):
        """Acceptance criterion 4 on a REAL process: header unreadable -> no owner, no syscall name, no guess."""
        proc = self._deadlocked_process()
        res = self._inspect(proc, OverridingLocalAdapter(exe_bytes=None))
        self.assertEqual(res["target_abi"]["status"], DETECTION_FAILED)
        self.assertEqual(res["lock_owner_status"], SUPPORT_INCONCLUSIVE)
        self.assertTrue(all(l["owner_tid"] is None for l in res["locks"]))
        self.assertEqual(res["wait_for_edges"], [])
        self.assertFalse(res["deadlock_detected"])
        self.assertTrue(all(t["syscall"] is None for t in res["threads"]))
        self.assertTrue(any(t["syscall_nr"] is not None for t in res["threads"]), "raw number still reported")
        self.assertTrue(all(t["syscall_status"] == SUPPORT_INCONCLUSIVE for t in res["threads"]))

    def test_syscall_names_follow_detected_target_not_host(self):
        """SYNTHETIC ABI over a REAL process: the same raw futex number is named per the TARGET table.
        Claiming the target is arm (32-bit) makes the native futex number resolve through the arm table."""
        proc = self._deadlocked_process()
        exe, maps = self._native_abi_with("/lib/ld-linux-x.so.1", "/lib/libc.so.6")
        native = self._wait_for_futex_threads(proc, OverridingLocalAdapter(exe_bytes=exe, maps=maps))
        nr = next(t["syscall_nr"] for t in native["threads"] if t["syscall"] == "futex")
        arm_exe = make_elf(40, 32, True, "/lib/ld-linux-armhf.so.3")
        arm = self._inspect(proc, OverridingLocalAdapter(exe_bytes=arm_exe, maps="/lib/libc.so.6"))
        self.assertEqual(arm["target_abi"]["architecture"], "arm")
        arm_names = {t["syscall_nr"]: t["syscall"] for t in arm["threads"] if t["syscall_nr"] is not None}
        self.assertEqual(arm_names[nr], SYSCALL_TABLES["arm"].get(nr, f"syscall_{nr}"))
        self.assertEqual(arm["lock_owner_status"], SUPPORT_NOT_SUPPORTED_ON_TARGET)  # 32-bit: no LP64 layout

    def _tls_proc(self):
        proc = self._launch(self.tls_bin)
        self.assertEqual(proc.stdout.readline().strip(), b"READY")
        time.sleep(0.1)
        return proc

    def test_tls_and_frame_decoders_report_status_instead_of_garbage(self):
        """REAL: the TLS decoder is supported on x86_64 and aarch64 (glibc) and resolves every thread's TCB;
        on a target outside the table (arm, synthetic ABI over the real process) it returns the explicit
        unsupported status and no values.  Frame decoding is CFI-based since IMP-011: supported on
        x86_64 and aarch64; outside the table likewise unsupported with no values."""
        proc = self._tls_proc()
        expected = SUPPORT_SUPPORTED if _NATIVE_MACHINE in ("x86_64", "aarch64") else SUPPORT_NOT_SUPPORTED_ON_TARGET
        tls = self.mgr.inspect_thread_local_storage(pid=proc.pid, companion_elf_path=self.tls_bin)
        self.assertEqual(tls["tcb_scan_status"], expected)
        frames = self.mgr.inspect_thread_locals_and_frame_vars(pid=proc.pid, companion_elf_path=self.tls_bin)
        expected_frames = SUPPORT_SUPPORTED if _NATIVE_MACHINE in ("x86_64", "aarch64") else SUPPORT_NOT_SUPPORTED_ON_TARGET
        self.assertEqual(frames["frame_decode_status"], expected_frames)
        if _NATIVE_MACHINE in ("x86_64", "aarch64"):
            self.assertEqual(tls["tcb_resolved_count"], tls["threads_count"])
        arm_exe_tls = make_elf(40, 32, True, "/lib/ld-linux-armhf.so.3")
        arm_tls = self.mgr.inspect_thread_local_storage(
            pid=proc.pid, companion_elf_path=self.tls_bin,
            adapter=OverridingLocalAdapter(exe_bytes=arm_exe_tls, maps="/lib/libc.so.6"),
        )
        self.assertEqual(arm_tls["tcb_scan_status"], SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertEqual(arm_tls["tcb_resolved_count"], 0)
        self.assertIn("not supported on this target", arm_tls["tcb_scan_status_reason"])
        for t in arm_tls["threads"]:
            self.assertIsNone(t["tcb_address"])
            self.assertEqual(t["tls_variables"], [])
        # a target the support table does not cover: frames may still be identified (return-address
        # scan + DWARF) but carry no decoded values, and the status says why
        arm_exe = make_elf(40, 32, True, "/lib/ld-linux-armhf.so.3")
        arm_frames = self.mgr.inspect_thread_locals_and_frame_vars(
            pid=proc.pid, companion_elf_path=self.tls_bin,
            adapter=OverridingLocalAdapter(exe_bytes=arm_exe, maps="/lib/libc.so.6"),
        )
        self.assertEqual(arm_frames["frame_decode_status"], SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertIn("not supported on this target", arm_frames["frame_decode_status_reason"])
        self.assertEqual(arm_frames["cfi_unwind_status"], SUPPORT_NOT_SUPPORTED_ON_TARGET)
        for t in arm_frames["threads"]:
            for fr in t["frames"]:
                self.assertEqual((fr["parameters"], fr["locals"]), ([], []))
                self.assertIsNone(fr["cfa_address"])
                self.assertEqual(fr["variables_status"], SUPPORT_NOT_SUPPORTED_ON_TARGET)
        # local adapter's own TCB fallback is gated too: no thread gets a TCB address on non-x86
        if not _IS_X86_64:
            for t in LocalTargetAdapter().get_threads(proc.pid):
                self.assertIsNone(t["stack_info"].get("tcb_address_int"))

    def test_session_info_contains_detected_abi(self):
        """Acceptance criterion 3: REAL local attach; architecture, libc and word size in session info."""
        proc = self._launch(self.tls_bin)
        self.assertEqual(proc.stdout.readline().strip(), b"READY")
        session = self.mgr.create_session(pid=proc.pid, interval_ms=0, capture_mode="MANUAL")
        info = session.to_dict()["target_abi"]
        if _NATIVE_MACHINE:
            self.assertEqual(info["architecture"], _NATIVE_MACHINE)
        self.assertEqual(info["word_size"], struct.calcsize("P") * 8)
        self.assertEqual(info["endianness"], sys.byteorder)
        self.assertIn(info["libc"], (LIBC_GLIBC, LIBC_MUSL))
        self.assertEqual(info["status"], DETECTION_DETECTED)
        summary = session.to_summary_dict()
        self.assertEqual((summary["architecture"], summary["libc"], summary["word_size"]),
                         (info["architecture"], info["libc"], info["word_size"]))
        # survives persistence / reload
        reloaded = WatchSessionManager(corpus_dir=self.mgr.corpus_dir).get_session(session.session_id)
        self.assertEqual(reloaded.target_abi["architecture"], info["architecture"])
        self.assertEqual(session.target_identity["word_size"], info["word_size"])

    def test_session_records_failed_detection(self):
        """SYNTHETIC: detection fails at attach -> recorded as FAILED, attach still succeeds."""
        proc = self._launch(self.tls_bin)
        self.assertEqual(proc.stdout.readline().strip(), b"READY")
        session = self.mgr.create_session(
            pid=proc.pid, interval_ms=0, capture_mode="MANUAL", adapter=OverridingLocalAdapter(exe_bytes=None))
        self.assertEqual(session.target_abi["status"], DETECTION_FAILED)
        self.assertIsNone(session.target_abi["architecture"])
        self.assertTrue(session.target_abi["error"])


if __name__ == "__main__":
    unittest.main()
