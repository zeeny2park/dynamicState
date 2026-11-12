"""aarch64/glibc thread-pointer (TCB) discovery without stopping or tracing the target.

The fixture reads TPIDR_EL0 itself (`mrs x0, tpidr_el0`) and prints it with its TID for the main thread and
three pthread-created threads; the production discovery (`WatchSessionManager._discover_thread_tcb_addresses`)
must reproduce exactly these values, and the TLS decoder must read each thread's own `__thread` values from the
block that follows the thread pointer (TLS variant I).  Skipped on other architectures (inline asm).
"""
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.target_abi import LIBC_GLIBC, TargetABI
from extractor.target_adapter import LocalTargetAdapter
from extractor.watch_session import WatchSessionManager

_AARCH64 = platform.machine() in ("aarch64", "arm64")

FIXTURE = r"""
#define _GNU_SOURCE
#include <pthread.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static __thread int tv_a = 11;
static __thread long tv_b = 22;
static __thread alignas(ALIGN) long tv_c = 33;

static void report(const char *who, int idx)
{
    uint64_t tp;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
    long tid = (long)syscall(SYS_gettid);
    tv_a = (int)tid;
    tv_b = 1000 + idx;
    tv_c = 2000 + idx;
    printf("%s tid=%ld tp=0x%lx\n", who, tid, (unsigned long)tp);
    fflush(stdout);
}

static void *worker(void *arg)
{
    report("worker", (int)(intptr_t)arg);
    for (;;)
        sleep(1);
    return 0;
}

int main(void)
{
    pthread_t t[3];
    report("main", 0);
    for (int i = 0; i < 3; i++)
        pthread_create(&t[i], 0, worker, (void *)(intptr_t)(i + 1));
    for (;;)
        sleep(1);
}
"""


class _ZeroAdapter:
    """Memory that never holds a valid thread control block."""

    def read_memory(self, pid, address, size):
        return bytes(size), "OBSERVED", None


@unittest.skipUnless(_AARCH64 and shutil.which("gcc"), "needs an aarch64 host with gcc")
class TestAarch64TcbDiscovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="dynstate_a64tcb_")
        cls.src = os.path.join(cls.tmp, "tp.c")
        with open(cls.src, "w") as f:
            f.write(FIXTURE)
        cls.mgr = WatchSessionManager(corpus_dir=os.path.join(cls.tmp, "corpus"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _launch(self, align):
        exe = os.path.join(self.tmp, f"tp_{align}")
        subprocess.run(["gcc", "-g", "-O0", f"-DALIGN={align}", self.src, "-o", exe, "-pthread"], check=True)
        proc = subprocess.Popen([exe], stdout=subprocess.PIPE, text=True)
        self.addCleanup(self._kill, proc)
        expected = {}
        for _ in range(4):
            m = re.search(r"tid=(\d+) tp=0x([0-9a-f]+)", proc.stdout.readline())
            self.assertIsNotNone(m, "fixture did not report")
            expected[int(m.group(1))] = int(m.group(2), 16)
        time.sleep(0.05)
        return exe, proc, expected

    @staticmethod
    def _kill(proc):
        proc.kill()
        proc.wait(timeout=5)
        if proc.stdout:
            proc.stdout.close()

    def test_discovered_thread_pointers_equal_tpidr_el0_of_every_thread(self):
        _exe, proc, expected = self._launch(64)
        adapter = LocalTargetAdapter()
        maps = adapter.get_proc_maps(proc.pid)
        threads = adapter.get_threads(proc.pid)
        self.assertEqual({t["tid"] for t in threads}, set(expected))
        for tls_align in (None, 64):  # PT_TLS alignment unknown / the fixture's alignas(64)
            got = self.mgr._discover_thread_tcb_addresses(
                pid=proc.pid, target_adapter=adapter, all_mappings=maps, threads=threads, tls_align=tls_align,
            )
            self.assertEqual(got, expected, f"tls_align={tls_align}")
        self.assertIn(proc.pid, expected)  # the main thread (initial TLS mapping) is included
        # a wrong PT_TLS alignment contradicts dtv[1] of every thread: nothing is validated, nothing is guessed
        self.assertEqual(self.mgr._discover_thread_tcb_addresses(
            pid=proc.pid, target_adapter=adapter, all_mappings=maps, threads=threads, tls_align=8), {})

    def test_tls_decoder_reads_each_threads_own_values(self):
        for align in (8, 64):
            with self.subTest(align=align):
                exe, proc, expected = self._launch(align)
                res = self.mgr.inspect_thread_local_storage(pid=proc.pid, companion_elf_path=exe)
                self.assertEqual(res["tcb_scan_status"], "SUPPORTED")
                self.assertEqual(res["tcb_resolved_count"], 4)
                self.assertGreaterEqual(res["tls_variables_discovered"], 3)
                by_tid = {t["tid"]: t for t in res["threads"]}
                self.assertEqual(set(by_tid), set(expected))
                for tid, tp in expected.items():
                    self.assertEqual(by_tid[tid]["tcb_address"], f"0x{tp:x}")
                    vals = {v["name"]: v["value"] for v in by_tid[tid]["tls_variables"]}
                    self.assertEqual(vals["tv_a"], tid)
                    self.assertEqual(vals["tv_b"] // 1000, 1)
                    self.assertEqual(vals["tv_c"] // 1000, 2)
                    self.assertEqual(vals["tv_c"] % 1000, vals["tv_b"] % 1000)
                # distinct threads hold distinct values (per-thread divergence is visible)
                summaries = {v["name"]: v for v in res["variable_summaries"]}
                self.assertTrue(summaries["tv_a"]["has_per_thread_divergence"])

    def test_validation_failure_returns_nothing(self):
        abi = TargetABI(status="DETECTED", architecture="aarch64", word_size=64, endianness="little", libc=LIBC_GLIBC)
        maps = [{"permissions": "rw-p", "pathname": "", "start_int": 0x10000, "end_int": 0x20000}]
        got = self.mgr._discover_thread_tcb_addresses(
            pid=1, target_adapter=_ZeroAdapter(), all_mappings=maps, threads=[{"tid": 0}, {"tid": 4242}],
            target_abi=abi,
        )
        self.assertEqual(got, {})


if __name__ == "__main__":
    unittest.main()
