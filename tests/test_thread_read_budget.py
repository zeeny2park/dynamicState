"""Read-count budget for many-thread targets (deterministic, no wall-clock assertion).

A diagnosis of a process with hundreds of threads was dominated by re-serialising evidence, not by /proc reads; these
tests pin the properties that keep it that way: the thread-sampling window is shared by every thread check (a second
check adds no per-thread reads), the per-thread reads of one window stay below a fixed multiple of the thread count,
and ``dataclass_dict.asdict`` is equal to ``dataclasses.asdict``.
"""
import builtins
import dataclasses
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor.dataclass_dict import asdict as fast_asdict  # noqa: E402
from extractor.diagnostic_recipes import DiagnosticRecipeRegistry  # noqa: E402
from extractor.recipe_plugins import thread_leak as tl  # noqa: E402
from extractor.runtime_evidence_provider import RuntimeEvidenceProvider  # noqa: E402
from extractor.target_adapter import LocalTargetAdapter  # noqa: E402
from extractor.watch_session import WatchSessionManager  # noqa: E402

N_THREADS = 60
CHILD = ("import threading,time\n"
         "for _ in range(%d):\n"
         "    threading.Thread(target=time.sleep,args=(120,),daemon=True).start()\n"
         "print('READY',flush=True)\n"
         "time.sleep(120)\n" % N_THREADS)

# Measured: 15 per-thread /proc file reads per thread for a 3-sample window (5 per sample: stat, status, schedstat,
# syscall, comm).  Allow 2x headroom; a regression to a separate window per check (x4 or more) fails.
MAX_TASK_READS_PER_THREAD_PER_WINDOW = 30


class _Spy(LocalTargetAdapter):
    def __init__(self):
        super().__init__()
        self.calls: Dict[str, int] = {}

    def _n(self, name):
        self.calls[name] = self.calls.get(name, 0) + 1

    def get_threads(self, pid):
        self._n("get_threads")
        return super().get_threads(pid)

    def read_thread_samples(self, pid, counters=None):
        self._n("read_thread_samples")
        return super().read_thread_samples(pid, counters)


class TestThreadReadBudget(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proc = subprocess.Popen([sys.executable, "-c", CHILD], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)
        cls.proc.stdout.readline()
        time.sleep(0.3)
        cls.tmp = tempfile.mkdtemp(prefix="thread_budget_")

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.wait()
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _provider(self):
        p = RuntimeEvidenceProvider(adapter=_Spy(), watch_manager=WatchSessionManager(corpus_dir=self.tmp))
        p.thread_series_cache = {}
        p.thread_sampling_overrides = {"thread_sample_count": 3, "thread_sample_interval_sec": 0.05}
        return p

    def _count_task_reads(self, fn):
        pid = self.proc.pid
        pat = re.compile(r"/proc/%d/task/\d+/" % pid)
        n = [0]
        real_open = builtins.open

        def spy_open(f, *a, **k):
            if isinstance(f, str) and pat.match(f):
                n[0] += 1
            return real_open(f, *a, **k)

        builtins.open = spy_open
        try:
            fn()
        finally:
            builtins.open = real_open
        return n[0]

    def test_second_thread_check_reuses_the_window(self):
        provider = self._provider()
        recipe = DiagnosticRecipeRegistry.get_recipe(tl.RECIPE_THREAD_LEAK)
        pid = self.proc.pid
        out1: Dict[str, Any] = {}
        first = self._count_task_reads(lambda: provider._collect_thread_series(recipe, pid, None, out1, []))
        self.assertEqual(out1.get("thread_sampling", {}).get("status"), "OK", out1.get("thread_sampling"))
        calls_after_first = dict(provider.adapter.calls)
        out2: Dict[str, Any] = {}
        second = self._count_task_reads(lambda: provider._collect_thread_series(recipe, pid, None, out2, []))
        self.assertEqual(second, 0, "a second thread check must not read the threads again")
        self.assertEqual(provider.adapter.calls, calls_after_first)
        self.assertEqual(out1.get("thread_count_series"), out2.get("thread_count_series"))
        threads = len(os.listdir("/proc/%d/task" % pid))
        self.assertGreaterEqual(threads, N_THREADS)
        self.assertLessEqual(first, MAX_TASK_READS_PER_THREAD_PER_WINDOW * threads,
                             "%d per-thread reads for %d threads" % (first, threads))

    def test_adapter_calls_per_window_are_bounded_by_samples_not_threads(self):
        provider = self._provider()
        recipe = DiagnosticRecipeRegistry.get_recipe(tl.RECIPE_THREAD_LEAK)
        provider._collect_thread_series(recipe, self.proc.pid, None, {}, [])
        calls = provider.adapter.calls
        # 3 samples (+ at most one extra pass): the number of adapter round trips does not depend on the thread count
        self.assertLessEqual(calls.get("get_threads", 0), 8, calls)
        self.assertLessEqual(calls.get("read_thread_samples", 0), 8, calls)


@dataclasses.dataclass
class _Inner:
    a: int
    b: List[Any]


@dataclasses.dataclass
class _Outer:
    name: str
    inner: _Inner
    items: List[_Inner]
    mapping: Dict[str, Any]
    tup: tuple
    opt: Optional[str] = None


class TestFastAsdict(unittest.TestCase):
    def test_equal_to_stdlib_and_not_shared(self):
        o = _Outer("x", _Inner(1, [1, {"k": [2, 3]}]), [_Inner(2, []), _Inner(3, [None])],
                   {"m": {"n": [1, 2]}, "i": _Inner(4, [])}, (1, (2, 3)))
        got = fast_asdict(o)
        self.assertEqual(got, dataclasses.asdict(o))
        self.assertIsInstance(got["tup"], tuple)
        got["mapping"]["m"]["n"].append(9)
        self.assertEqual(o.mapping["m"]["n"], [1, 2])

    def test_rejects_non_dataclass(self):
        with self.assertRaises(TypeError):
            fast_asdict({"a": 1})


if __name__ == "__main__":
    unittest.main()
