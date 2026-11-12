"""IMP-010: spin judgement by runnable fraction (schedstat), robust to machine load."""

import os
import subprocess
import sys
import unittest

from extractor.diagnostic_recipes import RECIPE_THREAD_STATE_ANOMALIES
from extractor.thread_sampler import (
    SCHEDSTAT_FALLBACK_NOTE, ThreadSamplingConfig, ThreadSeries, judge, read_thread_fields,
)
from tests.test_imp_010_thread_sampling import _RealProcessBase


def _rec(tick, run_ms=None, wait_ms=None, state="R", vol=0, io=0, frame="loop", name="t"):
    r = {"tid": 7, "name": name, "state": state, "utime_ticks": tick, "stime_ticks": 0,
         "voluntary_ctxt_switches": vol, "nonvoluntary_ctxt_switches": 0, "io_syscalls": io, "syscall": None,
         "top_frame": {"function": frame, "source_location": None}}
    if run_ms is not None:
        r["schedstat"] = {"run_ns": int(run_ms * 1e6), "wait_ns": int(wait_ms * 1e6),
                           "timeslices": 1 if (run_ms or wait_ms) else 0}
    return r


def _series(rows):
    s = ThreadSeries(pid=1, config=ThreadSamplingConfig())
    for i, (t, rec) in enumerate(rows, 1):
        s.samples.append({"index": i, "t": t, "threads": {7: rec}})
    return s


class TestDerivation(unittest.TestCase):
    def test_always_runnable_but_starved_is_flagged_with_both_numbers(self):
        # 1s window: 23% on CPU, 77% waiting on a run queue; a 0.23 CPU share alone would have missed it
        rows = [(i * 0.25, _rec(i * 6, run_ms=i * 57.5, wait_ms=i * 192.5)) for i in range(5)]
        j = judge(_series(rows))
        self.assertEqual(len(j["runaway_threads"]), 1, j["thread_findings"])
        r = j["runaway_threads"][0]
        self.assertEqual(r["judgement_basis"], "schedstat_runnable_fraction")
        self.assertGreaterEqual(r["runnable_fraction"], 0.99)
        self.assertAlmostEqual(r["runnable_cpu_received"], 0.23, delta=0.02)
        self.assertTrue(r["contended_machine"])
        self.assertIn("runnable 100% of the", j["thread_findings"][0].replace("was runnable", "runnable"))
        self.assertIn("received 23% of a CPU (machine contended)", j["thread_findings"][0])
        self.assertTrue(j["thread_sampling"]["schedstat_available"])

    def test_sleeping_thread_with_high_wait_is_not_flagged(self):
        # sampled in S half the time: not a spinner
        rows = [(i * 0.25, _rec(i * 2, run_ms=i * 25, wait_ms=i * 125, state="R" if i % 2 else "S")) for i in range(5)]
        self.assertEqual(judge(_series(rows))["runaway_threads"], [])
        # all samples R but runnable only 60% of the window (sleeps in between)
        rows = [(i * 0.25, _rec(i * 2, run_ms=i * 25, wait_ms=i * 125)) for i in range(5)]
        j = judge(_series(rows))
        self.assertEqual(j["runaway_threads"], [])
        self.assertAlmostEqual(j["thread_summary"][0]["runnable_fraction"], 0.6, delta=0.01)

    def test_runnable_but_doing_io_or_voluntary_switches_is_not_flagged(self):
        for kw in ({"io": 5}, {"vol": 50}):
            rows = [(i * 0.25, _rec(i * 6, run_ms=i * 57.5, wait_ms=i * 192.5,
                                    io=i * kw.get("io", 0), vol=i * kw.get("vol", 0))) for i in range(5)]
            self.assertEqual(judge(_series(rows))["runaway_threads"], [], kw)

    def test_fully_starved_thread_without_cpu_is_not_a_monopoly(self):
        rows = [(i * 0.25, _rec(0, run_ms=i * 0.1, wait_ms=i * 250)) for i in range(5)]
        self.assertEqual(judge(_series(rows))["runaway_threads"], [])

    def test_missing_or_zero_schedstat_uses_fallback_and_says_so(self):
        for mk in (lambda i: _rec(i * 25),                          # key absent
                   lambda i: _rec(i * 25, run_ms=0, wait_ms=0)):    # CONFIG_SCHED_INFO off: all zero
            j = judge(_series([(i * 0.25, mk(i)) for i in range(5)]))   # 100% CPU share
            r = j["runaway_threads"][0]
            self.assertEqual(r["judgement_basis"], "cpu_share_fallback")
            self.assertIsNone(r["runnable_fraction"])
            self.assertEqual(r["limitation"], SCHEDSTAT_FALLBACK_NOTE)
            self.assertIn("contended machine can hide a spinner", j["thread_findings"][0])
            self.assertFalse(j["thread_sampling"]["schedstat_available"])
            self.assertIn(SCHEDSTAT_FALLBACK_NOTE, j["thread_sampling"]["limitations"])
        # the fallback keeps the old threshold: a 20% share is not flagged
        j = judge(_series([(i * 0.25, _rec(i * 5)) for i in range(5)]))
        self.assertEqual(j["runaway_threads"], [])

    def test_local_reader_includes_schedstat(self):
        rec = read_thread_fields(os.getpid(), os.getpid(), {})
        if os.path.exists("/proc/self/schedstat"):
            self.assertEqual(set(rec["schedstat"]), {"run_ns", "wait_ns", "timeslices"})


class TestSpinUnderLoad(_RealProcessBase):
    def test_spinner_flagged_busy_worker_not_while_cpu_is_saturated(self):
        burners = [subprocess.Popen([sys.executable, "-c", "while True: pass"])
                   for _ in range(2 * (os.cpu_count() or 2))]

        def _kill():
            for b in burners:
                b.kill()
            for b in burners:
                b.wait()
        self.addCleanup(_kill)
        proc = self._spawn("proc_thread_spin_work_block", "swbc")
        eng = self._engine()
        session = eng.start_investigation("the service is unresponsive and one thread seems stalled", pid=proc.pid,
                                          companion_elf=self._binary("proc_thread_spin_work_block"))
        session.run_to_completion()
        checks = {c.recipe_id: c.status for c in session.checks}
        self.assertEqual(checks.get(RECIPE_THREAD_STATE_ANOMALIES), "FAIL", checks)
        obs = self._series_record(session).raw_details
        self.assertEqual([t["name"] for t in obs["runaway_threads"]], ["spin_hang"])
        spin = obs["runaway_threads"][0]
        self.assertGreaterEqual(spin["runnable_fraction"], 0.9)
        worker = next(t for t in obs["thread_summary"] if t["name"] == "busy_worker")
        self.assertGreater(worker["io_syscalls_delta"], 0)


if __name__ == "__main__":
    unittest.main()
