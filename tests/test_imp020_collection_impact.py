"""IMP-020: measuring the load a collection puts on the target.

Real processes: a small C fixture compiled at test time (architecture neutral) is the target; the "remote"
side is the natively built collector in daemon mode behind a local ``sh`` transport (same pattern as the
IMP-021 / IMP-011 tests).  Covers the measurement record (shape, monotonicity), the collector's own rusage,
the target-side CPU budget limit and ``timeout_ms`` bounding a deliberately slow read.
"""

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import time
import unittest

from extractor.capture_backend import (
    CaptureSafetyPolicy,
    ProcessTargetHandle,
    ProcessVmCaptureBackend,
    ProcfsCaptureBackend,
)
from extractor.capture_plan import CaptureMode, CapturePlan
from extractor.collection_impact import (
    CollectionImpactMeter,
    impact_summary_for_report,
    impact_summary_lines,
    parse_cpu_line,
    parse_stat_line,
)
from extractor.investigation import InvestigationSession
from extractor.observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
from extractor.target_adapter import LocalTargetAdapter, RemoteSshTargetAdapter
from tests.test_capture_lifecycle_seam import MockProcessTargetAdapter

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COLLECTOR_SRC = os.path.join(REPO_ROOT, "target", "collector")

FIXTURE_C = textwrap.dedent(
    r"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/prctl.h>
    int main(int argc, char **argv) {
        prctl(0x59616d61, (unsigned long)-1, 0, 0, 0);          /* PR_SET_PTRACER_ANY */
        static unsigned char buf[1 << 20];
        for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (unsigned char)(i * 7 + 3);
        printf("%lu\n", (unsigned long)(size_t)buf); fflush(stdout);
        if (argc > 1 && strcmp(argv[1], "idle") == 0) { for (;;) sleep(1); }
        volatile unsigned long n = 0;
        for (;;) n++;
    }
    """
)


def local_sh_runner(args, timeout, input_bytes=None):
    res = subprocess.run(["sh", "-c", args[-1]], input=input_bytes, capture_output=True, timeout=timeout)
    return res.returncode, res.stdout.decode(), res.stderr.decode()


def local_sh_stream(args):
    return subprocess.Popen(["sh", "-c", args[-1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)


@unittest.skipUnless(shutil.which("cc") and shutil.which("make") and os.path.exists("/proc/self/stat"),
                     "cc/make/procfs not available")
class CollectionImpactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp020_")
        src = os.path.join(cls.tmp, "fixture.c")
        with open(src, "w") as f:
            f.write(FIXTURE_C)
        cls.fixture = os.path.join(cls.tmp, "fixture")
        r = subprocess.run(["cc", "-O1", "-o", cls.fixture, src], capture_output=True, text=True)
        if r.returncode != 0:
            raise unittest.SkipTest("fixture build failed: " + r.stderr[-200:])
        build = os.path.join(cls.tmp, "build")
        shutil.copytree(COLLECTOR_SRC, build,
                        ignore=shutil.ignore_patterns("*.o", "dist", "dynamicstate-collector", "test_crypto"))
        r = subprocess.run(["make", "-C", build, "dynamicstate-collector"], capture_output=True, text=True)
        if r.returncode != 0:
            raise unittest.SkipTest("native collector build failed: " + r.stderr[-300:])
        cls.collector = os.path.join(build, "dynamicstate-collector")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self._procs = []
        self._adapters = []
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for a in self._adapters:
            a.close()
        for p in self._procs:
            p.kill()
            p.wait()
            p.stdout.close()

    def _spawn(self, mode):
        p = subprocess.Popen([self.fixture, mode], stdout=subprocess.PIPE, text=True)
        self._procs.append(p)
        return p, int(p.stdout.readline())

    def _remote(self, collector=None):
        a = RemoteSshTargetAdapter(host="localhost", command_runner=local_sh_runner, stream_opener=local_sh_stream,
                                   collector_path=collector)
        self._adapters.append(a)
        return a

    # ---- parsing -------------------------------------------------------------------------
    def test_parsers(self):
        rest = ["S"] + [str(i) for i in range(1, 11)] + ["25", "35", "0", "0", "0", "1", "0", "0", "777", "0", "0"]
        st = parse_stat_line("12 (a b) c) " + " ".join(rest))
        self.assertEqual((st["state"], st["utime"], st["stime"], st["starttime"]), ("S", 25, 35, "777"))
        self.assertEqual(parse_cpu_line("cpu  10 0 10 70 10 0 0 0 0 0"), {"total": 100, "idle": 80})
        self.assertIsNone(parse_cpu_line("garbage"))

    # ---- local measurement ---------------------------------------------------------------
    def test_local_record_shape_and_busy_target(self):
        p, _ = self._spawn("busy")
        meter = CollectionImpactMeter(LocalTargetAdapter(), p.pid).start()
        time.sleep(0.5)
        rec = meter.finish(bytes_read=4096, measured_stop_ms=0.0)
        d = json.loads(json.dumps(rec.to_dict()))
        for k in ("pid", "remote", "transport", "measured", "wall_ms", "bytes_read", "measured_stop_ms",
                  "target", "system", "diagnosis_attributable", "notes"):
            self.assertIn(k, d)
        self.assertTrue(d["measured"])
        self.assertFalse(d["remote"])
        self.assertEqual(d["transport"], "local")
        self.assertEqual((d["bytes_read"], d["measured_stop_ms"]), (4096, 0.0))
        t = d["target"]
        for k in ("cpu_ms", "utime_ms", "stime_ms", "ctx_switches", "ctx_switches_voluntary",
                  "ctx_switches_involuntary", "runqueue_wait_ms", "state_start", "state_end", "cpu_resolution_ms"):
            self.assertIn(k, t)
        self.assertGreaterEqual(d["wall_ms"], 450)
        self.assertGreater(t["cpu_ms"], 100)                         # spinning target used CPU...
        self.assertLessEqual(t["cpu_ms"], d["wall_ms"] * 1.2 + 30)   # ...but never more than the wall time
        self.assertIn(t["state_end"], ("R", "S"))
        self.assertIsNotNone(d["system"]["cpu_busy_fraction"])
        self.assertTrue(0.0 <= d["system"]["cpu_busy_fraction"] <= 1.0)
        a = d["diagnosis_attributable"]
        self.assertEqual(a["basis"], "diagnosing_process_cpu")
        self.assertIsNone(a["collector_cpu_ms"])
        self.assertTrue(any("not caused by the diagnosis" in n for n in d["notes"]))

    def test_local_idle_target_uses_no_cpu_and_nested_windows_are_monotonic(self):
        p, _ = self._spawn("idle")
        ad = LocalTargetAdapter()
        outer = CollectionImpactMeter(ad, p.pid).start()
        inner = CollectionImpactMeter(ad, p.pid).start()
        time.sleep(0.25)
        ri = inner.finish()
        time.sleep(0.25)
        ro = outer.finish()
        self.assertLess(ro.target["cpu_ms"], 50)                   # sleeping target
        self.assertEqual(ro.target["state_end"], "S")
        self.assertGreaterEqual(ro.wall_ms, ri.wall_ms)
        self.assertGreaterEqual(ro.target["cpu_ms"], ri.target["cpu_ms"])
        self.assertGreaterEqual(ro.target["ctx_switches"], ri.target["ctx_switches"])
        for r in (ri, ro):
            self.assertGreaterEqual(r.target["ctx_switches"], 0)
            self.assertGreaterEqual(r.diagnosis_attributable["host_process_cpu_ms"], 0)

    def test_target_gone_at_end_is_reported_not_raised(self):
        p, _ = self._spawn("idle")
        meter = CollectionImpactMeter(LocalTargetAdapter(), p.pid).start()
        p.kill()
        p.wait()
        rec = meter.finish()
        self.assertFalse(rec.measured)
        self.assertTrue(any("window end" in n for n in rec.notes))

    def test_summary_never_presents_unmeasured_as_zero(self):
        s = impact_summary_for_report(None, capture_mode="ZERO_STOP", measured_stop_ms=0.0, bytes_read=10)
        self.assertFalse(s["impact_measured"])
        self.assertNotIn("target_cpu_ms_during_window", s)
        self.assertTrue(any("not measured" in l for l in impact_summary_lines(s)))
        p, _ = self._spawn("idle")
        meter = CollectionImpactMeter(LocalTargetAdapter(), p.pid).start()
        time.sleep(0.05)
        s = impact_summary_for_report(meter.finish(), capture_mode="ZERO_STOP", measured_stop_ms=0.0, bytes_read=7,
                                      budget_exhausted=False)
        json.dumps(s)
        for k in ("target_cpu_ms_during_window", "target_ctx_switches_during_window", "system_cpu_busy_fraction",
                  "attributable_cpu_ms", "measured_stop_ms", "bytes_read", "capture_mode", "budget_exhausted"):
            self.assertIn(k, s)
        self.assertEqual((s["measured_stop_ms"], s["bytes_read"]), (0.0, 7))
        self.assertTrue(any("Target CPU during window" in l for l in impact_summary_lines(s)))

    # ---- remote through the real native collector ------------------------------------------
    def test_remote_collector_reports_target_and_its_own_rusage(self):
        p, base = self._spawn("busy")
        ad = self._remote(self.collector)
        meter = CollectionImpactMeter(ad, p.pid).start()
        for i in range(60):                                         # a diagnosis-like read sequence
            data, status, err = ad.read_memory(p.pid, base + (i * 4099) % (1 << 19), 8192)
            self.assertEqual(status, "OBSERVED", err)
        time.sleep(0.3)
        rec = meter.finish(bytes_read=60 * 8192, measured_stop_ms=0.0)
        d = rec.to_dict()
        self.assertTrue(d["remote"] and d["measured"])
        self.assertEqual(d["transport"], "daemon")
        self.assertEqual(ad.daemon_stats["opens"], 1)               # snapshot rode the one persistent channel
        self.assertGreater(d["target"]["cpu_ms"], 100)
        a = d["diagnosis_attributable"]
        self.assertEqual(a["basis"], "collector_process_rusage")
        self.assertGreater(a["collector_max_rss_kb"], 0)
        self.assertGreaterEqual(a["collector_cpu_ms"], 0.0)
        self.assertGreater(a["collector_cpu_total_ms"], 0.0)
        self.assertLess(a["collector_cpu_ms"], d["wall_ms"])        # the collector is not the busy one
        s = impact_summary_for_report(rec, capture_mode="ZERO_STOP")
        self.assertIsNotNone(s["collector_max_rss_kb"])
        self.assertEqual(s["attributable_basis"], "collector_process_rusage")

    def test_collector_stats_command_is_cumulative_and_monotonic(self):
        p, base = self._spawn("idle")
        ad = self._remote(self.collector)
        s0 = ad.read_collector_stats()
        for i in range(150):
            ad.read_memory(p.pid, base, 65536)
        s1 = ad.read_collector_stats()
        for k in ("pid", "cpu_user_us", "cpu_sys_us", "max_rss_kb"):
            self.assertIn(k, s0)
        self.assertGreater(s1["cpu_user_us"] + s1["cpu_sys_us"], s0["cpu_user_us"] + s0["cpu_sys_us"])
        self.assertGreaterEqual(s1["max_rss_kb"], s0["max_rss_kb"])
        self.assertEqual(ad.daemon_stats["opens"], 1)

    def test_remote_without_collector_falls_back_to_shell_and_says_so(self):
        p, _ = self._spawn("busy")
        ad = self._remote(None)
        meter = CollectionImpactMeter(ad, p.pid).start()
        time.sleep(0.3)
        rec = meter.finish()
        d = rec.to_dict()
        self.assertTrue(d["measured"])
        self.assertEqual(d["transport"], "shell")
        self.assertGreater(d["target"]["cpu_ms"], 50)
        self.assertIsNone(d["diagnosis_attributable"]["attributable_cpu_ms"])
        self.assertIsNone(d["diagnosis_attributable"]["collector_max_rss_kb"])
        self.assertTrue(any("collector self-cost unavailable" in n for n in d["notes"]))

    def test_old_collector_without_impact_command_falls_back(self):
        wrapper = os.path.join(self.tmp, "old_collector")
        with open(wrapper, "w") as f:   # an old collector answers UNKNOWN_COMMAND to the new commands
            f.write("#!/bin/sh\nwhile read l; do case \"$l\" in PING*) echo '{\"success\":true,\"status\":\"PONG\"}';;"
                    " QUIT*) echo '{\"success\":true,\"status\":\"BYE\"}'; exit 0;;"
                    " *) echo '{\"success\":false,\"error\":\"UNKNOWN_COMMAND\"}';; esac; done\n")
        os.chmod(wrapper, 0o755)
        p, _ = self._spawn("idle")
        ad = self._remote(wrapper)
        snap = ad.read_load_snapshot(p.pid)
        self.assertEqual(snap["transport"], "shell")
        self.assertIsNone(snap["collector"])
        self.assertIsNone(ad.read_collector_stats())

    # ---- budget: target-side CPU limit -------------------------------------------------------
    def test_budget_limit_unit(self):
        tr = ObservationBudgetTracker(ObservationBudgetLimits(max_target_cpu_ms=50.0))
        self.assertTrue(tr.can_continue())
        tr.record_target_cpu(30.0)
        self.assertTrue(tr.can_continue())
        tr.record_target_cpu(20.0)                                  # cumulative: never decreases
        self.assertTrue(tr.can_continue())
        tr.record_target_cpu(51.0)
        self.assertFalse(tr.can_continue())
        self.assertEqual(tr.metrics.exhausted_dimension, "TARGET_CPU")
        self.assertIn("EXCEEDED_TARGET_CPU", tr.exhaustion_reason)
        self.assertEqual(ObservationBudgetLimits.from_dict({"max_target_cpu_ms": 7}).max_target_cpu_ms, 7.0)
        self.assertIsNone(ObservationBudgetLimits().max_target_cpu_ms)
        unlimited = ObservationBudgetTracker(ObservationBudgetLimits())
        unlimited.attach_target_cpu_probe(lambda: 1e9)
        self.assertTrue(unlimited.can_continue())                   # no limit configured: probe is never consulted

    def test_remote_collector_cpu_limit_stops_collection_and_marks_partial(self):
        p, base = self._spawn("idle")
        ad = self._remote(self.collector)
        sess = InvestigationSession("inv_imp020", "cpu limit", "corpus", budgets={
            "max_target_cpu_ms": 3.0, "max_samples": 100000, "max_bytes_read": 1 << 40,
            "max_wall_clock_ms": 60000, "max_bytes_per_observation": 1 << 30,
        })
        sess.budget_tracker.attach_target_cpu_probe(None)           # re-attached by begin_collection_impact below
        sess.begin_collection_impact(ad, p.pid)
        sess.budget_tracker.attach_target_cpu_probe(sess.impact_meter.attributable_cpu_ms, poll_interval_ms=0)
        reads = 0
        while sess.budget_tracker.can_continue() and reads < 20000:
            ad.read_memory(p.pid, base, 65536)
            sess.budget_tracker.record_read(bytes_read=65536)
            reads += 1
        self.assertFalse(sess.budget_tracker.can_continue(), "CPU limit never tripped")
        self.assertLess(reads, 20000)
        self.assertEqual(sess.budget_tracker.metrics.exhausted_dimension, "TARGET_CPU")
        self.assertGreater(sess.budget_tracker.metrics.target_cpu_ms, 3.0)
        impact = sess.end_collection_impact()
        self.assertTrue(impact["budget_exhausted"])
        self.assertIn("EXCEEDED_TARGET_CPU", impact["budget_exhaustion_reason"])
        self.assertEqual(impact["attributable_basis"], "collector_process_rusage")
        self.assertGreater(impact["bytes_read"], 0)
        self.assertEqual(sess.to_dict()["collection_impact"], impact)
        self.assertTrue(any("collector" in l.lower() or "Budget exhausted" in l for l in impact_summary_lines(impact)))

    def test_local_host_cpu_limit_stops_collection(self):
        p, _ = self._spawn("idle")
        tr = ObservationBudgetTracker(ObservationBudgetLimits(max_target_cpu_ms=20.0))
        meter = CollectionImpactMeter(LocalTargetAdapter(), p.pid).start()
        tr.attach_target_cpu_probe(meter.attributable_cpu_ms, poll_interval_ms=0)
        self.assertTrue(tr.can_continue())
        t_end = time.process_time() + 0.2
        x = 0
        while time.process_time() < t_end:                          # host-side work counted as read cost
            x += 1
        self.assertFalse(tr.can_continue())
        self.assertEqual(tr.metrics.exhausted_dimension, "TARGET_CPU")

    # ---- timeout_ms --------------------------------------------------------------------------
    def _slow_capture(self, backend, timeout_ms):
        adapter = MockProcessTargetAdapter(initial_state="RUNNING")
        handle = ProcessTargetHandle(pid=adapter.pid, adapter=adapter)
        calls = []

        def slow_read(pid, addr, size):
            calls.append(addr)
            time.sleep(0.12)
            return b"S" * size

        ranges = [(0x1000 + i * 0x200, 0x1000 + i * 0x200 + 0x100) for i in range(8)]
        policy = CaptureSafetyPolicy(target_handle=handle, mem_reader=slow_read, timeout_ms=timeout_ms)
        plan = CapturePlan(mode=CaptureMode.ZERO_STOP.value, memory_ranges=ranges)
        t0 = time.monotonic()
        snap = backend.capture(adapter.pid, plan=plan, policy=policy)
        return snap, calls, time.monotonic() - t0

    def _assert_timeout_bounded(self, backend):
        snap, calls, took = self._slow_capture(backend, timeout_ms=300)
        self.assertGreaterEqual(len(calls), 1)
        self.assertLess(len(calls), 8, "timeout_ms did not stop the read loop")
        self.assertLess(took, 8 * 0.12 - 0.2)                       # well below the unbounded ~0.96 s
        prov = json.dumps([snap.provenance, snap.observation_metadata], default=str)
        self.assertIn("CAPTURE_TIMEOUT", prov)
        self.assertNotEqual(str(getattr(snap, "capture_status", "")), "COMPLETE")
        # the same capture with the bound disabled reads everything
        snap2, calls2, _ = self._slow_capture(backend, timeout_ms=0)
        self.assertEqual(len(calls2), 8)
        self.assertNotIn("CAPTURE_TIMEOUT", json.dumps([snap2.provenance, snap2.observation_metadata], default=str))

    def test_timeout_ms_bounds_slow_reads_process_vm_backend(self):
        self._assert_timeout_bounded(ProcessVmCaptureBackend())

    def test_timeout_ms_bounds_slow_reads_procfs_backend(self):
        self._assert_timeout_bounded(ProcfsCaptureBackend())

    # ---- benchmark smoke ------------------------------------------------------------------------
    def test_throughput_benchmark_smoke_shape(self):
        from benchmarks.collection_impact_benchmark import run_benchmark
        rep = json.loads(json.dumps(run_benchmark(0.3, 1, 50.0, ["local_unpinned", "remote_same_core"])))
        self.assertEqual(rep["benchmark"], "collection_impact_throughput")
        self.assertIn("architecture", rep["environment"])
        for sc in rep["scenarios"]:
            self.assertNotIn("skipped", sc)
            rp = sc["repetitions"][0]
            self.assertGreater(rp["idle_iter_per_s"], 0)
            self.assertGreater(rp["loaded_iter_per_s"], 0)
            self.assertIsNotNone(rp["throughput_delta_pct"])
            self.assertIn("median_throughput_delta_pct", sc)
            self.assertGreater(rp["diagnosis"]["bytes_read"], 0)
        self.assertEqual(rep["scenarios"][1]["repetitions"][0]["attributable_basis"], "collector_process_rusage")


if __name__ == "__main__":
    unittest.main()
