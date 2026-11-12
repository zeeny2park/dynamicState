"""IMP-010: per-thread time-series sampling wired to the thread-misbehaviour recipes.

Every test that makes a claim about a target runs a REAL process (C fixtures compiled at test time) through the
expert engine's normal path (``start_investigation`` + ``run_to_completion`` / ``run_recipe``) or through
``RuntimeEvidenceProvider.collect_for_recipe``.  No test injects a conclusion such as ``starvation_detected``;
the only synthetic inputs are raw samples/edges for the pure derivation/persistence unit tests.
"""

import os
import select
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from extractor import thread_sampler
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RECIPE_LONG_RUNNING_BLOCKED_THREADS,
    RECIPE_POTENTIAL_DEADLOCK_PATTERNS,
    RECIPE_THREAD_STATE_ANOMALIES,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
)
from extractor.expert_diagnostic_engine import ExpertDiagnosticEngine
from extractor.observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
from extractor.runtime_evidence_provider import RuntimeEvidenceProvider
from extractor.target_adapter import LocalTargetAdapter
from extractor.target_abi import SUPPORT_NOT_SUPPORTED_ON_TARGET, SupportDecision
from extractor.thread_sampler import (
    LONG_WAIT_VERDICT,
    LockObservationSeries,
    ThreadSampler,
    ThreadSamplingConfig,
    ThreadSeries,
    cycle_signature,
    derive,
    judge,
)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_runtime")
SPIN_FUNCTIONS = ("spin_forever", "spin_thread")   # leaf recovery names the callee on x86_64, the caller elsewhere


def _check_status(run_result, recipe_id):
    return next(c for c in run_result["checks"] if c["recipe_id"] == recipe_id)["status"]


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class _RealProcessBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="imp010_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp_dir, True)
        cls.bins = {}

    @classmethod
    def _binary(cls, name):
        if name not in cls.bins:
            out = os.path.join(cls.tmp_dir, name)
            subprocess.run(
                ["gcc", "-g", "-O0", "-Wl,--build-id=sha1", os.path.join(FIXTURES, name + ".c"), "-o", out, "-pthread"],
                check=True,
            )
            cls.bins[name] = out
        return cls.bins[name]

    def _spawn(self, name, *args, ready=True, min_threads=0):
        binary = self._binary(name)
        proc = subprocess.Popen([binary, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)

        def _kill():
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()
            if proc.stdout:
                proc.stdout.close()

        self.addCleanup(_kill)
        deadline = time.monotonic() + 15
        if ready:
            while True:
                r, _, _ = select.select([proc.stdout], [], [], 0.2)
                if r and proc.stdout.readline().startswith(b"READY"):
                    break
                self.assertIsNone(proc.poll(), "fixture exited before READY")
                self.assertLess(time.monotonic(), deadline, "fixture never printed READY")
        else:
            # fixtures without a READY line: wait (bounded) until all threads exist and the waiters are asleep
            while True:
                try:
                    tids = os.listdir(f"/proc/{proc.pid}/task")
                except OSError:
                    tids = []
                states = []
                for t in tids:
                    try:
                        with open(f"/proc/{proc.pid}/task/{t}/stat") as f:
                            states.append(f.read().rsplit(")", 1)[1].split()[0])
                    except OSError:
                        pass
                if len(tids) >= min_threads and states and all(s == "S" for s in states):
                    time.sleep(0.2)
                    break
                self.assertIsNone(proc.poll(), "fixture exited early")
                self.assertLess(time.monotonic(), deadline, "fixture threads never reached steady state")
                time.sleep(0.05)
        return proc

    def _engine(self):
        return ExpertDiagnosticEngine(corpus_dir=tempfile.mkdtemp(prefix="imp010_corpus_", dir=self.tmp_dir))

    def _series_record(self, session):
        recs = [r for r in session.collected_evidence_records if r.collection_scope == "THREAD_TIME_SERIES"]
        self.assertTrue(recs, "no thread time-series evidence record was collected")
        return recs[-1]

    def _run_recipe(self, recipe_id, proc, name, **kw):
        eng = self._engine()
        res = eng.run_recipe(recipe_id=recipe_id, pid=proc.pid, companion_elf=self._binary(name), **kw)
        return res, eng.sessions[res["investigation_id"]]


class TestSpinAndLongWait(_RealProcessBase):
    def test_normal_plan_reports_spinning_thread_by_name_function_and_share(self):
        proc = self._spawn("proc_thread_spin_work_block", "swbc")
        eng = self._engine()
        session = eng.start_investigation(
            "the service is unresponsive and one thread seems stalled", pid=proc.pid,
            companion_elf=self._binary("proc_thread_spin_work_block"),
        )
        session.run_to_completion()
        checks = {c.recipe_id: c.status for c in session.checks}
        self.assertEqual(checks.get(RECIPE_THREAD_STATE_ANOMALIES), "FAIL", checks)
        obs = self._series_record(session).raw_details
        names = [t["name"] for t in obs["runaway_threads"]]
        spin_row = [t for t in obs["thread_summary"] if t["name"] == "spin_hang"]
        self.assertEqual(names, ["spin_hang"], f"busy_worker must not be flagged; spin_hang row: {spin_row}")
        spin = obs["runaway_threads"][0]
        self.assertIn(spin["function"], SPIN_FUNCTIONS)
        self.assertGreaterEqual(spin["cpu_share"], 0.5)
        self.assertEqual(spin["verdict"], "CPU monopoly without observable progress")
        # the finding that reaches the engine's evidence names the thread
        findings = [e.get("finding", "") for e in session.collected_evidence]
        self.assertTrue(any("spin_hang" in f and "CPU monopoly without observable progress" in f for f in findings), findings)
        # the control: same CPU class, but progressing (read/write syscalls advance, different frames)
        worker = next(t for t in obs["thread_summary"] if t["name"] == "busy_worker")
        self.assertGreaterEqual(worker["cpu_share"], 0.4)
        self.assertGreater(worker["io_syscalls_delta"], 0)

    def test_long_wait_is_reported_as_unknown_expectation_not_a_fault(self):
        proc = self._spawn("proc_thread_spin_work_block", "bc")
        res, session = self._run_recipe(RECIPE_LONG_RUNNING_BLOCKED_THREADS, proc, "proc_thread_spin_work_block")
        self.assertNotEqual(_check_status(res, RECIPE_LONG_RUNNING_BLOCKED_THREADS), "FAIL")
        raw = self._series_record(session).raw_details
        lw = {t["name"]: t for t in raw["long_wait_threads"]}
        self.assertIn("blocked_reader", lw)
        self.assertIn("cv_idle", lw)
        self.assertEqual(lw["blocked_reader"]["syscall"], "read")          # target-ABI syscall name, any host
        self.assertEqual(lw["blocked_reader"]["verdict"], LONG_WAIT_VERDICT)
        self.assertEqual(lw["blocked_reader"]["expectation"], "UNKNOWN")
        self.assertEqual(lw["cv_idle"]["syscall"], "futex")
        self.assertIn("condition variable", lw["cv_idle"]["wait_kind"])
        self.assertGreater(lw["blocked_reader"]["waited_at_least_sec"], 0.3)
        self.assertEqual(raw["runaway_threads"], [])
        self.assertTrue(any("cannot determine whether expected" in e.get("finding", "") or
                            "cannot determine whether expected" in str(e.get("details", "")) for e in session.collected_evidence)
                        or any("cannot determine whether expected" in f for f in raw["long_wait_findings"]))

    def test_rule_result_for_long_wait_says_cannot_determine(self):
        proc = self._spawn("proc_thread_spin_work_block", "b")
        prov = RuntimeEvidenceProvider()
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_LONG_RUNNING_BLOCKED_THREADS)
        obs, _ = prov.collect_for_recipe(recipe, proc.pid, self._binary("proc_thread_spin_work_block"))
        res = DiagnosticRecipeRegistry.evaluate_recipe(RECIPE_LONG_RUNNING_BLOCKED_THREADS, obs)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertIn("cannot determine whether expected", res.confidence_basis.lower())

    def test_normal_condition_variable_worker_is_not_reported(self):
        proc = self._spawn("proc_thread_normal_cv", ready=False, min_threads=2)
        for rid in (RECIPE_LONG_RUNNING_BLOCKED_THREADS, RECIPE_THREAD_STATE_ANOMALIES, RECIPE_POTENTIAL_DEADLOCK_PATTERNS):
            with self.subTest(recipe=rid):
                res, session = self._run_recipe(rid, proc, "proc_thread_normal_cv")
                self.assertNotEqual(_check_status(res, rid), "FAIL")
                if rid != RECIPE_POTENTIAL_DEADLOCK_PATTERNS:
                    raw = self._series_record(session).raw_details
                    self.assertEqual(raw["long_wait_threads"], [], raw["long_wait_findings"])
                    self.assertEqual(raw["runaway_threads"], [])
                    self.assertEqual(raw["thread_sampling"]["status"], "OK")

    def test_contention_fixtures_give_no_false_deadlock_or_stall(self):
        for fixture, n_threads in (("proc_two_waiters_one_lock", 4), ("proc_scenario_c_thread_contention", 3)):
            with self.subTest(fixture=fixture):
                proc = self._spawn(fixture, ready=False, min_threads=n_threads)
                for rid in (RECIPE_POTENTIAL_DEADLOCK_PATTERNS, RECIPE_LONG_RUNNING_BLOCKED_THREADS,
                            RECIPE_THREAD_STATE_ANOMALIES):
                    res, session = self._run_recipe(rid, proc, fixture)
                    self.assertNotEqual(_check_status(res, rid), "FAIL", (fixture, rid))
                    recs = [r for r in session.collected_evidence_records if r.collection_scope == "THREAD_TIME_SERIES"]
                    for r in recs:
                        self.assertEqual(r.raw_details["stalled_lock_waits"], [])
                        self.assertEqual(r.raw_details["runaway_threads"], [])


class TestHealthyIdlePoolRegression(_RealProcessBase):
    """A pool of workers idle on a condition variable (plus an uncontended mutex) is not a fault.

    Regression: long-wait observations of unknown expectedness were passed as ``supporting_facts`` of an
    INSUFFICIENT_EVIDENCE result; the engine turns every supporting fact into SUPPORTED evidence, so diagnose()
    reported a CONFIRMED deadlock finding with no subjects.
    """
    NAME = "proc_idle_pool_uncontended_mutex"

    def test_idle_condvar_pool_yields_no_fault_finding_through_the_engine(self):
        from extractor.expert_diagnostic_engine import diagnose
        proc = self._spawn(self.NAME)
        for symptom in ("are the worker threads deadlocked?", "the process is unresponsive and one thread seems stalled"):
            with self.subTest(symptom=symptom):
                res = diagnose(proc.pid, self._binary(self.NAME), symptom, corpus_dir=tempfile.mkdtemp(dir=self.tmp_dir))
                self.assertNotIn(res.verdict, ("CONFIRMED_FAULT", "PROBABLE_FAULT"), res.confidence_basis)
                self.assertEqual(res.findings, [])
                for f in res.findings:
                    self.assertTrue(f["subjects"])
                self.assertNotIn("FAIL", [c["status"] for c in res.checks_run])

    def test_long_wait_observation_is_not_evidence(self):
        proc = self._spawn(self.NAME)
        res, session = self._run_recipe(RECIPE_LONG_RUNNING_BLOCKED_THREADS, proc, self.NAME)
        self.assertEqual([e for e in session.collected_evidence if e.get("status") == "SUPPORTED"], [],
                         "an observation of unknown expectedness must not become SUPPORTED evidence")


class TestMemberMutexDeadlock(_RealProcessBase):
    NAME = "proc_thread_member_mutex_deadlock"

    def test_deadlock_through_struct_member_mutexes_names_variable_member(self):
        proc = self._spawn(self.NAME)
        res, session = self._run_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, proc, self.NAME)
        self.assertEqual(_check_status(res, RECIPE_POTENTIAL_DEADLOCK_PATTERNS), "FAIL")
        lock_recs = [r for r in session.collected_evidence_records
                     if r.collection_scope == "THREAD_LOCK_GRAPH" and isinstance(r.raw_details, dict)
                     and r.raw_details.get("deadlock_detected")]
        self.assertGreaterEqual(len(lock_recs), 2, "both samples must be recorded as observations")
        cycle = lock_recs[0].raw_details["deadlock_cycle"]
        self.assertEqual({e["lock_name"] for e in cycle}, {"g_acct_a.guard", "g_acct_b.guard"})
        self.assertEqual({e["waiter_name"] for e in cycle}, {"xfer_ab", "xfer_ba"})
        self.assertEqual({e["owner_name"] for e in cycle}, {"xfer_ab", "xfer_ba"})

    def test_persistence_is_judged_by_the_wait_for_graph(self):
        proc = self._spawn(self.NAME)
        prov = RuntimeEvidenceProvider()
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        obs, _ = prov.collect_for_recipe(recipe, proc.pid, self._binary(self.NAME))
        self.assertEqual(obs["observation_count"], 2)
        self.assertTrue(obs["cycle_persistent"])
        self.assertEqual(obs["lock_graph_persistence"]["state"], "PERSISTENT_DEADLOCK")
        self.assertEqual(obs["lock_graph_persistence"]["epochs"], [1, 2])

    def test_unsupported_target_reports_status_and_guesses_no_owner(self):
        proc = self._spawn(self.NAME)
        prov = RuntimeEvidenceProvider()
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        unsupported = SupportDecision("mutex_owner", SUPPORT_NOT_SUPPORTED_ON_TARGET, "not supported (test)")
        with mock.patch.object(thread_sampler, "check_support", return_value=unsupported):
            obs, _ = prov.collect_for_recipe(recipe, proc.pid, self._binary(self.NAME))
        self.assertFalse(obs["deadlock_detected"])
        member_locks = [l for l in obs["callstacks_info"]["locks"] if l["name"].endswith(".guard")]
        self.assertEqual({l["name"] for l in member_locks}, {"g_acct_a.guard", "g_acct_b.guard"})
        for l in member_locks:
            self.assertIsNone(l["owner_tid"])
            self.assertEqual(l["owner_status"], SUPPORT_NOT_SUPPORTED_ON_TARGET)
        self.assertTrue(obs.get("incomplete_lock_graph"), "waiters without a decodable owner = incomplete graph")


class TestSamplerBehaviour(_RealProcessBase):
    def test_threads_appearing_and_disappearing_and_count_trend(self):
        proc = self._spawn("proc_thread_spin_work_block", "xg")
        sampler = ThreadSampler(LocalTargetAdapter(), None)
        series = sampler.collect(proc.pid, "", ThreadSamplingConfig(samples=6, interval_sec=0.12))
        self.assertEqual(len(series.samples), 6)
        dv = derive(series)
        self.assertEqual(dv["thread_count_trend"], "growing", dv["thread_count_series"])
        appeared = [d for d in dv["threads"].values() if d["appeared_at_sample"]]
        self.assertTrue(appeared, "leaked threads appear after the first sample")
        gone = [d for d in dv["threads"].values() if d["disappeared_after_sample"]]
        self.assertTrue(gone, "ephemeral threads disappear between samples")
        res = judge(series)       # must not raise; short-lived threads are not judged
        self.assertEqual(res["runaway_threads"], [])
        self.assertTrue(all(t["samples_present"] >= 3 for t in res["long_wait_threads"] + res["runaway_threads"]))

    def test_budget_bounds_the_sampling(self):
        proc = self._spawn("proc_thread_spin_work_block", "b")
        tracker = ObservationBudgetTracker(limits=ObservationBudgetLimits(max_samples=3))
        prov = RuntimeEvidenceProvider(budget_tracker=tracker)
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_LONG_RUNNING_BLOCKED_THREADS)
        obs, _ = prov.collect_for_recipe(recipe, proc.pid, self._binary("proc_thread_spin_work_block"))
        self.assertLessEqual(obs["thread_sampling"]["samples_collected"], 3)

    def test_sampling_does_not_signal_or_stop_the_target(self):
        proc = self._spawn("proc_thread_spin_work_block", "sb")
        prov = RuntimeEvidenceProvider()
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_THREAD_STATE_ANOMALIES)
        prov.collect_for_recipe(recipe, proc.pid, self._binary("proc_thread_spin_work_block"))
        with open(f"/proc/{proc.pid}/status") as f:
            status = f.read()
        self.assertIn("State:\t", status)
        self.assertNotIn("(stopped)", status)
        self.assertIn("SigCgt", status)
        sig_blk_line = next(l for l in status.splitlines() if l.startswith("ShdPnd:"))
        self.assertEqual(int(sig_blk_line.split()[1], 16), 0, "no signal was queued for the process")


class TestDerivationAndPersistenceUnits(unittest.TestCase):
    """Pure units over RAW samples / edges (no conclusions are injected)."""

    @staticmethod
    def _series(rows):
        s = ThreadSeries(pid=1, config=ThreadSamplingConfig())
        for i, (t, recs) in enumerate(rows, 1):
            s.samples.append({"index": i, "t": t, "threads": {r["tid"]: r for r in recs}})
        return s

    @staticmethod
    def _rec(tid, ticks, vol=0, state="S", syscall=None, name="t", frame=None, io=0):
        return {"tid": tid, "name": name, "state": state, "utime_ticks": ticks, "stime_ticks": 0,
                "voluntary_ctxt_switches": vol, "nonvoluntary_ctxt_switches": 0, "io_syscalls": io,
                "syscall": syscall, "top_frame": {"function": frame, "source_location": None} if frame else None}

    def test_cpu_share_idle_time_and_same_frame_time(self):
        spin = lambda k: self._rec(7, k * 10, state="R", name="spin", frame="loop")      # noqa: E731
        s = self._series([(i * 0.1, [spin(i)]) for i in range(5)])
        d = derive(s)["threads"][7]
        self.assertAlmostEqual(d["cpu_share"], 1.0, places=2)         # 10 ticks per 0.1 s at CLK_TCK=100
        self.assertAlmostEqual(d["same_frame_sec"], 0.4, places=3)
        self.assertEqual(d["voluntary_switches_delta"], 0)
        res = judge(s)
        self.assertEqual([t["name"] for t in res["runaway_threads"]], ["spin"])

    def test_progress_by_syscalls_means_no_runaway(self):
        w = lambda k: self._rec(7, k * 10, state="R", name="work", frame="loop", io=k * 50)   # noqa: E731
        res = judge(self._series([(i * 0.1, [w(i)]) for i in range(5)]))
        self.assertEqual(res["runaway_threads"], [])

    def test_time_since_last_progress_and_thread_count(self):
        sc = {"running": False, "nr": 202, "args": [1, 128, 2, 0, 0, 0]}
        rows = [(0.0, [self._rec(1, 5, vol=1, syscall=sc)]),
                (0.1, [self._rec(1, 6, vol=2, syscall=sc)]),
                (0.2, [self._rec(1, 6, vol=2, syscall=sc), self._rec(2, 0)]),
                (0.3, [self._rec(1, 6, vol=2, syscall=sc), self._rec(2, 0)])]
        dv = derive(self._series(rows))
        self.assertAlmostEqual(dv["threads"][1]["idle_sec"], 0.2, places=3)
        self.assertFalse(dv["threads"][1]["idle_is_lower_bound"])
        self.assertEqual(dv["thread_count_series"], [1, 1, 2, 2])
        self.assertEqual(dv["thread_count_trend"], "growing")
        self.assertEqual(dv["threads"][2]["appeared_at_sample"], 3)

    def test_failed_sample_is_not_an_observation_and_different_cycle_is_not_persistence(self):
        def edge(w, lock, o):
            return {"waiter_tid": w, "waiter_name": f"t{w}", "lock_name": lock, "lock_address": lock,
                    "owner_tid": o, "owner_name": f"t{o}"}
        cyc = [edge(1, "A", 2), edge(2, "B", 1)]
        info = {"wait_for_edges": cyc, "deadlock_detected": True, "deadlock_cycles": [cyc]}
        sig = cycle_signature(cyc)

        one = LockObservationSeries()
        one.add_sample(1, info)
        self.assertFalse(one.persistence(sig)["persistent"])

        failed = LockObservationSeries()
        failed.add_sample(1, info)
        failed.add_failure(2, "EACCES")
        self.assertEqual(failed.observation_count, 1)
        self.assertFalse(failed.persistence(sig)["persistent"])

        other = [edge(1, "A", 3), edge(3, "C", 1)]
        diff = LockObservationSeries()
        diff.add_sample(1, info)
        diff.add_sample(2, {"wait_for_edges": other, "deadlock_detected": True, "deadlock_cycles": [other]})
        self.assertFalse(diff.persistence(sig)["persistent"])

        two = LockObservationSeries()
        two.add_sample(1, info)
        two.add_sample(2, info)
        p = two.persistence(sig)
        self.assertTrue(p["persistent"])
        self.assertEqual(p["state"], "PERSISTENT_DEADLOCK")

        resolved = LockObservationSeries()
        resolved.add_sample(1, info)
        resolved.add_sample(2, dict(info, deadlock_detected=False, deadlock_cycles=[]))
        self.assertFalse(resolved.persistence(sig)["persistent"])


if __name__ == "__main__":
    unittest.main()
