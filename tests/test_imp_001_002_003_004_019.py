"""Verification suite for roadmap items IMP-001, IMP-002, IMP-003, IMP-004 and IMP-019.

Each test drives the production code path and checks specific result fields (not whole-document
substring greps). Acceptance criteria: `20261112-1016-full/IMPROVEMENT_ROADMAP.md`.

- IMP-001: collection failure never becomes HEALTHY / 100 / NO_ISSUE_DETECTED / "healthy" wording.
- IMP-002: default capture never stops the target (polled from a separate process), stop modes need
           explicit approval, approved stops report a measured stop time, no "0.00ms" literal in sources.
- IMP-003: a single circular-wait observation is not a persistent deadlock; the collector re-observes.
- IMP-004: a supported growth recipe schedules and executes the two follow-up recipes.
- IMP-019: a runtime started without allow_mutation refuses every live state-changing operation,
           even after a request asks for CONSISTENT mode; web API auth/origin hardening.
"""

import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

from extractor.agent_runtime import AgentRuntime
from extractor.capture_backend import ProcessVmCaptureBackend
from extractor.capture_plan import CaptureMode, CapturePlan
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RecipeEvaluationResult,
    RECIPE_OBJECT_LIFETIME_ANOMALIES,
    RECIPE_POTENTIAL_DEADLOCK_PATTERNS,
    RECIPE_PROCESS_MEMORY_GROWTH,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
)
from extractor.expert_diagnostic_engine import ExpertDiagnosticEngine
from extractor.investigation import InvestigationManager
from extractor.runtime_evidence_provider import (
    COLLECTION_STATUS_FAILED,
    RuntimeEvidenceProvider,
)
from extractor.verdict_engine import DIAG_INCONCLUSIVE
from extractor.watch_session import WatchSessionManager
from extractor.web.server import run_server

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_DIR = os.path.join(REPO_ROOT, "tests", "fixtures", "real_runtime")

C_TARGET_SRC = r"""
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int in_use;
    int owner_tid;
    uint32_t seq;
    uint32_t size;
} Slot;

typedef struct {
    uint32_t magic;
    int active_buffers;
    int total_buffers;
    Slot buffers[4];
} Pool;

static Pool g_pool;
Pool *gpMem = &g_pool;
pthread_mutex_t g_lock_a = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_lock_b = PTHREAD_MUTEX_INITIALIZER;
volatile int g_running = 1;

void *transient_lock_worker(void *arg) {
    (void)arg;
    while (g_running) {
        pthread_mutex_lock(&g_lock_a);
        pthread_mutex_lock(&g_lock_b);
        usleep(500);
        pthread_mutex_unlock(&g_lock_b);
        pthread_mutex_unlock(&g_lock_a);
        usleep(10000);
    }
    return NULL;
}

int main(void) {
    memset(&g_pool, 0, sizeof(g_pool));
    g_pool.magic = 0xCAFEBABE;
    g_pool.total_buffers = 4;
    g_pool.active_buffers = 1;
    g_pool.buffers[0].in_use = 1;
    g_pool.buffers[0].seq = 1;
    g_pool.buffers[0].size = 64;

    pthread_t th;
    pthread_create(&th, NULL, transient_lock_worker, NULL);
    while (g_running) {
        usleep(20000);
    }
    pthread_join(th, NULL);
    return 0;
}
"""

# Cross-process /proc/<pid>/stat poller. Runs in its own interpreter so that it is scheduled
# independently of the capturing process and can observe sub-millisecond SIGSTOP windows.
POLLER_SRC = r"""
import os, sys
pid, stop_file, out_file = sys.argv[1], sys.argv[2], sys.argv[3]
path = "/proc/%s/stat" % pid
polls = 0
stopped = 0
open(out_file + ".ready", "w").close()
while not os.path.exists(stop_file):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        break
    state = data[data.rfind(b")") + 2:data.rfind(b")") + 3]
    polls += 1
    if state in (b"T", b"t"):
        stopped += 1
with open(out_file, "w") as f:
    f.write("%d %d" % (polls, stopped))
"""


def _compile(src_path: str, out_path: str) -> None:
    subprocess.run(["gcc", "-g", "-O0", "-pthread", src_path, "-o", out_path], check=True)


def _nonexistent_pid() -> int:
    p = subprocess.Popen(["true"])
    p.wait(timeout=5)
    pid = p.pid
    while os.path.exists(f"/proc/{pid}"):
        pid += 7919
    return pid


class _ImpTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.TemporaryDirectory(prefix="dynstate_imp_")
        cls.src_path = os.path.join(cls.tmp_dir.name, "imp_target.c")
        cls.bin_path = os.path.join(cls.tmp_dir.name, "imp_target")
        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(C_TARGET_SRC)
        _compile(cls.src_path, cls.bin_path)
        cls.proc = subprocess.Popen([cls.bin_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.2)
        cls.corpus_dir = os.path.join(cls.tmp_dir.name, "corpus")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2)
            except Exception:
                cls.proc.kill()
        cls.tmp_dir.cleanup()

    def _spawn_fixture(self, fixture_name: str) -> subprocess.Popen:
        out = os.path.join(self.tmp_dir.name, os.path.splitext(fixture_name)[0])
        if not os.path.exists(out):
            _compile(os.path.join(FIXTURE_DIR, fixture_name), out)
        proc = subprocess.Popen([out], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def _cleanup() -> None:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)

        self.addCleanup(_cleanup)
        return proc


# -----------------------------------------------------------------------------
# IMP-001
# -----------------------------------------------------------------------------
class TestImp001CollectionFailureIsInconclusive(_ImpTestBase):
    HEALTHY_REMEDIATION = "within expected parameters"

    def _assert_inconclusive_incident(self, rep: Dict[str, Any], expect_limitation: Optional[str] = None) -> None:
        self.assertEqual(rep["overall_status"], "INCONCLUSIVE")
        self.assertEqual(rep["verdict"], DIAG_INCONCLUSIVE)
        self.assertIsNone(rep["health_score"])
        self.assertTrue(rep["limitations"], "inconclusive report must carry the failure reason")
        if expect_limitation:
            self.assertTrue(any(expect_limitation in lim for lim in rep["limitations"]), rep["limitations"])
        rj = json.loads(rep["report_json"])
        self.assertEqual(rj["final_diagnosis"], DIAG_INCONCLUSIVE)
        self.assertNotEqual(rj["stop_reason"], "SUFFICIENT_EVIDENCE")
        self.assertLessEqual(rj["confidence_score"], 0.2)
        for item in rep["remediation_checklist"]:
            self.assertNotIn(self.HEALTHY_REMEDIATION, item)
        self.assertIn("N/A", re.search(r"\*\*Overall Status\*\*.*", rep["report_markdown"]).group(0))
        self.assertNotIn("Health Score: 100", rep["llm_next_step_hint"])

    def test_triage_exception_yields_inconclusive_report(self) -> None:
        wsm = WatchSessionManager(corpus_dir=self.corpus_dir)
        with mock.patch.object(
            WatchSessionManager, "auto_triage_incident", side_effect=RuntimeError("simulated triage failure")
        ) as m_triage:
            rep = wsm.export_incident_report(
                title="IMP-001 triage failure",
                pid=self.proc.pid,
                companion_elf_path=self.bin_path,
            )
        self.assertTrue(m_triage.called)
        self._assert_inconclusive_incident(rep, expect_limitation="simulated triage failure")

    def test_triage_exception_caps_passing_hypothesis_verdict(self) -> None:
        wsm = WatchSessionManager(corpus_dir=self.corpus_dir)
        # Sanity: the assertion really passes on the live target, so the cap below is meaningful.
        hyp = wsm.verify_runtime_hypothesis(
            hypothesis="pool magic intact",
            assertions=["gpMem.magic == 3405691582"],
            pid=self.proc.pid,
            companion_elf_path=self.bin_path,
            correlate_owners=False,
        )
        self.assertEqual(hyp["verdict"], "CONFIRMED")
        with mock.patch.object(
            WatchSessionManager, "auto_triage_incident", side_effect=RuntimeError("simulated triage failure")
        ):
            rep = wsm.export_incident_report(
                title="IMP-001 triage failure with passing hypothesis",
                pid=self.proc.pid,
                companion_elf_path=self.bin_path,
                hypothesis="pool magic intact",
                assertions=["gpMem.magic == 3405691582"],
            )
        self._assert_inconclusive_incident(rep, expect_limitation="simulated triage failure")

    def test_unreadable_pid_yields_inconclusive_report(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("running as root: PID 2 is readable")
        if not os.path.exists("/proc/2/stat"):
            self.skipTest("PID 2 (kthreadd) not visible in this PID namespace")
        try:
            os.readlink("/proc/2/exe")
            self.skipTest("/proc/2/exe unexpectedly readable")
        except PermissionError:
            pass
        except OSError:
            pass
        wsm = WatchSessionManager(corpus_dir=self.corpus_dir)
        rep = wsm.export_incident_report(title="IMP-001 unreadable PID", pid=2)
        self._assert_inconclusive_incident(rep)

    def test_nonexistent_pid_yields_inconclusive_report(self) -> None:
        dead_pid = _nonexistent_pid()
        wsm = WatchSessionManager(corpus_dir=self.corpus_dir)
        rep = wsm.export_incident_report(
            title="IMP-001 nonexistent PID", pid=dead_pid, companion_elf_path=self.bin_path
        )
        self._assert_inconclusive_incident(rep, expect_limitation=str(dead_pid))

    def test_all_insufficient_expert_run_has_no_healthy_wording(self) -> None:
        """A run whose every recipe is INSUFFICIENT_EVIDENCE must not read as healthy / confirmed clean.

        A single-recipe session on a live idle process has no allocation lifetime data (object lifetime) and no
        lock graph (deadlock), so each recipe is genuinely INSUFFICIENT_EVIDENCE through the production path.
        (Until IMP-008 the memory-growth recipe served here - one RSS sample per run; it now observes memory >= 3
        times per run and can measure that an idle process is stable, so it is no longer insufficient. The
        object-lifetime recipe goes through the same memory collection path, including the heap walks.)
        """
        idle = subprocess.Popen(["sleep", "60"])
        self.addCleanup(lambda: (idle.kill(), idle.wait(timeout=5)))
        time.sleep(0.1)
        eng = ExpertDiagnosticEngine(corpus_dir=self.corpus_dir)
        for rid in (RECIPE_OBJECT_LIFETIME_ANOMALIES, RECIPE_POTENTIAL_DEADLOCK_PATTERNS):
            with self.subTest(recipe=rid):
                sess = eng.start_investigation(
                    problem_statement=f"Targeted execution of diagnostic recipe {rid}", pid=idle.pid, target_recipe=rid
                )
                concl = sess.run_to_completion(max_steps=10)
                self.assertEqual([(c.recipe_id, c.status) for c in sess.checks], [(rid, "INCONCLUSIVE")])
                self.assertEqual(sess.verified_checks_count, 0)
                self.assertIn(concl.overall_verdict, ("INCONCLUSIVE", "ABORTED"))
                texts = [concl.executive_summary, concl.primary_finding] + list(concl.recommended_remediations)
                for text in texts:
                    low = str(text).lower()
                    self.assertNotIn("healthy", low)
                    self.assertNotIn("no abnormal runtime indicators", low)
                    self.assertNotIn("strongest hypothesis confirmed", low)
                    self.assertNotIn("no active remediation required", low)


# -----------------------------------------------------------------------------
# IMP-002
# -----------------------------------------------------------------------------
class TestImp002ZeroStopDefault(_ImpTestBase):
    def _poll_while(self, pid: int, action) -> Tuple[int, int]:
        work = tempfile.mkdtemp(dir=self.tmp_dir.name)
        stop_file = os.path.join(work, "stop")
        out_file = os.path.join(work, "out")
        poller = subprocess.Popen([sys.executable, "-I", "-c", POLLER_SRC, str(pid), stop_file, out_file])
        try:
            deadline = time.monotonic() + 10
            while not os.path.exists(out_file + ".ready"):
                self.assertLess(time.monotonic(), deadline, "poller did not start")
                time.sleep(0.01)
            time.sleep(0.05)
            action()
        finally:
            open(stop_file, "w").close()
            poller.wait(timeout=10)
        with open(out_file, encoding="utf-8") as f:
            polls, stopped = (int(x) for x in f.read().split())
        self.assertGreater(polls, 100, "poller did not sample the target often enough")
        return polls, stopped

    def test_default_capture_paths_never_stop_target_and_stop_modes_require_approval(self) -> None:
        pid = self.proc.pid
        mgr = InvestigationManager(corpus_dir=self.corpus_dir)
        runtime = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir.name, "corpus_rt"))
        results: Dict[str, Any] = {}

        def default_paths() -> None:
            for _ in range(5):
                results["inv"] = mgr.start_investigation(
                    goal="default investigate", pid=pid, debug_image=self.bin_path, authorize_target=True
                )
                ProcessVmCaptureBackend().capture(pid)
                results["fast"] = runtime.fast_capture(pid=pid)

        _, stopped_default = self._poll_while(pid, default_paths)
        self.assertEqual(stopped_default, 0, "default capture paths must never put the target into state T")
        rep = mgr.generate_report(results["inv"]["investigation_id"])
        self.assertEqual(rep["collection_mode"], "ZERO_STOP")
        self.assertEqual(rep["capture_quality"]["stop_mechanism"], "NONE")
        self.assertTrue(results["fast"].success)

        # Stop modes without approval are rejected.
        with self.assertRaises(PermissionError):
            ProcessVmCaptureBackend().capture(pid, plan=CapturePlan(mode=CaptureMode.FULL.value))
        res_unapproved = runtime.fast_capture(pid=pid, plan={"mode": "FULL"})
        self.assertFalse(res_unapproved.success)

        # Sensitivity control: the same poller does see an approved stopped capture.
        def approved_stops() -> None:
            for _ in range(20):
                results["stop_inv"] = mgr.start_investigation(
                    goal="approved stopped investigate",
                    pid=pid,
                    debug_image=self.bin_path,
                    authorize_target=True,
                    allow_stop=True,
                    constraints={"capture_mode": "FULL", "allow_stop": True},
                )

        _, stopped_full = self._poll_while(pid, approved_stops)
        self.assertGreater(stopped_full, 0, "poller is not sensitive enough to observe an approved SIGSTOP")

        rep_stop = mgr.generate_report(results["stop_inv"]["investigation_id"])
        self.assertEqual(rep_stop["collection_mode"], "FULL")
        self.assertEqual(rep_stop["capture_quality"]["stop_mechanism"], "SIGSTOP")
        self.assertGreater(rep_stop["stop_duration_ms"], 0.0)

    def test_no_hardcoded_zero_stop_duration_literal_in_sources(self) -> None:
        pattern = re.compile(r"0\.00 ?ms")
        hits: List[str] = []
        for top in ("extractor", "scripts"):
            for dirpath, _dirs, files in os.walk(os.path.join(REPO_ROOT, top)):
                for name in files:
                    if not name.endswith((".py", ".js", ".html")):
                        continue
                    path = os.path.join(dirpath, name)
                    with open(path, encoding="utf-8", errors="replace") as f:
                        for lineno, line in enumerate(f, 1):
                            if pattern.search(line):
                                hits.append(f"{os.path.relpath(path, REPO_ROOT)}:{lineno}: {line.strip()[:120]}")
        self.assertEqual(hits, [], "hard-coded '0.00ms' stop-time claims remain:\n" + "\n".join(hits))


# -----------------------------------------------------------------------------
# IMP-003
# -----------------------------------------------------------------------------
class TestImp003DeadlockPersistence(_ImpTestBase):
    def test_single_cycle_flag_is_not_persistent(self) -> None:
        rec_dl = DiagnosticRecipeRegistry.get_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        res = DiagnosticRecipeRegistry().evaluate_recipe(rec_dl, {"cycle_detected": True})
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertNotEqual(res.details.get("state"), "PERSISTENT_DEADLOCK")
        self.assertFalse(res.details.get("deadlock_confirmed", False))

    def _first_cycle_sample(self, pid: int, binary: str) -> Dict[str, Any]:
        wsm = WatchSessionManager(corpus_dir=self.corpus_dir)
        deadline = time.monotonic() + 10
        while True:
            info = wsm.inspect_thread_callstacks_and_locks(pid=pid, companion_elf_path=binary)
            if info.get("deadlock_detected"):
                return info
            self.assertLess(time.monotonic(), deadline, "fixture never reached its deadlock")
            time.sleep(0.1)

    def test_real_deadlock_is_persistent_after_two_observations(self) -> None:
        proc = self._spawn_fixture("proc_thread_circular_deadlock.c")
        binary = os.path.join(self.tmp_dir.name, "proc_thread_circular_deadlock")
        self._first_cycle_sample(proc.pid, binary)
        provider = RuntimeEvidenceProvider(corpus_dir=self.corpus_dir)
        rec_dl = DiagnosticRecipeRegistry.get_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        obs, records = provider.collect_for_recipe(rec_dl, pid=proc.pid, companion_elf=binary)
        self.assertEqual(obs["observation_count"], 2)
        self.assertTrue(obs["cycle_persistent"])
        res = DiagnosticRecipeRegistry().evaluate_recipe(rec_dl, obs)
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertEqual(res.details.get("state"), "PERSISTENT_DEADLOCK")

        eng = ExpertDiagnosticEngine(corpus_dir=self.corpus_dir)
        run = eng.run_recipe(recipe_id=RECIPE_POTENTIAL_DEADLOCK_PATTERNS, pid=proc.pid, companion_elf=binary)
        dl_check = next(c for c in run["checks"] if c["recipe_id"] == RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        self.assertEqual(dl_check["status"], "FAIL")

    def test_transient_lock_holder_is_not_a_deadlock(self) -> None:
        eng = ExpertDiagnosticEngine(corpus_dir=self.corpus_dir)
        run = eng.run_recipe(recipe_id=RECIPE_POTENTIAL_DEADLOCK_PATTERNS, pid=self.proc.pid, companion_elf=self.bin_path)
        dl_check = next(c for c in run["checks"] if c["recipe_id"] == RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        self.assertNotEqual(dl_check["status"], "FAIL")

    def test_reobservation_outcomes(self) -> None:
        """Second sample: no cycle / different cycle / error dict / exception -> never persistent."""
        proc = self._spawn_fixture("proc_thread_circular_deadlock.c")
        binary = os.path.join(self.tmp_dir.name, "proc_thread_circular_deadlock")
        first = self._first_cycle_sample(proc.pid, binary)
        self.assertTrue(first.get("deadlock_cycle") or first.get("deadlock_cycles"))

        no_cycle = dict(first, deadlock_detected=False, deadlock_cycle=[], deadlock_cycles=[])
        cyc = list(first.get("deadlock_cycle") or first["deadlock_cycles"][0])
        other_cycle = [dict(c, owner_tid=int(c.get("owner_tid") or 0) + 100000) for c in cyc]
        different = dict(first, deadlock_cycle=other_cycle, deadlock_cycles=[other_cycle])
        error_dict = {"error": "simulated EACCES on second sample", "threads": [], "deadlock_detected": False}

        rec_dl = DiagnosticRecipeRegistry.get_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        cases = [
            ("no_cycle", no_cycle, False),
            ("different_cycle", different, False),
            ("error_dict", error_dict, True),
            ("raises", RuntimeError("simulated second-sample crash"), True),
        ]
        for name, second, is_failure in cases:
            with self.subTest(second_sample=name):
                provider = RuntimeEvidenceProvider(corpus_dir=self.corpus_dir)
                with mock.patch.object(
                    provider.watch_manager, "inspect_thread_callstacks_and_locks", side_effect=[first, second]
                ):
                    obs, records = provider.collect_for_recipe(rec_dl, pid=proc.pid, companion_elf=binary)
                self.assertFalse(obs["cycle_persistent"])
                res = DiagnosticRecipeRegistry().evaluate_recipe(rec_dl, obs)
                self.assertNotEqual(res.status, RECIPE_STATUS_SUPPORTED)
                self.assertNotEqual(res.details.get("state"), "PERSISTENT_DEADLOCK")
                lock_recs = [r for r in records if r.collection_scope == "THREAD_LOCK_GRAPH" or "sample_index" in str(r.observed_value)]
                if is_failure:
                    self.assertEqual(obs["observation_count"], 1, "a failed re-read is not an observation")
                    self.assertFalse(obs.get("transient_cycle_resolved", False), "a failed re-read is not a resolution")
                    failed = [r for r in records if r.collection_status == COLLECTION_STATUS_FAILED]
                    self.assertTrue(failed, "the failed re-read must be recorded")
                    self.assertTrue(any("sample 2" in lim for r in failed for lim in r.limitations))
                else:
                    self.assertEqual(obs["observation_count"], 2)
                    self.assertTrue(lock_recs)
                if name == "no_cycle":
                    self.assertTrue(obs.get("transient_cycle_resolved"))


# -----------------------------------------------------------------------------
# IMP-004
# -----------------------------------------------------------------------------
class TestImp004GrowthFollowUps(_ImpTestBase):
    FOLLOW_UPS = ("RECIPE_HEAP_GROWTH", "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION")

    def test_supported_growth_adds_and_executes_follow_up_steps(self) -> None:
        """Runs run_recipe(growth) on the real growing fixture.

        A single run_recipe session takes one RSS sample, so the real growth evaluation cannot reach
        SUPPORTED without the multi-observation waiting that IMP-008 owns. The test therefore controls
        only the growth recipe's evaluation result (the narrowest seam); follow-up step construction,
        scheduling, collection and evaluation run unpatched against the live process.
        """
        proc = self._spawn_fixture("proc_scenario_b_growing_mem.c")
        binary = os.path.join(self.tmp_dir.name, "proc_scenario_b_growing_mem")
        time.sleep(0.2)
        orig_evaluate = DiagnosticRecipeRegistry.evaluate_recipe

        for confidence in (0.88, 0.96):  # below and above the early-stop threshold (0.90)
            with self.subTest(growth_confidence=confidence):
                def fake_evaluate(*args, **kwargs):
                    recipe = kwargs.get("recipe", args[-2] if len(args) >= 2 else None)
                    if recipe is not None and recipe.recipe_id == RECIPE_PROCESS_MEMORY_GROWTH:
                        return RecipeEvaluationResult(
                            recipe_id=recipe.recipe_id,
                            status=RECIPE_STATUS_SUPPORTED,
                            confidence=confidence,
                            confidence_basis="controlled growth evaluation (IMP-004 test seam)",
                            supporting_facts=["controlled"],
                            details={"growth_confirmed": True},
                        )
                    return orig_evaluate(*args, **kwargs)

                eng = ExpertDiagnosticEngine(corpus_dir=self.corpus_dir)
                with mock.patch.object(DiagnosticRecipeRegistry, "evaluate_recipe", side_effect=fake_evaluate):
                    run = eng.run_recipe(recipe_id=RECIPE_PROCESS_MEMORY_GROWTH, pid=proc.pid, companion_elf=binary)

                check_ids = [c["recipe_id"] for c in run["checks"]]
                self.assertEqual(check_ids.count(RECIPE_PROCESS_MEMORY_GROWTH), 1)
                self.assertEqual(sorted(check_ids), sorted([RECIPE_PROCESS_MEMORY_GROWTH, *self.FOLLOW_UPS]))
                for fid in self.FOLLOW_UPS:
                    chk = next(c for c in run["checks"] if c["recipe_id"] == fid)
                    self.assertNotIn(chk["status"], ("SKIPPED", "PENDING", "NOT_EXECUTED"))
                    # Executed against the live target: the check carries its own live observation.
                    self.assertTrue(chk.get("completion_timestamp"), f"{fid} has no recorded completion")
                    obs = chk.get("actual_observations") or {}
                    self.assertEqual(obs.get("recipe_id"), fid)
                    self.assertEqual(obs.get("pid"), proc.pid)
                    self.assertIsNotNone(obs.get("current_rss_kb"), f"{fid} recorded no live observation")


# -----------------------------------------------------------------------------
# IMP-019
# -----------------------------------------------------------------------------
class _FakeController:
    """Controller double: records every call so the test can prove refused actions never reach it."""

    def __init__(self) -> None:
        self.calls: List[str] = []

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)

        def _call(*args, **kwargs):
            self.calls.append(name)
            return {}

        return _call


MUTATING_CALLS = {
    "CHECKPOINT": lambda rt: rt.checkpoint(),
    "RESTORE": lambda rt: rt.restore("cp_1"),
    "EXECUTE_TRANSITION": lambda rt: rt.execute_transition({"candidate_id": "c1", "proposed_value": 1}),
    "EXPLORE": lambda rt: rt.explore(max_steps=1),
    "LIST_MUTATION_CANDIDATES": lambda rt: rt.list_mutation_candidates(),
    "REPLAY_MUTATION": lambda rt: rt.replay_mutation("s1", "o1", "f", 1),
    "VERIFY_RESTART_DETERMINISM": lambda rt: rt.verify_restart_determinism(),
}


class TestImp019ReadOnlyRuntime(_ImpTestBase):
    def test_default_runtime_refuses_mutation_even_after_consistent_observe(self) -> None:
        ctrl = _FakeController()
        rt = AgentRuntime(controller=ctrl, corpus_dir=os.path.join(self.tmp_dir.name, "corpus_ro"))
        obs = rt.observe(mode="CONSISTENT")
        self.assertFalse(obs.success)
        self.assertEqual(rt.observation_mode, "LOW_IMPACT")
        obs2 = rt.dispatch_action({"action": "OBSERVE", "mode": "CONSISTENT"})
        self.assertFalse(obs2.success)
        for name, call in MUTATING_CALLS.items():
            with self.subTest(operation=name):
                res = call(rt)
                self.assertFalse(res.success)
                self.assertEqual(res.error.code, "CAPABILITY_UNSUPPORTED")
                self.assertIn("read-only", res.error.message)
        self.assertEqual(ctrl.calls, [], "refused operations must never reach the controller")

    def test_consistent_mode_without_allow_mutation_is_still_read_only(self) -> None:
        ctrl = _FakeController()
        rt = AgentRuntime(controller=ctrl, corpus_dir=os.path.join(self.tmp_dir.name, "corpus_c"), observation_mode="CONSISTENT")
        for name, call in MUTATING_CALLS.items():
            with self.subTest(operation=name):
                res = call(rt)
                self.assertFalse(res.success)
                self.assertEqual(res.error.code, "CAPABILITY_UNSUPPORTED")
                self.assertIn("read-only", res.error.message)
        self.assertEqual(ctrl.calls, [])

    def test_allow_mutation_runtime_reaches_controller(self) -> None:
        ctrl = _FakeController()
        rt = AgentRuntime(controller=ctrl, corpus_dir=os.path.join(self.tmp_dir.name, "corpus_rw"), allow_mutation=True)
        res = rt.checkpoint()
        self.assertTrue(res.error is None or "read-only" not in res.error.message)
        self.assertIn("checkpoint", ctrl.calls)


class TestImp019WebApi(_ImpTestBase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.ctrl = _FakeController()
        cls.runtime = AgentRuntime(controller=cls.ctrl, corpus_dir=os.path.join(cls.tmp_dir.name, "corpus_web"))
        cls.server = run_server(runtime=cls.runtime, host="127.0.0.1", port=0)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.port = cls.server.server_address[1]
        cls.token = cls.server.session_token

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        super().tearDownClass()

    def _req(self, method: str, path: str, body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        hdrs = {"X-Session-Token": self.token}
        if body is not None:
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        hdrs = {k: v for k, v in hdrs.items() if v is not None}
        conn.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            data = {}
        return resp.status, data, resp

    def test_observe_request_cannot_unlock_mutation_endpoints(self) -> None:
        status, data, _ = self._req("POST", "/api/observe", {})
        self.assertEqual(status, 200)
        status, data, _ = self._req("POST", "/api/observe", {"mode": "CONSISTENT"})
        self.assertFalse(data.get("success"))
        for path, body in (
            ("/api/checkpoint", {}),
            ("/api/restore", {"checkpoint_id": "cp_1"}),
            ("/api/transition", {"candidate_id": "c1", "proposed_value": 1}),
            ("/api/explore", {"max_steps": 1}),
            ("/api/verify-determinism", {}),
            ("/api/snapshots/s1/replay", {"target_object_id": "o1", "field_name": "f", "value": 1}),
        ):
            with self.subTest(endpoint=path):
                _, data, _ = self._req("POST", path, body)
                self.assertFalse(data.get("success"), data)
                self.assertEqual(data["error"]["code"], "CAPABILITY_UNSUPPORTED")
                self.assertIn("read-only", data["error"]["message"])
        _, data, _ = self._req("GET", "/api/mutation-candidates")
        self.assertEqual(data["error"]["code"], "CAPABILITY_UNSUPPORTED")
        self.assertIn("read-only", data["error"]["message"])
        for forbidden in ("checkpoint", "restore", "explore", "verify_restart_determinism", "propose_mutations"):
            self.assertNotIn(forbidden, self.ctrl.calls)

    def test_origin_must_match_scheme_host_and_port(self) -> None:
        own = f"http://127.0.0.1:{self.port}"
        status, _, resp = self._req("GET", "/api/health", headers={"Origin": own})
        self.assertEqual(status, 200)
        self.assertEqual(resp.getheader("Access-Control-Allow-Origin"), own)
        other_port = self.port + 1 if self.port < 65535 else self.port - 1
        for origin in (f"http://localhost:{other_port}", f"http://127.0.0.1:{other_port}", f"https://127.0.0.1:{self.port}", "http://evil.example"):
            with self.subTest(origin=origin):
                status, _, resp = self._req("GET", "/api/health", headers={"Origin": origin})
                self.assertEqual(status, 403)
                self.assertIsNone(resp.getheader("Access-Control-Allow-Origin"))

    def test_token_only_from_headers_or_cookie(self) -> None:
        status, _, _ = self._req("GET", f"/api/health?token={self.token}", headers={"X-Session-Token": None})
        self.assertEqual(status, 401)
        status, _, _ = self._req("GET", "/api/health", headers={"X-Session-Token": None, "Cookie": f"dynamicstate_session={self.token}"})
        self.assertEqual(status, 200)

    def test_non_ascii_token_is_rejected_with_401(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.putrequest("GET", "/api/health")
        conn.putheader("X-Session-Token", "tökené".encode("latin-1"))
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        conn.close()
        self.assertEqual(resp.status, 401)


if __name__ == "__main__":
    unittest.main()
