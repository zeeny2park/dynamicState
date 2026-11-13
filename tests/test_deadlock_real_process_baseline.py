"""Real-process baseline for the current deadlock / thread-lock diagnosis path.

Compiles fixture programs from tests/fixtures/real_runtime at test time, launches them as
live processes, and runs the production path
    RuntimeEvidenceProvider.collect_for_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        -> DiagnosticRecipeRegistry.evaluate_recipe
against them.  No evidence is hand-built: all input comes from the live process.

Cases: two positives (2-thread and 3-thread circular wait) and two negative controls
(normal condition-variable wait, plain lock contention).
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.diagnostic_recipes import (
    RECIPE_POTENTIAL_DEADLOCK_PATTERNS,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipeRegistry,
)
from extractor.runtime_evidence_provider import RuntimeEvidenceProvider
from tests.support.fixture_process import fixture_popen

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_runtime")
SETTLE_S = 0.3          # let the fixture threads reach their steady (blocked) state
POSITIVE_WAIT_S = 5.0   # max time to wait for a deadlock to become observable


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestDeadlockRealProcessBaseline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="deadlock_baseline_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp_dir, True)
        cls.bins = {}
        for name in (
            "proc_thread_circular_deadlock",
            "proc_thread_3way_deadlock",
            "proc_thread_normal_cv",
            "proc_scenario_c_thread_contention",
        ):
            out = os.path.join(cls.tmp_dir, name)
            subprocess.run(
                ["gcc", "-g", "-O0", "-Wl,--build-id=sha1", os.path.join(FIXTURES, name + ".c"),
                 "-o", out, "-pthread"],
                check=True,
            )
            cls.bins[name] = out
        cls.provider = RuntimeEvidenceProvider()
        cls.recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)

    def _launch(self, name):
        proc = fixture_popen(
            [self.bins[name]], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        def _kill():
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()

        self.addCleanup(_kill)
        time.sleep(SETTLE_S)
        self.assertIsNone(proc.poll(), "fixture process exited prematurely")
        return proc

    def _observe(self, name, proc, epoch):
        obs, records = self.provider.collect_for_recipe(
            self.recipe, proc.pid, self.bins[name], session_id=f"dlbase_{proc.pid}", epoch_id=epoch
        )
        self.assertNotIn("lock_inspection_error", obs, obs.get("lock_inspection_error"))
        res = DiagnosticRecipeRegistry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, obs)
        return obs, res

    def _observe_positive(self, name, proc):
        deadline = time.monotonic() + POSITIVE_WAIT_S
        epoch = 1
        while True:
            obs, res = self._observe(name, proc, epoch)
            if obs.get("deadlock_detected") or time.monotonic() > deadline:
                return obs, res
            epoch += 1
            time.sleep(0.1)

    def _assert_positive(self, name, expected_locks, expected_cycle_len):
        proc = self._launch(name)
        obs, res = self._observe_positive(name, proc)

        self.assertTrue(obs.get("deadlock_detected"), "live deadlock not detected")
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED, res.confidence_basis)
        self.assertTrue(res.details.get("deadlock_confirmed"))

        cycle = obs["deadlock_cycle"]
        self.assertEqual(len(cycle), expected_cycle_len)
        waiters = [e["waiter_tid"] for e in cycle]
        owners = [e["owner_tid"] for e in cycle]
        live_tids = {t["tid"] for t in obs["threads"]}
        # every participant is a real thread of the process, none is the main thread
        self.assertEqual(len(set(waiters)), expected_cycle_len)
        self.assertEqual(set(waiters), set(owners), "cycle must be closed: waiters == owners")
        self.assertTrue(set(waiters) <= live_tids)
        self.assertNotIn(proc.pid, waiters)
        # each edge's owner is the next edge's waiter
        for i, edge in enumerate(cycle):
            self.assertEqual(edge["owner_tid"], cycle[(i + 1) % len(cycle)]["waiter_tid"])
        self.assertEqual({e["lock_name"] for e in cycle}, expected_locks)

    def _assert_negative(self, name):
        proc = self._launch(name)
        for epoch in (1, 2, 3):
            obs, res = self._observe(name, proc, epoch)
            self.assertFalse(obs.get("deadlock_detected"), f"false deadlock on {name}: {obs.get('deadlock_cycle')}")
            self.assertEqual(obs.get("deadlock_cycle"), [])
            self.assertEqual(obs.get("deadlock_cycles"), [])
            self.assertEqual(res.status, RECIPE_STATUS_CONTRADICTED, res.confidence_basis)
            self.assertFalse(res.details.get("deadlock_confirmed"))
            self.assertNotEqual(res.details.get("state"), "PERSISTENT_DEADLOCK")
            time.sleep(0.1)

    def test_positive_two_thread_circular_deadlock(self):
        self._assert_positive("proc_thread_circular_deadlock", {"g_mutex_a", "g_mutex_b"}, 2)

    def test_positive_three_thread_circular_deadlock(self):
        self._assert_positive("proc_thread_3way_deadlock", {"g_mutex_a", "g_mutex_b", "g_mutex_c"}, 3)

    def test_negative_control_normal_condition_variable_wait(self):
        self._assert_negative("proc_thread_normal_cv")

    def test_negative_control_plain_lock_contention(self):
        self._assert_negative("proc_scenario_c_thread_contention")


if __name__ == "__main__":
    unittest.main()
