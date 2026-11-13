"""An incomplete lock graph (a waiter whose lock has no owner) must be confirmed by re-reads before the deadlock /
blocked-thread checks call it incomplete: a contended mutex being handed on shows that state for a moment (the word
already reads unlocked while the woken waiter is still in its futex wait), which made a healthy target INCONCLUSIVE
under host load."""
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor import runtime_evidence_provider as rep  # noqa: E402
from extractor.diagnostic_recipes import (  # noqa: E402
    RECIPE_POTENTIAL_DEADLOCK_PATTERNS, RECIPE_STATUS_CONTRADICTED, RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    DiagnosticRecipeRegistry,
)

LOCK = "0x601040"


def _info(owner):
    """One inspection: tid 11 holds nothing and waits in futex on LOCK; the lock's owner is ``owner`` (None: unlocked
    or owner word not yet written)."""
    return {"success": True, "deadlock_detected": False, "deadlock_cycles": [], "lock_owner_status": "SUPPORTED",
            "locks": [{"name": "mu", "runtime_address": LOCK, "lock_state_word": 2 if owner else 0, "owner_tid": owner,
                       "waiting_tids": [11]}],
            "threads": [{"tid": 10, "name": "a", "waiting_on_lock": None},
                        {"tid": 11, "name": "b", "waiting_on_lock": {"lock_name": "mu", "lock_address": LOCK,
                                                                     "held_by_tid": owner}}],
            "blocked_threads": []}


class TestReread(unittest.TestCase):
    def _collect(self, seq):
        prov = rep.RuntimeEvidenceProvider()
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        it = iter(seq)
        calls = []

        def fake(pid, elf):
            calls.append(1)
            nxt = next(it)
            if isinstance(nxt, Exception):
                raise nxt
            return nxt
        with mock.patch.object(rep.RuntimeEvidenceProvider, "_inspect_locks", side_effect=fake), \
                mock.patch.object(rep.time, "sleep"):
            obs, _ = prov.collect_for_recipe(recipe, os.getpid(), "")
        return obs, len(calls)

    def test_unresolved_lock_waits(self):
        self.assertEqual(rep.unresolved_lock_waits(_info(None)), [(11, LOCK)])
        self.assertEqual(rep.unresolved_lock_waits(_info(10)), [])
        self.assertEqual(rep.unresolved_lock_waits(None), [])

    def test_transient_handoff_is_not_an_incomplete_graph(self):
        obs, calls = self._collect([_info(None), _info(10)])
        self.assertEqual(calls, 2)
        self.assertFalse(obs.get("incomplete_lock_graph"))
        self.assertEqual(obs["transient_unresolved_lock_waits"], [[{"tid": 11, "lock_address": LOCK}]])
        self.assertEqual(obs["callstacks_info"]["locks"][0]["owner_tid"], 10)

    def test_persistent_unresolved_owner_stays_incomplete(self):
        obs, calls = self._collect([_info(None)] * 4)
        self.assertEqual(calls, 1 + len(rep.UNRESOLVED_WAIT_REREAD_GAPS_S))
        self.assertTrue(obs.get("incomplete_lock_graph"))
        self.assertNotIn("transient_unresolved_lock_waits", obs)
        res = DiagnosticRecipeRegistry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, obs)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    def test_failed_reread_keeps_the_incomplete_first_read(self):
        obs, calls = self._collect([_info(None), RuntimeError("thread vanished")])
        self.assertEqual(calls, 2)
        self.assertTrue(obs.get("incomplete_lock_graph"))
        self.assertNotIn("lock_inspection_error", obs)

    def test_complete_first_read_is_not_reread(self):
        obs, calls = self._collect([_info(10)])
        self.assertEqual(calls, 1)
        self.assertFalse(obs.get("incomplete_lock_graph"))
        res = DiagnosticRecipeRegistry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, obs)
        self.assertEqual(res.status, RECIPE_STATUS_CONTRADICTED, res.confidence_basis)

    def test_settled_graph_clears_the_deadlock_check(self):
        obs, _ = self._collect([_info(None), _info(None), _info(10)])
        res = DiagnosticRecipeRegistry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, obs)
        self.assertEqual(res.status, RECIPE_STATUS_CONTRADICTED, res.confidence_basis)


if __name__ == "__main__":
    unittest.main()
