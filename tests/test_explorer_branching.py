import copy
import shutil
import tempfile
import unittest

from extractor.explorer import MutationCandidate, StateExplorer
from extractor.runtime_controller import ExecutionResult, RuntimeController
from extractor.snapshot import RuntimeSnapshot, StateTransition
from extractor.state_corpus import StateCorpus
from extractor.state_restorer import MockStateRestorer
from tests.test_state_hash import make_snapshot


class BranchingMockController(RuntimeController):
    """Simulates inferior process memory and branching execution."""

    def __init__(self):
        # Current simulated inferior state
        self.state = {"retry": 2, "state": "CONNECTED", "priority": 7}
        self.restorer = MockStateRestorer(
            capture_fn=lambda: copy.deepcopy(self.state),
            restore_fn=lambda saved: self._do_restore(saved)
        )
        self.transition_log = []
        self.snapshots = {}
        self._step = 0

    def _do_restore(self, saved):
        self.state = copy.deepcopy(saved)

    def checkpoint(self, checkpoint_id=None):
        return self.restorer.checkpoint(checkpoint_id=checkpoint_id)

    def restore(self, checkpoint):
        self.restorer.restore(checkpoint)

    def release_checkpoint(self, checkpoint):
        self.restorer.release(checkpoint)

    def observe(self):
        return make_snapshot(retry=self.state["retry"], state=self.state["state"])

    def snapshot(self, snapshot_id=None, output=None):
        snap = make_snapshot(retry=self.state["retry"], state=self.state["state"], snapshot_id=snapshot_id)
        if snapshot_id:
            self.snapshots[snapshot_id] = snap
        return snap

    def execute_transition(self, object_id=None, field_path=None, value=None, timeout_ms=1000, **kwargs):
        self._step += 1
        parent_retry = self.state["retry"]
        parent_snap_id = f"S_PARENT_{self._step}"
        parent_snap = make_snapshot(retry=parent_retry, state=self.state["state"], snapshot_id=parent_snap_id)
        self.snapshots[parent_snap_id] = parent_snap

        # Apply mutation to simulated memory
        old_val = self.state.get(field_path)
        self.state[field_path] = value

        # Simulate inferior continuation
        if self.state["retry"] == 0:
            self.state["state"] = "DISCONNECTED"
        elif self.state["retry"] >= 3:
            self.state["state"] = "ERROR"
        else:
            self.state["state"] = "CONNECTED"

        child_snap_id = f"S_CHILD_{self._step}"
        child_snap = make_snapshot(retry=self.state["retry"], state=self.state["state"], snapshot_id=child_snap_id)
        self.snapshots[child_snap_id] = child_snap

        from extractor.state_diff import StateDiffEngine
        diff_res = StateDiffEngine().diff(parent_snap, child_snap)

        trans = StateTransition(
            transition_id=f"T{self._step:04d}",
            parent_snapshot=parent_snap_id,
            child_snapshot=child_snap_id,
            mutation={"success": True, "object_id": object_id or "obj_0001", "field": field_path,
                      "before": old_val, "after": value},
            execution=ExecutionResult("STOPPED", reason="breakpoint"),
            diff=diff_res
        )
        self.transition_log.append(trans)
        return trans


class ExplorerBranchingTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.controller = BranchingMockController()
        self.corpus = StateCorpus(self.tmpdir)
        self.explorer = StateExplorer(self.controller, self.corpus, self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_independent_candidate_branching(self):
        """Verify that multiple candidates branch from the same parent state."""
        self.explorer.seed()
        self.assertEqual(self.controller.state["retry"], 2)

        # Explicitly supply the 3 test candidates: retry = 3, retry = 1, retry = 0
        candidates = [
            MutationCandidate("M0001", "S001", "obj_0001", "retry", 2, 3, "uint32_t", "BOUNDARY_PLUS_ONE"),
            MutationCandidate("M0002", "S001", "obj_0001", "retry", 2, 1, "uint32_t", "BOUNDARY_MINUS_ONE"),
            MutationCandidate("M0003", "S001", "obj_0001", "retry", 2, 0, "uint32_t", "ZERO_BOUNDARY"),
        ]

        # Override propose_mutations for this test to exactly test the 3 candidates
        self.explorer.propose_mutations = lambda snap=None: candidates

        result = self.explorer.run(max_steps=3)
        self.assertEqual(result["steps"], 3)

        transitions = self.controller.transition_log
        self.assertEqual(len(transitions), 3)

        # 1. Verify parent state for all 3 transitions was retry == 2
        for i, trans in enumerate(transitions):
            parent_snap = self.controller.snapshots[trans.parent_snapshot]
            parent_retry = next(f["value"] for f in parent_snap["persistent"]["objects"][0]["fields"] if f["name"] == "retry")
            self.assertEqual(parent_retry, 2, f"Transition {i+1} parent retry must be 2, but was {parent_retry}")
            self.assertEqual(trans.mutation["before"], 2)

        # 2. Verify children: T1 -> 3, T2 -> 1, T3 -> 0
        child1_snap = self.controller.snapshots[transitions[0].child_snapshot]
        child2_snap = self.controller.snapshots[transitions[1].child_snapshot]
        child3_snap = self.controller.snapshots[transitions[2].child_snapshot]

        child1_retry = next(f["value"] for f in child1_snap["persistent"]["objects"][0]["fields"] if f["name"] == "retry")
        child2_retry = next(f["value"] for f in child2_snap["persistent"]["objects"][0]["fields"] if f["name"] == "retry")
        child3_retry = next(f["value"] for f in child3_snap["persistent"]["objects"][0]["fields"] if f["name"] == "retry")

        self.assertEqual(child1_retry, 3)
        self.assertEqual(child2_retry, 1)
        self.assertEqual(child3_retry, 0)

        # 3. Verify restore was called 3 times (once per candidate)
        self.assertEqual(self.controller.restorer.restore_count, 3)

        # 4. Strict assertion against linear chaining (2 -> 3 -> 1 -> 0):
        # In a chained execution, trans[1].before would be 3 and trans[2].before would be 1.
        self.assertNotEqual(transitions[1].mutation["before"], 3, "Chained execution detected: transition 2 started from child 1!")
        self.assertNotEqual(transitions[2].mutation["before"], 1, "Chained execution detected: transition 3 started from child 2!")


if __name__ == "__main__":
    unittest.main()
