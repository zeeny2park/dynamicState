import shutil
import tempfile
import unittest

from extractor.explorer import StateExplorer
from extractor.runtime_controller import ExecutionResult, RuntimeController
from extractor.snapshot import StateTransition
from extractor.state_corpus import StateCorpus
from tests.test_state_hash import make_snapshot


class MockExplorationController(RuntimeController):
    def __init__(self):
        self.snapshots = {
            "S001": make_snapshot(retry=2, state="CONNECTED"),
            "S002": make_snapshot(retry=3, state="ERROR"),
            "S003": make_snapshot(retry=2, state="CONNECTED"),  # duplicate of S001
        }
        self._step = 0

    def observe(self):
        return self.snapshots["S001"]

    def snapshot(self, snapshot_id=None, output=None):
        return self.snapshots["S001"]

    def get_object(self, object_id):
        return None

    def get_field(self, object_id, field):
        return None

    def mutate(self, object_id, field_path, value):
        return None

    def continue_execution(self, timeout_ms=1000):
        return ExecutionResult("STOPPED", reason="breakpoint")

    def diff(self, before, after):
        from extractor.state_diff import StateDiffEngine
        return StateDiffEngine().diff(before, after)

    def execute_transition(self, object_id=None, field_path=None, value=None, **kwargs):
        self._step += 1
        child_id = "S002" if self._step == 1 else "S003"
        parent = self.snapshots["S001"]
        child = self.snapshots[child_id]
        diff_res = self.diff(parent, child)
        return StateTransition(
            transition_id=f"T{self._step:04d}",
            parent_snapshot="S001",
            child_snapshot=child_id,
            mutation={"success": True, "object_id": object_id, "field": field_path, "after": value},
            execution=ExecutionResult("STOPPED", reason="breakpoint"),
            diff=diff_res
        )


class StateExplorerTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.controller = MockExplorationController()
        self.corpus = StateCorpus(self.tmpdir)
        self.explorer = StateExplorer(self.controller, self.corpus, self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_seed(self):
        state_id = self.explorer.seed()
        self.assertEqual(state_id, "state_000001")
        self.assertEqual(self.explorer.seed_state_id, "state_000001")

    def test_run_exploration_loop(self):
        self.explorer.seed()
        result = self.explorer.run(max_steps=2)

        self.assertEqual(result["steps"], 2)
        summary = result["summary"]
        self.assertEqual(summary["executed"], 2)
        self.assertEqual(summary["new_states"], 1)  # S002 was new
        self.assertEqual(summary["duplicate_states"], 1)  # S003 was duplicate of S001
        self.assertEqual(len(result["transitions"]), 2)
        self.assertIn("performance", result)
        self.assertIn("avg_step_ms", result["performance"])


if __name__ == "__main__":
    unittest.main()
