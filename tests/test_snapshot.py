import unittest

from extractor.runtime_state import ExecutionState, PersistentState, RuntimeState
from extractor.snapshot import RuntimeSnapshot


class SnapshotTests(unittest.TestCase):
    def test_snapshot_schema_and_metadata(self):
        state = RuntimeState("0.2", {"pid": 7, "binary": "sample"}, ExecutionState(), [], PersistentState())
        snapshot = RuntimeSnapshot.from_runtime_state(state, "S001").to_dict()
        self.assertEqual(snapshot["schema_version"], "0.3")
        self.assertEqual(snapshot["snapshot"]["snapshot_id"], "S001")
        self.assertEqual(snapshot["snapshot"]["pid"], 7)
