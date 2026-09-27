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

    def test_state_transition_serialization(self):
        import tempfile, os
        from extractor.snapshot import StateTransition, load_transition
        trans = StateTransition(
            transition_id="T001",
            parent_snapshot="S001",
            child_snapshot="S002",
            mutation={"success": True, "object_id": "obj_0001", "field": "retry", "before": 2, "after": 3},
            execution={"status": "STOPPED", "reason": "breakpoint"},
            diff={"summary": {"value_changes": 1}, "changes": [{"kind": "value_change", "path": "Session.retry", "before": 2, "after": 3}]},
            performance={"total_ms": 12.5}
        )
        d = trans.to_dict()
        self.assertEqual(d["schema_version"], "0.3")
        self.assertEqual(d["transition_id"], "T001")
        self.assertEqual(d["parent_snapshot"], "S001")
        self.assertEqual(d["child_snapshot"], "S002")
        self.assertEqual(d["transition"]["transition_id"], "T001")
        self.assertTrue(d["transition"]["mutation"]["success"])
        self.assertEqual(d["transition"]["execution"]["status"], "STOPPED")
        self.assertEqual(d["transition"]["performance"]["total_ms"], 12.5)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "transitions", "T001.json")
            trans.write_json(out_file)
            loaded = load_transition(out_file)
            self.assertEqual(loaded["schema_version"], "0.3")
            self.assertEqual(loaded["transition"]["transition_id"], "T001")

    def test_crash_and_timeout_transition(self):
        from extractor.snapshot import StateTransition
        # Crash transition
        crash = StateTransition(
            transition_id="T003",
            parent_snapshot="S001",
            child_snapshot=None,
            mutation={"success": True},
            execution={"status": "CRASHED", "signal": "SIGSEGV"},
            diff=None
        )
        d_crash = crash.to_dict()
        self.assertIsNone(d_crash["child_snapshot"])
        self.assertIsNone(d_crash["diff"])
        self.assertEqual(d_crash["execution"]["status"], "CRASHED")
        self.assertEqual(d_crash["execution"]["signal"], "SIGSEGV")

        # Timeout transition
        timeout = StateTransition(
            transition_id="T004",
            parent_snapshot="S001",
            child_snapshot=None,
            execution={"status": "TIMEOUT"},
            diff=None
        )
        d_timeout = timeout.to_dict()
        self.assertEqual(d_timeout["execution"]["status"], "TIMEOUT")
        self.assertIsNone(d_timeout["child_snapshot"])

    def test_object_matcher(self):
        from extractor.state_diff import AddressTypeObjectMatcher
        matcher = AddressTypeObjectMatcher()
        o1 = {"address": "0x1000", "type": "Session"}
        o2 = {"address": "0x1000", "type": "Session"}
        o3 = {"address": "0x1000", "type": "Buffer"}
        o4 = {"address": "0x2000", "type": "Session"}
        self.assertTrue(matcher.match(o1, o2))
        self.assertFalse(matcher.match(o1, o3))
        self.assertFalse(matcher.match(o1, o4))
        self.assertEqual(matcher.identity_key(o1), ("0x1000", "Session"))
