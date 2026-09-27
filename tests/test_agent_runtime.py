"""Unit tests for Phase 5 AgentRuntime reference implementation."""

import tempfile
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.explorer import MutationCandidate
from extractor.runtime_controller import ExecutionResult, MutationResult, RuntimeCapabilities, RuntimeController
from extractor.snapshot import RuntimeSnapshot, StateTransition


class MockController(RuntimeController):
    """Mock RuntimeController for deterministic AgentRuntime unit tests."""

    def __init__(self):
        self._counter = 0
        self.snapshots = {}
        self._latest = None
        self._mock_checkpoint = "CP_001"
        self._checkpoints = {}

        # Create a sample snapshot
        self._sample_snap = {
            "schema_version": "0.3",
            "snapshot_id": "S001",
            "execution": {
                "threads": [
                    {
                        "thread_id": 1,
                        "frames": [
                            {"level": 0, "function": "process_packet", "location": "sample.cpp:43", "pc": "0x858"}
                        ]
                    }
                ]
            },
            "persistent": {
                "roots": [{"name": "session", "kind": "frame_local"}],
                "objects": [
                    {
                        "object_id": "obj_0001",
                        "type": "Session",
                        "storage": "heap",
                        "fields": [
                            {"name": "retry", "type": "uint32_t", "value": 2},
                            {"name": "state", "type": "SessionState", "value": "CONNECTED"},
                            {"name": "buffer", "type": "Buffer*", "value": "0x1000", "object_ref": "obj_0002"},
                            {"name": "flagged", "type": "bool", "value": False},
                        ]
                    },
                    {
                        "object_id": "obj_0002",
                        "type": "Buffer",
                        "storage": "heap",
                        "fields": [
                            {"name": "length", "type": "uint32_t", "value": 64},
                            {"name": "capacity", "type": "uint32_t", "value": 256},
                        ]
                    }
                ],
                "statistics": {"object_count": 2, "root_count": 1, "edge_count": 1}
            },
            "provenance": {
                "runtime_binary": {"stripped": True, "build_id": "mock_id"},
                "debug_image": {"source": "external", "verified": True, "compatible": True}
            }
        }
        self.snapshots["S001"] = self._sample_snap
        self._latest = self._sample_snap

    def observe(self):
        return self._latest

    def snapshot(self, snapshot_id=None, output=None):
        self._counter += 1
        sid = snapshot_id or f"S{self._counter:03d}"
        snap = dict(self._sample_snap)
        snap["snapshot_id"] = sid
        self.snapshots[sid] = snap
        self._latest = snap
        return snap

    def get_object(self, object_id):
        objs = self._sample_snap["persistent"]["objects"]
        return next((o for o in objs if o["object_id"] == object_id), None)

    def get_field(self, object_id, field):
        obj = self.get_object(object_id)
        if not obj:
            return None
        return next((f for f in obj["fields"] if f["name"] == field), None)

    def propose_mutations(self, snapshot=None):
        return [
            MutationCandidate("M001", "S001", "obj_0001", "retry", 2, 3, "uint32_t", "BOUNDARY_PLUS_ONE"),
            MutationCandidate("M002", "S001", "obj_0001", "retry", 2, 0, "uint32_t", "ZERO_BOUNDARY"),
            MutationCandidate("M003", "S001", "obj_0001", "state", "CONNECTED", "ERROR", "SessionState", "ENUM_MEMBER"),
        ]

    def checkpoint(self, checkpoint_id=None):
        cid = checkpoint_id or "CP_001"
        self._checkpoints[cid] = cid
        return cid

    def restore(self, checkpoint):
        pass

    def execute_transition(self, object_id=None, field_path=None, value=None, path=None, timeout_ms=1000):
        child_snap = dict(self._sample_snap)
        child_snap["snapshot_id"] = "S002"
        # Simulate value change: retry = 3 -> state = ERROR
        for o in child_snap["persistent"]["objects"]:
            if o["object_id"] == "obj_0001":
                for f in o["fields"]:
                    if f["name"] == "retry":
                        f["value"] = value
                    elif f["name"] == "state":
                        f["value"] = "ERROR"
                    elif f["name"] == "flagged":
                        f["value"] = True

        self.snapshots["S002"] = child_snap
        self._latest = child_snap

        return StateTransition(
            transition_id="T001",
            parent_snapshot="S001",
            child_snapshot="S002",
            mutation={"success": True, "object_id": object_id, "field": field_path, "before": 2, "after": value},
            execution={"status": "STOPPED", "reason": "breakpoint"},
            diff={
                "summary": {"value_changes": 3},
                "changes": [
                    {"kind": "value_change", "path": "Session.retry", "before": 2, "after": value},
                    {"kind": "value_change", "path": "Session.state", "before": "CONNECTED", "after": "ERROR"},
                    {"kind": "value_change", "path": "Session.flagged", "before": False, "after": True},
                ]
            }
        )

    def get_capabilities(self):
        return RuntimeCapabilities(external_debug_image=True).to_dict()


class AgentRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.controller = MockController()
        self.runtime = AgentRuntime(self.controller, corpus_dir=self.tmp_dir)

    def test_observe(self):
        res = self.runtime.observe()
        self.assertTrue(res.success)
        self.assertEqual(res.action, "OBSERVE")
        ctx = res.data
        self.assertEqual(ctx["snapshot_id"], "S001")
        self.assertEqual(ctx["execution"]["function"], "process_packet")
        self.assertEqual(len(ctx["objects"]), 2)
        self.assertTrue(ctx["provenance"]["runtime_binary"]["stripped"])

    def test_list_and_inspect_objects(self):
        res_list = self.runtime.list_objects()
        self.assertTrue(res_list.success)
        self.assertEqual(len(res_list.data), 2)
        self.assertEqual(res_list.data[0]["object_id"], "obj_0001")
        self.assertEqual(res_list.data[0]["type"], "Session")

        # Inspect obj_0001
        res_obj = self.runtime.inspect_object("obj_0001")
        self.assertTrue(res_obj.success)
        self.assertEqual(res_obj.data["type"], "Session")
        self.assertEqual(len(res_obj.data["fields"]), 4)

        # Inspect nonexistent object
        res_none = self.runtime.inspect_object("nonexistent_obj")
        self.assertFalse(res_none.success)
        self.assertEqual(res_none.error.code, "INVALID_OBJECT")

    def test_inspect_field(self):
        res_field = self.runtime.inspect_field("obj_0001", "retry")
        self.assertTrue(res_field.success)
        self.assertEqual(res_field.data["field"], "retry")
        self.assertEqual(res_field.data["value"], 2)
        self.assertEqual(res_field.data["mutability"], "mutable")

        # Nonexistent field
        res_nf = self.runtime.inspect_field("obj_0001", "nonexistent_field")
        self.assertFalse(res_nf.success)
        self.assertEqual(res_nf.error.code, "INVALID_FIELD")

    def test_list_mutation_candidates(self):
        res = self.runtime.list_mutation_candidates()
        self.assertTrue(res.success)
        candidates = res.data
        self.assertEqual(len(candidates), 3)

        # Verified candidate fields
        self.assertEqual(candidates[0].candidate_id, "M003")  # Enum ranks first
        self.assertIn("ENUM_TRANSITION", candidates[0].ranking_reasons)

        self.assertIn("candidate_generation_ms", res.performance)
        self.assertIn("candidate_ranking_ms", res.performance)

    def test_execute_transition_by_candidate_id(self):
        # 1. First get ranked candidates
        self.runtime.list_mutation_candidates()

        # 2. Select M001 (retry = 3)
        res_trans = self.runtime.execute_transition("M001")
        self.assertTrue(res_trans.success)
        self.assertEqual(res_trans.action, "EXECUTE_TRANSITION")

        agent_trans = res_trans.data
        self.assertEqual(agent_trans["transition_id"], "T001")
        self.assertTrue(agent_trans["facts"]["branch_changed"])
        self.assertEqual(agent_trans["mutation"]["after"], 3)

        evidence = agent_trans["evidence"]
        self.assertGreaterEqual(len(evidence), 3)
        obs_texts = [e["observation"] for e in evidence]
        self.assertTrue(any("Session.state changed" in t for t in obs_texts))

    def test_execute_transition_invalid_candidate(self):
        res = self.runtime.execute_transition("NONEXISTENT_CANDIDATE")
        self.assertFalse(res.success)
        self.assertEqual(res.error.code, "INVALID_CANDIDATE")

    def test_checkpoint_and_restore(self):
        res_cp = self.runtime.checkpoint()
        self.assertTrue(res_cp.success)
        cp_id = res_cp.data["checkpoint_id"]

        res_rest = self.runtime.restore(cp_id)
        self.assertTrue(res_rest.success)
        self.assertTrue(res_rest.data["restored"])

    def test_state_hash(self):
        res = self.runtime.state_hash()
        self.assertTrue(res.success)
        self.assertIn("state_hash", res.data)
        self.assertEqual(len(res.data["state_hash"]), 16)

    def test_detect_invariants(self):
        res = self.runtime.detect_invariant_candidates()
        self.assertTrue(res.success)
        invs = res.data
        self.assertGreaterEqual(len(invs), 2)
        exprs = [inv["expression"] for inv in invs]
        self.assertIn("Buffer.length <= Buffer.capacity", exprs)
        self.assertIn("Session.retry >= 0", exprs)


if __name__ == "__main__":
    unittest.main()
