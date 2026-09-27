"""Unit tests for Phase 5 Agent-facing Models."""

import json
import unittest

from extractor.agent_models import (
    AgentAction,
    AgentActionError,
    AgentActionResult,
    AgentEvidence,
    AgentExplorationResult,
    AgentField,
    AgentInvariantCandidate,
    AgentMutationCandidate,
    AgentObject,
    AgentStateContext,
    AgentTransition,
)


class AgentModelsTests(unittest.TestCase):
    def test_action_and_result_serialization(self):
        action = AgentAction(
            action="INSPECT_FIELD",
            object_id="obj_0001",
            field_path="retry"
        )
        d = action.to_dict()
        self.assertEqual(d["action"], "INSPECT_FIELD")
        self.assertEqual(d["object_id"], "obj_0001")
        self.assertEqual(d["field_path"], "retry")

        restored_action = AgentAction.from_dict(d)
        self.assertEqual(restored_action.action, "INSPECT_FIELD")

        err = AgentActionError(code="INVALID_FIELD", message="Field not found", details={"field": "foo"})
        result = AgentActionResult(
            success=False,
            action="INSPECT_FIELD",
            error=err,
            performance={"total_ms": 1.25}
        )
        res_dict = result.to_dict()
        self.assertFalse(res_dict["success"])
        self.assertEqual(res_dict["error"]["code"], "INVALID_FIELD")
        self.assertEqual(res_dict["performance"]["total_ms"], 1.25)

        # JSON round-trip
        json_str = result.to_json()
        data = json.loads(json_str)
        self.assertEqual(data["action"], "INSPECT_FIELD")

    def test_agent_state_context(self):
        ctx = AgentStateContext(
            snapshot_id="S001",
            execution={"thread_id": 1, "function": "process_packet", "frame_level": 0},
            objects=[
                {"object_id": "obj_0001", "type": "Session", "fields": {"retry": 2, "state": "CONNECTED"}}
            ],
            statistics={"object_count": 1, "root_count": 1, "edge_count": 0},
            state_id="state_000001",
            state_hash="a1b2c3d4",
            provenance={"runtime_binary": {"stripped": True}}
        )
        d = ctx.to_dict()
        self.assertEqual(d["snapshot_id"], "S001")
        self.assertEqual(d["state_id"], "state_000001")
        self.assertEqual(d["state_hash"], "a1b2c3d4")
        self.assertEqual(d["objects"][0]["object_id"], "obj_0001")
        self.assertTrue(d["provenance"]["runtime_binary"]["stripped"])

        restored = AgentStateContext.from_dict(d)
        self.assertEqual(restored.snapshot_id, "S001")

    def test_agent_object_and_field(self):
        f = AgentField(
            object_id="obj_0001",
            field="retry",
            type="uint32_t",
            value=2,
            mutability="mutable"
        )
        fd = f.to_dict()
        self.assertEqual(fd["field"], "retry")
        self.assertEqual(fd["mutability"], "mutable")

        obj = AgentObject(
            object_id="obj_0001",
            type="Session",
            storage="heap",
            fields=[fd]
        )
        od = obj.to_dict()
        self.assertEqual(od["object_id"], "obj_0001")
        self.assertEqual(od["type"], "Session")
        self.assertEqual(len(od["fields"]), 1)

    def test_mutation_candidate(self):
        cand = AgentMutationCandidate(
            candidate_id="M001",
            snapshot_id="S001",
            object_id="obj_0001",
            field="retry",
            type="uint32_t",
            current_value=2,
            proposed_value=3,
            reason="BOUNDARY_PLUS_ONE",
            priority_score=6.5,
            ranking_reasons=["NUMERIC_BOUNDARY", "BRANCH_SENSITIVE"]
        )
        d = cand.to_dict()
        self.assertEqual(d["candidate_id"], "M001")
        self.assertEqual(d["priority_score"], 6.5)
        self.assertIn("NUMERIC_BOUNDARY", d["ranking_reasons"])

        restored = AgentMutationCandidate.from_dict(d)
        self.assertEqual(restored.proposed_value, 3)

    def test_transition_and_evidence(self):
        ev = AgentEvidence(
            evidence_id="EV_0001",
            source="diff",
            transition_id="T001",
            observation="Session.state changed CONNECTED -> ERROR",
            facts={"field": "Session.state", "before": "CONNECTED", "after": "ERROR"}
        )
        trans = AgentTransition(
            transition_id="T001",
            parent_snapshot="S001",
            child_snapshot="S002",
            parent_state="state_000001",
            child_state="state_000002",
            mutation={"field": "retry", "before": 2, "after": 3},
            execution={"status": "STOPPED", "reason": "breakpoint"},
            facts={"branch_changed": True, "field_changed": ["Session.state"]},
            evidence=[ev.to_dict()]
        )
        td = trans.to_dict()
        self.assertEqual(td["transition_id"], "T001")
        self.assertTrue(td["facts"]["branch_changed"])
        self.assertEqual(len(td["evidence"]), 1)
        self.assertEqual(td["evidence"][0]["evidence_id"], "EV_0001")

    def test_invariant_candidate(self):
        inv = AgentInvariantCandidate(
            expression="Buffer.length <= Buffer.capacity",
            category="bounds",
            evidence=["obj_0002: length=64 <= capacity=256"]
        )
        d = inv.to_dict()
        self.assertEqual(d["type"], "invariant_candidate")
        self.assertEqual(d["status"], "unconfirmed_candidate")
        self.assertEqual(d["expression"], "Buffer.length <= Buffer.capacity")

    def test_exploration_result(self):
        res = AgentExplorationResult(
            exploration_id="E001",
            seed_state="state_000001",
            steps=5,
            new_states=2,
            new_transitions=4,
            crashes=0,
            timeouts=0,
            corpus_summary={"states": 3}
        )
        d = res.to_dict()
        self.assertEqual(d["exploration_id"], "E001")
        self.assertEqual(d["new_states"], 2)


if __name__ == "__main__":
    unittest.main()
