"""Contract-level Agent Workflow Tests for Phase 6.0.

Validates the Agent Runtime Protocol (ARP) semantic contract:
- Test A: Observe -> Object Selection -> Inspect Object -> Inspect Field -> Mutation Candidates
- Test B: Hypothesis Mutation (retry = 2 -> 3, continue, state CONNECTED -> ERROR)
- Test C: Restore + Alternative Hypothesis (restore C_SEED, retry = 2 -> 0, state CONNECTED -> DISCONNECTED)
- Test D: Crash Isolation (priority = 139 -> SIGSEGV, verify parent intact, restore works, sibling executes)
- Test E: LOW_IMPACT Capabilities (semantic state returned, execution UNAVAILABLE, mutations rejected with CAPABILITY_UNSUPPORTED)
- Test F: Debug Image Failure (DEBUG_IMAGE_MISMATCH semantic error without raw unhandled crash)
"""

import copy
import json
import os
import tempfile
import unittest

from extractor.agent_models import (
    AgentAction,
    AgentActionError,
    AgentActionResult,
    AgentEvidence,
    AgentField,
    AgentMutationCandidate,
    AgentObject,
    AgentStateContext,
    AgentTransition,
)
from extractor.agent_runtime import AgentRuntime
from extractor.explorer import MutationCandidate
from extractor.runtime_controller import (
    ExecutionResult,
    MutationResult,
    RuntimeCapabilities,
    RuntimeController,
)
from extractor.snapshot import RuntimeSnapshot, StateTransition
from extractor.state_hash import compute_state_hash


class ContractMockRuntimeController(RuntimeController):
    """Deterministic runtime controller implementing multi-branch state and crash simulation."""

    def __init__(self):
        self._counter = 1
        self.snapshots = {}
        self._checkpoints = {}

        # Initial seed state
        self._seed_snap = {
            "schema_version": "0.3",
            "snapshot_id": "S001",
            "process": {"pid": 12345, "binary": "/path/to/production_binary"},
            "execution": {
                "threads": [
                    {
                        "thread_id": 1,
                        "frames": [
                            {
                                "level": 0,
                                "function": "worker_loop",
                                "location": "sample_prod.cpp:62",
                                "pc": "0xaaaaaaaa1984"
                            }
                        ]
                    }
                ]
            },
            "persistent": {
                "roots": [{"name": "session", "source": "local", "type": "Session*", "object_ref": "obj_0001"}],
                "objects": [
                    {
                        "object_id": "obj_0001",
                        "type": "Session",
                        "storage": "heap",
                        "fields": [
                            {"name": "retry", "type": "uint32_t", "value": 2},
                            {"name": "state", "type": "SessionState", "value": "CONNECTED"},
                            {"name": "priority", "type": "uint32_t", "value": 7},
                            {"name": "parent", "type": "Session*", "value": "0xaaaaaaad3320", "object_ref": "obj_0001"},
                            {"name": "buffer", "type": "Buffer*", "value": "0xaaaaaaad3380", "object_ref": "obj_0002"},
                            {"name": "raw_ptr", "type": "void*", "value": "0xaaaaaaad3400"},
                            {"name": "null_ptr", "type": "char*", "value": "0x0"},
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
                "statistics": {"object_count": 2, "root_count": 1, "edge_count": 2}
            },
            "provenance": {
                "runtime_binary": {"stripped": True, "build_id": "abc123buildid"},
                "debug_image": {"source": "external", "verified": True, "compatible": True}
            }
        }
        self.snapshots["S001"] = copy.deepcopy(self._seed_snap)
        self._latest = copy.deepcopy(self._seed_snap)
        self.debug_image_path = "/path/to/valid.debug"

    def observe(self):
        return copy.deepcopy(self._latest)

    def snapshot(self, snapshot_id=None, output=None):
        self._counter += 1
        sid = snapshot_id or f"S{self._counter:03d}"
        snap = copy.deepcopy(self._latest)
        snap["snapshot_id"] = sid
        self.snapshots[sid] = snap
        self._latest = snap
        return snap

    def checkpoint(self, checkpoint_id=None):
        cid = checkpoint_id or f"C{len(self._checkpoints)+1:03d}"
        self._checkpoints[cid] = copy.deepcopy(self._latest)
        return cid

    def restore(self, checkpoint):
        cid = checkpoint if isinstance(checkpoint, str) else getattr(checkpoint, "checkpoint_id", str(checkpoint))
        if cid not in self._checkpoints:
            raise RuntimeError(f"CHECKPOINT_NOT_FOUND: {cid}")
        self._latest = copy.deepcopy(self._checkpoints[cid])

    def propose_mutations(self, snapshot=None):
        return [
            MutationCandidate("M001", "S001", "obj_0001", "retry", 2, 3, "uint32_t", "BOUNDARY_PLUS_ONE"),
            MutationCandidate("M002", "S001", "obj_0001", "retry", 2, 0, "uint32_t", "ZERO_BOUNDARY"),
            MutationCandidate("M003", "S001", "obj_0001", "state", "CONNECTED", "ERROR", "SessionState", "ENUM_MEMBER"),
            MutationCandidate("M004", "S001", "obj_0001", "priority", 7, 139, "uint32_t", "MAX_BOUNDARY"),
        ]

    def execute_transition(self, object_id=None, field_path=None, value=None, path=None, timeout_ms=1000):
        # Crash case: priority = 139 triggers SIGSEGV
        if field_path == "priority" and value == 139:
            return StateTransition(
                transition_id="T_CRASH",
                parent_snapshot=self._latest["snapshot_id"],
                child_snapshot=None,
                mutation=MutationResult(success=True, object_id=object_id, field=field_path, before=7, after=139),
                execution=ExecutionResult(status="CRASHED", signal="SIGSEGV", reason="Address not mapped to object"),
                diff=None
            )

        # Standard state transition: clone parent and apply change
        self._counter += 1
        child_id = f"S{self._counter:03d}"
        child_snap = copy.deepcopy(self._latest)
        child_snap["snapshot_id"] = child_id

        old_val = None
        for o in child_snap["persistent"]["objects"]:
            if o["object_id"] == object_id:
                for f in o["fields"]:
                    if f["name"] == field_path:
                        old_val = f["value"]
                        f["value"] = value
                    # Branch 1 effect: retry = 3 triggers state -> ERROR
                    if field_path == "retry" and value == 3:
                        if f["name"] == "state":
                            f["value"] = "ERROR"
                    # Branch 2 effect: retry = 0 triggers state -> DISCONNECTED
                    elif field_path == "retry" and value == 0:
                        if f["name"] == "state":
                            f["value"] = "DISCONNECTED"

        self.snapshots[child_id] = child_snap
        self._latest = child_snap

        tid = f"T{self._counter:03d}"
        changes = [
            {"kind": "value_change", "path": f"Session.{field_path}", "before": old_val, "after": value}
        ]
        if field_path == "retry" and value == 3:
            changes.append({"kind": "value_change", "path": "Session.state", "before": "CONNECTED", "after": "ERROR"})
        elif field_path == "retry" and value == 0:
            changes.append({"kind": "value_change", "path": "Session.state", "before": "CONNECTED", "after": "DISCONNECTED"})

        return StateTransition(
            transition_id=tid,
            parent_snapshot="S001",
            child_snapshot=child_id,
            mutation=MutationResult(success=True, object_id=object_id, field=field_path, before=old_val, after=value),
            execution=ExecutionResult(status="STOPPED", reason="breakpoint"),
            diff={"summary": {"value_changes": len(changes)}, "changes": changes}
        )

    def get_capabilities(self):
        return RuntimeCapabilities(external_debug_image=True).to_dict()


class AgentSemanticContractTests(unittest.TestCase):
    """CONTRACT: Strict test suite verifying Phase 6 Agent-facing semantic contracts."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="agent_contract_")
        self.controller = ContractMockRuntimeController()
        self.runtime = AgentRuntime(self.controller, corpus_dir=self.tmp_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Test A: Observe -> Object Selection -> Inspect Object -> Inspect Field -> Candidates
    # -------------------------------------------------------------------------
    def test_a_observe_inspect_candidate_flow(self):
        """Test A: Full semantic discovery flow with zero memory address or DWARF leakages."""
        # 1. Observe
        res_obs = self.runtime.observe()
        self.assertTrue(res_obs.success, "Observe must succeed")
        self.assertEqual(res_obs.action, "OBSERVE")
        ctx = res_obs.data
        self.assertIsInstance(ctx, (dict, AgentStateContext))

        # Verification of Information Leakage Guard:
        # - execution.pc must be None (no raw instruction pointer leak)
        # - execution function and location provide semantic coordinates
        self.assertIsNone(ctx["execution"]["pc"], "Raw execution.pc must be sanitized to None")
        self.assertEqual(ctx["execution"]["function"], "worker_loop")
        self.assertEqual(ctx["execution"]["location"], "sample_prod.cpp:62")

        # Verify objects in context summary
        objects = ctx["objects"]
        self.assertEqual(len(objects), 2)
        session_summary = next(o for o in objects if o["object_id"] == "obj_0001")
        self.assertEqual(session_summary["type"], "Session")
        # Pointer fields must resolve to semantic object_ref or semantic placeholder, NEVER hex address
        self.assertEqual(session_summary["fields"]["parent"], "obj_0001")
        self.assertEqual(session_summary["fields"]["buffer"], "obj_0002")
        self.assertEqual(session_summary["fields"]["null_ptr"], "<null>")
        self.assertEqual(session_summary["fields"]["raw_ptr"], "<pointer>")

        # 2. List Objects (Level 2 Progressive Disclosure)
        res_list = self.runtime.list_objects()
        self.assertTrue(res_list.success)
        self.assertEqual(len(res_list.data), 2)
        obj_ids = [o["object_id"] for o in res_list.data]
        self.assertIn("obj_0001", obj_ids)
        self.assertIn("obj_0002", obj_ids)

        # 3. Inspect Object (Level 3 Progressive Disclosure)
        res_inspect = self.runtime.inspect_object("obj_0001")
        self.assertTrue(res_inspect.success)
        s_obj = res_inspect.data
        self.assertEqual(s_obj["type"], "Session")
        fields_by_name = {f["name"]: f for f in s_obj["fields"]}

        # Pointer to aggregate has object_ref and sanitized semantic value
        self.assertEqual(fields_by_name["buffer"]["value"], "obj_0002")
        self.assertEqual(fields_by_name["buffer"]["object_ref"], "obj_0002")
        # Circular reference pointer
        self.assertEqual(fields_by_name["parent"]["value"], "obj_0001")
        self.assertEqual(fields_by_name["parent"]["object_ref"], "obj_0001")
        # Null pointer
        self.assertEqual(fields_by_name["null_ptr"]["value"], "<null>")
        # Unexpanded pointer
        self.assertEqual(fields_by_name["raw_ptr"]["value"], "<pointer>")

        # 4. Inspect Field (Level 4 Progressive Disclosure)
        res_field = self.runtime.inspect_field("obj_0001", "retry")
        self.assertTrue(res_field.success)
        f_data = res_field.data
        self.assertEqual(f_data["field"], "retry")
        self.assertEqual(f_data["value"], 2)
        self.assertEqual(f_data["mutability"], "mutable")
        self.assertEqual(f_data["type"], "uint32_t")

        # 5. List Mutation Candidates (Level 5 Progressive Disclosure)
        res_cands = self.runtime.list_mutation_candidates()
        self.assertTrue(res_cands.success)
        cands = res_cands.data
        self.assertGreaterEqual(len(cands), 3)
        for cand in cands:
            self.assertIsNotNone(cand.candidate_id)
            self.assertIsNotNone(cand.reason)
            self.assertIsInstance(cand.ranking_reasons, list)
            self.assertGreater(cand.priority_score, 0.0)

    # -------------------------------------------------------------------------
    # Test B: Hypothesis Mutation (retry 2 -> 3, continue, state CONNECTED -> ERROR)
    # -------------------------------------------------------------------------
    def test_b_hypothesis_mutation(self):
        """Test B: Verified candidate mutation producing explainable state transition and evidence."""
        # Find candidate for retry = 3
        res_cands = self.runtime.list_mutation_candidates()
        cand_3 = next(c for c in res_cands.data if c.field == "retry" and c.proposed_value == 3)

        # Execute transition using candidate_id
        res_trans = self.runtime.execute_transition(cand_3.candidate_id)
        self.assertTrue(res_trans.success, "Transition execution must succeed")
        self.assertEqual(res_trans.action, "EXECUTE_TRANSITION")

        trans = res_trans.data
        self.assertIsInstance(trans, AgentTransition)
        self.assertEqual(trans.parent_snapshot, "S001")
        self.assertIsNotNone(trans.child_snapshot)

        # Semantic facts verification
        facts = trans.facts
        self.assertTrue(facts["branch_changed"])
        self.assertIn("Session.retry", facts["field_changed"])
        self.assertIn("Session.state", facts["field_changed"])
        self.assertFalse(facts["crash"])

        # Structured evidence verification
        evidence_list = trans.evidence
        self.assertGreaterEqual(len(evidence_list), 2)
        state_evidence = next(e for e in evidence_list if "Session.state" in e["observation"])
        self.assertIn("CONNECTED", state_evidence["observation"])
        self.assertIn("ERROR", state_evidence["observation"])

    # -------------------------------------------------------------------------
    # Test C: Restore + Alternative Hypothesis (Branch Isolation)
    # -------------------------------------------------------------------------
    def test_c_restore_alternative_hypothesis_branching(self):
        """Test C: Checkpoint parent, execute Branch 1, restore, execute Branch 2."""
        # Step 1: Capture Checkpoint
        res_cp = self.runtime.checkpoint("C_SEED")
        self.assertTrue(res_cp.success)
        self.assertEqual(res_cp.data["checkpoint_id"], "C_SEED")

        # Step 2: Branch 1 (retry 2 -> 3)
        self.runtime.list_mutation_candidates()
        res_b1 = self.runtime.execute_transition({"object_id": "obj_0001", "field": "retry", "proposed_value": 3})
        self.assertTrue(res_b1.success)
        child1_state = res_b1.data.child_state
        child1_meta = self.runtime.corpus.get_metadata(child1_state)
        hash1 = child1_meta["state_hash"]

        # Step 3: Restore Checkpoint C_SEED
        res_rest = self.runtime.restore("C_SEED")
        self.assertTrue(res_rest.success)
        self.assertTrue(res_rest.data["restored"])

        # Verify parent state restored cleanly
        res_retry = self.runtime.inspect_field("obj_0001", "retry")
        self.assertEqual(res_retry.data["value"], 2, "Parent field must be restored to 2")
        res_state = self.runtime.inspect_field("obj_0001", "state")
        self.assertEqual(res_state.data["value"], "CONNECTED", "Parent state must be restored to CONNECTED")

        # Step 4: Branch 2 (retry 2 -> 0)
        self.runtime.list_mutation_candidates()
        res_b2 = self.runtime.execute_transition({"object_id": "obj_0001", "field": "retry", "proposed_value": 0})
        self.assertTrue(res_b2.success)
        child2_state = res_b2.data.child_state
        child2_meta = self.runtime.corpus.get_metadata(child2_state)
        hash2 = child2_meta["state_hash"]

        # Verify that branches generated distinct semantic state hashes
        self.assertNotEqual(hash1, hash2, "Alternative mutation branches must produce distinct state hashes")

    # -------------------------------------------------------------------------
    # Test D: Crash Isolation (priority 7 -> 139 triggers SIGSEGV)
    # -------------------------------------------------------------------------
    def test_d_crash_isolation(self):
        """Test D: Application crash represented cleanly, parent intact, restore works, sibling executes."""
        # 1. Checkpoint master state
        res_cp = self.runtime.checkpoint("C_MASTER")
        self.assertTrue(res_cp.success)

        # 2. Trigger crash transition
        self.runtime.list_mutation_candidates()
        res_crash = self.runtime.execute_transition({"object_id": "obj_0001", "field": "priority", "proposed_value": 139})
        self.assertTrue(res_crash.success, "Action envelope succeeds with crash details")

        trans = res_crash.data
        self.assertEqual(trans.execution["status"], "CRASHED")
        self.assertEqual(trans.execution["signal"], "SIGSEGV")
        self.assertTrue(trans.facts["crash"])
        self.assertEqual(trans.facts["crash_signal"], "SIGSEGV")

        # 3. Restore master state
        res_restore = self.runtime.restore("C_MASTER")
        self.assertTrue(res_restore.success)

        # 4. Sibling branch can execute normally
        self.runtime.list_mutation_candidates()
        res_sibling = self.runtime.execute_transition({"object_id": "obj_0001", "field": "retry", "proposed_value": 0})
        self.assertTrue(res_sibling.success)
        self.assertEqual(res_sibling.data.execution["status"], "STOPPED")

    # -------------------------------------------------------------------------
    # Test E: LOW_IMPACT Capabilities
    # -------------------------------------------------------------------------
    def test_e_low_impact_capabilities(self):
        """Test E: LOW_IMPACT observation mode returns UNAVAILABLE execution and rejects mutations."""
        # Set mode to LOW_IMPACT
        self.runtime.observation_mode = "LOW_IMPACT"

        # Mutation candidate query must be rejected
        res_cands = self.runtime.list_mutation_candidates()
        self.assertFalse(res_cands.success)
        self.assertEqual(res_cands.error.code, "CAPABILITY_UNSUPPORTED")

        # Checkpoint must be rejected
        res_cp = self.runtime.checkpoint("C_FORBIDDEN")
        self.assertFalse(res_cp.success)
        self.assertEqual(res_cp.error.code, "CAPABILITY_UNSUPPORTED")

        # Restore must be rejected
        res_rest = self.runtime.restore("C_FORBIDDEN")
        self.assertFalse(res_rest.success)
        self.assertEqual(res_rest.error.code, "CAPABILITY_UNSUPPORTED")

        # Transition execution must be rejected
        res_trans = self.runtime.execute_transition("M001")
        self.assertFalse(res_trans.success)
        self.assertEqual(res_trans.error.code, "CAPABILITY_UNSUPPORTED")

        # Exploration loop must be rejected
        res_exp = self.runtime.explore()
        self.assertFalse(res_exp.success)
        self.assertEqual(res_exp.error.code, "CAPABILITY_UNSUPPORTED")

    # -------------------------------------------------------------------------
    # Test F: Debug Image Failure
    # -------------------------------------------------------------------------
    def test_f_debug_image_failure_semantics(self):
        """Test F: Invalid or mismatched debug image produces structured semantic error."""
        # Analyze memory snapshot with mismatched or non-existent debug image
        # Register a mock raw snapshot
        from extractor.memory_snapshot import RawMemorySnapshot
        snap = RawMemorySnapshot(
            snapshot_id="M_MOCK",
            pid=1234,
            binary="/bin/test",
            timestamp_ns=123000000,
        )
        self.runtime.memory_snapshots["M_MOCK"] = snap

        res = self.runtime.analyze_memory_snapshot(
            memory_snapshot_id="M_MOCK",
            debug_image="/nonexistent/mismatched.debug"
        )
        self.assertFalse(res.success)
        self.assertIn(res.error.code, ("DEBUG_IMAGE_MISMATCH", "INVALID_DEBUG_IMAGE", "RUNTIME_ERROR"))
        self.assertNotIn("Traceback", res.error.message)


if __name__ == "__main__":
    unittest.main()
