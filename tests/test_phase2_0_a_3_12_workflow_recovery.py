"""Phase 2.0-A.3.12 Workflow Execution and Recovery Integrity Tests.

Verifies:
1. Strict stage transition enforcement and prohibition of direct current_stage mutation.
2. Workflow definition validation (reachability of terminal states, absence of dead-ends).
3. Full EvidenceLedger and context recovery from checkpoint file.
4. Checksum integrity verification on saved checkpoints (corrupted files rejected).
5. Target process identity re-verification on resume (detects PID reuse and executable changes).
6. Non-re-execution of already completed observation reads across resume.
"""

import json
import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

from extractor.workflow import (
    ALL_WORKFLOW_STAGES,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    STAGE_BLOCKED,
    STAGE_CHECKING_BUDGET,
    STAGE_COMPLETED,
    STAGE_EVALUATING_EVIDENCE,
    STAGE_EXECUTING_OBSERVATION,
    STAGE_INITIALIZING,
    STAGE_PROBING,
    STAGE_SELECTING_RECIPE,
    STAGE_UPDATING_HYPOTHESIS,
    InvestigationWorkflowDefinition,
    InvestigationWorkflowEngine,
    WorkflowExecutionState,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.target_adapter import LocalTargetAdapter, PIDReusedError


class TestPhase20A312WorkflowRecovery(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="wf_rec_")
        self.pid = 7788
        self.session_id = "sess_rec_test"
        self.mock_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:2000:boot",
            "start_time": "2000",
            "executable": "/usr/bin/target",
            "executable_identity": "/usr/bin/target:999",
            "exe_inode": 999,
            "build_id": "c0ffee",
        }

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _setup_adapter(self):
        adapter = LocalTargetAdapter()
        adapter.check_liveness = lambda p: (True, None)
        adapter.get_threads = lambda p: [{"tid": p, "state": "R", "is_running_user_space": True, "voluntary_ctxt_switches": 5, "wchan": "0"}]
        adapter.get_proc_maps = lambda p: [{"start_int": 0x500000, "end_int": 0x510000, "size": 65536, "is_readable": True, "category": "data"}]
        adapter.get_process_identity = lambda p: dict(self.mock_ident)
        def _mock_read(p, a, s):
            data = b"\x11" * s
            adapter._record_physical_read(len(data), 1, data=data, pid=p, address=a, requested_size=s, status="OBSERVED")
            return data, "OBSERVED", None
        adapter.read_memory = _mock_read
        return adapter

    # -------------------------------------------------------------------------
    # 1. Direct State Mutation Prohibition & Illegal Transition Rejection
    # -------------------------------------------------------------------------
    def test_01_direct_stage_mutation_prohibited_and_illegal_transitions_rejected(self):
        """current_stage cannot be directly assigned outside transition_stage API."""
        engine = InvestigationWorkflowEngine()
        inst = engine.create_instance(self.session_id, self.pid, "Direct mutation check")

        # Attempting direct mutation outside transition API must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            inst.current_stage = STAGE_COMPLETED
        self.assertIn("Direct mutation of current_stage", str(ctx.exception))

        # Attempting illegal transition skipping prerequisites must be rejected
        ok, err = engine.validate_transition(inst, STAGE_COMPLETED)
        self.assertFalse(ok)
        self.assertIn("Illegal stage transition", err)

    # -------------------------------------------------------------------------
    # 2. Workflow Definition Validation
    # -------------------------------------------------------------------------
    def test_02_workflow_definition_validation_catches_flaws(self):
        """Definition validation detects dead-ends, unreachable terminal states, or invalid prerequisites."""
        # 2.1: Dead-end state (non-terminal state with no outgoing transitions)
        flawed_transitions = dict(engine = InvestigationWorkflowDefinition().allowed_transitions)
        flawed_transitions[STAGE_PROBING] = set()  # Dead-end!
        bad_def = InvestigationWorkflowDefinition(allowed_transitions=flawed_transitions)
        ok, err = bad_def.validate()
        self.assertFalse(ok)
        self.assertIn("Dead-end non-terminal stage detected", err)

        # 2.2: Valid definition passes
        good_def = InvestigationWorkflowDefinition()
        ok_good, err_good = good_def.validate()
        self.assertTrue(ok_good, err_good)

    # -------------------------------------------------------------------------
    # 3. Full EvidenceLedger and State Checkpoint Recovery
    # -------------------------------------------------------------------------
    def test_03_full_evidence_ledger_and_hypothesis_recovery_from_checkpoint(self):
        """Checkpoints persist complete EvidenceLedger contents, receipts, and hypothesis states."""
        adapter = self._setup_adapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)

        inst = engine.create_instance(self.session_id, self.pid, "Full recovery test")
        engine.execute_stage_initializing(inst)
        engine.execute_stage_probing(inst)
        engine.execute_stage_formulating_hypothesis(inst)
        engine.execute_stage_selecting_recipe(inst)
        engine.execute_stage_executing_observation(inst)
        engine.execute_stage_evaluating_evidence(inst)
        engine.execute_stage_updating_hypothesis(inst)

        # Verify evidence ledger has records before saving
        self.assertEqual(len(engine.evidence_ledger.records), 1)
        rec_id = engine.evidence_ledger.records[0].evidence_id

        # Persist to checkpoint
        ckpt_path = os.path.join(self.tmp_dir, "test_ckpt.json")
        engine.persist_state(inst, ckpt_path)
        self.assertTrue(os.path.exists(ckpt_path))

        # Create a new engine instance simulating crash/restart and resume
        new_engine = InvestigationWorkflowEngine(target_adapter=adapter)
        resumed_inst = new_engine.resume_investigation(ckpt_path)

        self.assertEqual(resumed_inst.instance_id, inst.instance_id)
        self.assertEqual(resumed_inst.current_stage, STAGE_CHECKING_BUDGET)
        # Verify restored evidence ledger
        self.assertIsNotNone(new_engine.evidence_ledger)
        self.assertEqual(len(new_engine.evidence_ledger.records), 1)
        self.assertEqual(new_engine.evidence_ledger.records[0].evidence_id, rec_id)

    # -------------------------------------------------------------------------
    # 4. Checksum Integrity Verification
    # -------------------------------------------------------------------------
    def test_04_corrupted_checkpoint_fails_closed_on_integrity_check(self):
        """Tampered or corrupted checkpoint file fails closed on resume with integrity error."""
        adapter = self._setup_adapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)
        inst = engine.create_instance(self.session_id, self.pid, "Tamper check")
        ckpt_path = os.path.join(self.tmp_dir, "tamper_ckpt.json")
        engine.persist_state(inst, ckpt_path)

        # Tamper with checkpoint file content
        with open(ckpt_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["checkpoint_data"]["instance"]["goal"] = "Maliciously modified goal"
        with open(ckpt_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        # Attempt to resume from tampered checkpoint must be rejected
        with self.assertRaises(ValueError) as ctx:
            InvestigationWorkflowEngine.resume_instance(ckpt_path)
        self.assertIn("Checkpoint integrity verification failed", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 5. Target Re-verification on Resume (PID Reuse / Executable Change)
    # -------------------------------------------------------------------------
    def test_05_target_identity_revalidation_on_resume_detects_pid_reuse(self):
        """Resume fails closed if the target process start_time or executable changed."""
        adapter = self._setup_adapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)
        inst = engine.create_instance(self.session_id, self.pid, "PID reuse resume check")
        inst.context["pinned_identity"] = dict(self.mock_ident)
        ckpt_path = os.path.join(self.tmp_dir, "pid_reuse_ckpt.json")
        engine.persist_state(inst, ckpt_path)

        # Simulate PID reuse by modifying adapter's reported process identity
        reused_adapter = self._setup_adapter()
        reused_ident = dict(self.mock_ident)
        reused_ident["start_time"] = "9999999"  # Reused PID!
        reused_adapter.get_process_identity = lambda p: reused_ident

        resumed_engine = InvestigationWorkflowEngine(target_adapter=reused_adapter)
        with self.assertRaises(PIDReusedError) as ctx:
            resumed_engine.resume_investigation(ckpt_path)
        self.assertIn("PID reuse detected on resume", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 6. Non-Re-execution of Completed Observations
    # -------------------------------------------------------------------------
    def test_06_non_reexecution_of_completed_observations_on_resume(self):
        """A resumed investigation skips redundant physical memory reads for already completed observations."""
        adapter = self._setup_adapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)

        inst = engine.create_instance(self.session_id, self.pid, "Duplicate observation check")
        engine.execute_stage_initializing(inst)
        engine.execute_stage_probing(inst)
        engine.execute_stage_formulating_hypothesis(inst)
        engine.execute_stage_selecting_recipe(inst)
        # Stage is now STAGE_EXECUTING_OBSERVATION.
        # Pre-seed completed_observations to simulate a resumed state where this recipe was already completed.
        target_addr = inst.context["target_addr"]
        target_size = inst.context["target_size"]
        obs_key = f"0x{target_addr:x}:{target_size}"
        inst.context["completed_observations"] = [obs_key]
        inst.context["last_receipt"] = {
            "receipt_id": "rcpt_mock_cached_001",
            "process_identity": "test",
            "executable_identity": "test",
            "build_id": "test",
            "snapshot_binding": "snap_1",
            "capture_epoch": 1,
            "observation_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "physical_bytes_read": 128,
            "authority_level": "TEST",
        }

        reads_before = adapter.physical_reads_count

        ckpt_path = os.path.join(self.tmp_dir, "dedup_ckpt.json")
        engine.persist_state(inst, ckpt_path)

        # Simulate re-running execute_stage_executing_observation on resumed instance
        resumed_engine = InvestigationWorkflowEngine(target_adapter=adapter)
        resumed_inst = resumed_engine.resume_investigation(ckpt_path)
        self.assertEqual(resumed_inst.current_stage, STAGE_EXECUTING_OBSERVATION)

        # Stepping observation stage should detect completed observation and not re-read
        ok = resumed_engine.execute_stage_executing_observation(resumed_inst)
        self.assertTrue(ok)
        self.assertEqual(resumed_inst.current_stage, STAGE_EVALUATING_EVIDENCE)
        # Physical reads must not have increased
        self.assertEqual(adapter.physical_reads_count, reads_before)


if __name__ == "__main__":
    unittest.main()
