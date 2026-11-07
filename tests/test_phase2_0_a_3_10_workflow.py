"""Phase 2.0-A.3.10 Investigation Workflow Engine Tests.

Tests:
1. Workflow definition stages and prerequisites validation
2. Illegal transition rejection
3. User cancellation handling
4. State persistence, checkpointing, and resume
5. Execution on real target process with audit trail
6. Target termination handling
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.workflow import (
    ALL_STOPPING_REASONS,
    ALL_WORKFLOW_STAGES,
    STAGE_ABSTAINED,
    STAGE_BLOCKED,
    STAGE_CANCELLED,
    STAGE_COMPLETED,
    STAGE_EXECUTING_OBSERVATION,
    STAGE_FAILED,
    STAGE_FORMING_DIAGNOSIS,
    STAGE_INITIALIZING,
    STAGE_PROBING,
    STOP_TARGET_TERMINATED,
    STOP_USER_CANCELLED,
    InvestigationWorkflowDefinition,
    InvestigationWorkflowEngine,
    WorkflowExecutionState,
)


class TestPhase20A310Workflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="wf_test_")
        cls.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")
        cls.healthy_src = os.path.join(cls.fixtures_dir, "proc_scenario_a_healthy.c")
        cls.healthy_bin = os.path.join(cls.tmp_dir, "proc_scenario_a")
        subprocess.run(["gcc", "-g", "-O0", cls.healthy_src, "-o", cls.healthy_bin, "-pthread"], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def setUp(self):
        self.wf_def = InvestigationWorkflowDefinition()
        self.engine = InvestigationWorkflowEngine(definition=self.wf_def)

    def test_01_workflow_stages_and_prerequisites(self):
        """All 15+ lifecycle stages and stopping reasons are explicitly defined."""
        self.assertGreaterEqual(len(self.wf_def.stages), 15)
        self.assertIn(STAGE_INITIALIZING, self.wf_def.stages)
        self.assertIn(STAGE_PROBING, self.wf_def.stages)
        self.assertIn(STAGE_EXECUTING_OBSERVATION, self.wf_def.stages)
        self.assertIn(STAGE_COMPLETED, self.wf_def.stages)
        self.assertIn(STAGE_CANCELLED, self.wf_def.stages)

        for sr in ALL_STOPPING_REASONS:
            self.assertTrue(sr.isupper())

    def test_02_illegal_transition_rejected(self):
        """Transition validation rejects illegal jumps skipping prerequisites."""
        instance = self.engine.create_instance(
            session_id="sess_wf_1",
            target_pid=os.getpid(),
            goal="Test transition rules",
        )
        self.assertEqual(instance.current_stage, STAGE_INITIALIZING)

        # Illegal direct jump from INITIALIZING to COMPLETED
        ok, err = self.engine.validate_transition(instance, STAGE_COMPLETED)
        self.assertFalse(ok)
        self.assertIn("Illegal stage transition", err)

        # Legal transition to PROBING
        ok_probe, err_probe = self.engine.validate_transition(instance, STAGE_PROBING)
        self.assertTrue(ok_probe, err_probe)

    def test_03_user_cancellation(self):
        """In-progress investigation can be cancelled cleanly with audit entry."""
        instance = self.engine.create_instance(
            session_id="sess_wf_cancel",
            target_pid=os.getpid(),
            goal="Investigate before cancellation",
        )
        self.engine.cancel(instance, reason="User clicked stop")
        self.assertEqual(instance.current_stage, STAGE_CANCELLED)
        self.assertEqual(instance.status, STAGE_CANCELLED)
        self.assertEqual(instance.stopping_reason, STOP_USER_CANCELLED)

        # Verify audit trail contains cancellation
        cancel_entries = [e for e in instance.audit_trail if e["to_stage"] == STAGE_CANCELLED]
        self.assertEqual(len(cancel_entries), 1)
        self.assertEqual(cancel_entries[0]["reason"], "User clicked stop")

    def test_04_state_persistence_and_recovery(self):
        """WorkflowExecutionState serializes to JSON file and resumes identically."""
        instance = self.engine.create_instance(
            session_id="sess_wf_persist",
            target_pid=1234,
            goal="Test persistence",
        )
        instance.record_transition(STAGE_PROBING, "Probing verified")
        instance.context["custom_key"] = "saved_state_123"

        ckpt_file = os.path.join(self.tmp_dir, "ckpt_instance.json")
        self.engine.persist_state(instance, ckpt_file)
        self.assertTrue(os.path.exists(ckpt_file))

        resumed = InvestigationWorkflowEngine.resume_instance(ckpt_file)
        self.assertEqual(resumed.instance_id, instance.instance_id)
        self.assertEqual(resumed.session_id, instance.session_id)
        self.assertEqual(resumed.current_stage, STAGE_PROBING)
        self.assertEqual(resumed.context["custom_key"], "saved_state_123")
        self.assertEqual(len(resumed.audit_trail), len(instance.audit_trail))

    def test_05_execution_on_dead_target_blocks_cleanly(self):
        """Investigation of a dead/non-existent PID transitions to BLOCKED with TARGET_TERMINATED."""
        dead_pid = 9999999
        instance = self.engine.create_instance(
            session_id="sess_wf_dead",
            target_pid=dead_pid,
            goal="Check dead PID",
        )
        res = self.engine.execute_investigation(instance, checkpoint_dir=self.tmp_dir)
        self.assertEqual(instance.current_stage, STAGE_BLOCKED)
        self.assertEqual(instance.stopping_reason, STOP_TARGET_TERMINATED)

    def test_06_execution_on_real_healthy_process_completes_with_audit(self):
        """Full end-to-end execution on real running C++ process produces all stages and audit log."""
        proc = subprocess.Popen([self.healthy_bin])
        try:
            time.sleep(0.1)
            instance = self.engine.create_instance(
                session_id=f"sess_wf_live_{proc.pid}",
                target_pid=proc.pid,
                goal="Real live C++ process health verification",
            )
            res = self.engine.execute_investigation(instance, checkpoint_dir=self.tmp_dir)
            self.assertEqual(instance.current_stage, STAGE_COMPLETED)
            self.assertIn("report", instance.context)

            # Audit trail must show structured progress through lifecycle
            stages_visited = [e["to_stage"] for e in instance.audit_trail]
            self.assertIn(STAGE_INITIALIZING, stages_visited)
            self.assertIn(STAGE_PROBING, stages_visited)
            self.assertIn(STAGE_EXECUTING_OBSERVATION, stages_visited)
            self.assertIn(STAGE_FORMING_DIAGNOSIS, stages_visited)
            self.assertIn(STAGE_COMPLETED, stages_visited)
        finally:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
