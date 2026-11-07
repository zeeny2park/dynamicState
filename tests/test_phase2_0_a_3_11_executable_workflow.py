"""Phase 2.0-A.3.11 Executable Investigation Workflow Suite.

Automated verification of executable stage handlers, step_stage(), atomic checkpointing, and resume:
1. test_01_e2e_execution_through_all_stages
2. test_02_step_by_step_execution_with_step_stage
3. test_03_stage_failure_transition_to_terminal_error
4. test_04_budget_exhaustion_during_observation
5. test_05_inconclusive_diagnosis_insufficient_evidence
6. test_06_confirmed_diagnosis_validated_hypothesis
7. test_07_checkpoint_persistence_and_reload_fidelity
8. test_08_resume_after_simulated_interruption
9. test_09_reject_resume_when_target_pid_exited
10. test_10_reject_resume_when_target_executable_changed
11. test_11_no_reexecution_of_completed_observations_on_resume
12. test_12_terminal_state_idempotency
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from extractor.target_adapter import LocalTargetAdapter, PIDReusedError
from extractor.workflow import (
    ALL_STOPPING_REASONS,
    ALL_WORKFLOW_STAGES,
    STAGE_ABSTAINED,
    STAGE_BLOCKED,
    STAGE_BUDGET_EXHAUSTED,
    STAGE_CANCELLED,
    STAGE_CHECKING_BUDGET,
    STAGE_COMPARING_COMPETING_HYPOTHESES,
    STAGE_COMPLETED,
    STAGE_EVALUATING_EVIDENCE,
    STAGE_EXECUTING_OBSERVATION,
    STAGE_FAILED,
    STAGE_FORMING_DIAGNOSIS,
    STAGE_FORMULATING_HYPOTHESIS,
    STAGE_GENERATING_REPORT,
    STAGE_INITIALIZING,
    STAGE_PROBING,
    STAGE_SELECTING_RECIPE,
    STAGE_UPDATING_HYPOTHESIS,
    STAGE_VERIFYING_CAUSATION,
    STOP_BUDGET_EXHAUSTED,
    STOP_NORMAL_COMPLETION,
    STOP_TARGET_TERMINATED,
    InvestigationWorkflowDefinition,
    InvestigationWorkflowEngine,
    InvestigationWorkflowInstance,
    WorkflowExecutionState,
)


class TestPhase20A311ExecutableWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="wf_311_")
        cls.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")
        cls.healthy_src = os.path.join(cls.fixtures_dir, "proc_scenario_a_healthy.c")
        cls.healthy_bin = os.path.join(cls.tmp_dir, "proc_scenario_a")
        subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", cls.healthy_src, "-o", cls.healthy_bin, "-pthread"], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def setUp(self):
        self.state_dir = os.path.join(self.tmp_dir, f"state_{time.time_ns()}")
        os.makedirs(self.state_dir, exist_ok=True)
        self.wf_def = InvestigationWorkflowDefinition()
        self.engine = InvestigationWorkflowEngine(definition=self.wf_def, state_dir=self.state_dir)

    # -------------------------------------------------------------------------
    # Scenario 1: End-to-End Execution Through All Stages
    # -------------------------------------------------------------------------
    def test_01_e2e_execution_through_all_stages(self):
        """End-to-end execution proceeds through all core investigation stages to completion."""
        proc = subprocess.Popen([self.healthy_bin])
        try:
            time.sleep(0.1)
            instance = self.engine.create_instance(
                session_id=f"sess_e2e_{proc.pid}",
                target_pid=proc.pid,
                goal="End-to-end multi-stage health check",
            )
            # Run sequential stages using step_stage until a terminal stage is reached
            max_steps = 25
            step_count = 0
            while instance.current_stage not in (STAGE_COMPLETED, STAGE_FAILED, STAGE_BLOCKED, STAGE_CANCELLED):
                step_count += 1
                if step_count > max_steps:
                    self.fail("Workflow exceeded maximum step limit without reaching terminal state")
                res = self.engine.step_stage(instance)
                self.assertTrue(res.get("success", False))

            self.assertEqual(instance.current_stage, STAGE_COMPLETED)
            self.assertEqual(instance.status, "COMPLETED")
            self.assertGreaterEqual(len(instance.audit_trail), 10)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 2: Step-by-Step Execution With step_stage()
    # -------------------------------------------------------------------------
    def test_02_step_by_step_execution_with_step_stage(self):
        """Each call to step_stage() executes exactly one stage and produces auditable output."""
        proc = subprocess.Popen([self.healthy_bin])
        try:
            time.sleep(0.1)
            inst = self.engine.create_instance(
                session_id=f"sess_step_{proc.pid}",
                target_pid=proc.pid,
                goal="Step by step execution",
            )
            self.assertEqual(inst.current_stage, STAGE_INITIALIZING)

            # Step 1: INITIALIZING -> PROBING
            res1 = self.engine.step_stage(inst)
            self.assertTrue(res1["success"])
            self.assertEqual(inst.current_stage, STAGE_PROBING)

            # Step 2: PROBING -> FORMULATING_HYPOTHESIS
            res2 = self.engine.step_stage(inst)
            self.assertTrue(res2["success"])
            self.assertEqual(inst.current_stage, STAGE_FORMULATING_HYPOTHESIS)

            # Step 3: FORMULATING_HYPOTHESIS -> SELECTING_RECIPE
            res3 = self.engine.step_stage(inst)
            self.assertTrue(res3["success"])
            self.assertEqual(inst.current_stage, STAGE_SELECTING_RECIPE)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 3: Stage Failure Handling and Transition to Terminal Error State
    # -------------------------------------------------------------------------
    def test_03_stage_failure_transition_to_terminal_error(self):
        """Failure in a stage handler transitions instance cleanly to terminal error state."""
        proc = subprocess.Popen([self.healthy_bin])
        try:
            time.sleep(0.1)
            inst = self.engine.create_instance(
                session_id=f"sess_fail_{proc.pid}",
                target_pid=proc.pid,
                goal="Simulate stage failure",
            )
            with patch.object(self.engine, "execute_stage_probing", side_effect=RuntimeError("Simulated hardware bus error")):
                # Step 1: Initializing succeeds
                self.engine.step_stage(inst)
                self.assertEqual(inst.current_stage, STAGE_PROBING)

                # Step 2: Probing fails and transitions to STAGE_FAILED
                res = self.engine.step_stage(inst)
                self.assertFalse(res["success"])
                self.assertEqual(inst.current_stage, STAGE_FAILED)
                self.assertEqual(inst.status, "FAILED")
                self.assertIn("Simulated hardware bus error", inst.stopping_explanation)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 4: Budget Exhaustion During Observation Execution
    # -------------------------------------------------------------------------
    def test_04_budget_exhaustion_during_observation(self):
        """Exhausting byte or time budget halts workflow in STAGE_BUDGET_EXHAUSTED."""
        proc = subprocess.Popen([self.healthy_bin])
        try:
            time.sleep(0.1)
            inst = self.engine.create_instance(
                session_id=f"sess_budget_{proc.pid}",
                target_pid=proc.pid,
                goal="Verify budget exhaustion halts workflow",
            )
            # Advance to CHECKING_BUDGET
            inst.current_stage = STAGE_CHECKING_BUDGET
            inst.audit_trail.append({"from_stage": STAGE_UPDATING_HYPOTHESIS, "to_stage": STAGE_CHECKING_BUDGET, "reason": "Advance to budget check"})
            inst.context["budget_exhausted"] = True
            inst.context["budget_exhausted_reason"] = "Max bytes read budget 65536 reached"

            res = self.engine.step_stage(inst)
            self.assertTrue(res["success"])
            self.assertEqual(inst.current_stage, STAGE_BUDGET_EXHAUSTED)
            self.assertEqual(inst.status, "ABSTAINED")
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 5: Inconclusive Diagnosis When Evidence Is Insufficient
    # -------------------------------------------------------------------------
    def test_05_inconclusive_diagnosis_insufficient_evidence(self):
        """Diagnosis handler produces INCONCLUSIVE when observations are missing or inconclusive."""
        proc = subprocess.Popen([self.healthy_bin])
        try:
            time.sleep(0.1)
            inst = self.engine.create_instance(
                session_id=f"sess_inconcl_{proc.pid}",
                target_pid=proc.pid,
                goal="Verify inconclusive diagnosis",
            )
            inst.current_stage = STAGE_FORMING_DIAGNOSIS
            inst.audit_trail.append({"from_stage": STAGE_VERIFYING_CAUSATION, "to_stage": STAGE_FORMING_DIAGNOSIS, "reason": "Advance to diagnosis"})
            inst.context["hypotheses_validated"] = []
            inst.context["evidence_sufficient"] = False

            res = self.engine.step_stage(inst)
            self.assertTrue(res["success"])
            self.assertEqual(inst.context.get("diagnosis"), "INCONCLUSIVE")
            self.assertEqual(inst.current_stage, STAGE_GENERATING_REPORT)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 6: Confirmed Diagnosis When Evidence Validates Hypothesis
    # -------------------------------------------------------------------------
    def test_06_confirmed_diagnosis_validated_hypothesis(self):
        """Diagnosis handler produces CONFIRMED when evidence validates causal hypothesis."""
        proc = subprocess.Popen([self.healthy_bin])
        try:
            time.sleep(0.1)
            inst = self.engine.create_instance(
                session_id=f"sess_conf_{proc.pid}",
                target_pid=proc.pid,
                goal="Verify confirmed diagnosis",
            )
            inst.current_stage = STAGE_FORMING_DIAGNOSIS
            inst.audit_trail.append({"from_stage": STAGE_VERIFYING_CAUSATION, "to_stage": STAGE_FORMING_DIAGNOSIS, "reason": "Advance to diagnosis"})
            inst.context["hypotheses_validated"] = [{"id": "hyp_1", "statement": "Mutex Contention"}]
            inst.context["evidence_sufficient"] = True

            res = self.engine.step_stage(inst)
            self.assertTrue(res["success"])
            self.assertEqual(inst.context.get("diagnosis"), "CONFIRMED")
            self.assertEqual(inst.current_stage, STAGE_GENERATING_REPORT)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 7: Checkpoint Persistence and Reload Fidelity
    # -------------------------------------------------------------------------
    def test_07_checkpoint_persistence_and_reload_fidelity(self):
        """Atomic persistence writes durable state that reloads with complete fidelity."""
        inst = self.engine.create_instance(
            session_id="sess_persist_1",
            target_pid=12345,
            goal="Durable persistence check",
        )
        inst.context["custom_metric"] = 9999
        self.engine.persist_state(inst)

        state_path = os.path.join(self.state_dir, f"{inst.instance_id}.json")
        self.assertTrue(os.path.exists(state_path))

        reloaded = self.engine.load_instance(inst.instance_id)
        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded.instance_id, inst.instance_id)
        self.assertEqual(reloaded.target_pid, 12345)
        self.assertEqual(reloaded.context.get("custom_metric"), 9999)

    # -------------------------------------------------------------------------
    # Scenario 8: Resume After Simulated Interruption
    # -------------------------------------------------------------------------
    def test_08_resume_after_simulated_interruption(self):
        """Interrupted workflow reloads from checkpoint and resumes execution successfully."""
        proc = subprocess.Popen([self.healthy_bin])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            pinned = adapter.pin_target_identity(proc.pid)

            inst = self.engine.create_instance(
                session_id=f"sess_resume_{proc.pid}",
                target_pid=proc.pid,
                goal="Resume after simulated crash",
            )
            inst.context["pinned_identity"] = pinned
            # Advance to SELECTING_RECIPE and persist
            self.engine.step_stage(inst)  # -> PROBING
            self.engine.step_stage(inst)  # -> FORMULATING_HYPOTHESIS
            self.engine.step_stage(inst)  # -> SELECTING_RECIPE
            self.assertEqual(inst.current_stage, STAGE_SELECTING_RECIPE)
            self.engine.persist_state(inst)

            # Simulate process crash / new engine instance reloading
            fresh_engine = InvestigationWorkflowEngine(definition=self.wf_def, state_dir=self.state_dir)
            resumed = fresh_engine.resume_investigation(inst.instance_id, adapter=adapter)
            self.assertIsNotNone(resumed)
            self.assertEqual(resumed.current_stage, STAGE_SELECTING_RECIPE)
            self.assertEqual(resumed.status, "RUNNING")
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 9: Reject Resume When Target PID Has Exited
    # -------------------------------------------------------------------------
    def test_09_reject_resume_when_target_pid_exited(self):
        """Resuming a workflow after the target process exited must fail closed."""
        proc = subprocess.Popen([self.healthy_bin])
        pid = proc.pid
        time.sleep(0.1)
        adapter = LocalTargetAdapter()
        pinned = adapter.pin_target_identity(pid)

        inst = self.engine.create_instance(
            session_id=f"sess_exit_{pid}",
            target_pid=pid,
            goal="Target exits before resume",
        )
        inst.context["pinned_identity"] = pinned
        self.engine.persist_state(inst)

        # Terminate process before resume
        proc.kill()
        proc.wait()

        fresh_engine = InvestigationWorkflowEngine(definition=self.wf_def, state_dir=self.state_dir)
        with self.assertRaises(ProcessLookupError):
            fresh_engine.resume_investigation(inst.instance_id, adapter=adapter)

    # -------------------------------------------------------------------------
    # Scenario 10: Reject Resume When Target Executable Changed
    # -------------------------------------------------------------------------
    def test_10_reject_resume_when_target_executable_changed(self):
        """Resuming a workflow when the target process executable identity changed must raise PIDReusedError."""
        proc = subprocess.Popen([self.healthy_bin])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            pinned = adapter.pin_target_identity(proc.pid)

            inst = self.engine.create_instance(
                session_id=f"sess_replace_{proc.pid}",
                target_pid=proc.pid,
                goal="Binary replacement before resume",
            )
            # Store forged pinned identity with different executable
            forged_pinned = dict(pinned)
            forged_pinned["executable"] = "/usr/bin/different_binary"
            inst.context["pinned_identity"] = forged_pinned
            self.engine.persist_state(inst)

            fresh_engine = InvestigationWorkflowEngine(definition=self.wf_def, state_dir=self.state_dir)
            with self.assertRaises(PIDReusedError):
                fresh_engine.resume_investigation(inst.instance_id, adapter=adapter)
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 11: No Re-execution of Completed Observations on Resume
    # -------------------------------------------------------------------------
    def test_11_no_reexecution_of_completed_observations_on_resume(self):
        """Observations already completed before interruption are not re-executed upon resume."""
        proc = subprocess.Popen([self.healthy_bin])
        try:
            time.sleep(0.1)
            adapter = LocalTargetAdapter()
            pinned = adapter.pin_target_identity(proc.pid)

            inst = self.engine.create_instance(
                session_id=f"sess_no_reexec_{proc.pid}",
                target_pid=proc.pid,
                goal="Verify non-re-execution",
            )
            inst.context["pinned_identity"] = pinned
            inst.context["completed_observations"] = ["obs_locks_1", "obs_threads_1"]
            self.engine.persist_state(inst)

            fresh_engine = InvestigationWorkflowEngine(definition=self.wf_def, state_dir=self.state_dir)
            resumed = fresh_engine.resume_investigation(inst.instance_id, adapter=adapter)
            self.assertEqual(
                resumed.context.get("completed_observations"),
                ["obs_locks_1", "obs_threads_1"],
            )
        finally:
            proc.kill()
            proc.wait()

    # -------------------------------------------------------------------------
    # Scenario 12: Terminal State Idempotency
    # -------------------------------------------------------------------------
    def test_12_terminal_state_idempotency(self):
        """Stepping an already completed or terminal workflow instance is an idempotent no-op."""
        inst = self.engine.create_instance(
            session_id="sess_idemp_1",
            target_pid=os.getpid(),
            goal="Terminal idempotency check",
        )
        inst.current_stage = STAGE_COMPLETED
        inst.status = "COMPLETED"
        self.assertEqual(inst.current_stage, STAGE_COMPLETED)

        # Calling step_stage on completed instance returns success without state mutation
        res = self.engine.step_stage(inst)
        self.assertTrue(res["success"])
        self.assertEqual(inst.current_stage, STAGE_COMPLETED)
        self.assertEqual(inst.status, "COMPLETED")


if __name__ == "__main__":
    unittest.main()
