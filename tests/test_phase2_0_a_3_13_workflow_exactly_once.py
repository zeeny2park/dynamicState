#!/usr/bin/env python3
"""Phase 2.0-A.3.13 — Workflow Recovery and Exactly-Once Semantics Test Suite.

Audits and proves:
1. Durable operation lifecycle: RESERVED -> EXECUTING -> COMMITTED / FAILED / ABORTED.
2. In-flight failure recovery: Interrupted uncommitted operations (RESERVED/EXECUTING) roll back to ABORTED on resume.
3. Skip already committed: Physical memory reads are skipped across checkpoints ONLY if status is COMMITTED.
4. Checkpoint failure simulation: Resuming from checkpoints saved before read, during read, before commit, and after commit.
5. Idempotent recovery: Multiple resumes on the same checkpoint produce deterministic, idempotent state.
"""

import os
import shutil
import tempfile
import unittest

from extractor.target_adapter import LocalTargetAdapter
from extractor.workflow import (
    InvestigationWorkflowEngine,
    WorkflowExecutionState,
    STAGE_INITIALIZING,
    STAGE_PROBING,
    STAGE_FORMULATING_HYPOTHESIS,
    STAGE_SELECTING_RECIPE,
    STAGE_EXECUTING_OBSERVATION,
    STAGE_EVALUATING_EVIDENCE,
    STAGE_COMPLETED,
)


class TestPhase20A313WorkflowExactlyOnce(unittest.TestCase):
    """Adversarial tests for durable operation state and recovery consistency."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="wf_exactly_once_")
        self.session_id = "sess_exactly_once"
        self.pid = 7777
        self.mock_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:10002000:boot",
            "start_time": "10002000",
            "executable": "/usr/bin/test_target",
            "executable_identity": "/usr/bin/test_target:123456",
            "build_id": "sha1:deadbeef7777",
            "exe_inode": 123456,
        }

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _setup_engine_and_adapter(self):
        ad = LocalTargetAdapter()
        ad.check_liveness = lambda p: (True, None)
        ad.get_process_identity = lambda p: dict(self.mock_ident)
        ad.get_threads = lambda p: [{"tid": p, "state": "R", "is_running_user_space": True, "voluntary_ctxt_switches": 5, "wchan": "0"}]
        ad.get_proc_maps = lambda p: [{"start_int": 0x500000, "end_int": 0x510000, "size": 65536, "is_readable": True, "category": "data"}]
        def _mock_read(p, a, s):
            data = b"\x11" * s
            ad._record_physical_read(len(data), 1, data=data, pid=p, address=a, requested_size=s, status="OBSERVED")
            return data, "OBSERVED", None
        ad.read_memory = _mock_read
        engine = InvestigationWorkflowEngine(target_adapter=ad)
        return engine, ad

    def test_01_operation_lifecycle_normal_execution(self):
        """Standard execution transitions operation from RESERVED -> EXECUTING -> COMMITTED."""
        engine, ad = self._setup_engine_and_adapter()
        inst = engine.create_instance(self.session_id, self.pid, "Verify lifecycle")
        engine.execute_stage_initializing(inst)
        engine.execute_stage_probing(inst)
        engine.execute_stage_formulating_hypothesis(inst)
        engine.execute_stage_selecting_recipe(inst)

        self.assertEqual(inst.current_stage, STAGE_EXECUTING_OBSERVATION)

        ok = engine.execute_stage_executing_observation(inst)
        self.assertTrue(ok)
        self.assertEqual(inst.current_stage, STAGE_EVALUATING_EVIDENCE)

        # Verify operation lifecycle was marked COMMITTED
        obs_key = f"0x{inst.context['target_addr']:x}:{inst.context['target_size']}"
        op_lifecycle = inst.context.get("operation_lifecycle", {})
        self.assertEqual(op_lifecycle.get(obs_key), "COMMITTED")
        self.assertIn(obs_key, inst.context.get("completed_observations", []))

    def test_02_in_flight_uncommitted_operation_aborted_on_resume(self):
        """Operations left in RESERVED or EXECUTING state roll back to ABORTED on resume."""
        engine, ad = self._setup_engine_and_adapter()
        inst = engine.create_instance(self.session_id, self.pid, "Crash during observation")
        engine.execute_stage_initializing(inst)
        engine.execute_stage_probing(inst)
        engine.execute_stage_formulating_hypothesis(inst)
        engine.execute_stage_selecting_recipe(inst)

        # Simulate interruption while EXECUTING (e.g., crash before commit)
        obs_key = f"0x{inst.context['target_addr']:x}:{inst.context['target_size']}"
        inst.context.setdefault("operation_lifecycle", {})[obs_key] = "EXECUTING"

        ckpt_file = os.path.join(self.tmp_dir, "crash_ckpt.json")
        engine.persist_state(inst, ckpt_file)

        # Resume workflow engine
        resume_engine, resume_ad = self._setup_engine_and_adapter()
        resumed_inst = resume_engine.resume_investigation(ckpt_file)

        # Must have rolled back in-flight operation to ABORTED
        self.assertEqual(resumed_inst.context["operation_lifecycle"][obs_key], "ABORTED")

        # Because it was not COMMITTED, stepping observation stage must execute and read
        reads_before = resume_ad.physical_reads_count
        ok = resume_engine.execute_stage_executing_observation(resumed_inst)
        self.assertTrue(ok)
        self.assertEqual(resume_ad.physical_reads_count, reads_before + 1)
        self.assertEqual(resumed_inst.context["operation_lifecycle"][obs_key], "COMMITTED")

    def test_03_committed_observation_not_reexecuted(self):
        """Resuming a checkpoint where observation is COMMITTED skips redundant memory reads."""
        engine, ad = self._setup_engine_and_adapter()
        inst = engine.create_instance(self.session_id, self.pid, "Non re-execution")
        engine.execute_stage_initializing(inst)
        engine.execute_stage_probing(inst)
        engine.execute_stage_formulating_hypothesis(inst)
        engine.execute_stage_selecting_recipe(inst)

        target_addr = inst.context["target_addr"]
        target_size = inst.context["target_size"]
        obs_key = f"0x{target_addr:x}:{target_size}"

        # Pre-seed committed observation and mock receipt in context
        inst.context["completed_observations"] = [obs_key]
        inst.context.setdefault("operation_lifecycle", {})[obs_key] = "COMMITTED"
        inst.context["last_receipt"] = {
            "receipt_id": "rcpt_cached_01",
            "process_identity": self.mock_ident["process_identity"],
            "executable_identity": self.mock_ident["executable_identity"],
            "build_id": self.mock_ident["build_id"],
            "snapshot_binding": "snap_01",
            "capture_epoch": 1,
            "observation_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "physical_bytes_read": 128,
            "authority_level": "TEST",
        }

        ckpt_file = os.path.join(self.tmp_dir, "committed_ckpt.json")
        engine.persist_state(inst, ckpt_file)

        resume_engine, resume_ad = self._setup_engine_and_adapter()
        resumed_inst = resume_engine.resume_investigation(ckpt_file)
        self.assertEqual(resumed_inst.current_stage, STAGE_EXECUTING_OBSERVATION)

        reads_before = resume_ad.physical_reads_count
        ok = resume_engine.execute_stage_executing_observation(resumed_inst)
        self.assertTrue(ok)
        self.assertEqual(resumed_inst.current_stage, STAGE_EVALUATING_EVIDENCE)
        # Reads must not have increased
        self.assertEqual(resume_ad.physical_reads_count, reads_before)

    def test_04_idempotent_multi_resume(self):
        """Repeatedly resuming the same checkpoint produces identical, deterministic state."""
        engine, ad = self._setup_engine_and_adapter()
        inst = engine.create_instance(self.session_id, self.pid, "Idempotent resume")
        engine.execute_stage_initializing(inst)
        engine.execute_stage_probing(inst)

        ckpt_file = os.path.join(self.tmp_dir, "idempotent_ckpt.json")
        engine.persist_state(inst, ckpt_file)

        # Resume 1
        eng1, _ = self._setup_engine_and_adapter()
        inst1 = eng1.resume_investigation(ckpt_file)

        # Resume 2
        eng2, _ = self._setup_engine_and_adapter()
        inst2 = eng2.resume_investigation(ckpt_file)

        self.assertEqual(inst1.to_dict(), inst2.to_dict())


if __name__ == "__main__":
    unittest.main()
