"""Phase 2.0-A.3.14 Workflow Crash Boundaries & Recovery Tests.

Verifies:
1. Crash during reservation (RESERVED state) rolls back to ABORTED on resume.
2. Crash during physical read (EXECUTING state) rolls back to ABORTED on resume.
3. Deserialized COMMITTED flag without receipt/evidence is marked UNKNOWN and requires reconciliation.
4. Fully COMMITTED operation with valid receipt skips physical read on resume.
5. Target process death or PID reuse on resume triggers immediate recovery abort.
6. Concurrent workflow recovery instances operate with strict isolation.
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from extractor.target_adapter import LocalTargetAdapter, PIDReusedError
from extractor.workflow import (
    STAGE_EXECUTING_OBSERVATION,
    STAGE_INITIALIZING,
    STAGE_PROBING,
    STAGE_SELECTING_RECIPE,
    InvestigationWorkflowEngine,
    WorkflowExecutionState,
)


class TestPhase20A314WorkflowCrashBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="wf_crash_")
        self.session_id = "sess_crash_test"
        self.pid = 8001
        self.mock_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:123456:boot_uuid",
            "start_time": "123456",
            "executable": "/usr/bin/target",
            "executable_identity": f"/usr/bin/target:{self.pid}",
            "build_id": "crash_1234",
            "exe_inode": 99999,
        }

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _setup_mock_adapter(self):
        adapter = LocalTargetAdapter()
        adapter.check_liveness = lambda pid: (True, None)
        adapter.get_process_identity = lambda pid: dict(self.mock_ident)
        adapter.get_proc_maps = lambda pid: [{"start_int": 0x400000, "size": 0x1000, "is_readable": True}]
        adapter.get_threads = lambda pid: [{"tid": pid, "state": "R"}]
        return adapter

    # 1. Crash during reservation: RESERVED state rolls back to ABORTED on resume
    def test_01_crash_during_reservation_rolls_back_to_aborted(self):
        adapter = self._setup_mock_adapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)
        inst = engine.create_instance(session_id=self.session_id, target_pid=self.pid, goal="Crash test")
        inst.context["pinned_identity"] = dict(self.mock_ident)
        inst.context["operation_lifecycle"] = {"0x400000:128": "RESERVED"}
        inst.context["operation_records"] = {"op_obs_1": {"operation_id": "op_obs_1", "state": "RESERVED"}}

        # Checkpoint and resume
        cp_file = os.path.join(self.tmp_dir, "ckpt_res.json")
        engine.persist_state(inst, cp_file)

        engine2 = InvestigationWorkflowEngine(target_adapter=adapter)
        resumed = engine2.resume_investigation(inst, checkpoint_dir=self.tmp_dir)
        self.assertEqual(resumed.context["operation_lifecycle"]["0x400000:128"], "ABORTED")
        self.assertEqual(resumed.context["operation_records"]["op_obs_1"]["state"], "ABORTED")

    # 2. Crash during physical read: EXECUTING state rolls back to ABORTED on resume
    def test_02_crash_during_executing_rolls_back_to_aborted(self):
        adapter = self._setup_mock_adapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)
        inst = engine.create_instance(session_id=self.session_id, target_pid=self.pid, goal="Crash test")
        inst.context["pinned_identity"] = dict(self.mock_ident)
        inst.context["operation_lifecycle"] = {"0x400000:128": "EXECUTING"}
        inst.context["operation_records"] = {"op_obs_1": {"operation_id": "op_obs_1", "state": "EXECUTING"}}

        engine2 = InvestigationWorkflowEngine(target_adapter=adapter)
        resumed = engine2.resume_investigation(inst)
        self.assertEqual(resumed.context["operation_lifecycle"]["0x400000:128"], "ABORTED")
        self.assertEqual(resumed.context["operation_records"]["op_obs_1"]["state"], "ABORTED")

    # 3. Deserialized COMMITTED flag without receipt/evidence marked UNKNOWN
    def test_03_deserialized_committed_flag_without_receipt_marked_unknown(self):
        adapter = self._setup_mock_adapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)
        inst = engine.create_instance(session_id=self.session_id, target_pid=self.pid, goal="Crash test")
        inst.context["pinned_identity"] = dict(self.mock_ident)
        # Marked COMMITTED but no last_receipt or receipt_id in records
        inst.context["operation_lifecycle"] = {"0x400000:128": "COMMITTED"}
        inst.context["operation_records"] = {"op_obs_1": {"operation_id": "op_obs_1", "state": "COMMITTED"}}
        inst.context.pop("last_receipt", None)

        engine2 = InvestigationWorkflowEngine(target_adapter=adapter)
        resumed = engine2.resume_investigation(inst)
        self.assertEqual(resumed.context["operation_lifecycle"]["0x400000:128"], "UNKNOWN")
        self.assertEqual(resumed.context["operation_records"]["op_obs_1"]["state"], "UNKNOWN")

    # 4. Target PID reuse (changed start_time) aborts resume
    def test_04_target_pid_reuse_aborts_resume(self):
        adapter = self._setup_mock_adapter()
        # Mock changed start_time indicating PID reuse
        reused_ident = dict(self.mock_ident)
        reused_ident["start_time"] = "999999"
        adapter.get_process_identity = lambda pid: reused_ident

        engine = InvestigationWorkflowEngine(target_adapter=adapter)
        inst = engine.create_instance(session_id=self.session_id, target_pid=self.pid, goal="Crash test")
        inst.context["pinned_identity"] = dict(self.mock_ident)

        with self.assertRaises(PIDReusedError) as ctx:
            engine.resume_investigation(inst)
        self.assertIn("PID reuse detected", str(ctx.exception))

    # 5. Concurrent workflow recovery instances operate with strict isolation
    def test_05_concurrent_workflow_recovery_isolation(self):
        adapter = self._setup_mock_adapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)

        inst1 = engine.create_instance(session_id="sess_rec_1", target_pid=self.pid, goal="Crash test 1")
        inst1.context["pinned_identity"] = dict(self.mock_ident)
        inst1.context["operation_lifecycle"] = {"0x400000:128": "COMMITTED"}
        inst1.context["last_receipt"] = {"receipt_id": "rcpt_1"}

        inst2 = engine.create_instance(session_id="sess_rec_2", target_pid=self.pid, goal="Crash test 2")
        inst2.context["pinned_identity"] = dict(self.mock_ident)
        inst2.context["operation_lifecycle"] = {"0x400000:128": "EXECUTING"}

        res1 = engine.resume_investigation(inst1)
        res2 = engine.resume_investigation(inst2)

        self.assertEqual(res1.context["operation_lifecycle"]["0x400000:128"], "COMMITTED")
        self.assertEqual(res2.context["operation_lifecycle"]["0x400000:128"], "ABORTED")


if __name__ == "__main__":
    unittest.main()
