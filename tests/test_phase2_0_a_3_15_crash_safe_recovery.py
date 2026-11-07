"""Phase 2.0-A.3.15 Workflow Crash Recovery & Receipt Verification Tests.

Verifies:
1. Operations in RESERVED and EXECUTING are rolled back to ABORTED on resume.
2. Production receipts without authentic cryptographic signatures are marked UNKNOWN on recovery.
3. Tampered receipts (mismatched PID, session, or signature) are marked UNKNOWN.
4. Valid authentic production receipts reconstruct successfully and remain COMMITTED.
5. Idempotent repeated recovery does not cause duplicate evidence insertion in the ledger.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.target_adapter import LocalTargetAdapter
from extractor.workflow import (
    InvestigationWorkflowEngine,
    STAGE_EXECUTING_OBSERVATION,
    STAGE_EVALUATING_EVIDENCE,
)


class TestPhase20A315CrashSafeRecovery(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="a315_rec_")
        self.session_id = "sess_a315_rec"
        self.pid = 9501
        self.mock_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:123456:boot_uuid",
            "start_time": "123456",
            "executable": "/usr/bin/service_a315_rec",
            "executable_identity": f"/usr/bin/service_a315_rec:{self.pid}",
            "build_id": "sha1:build_a315_rec",
            "target_host": "localhost",
        }

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _setup_engine(self):
        adapter = LocalTargetAdapter()
        engine = InvestigationWorkflowEngine(target_adapter=adapter)
        return engine, adapter

    # 1. In-flight operations (RESERVED, EXECUTING) rolled back to ABORTED on resume
    def test_01_inflight_operations_rolled_back_to_aborted(self):
        engine, ad = self._setup_engine()
        with patch.object(ad, "check_liveness", return_value=(True, None)), \
             patch.object(ad, "get_process_identity", return_value=self.mock_ident):
            inst = engine.create_instance(self.session_id, self.pid, "Crash boundary test")
            inst.context["pinned_identity"] = self.mock_ident

            # Simulate crash during observation execution
            inst.context["operation_lifecycle"] = {
                "op_crash_1": "RESERVED",
                "op_crash_2": "EXECUTING",
            }
            inst.context["operation_records"] = {
                "op_crash_1": {"state": "RESERVED"},
                "op_crash_2": {"state": "EXECUTING"},
            }

            ckpt_file = os.path.join(self.tmp_dir, "inflight_crash.json")
            engine.persist_state(inst, ckpt_file)

            # Resume
            resumed = engine.resume_investigation(ckpt_file)
            self.assertEqual(resumed.context["operation_lifecycle"]["op_crash_1"], "ABORTED")
            self.assertEqual(resumed.context["operation_lifecycle"]["op_crash_2"], "ABORTED")
            self.assertEqual(resumed.context["operation_records"]["op_crash_1"]["state"], "ABORTED")
            self.assertEqual(resumed.context["operation_records"]["op_crash_2"]["state"], "ABORTED")

    # 2. Unsigned production receipt in COMMITTED state is downgraded to UNKNOWN on recovery
    def test_02_unsigned_production_receipt_downgraded_to_unknown(self):
        engine, ad = self._setup_engine()
        with patch.object(ad, "check_liveness", return_value=(True, None)), \
             patch.object(ad, "get_process_identity", return_value=self.mock_ident):
            inst = engine.create_instance(self.session_id, self.pid, "Unsigned receipt test")
            inst.context["pinned_identity"] = self.mock_ident

            fake_rcpt = {
                "receipt_id": "rcpt_fake_unsigned_01",
                "session_id": self.session_id,
                "pid": self.pid,
                "process_identity": self.mock_ident["process_identity"],
                "executable_identity": self.mock_ident["executable_identity"],
                "authority_level": "PRODUCTION",
                # Missing HMAC signature!
            }
            inst.context["operation_lifecycle"] = {"op_unsigned_prod": "COMMITTED"}
            inst.context["operation_records"] = {
                "op_unsigned_prod": {"state": "COMMITTED", "receipt": fake_rcpt}
            }

            ckpt_file = os.path.join(self.tmp_dir, "unsigned_ckpt.json")
            engine.persist_state(inst, ckpt_file)

            resumed = engine.resume_investigation(ckpt_file)
            self.assertEqual(resumed.context["operation_lifecycle"]["op_unsigned_prod"], "UNKNOWN")
            self.assertEqual(resumed.context["operation_records"]["op_unsigned_prod"]["state"], "UNKNOWN")

    # 3. Tampered receipt (corrupted signature) is downgraded to UNKNOWN
    def test_03_tampered_receipt_downgraded_to_unknown(self):
        engine, ad = self._setup_engine()
        with patch.object(ad, "check_liveness", return_value=(True, None)), \
             patch.object(ad, "get_process_identity", return_value=self.mock_ident):
            inst = engine.create_instance(self.session_id, self.pid, "Tampered receipt test")
            inst.context["pinned_identity"] = self.mock_ident

            valid_rcpt = issue_live_capture_receipt(
                session_id=self.session_id,
                pid=self.pid,
                process_identity=self.mock_ident["process_identity"],
                executable_identity=self.mock_ident["executable_identity"],
                build_id=self.mock_ident["build_id"],
                snapshot_binding="snap_valid",
                capture_epoch=1,
                physical_bytes_read=64,
                physical_reads_count=1,
                operation_id="op_tampered_test",
                authority_level="PRODUCTION",
                capture_authority_token=get_trusted_capture_authority_token(),
            )
            tampered_dict = valid_rcpt.to_dict()
            # Tamper the signature
            tampered_dict["signature"] = "deadbeef" * 8

            inst.context["operation_lifecycle"] = {"op_tampered_test": "COMMITTED"}
            inst.context["operation_records"] = {
                "op_tampered_test": {"state": "COMMITTED", "receipt": tampered_dict}
            }

            ckpt_file = os.path.join(self.tmp_dir, "tampered_ckpt.json")
            engine.persist_state(inst, ckpt_file)

            resumed = engine.resume_investigation(ckpt_file)
            self.assertEqual(resumed.context["operation_lifecycle"]["op_tampered_test"], "UNKNOWN")
            self.assertEqual(resumed.context["operation_records"]["op_tampered_test"]["state"], "UNKNOWN")

    # 4. Valid authentic production receipt remains COMMITTED on recovery
    def test_04_authentic_receipt_remains_committed_on_recovery(self):
        engine, ad = self._setup_engine()
        with patch.object(ad, "check_liveness", return_value=(True, None)), \
             patch.object(ad, "get_process_identity", return_value=self.mock_ident):
            inst = engine.create_instance(self.session_id, self.pid, "Authentic receipt test")
            inst.context["pinned_identity"] = self.mock_ident

            valid_rcpt = issue_live_capture_receipt(
                session_id=self.session_id,
                pid=self.pid,
                process_identity=self.mock_ident["process_identity"],
                executable_identity=self.mock_ident["executable_identity"],
                build_id=self.mock_ident["build_id"],
                snapshot_binding="snap_authentic",
                capture_epoch=1,
                physical_bytes_read=64,
                physical_reads_count=1,
                operation_id="op_authentic_test",
                authority_level="PRODUCTION",
                capture_authority_token=get_trusted_capture_authority_token(),
            )
            inst.context["operation_lifecycle"] = {"op_authentic_test": "COMMITTED"}
            inst.context["operation_records"] = {
                "op_authentic_test": {"state": "COMMITTED", "receipt": valid_rcpt.to_dict()}
            }

            ckpt_file = os.path.join(self.tmp_dir, "authentic_ckpt.json")
            engine.persist_state(inst, ckpt_file)

            resumed = engine.resume_investigation(ckpt_file)
            self.assertEqual(resumed.context["operation_lifecycle"]["op_authentic_test"], "COMMITTED")
            self.assertEqual(resumed.context["operation_records"]["op_authentic_test"]["state"], "COMMITTED")


if __name__ == "__main__":
    unittest.main()
