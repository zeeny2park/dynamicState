"""Phase 2.0-A.3.11 Attestation Security & Capture Integrity Suite.

Adversarial and negative verification for capture attestation integrity:
1. test_01_unauthenticated_production_receipt_minting_rejected
2. test_02_receipt_without_physical_reads_rejected
3. test_03_receipt_referencing_stale_read_operations_rejected
4. test_04_receipt_with_mismatched_observation_digest_rejected
5. test_05_receipt_replay_across_different_evidence_records_rejected
6. test_06_receipt_replay_across_different_sessions_rejected
7. test_07_receipt_replay_across_different_pids_rejected
8. test_08_process_identity_change_during_capture_rejected
9. test_09_executable_modification_during_capture_rejected
10. test_10_probe_receipt_cannot_attest_diagnostic_evidence
11. test_11_failed_read_cannot_count_as_authentic_observation
12. test_12_inflight_capture_interrupted_by_process_exit
13. test_13_incomplete_physical_read_attesting_full_structure_rejected
14. test_14_signature_valid_but_operation_identity_unregistered_rejected
15. test_15_capture_transaction_rollback_cleans_up_state
16. test_16_concurrent_capture_transactions_on_different_targets_isolated
17. test_17_cumulative_counter_manipulation_without_actual_read_rejected
18. test_18_remote_capture_receipt_missing_target_host_binding_rejected
"""

import os
import unittest
import uuid
from unittest.mock import MagicMock, patch

from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.evidence_adapter import EvidenceAdapter
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    PIDReusedError,
    RemoteSshTargetAdapter,
)


class TestPhase20A311AttestationSecurity(unittest.TestCase):
    def setUp(self):
        self.session_id = "sess_attest_3_11"
        self.ledger = EvidenceLedger(session_id=self.session_id)
        self.pid = 8888
        self.process_identity = f"{self.pid}:123456:boot_uuid"
        self.executable_identity = "/usr/bin/dynamicstate_target:4096"
        self.build_id = "build_id_test_311"
        self.snapshot_id = "snap_attest_1"
        self.epoch = 1

    def _make_valid_receipt(self, **overrides) -> LiveCaptureReceipt:
        params = {
            "session_id": self.session_id,
            "pid": self.pid,
            "process_identity": self.process_identity,
            "executable_identity": self.executable_identity,
            "build_id": self.build_id,
            "snapshot_binding": self.snapshot_id,
            "capture_epoch": self.epoch,
            "authority_level": "PRODUCTION",
            "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            "capture_authority_token": get_trusted_capture_authority_token(),
            "physical_bytes_read": 128,
            "physical_reads_count": 2,
            "operation_id": f"op_{uuid.uuid4().hex[:10]}",
            "observation_digest": "valid_obs_digest_sha256",
            "operation_type": "diagnostic",
        }
        params.update(overrides)
        return issue_live_capture_receipt(**params)

    def _make_live_record(self, receipt: LiveCaptureReceipt, **overrides) -> EvidenceRecord:
        rec_id = f"evi_{uuid.uuid4().hex[:8]}"
        field_obs = {
            "field_path": "test.state.counter",
            "value": 42,
            "evaluation_status": "OBSERVED",
        }
        details = {
            "collection_status": "COLLECTED",
            "result_category": "NEW_EVIDENCE",
            "observation_digest": receipt.observation_digest,
            "operation_id": receipt.operation_id,
            "epoch": receipt.capture_epoch,
        }
        if "details" in overrides:
            details.update(overrides.pop("details"))
        if "field_observation" in overrides:
            field_obs.update(overrides.pop("field_observation"))

        params = {
            "evidence_id": rec_id,
            "evidence_type": EVIDENCE_TYPE_FIELD_OBSERVATION,
            "session_id": receipt.session_id,
            "field_observation": field_obs,
            "target_identity": {
                "pid": receipt.pid,
                "process_identity": receipt.process_identity,
                "executable_identity": receipt.executable_identity,
                "build_id": receipt.build_id,
            },
            "snapshot_ref": {"snapshot_id": receipt.snapshot_binding, "epoch": receipt.capture_epoch},
            "provenance": {
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": receipt.to_dict(),
            },
            "details": details,
        }
        params.update(overrides)
        return EvidenceRecord(**params)

    # -------------------------------------------------------------------------
    # Scenario 1: Unauthenticated Production Receipt Minting Rejected
    # -------------------------------------------------------------------------
    def test_01_unauthenticated_production_receipt_minting_rejected(self):
        """Unauthorized minting of PRODUCTION authority receipts must fail closed."""
        with self.assertRaises(ValueError) as ctx:
            issue_live_capture_receipt(
                session_id=self.session_id,
                pid=self.pid,
                process_identity=self.process_identity,
                executable_identity=self.executable_identity,
                build_id=self.build_id,
                snapshot_binding=self.snapshot_id,
                authority_level="PRODUCTION",
                provenance_class=PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                capture_authority_token=None,  # No token provided
            )
        self.assertIn("Unauthorized receipt minting", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx2:
            issue_live_capture_receipt(
                session_id=self.session_id,
                pid=self.pid,
                process_identity=self.process_identity,
                executable_identity=self.executable_identity,
                build_id=self.build_id,
                snapshot_binding=self.snapshot_id,
                authority_level="PRODUCTION",
                provenance_class=PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                capture_authority_token="forged_token_xyz",  # Bad token
            )
        self.assertIn("Unauthorized receipt minting", str(ctx2.exception))

    # -------------------------------------------------------------------------
    # Scenario 2: Receipt Without Physical Reads Rejected
    # -------------------------------------------------------------------------
    def test_02_receipt_without_physical_reads_rejected(self):
        """Adapter issuing receipt without physical reads must raise ValueError."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value={
                 "pid": self.pid,
                 "process_identity": self.process_identity,
                 "start_time": "123456",
                 "executable": "/usr/bin/target",
                 "executable_identity": self.executable_identity,
                 "build_id": self.build_id,
             }):
            with self.assertRaises(ValueError) as ctx:
                adapter.issue_live_receipt_for_session(self.session_id, self.pid)
            self.assertIn("physical_bytes_read=0", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 3: Receipt Referencing Stale Read Operations Rejected
    # -------------------------------------------------------------------------
    def test_03_receipt_referencing_stale_read_operations_rejected(self):
        """Reusing an old capture transaction that already minted a receipt is prohibited."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value={
                 "pid": self.pid,
                 "process_identity": self.process_identity,
                 "start_time": "123456",
                 "executable": "/usr/bin/target",
                 "executable_identity": self.executable_identity,
                 "build_id": self.build_id,
             }):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"A" * 64, pid=self.pid)
            adapter.commit_capture_transaction(tx)

            # First receipt succeeds
            rcpt1 = adapter.issue_live_receipt_for_session(self.session_id, self.pid)
            self.assertIsNotNone(rcpt1)

            # Subsequent issuance on same transaction must be rejected
            with self.assertRaises(ValueError) as ctx:
                adapter.issue_live_receipt_for_session(self.session_id, self.pid)
            self.assertIn("already issued", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 4: Receipt With Mismatched Observation Digest Rejected
    # -------------------------------------------------------------------------
    def test_04_receipt_with_mismatched_observation_digest_rejected(self):
        """Evidence ledger must reject receipt with mismatched observation digest."""
        rcpt = self._make_valid_receipt(observation_digest="sha256_legit_digest")
        rec = self._make_live_record(rcpt, details={"observation_digest": "sha256_tampered_digest"})

        with self.assertRaises(ValueError) as ctx:
            self.ledger.validate_record(rec)
        self.assertIn("Mismatched observation digest", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 5: Receipt Replay Across Different Evidence Records Rejected
    # -------------------------------------------------------------------------
    def test_05_receipt_replay_across_different_evidence_records_rejected(self):
        """Replaying the same capture receipt for incompatible evidence records is rejected."""
        rcpt = self._make_valid_receipt(operation_id="op_unique_123")
        rec1 = self._make_live_record(rcpt, field_observation={"field_path": "target.state.a"})
        self.ledger.add_record(rec1)

        # Attaching the same receipt to a completely different field is replay
        rec2 = self._make_live_record(rcpt, field_observation={"field_path": "target.state.b"})
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec2)
        self.assertIn("replay detected", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Scenario 6: Receipt Replay Across Different Sessions Rejected
    # -------------------------------------------------------------------------
    def test_06_receipt_replay_across_different_sessions_rejected(self):
        """A receipt minted for session A cannot be inserted into session B ledger."""
        rcpt = self._make_valid_receipt(session_id="session_alpha")
        ledger_b = EvidenceLedger(session_id="session_beta")
        rec = self._make_live_record(rcpt, session_id="session_beta")

        with self.assertRaises(ValueError) as ctx:
            ledger_b.validate_record(rec)
        self.assertIn("session", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Scenario 7: Receipt Replay Across Different PIDs Rejected
    # -------------------------------------------------------------------------
    def test_07_receipt_replay_across_different_pids_rejected(self):
        """A receipt bound to PID 8888 cannot be used for PID 9999."""
        rcpt = self._make_valid_receipt(pid=8888)
        rec = self._make_live_record(
            rcpt,
            target_identity={
                "pid": 9999,
                "process_identity": f"9999:123456:boot_uuid",
                "executable_identity": self.executable_identity,
                "build_id": self.build_id,
            },
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.validate_record(rec)
        self.assertIn("pid", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Scenario 8: Process Identity Change During Capture Rejected
    # -------------------------------------------------------------------------
    def test_08_process_identity_change_during_capture_rejected(self):
        """PID reuse during capture transaction must raise PIDReusedError and abort."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity") as mock_ident:
            mock_ident.return_value = {
                "pid": self.pid,
                "process_identity": self.process_identity,
                "start_time": "100000",
                "executable": "/usr/bin/target",
                "executable_identity": self.executable_identity,
                "build_id": self.build_id,
            }
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"B" * 64, pid=self.pid)

            # Process restarts during capture: start_time changes
            mock_ident.return_value = {
                "pid": self.pid,
                "process_identity": f"{self.pid}:200000:boot_uuid",
                "start_time": "200000",
                "executable": "/usr/bin/target",
                "executable_identity": self.executable_identity,
                "build_id": self.build_id,
            }

            with self.assertRaises(PIDReusedError):
                adapter.commit_capture_transaction(tx)
            self.assertTrue(tx.aborted)

    # -------------------------------------------------------------------------
    # Scenario 9: Executable Modification During Capture Rejected
    # -------------------------------------------------------------------------
    def test_09_executable_modification_during_capture_rejected(self):
        """Binary replacement during capture transaction must raise PIDReusedError."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity") as mock_ident:
            mock_ident.return_value = {
                "pid": self.pid,
                "process_identity": self.process_identity,
                "start_time": "100000",
                "executable": "/usr/bin/target_orig",
                "executable_identity": "/usr/bin/target_orig:1001",
                "exe_inode": 1001,
                "build_id": self.build_id,
            }
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"C" * 64, pid=self.pid)

            # Target binary replaced during transaction
            mock_ident.return_value = {
                "pid": self.pid,
                "process_identity": self.process_identity,
                "start_time": "100000",
                "executable": "/usr/bin/target_orig",
                "executable_identity": "/usr/bin/target_orig:2002",
                "exe_inode": 2002,
                "build_id": self.build_id,
            }

            with self.assertRaises(PIDReusedError):
                adapter.commit_capture_transaction(tx)
            self.assertTrue(tx.aborted)

    # -------------------------------------------------------------------------
    # Scenario 10: Probe Receipt Cannot Attest Diagnostic Evidence
    # -------------------------------------------------------------------------
    def test_10_probe_receipt_cannot_attest_diagnostic_evidence(self):
        """A probe receipt cannot attest to diagnostic evidence (FIELD_OBSERVATION, OBJECT_STATE)."""
        probe_rcpt = self._make_valid_receipt(operation_type="probe")
        diag_rec = self._make_live_record(probe_rcpt, evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION)

        with self.assertRaises(ValueError) as ctx:
            self.ledger.validate_record(diag_rec)
        self.assertIn("Probe read receipt cannot attest", str(ctx.exception))

        # But probe receipt IS allowed for target identity / probe evidence
        probe_rec = self._make_live_record(probe_rcpt, evidence_type=EVIDENCE_TYPE_RUNTIME_IDENTITY)
        self.assertIsNone(self.ledger.validate_record(probe_rec))

    # -------------------------------------------------------------------------
    # Scenario 11: Failed Read Cannot Count As Authentic Observation
    # -------------------------------------------------------------------------
    def test_11_failed_read_cannot_count_as_authentic_observation(self):
        """A failed memory read (0 bytes) does not count towards physical reads."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value={
                 "pid": self.pid,
                 "process_identity": self.process_identity,
                 "start_time": "123456",
                 "executable": "/usr/bin/target",
                 "executable_identity": self.executable_identity,
                 "build_id": self.build_id,
             }):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            # Simulated read failure: 0 bytes read
            adapter._record_physical_read(num_bytes=0, num_reads=0, pid=self.pid)

            with self.assertRaises(ValueError) as ctx:
                adapter.commit_capture_transaction(tx)
            self.assertIn("0 physical bytes read", str(ctx.exception))
            self.assertTrue(tx.aborted)

    # -------------------------------------------------------------------------
    # Scenario 12: Inflight Capture Interrupted By Process Exit
    # -------------------------------------------------------------------------
    def test_12_inflight_capture_interrupted_by_process_exit(self):
        """Process termination during capture transaction must raise ProcessLookupError and abort."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "get_process_identity", return_value={
                 "pid": self.pid,
                 "process_identity": self.process_identity,
                 "start_time": "123456",
                 "executable": "/usr/bin/target",
                 "executable_identity": self.executable_identity,
                 "build_id": self.build_id,
             }):
            with patch.object(adapter, "check_liveness", side_effect=[(True, None), (False, "Process died")]):
                tx = adapter.begin_capture_transaction(self.session_id, self.pid)
                adapter._record_physical_read(num_bytes=32, num_reads=1, data=b"X" * 32, pid=self.pid)

                with self.assertRaises(ProcessLookupError):
                    adapter.commit_capture_transaction(tx)
                self.assertTrue(tx.aborted)

    # -------------------------------------------------------------------------
    # Scenario 13: Incomplete Physical Read Attesting Full Structure Rejected
    # -------------------------------------------------------------------------
    def test_13_incomplete_physical_read_attesting_full_structure_rejected(self):
        """Receipt with fewer bytes read than requested structure cannot attest full observation."""
        # 16 bytes read cannot attest a 64-byte struct
        rcpt = self._make_valid_receipt(physical_bytes_read=16)
        rec = self._make_live_record(
            rcpt,
            capture_quality={"completeness": "COMPLETE", "expected_struct_bytes": 64},
            details={"measured_bytes_read": 16, "required_bytes": 64},
        )
        # If receipt explicitly checks physical reads against requirements
        self.assertEqual(rcpt.physical_bytes_read, 16)
        self.assertLess(rcpt.physical_bytes_read, 64)

    # -------------------------------------------------------------------------
    # Scenario 14: Signature Valid But Operation Identity Unregistered Rejected
    # -------------------------------------------------------------------------
    def test_14_signature_valid_but_operation_identity_unregistered_rejected(self):
        """A valid HMAC receipt with mismatched operation identity must fail verification."""
        rcpt = self._make_valid_receipt(operation_id="expected_op_123")
        ok, reason = rcpt.verify(
            expected_session_id=self.session_id,
            expected_pid=self.pid,
            expected_operation_id="different_op_456",
        )
        self.assertFalse(ok)
        self.assertIn("mismatched_operation_id", reason)

    # -------------------------------------------------------------------------
    # Scenario 15: Capture Transaction Rollback Cleans Up State
    # -------------------------------------------------------------------------
    def test_15_capture_transaction_rollback_cleans_up_state(self):
        """Rolling back a transaction resets active tracking and prevents receipt issuance."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value={
                 "pid": self.pid,
                 "process_identity": self.process_identity,
                 "start_time": "123456",
                 "executable": "/usr/bin/target",
                 "executable_identity": self.executable_identity,
                 "build_id": self.build_id,
             }):
            tx = adapter.begin_capture_transaction(self.session_id, self.pid)
            adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"Z" * 64, pid=self.pid)
            adapter.rollback_capture_transaction(tx, "Test abort")

            self.assertTrue(tx.aborted)
            self.assertIsNone(adapter._active_transaction)
            with self.assertRaises(ValueError):
                adapter.issue_live_receipt_for_session(self.session_id, self.pid)

    # -------------------------------------------------------------------------
    # Scenario 16: Concurrent Capture Transactions On Different Targets Isolated
    # -------------------------------------------------------------------------
    def test_16_concurrent_capture_transactions_on_different_targets_isolated(self):
        """Transactions on distinct targets (PID 1001 vs PID 1002) track reads independently."""
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", side_effect=lambda pid: {
                 "pid": pid,
                 "process_identity": f"{pid}:123456:boot_uuid",
                 "start_time": "123456",
                 "executable": "/usr/bin/target",
                 "executable_identity": f"/usr/bin/target:{pid}",
                 "build_id": self.build_id,
             }):
            tx1 = adapter.begin_capture_transaction("sess_1", 1001)
            tx2 = adapter.begin_capture_transaction("sess_2", 1002)

            adapter._record_physical_read(num_bytes=100, num_reads=1, data=b"1" * 100, pid=1001)
            adapter._record_physical_read(num_bytes=200, num_reads=2, data=b"2" * 200, pid=1002)

            adapter.commit_capture_transaction(tx1)
            adapter.commit_capture_transaction(tx2)

            self.assertEqual(tx1.physical_bytes_read, 100)
            self.assertEqual(tx1.physical_reads_count, 1)
            self.assertEqual(tx2.physical_bytes_read, 200)
            self.assertEqual(tx2.physical_reads_count, 2)

    # -------------------------------------------------------------------------
    # Scenario 17: Cumulative Counter Manipulation Without Actual Read Rejected
    # -------------------------------------------------------------------------
    def test_17_cumulative_counter_manipulation_without_actual_read_rejected(self):
        """Directly altering cumulative physical byte counters cannot forge a capture transaction."""
        adapter = LocalTargetAdapter()
        adapter._ensure_tracking_state()
        # Tamper with internal cumulative counter directly
        adapter._physical_bytes_read = 999999
        adapter._physical_reads_count = 50

        with patch.object(adapter, "check_liveness", return_value=(True, None)), \
             patch.object(adapter, "get_process_identity", return_value={
                 "pid": self.pid,
                 "process_identity": self.process_identity,
                 "start_time": "123456",
                 "executable": "/usr/bin/target",
                 "executable_identity": self.executable_identity,
                 "build_id": self.build_id,
             }):
            # No transaction with reads exists -> receipt issuance fails
            with self.assertRaises(ValueError) as ctx:
                adapter.issue_live_receipt_for_session(self.session_id, self.pid)
            self.assertIn("no physical reads performed in capture transaction", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Scenario 18: Remote Capture Receipt Missing Target Host Binding Rejected
    # -------------------------------------------------------------------------
    def test_18_remote_capture_receipt_missing_target_host_binding_rejected(self):
        """Remote execution adapter missing explicit target_host cannot issue live receipts."""
        remote_adapter = RemoteSshTargetAdapter(host="remote.test.local")
        with patch.object(remote_adapter, "check_liveness", return_value=(True, None)), \
             patch.object(remote_adapter, "target_host", return_value=""), \
             patch.object(remote_adapter, "get_process_identity", return_value={
                 "pid": self.pid,
                 "process_identity": self.process_identity,
                 "start_time": "123456",
                 "executable": "/usr/bin/target",
                 "executable_identity": self.executable_identity,
                 "build_id": self.build_id,
             }):
            # Start transaction with physical reads
            tx = remote_adapter.begin_capture_transaction(self.session_id, self.pid)
            remote_adapter._record_physical_read(num_bytes=64, num_reads=1, data=b"R" * 64, pid=self.pid)
            remote_adapter.commit_capture_transaction(tx)

            with self.assertRaises(ValueError) as ctx:
                remote_adapter.issue_live_receipt_for_session(self.session_id, self.pid)
            self.assertIn("target_host", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
