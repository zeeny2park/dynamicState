"""Phase 2.0-A.3.16 Durable Anti-Replay Enforcement Tests.

Verifies:
1. Attestation IDs are persisted and replayed IDs are rejected fail-closed.
2. Operation IDs are persisted and replayed across sessions or PIDs are rejected.
3. DurableTrustStore.used_operation_ids lifecycle (recording session, PID, timestamp, metadata).
4. Receipt-to-operation cardinality: 1:1 binding strictly enforced.
5. Replay acceptance and durable recording are atomic (persistence failure aborts trust acceptance).
6. Concurrent replay attempts result in exactly one successful acceptance.
"""

from concurrent.futures import ThreadPoolExecutor
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from extractor.capture_backend import (
    CausalAttestation,
    CausalVerifierAuthority,
    DurableTrustStore,
    get_trusted_capture_authority_token,
    issue_causal_attestation,
    issue_live_capture_receipt,
    set_default_trust_store,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)


class TestPhase20A316DurableAntiReplay(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="a316_replay_")
        self.store_path = os.path.join(self.tmp_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)
        set_default_trust_store(self.trust_store)

        self.session_id = "sess_a316_replay"
        self.pid = 9301
        self.target_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:334455:boot_uuid",
            "start_time": "334455",
            "executable": "/usr/bin/service_a316_replay",
            "executable_identity": f"/usr/bin/service_a316_replay:{self.pid}",
            "build_id": "sha1:build_a316_replay",
            "target_host": "localhost",
        }

    def tearDown(self):
        set_default_trust_store(None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # 1. Attestation IDs are persisted and replayed IDs are rejected fail-closed
    def test_01_attestation_id_persisted_and_replays_rejected(self):
        self.trust_store.register_key("k1", "secret_1", is_active=True)
        self.assertFalse(self.trust_store.is_attestation_used("causal_att_single_01"))

        # First consumption succeeds
        self.trust_store.record_used_attestation("causal_att_single_01")
        self.assertTrue(self.trust_store.is_attestation_used("causal_att_single_01"))

        # Second consumption in same process fails closed
        with self.assertRaises(ValueError) as ctx:
            self.trust_store.record_used_attestation("causal_att_single_01")
        self.assertIn("replay of causal attestation id", str(ctx.exception).lower())

        # Second process loading fresh from disk also rejects
        store2 = DurableTrustStore(self.store_path)
        self.assertTrue(store2.is_attestation_used("causal_att_single_01"))
        with self.assertRaises(ValueError) as ctx2:
            store2.record_used_attestation("causal_att_single_01")
        self.assertIn("replay of causal attestation id", str(ctx2.exception).lower())

    # 2. Operation IDs lifecycle and cross-session/cross-PID rejection
    def test_02_operation_id_lifecycle_and_cross_session_rejection(self):
        self.assertFalse(self.trust_store.is_operation_used("op_task_01"))

        # Record operation
        self.trust_store.record_used_operation(
            op_id="op_task_01",
            session_id=self.session_id,
            pid=self.pid,
            metadata={"field": "queue.length", "value": 42},
        )
        self.assertTrue(self.trust_store.is_operation_used("op_task_01"))
        op_info = self.trust_store.used_operation_ids["op_task_01"]
        self.assertEqual(op_info["session_id"], self.session_id)
        self.assertEqual(op_info["pid"], self.pid)
        self.assertEqual(op_info["field"], "queue.length")
        self.assertIn("recorded_at", op_info)

        # Attempt to replay across different session
        with self.assertRaises(ValueError) as ctx_sess:
            self.trust_store.record_used_operation(
                op_id="op_task_01",
                session_id="other_session_999",
                pid=self.pid,
            )
        self.assertIn("replay across sessions", str(ctx_sess.exception).lower())

        # Attempt to replay across different PID
        with self.assertRaises(ValueError) as ctx_pid:
            self.trust_store.record_used_operation(
                op_id="op_task_01",
                session_id=self.session_id,
                pid=9999,
            )
        self.assertIn("replay across pids", str(ctx_pid.exception).lower())

        # Duplicate attempt with same session and PID fails as already committed
        with self.assertRaises(ValueError) as ctx_dup:
            self.trust_store.record_used_operation(
                op_id="op_task_01",
                session_id=self.session_id,
                pid=self.pid,
            )
        self.assertIn("already committed and single-use", str(ctx_dup.exception).lower())

    # 3. Receipt-to-operation cardinality (1:1 binding)
    def test_03_receipt_to_operation_cardinality(self):
        self.trust_store.register_key("k1", "sec_card", is_active=True)
        rcpt1 = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_ident["process_identity"],
            executable_identity=self.target_ident["executable_identity"],
            build_id=self.target_ident["build_id"],
            snapshot_binding=f"snap:{self.pid}",
            operation_id="ctx_op_card_01",
            capture_authority_token=get_trusted_capture_authority_token(),
            secret="sec_card",
            key_id="k1",
        )
        rcpt2 = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_ident["process_identity"],
            executable_identity=self.target_ident["executable_identity"],
            build_id=self.target_ident["build_id"],
            snapshot_binding=f"snap:{self.pid}",
            operation_id="ctx_op_card_01",  # Same op_id!
            capture_authority_token=get_trusted_capture_authority_token(),
            secret="sec_card",
            key_id="k1",
        )
        self.assertNotEqual(rcpt1.receipt_id, rcpt2.receipt_id)

        ledger = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rec1 = EvidenceRecord(
            evidence_id="ev_card_01",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Obs 1",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt1.to_dict()},
            target_identity=dict(self.target_ident),
            details={"operation_id": "ctx_op_card_01"},
            session_id=self.session_id,
        )
        ledger.add_record(rec1)
        self.assertEqual(ledger._operation_to_receipt_id["ctx_op_card_01"], rcpt1.receipt_id)

        # Record 2 claims the same operation_id but carries rcpt2 -> Must be rejected!
        rec2 = EvidenceRecord(
            evidence_id="ev_card_02",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Obs 2 conflicting receipt",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt2.to_dict()},
            target_identity=dict(self.target_ident),
            details={"operation_id": "ctx_op_card_01"},
            session_id=self.session_id,
        )
        with self.assertRaises(ValueError) as ctx:
            ledger.add_record(rec2)
        self.assertIn("receipt-to-operation conflict", str(ctx.exception).lower())

    # 4. Atomic replay acceptance (persistence failure aborts trust acceptance)
    def test_04_persistence_failure_aborts_trust_acceptance(self):
        store = DurableTrustStore(self.store_path)
        store.register_key("k1", "sec_atomic")

        # Simulate save() raising an OSError (e.g. disk full or permission error)
        with patch.object(store, "save", side_effect=RuntimeError("Simulated disk I/O failure")):
            with self.assertRaises(RuntimeError):
                store.record_used_attestation("att_should_abort")

        # Verify that att_should_abort was NOT durably registered
        store_recovered = DurableTrustStore(self.store_path)
        self.assertFalse(store_recovered.is_attestation_used("att_should_abort"))

    # 5. Concurrent replay attempts result in exactly one successful acceptance
    def test_05_concurrent_replay_attempts_single_success(self):
        store = DurableTrustStore(self.store_path)
        store.register_key("k1", "sec_race")
        target_att_id = "causal_att_race_target"

        success_count = 0
        failure_count = 0

        def try_consume():
            local_store = DurableTrustStore(self.store_path)
            try:
                local_store.record_used_attestation(target_att_id)
                return True
            except ValueError:
                return False

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(try_consume) for _ in range(10)]
            results = [f.result() for f in futures]

        success_count = sum(1 for r in results if r is True)
        failure_count = sum(1 for r in results if r is False)

        self.assertEqual(success_count, 1)
        self.assertEqual(failure_count, 9)
        self.assertTrue(store.is_attestation_used(target_att_id))


if __name__ == "__main__":
    unittest.main()
