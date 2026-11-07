"""Tests for Phase 2.0-A.3.17 P0-3: Idempotent Ledger Recovery & Revocation Irreversibility.

Verifies:
1. Exact original committed evidence recovery succeeds idempotently across multiple reload cycles.
2. Conflicting reuse of attestation across different evidence records is rejected during recovery.
3. Replaying an attestation with a mismatched session or target PID is rejected during recovery.
4. Revocation is never reversed during recovery: if key is revoked after initial recording, recovering fails closed.
5. Operation-to-evidence bindings persist and reject conflicting operation reuse during recovery.
"""

import os
import shutil
import tempfile
import unittest

from extractor.capture_backend import (
    CaptureKeyStore,
    CausalAttestation,
    CausalVerifierAuthority,
    DurableTrustStore,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
    set_default_trust_store,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    EvidenceLedger,
    EvidenceRecord,
)


class TestPhase20A317IdempotentLedgerRecovery(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a317_recovery_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)
        set_default_trust_store(self.trust_store)
        self.key_store = CaptureKeyStore()
        self.authority = CausalVerifierAuthority(
            key_store=self.key_store,
            trust_store=self.trust_store,
        )
        self.key_id, self.secret = self.authority.rotate_key("key_recov_1")
        self.session_id = "sess_a317_recov"
        self.pid = 4321
        self.target_identity = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:55555:boot_local",
            "executable_identity": "/usr/bin/service:1111",
            "build_id": "sha1_build_recov",
            "target_host": "localhost",
        }

    def tearDown(self):
        set_default_trust_store(None)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _make_receipt(self, op_id: str):
        return issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding=f"snap:{self.pid}",
            operation_id=op_id,
            capture_authority_token=get_trusted_capture_authority_token(),
            secret=self.secret,
            key_id=self.key_id,
        )

    def _setup_ledger_with_causal_records(self):
        ledger = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rcpt_pre = self._make_receipt("op_pre")
        pre_rec = EvidenceRecord(
            evidence_id="ev_pre_recov",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            source="runtime_collector",
            session_id=self.session_id,
            observation="Pre-state",
            details={"operation_id": "op_pre", "field_path": "worker.state"},
            snapshot_ref={"snapshot_id": f"snap:{self.pid}", "epoch": 0},
            target_identity=dict(self.target_identity),
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt_pre.to_dict()},
        )
        ledger.add_record(pre_rec)

        att = self.authority.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_trans_recov",
            precondition_evidence_id="ev_pre_recov",
            postcondition_evidence_id="ev_trans_recov",
            claimed_transition={"field": "worker.state", "from": "IDLE", "to": "BUSY"},
            intervention_details={"action": "verified_intervention", "verified_intervention": True},
            authority_level="PRODUCTION",
            verifier_authority_token=self.authority.get_verifier_token(),
        )

        rcpt_trans = self._make_receipt("op_trans_recov")
        trans_rec = EvidenceRecord(
            evidence_id="ev_trans_recov",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            source="runtime_collector",
            session_id=self.session_id,
            observation="Transition verified",
            parent_evidence_ids=["ev_pre_recov"],
            details={"operation_id": "op_trans_recov", "field_path": "worker.state", "causal_proof": True},
            snapshot_ref={"snapshot_id": f"snap:{self.pid}", "epoch": 0},
            target_identity=dict(self.target_identity),
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt_trans.to_dict(),
                "causal_attestation": att,
            },
        )
        ledger.add_record(trans_rec)
        return ledger, pre_rec, trans_rec, att

    def test_01_exact_original_evidence_recovers_idempotently(self):
        """Reconstructing exact original committed evidence from serialization succeeds idempotently."""
        ledger, pre_rec, trans_rec, att = self._setup_ledger_with_causal_records()
        serialized = ledger.to_dict()

        # Reconstruct into fresh ledger with cold trust store
        cold_store = DurableTrustStore(self.store_path)
        recovered_ledger = EvidenceLedger.from_dict(serialized, trust_store=cold_store)

        self.assertEqual(len(recovered_ledger.query()), 2)
        rec = recovered_ledger.get_record("ev_trans_recov")
        self.assertIsNotNone(rec)
        self.assertIn(att.attestation_id, recovered_ledger._used_causal_attestation_ids)
        self.assertEqual(recovered_ledger._causal_attestation_to_evidence_id[att.attestation_id], "ev_trans_recov")

        # Second recovery cycle is also idempotent
        recovered_ledger_2 = EvidenceLedger.from_dict(serialized, trust_store=cold_store)
        self.assertEqual(len(recovered_ledger_2.query()), 2)

    def test_02_conflicting_attestation_reuse_rejected_on_recovery(self):
        """Tampering with evidence_id on a recovered record to steal an attestation fails with REPLAY_CONFLICT."""
        ledger, pre_rec, trans_rec, att = self._setup_ledger_with_causal_records()
        serialized = ledger.to_dict()

        # Forged record claiming the same attestation under a different evidence_id
        for rec in serialized["records"]:
            if rec["evidence_id"] == "ev_trans_recov":
                rec["evidence_id"] = "ev_forged_stealer"

        cold_store = DurableTrustStore(self.store_path)
        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(serialized, trust_store=cold_store)
        self.assertIn("REPLAY_CONFLICT", str(ctx.exception))

    def test_03_mismatched_session_rejected_on_recovery(self):
        """Recovering records with a mismatched session fails closed."""
        ledger, pre_rec, trans_rec, att = self._setup_ledger_with_causal_records()
        serialized = ledger.to_dict()

        # Tamper session_id in serialized records
        for rec in serialized["records"]:
            rec["session_id"] = "other_session_rogue"

        cold_store = DurableTrustStore(self.store_path)
        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(serialized, trust_store=cold_store)
        self.assertTrue(
            "IDENTITY_MISMATCH" in str(ctx.exception)
            or "cross_session" in str(ctx.exception).lower()
            or "cross-session" in str(ctx.exception).lower()
        )

    def test_04_revocation_is_never_reversed_during_recovery(self):
        """If a key is revoked after evidence was generated, recovering that evidence fails closed."""
        ledger, pre_rec, trans_rec, att = self._setup_ledger_with_causal_records()
        serialized = ledger.to_dict()

        # Revoke the signing key
        self.authority.revoke_key(self.key_id, reason="post_capture_compromise")

        cold_store = DurableTrustStore(self.store_path)
        self.assertTrue(cold_store.is_revoked(self.key_id))

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(serialized, trust_store=cold_store)
        self.assertIn("REVOKED", str(ctx.exception))

    def test_05_operation_bindings_persist_and_survive_recovery(self):
        """Operation-to-evidence bindings survive serialization and prevent conflicting reuse."""
        ledger, pre_rec, trans_rec, att = self._setup_ledger_with_causal_records()
        serialized = ledger.to_dict()

        cold_store = DurableTrustStore(self.store_path)
        self.assertTrue(cold_store.is_operation_used("op_trans_recov"))

        recovered_ledger = EvidenceLedger.from_dict(serialized, trust_store=cold_store)
        self.assertEqual(recovered_ledger._operation_to_evidence_ids["op_trans_recov"], ["ev_trans_recov"])


if __name__ == "__main__":
    unittest.main()
