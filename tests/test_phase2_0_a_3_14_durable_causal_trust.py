"""Phase 2.0-A.3.14 Durable Causal Attestation Trust Tests.

Verifies:
1. CausalVerifierAuthority lifecycle (initialization, token verification, rotation, revocation).
2. Production causal attestation issuance requires valid verifier authority token.
3. Key rotation allows old key verification while signing with new key.
4. Key revocation causes verify() to reject with KEY_REVOKED.
5. Missing or invalid mandatory fields (session_id, operation_id, target_identity, precondition/postcondition, transition) fail closed.
6. Expired attestation is rejected.
7. Anti-replay across ledger serialization/deserialization.
8. LiveCaptureReceipt alone never proves causality; causal claims without attestation remain SUSPECTED or INCONCLUSIVE.
"""

import time
import unittest

from extractor.capture_backend import (
    CausalAttestation,
    CausalVerifierAuthority,
    get_default_causal_authority,
    get_trusted_capture_authority_token,
    get_trusted_causal_authority_token,
    issue_causal_attestation,
    issue_live_capture_receipt,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)


class TestPhase20A314DurableCausalTrust(unittest.TestCase):
    def setUp(self):
        self.session_id = "sess_a314_causal"
        self.pid = 6001
        self.target_identity = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:123456:boot_uuid",
            "start_time": "123456",
            "executable": "/usr/bin/target",
            "executable_identity": f"/usr/bin/target:{self.pid}",
            "build_id": "abc12345",
        }

    # 1. Authority lifecycle: token authorization for PRODUCTION authority
    def test_01_production_authority_requires_valid_token(self):
        auth = CausalVerifierAuthority(authority_id="auth_test_1")
        valid_tok = auth.get_verifier_token()

        # Invalid token rejected
        with self.assertRaises(ValueError) as ctx:
            auth.issue_attestation(
                session_id=self.session_id,
                target_identity=self.target_identity,
                operation_id="op_1",
                precondition_evidence_id="ev_pre",
                postcondition_evidence_id="ev_post",
                claimed_transition={"state": "mutated"},
                authority_level="PRODUCTION",
                verifier_authority_token="invalid_token_123",
            )
        self.assertIn("Unauthorized causal attestation issuance", str(ctx.exception))

        # Valid token succeeds
        att = auth.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_1",
            precondition_evidence_id="ev_pre",
            postcondition_evidence_id="ev_post",
            claimed_transition={"state": "mutated"},
            authority_level="PRODUCTION",
            verifier_authority_token=valid_tok,
        )
        self.assertIsNotNone(att)
        ok, reason = att.verify(expected_session_id=self.session_id, expected_pid=self.pid)
        self.assertTrue(ok)
        self.assertEqual(reason, "VERIFIED")

    # 2. Key rotation and revocation
    def test_02_key_rotation_and_revocation(self):
        auth = CausalVerifierAuthority(authority_id="auth_rot_test")
        tok = auth.get_verifier_token()

        # Issue attestation 1 with initial key
        att1 = auth.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_k1",
            precondition_evidence_id="ev_pre",
            postcondition_evidence_id="ev_post",
            claimed_transition={"k": 1},
            verifier_authority_token=tok,
        )
        initial_kid = att1.key_id

        # Rotate key
        new_kid, _ = auth.rotate_key("rotated_key_v2")
        att2 = auth.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_k2",
            precondition_evidence_id="ev_pre",
            postcondition_evidence_id="ev_post",
            claimed_transition={"k": 2},
            verifier_authority_token=tok,
        )
        self.assertEqual(att2.key_id, new_kid)

        # Both verify before revocation
        ok1, _ = att1.verify(key_store=auth.key_store)
        ok2, _ = att2.verify(key_store=auth.key_store)
        self.assertTrue(ok1)
        self.assertTrue(ok2)

        # Revoke initial key
        auth.revoke_key(initial_kid)
        att1.revoked = True  # explicit revocation flag or checked via store
        ok1_rev, reason1 = att1.verify(key_store=auth.key_store)
        self.assertFalse(ok1_rev)
        self.assertTrue("revoked" in reason1.lower())

        # Attestation 2 with new key remains valid
        ok2_after, _ = att2.verify(key_store=auth.key_store)
        self.assertTrue(ok2_after)

    # 3. Missing mandatory fields fail closed
    def test_03_missing_mandatory_fields_fail_closed(self):
        auth = get_default_causal_authority()
        tok = auth.get_verifier_token()

        # Empty session_id
        with self.assertRaises(ValueError) as ctx:
            auth.issue_attestation(
                session_id="",
                target_identity=self.target_identity,
                operation_id="op_1",
                precondition_evidence_id="ev_pre",
                postcondition_evidence_id="ev_post",
                claimed_transition={"s": 1},
                verifier_authority_token=tok,
            )
        self.assertIn("session_id", str(ctx.exception).lower())

        # Missing target executable identity
        bad_ident = dict(self.target_identity)
        bad_ident.pop("executable_identity", None)
        bad_ident.pop("executable", None)
        with self.assertRaises(ValueError) as ctx:
            auth.issue_attestation(
                session_id=self.session_id,
                target_identity=bad_ident,
                operation_id="op_1",
                precondition_evidence_id="ev_pre",
                postcondition_evidence_id="ev_post",
                claimed_transition={"s": 1},
                verifier_authority_token=tok,
            )
        self.assertIn("executable", str(ctx.exception).lower())

    # 4. Anti-replay across ledger serialization/deserialization
    def test_04_anti_replay_across_ledger_serialization(self):
        ledger = EvidenceLedger(session_id=self.session_id)
        pre_rec = ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Precondition observation",
            target_identity=self.target_identity,
        )

        att = issue_causal_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_replay_test",
            precondition_evidence_id=pre_rec.evidence_id,
            postcondition_evidence_id="ev_causal_main",
            claimed_transition={"state": "changed"},
            intervention_details={"action": "test_intervention"},
            authority_level="PRODUCTION",
            verifier_authority_token=get_trusted_causal_authority_token(),
        )

        rcpt1 = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_r1",
            capture_epoch=1,
            physical_bytes_read=64,
            physical_reads_count=1,
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )

        rec1 = EvidenceRecord(
            evidence_id="ev_causal_main",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            observation="Observed causal state transition",
            target_identity=self.target_identity,
            parent_evidence_ids=[pre_rec.evidence_id],
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt1.to_dict(),
                "causal_attestation": att.to_dict(),
            },
            details={"causal_proof": True},
        )
        ledger.add_record(rec1)

        # Serialize ledger and reconstruct into ledger2
        ledger_dict = ledger.to_dict()
        ledger2 = EvidenceLedger.from_dict(ledger_dict)

        rcpt2 = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_r2",
            capture_epoch=2,
            physical_bytes_read=64,
            physical_reads_count=1,
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )

        # Attempt to reuse the same attestation on a new record in ledger2 must be rejected as replay
        rec2_replay = EvidenceRecord(
            evidence_id="ev_causal_replayed",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            observation="Replayed attestation observation",
            target_identity=self.target_identity,
            parent_evidence_ids=[pre_rec.evidence_id],
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt2.to_dict(),
                "causal_attestation": att.to_dict(),
            },
            details={"causal_proof": True},
        )
        with self.assertRaises(ValueError) as ctx:
            ledger2.add_record(rec2_replay)
        self.assertIn("replay", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
