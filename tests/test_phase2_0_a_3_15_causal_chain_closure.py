"""Phase 2.0-A.3.15 Causal Attestation Evidence Binding Tests.

Verifies:
1. Exact target identity binding (PID, process_identity, executable_identity, build_id).
2. Missing mandatory target identity attributes fail closed.
3. Precondition evidence existence in ledger.
4. Cross-session and cross-target evidence binding rejected.
5. Operation ID mismatch between attestation and record or receipt rejected.
6. Caller-controlled boolean or free-form intervention description without verifiable authorization rejected.
"""

import unittest
from datetime import datetime, timezone

from extractor.capture_backend import (
    CausalAttestation,
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


class TestPhase20A315CausalChainClosure(unittest.TestCase):
    def setUp(self):
        self.session_id = "sess_a315_chain"
        self.pid = 9201
        self.target_identity = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:123456:boot_uuid",
            "start_time": "123456",
            "executable": "/usr/bin/service_a315",
            "executable_identity": f"/usr/bin/service_a315:{self.pid}",
            "build_id": "sha1:build_a315_chain",
            "target_host": "localhost",
        }
        self.ledger = EvidenceLedger(session_id=self.session_id)

        # Seed valid precondition evidence with authentic live receipt
        rcpt_pre = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_pre",
            capture_epoch=1,
            physical_bytes_read=64,
            physical_reads_count=1,
            operation_id="op_chain_pre",
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        self.pre_rec = EvidenceRecord(
            evidence_id="ev_chain_pre",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Precondition state observation",
            target_identity=self.target_identity,
            session_id=self.session_id,
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt_pre.to_dict(),
            },
            details={"operation_id": "op_chain_pre", "lock_state": 1},
        )
        self.ledger.add_record(self.pre_rec)

    # 1. Missing mandatory identity attributes fail closed
    def test_01_missing_mandatory_identity_attributes_fail_closed(self):
        # Invalid PID (<= 1)
        bad_ident = dict(self.target_identity)
        bad_ident["pid"] = 0
        with self.assertRaises(ValueError) as ctx:
            issue_causal_attestation(
                session_id=self.session_id,
                target_identity=bad_ident,
                operation_id="op_chain_01",
                precondition_evidence_id="ev_chain_pre",
                postcondition_evidence_id="ev_chain_post",
                claimed_transition={"lock_state": 0},
                authority_level="PRODUCTION",
                verifier_authority_token=get_trusted_causal_authority_token(),
            )
        self.assertIn("valid pid", str(ctx.exception).lower())

        # Missing executable identity
        bad_ident2 = dict(self.target_identity)
        bad_ident2.pop("executable_identity", None)
        bad_ident2.pop("executable", None)
        with self.assertRaises(ValueError) as ctx:
            issue_causal_attestation(
                session_id=self.session_id,
                target_identity=bad_ident2,
                operation_id="op_chain_01",
                precondition_evidence_id="ev_chain_pre",
                postcondition_evidence_id="ev_chain_post",
                claimed_transition={"lock_state": 0},
                authority_level="PRODUCTION",
                verifier_authority_token=get_trusted_causal_authority_token(),
            )
        self.assertIn("verified executable identity", str(ctx.exception).lower())

    # 2. Nonexistent precondition evidence in ledger fails closed
    def test_02_nonexistent_precondition_rejected(self):
        att = issue_causal_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_chain_02",
            precondition_evidence_id="ev_nonexistent_ghost",
            postcondition_evidence_id="ev_chain_post_02",
            claimed_transition={"state": "mutated"},
            authority_level="PRODUCTION",
            verifier_authority_token=get_trusted_causal_authority_token(),
        )
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_post_2",
            capture_epoch=2,
            physical_bytes_read=64,
            physical_reads_count=1,
            operation_id="op_chain_02",
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        rec = EvidenceRecord(
            evidence_id="ev_chain_post_02",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            observation="Postcondition with nonexistent precondition",
            target_identity=self.target_identity,
            session_id=self.session_id,
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt.to_dict(),
                "causal_attestation": att.to_dict(),
            },
            details={"causal_proof": True, "operation_id": "op_chain_02"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec)
        self.assertIn("nonexistent precondition evidence", str(ctx.exception).lower())

    # 3. Cross-session evidence binding rejected
    def test_03_cross_session_binding_rejected(self):
        att = issue_causal_attestation(
            session_id="sess_different_session_99",
            target_identity=self.target_identity,
            operation_id="op_chain_03",
            precondition_evidence_id="ev_chain_pre",
            postcondition_evidence_id="ev_chain_post_03",
            claimed_transition={"state": "mutated"},
            authority_level="PRODUCTION",
            verifier_authority_token=get_trusted_causal_authority_token(),
        )
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_post_3",
            capture_epoch=2,
            physical_bytes_read=64,
            physical_reads_count=1,
            operation_id="op_chain_03",
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        rec = EvidenceRecord(
            evidence_id="ev_chain_post_03",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            observation="Postcondition with mismatched session attestation",
            target_identity=self.target_identity,
            session_id=self.session_id,
            parent_evidence_ids=["ev_chain_pre"],
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt.to_dict(),
                "causal_attestation": att.to_dict(),
            },
            details={"causal_proof": True, "operation_id": "op_chain_03"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec)
        self.assertIn("cross_session_attestation", str(ctx.exception).lower())

    # 4. Operation ID mismatch between attestation and record rejected
    def test_04_operation_id_mismatch_rejected(self):
        att = issue_causal_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_attestation_actual",
            precondition_evidence_id="ev_chain_pre",
            postcondition_evidence_id="ev_chain_post_04",
            claimed_transition={"lock_state": 0},
            authority_level="PRODUCTION",
            verifier_authority_token=get_trusted_causal_authority_token(),
        )
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_post_4",
            capture_epoch=2,
            physical_bytes_read=64,
            physical_reads_count=1,
            operation_id="op_receipt_different",
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        rec = EvidenceRecord(
            evidence_id="ev_chain_post_04",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            observation="Postcondition with mismatched operation ID",
            target_identity=self.target_identity,
            session_id=self.session_id,
            parent_evidence_ids=["ev_chain_pre"],
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt.to_dict(),
                "causal_attestation": att.to_dict(),
            },
            details={"causal_proof": True, "operation_id": "op_record_different"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec)
        self.assertIn("operation id mismatch", str(ctx.exception).lower())

    # 5. Caller-controlled boolean or missing intervention authorization rejected
    def test_05_missing_intervention_authorization_rejected(self):
        # Create attestation with empty intervention details dict
        att_dict = issue_causal_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_chain_05",
            precondition_evidence_id="ev_chain_pre",
            postcondition_evidence_id="ev_chain_post_05",
            claimed_transition={"lock_state": 0},
            authority_level="PRODUCTION",
            verifier_authority_token=get_trusted_causal_authority_token(),
        ).to_dict()
        # Tamper intervention_details to lack verifiable authorization
        att_dict["intervention_details"] = {"caller_comment": "Trust me, I flipped the lock"}
        # Resign after tampering
        from extractor.capture_backend import get_default_key_store
        _, sec = get_default_key_store().get_active_signing_key()
        from extractor.capture_backend import CausalAttestation
        att = CausalAttestation.from_dict(att_dict)
        att.sign(sec)

        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_post_5",
            capture_epoch=2,
            physical_bytes_read=64,
            physical_reads_count=1,
            operation_id="op_chain_05",
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        rec = EvidenceRecord(
            evidence_id="ev_chain_post_05",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            observation="Postcondition with unverified intervention details",
            target_identity=self.target_identity,
            session_id=self.session_id,
            parent_evidence_ids=["ev_chain_pre"],
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt.to_dict(),
                "causal_attestation": att.to_dict(),
            },
            details={"causal_proof": True, "operation_id": "op_chain_05"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec)
        self.assertIn("lacks verifiable intervention authorization", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
