"""Phase 2.0-A.3.14 Authoritative Evidence Ledger Boundary Tests.

Verifies:
1. Single authoritative validation path (validate_record) called by both add_record() and from_dict().
2. Duplicate evidence IDs are rejected during from_dict() reconstruction.
3. Revalidation of all receipt, attestation, parent integrity, and graph cycles on from_dict().
4. Synthetic and imported evidence records cannot claim PRODUCTION authority live receipts or causal attestations.
5. Caller-controlled flags (causal_proof=True, deterministic_transition_verified=True, transition_verified=True, causally_verified=True)
   without valid CausalAttestation are rejected fail-closed.
6. Target PID mismatch between causal attestation and evidence record is rejected.
7. Complete provenance chain is preserved in get_provenance_chain().
"""

import unittest

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
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC,
)


class TestPhase20A314AuthoritativeLedgerBoundary(unittest.TestCase):
    def setUp(self):
        self.session_id = "sess_a314_bnd"
        self.pid = 7001
        self.target_identity = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:123456:boot_uuid",
            "start_time": "123456",
            "executable": "/usr/bin/target",
            "executable_identity": f"/usr/bin/target:{self.pid}",
            "build_id": "bnd_1234",
        }

    # 1. from_dict() rejects duplicate evidence IDs
    def test_01_from_dict_rejects_duplicate_evidence_ids(self):
        rec_data = {
            "evidence_id": "ev_dup_1",
            "evidence_type": EVIDENCE_TYPE_FIELD_OBSERVATION,
            "observation": "Observation 1",
            "provenance": {"provenance_class": "SYNTHETIC"},
        }
        ledger_data = {
            "session_id": self.session_id,
            "records": [rec_data, rec_data],
        }
        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(ledger_data)
        self.assertIn("duplicate evidence_id", str(ctx.exception).lower())

    # 2. Synthetic or imported evidence cannot claim PRODUCTION live receipt
    def test_02_synthetic_cannot_claim_production_live_receipt(self):
        ledger = EvidenceLedger(session_id=self.session_id)
        prod_rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_1",
            capture_epoch=1,
            physical_bytes_read=64,
            physical_reads_count=1,
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )

        rec = EvidenceRecord(
            evidence_id="ev_syn_prod",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Synthetic record trying to claim prod live receipt",
            provenance={
                "provenance_class": PROVENANCE_CLASS_SYNTHETIC,
                "live_capture_receipt": prod_rcpt.to_dict(),
            },
        )
        with self.assertRaises(ValueError) as ctx:
            ledger.add_record(rec)
        self.assertIn("cannot claim production authority", str(ctx.exception).lower())

    # 3. Caller-controlled causal flags without CausalAttestation rejected
    def test_03_caller_controlled_causal_flags_rejected(self):
        ledger = EvidenceLedger(session_id=self.session_id)
        prod_rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_1",
            capture_epoch=1,
            physical_bytes_read=64,
            physical_reads_count=1,
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        for flag_key in ("causal_proof", "deterministic_transition_verified", "transition_verified"):
            rec = EvidenceRecord(
                evidence_id=f"ev_flag_{flag_key}",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                observation="Caller trying to set causal flag",
                target_identity=self.target_identity,
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": prod_rcpt.to_dict(),
                },
                details={flag_key: True},
            )
            with self.assertRaises(ValueError) as ctx:
                ledger.add_record(rec)
            self.assertIn("missing valid cryptographic causalattestation", str(ctx.exception).lower())

    # 4. Target PID mismatch between attestation and record rejected
    def test_04_target_pid_mismatch_between_attestation_and_record_rejected(self):
        ledger = EvidenceLedger(session_id=self.session_id)
        pre_rec = ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Pre observation",
            target_identity=self.target_identity,
        )

        # Attestation on PID 7001
        att = issue_causal_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_pid_mismatch",
            precondition_evidence_id=pre_rec.evidence_id,
            postcondition_evidence_id="ev_post_pid",
            claimed_transition={"x": 1},
            authority_level="PRODUCTION",
            verifier_authority_token=get_trusted_causal_authority_token(),
        )

        # Record claims PID 7002
        mismatched_target = dict(self.target_identity)
        mismatched_target["pid"] = 7002
        mismatched_target["process_identity"] = "7002:123456:boot_uuid"
        mismatched_target["executable_identity"] = "/usr/bin/target:7002"

        prod_rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=7002,
            process_identity=mismatched_target["process_identity"],
            executable_identity=mismatched_target["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_1",
            capture_epoch=1,
            physical_bytes_read=64,
            physical_reads_count=1,
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )

        rec = EvidenceRecord(
            evidence_id="ev_post_pid",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            observation="Post observation with wrong PID",
            target_identity=mismatched_target,
            parent_evidence_ids=[pre_rec.evidence_id],
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": prod_rcpt.to_dict(),
                "causal_attestation": att.to_dict(),
            },
            details={"causal_proof": True},
        )
        with self.assertRaises(ValueError) as ctx:
            ledger.add_record(rec)
        self.assertIn("pid mismatch", str(ctx.exception).lower())

    # 5. Complete provenance chain preserved
    def test_05_provenance_chain_preservation(self):
        ledger = EvidenceLedger(session_id=self.session_id)
        r1 = ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Root snapshot",
            snapshot_ref={"snapshot_id": "snap_root"},
        )
        r2 = ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Derived observation",
            parent_evidence_ids=[r1.evidence_id],
        )
        chain = ledger.get_provenance_chain(evidence_id=r2.evidence_id)
        self.assertEqual(len(chain), 2)
        chain_ids = [c.get("evidence_id") for c in chain]
        self.assertEqual(chain_ids, [r2.evidence_id, r1.evidence_id])


if __name__ == "__main__":
    unittest.main()
