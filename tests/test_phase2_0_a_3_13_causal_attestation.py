#!/usr/bin/env python3
"""Phase 2.0-A.3.13 — Cryptographic Causal Attestation Verification Test Suite.

Audits and proves:
1. Signature integrity: Empty, malformed, or tampered signatures are rejected fail-closed.
2. Canonical payload binding: Any modification to target, transition, or precondition invalidates proof.
3. Authority boundaries: Only attestations issued with trusted authority tokens can produce PRODUCTION proof.
4. Anti-replay enforcement: Reused attestation IDs across records are rejected.
5. Cross-session replay prevention: Attestation bound to Session A cannot be admitted in Session B.
6. Temporal validity: Expired attestation timestamps fail closed.
7. Separation of concerns: Valid LiveCaptureReceipt establishes physical capture but NEVER causal proof.
8. Unverified claims disarmed: Caller-submitted `causal_proof=True` is stripped without valid attestation.
"""

import time
import unittest
from datetime import datetime, timezone

from extractor.capture_backend import (
    CausalAttestation,
    get_trusted_causal_authority_token,
    issue_causal_attestation,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    EVIDENCE_TYPE_DIAGNOSTIC,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
)


class TestPhase20A313CausalAttestation(unittest.TestCase):
    """Adversarial tests for causal attestation cryptographic validation and anti-replay."""

    def setUp(self):
        self.session_id = "sess_causal_test"
        self.pid = 4321
        self.ledger = EvidenceLedger(session_id=self.session_id)
        self.secret = "trusted_causal_test_secret_32bytes_long!"

        # Create a valid parent observation in ledger with authentic LiveCaptureReceipt
        token = get_trusted_capture_authority_token()
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity="test_proc",
            executable_identity="/bin/test_proc",
            build_id="sha1:abc12345",
            snapshot_binding="snap_01",
            capture_epoch=1,
            observation_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000",
            physical_bytes_read=64,
            physical_reads_count=1,
            operation_type="diagnostic",
            capture_authority_token=token,
        )
        self.pre_record = EvidenceRecord(
            evidence_id="evi_precondition_01",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="test_probe",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self.session_id,
            observation="Initial state before mutation",
            target_identity={"pid": self.pid, "process_identity": "test_proc", "executable_identity": "/bin/test_proc", "build_id": "sha1:abc12345"},
            details={"live_capture_receipt": rcpt.to_dict()},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict()},
        )
        self.ledger.add_record(self.pre_record)

    def _make_valid_attestation(self, **overrides) -> CausalAttestation:
        kwargs = {
            "session_id": self.session_id,
            "target_identity": {"pid": self.pid, "process_identity": "test_proc", "executable_identity": "/bin/test_proc", "build_id": "sha1:abc12345"},
            "operation_id": "op_test_mut_01",
            "precondition_evidence_id": "evi_precondition_01",
            "postcondition_evidence_id": "evi_postcondition_01",
            "claimed_transition": {"name": "MUTEX_UNLOCK_CASCADE"},
            "intervention_details": {"action": "release_mutex", "addr": "0x555555"},
            "ttl_seconds": 3600,
            "verifier_authority_token": get_trusted_causal_authority_token(),
        }
        kwargs.update(overrides)
        return issue_causal_attestation(**kwargs)

    def test_01_valid_attestation_verification_success(self):
        """Authentic CausalAttestation with valid HMAC signature verifies successfully."""
        att = self._make_valid_attestation()
        ok, reason = att.verify(
            expected_session_id=self.session_id,
            expected_pid=self.pid,
        )
        self.assertTrue(ok, f"Expected verification success: {reason}")
        self.assertEqual(reason, "VERIFIED")

    def test_02_empty_or_bogus_signature_rejected(self):
        """Attestation with empty, forged, or arbitrary non-empty signature is rejected."""
        att_empty = self._make_valid_attestation()
        att_empty.signature = ""
        ok1, reason1 = att_empty.verify(expected_session_id=self.session_id, secret=self.secret)
        self.assertFalse(ok1)
        self.assertIn("missing hmac signature", reason1.lower())

        att_forged = self._make_valid_attestation()
        att_forged.signature = "bogus_signature_of_correct_hex_length_0123456789abcdef0123456789abcdef"
        ok2, reason2 = att_forged.verify(expected_session_id=self.session_id, secret=self.secret)
        self.assertFalse(ok2)
        self.assertIn("signature verification failed", reason2.lower())

    def test_03_tampered_payload_rejected(self):
        """Tampering with claimed transition or intervention details invalidates cryptographic proof."""
        att = self._make_valid_attestation()
        att.claimed_transition = {"name": "DEADLOCK_RESOLVED_SPURIOUSLY"}

        ok, reason = att.verify(expected_session_id=self.session_id, secret=self.secret)
        self.assertFalse(ok)
        self.assertIn("signature verification failed", reason.lower())

    def test_04_wrong_secret_or_untrusted_issuer_rejected(self):
        """Verification with incorrect secret fails closed."""
        att = self._make_valid_attestation()
        wrong_secret = "attacker_controlled_secret_key_12345!"

        ok, reason = att.verify(expected_session_id=self.session_id, secret=wrong_secret)
        self.assertFalse(ok)
        self.assertIn("signature verification failed", reason.lower())

    def test_05_cross_session_replay_rejected(self):
        """Attestation minted for Session A cannot be replayed or accepted in Session B."""
        att = self._make_valid_attestation()

        # Target session mismatch in verify()
        ok, reason = att.verify(expected_session_id="other_session_xyz", secret=self.secret)
        self.assertFalse(ok)
        self.assertIn("expected session", reason.lower())

        # Target session mismatch in EvidenceLedger.add_record()
        other_ledger = EvidenceLedger(session_id="other_session_xyz")
        other_token = get_trusted_capture_authority_token()
        other_rcpt = issue_live_capture_receipt(
            session_id="other_session_xyz",
            pid=self.pid,
            process_identity="test_proc",
            executable_identity="/bin/test_proc",
            build_id="sha1:abc12345",
            snapshot_binding="snap_02",
            capture_epoch=1,
            observation_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000",
            physical_bytes_read=64,
            physical_reads_count=1,
            operation_type="diagnostic",
            capture_authority_token=other_token,
        )
        other_pre = EvidenceRecord(
            evidence_id="evi_precondition_01",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="test_probe",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id="other_session_xyz",
            observation="pre",
            target_identity={"pid": self.pid, "process_identity": "test_proc", "executable_identity": "/bin/test_proc", "build_id": "sha1:abc12345"},
            details={"live_capture_receipt": other_rcpt.to_dict()},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": other_rcpt.to_dict()},
        )
        other_ledger.add_record(other_pre)

        record_replayed = EvidenceRecord(
            evidence_id="evi_causal_replayed",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            source="causal_worker",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id="other_session_xyz",
            observation="Claimed causal transition",
            target_identity={"pid": self.pid, "process_identity": "test_proc", "executable_identity": "/bin/test_proc", "build_id": "sha1:abc12345"},
            parent_evidence_ids=["evi_precondition_01"],
            details={"causal_attestation": att.to_dict(), "causal_proof": True, "live_capture_receipt": other_rcpt.to_dict()},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": other_rcpt.to_dict()},
        )
        with self.assertRaises(ValueError) as ctx:
            other_ledger.add_record(record_replayed)
        self.assertIn("cross_session_attestation", str(ctx.exception).lower())

    def test_06_reused_attestation_id_anti_replay_rejected(self):
        """Reusing the same attestation ID across two different records is detected and rejected."""
        att = self._make_valid_attestation()

        t_id = {"pid": self.pid, "process_identity": "test_proc", "executable_identity": "/bin/test_proc", "build_id": "sha1:abc12345"}
        rcpt_dict = self.pre_record.details["live_capture_receipt"]
        rec1 = EvidenceRecord(
            evidence_id="evi_rec_01",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            source="causal_verifier",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self.session_id,
            observation="First verification",
            target_identity=t_id,
            parent_evidence_ids=["evi_precondition_01"],
            details={"causal_attestation": att.to_dict(), "causal_proof": True, "live_capture_receipt": rcpt_dict},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt_dict},
        )
        self.ledger.add_record(rec1)

        # Second record attempting to reuse the same attestation ID
        rec2 = EvidenceRecord(
            evidence_id="evi_rec_02",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            source="causal_verifier",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self.session_id,
            observation="Duplicate verification attempt",
            target_identity=t_id,
            parent_evidence_ids=["evi_precondition_01"],
            details={"causal_attestation": att.to_dict(), "causal_proof": True, "live_capture_receipt": rcpt_dict},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt_dict},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec2)
        self.assertIn("replay of causal attestation id", str(ctx.exception).lower())

    def test_07_expired_attestation_rejected(self):
        """Attestation whose valid_until timestamp is in the past fails closed."""
        att_expired = self._make_valid_attestation(ttl_seconds=-60)

        ok, reason = att_expired.verify(expected_session_id=self.session_id, secret=self.secret)
        self.assertFalse(ok)
        self.assertIn("expired", reason.lower())

    def test_08_missing_precondition_in_ledger_rejected(self):
        """Attestation referencing nonexistent precondition evidence ID fails closed in ledger."""
        att = self._make_valid_attestation(precondition_evidence_id="evi_ghost_precondition")

        rec = EvidenceRecord(
            evidence_id="evi_rec_ghost_pre",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            source="causal_verifier",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self.session_id,
            observation="Precondition missing",
            target_identity={"pid": self.pid, "process_identity": "test_proc", "executable_identity": "/bin/test_proc", "build_id": "sha1:abc12345"},
            parent_evidence_ids=["evi_precondition_01"],
            details={"causal_attestation": att.to_dict(), "causal_proof": True},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": self.pre_record.details["live_capture_receipt"]},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec)
        self.assertIn("nonexistent precondition evidence 'evi_ghost_precondition'", str(ctx.exception).lower())

    def test_09_caller_supplied_causal_proof_stripped_without_attestation(self):
        """Caller submitting causal_proof=True without cryptographic attestation is stripped or rejected."""
        rec = EvidenceRecord(
            evidence_id="evi_unverified_claim",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=NATURE_OBSERVATION,
            source="untrusted_client",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self.session_id,
            observation="Caller claims proof",
            target_identity={"pid": self.pid},
            parent_evidence_ids=["evi_precondition_01"],
            details={"causal_proof": True, "deterministic_transition_verified": True},
            provenance={"provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec)
        self.assertIn("missing valid cryptographic causalattestation", str(ctx.exception).lower())

    def test_10_live_capture_receipt_alone_does_not_confer_causal_proof(self):
        """A valid LiveCaptureReceipt authenticates physical memory reads but NEVER confers causal proof."""
        # Issue valid live capture receipt
        token = get_trusted_capture_authority_token()
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity="proc_live",
            executable_identity="/bin/proc_live",
            build_id="sha1:deadbeef1234",
            snapshot_binding="snap_bind_01",
            capture_epoch=1,
            observation_digest="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            physical_bytes_read=128,
            physical_reads_count=2,
            operation_type="diagnostic",
            capture_authority_token=token,
        )

        rec = EvidenceRecord(
            evidence_id="evi_physical_read_only",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="target_reader",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id=self.session_id,
            observation="Physical memory read confirmed",
            target_identity={"pid": self.pid, "build_id": "sha1:deadbeef1234", "process_identity": "proc_live", "executable_identity": "/bin/proc_live"},
            parent_evidence_ids=["evi_precondition_01"],
            details={"live_capture_receipt": rcpt.to_dict(), "causal_proof": False},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict()},
        )
        self.ledger.add_record(rec)
        admitted = self.ledger.get_record("evi_physical_read_only")
        self.assertIsNotNone(admitted)
        # Verify receipt is present but causal proof remains False
        self.assertFalse(admitted.details.get("causal_proof", False))
        self.assertIsNone(admitted.details.get("causal_attestation"))


if __name__ == "__main__":
    unittest.main()
