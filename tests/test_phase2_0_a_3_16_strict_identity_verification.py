"""Phase 2.0-A.3.16 Strict Target Identity Verification Tests.

Verifies:
1. Missing mandatory identity fields are rejected fail-closed for PRODUCTION authority.
2. Expected identity fields are never silently skipped because the corresponding attestation field is absent.
3. expected_target_host is actively verified (matching, mismatch, missing in attestation).
4. Canonical signature serialization binds every target identity attribute (including target_host).
5. Tampered serialized identity attributes cause cryptographic signature failure.
6. Backward compatibility is preserved for legacy attestations without weakening production checks.
"""

import unittest
from unittest.mock import patch

from extractor.capture_backend import (
    CausalAttestation,
    CausalVerifierAuthority,
    get_default_key_store,
)


class TestPhase20A316StrictIdentityVerification(unittest.TestCase):
    def setUp(self):
        self.authority = CausalVerifierAuthority()
        self.token = self.authority.get_verifier_token()
        self.session_id = "sess_a316_id"
        self.operation_id = "ctx_a316_op_01"
        self.pid = 9101
        self.valid_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:987654:boot_uuid",
            "start_time": "987654",
            "executable": "/usr/bin/service_a316",
            "executable_identity": f"/usr/bin/service_a316:{self.pid}",
            "build_id": "sha1:build_a316_strict",
            "target_host": "cluster-node-01.local",
        }

    # 1. Missing mandatory identity attributes rejected for PRODUCTION authority
    def test_01_missing_mandatory_identity_attributes_rejected(self):
        # Missing PID
        ident_no_pid = dict(self.valid_ident)
        ident_no_pid.pop("pid")
        with self.assertRaises(ValueError) as ctx:
            self.authority.issue_attestation(
                session_id=self.session_id,
                target_identity=ident_no_pid,
                operation_id=self.operation_id,
                precondition_evidence_id="ev_pre_01",
                postcondition_evidence_id="ev_post_01",
                claimed_transition={"state": "active"},
                verifier_authority_token=self.token,
            )
        self.assertIn("valid pid", str(ctx.exception).lower())

        # Missing process_identity
        ident_no_proc = dict(self.valid_ident)
        ident_no_proc.pop("process_identity")
        with self.assertRaises(ValueError) as ctx:
            self.authority.issue_attestation(
                session_id=self.session_id,
                target_identity=ident_no_proc,
                operation_id=self.operation_id,
                precondition_evidence_id="ev_pre_01",
                postcondition_evidence_id="ev_post_01",
                claimed_transition={"state": "active"},
                verifier_authority_token=self.token,
            )
        self.assertIn("process_identity", str(ctx.exception).lower())

        # Missing build_id
        ident_no_bid = dict(self.valid_ident)
        ident_no_bid.pop("build_id")
        with self.assertRaises(ValueError) as ctx:
            self.authority.issue_attestation(
                session_id=self.session_id,
                target_identity=ident_no_bid,
                operation_id=self.operation_id,
                precondition_evidence_id="ev_pre_01",
                postcondition_evidence_id="ev_post_01",
                claimed_transition={"state": "active"},
                verifier_authority_token=self.token,
            )
        self.assertIn("build_id", str(ctx.exception).lower())

        # Missing executable_identity and executable
        ident_no_exe = dict(self.valid_ident)
        ident_no_exe.pop("executable")
        ident_no_exe.pop("executable_identity")
        with self.assertRaises(ValueError) as ctx:
            self.authority.issue_attestation(
                session_id=self.session_id,
                target_identity=ident_no_exe,
                operation_id=self.operation_id,
                precondition_evidence_id="ev_pre_01",
                postcondition_evidence_id="ev_post_01",
                claimed_transition={"state": "active"},
                verifier_authority_token=self.token,
            )
        self.assertIn("executable identity", str(ctx.exception).lower())

        # Malformed production attestation verify() checks
        att = self.authority.issue_attestation(
            session_id=self.session_id,
            target_identity=self.valid_ident,
            operation_id=self.operation_id,
            precondition_evidence_id="ev_pre_01",
            postcondition_evidence_id="ev_post_01",
            claimed_transition={"state": "active"},
            verifier_authority_token=self.token,
        )

        # Incomplete attestation: target_identity stripped
        att_bad = CausalAttestation.from_dict(att.to_dict())
        att_bad.target_identity = {}
        ok, reason = att_bad.verify(key_store=self.authority.key_store)
        self.assertFalse(ok)
        self.assertIn("MALFORMED_ATTESTATION", reason)

        # Incomplete attestation: process_identity missing
        att_bad2 = CausalAttestation.from_dict(att.to_dict())
        att_bad2.target_identity.pop("process_identity", None)
        ok2, reason2 = att_bad2.verify(key_store=self.authority.key_store)
        self.assertFalse(ok2)
        self.assertIn("MISSING_PROCESS_IDENTITY", reason2)

    # 2. Expected identity fields are never silently skipped
    def test_02_expected_identity_not_skipped_when_attestation_lacks_field(self):
        att = self.authority.issue_attestation(
            session_id=self.session_id,
            target_identity=self.valid_ident,
            operation_id=self.operation_id,
            precondition_evidence_id="ev_pre_01",
            postcondition_evidence_id="ev_post_01",
            claimed_transition={"state": "active"},
            verifier_authority_token=self.token,
        )

        # Create an attestation whose target_identity lacks target_host
        att_no_host = CausalAttestation.from_dict(att.to_dict())
        att_no_host.target_identity.pop("target_host", None)
        att_no_host.sign(self.authority.key_store.get_active_signing_key()[1])

        # Verifier expects target_host -> MUST NOT SILENTLY SKIP
        ok, reason = att_no_host.verify(
            expected_target_host="cluster-node-01.local",
            key_store=self.authority.key_store,
        )
        self.assertFalse(ok)
        self.assertIn("TARGET_HOST_MISMATCH", reason)
        self.assertIn("Attestation missing target_host", reason)

        # Verifier expects build_id on non-production or stripped attestation -> MUST NOT SILENTLY SKIP
        att_no_bid = CausalAttestation.from_dict(att.to_dict())
        att_no_bid.authority_level = "TEST"
        att_no_bid.target_identity.pop("build_id", None)
        att_no_bid.sign(self.authority.key_store.get_active_signing_key()[1])

        ok_bid, r_bid = att_no_bid.verify(
            expected_build_id="sha1:expected_build",
            key_store=self.authority.key_store,
        )
        self.assertFalse(ok_bid)
        self.assertIn("BUILD_ID_MISMATCH", r_bid)
        self.assertIn("Attestation missing build_id", r_bid)

        # Verifier expects process_identity on stripped attestation -> MUST NOT SILENTLY SKIP
        att_no_proc = CausalAttestation.from_dict(att.to_dict())
        att_no_proc.authority_level = "TEST"
        att_no_proc.target_identity.pop("process_identity", None)
        att_no_proc.sign(self.authority.key_store.get_active_signing_key()[1])

        ok_proc, r_proc = att_no_proc.verify(
            expected_process_identity="9101:987654:boot_uuid",
            key_store=self.authority.key_store,
        )
        self.assertFalse(ok_proc)
        self.assertIn("PROCESS_IDENTITY_MISMATCH", r_proc)
        self.assertIn("Attestation missing process_identity", r_proc)

    # 3. expected_target_host is actively verified
    def test_03_expected_target_host_verification(self):
        att = self.authority.issue_attestation(
            session_id=self.session_id,
            target_identity=self.valid_ident,
            operation_id=self.operation_id,
            precondition_evidence_id="ev_pre_01",
            postcondition_evidence_id="ev_post_01",
            claimed_transition={"state": "active"},
            verifier_authority_token=self.token,
        )

        # Matching host succeeds
        ok_match, r_match = att.verify(
            expected_target_host="cluster-node-01.local",
            key_store=self.authority.key_store,
        )
        self.assertTrue(ok_match)
        self.assertEqual(r_match, "VERIFIED")

        # Mismatched host fails closed
        ok_mismatch, r_mismatch = att.verify(
            expected_target_host="cluster-node-02.remote",
            key_store=self.authority.key_store,
        )
        self.assertFalse(ok_mismatch)
        self.assertIn("TARGET_HOST_MISMATCH", r_mismatch)
        self.assertIn("Expected target host 'cluster-node-02.remote'", r_mismatch)

    # 4. Canonical signature serialization binds every identity attribute
    def test_04_canonical_signature_serialization_binds_target_host(self):
        att = self.authority.issue_attestation(
            session_id=self.session_id,
            target_identity=self.valid_ident,
            operation_id=self.operation_id,
            precondition_evidence_id="ev_pre_01",
            postcondition_evidence_id="ev_post_01",
            claimed_transition={"state": "active"},
            verifier_authority_token=self.token,
        )

        # Modify target_host in payload without re-signing
        att_tampered = CausalAttestation.from_dict(att.to_dict())
        att_tampered.target_identity["target_host"] = "evil-host.attacker"

        ok, reason = att_tampered.verify(key_store=self.authority.key_store)
        self.assertFalse(ok)
        self.assertIn("CORRUPT_ATTESTATION", reason)

    # 5. Tampered serialized identity attributes cause verification failure
    def test_05_tampered_serialized_identity_attributes_rejected(self):
        att = self.authority.issue_attestation(
            session_id=self.session_id,
            target_identity=self.valid_ident,
            operation_id=self.operation_id,
            precondition_evidence_id="ev_pre_01",
            postcondition_evidence_id="ev_post_01",
            claimed_transition={"state": "active"},
            verifier_authority_token=self.token,
        )

        # Tamper PID
        t_pid = CausalAttestation.from_dict(att.to_dict())
        t_pid.target_identity["pid"] = 9999
        ok, reason = t_pid.verify(key_store=self.authority.key_store)
        self.assertFalse(ok)
        self.assertIn("CORRUPT_ATTESTATION", reason)

        # Tamper process_identity
        t_proc = CausalAttestation.from_dict(att.to_dict())
        t_proc.target_identity["process_identity"] = "forged:process:ident"
        ok, reason = t_proc.verify(key_store=self.authority.key_store)
        self.assertFalse(ok)
        self.assertIn("CORRUPT_ATTESTATION", reason)

        # Tamper build_id
        t_bid = CausalAttestation.from_dict(att.to_dict())
        t_bid.target_identity["build_id"] = "sha1:forged_build_id"
        ok, reason = t_bid.verify(key_store=self.authority.key_store)
        self.assertFalse(ok)
        self.assertIn("CORRUPT_ATTESTATION", reason)

        # Tamper operation_id
        t_op = CausalAttestation.from_dict(att.to_dict())
        t_op.operation_id = "ctx_tampered_op_99"
        ok, reason = t_op.verify(key_store=self.authority.key_store)
        self.assertFalse(ok)
        self.assertIn("CORRUPT_ATTESTATION", reason)

    # 6. Backward compatibility preserved for legacy attestations
    def test_06_backward_compatibility_for_legacy_attestations(self):
        ident_no_host = dict(self.valid_ident)
        ident_no_host.pop("target_host", None)
        active_kid, active_sec = self.authority.key_store.get_active_signing_key()

        # Sign using legacy canonical payload (omitting target_host)
        now_ns = 1700000000000000000
        att = CausalAttestation(
            attestation_id="causal_att_legacy_01",
            session_id=self.session_id,
            target_identity=ident_no_host,
            operation_id=self.operation_id,
            precondition_evidence_id="ev_pre_01",
            postcondition_evidence_id="ev_post_01",
            claimed_transition={"state": "active"},
            intervention_details={"action": "verified_transition", "verified_intervention": True},
            issued_at_ns=now_ns,
            expires_at_ns=now_ns + 3600 * 1_000_000_000,
            verifier_identity=self.authority.authority_id,
            key_id=active_kid,
            authority_level="PRODUCTION",
        )
        import hashlib
        import hmac
        att.signature = hmac.new(active_sec.encode("utf-8"), att.canonical_bytes_legacy(), hashlib.sha256).hexdigest()

        # Legacy attestation verifies successfully when expected_target_host is not queried
        ok, reason = att.verify(key_store=self.authority.key_store, current_time_ns=now_ns)
        self.assertTrue(ok)
        self.assertEqual(reason, "VERIFIED")

        # But if expected_target_host IS queried, it fails closed
        ok_host, r_host = att.verify(
            expected_target_host="cluster-node-01.local",
            key_store=self.authority.key_store,
            current_time_ns=now_ns,
        )
        self.assertFalse(ok_host)
        self.assertIn("TARGET_HOST_MISMATCH", r_host)


if __name__ == "__main__":
    unittest.main()
