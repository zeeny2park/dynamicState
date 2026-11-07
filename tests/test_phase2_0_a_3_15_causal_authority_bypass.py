"""Phase 2.0-A.3.15 Causal Authority Bypass & Trust Boundary Tests.

Verifies:
1. Authority instance rejects global _TRUSTED_CAUSAL_VERIFIER_TOKEN when configured with an instance-specific token.
2. Production causal attestation issuance strictly requires the matching authority token.
3. Separation of verifier authorization: unauthorized callers cannot mint PRODUCTION attestations.
4. Independent verification using explicitly trusted verification material.
5. Key rotation and revocation lifecycle on CausalVerifierAuthority.
"""

import os
import unittest
from unittest.mock import patch

from extractor.capture_backend import (
    CaptureKeyStore,
    CausalAttestation,
    CausalVerifierAuthority,
    _TRUSTED_CAUSAL_VERIFIER_TOKEN,
    get_default_key_store,
    get_trusted_causal_authority_token,
    issue_causal_attestation,
)


class TestPhase20A315CausalAuthorityBypass(unittest.TestCase):
    def setUp(self):
        self.session_id = "sess_a315_auth"
        self.pid = 8101
        self.target_identity = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:123456:boot_uuid",
            "executable": "/usr/bin/target_service",
            "executable_identity": f"/usr/bin/target_service:{self.pid}",
            "build_id": "sha1:a315authbuild",
            "target_host": "localhost",
        }

    # 1. Global token fallback is rejected on instance-specific authority
    def test_01_global_token_fallback_rejected(self):
        instance_token = os.urandom(32).hex()
        auth = CausalVerifierAuthority(
            authority_id="custom_authority_01",
            authority_secret=instance_token,
        )

        # Attempting to use global token on instance with specific secret MUST be rejected
        with self.assertRaises(ValueError) as ctx:
            auth.issue_attestation(
                session_id=self.session_id,
                target_identity=self.target_identity,
                operation_id="op_bypass_01",
                precondition_evidence_id="ev_pre_01",
                postcondition_evidence_id="ev_post_01",
                claimed_transition={"state": "mutated"},
                authority_level="PRODUCTION",
                verifier_authority_token=_TRUSTED_CAUSAL_VERIFIER_TOKEN,
            )
        self.assertIn("unauthorized causal attestation issuance", str(ctx.exception).lower())

        # Using the matching instance token succeeds
        att = auth.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_bypass_01",
            precondition_evidence_id="ev_pre_01",
            postcondition_evidence_id="ev_post_01",
            claimed_transition={"state": "mutated"},
            authority_level="PRODUCTION",
            verifier_authority_token=instance_token,
        )
        self.assertIsNotNone(att)
        self.assertEqual(att.verifier_identity, "custom_authority_01")

    # 2. Unauthorized caller without authority token cannot issue PRODUCTION attestation
    def test_02_unauthorized_production_issuance_rejected(self):
        auth = CausalVerifierAuthority()
        for bad_token in [None, "", "invalid_token_123", "attacker_controlled"]:
            with self.assertRaises(ValueError) as ctx:
                auth.issue_attestation(
                    session_id=self.session_id,
                    target_identity=self.target_identity,
                    operation_id="op_unauth_01",
                    precondition_evidence_id="ev_pre_01",
                    postcondition_evidence_id="ev_post_01",
                    claimed_transition={"state": "mutated"},
                    authority_level="PRODUCTION",
                    verifier_authority_token=bad_token,
                )
            self.assertIn("unauthorized causal attestation issuance", str(ctx.exception).lower())

    # 3. Independent workers verify attestations using explicitly trusted key store
    def test_03_independent_worker_verification(self):
        # Worker A (Authority) creates attestation with dedicated key
        ks_a = CaptureKeyStore()
        ks_a.register_key("worker_shared_key_1", "super_secret_shared_key_1234567890", is_active=True)
        auth_a = CausalVerifierAuthority(authority_id="auth_worker_a", key_store=ks_a)
        tok_a = auth_a.get_verifier_token()

        att = auth_a.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_worker_01",
            precondition_evidence_id="ev_pre_01",
            postcondition_evidence_id="ev_post_01",
            claimed_transition={"status": "confirmed"},
            authority_level="PRODUCTION",
            verifier_authority_token=tok_a,
            key_id="worker_shared_key_1",
        )

        # Worker B has independent key store provisioned with the same key
        ks_b = CaptureKeyStore()
        ks_b.register_key("worker_shared_key_1", "super_secret_shared_key_1234567890", is_active=True)

        ok_v, reason_v = att.verify(key_store=ks_b)
        self.assertTrue(ok_v)
        self.assertEqual(reason_v, "VERIFIED")

        # Worker C with untrusted / different key fails verification
        ks_c = CaptureKeyStore()
        ks_c.register_key("worker_shared_key_1", "wrong_secret_untrusted_key_000000000", is_active=True)
        ok_c, reason_c = att.verify(key_store=ks_c)
        self.assertFalse(ok_c)
        self.assertIn("hmac signature verification failed", reason_c.lower())

    # 4. Key revocation on authority immediately renders attestation unverifiable
    def test_04_key_revocation_lifecycle(self):
        ks = CaptureKeyStore()
        ks.register_key("key_rot_1", "secret_key_rotation_1234567890", is_active=True)
        auth = CausalVerifierAuthority(key_store=ks)
        tok = auth.get_verifier_token()

        att = auth.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_rev_01",
            precondition_evidence_id="ev_pre_01",
            postcondition_evidence_id="ev_post_01",
            claimed_transition={"flag": True},
            authority_level="PRODUCTION",
            verifier_authority_token=tok,
            key_id="key_rot_1",
        )
        ok_before, _ = att.verify(key_store=ks)
        self.assertTrue(ok_before)

        # Revoke key
        auth.revoke_key("key_rot_1", reason="compromise_simulated")
        self.assertTrue(auth.is_key_revoked("key_rot_1"))

        # Subsequent verification fails closed
        ok_after, err_after = att.verify(key_store=ks)
        self.assertFalse(ok_after)
        self.assertIn("key_revoked", err_after.lower())


if __name__ == "__main__":
    unittest.main()
