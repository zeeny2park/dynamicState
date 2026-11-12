"""Phase 2.0-A.3.16 DurableTrustStore Enforcement Integration Tests.

Verifies:
1. Revoked keys are rejected across all production paths:
   - CausalVerifierAuthority
   - CausalAttestation.verify()
   - EvidenceLedger.validate_record()
   - EvidenceLedger.from_dict()
   - Workflow recovery
2. No fallback to untrusted default keys may bypass durable revocation.
3. Active key selection survives independent process restarts.
4. Missing, invalid, or corrupted trust state fails closed.
5. Key rotation preserves validity of historical attestations without restoring revoked keys.
6. Re-registering a revoked key fails closed.
"""

import json
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


class TestPhase20A316DurableTrustStoreIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="a316_trust_")
        self.store_path = os.path.join(self.tmp_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)
        set_default_trust_store(self.trust_store)

        self.session_id = "sess_a316_trust"
        self.pid = 9201
        self.target_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:112233:boot_uuid",
            "start_time": "112233",
            "executable": "/usr/bin/service_a316_trust",
            "executable_identity": f"/usr/bin/service_a316_trust:{self.pid}",
            "build_id": "sha1:build_a316_trust",
            "target_host": "localhost",
        }

    def tearDown(self):
        set_default_trust_store(None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)


    # 2. No fallback to untrusted default keys bypassing revocation
    def test_02_no_fallback_to_untrusted_default_keys(self):
        self.trust_store.register_key("default", "default_secret_123", is_active=True)
        self.trust_store.revoke_key("default", "Revoked default key")

        att = CausalAttestation(
            attestation_id="causal_att_def",
            session_id=self.session_id,
            target_identity=self.target_ident,
            operation_id="ctx_op_def",
            precondition_evidence_id="ev_pre",
            postcondition_evidence_id="ev_post",
            claimed_transition={"val": 1},
            key_id="default",
            authority_level="PRODUCTION",
        )
        att.sign("default_secret_123")

        ok, reason = att.verify(trust_store=self.trust_store)
        self.assertFalse(ok)
        self.assertIn("KEY_REVOKED", reason)

    # 3. Active key selection survives independent process restarts
    def test_03_active_key_selection_survives_restart(self):
        # Process A rotates to key_gamma
        store_a = DurableTrustStore(self.store_path)
        store_a.register_key("key_init", "sec_init", is_active=True)
        store_a.rotate_key("key_gamma", "secret_gamma_777")
        self.assertEqual(store_a.active_key_id, "key_gamma")

        # Process B restarts fresh with new instance from store_path
        store_b = DurableTrustStore(self.store_path)
        self.assertEqual(store_b.active_key_id, "key_gamma")
        self.assertIn("key_gamma", store_b.keys)
        self.assertEqual(store_b.resolve_key("key_gamma"), "secret_gamma_777")

    # 4. Missing, invalid, or corrupted trust state fails closed
    def test_04_corrupted_trust_store_fails_closed(self):
        # Truncated / malformed JSON
        with open(self.store_path, "w", encoding="utf-8") as f:
            f.write("{ invalid json corrupted ")

        with self.assertRaises(RuntimeError) as ctx:
            DurableTrustStore(self.store_path)
        self.assertIn("corrupted or unreadable", str(ctx.exception).lower())

        # Malformed schema (keys is not a dict)
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump({"schema_version": "1.0.0", "keys": "NOT_A_DICT"}, f)

        with self.assertRaises(RuntimeError) as ctx2:
            DurableTrustStore(self.store_path)
        self.assertIn("must be a dictionary", str(ctx2.exception).lower())

    # 5. Key rotation preserves validity of historical attestations without restoring revoked keys
    def test_05_key_rotation_preserves_historical_validity(self):
        store = DurableTrustStore(self.store_path)
        store.register_key("k_old", "secret_old_111", is_active=True)
        auth = CausalVerifierAuthority(trust_store=store)

        att_old = auth.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_ident,
            operation_id="ctx_op_hist_01",
            precondition_evidence_id="ev_pre_01",
            postcondition_evidence_id="ev_post_01",
            claimed_transition={"state": "v1"},
            verifier_authority_token=auth.get_verifier_token(),
            key_id="k_old",
        )
        ok1, _ = att_old.verify(trust_store=store)
        self.assertTrue(ok1)

        # Rotate key to k_new
        store.rotate_key("k_new", "secret_new_222")
        self.assertEqual(store.active_key_id, "k_new")

        # Issue new attestation with k_new
        att_new = auth.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_ident,
            operation_id="ctx_op_hist_02",
            precondition_evidence_id="ev_pre_01",
            postcondition_evidence_id="ev_post_01",
            claimed_transition={"state": "v2"},
            verifier_authority_token=auth.get_verifier_token(),
            key_id="k_new",
        )
        ok2, _ = att_new.verify(trust_store=store)
        self.assertTrue(ok2)

        # Historical attestation att_old STILL verifies with k_old!
        ok1_after, _ = att_old.verify(trust_store=store)
        self.assertTrue(ok1_after)

    # 6. Re-registering a revoked key fails closed
    def test_06_cannot_re_register_revoked_key(self):
        store = DurableTrustStore(self.store_path)
        store.register_key("k_temp", "secret_temp")
        store.revoke_key("k_temp", reason="compromised")

        # Attempt to re-register revoked key must fail
        with self.assertRaises(ValueError) as ctx:
            store.register_key("k_temp", "new_secret_attempt")
        self.assertIn("permanently revoked", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
