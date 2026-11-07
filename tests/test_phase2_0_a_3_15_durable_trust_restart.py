"""Phase 2.0-A.3.15 Durable Trust Store & Process Restart Verification Tests.

Verifies:
1. Durable trust store persists keys and revocation state atomically to disk.
2. Independent authority instances and simulated process restarts preserve revocation.
3. Anti-replay attestation identifiers survive process restarts.
4. Corrupted trust store files fail closed with RuntimeError.
5. Multi-worker verification: worker process verifies attestations using the shared trust store.
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
)


class TestPhase20A315DurableTrustRestart(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="a315_trust_")
        self.store_path = os.path.join(self.tmp_dir, "durable_trust.json")
        self.session_id = "sess_a315_trust"
        self.pid = 9401
        self.target_identity = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:123456:boot_uuid",
            "start_time": "123456",
            "executable": "/usr/bin/service_a315_durable",
            "executable_identity": f"/usr/bin/service_a315_durable:{self.pid}",
            "build_id": "sha1:build_a315_trust",
            "target_host": "localhost",
        }

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # 1. Atomic key rotation persists to disk and survives restart
    def test_01_atomic_key_rotation_persists_to_disk(self):
        # Process 1 creates trust store and rotates key
        store1 = DurableTrustStore(self.store_path)
        auth1 = CausalVerifierAuthority(trust_store=store1)
        kid, sec = auth1.rotate_key("key_epoch_1", "secret_epoch_1_abcdef1234567890")
        self.assertTrue(os.path.exists(self.store_path))

        # Inspect raw JSON file on disk
        with open(self.store_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("key_epoch_1", data["keys"])
        self.assertEqual(data["active_key_id"], "key_epoch_1")

        # Process 2 (simulated restart) loads from store file
        store2 = DurableTrustStore(self.store_path)
        auth2 = CausalVerifierAuthority(trust_store=store2)
        self.assertEqual(auth2.key_store._keys.get("key_epoch_1"), sec)

    # 2. Revoked keys remain revoked after process restart
    def test_02_revocation_survives_process_restart(self):
        store1 = DurableTrustStore(self.store_path)
        auth1 = CausalVerifierAuthority(trust_store=store1)
        auth1.rotate_key("key_to_revoke", "secret_revoked_1234567890")
        tok1 = auth1.get_verifier_token()

        att = auth1.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_durable_rev",
            precondition_evidence_id="ev_pre",
            postcondition_evidence_id="ev_post",
            claimed_transition={"x": 1},
            authority_level="PRODUCTION",
            verifier_authority_token=tok1,
            key_id="key_to_revoke",
        )

        # Revoke the key
        auth1.revoke_key("key_to_revoke", reason="compromised_key_test")
        self.assertTrue(auth1.is_key_revoked("key_to_revoke"))

        # Process 2 (restart) loads from disk
        store2 = DurableTrustStore(self.store_path)
        auth2 = CausalVerifierAuthority(trust_store=store2)
        self.assertTrue(auth2.is_key_revoked("key_to_revoke"))

        # Verification fails closed on revoked key
        ok, err = att.verify(trust_store=store2)
        self.assertFalse(ok)
        self.assertIn("key_revoked", err.lower())

    # 3. Anti-replay attestation identifiers survive process restart
    def test_03_anti_replay_survives_process_restart(self):
        store1 = DurableTrustStore(self.store_path)
        store1.record_used_attestation("causal_att_single_use_01")
        self.assertTrue(store1.is_attestation_used("causal_att_single_use_01"))

        # Replaying on store1 raises ValueError
        with self.assertRaises(ValueError) as ctx:
            store1.record_used_attestation("causal_att_single_use_01")
        self.assertIn("replay of causal attestation id", str(ctx.exception).lower())

        # Process 2 (restart) loads from disk and rejects replay
        store2 = DurableTrustStore(self.store_path)
        self.assertTrue(store2.is_attestation_used("causal_att_single_use_01"))
        with self.assertRaises(ValueError) as ctx:
            store2.record_used_attestation("causal_att_single_use_01")
        self.assertIn("replay of causal attestation id", str(ctx.exception).lower())

    # 4. Corrupted trust store file fails closed with RuntimeError
    def test_04_corrupted_trust_store_fails_closed(self):
        # Write corrupted garbage to trust store path
        with open(self.store_path, "w", encoding="utf-8") as f:
            f.write("{corrupt_garbage_json: !!!")

        with self.assertRaises(RuntimeError) as ctx:
            DurableTrustStore(self.store_path)
        self.assertIn("corrupted or unreadable", str(ctx.exception).lower())

    # 5. Multi-worker verification sharing durable trust store
    def test_05_multi_worker_shared_trust_store(self):
        store_authority = DurableTrustStore(self.store_path)
        auth = CausalVerifierAuthority(trust_store=store_authority)
        auth.rotate_key("worker_shared_key", "super_shared_secret_1234567890")
        tok = auth.get_verifier_token()

        att = auth.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id="op_multi_worker",
            precondition_evidence_id="ev_pre",
            postcondition_evidence_id="ev_post",
            claimed_transition={"state": "committed"},
            authority_level="PRODUCTION",
            verifier_authority_token=tok,
            key_id="worker_shared_key",
        )

        # Worker process reads shared trust store
        worker_store = DurableTrustStore(self.store_path)
        ok, reason = att.verify(trust_store=worker_store)
        self.assertTrue(ok)
        self.assertEqual(reason, "VERIFIED")


if __name__ == "__main__":
    unittest.main()
