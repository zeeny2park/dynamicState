"""Tests for Phase 2.0-A.3.17 P0-1: Atomic Trust Consumption Contract.

Verifies:
1. NEW_ACCEPTANCE on fresh valid attestation.
2. IDEMPOTENT_RECOVERY when same evidence record re-consumes the attestation.
3. REPLAY_CONFLICT when a different evidence record tries to consume the same attestation.
4. REPLAY_CONFLICT when attestation is replayed across different sessions or PIDs.
5. REVOKED status when key or attestation is revoked.
6. INVALID_SIGNATURE status when signature is tampered.
7. IDENTITY_MISMATCH when target identity or session does not match expectations.
8. PERSISTENCE_FAILURE and rollback: failed disk write rolls back in-memory trust store.
9. No check-then-record race under concurrent multi-threaded consumption.
"""

import concurrent.futures
import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

from extractor.capture_backend import (
    CaptureKeyStore,
    CausalAttestation,
    CausalVerifierAuthority,
    DurableTrustStore,
    TrustConsumptionResult,
    TrustConsumptionStatus,
)


class TestPhase20A317AtomicTrustConsumption(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a317_atomic_trust_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)
        self.key_store = CaptureKeyStore()
        self.authority = CausalVerifierAuthority(
            key_store=self.key_store,
            trust_store=self.trust_store,
        )
        self.key_id, self.secret = self.authority.rotate_key("key_a317_1")
        self.session_id = "sess_a317_test"
        self.pid = 9182
        self.target_identity = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:12345:boot_local",
            "executable_identity": "/usr/bin/app:45678",
            "build_id": "sha1_build_id_a317",
            "target_host": "localhost",
        }

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _mint_attestation(self, op_id="op_1", pre="ev_pre", post="ev_post"):
        return self.authority.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_identity,
            operation_id=op_id,
            precondition_evidence_id=pre,
            postcondition_evidence_id=post,
            claimed_transition={"field": "count", "from": 1, "to": 2},
            intervention_details={"action": "verified_intervention", "verified_intervention": True},
            authority_level="PRODUCTION",
            verifier_authority_token=self.authority.get_verifier_token(),
        )

    def test_01_new_acceptance_and_idempotent_recovery(self):
        """Fresh attestation produces NEW_ACCEPTANCE; re-consumption with same evidence produces IDEMPOTENT_RECOVERY."""
        att = self._mint_attestation("op_1")
        evidence_id = "ev_main_1"

        res1 = self.trust_store.consume_attestation(
            attestation=att,
            evidence_id=evidence_id,
            session_id=self.session_id,
            expected_pid=self.pid,
            expected_process_identity=self.target_identity["process_identity"],
            expected_executable_identity=self.target_identity["executable_identity"],
            expected_build_id=self.target_identity["build_id"],
            expected_target_host=self.target_identity["target_host"],
        )
        self.assertEqual(res1.status, TrustConsumptionStatus.NEW_ACCEPTANCE)
        self.assertTrue(res1.is_accepted)
        self.assertTrue(self.trust_store.is_attestation_used(att.attestation_id))

        # Re-consuming the exact same evidence record produces IDEMPOTENT_RECOVERY
        res2 = self.trust_store.consume_attestation(
            attestation=att,
            evidence_id=evidence_id,
            session_id=self.session_id,
            expected_pid=self.pid,
        )
        self.assertEqual(res2.status, TrustConsumptionStatus.IDEMPOTENT_RECOVERY)
        self.assertTrue(res2.is_accepted)

    def test_02_replay_conflict_different_evidence_or_session(self):
        """Re-consuming with a different evidence ID or cross-session produces REPLAY_CONFLICT."""
        att = self._mint_attestation("op_2")
        res1 = self.trust_store.consume_attestation(
            attestation=att,
            evidence_id="ev_orig",
            session_id=self.session_id,
            expected_pid=self.pid,
        )
        self.assertEqual(res1.status, TrustConsumptionStatus.NEW_ACCEPTANCE)

        # Different evidence ID
        res_diff_ev = self.trust_store.consume_attestation(
            attestation=att,
            evidence_id="ev_forged_reuse",
            session_id=self.session_id,
            expected_pid=self.pid,
        )
        self.assertEqual(res_diff_ev.status, TrustConsumptionStatus.REPLAY_CONFLICT)
        self.assertFalse(res_diff_ev.is_accepted)
        self.assertIn("already consumed by evidence 'ev_orig'", res_diff_ev.reason)

        # Different session ID
        res_diff_sess = self.trust_store.consume_attestation(
            attestation=att,
            evidence_id="ev_orig",
            session_id="different_session_999",
            expected_pid=self.pid,
        )
        self.assertEqual(res_diff_sess.status, TrustConsumptionStatus.IDENTITY_MISMATCH)

    def test_03_revoked_key_and_revoked_attestation(self):
        """Attestation signed by a revoked key or explicitly revoked returns REVOKED."""
        att = self._mint_attestation("op_3")
        self.authority.revoke_key(self.key_id, reason="compromised")

        res_rev_key = self.trust_store.consume_attestation(
            attestation=att,
            evidence_id="ev_rev_1",
            session_id=self.session_id,
            expected_pid=self.pid,
        )
        self.assertEqual(res_rev_key.status, TrustConsumptionStatus.REVOKED)
        self.assertFalse(res_rev_key.is_accepted)

        # Explicitly revoked attestation flag
        kid2, _ = self.authority.rotate_key("key_a317_2")
        att2 = self._mint_attestation("op_4")
        att2.revoked = True
        res_rev_att = self.trust_store.consume_attestation(
            attestation=att2,
            evidence_id="ev_rev_2",
            session_id=self.session_id,
            expected_pid=self.pid,
        )
        self.assertEqual(res_rev_att.status, TrustConsumptionStatus.REVOKED)

    def test_04_invalid_signature_and_identity_mismatch(self):
        """Tampered attestation signature or target identity mismatch returns appropriate status."""
        att = self._mint_attestation("op_5")
        att.signature = "a" * 64

        res_bad_sig = self.trust_store.consume_attestation(
            attestation=att,
            evidence_id="ev_sig_fail",
            session_id=self.session_id,
            expected_pid=self.pid,
        )
        self.assertEqual(res_bad_sig.status, TrustConsumptionStatus.INVALID_SIGNATURE)

        # Target PID mismatch
        att_valid = self._mint_attestation("op_6")
        res_bad_pid = self.trust_store.consume_attestation(
            attestation=att_valid,
            evidence_id="ev_pid_mismatch",
            session_id=self.session_id,
            expected_pid=99999,
        )
        self.assertEqual(res_bad_pid.status, TrustConsumptionStatus.IDENTITY_MISMATCH)

    def test_05_persistence_failure_rolls_back_in_memory_state(self):
        """Persistence failure during atomic consumption rolls back in-memory state and returns PERSISTENCE_FAILURE."""
        att = self._mint_attestation("op_7")
        evidence_id = "ev_fail_write"

        with patch.object(self.trust_store, "save", side_effect=OSError("Disk full / simulated EIO")):
            res = self.trust_store.consume_attestation(
                attestation=att,
                evidence_id=evidence_id,
                session_id=self.session_id,
                expected_pid=self.pid,
            )
            self.assertEqual(res.status, TrustConsumptionStatus.PERSISTENCE_FAILURE)
            self.assertFalse(res.is_accepted)
            # In-memory rollback verification
            self.assertNotIn(att.attestation_id, self.trust_store.used_attestation_ids)
            self.assertNotIn(att.attestation_id, self.trust_store.used_attestations)

    def test_06_no_check_then_record_race_concurrent_threads(self):
        """Under concurrent multi-threaded consumption, exactly one thread gets NEW_ACCEPTANCE and others get REPLAY_CONFLICT."""
        att = self._mint_attestation("op_race")
        results = []

        def _consume_worker(worker_id):
            return self.trust_store.consume_attestation(
                attestation=att,
                evidence_id=f"ev_worker_{worker_id}",
                session_id=self.session_id,
                expected_pid=self.pid,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(_consume_worker, i) for i in range(8)]
            for fut in concurrent.futures.as_completed(futures):
                results.append(fut.result().status)

        new_count = results.count(TrustConsumptionStatus.NEW_ACCEPTANCE)
        conflict_count = results.count(TrustConsumptionStatus.REPLAY_CONFLICT)
        self.assertEqual(new_count, 1, f"Expected exactly 1 NEW_ACCEPTANCE, got {new_count}")
        self.assertEqual(conflict_count, 7, f"Expected 7 REPLAY_CONFLICT, got {conflict_count}")


if __name__ == "__main__":
    unittest.main()
