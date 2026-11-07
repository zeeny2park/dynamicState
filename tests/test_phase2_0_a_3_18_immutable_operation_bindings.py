"""Tests for Phase 2.0-A.3.18 P0-2: Immutable Operation Bindings & Verifiable Multi-Evidence Derivation.

Verifies:
1. Replay across sessions is rejected.
2. Replay across PIDs is rejected.
3. Conflicting process_identity, executable_identity, build_id, target_host, receipt_id, observation_digest are rejected.
4. Multi-evidence operation without verifiable derivation from primary observation is rejected.
5. Multi-evidence operation with valid derived_from / parent_evidence_ids succeeds and binds.
6. Independent ledgers sharing a trust store cannot reuse an operation without derivation.
7. bind_operation_evidence rejects secondary evidence if not derived from primary observation.
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
    LiveCaptureReceipt,
    get_default_key_store,
    issue_live_capture_receipt,
    get_trusted_capture_authority_token,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    EVIDENCE_TYPE_OBJECT_STATE,
    NATURE_OBSERVATION,
    NATURE_INFERENCE,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)


class TestPhase20A318ImmutableOperationBindings(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a318_p02_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)
        self.session_id = "test_session_p02"
        self.pid = 4100
        self.identity = {
            "pid": self.pid,
            "process_identity": "proc_core_worker",
            "executable_identity": "/usr/bin/python3",
            "build_id": "build_2026_11_07",
            "target_host": "prod-node-01",
        }

    def tearDown(self):
        get_default_key_store().revoke_key("key_p02")
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_reject_conflicting_session_and_pid(self):
        """DurableTrustStore rejects conflicting session or PID for same operation."""
        self.trust_store.record_used_operation("op_1", "sess_A", 100)

        # Replay with different session
        with self.assertRaises(ValueError) as ctx_sess:
            self.trust_store.record_used_operation("op_1", "sess_B", 100, allow_idempotent=True)
        self.assertIn("across sessions", str(ctx_sess.exception))

        # Replay with different PID
        with self.assertRaises(ValueError) as ctx_pid:
            self.trust_store.record_used_operation("op_1", "sess_A", 200, allow_idempotent=True)
        self.assertIn("across PIDs", str(ctx_pid.exception))

    def test_02_reject_conflicting_target_identity_fields(self):
        """Conflicting process_identity, executable_identity, build_id, target_host are rejected."""
        self.trust_store.record_used_operation(
            "op_ident",
            "sess_1",
            self.pid,
            metadata=dict(self.identity),
        )

        # Conflicting target_host
        with self.assertRaises(ValueError) as ctx1:
            self.trust_store.record_used_operation(
                "op_ident",
                "sess_1",
                self.pid,
                metadata={"target_host": "diff-node-99"},
                allow_idempotent=True,
            )
        self.assertIn("target_host", str(ctx1.exception))

        # Conflicting process_identity
        with self.assertRaises(ValueError) as ctx2:
            self.trust_store.record_used_operation(
                "op_ident",
                "sess_1",
                self.pid,
                metadata={"process_identity": "proc_other"},
                allow_idempotent=True,
            )
        self.assertIn("process_identity", str(ctx2.exception))

        # Conflicting build_id
        with self.assertRaises(ValueError) as ctx3:
            self.trust_store.record_used_operation(
                "op_ident",
                "sess_1",
                self.pid,
                metadata={"build_id": "diff_build_id"},
                allow_idempotent=True,
            )
        self.assertIn("build_id", str(ctx3.exception))

    def test_03_reject_multi_evidence_without_verifiable_derivation(self):
        """Secondary evidence claiming same operation without derivation is rejected."""
        self.trust_store.record_used_operation(
            "op_multi",
            "sess_1",
            self.pid,
            metadata={"evidence_id": "ev_primary_1", **self.identity},
        )
        self.trust_store.bind_operation_evidence("op_multi", "ev_primary_1")

        # Attempt to bind secondary evidence without derivation
        with self.assertRaises(ValueError) as ctx_rec:
            self.trust_store.record_used_operation(
                "op_multi",
                "sess_1",
                self.pid,
                metadata={"evidence_id": "ev_secondary_rogue", **self.identity},
                allow_idempotent=True,
            )
        self.assertIn("requires verifiable derivation", str(ctx_rec.exception))

        with self.assertRaises(ValueError) as ctx_bind:
            self.trust_store.bind_operation_evidence(
                "op_multi",
                "ev_secondary_rogue",
            )
        self.assertIn("lacks verifiable derivation", str(ctx_bind.exception))

    def test_04_allow_multi_evidence_with_valid_derivation(self):
        """Secondary evidence claiming same operation with valid derivation succeeds."""
        self.trust_store.record_used_operation(
            "op_multi_valid",
            "sess_1",
            self.pid,
            metadata={"evidence_id": "ev_primary_valid", **self.identity},
        )
        self.trust_store.bind_operation_evidence("op_multi_valid", "ev_primary_valid")

        # Secondary evidence derived from primary
        self.trust_store.record_used_operation(
            "op_multi_valid",
            "sess_1",
            self.pid,
            metadata={
                "evidence_id": "ev_derived_1",
                "derived_from": "ev_primary_valid",
                "parent_evidence_ids": ["ev_primary_valid"],
                **self.identity,
            },
            allow_idempotent=True,
        )
        self.trust_store.bind_operation_evidence(
            "op_multi_valid",
            "ev_derived_1",
            derived_from="ev_primary_valid",
            parent_evidence_ids=["ev_primary_valid"],
        )

        op_entry = self.trust_store.used_operation_ids["op_multi_valid"]
        # Primary evidence_id remains primary
        self.assertEqual(op_entry["evidence_id"], "ev_primary_valid")
        # Both are tracked in evidence_ids
        self.assertEqual(op_entry["evidence_ids"], ["ev_primary_valid", "ev_derived_1"])

    def test_05_cross_ledger_operation_reuse_rejected_by_trust_store(self):
        """Independent ledger attempting to reuse an operation without derivation is rejected by trust store."""
        key_store = CaptureKeyStore()
        authority = CausalVerifierAuthority(key_store=key_store, trust_store=self.trust_store)
        kid, sec = authority.rotate_key("key_p02")
        self.trust_store.register_key(kid, sec, is_active=True)
        get_default_key_store().register_key(kid, sec, is_active=True)

        ledger_a = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.identity["process_identity"],
            executable_identity=self.identity["executable_identity"],
            build_id=self.identity["build_id"],
            snapshot_binding=f"snap:{self.pid}",
            operation_id="op_tx_100",
            capture_authority_token=get_trusted_capture_authority_token(),
            secret=sec,
            key_id=kid,
        )

        # Ledger A records primary observation
        rec_a = EvidenceRecord(
            evidence_id="ev_a_primary",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature=NATURE_OBSERVATION,
            source="collector_a",
            session_id=self.session_id,
            target_identity=dict(self.identity),
            details={"operation_id": "op_tx_100"},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt},
        )
        ledger_a.add_record(rec_a)

        # Ledger B (separate instance, same trust store) attempts to use same operation without derivation
        ledger_b = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rec_b_rogue = EvidenceRecord(
            evidence_id="ev_b_rogue",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature=NATURE_OBSERVATION,
            source="collector_b",
            session_id=self.session_id,
            target_identity=dict(self.identity),
            details={"operation_id": "op_tx_100"},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt},
        )

        with self.assertRaises(ValueError) as ctx:
            ledger_b.add_record(rec_b_rogue)
        self.assertIn("requires verifiable derivation", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
