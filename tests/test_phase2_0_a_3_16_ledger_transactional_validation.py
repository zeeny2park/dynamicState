"""Phase 2.0-A.3.16 EvidenceLedger Transactional Validation Tests.

Verifies:
1. Failed validation cannot leave partial internal mutations.
2. Adversarial tests deliberately failing validation after each mutation point roll back cleanly:
   - Failure after operation-to-receipt mapping
   - Failure after operation-to-evidence mapping
   - Failure after causal attestation mapping
   - Duplicate evidence_id failure in add_record()
3. Repeated validation of the same record is idempotent and does not create inconsistent state.
4. Derived evidence cannot cross operation boundaries.
5. Deserialization via from_dict() reconstructs and revalidates all authoritative indexes.
6. Corrupted record in from_dict() fails closed without partial state admission.
"""

import copy
import os
import shutil
import tempfile
import unittest

from extractor.capture_backend import (
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


class TestPhase20A316LedgerTransactionalValidation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="a316_tx_val_")
        self.store_path = os.path.join(self.tmp_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)
        set_default_trust_store(self.trust_store)

        self.authority = CausalVerifierAuthority(trust_store=self.trust_store)
        self.session_id = "sess_a316_tx"
        self.pid = 9401
        self.target_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:556677:boot_uuid",
            "start_time": "556677",
            "executable": "/usr/bin/service_a316_tx",
            "executable_identity": f"/usr/bin/service_a316_tx:{self.pid}",
            "build_id": "sha1:build_a316_tx",
            "target_host": "localhost",
        }
        self.key_id = "k_tx"
        self.secret = "secret_tx_444"
        self.trust_store.register_key(self.key_id, self.secret, is_active=True)

    def tearDown(self):
        set_default_trust_store(None)
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _make_receipt(self, op_id: str):
        return issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_ident["process_identity"],
            executable_identity=self.target_ident["executable_identity"],
            build_id=self.target_ident["build_id"],
            snapshot_binding=f"snap:{self.pid}",
            operation_id=op_id,
            capture_authority_token=get_trusted_capture_authority_token(),
            secret=self.secret,
            key_id=self.key_id,
        )

    # 1. Failure after operation-to-receipt mapping rolls back completely
    def test_01_failure_after_receipt_mapping_rolls_back(self):
        ledger = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rcpt = self._make_receipt("ctx_op_fail_01")

        # Create record with derived_from referencing nonexistent source
        bad_derived_rec = EvidenceRecord(
            evidence_id="ev_bad_derived",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Bad derived observation",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict()},
            target_identity=dict(self.target_ident),
            details={"operation_id": "ctx_op_fail_01", "derived_from": "ev_nonexistent_src"},
            session_id=self.session_id,
        )

        with self.assertRaises(ValueError) as ctx:
            ledger.validate_record(bad_derived_rec)
        self.assertIn("nonexistent source observation", str(ctx.exception).lower())

        # Operation-to-receipt mapping MUST have been rolled back
        self.assertNotIn("ctx_op_fail_01", ledger._operation_to_receipt_id)
        self.assertNotIn("ctx_op_fail_01", ledger._operation_to_evidence_ids)

    # 2. Failure after causal attestation mapping rolls back completely
    def test_02_failure_after_causal_mapping_rolls_back(self):
        ledger = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rcpt = self._make_receipt("ctx_op_causal_fail")

        # Precondition is nonexistent
        att = self.authority.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_ident,
            operation_id="ctx_op_causal_fail",
            precondition_evidence_id="ev_missing_pre",
            postcondition_evidence_id="ev_post_fail",
            claimed_transition={"active": True},
            verifier_authority_token=self.authority.get_verifier_token(),
            key_id=self.key_id,
            secret=self.secret,
        )

        rec = EvidenceRecord(
            evidence_id="ev_post_fail",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Post fail observation",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "causal_attestation": att.to_dict(), "live_capture_receipt": rcpt.to_dict()},
            target_identity=dict(self.target_ident),
            details={"operation_id": "ctx_op_causal_fail", "causal_attestation": att.to_dict()},
            session_id=self.session_id,
        )

        with self.assertRaises(ValueError) as ctx:
            ledger.validate_record(rec)
        self.assertIn("nonexistent precondition evidence", str(ctx.exception).lower())

        # Causal attestation ID must NOT be recorded as used!
        self.assertNotIn(att.attestation_id, ledger._used_causal_attestation_ids)
        self.assertNotIn(att.attestation_id, ledger._causal_attestation_to_evidence_id)

    # 3. Duplicate evidence_id in add_record() rolls back all indexes
    def test_03_duplicate_evidence_id_in_add_record_rolls_back(self):
        ledger = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rcpt1 = self._make_receipt("ctx_op_rec_01")
        rec1 = EvidenceRecord(
            evidence_id="ev_dup_target",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Obs 1",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt1.to_dict()},
            target_identity=dict(self.target_ident),
            details={"operation_id": "ctx_op_rec_01"},
            session_id=self.session_id,
        )
        ledger.add_record(rec1)
        self.assertEqual(len(ledger.records), 1)

        # Attempt to add another record with SAME evidence_id but DIFFERENT operation_id
        rcpt2 = self._make_receipt("ctx_op_rec_02")
        rec_dup = EvidenceRecord(
            evidence_id="ev_dup_target",  # Duplicate ID!
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Obs duplicate",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt2.to_dict()},
            target_identity=dict(self.target_ident),
            details={"operation_id": "ctx_op_rec_02"},
            session_id=self.session_id,
        )
        with self.assertRaises(ValueError) as ctx:
            ledger.add_record(rec_dup)
        self.assertIn("duplicate evidence_id", str(ctx.exception).lower())

        # Operation 2 must NOT be leaked into mappings!
        self.assertNotIn("ctx_op_rec_02", ledger._operation_to_receipt_id)
        self.assertNotIn("ctx_op_rec_02", ledger._operation_to_evidence_ids)
        self.assertNotIn("ctx_op_rec_02", ledger._used_operation_ids)

    # 4. Repeated validation idempotency
    def test_04_repeated_validation_idempotency(self):
        ledger = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rcpt = self._make_receipt("ctx_op_idemp")
        rec = EvidenceRecord(
            evidence_id="ev_idemp",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Obs idempotent",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict()},
            target_identity=dict(self.target_ident),
            details={"operation_id": "ctx_op_idemp"},
            session_id=self.session_id,
        )

        # Validate 3 times consecutively
        ledger.validate_record(rec)
        ledger.validate_record(rec)
        ledger.validate_record(rec)

        # Mappings must remain clean with single entry
        self.assertEqual(ledger._operation_to_evidence_ids["ctx_op_idemp"], ["ev_idemp"])
        self.assertEqual(ledger._operation_to_receipt_id["ctx_op_idemp"], rcpt.receipt_id)

    # 5. Derived evidence cannot cross operation boundaries
    def test_05_derived_evidence_cannot_cross_operation_boundaries(self):
        ledger = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rcpt1 = self._make_receipt("ctx_op_root")
        rec1 = EvidenceRecord(
            evidence_id="ev_src_root",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Root observation",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt1.to_dict()},
            target_identity=dict(self.target_ident),
            details={"operation_id": "ctx_op_root"},
            session_id=self.session_id,
        )
        ledger.add_record(rec1)

        # Child record claims ctx_op_different but derives from ev_src_root (ctx_op_root)
        rcpt2 = self._make_receipt("ctx_op_different")
        bad_child = EvidenceRecord(
            evidence_id="ev_bad_child",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Cross-operation child",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt2.to_dict()},
            target_identity=dict(self.target_ident),
            details={"operation_id": "ctx_op_different", "derived_from": "ev_src_root"},
            session_id=self.session_id,
        )

        with self.assertRaises(ValueError) as ctx:
            ledger.add_record(bad_child)
        self.assertIn("derivation operation mismatch", str(ctx.exception).lower())

    # 6. Deserialization reconstructs and revalidates all authoritative indexes
    def test_06_from_dict_reconstructs_and_revalidates_indexes(self):
        ledger = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rcpt = self._make_receipt("ctx_op_roundtrip")
        rec = EvidenceRecord(
            evidence_id="ev_roundtrip",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Roundtrip observation",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict()},
            target_identity=dict(self.target_ident),
            details={"operation_id": "ctx_op_roundtrip"},
            session_id=self.session_id,
        )
        ledger.add_record(rec)

        serialized = ledger.to_dict()
        self.assertIn("causal_attestation_to_evidence_id", serialized)
        self.assertIn("operation_to_evidence_ids", serialized)

        # Reconstruct fresh ledger
        restored = EvidenceLedger.from_dict(serialized, trust_store=self.trust_store)
        self.assertEqual(len(restored.records), 1)
        self.assertEqual(restored._operation_to_evidence_ids["ctx_op_roundtrip"], ["ev_roundtrip"])
        self.assertEqual(restored._operation_to_receipt_id["ctx_op_roundtrip"], rcpt.receipt_id)

        # Corrupt serialized record signature -> from_dict() must fail closed
        corrupted = copy.deepcopy(serialized)
        corrupted["records"][0]["provenance"]["live_capture_receipt"]["signature"] = "deadbeef" * 8
        with self.assertRaises(ValueError) as ctx_corrupt:
            EvidenceLedger.from_dict(corrupted, trust_store=self.trust_store)
        self.assertIn("invalid_signature", str(ctx_corrupt.exception).lower())


if __name__ == "__main__":
    unittest.main()
