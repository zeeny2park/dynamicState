"""Tests for Phase 2.0-A.3.17 P0-4: Authoritative Index Reconstruction & Integrity Verification.

Verifies:
1. Rebuilding authoritative EvidenceLedger indexes dynamically from validated records.
2. Comparing serialized indexes against rebuilt indexes (valid ledger round-trips with 100% equivalence).
3. Rejecting forged mappings in causal_attestation_to_evidence_id.
4. Rejecting forged mappings in operation_to_receipt_id.
5. Rejecting forged mappings in operation_to_evidence_ids.
6. Rejecting phantom operations in used_operation_ids.
7. Rejecting inconsistent session/PID in used_operation_ids.
8. Failed reconstruction admits zero partial state.
"""

import os
import shutil
import tempfile
import unittest

from extractor.capture_backend import (
    CaptureKeyStore,
    CausalVerifierAuthority,
    DurableTrustStore,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
    set_default_trust_store,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    EvidenceLedger,
    EvidenceRecord,
)


class TestPhase20A317AuthoritativeIndexReconstruction(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a317_idx_reconstruct_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)
        set_default_trust_store(self.trust_store)
        self.key_store = CaptureKeyStore()
        self.authority = CausalVerifierAuthority(
            key_store=self.key_store,
            trust_store=self.trust_store,
        )
        self.key_id, self.secret = self.authority.rotate_key("key_idx_1")
        self.session_id = "sess_a317_idx"
        self.pid = 7788
        self.target_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:33333:boot_local",
            "executable_identity": "/usr/bin/app_idx:2222",
            "build_id": "sha1_build_idx",
            "target_host": "localhost",
        }

    def tearDown(self):
        set_default_trust_store(None)
        shutil.rmtree(self.test_dir, ignore_errors=True)

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

    def _create_valid_ledger(self):
        ledger = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rcpt1 = self._make_receipt("op_rec_1")
        rec1 = EvidenceRecord(
            evidence_id="ev_rec_1",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            source="runtime_collector",
            session_id=self.session_id,
            observation="Obs 1",
            details={"operation_id": "op_rec_1", "field_path": "cache.hits"},
            snapshot_ref={"snapshot_id": f"snap:{self.pid}", "epoch": 0},
            target_identity=dict(self.target_ident),
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt1.to_dict()},
        )
        ledger.add_record(rec1)

        att = self.authority.issue_attestation(
            session_id=self.session_id,
            target_identity=self.target_ident,
            operation_id="op_rec_2",
            precondition_evidence_id="ev_rec_1",
            postcondition_evidence_id="ev_rec_2",
            claimed_transition={"field": "cache.hits", "from": 10, "to": 20},
            intervention_details={"action": "verified_intervention", "verified_intervention": True},
            authority_level="PRODUCTION",
            verifier_authority_token=self.authority.get_verifier_token(),
        )
        rcpt2 = self._make_receipt("op_rec_2")
        rec2 = EvidenceRecord(
            evidence_id="ev_rec_2",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            source="runtime_collector",
            session_id=self.session_id,
            observation="Obs 2",
            parent_evidence_ids=["ev_rec_1"],
            details={"operation_id": "op_rec_2", "field_path": "cache.hits", "causal_proof": True},
            snapshot_ref={"snapshot_id": f"snap:{self.pid}", "epoch": 0},
            target_identity=dict(self.target_ident),
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt2.to_dict(),
                "causal_attestation": att,
            },
        )
        ledger.add_record(rec2)
        return ledger, att

    def test_01_valid_roundtrip_index_reconstruction(self):
        """Authoritative indexes rebuilt from validated records match serialized indexes exactly."""
        ledger, att = self._create_valid_ledger()
        data = ledger.to_dict()

        reconstructed = EvidenceLedger.from_dict(data, trust_store=self.trust_store)
        self.assertEqual(len(reconstructed.records), 2)
        self.assertEqual(reconstructed._causal_attestation_to_evidence_id[att.attestation_id], "ev_rec_2")
        self.assertEqual(reconstructed._operation_to_evidence_ids["op_rec_1"], ["ev_rec_1"])
        self.assertEqual(reconstructed._operation_to_evidence_ids["op_rec_2"], ["ev_rec_2"])

    def test_02_reject_forged_causal_attestation_to_evidence_mapping(self):
        """Forged mapping in causal_attestation_to_evidence_id fails closed during reconstruction."""
        ledger, att = self._create_valid_ledger()
        data = ledger.to_dict()
        # Tamper mapping
        data["causal_attestation_to_evidence_id"][att.attestation_id] = "ev_forged_999"

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data, trust_store=self.trust_store)
        self.assertIn("Forged or conflicting index detected: serialized causal_attestation_to_evidence_id", str(ctx.exception))

    def test_03_reject_forged_operation_to_receipt_mapping(self):
        """Forged mapping in operation_to_receipt_id fails closed during reconstruction."""
        ledger, att = self._create_valid_ledger()
        data = ledger.to_dict()
        data["operation_to_receipt_id"]["op_rec_1"] = "live_rcpt_fake_receipt_999"

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data, trust_store=self.trust_store)
        self.assertIn("Forged or conflicting index detected: serialized operation_to_receipt_id", str(ctx.exception))

    def test_04_reject_forged_operation_to_evidence_mapping(self):
        """Forged or mismatched evidence in operation_to_evidence_ids fails closed."""
        ledger, att = self._create_valid_ledger()
        data = ledger.to_dict()
        data["operation_to_evidence_ids"]["op_rec_1"] = ["ev_rec_1", "ev_unvalidated_injected"]

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data, trust_store=self.trust_store)
        self.assertIn("Evidence mapping mismatch", str(ctx.exception))

    def test_05_reject_phantom_operation_in_used_operation_ids(self):
        """Phantom operation in used_operation_ids without corresponding validated record fails closed."""
        ledger, att = self._create_valid_ledger()
        data = ledger.to_dict()
        data["used_operation_ids"]["op_phantom_unverified"] = {
            "session_id": self.session_id,
            "pid": self.pid,
        }

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data, trust_store=self.trust_store)
        self.assertIn("Forged operation mapping detected", str(ctx.exception))

    def test_06_reject_inconsistent_session_or_pid_in_used_operations(self):
        """Inconsistent session or PID in used_operation_ids fails closed during reconstruction."""
        ledger, att = self._create_valid_ledger()
        data = ledger.to_dict()
        data["used_operation_ids"]["op_rec_1"]["session_id"] = "tampered_session_bad"

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data, trust_store=self.trust_store)
        self.assertIn("Session inconsistency for operation 'op_rec_1'", str(ctx.exception))

    def test_07_failed_reconstruction_leaves_no_partial_state(self):
        """Reconstruction failure raises an exception and never returns a partially populated ledger."""
        ledger, att = self._create_valid_ledger()
        data = ledger.to_dict()
        # Corrupt one record
        data["records"][1]["evidence_type"] = "INVALID_CORRUPTED_TYPE"

        partial_res = None
        try:
            partial_res = EvidenceLedger.from_dict(data, trust_store=self.trust_store)
        except ValueError:
            pass

        self.assertIsNone(partial_res, "from_dict must not return partial state on error")


if __name__ == "__main__":
    unittest.main()
