"""Tests for Phase 2.0-A.3.18 P0-3: Strict Key-Set Equality & Authoritative Index Reconstruction.

Verifies:
1. Exact key-set equality between serialized and rebuilt used_operation_ids:
   - Detects extra entries (phantom operations)
   - Detects missing entries (unrepresented valid records)
2. Identity and receipt metadata validation during reconstruction:
   - process_identity mismatch
   - executable_identity mismatch
   - build_id mismatch
   - target_host mismatch
   - receipt_id mismatch
3. Duplicate evidence IDs in serialized operation_to_evidence_ids are rejected (no lossy set collapsing).
4. Strict list equality in operation_to_evidence_ids.
"""

import copy
import os
import shutil
import tempfile
import unittest

from extractor.capture_backend import (
    CaptureKeyStore,
    CausalVerifierAuthority,
    DurableTrustStore,
    get_default_key_store,
    issue_live_capture_receipt,
    get_trusted_capture_authority_token,
    set_default_trust_store,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    EVIDENCE_TYPE_OBJECT_STATE,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)


class TestPhase20A318StrictIndexEquality(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a318_p03_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)
        set_default_trust_store(self.trust_store)
        self.key_store = CaptureKeyStore()
        self.authority = CausalVerifierAuthority(
            key_store=self.key_store,
            trust_store=self.trust_store,
        )
        self.key_id, self.secret = self.authority.rotate_key("key_idx_p03")
        get_default_key_store().register_key(self.key_id, self.secret, is_active=True)

        self.session_id = "sess_a318_idx"
        self.pid = 8899
        self.target_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:55555:boot_local",
            "executable_identity": "/usr/bin/app_strict:4444",
            "build_id": "sha1_build_strict",
            "target_host": "prod-node-03",
        }

    def tearDown(self):
        get_default_key_store().revoke_key(self.key_id)
        set_default_trust_store(None)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_valid_ledger(self):
        ledger = EvidenceLedger(session_id=self.session_id, trust_store=self.trust_store)
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_ident["process_identity"],
            executable_identity=self.target_ident["executable_identity"],
            build_id=self.target_ident["build_id"],
            snapshot_binding=f"snap:{self.pid}",
            operation_id="op_strict_1",
            capture_authority_token=get_trusted_capture_authority_token(),
            secret=self.secret,
            key_id=self.key_id,
        )
        rec = EvidenceRecord(
            evidence_id="ev_strict_1",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature=NATURE_OBSERVATION,
            source="collector_strict",
            session_id=self.session_id,
            target_identity=dict(self.target_ident),
            details={"operation_id": "op_strict_1"},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt},
        )
        ledger.add_record(rec)
        return ledger

    def test_01_reject_extra_entry_in_used_operation_ids(self):
        """Extra operation in serialized used_operation_ids not present in records is rejected."""
        ledger = self._create_valid_ledger()
        data = ledger.to_dict()
        data["used_operation_ids"]["op_phantom_extra"] = {
            "session_id": self.session_id,
            "pid": self.pid,
        }

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data, trust_store=self.trust_store)
        self.assertIn("key-set mismatch", str(ctx.exception).lower())
        self.assertIn("op_phantom_extra", str(ctx.exception))

    def test_02_reject_missing_entry_in_used_operation_ids(self):
        """Missing operation in serialized used_operation_ids present in records is rejected."""
        ledger = self._create_valid_ledger()
        data = ledger.to_dict()
        # Drop the valid operation from serialized dict
        del data["used_operation_ids"]["op_strict_1"]

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data, trust_store=self.trust_store)
        self.assertIn("key-set mismatch", str(ctx.exception).lower())
        self.assertIn("op_strict_1", str(ctx.exception))

    def test_03_reject_mismatched_identity_metadata_in_used_operations(self):
        """Tampered process_identity, executable_identity, build_id, target_host in serialized op fails."""
        fields_to_test = [
            ("process_identity", "forged_process_ident"),
            ("executable_identity", "/usr/bin/malicious_exec"),
            ("build_id", "forged_build_id"),
            ("target_host", "evil_host"),
            ("receipt_id", "forged_receipt_id"),
        ]

        for field_name, bad_value in fields_to_test:
            with self.subTest(field=field_name):
                ledger = self._create_valid_ledger()
                data = ledger.to_dict()
                data["used_operation_ids"]["op_strict_1"][field_name] = bad_value

                with self.assertRaises(ValueError) as ctx:
                    EvidenceLedger.from_dict(data, trust_store=self.trust_store)
                self.assertIn("metadata mismatch", str(ctx.exception).lower())
                self.assertIn(field_name, str(ctx.exception))

    def test_04_reject_duplicate_evidence_id_in_serialized_operation_to_evidence(self):
        """Duplicate evidence IDs in serialized operation_to_evidence_ids must not be collapsed lossily."""
        ledger = self._create_valid_ledger()
        data = ledger.to_dict()
        # Inject duplicate evidence ID in list
        data["operation_to_evidence_ids"]["op_strict_1"] = ["ev_strict_1", "ev_strict_1"]

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data, trust_store=self.trust_store)
        self.assertIn("duplicate evidence id", str(ctx.exception).lower())

    def test_05_reject_evidence_list_mismatch_without_lossy_set_comparison(self):
        """Mismatched evidence list in serialized operation_to_evidence_ids is strictly rejected."""
        ledger = self._create_valid_ledger()
        data = ledger.to_dict()
        data["operation_to_evidence_ids"]["op_strict_1"] = ["ev_strict_other"]

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data, trust_store=self.trust_store)
        self.assertIn("evidence mapping mismatch", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
