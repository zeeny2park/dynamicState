#!/usr/bin/env python3
"""
Unit tests for Phase 2.0-A.3.19: Verifiable Multi-Evidence Derivation (P0-2).

Validates:
- Self-referencing derivation rejection (parent_evidence_ids or derived_from pointing to self).
- Non-existent parent evidence rejection.
- Cross-session derivation rejection.
- Cross-target derivation rejection (PID, target_host, process_identity mismatch).
- Canonical parent evidence digest binding and tampering detection.
- Allowed evidence types restriction for primary and derived records sharing operation IDs.
- DurableTrustStore bind_operation_evidence validation.
"""

import os
import shutil
import tempfile
import unittest

from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    compute_evidence_fingerprint,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_DIAGNOSTIC,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_INFERENCE,
    EVIDENCE_TYPE_HYPOTHESIS,
    ALLOWED_PRIMARY_OPERATION_EVIDENCE_TYPES,
    ALLOWED_DERIVED_OPERATION_EVIDENCE_TYPES,
)
from extractor.capture_backend import (
    DurableTrustStore,
)


class TestVerifiableMultiEvidenceDerivation(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_a319_derivation_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(store_path=self.store_path)
        self.ledger = EvidenceLedger(session_id="test-session-001", trust_store=self.trust_store)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_primary_record(self, evidence_id="ev_prim_01", op_id="op_capture_100"):
        return EvidenceRecord(
            evidence_id=evidence_id,
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature="observation",
            session_id="test-session-001",
            target_identity={"pid": 1234, "process_identity": "proc-a", "executable_identity": "/bin/app", "target_host": "host-1"},
            object_observation={"obj_ptr": "0x123", "type_name": "Counter", "size": 32},
            details={"operation_id": op_id, "observation_digest": "sha256:abc123"},
        )

    def test_self_reference_rejection_parent_ids(self):
        """Reject record listing its own evidence_id in parent_evidence_ids."""
        with self.assertRaises(ValueError) as ctx:
            rec = EvidenceRecord(
                evidence_id="ev_self_01",
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature="observation",
                session_id="test-session-001",
                parent_evidence_ids=["ev_self_01"],
                details={"operation_id": "op_self_1"},
            )
            self.ledger.add_record(rec)
        self.assertIn("Self-referenc", str(ctx.exception))

    def test_self_reference_rejection_derived_from(self):
        """Reject record with derived_from equal to its own evidence_id."""
        rec = EvidenceRecord(
            evidence_id="ev_self_02",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature="observation",
            session_id="test-session-001",
            details={"operation_id": "op_self_2", "derived_from": "ev_self_02"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec)
        self.assertIn("Self-referential derivation rejected", str(ctx.exception))

    def test_nonexistent_parent_rejection(self):
        """Reject derivation referencing parent evidence ID not present in ledger."""
        rec = EvidenceRecord(
            evidence_id="ev_child_01",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            session_id="test-session-001",
            parent_evidence_ids=["ev_nonexistent_parent"],
            details={"operation_id": "op_capture_100", "derived_from": "ev_nonexistent_parent"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec)
        self.assertTrue(
            "does not exist in ledger" in str(ctx.exception)
            or "nonexistent" in str(ctx.exception)
        )

    def test_cross_session_derivation_rejection(self):
        """Reject child record deriving from parent in a different session."""
        prim = self._create_primary_record("ev_prim_sess", "op_sess_01")
        self.ledger.add_record(prim)

        child = EvidenceRecord(
            evidence_id="ev_child_sess",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            session_id="other-session-999",
            target_identity={"pid": 1234, "process_identity": "proc-a", "executable_identity": "/bin/app", "target_host": "host-1"},
            parent_evidence_ids=["ev_prim_sess"],
            details={"operation_id": "op_sess_01", "derived_from": "ev_prim_sess"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(child)
        self.assertIn("Cross-session derivation rejected", str(ctx.exception))

    def test_cross_target_derivation_rejection_pid(self):
        """Reject derivation across different PIDs."""
        prim = self._create_primary_record("ev_prim_pid", "op_pid_01")
        self.ledger.add_record(prim)

        child = EvidenceRecord(
            evidence_id="ev_child_pid",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            session_id="test-session-001",
            target_identity={"pid": 9999, "process_identity": "proc-a", "executable_identity": "/bin/app", "target_host": "host-1"},
            parent_evidence_ids=["ev_prim_pid"],
            details={"operation_id": "op_pid_01", "derived_from": "ev_prim_pid"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(child)
        self.assertIn("Cross-target derivation rejected", str(ctx.exception))
        self.assertIn("PID", str(ctx.exception))

    def test_cross_target_derivation_rejection_host(self):
        """Reject derivation across different target hosts."""
        prim = self._create_primary_record("ev_prim_host", "op_host_01")
        self.ledger.add_record(prim)

        child = EvidenceRecord(
            evidence_id="ev_child_host",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            session_id="test-session-001",
            target_identity={"pid": 1234, "process_identity": "proc-a", "executable_identity": "/bin/app", "target_host": "host-2"},
            parent_evidence_ids=["ev_prim_host"],
            details={"operation_id": "op_host_01", "derived_from": "ev_prim_host"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(child)
        self.assertIn("Cross-target derivation rejected", str(ctx.exception))
        self.assertIn("host", str(ctx.exception))

    def test_canonical_parent_digest_verification_and_tamper_detection(self):
        """Test canonical parent evidence digest computation, auto-binding, and tamper detection."""
        prim = self._create_primary_record("ev_prim_fp", "op_fp_01")
        self.ledger.add_record(prim)
        expected_fp = compute_evidence_fingerprint(prim)

        # 1. Child with tampered parent digest
        tampered_child = EvidenceRecord(
            evidence_id="ev_child_tampered",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            session_id="test-session-001",
            target_identity={"pid": 1234, "process_identity": "proc-a", "executable_identity": "/bin/app", "target_host": "host-1"},
            parent_evidence_ids=["ev_prim_fp"],
            details={
                "operation_id": "op_fp_01",
                "derived_from": "ev_prim_fp",
                "parent_evidence_digest": "sha256:forged_digest_00000000000000000000000000",
            },
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(tampered_child)
        self.assertIn("Parent evidence digest mismatch", str(ctx.exception))

        # 2. Child without parent digest gets auto-bound to expected_fp
        valid_child = EvidenceRecord(
            evidence_id="ev_child_valid",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            session_id="test-session-001",
            target_identity={"pid": 1234, "process_identity": "proc-a", "executable_identity": "/bin/app", "target_host": "host-1"},
            parent_evidence_ids=["ev_prim_fp"],
            details={"operation_id": "op_fp_01", "derived_from": "ev_prim_fp"},
        )
        added = self.ledger.add_record(valid_child)
        self.assertEqual(added.details["parent_evidence_digest"], expected_fp)

    def test_allowed_operation_evidence_types_restriction(self):
        """Validate ALLOWED_PRIMARY_OPERATION_EVIDENCE_TYPES and ALLOWED_DERIVED_OPERATION_EVIDENCE_TYPES."""
        # 1. Disallowed primary type sharing capture operation ID
        bad_prim = EvidenceRecord(
            evidence_id="ev_bad_prim",
            evidence_type=EVIDENCE_TYPE_INFERENCE,  # INFERENCE is derived-only, not allowed as primary
            nature="inference",
            session_id="test-session-001",
            target_identity={"pid": 1234, "process_identity": "proc-a", "executable_identity": "/bin/app"},
            details={"operation_id": "op_type_test_01"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(bad_prim)
        self.assertIn("not permitted as primary record", str(ctx.exception))

        # 2. Allowed primary type succeeds
        good_prim = self._create_primary_record("ev_good_prim", "op_type_test_02")
        self.ledger.add_record(good_prim)

        # 3. Disallowed derived type sharing capture operation ID
        bad_derived = EvidenceRecord(
            evidence_id="ev_bad_derived",
            evidence_type=EVIDENCE_TYPE_CAPTURE_QUALITY,  # CAPTURE_QUALITY is primary-only, not allowed as derived
            nature="observation",
            session_id="test-session-001",
            target_identity={"pid": 1234, "process_identity": "proc-a", "executable_identity": "/bin/app", "target_host": "host-1"},
            parent_evidence_ids=["ev_good_prim"],
            details={"operation_id": "op_type_test_02", "derived_from": "ev_good_prim"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(bad_derived)
        self.assertIn("not permitted to share capture operation ID", str(ctx.exception))

        # 4. Allowed derived type succeeds
        good_derived = EvidenceRecord(
            evidence_id="ev_good_derived",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            session_id="test-session-001",
            target_identity={"pid": 1234, "process_identity": "proc-a", "executable_identity": "/bin/app", "target_host": "host-1"},
            parent_evidence_ids=["ev_good_prim"],
            details={"operation_id": "op_type_test_02", "derived_from": "ev_good_prim"},
        )
        added_derived = self.ledger.add_record(good_derived)
        self.assertEqual(added_derived.evidence_id, "ev_good_derived")

    def test_trust_store_bind_operation_evidence_parent_digest(self):
        """Verify trust store enforces parent evidence digest consistency in bind_operation_evidence."""
        op_id = "op_trust_store_bind_01"
        self.trust_store.record_used_operation(op_id=op_id, session_id="test-session-001", pid=1234)

        # Primary bind
        self.trust_store.bind_operation_evidence(op_id, "ev_primary_1")

        # Valid derived bind with parent digest
        self.trust_store.bind_operation_evidence(
            op_id,
            "ev_derived_1",
            derived_from="ev_primary_1",
            parent_evidence_ids=["ev_primary_1"],
            parent_evidence_digest="sha256:parent_dig_aaa",
        )

        # Conflicting parent digest for same derived evidence
        with self.assertRaises(ValueError) as ctx:
            self.trust_store.bind_operation_evidence(
                op_id,
                "ev_derived_1",
                derived_from="ev_primary_1",
                parent_evidence_ids=["ev_primary_1"],
                parent_evidence_digest="sha256:conflicting_parent_dig_bbb",
            )
        self.assertIn("Conflicting parent digest", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
