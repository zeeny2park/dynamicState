#!/usr/bin/env python3
"""
Unit tests for Phase 2.0-A.3.19: Strict Operation Metadata Reconstruction (P0-3).

Validates:
- Detection of missing canonical metadata fields in serialized used_operation_ids.
- Detection of conflicting metadata across canonical fields.
- Rejection of unexpected/rogue metadata fields in serialized used_operation_ids.
- Rejection of duplicate evidence IDs in serialized used_operation_ids["evidence_ids"].
- Strict equality check of canonical ordered evidence IDs list.
"""

import copy
import unittest

from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
)


class TestStrictOperationMetadataReconstruction(unittest.TestCase):
    def setUp(self):
        self.session_id = "test-session-strict-recon"
        self.ledger = EvidenceLedger(session_id=self.session_id)

        # Primary record
        self.rec1 = EvidenceRecord(
            evidence_id="ev_strict_01",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature="observation",
            session_id=self.session_id,
            timestamp="2026-11-07T12:00:00Z",
            target_identity={
                "pid": 54321,
                "process_identity": "worker-proc",
                "executable_identity": "/usr/bin/app",
                "build_id": "build-abc-999",
                "target_host": "node-42",
            },
            object_observation={"obj_ptr": "0x5555", "type_name": "TaskQueue"},
            details={
                "operation_id": "op_strict_999",
                "receipt_id": "rcpt_strict_001",
                "observation_digest": "sha256:obs_dig_primary",
                "operation_type": "capture",
                "field_path": "TaskQueue.items",
            },
        )
        self.ledger.add_record(self.rec1)

        # Derived record
        self.rec2 = EvidenceRecord(
            evidence_id="ev_strict_02",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature="observation",
            session_id=self.session_id,
            timestamp="2026-11-07T12:00:01Z",
            target_identity={
                "pid": 54321,
                "process_identity": "worker-proc",
                "executable_identity": "/usr/bin/app",
                "build_id": "build-abc-999",
                "target_host": "node-42",
            },
            field_observation={"field_name": "items", "field_value": 5},
            parent_evidence_ids=["ev_strict_01"],
            details={
                "operation_id": "op_strict_999",
                "derived_from": "ev_strict_01",
                "receipt_id": "rcpt_strict_001",
                "observation_digest": "sha256:obs_dig_primary",
                "operation_type": "capture",
            },
        )
        self.ledger.add_record(self.rec2)

        # Base serialized dict
        self.base_dict = self.ledger.to_dict()

    def test_clean_roundtrip_reconstruction(self):
        """Authoritative rebuild from validated records matches valid serialized data."""
        rebuilt = EvidenceLedger.from_dict(copy.deepcopy(self.base_dict))
        self.assertEqual(len(rebuilt._records), 2)
        self.assertIn("op_strict_999", rebuilt._used_operation_ids)
        self.assertEqual(
            rebuilt._used_operation_ids["op_strict_999"]["evidence_ids"],
            ["ev_strict_01", "ev_strict_02"],
        )

    def test_missing_canonical_metadata_detection(self):
        """Reject serialized used_operation_ids missing any canonical metadata field."""
        canonical_fields = [
            "session_id",
            "pid",
            "process_identity",
            "executable_identity",
            "build_id",
            "target_host",
            "receipt_id",
            "observation_digest",
            "operation_type",
            "evidence_id",
            "recorded_at",
        ]

        for field in canonical_fields:
            with self.subTest(missing_field=field):
                data = copy.deepcopy(self.base_dict)
                op_entry = data["used_operation_ids"]["op_strict_999"]
                # Remove field or set to None
                op_entry.pop(field, None)

                with self.assertRaises(ValueError) as ctx:
                    EvidenceLedger.from_dict(data)
                self.assertIn("Missing canonical metadata field", str(ctx.exception))
                self.assertIn(field, str(ctx.exception))

    def test_conflicting_metadata_detection(self):
        """Reject serialized used_operation_ids with conflicting canonical field values."""
        conflicts = {
            "session_id": "forged-session-id",
            "pid": 99999,
            "process_identity": "forged-proc",
            "executable_identity": "/bin/forged",
            "build_id": "forged-build",
            "target_host": "forged-node",
            "receipt_id": "rcpt_forged_999",
            "observation_digest": "sha256:forged_dig",
            "operation_type": "forged_probe",
            "evidence_id": "ev_forged_root",
            "recorded_at": "1999-01-01T00:00:00Z",
        }

        for field, bad_val in conflicts.items():
            with self.subTest(conflict_field=field):
                data = copy.deepcopy(self.base_dict)
                data["used_operation_ids"]["op_strict_999"][field] = bad_val

                with self.assertRaises(ValueError) as ctx:
                    EvidenceLedger.from_dict(data)
                self.assertTrue(
                    "conflict" in str(ctx.exception).lower()
                    or "mismatch" in str(ctx.exception).lower()
                    or "inconsistency" in str(ctx.exception).lower()
                )

    def test_unexpected_metadata_field_rejection(self):
        """Reject unexpected/unknown metadata fields in serialized used_operation_ids."""
        data = copy.deepcopy(self.base_dict)
        data["used_operation_ids"]["op_strict_999"]["rogue_injected_attribute"] = "malicious_payload"

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data)
        self.assertIn("Unexpected metadata field 'rogue_injected_attribute'", str(ctx.exception))

    def test_duplicate_evidence_id_in_used_operations_rejection(self):
        """Reject duplicate evidence IDs in serialized used_operation_ids['evidence_ids']."""
        data = copy.deepcopy(self.base_dict)
        data["used_operation_ids"]["op_strict_999"]["evidence_ids"] = [
            "ev_strict_01",
            "ev_strict_01",
        ]

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data)
        self.assertIn("Duplicate evidence ID detected in used_operation_ids", str(ctx.exception))

    def test_ordered_evidence_ids_mismatch_rejection(self):
        """Reject serialized used_operation_ids['evidence_ids'] when order is changed."""
        data = copy.deepcopy(self.base_dict)
        data["used_operation_ids"]["op_strict_999"]["evidence_ids"] = [
            "ev_strict_02",
            "ev_strict_01",
        ]

        with self.assertRaises(ValueError) as ctx:
            EvidenceLedger.from_dict(data)
        self.assertIn("Canonical ordered evidence_ids mismatch", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
