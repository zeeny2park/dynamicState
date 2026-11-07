"""Phase 2.0-A.3.15 Evidence-to-Operation Provenance Closure Tests.

Verifies:
1. Immutable operation identity for every physical observation.
2. Bind each receipt to exactly one committed operation.
3. Multiple records for the same operation are rejected without validated derivation.
4. Validated derived records require existing source record in ledger, in parent_evidence_ids, and matching operation.
5. Operation-to-evidence and operation-to-receipt mappings are preserved and revalidated across to_dict() / from_dict().
"""

import unittest
from datetime import datetime, timezone

from extractor.capture_backend import (
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)


class TestPhase20A315OperationProvenance(unittest.TestCase):
    def setUp(self):
        self.session_id = "sess_a315_op"
        self.pid = 9301
        self.target_identity = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:123456:boot_uuid",
            "start_time": "123456",
            "executable": "/usr/bin/service_a315_op",
            "executable_identity": f"/usr/bin/service_a315_op:{self.pid}",
            "build_id": "sha1:build_a315_op",
            "target_host": "localhost",
        }
        self.ledger = EvidenceLedger(session_id=self.session_id)

    # 1. Primary source observation succeeds and binds receipt to operation
    def test_01_primary_source_observation_binds_operation_and_receipt(self):
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_op_01",
            capture_epoch=1,
            physical_bytes_read=128,
            physical_reads_count=2,
            operation_id="op_primary_01",
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        rec = EvidenceRecord(
            evidence_id="ev_prim_01",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Primary memory slice observation",
            target_identity=self.target_identity,
            session_id=self.session_id,
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt.to_dict(),
            },
            details={"operation_id": "op_primary_01", "field_path": "slice.field_a"},
        )
        self.ledger.add_record(rec)

        # Verified mappings in ledger
        self.assertEqual(self.ledger._operation_to_receipt_id.get("op_primary_01"), rcpt.receipt_id)
        self.assertEqual(self.ledger._operation_to_evidence_ids.get("op_primary_01"), ["ev_prim_01"])

    # 2. Second unrelated record attempting to reuse the same operation/receipt without derivation is rejected
    def test_02_unrelated_record_reusing_operation_rejected(self):
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_op_02",
            capture_epoch=1,
            physical_bytes_read=128,
            physical_reads_count=2,
            operation_id="op_reuse_02",
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        rec1 = EvidenceRecord(
            evidence_id="ev_source_02",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="First observation from op_reuse_02",
            target_identity=self.target_identity,
            session_id=self.session_id,
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt.to_dict(),
            },
            details={"operation_id": "op_reuse_02", "field_path": "slice.field_a"},
        )
        self.ledger.add_record(rec1)

        # Unrelated second record claims same operation without derivation
        rec2 = EvidenceRecord(
            evidence_id="ev_unrelated_02",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Unrelated second observation trying to reuse op_reuse_02",
            target_identity=self.target_identity,
            session_id=self.session_id,
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt.to_dict(),
            },
            details={"operation_id": "op_reuse_02", "field_path": "slice.field_b"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec2)
        self.assertIn("replay detected", str(ctx.exception).lower())

    # 3. Validated derived record for extracted field from same physical read succeeds
    def test_03_validated_derivation_from_source_observation_succeeds(self):
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_op_03",
            capture_epoch=1,
            physical_bytes_read=256,
            physical_reads_count=1,
            operation_id="op_derivation_03",
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        rec_src = EvidenceRecord(
            evidence_id="ev_slice_03",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Root physical memory capture slice (256 bytes)",
            target_identity=self.target_identity,
            session_id=self.session_id,
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt.to_dict(),
            },
            details={"operation_id": "op_derivation_03", "field_path": "memory.root"},
        )
        self.ledger.add_record(rec_src)

        # Derived field extracted from root slice
        rec_derived = EvidenceRecord(
            evidence_id="ev_field_derived_03",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Field 2 extracted from root slice",
            target_identity=self.target_identity,
            session_id=self.session_id,
            parent_evidence_ids=["ev_slice_03"],
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt.to_dict(),
            },
            details={
                "operation_id": "op_derivation_03",
                "derived_from": "ev_slice_03",
                "field_path": "memory.field_2",
            },
        )
        self.ledger.add_record(rec_derived)

        # Both records are tracked under the same operation
        op_evidence = self.ledger._operation_to_evidence_ids["op_derivation_03"]
        self.assertEqual(op_evidence, ["ev_slice_03", "ev_field_derived_03"])

    # 4. Caller-controlled derived_from with nonexistent source is rejected
    def test_04_derived_from_nonexistent_source_rejected(self):
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_op_04",
            capture_epoch=1,
            physical_bytes_read=64,
            physical_reads_count=1,
            operation_id="op_fake_derived_04",
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        rec = EvidenceRecord(
            evidence_id="ev_fake_child",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Trying to claim derivation from phantom source",
            target_identity=self.target_identity,
            session_id=self.session_id,
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": rcpt.to_dict(),
            },
            details={"operation_id": "op_fake_derived_04", "derived_from": "ev_phantom_parent"},
        )
        with self.assertRaises(ValueError) as ctx:
            self.ledger.add_record(rec)
        self.assertIn("nonexistent source observation", str(ctx.exception).lower())

    # 5. Serialization and deserialization preserves and revalidates operation mappings
    def test_05_serialization_preserves_operation_provenance(self):
        rcpt = issue_live_capture_receipt(
            session_id=self.session_id,
            pid=self.pid,
            process_identity=self.target_identity["process_identity"],
            executable_identity=self.target_identity["executable_identity"],
            build_id=self.target_identity["build_id"],
            snapshot_binding="snap_op_05",
            capture_epoch=1,
            physical_bytes_read=128,
            physical_reads_count=1,
            operation_id="op_durable_05",
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        r1 = EvidenceRecord(
            evidence_id="ev_durable_root",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Root observation",
            target_identity=self.target_identity,
            session_id=self.session_id,
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict()},
            details={"operation_id": "op_durable_05", "field_path": "root"},
        )
        r2 = EvidenceRecord(
            evidence_id="ev_durable_child",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Derived observation",
            target_identity=self.target_identity,
            session_id=self.session_id,
            parent_evidence_ids=["ev_durable_root"],
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict()},
            details={"operation_id": "op_durable_05", "derived_from": "ev_durable_root", "field_path": "child"},
        )
        self.ledger.add_record(r1)
        self.ledger.add_record(r2)

        data = self.ledger.to_dict()
        self.assertIn("operation_to_evidence_ids", data)
        self.assertIn("operation_to_receipt_id", data)

        reconstructed = EvidenceLedger.from_dict(data)
        self.assertEqual(len(reconstructed.records), 2)
        self.assertEqual(reconstructed._operation_to_receipt_id.get("op_durable_05"), rcpt.receipt_id)
        self.assertEqual(reconstructed._operation_to_evidence_ids.get("op_durable_05"), ["ev_durable_root", "ev_durable_child"])


if __name__ == "__main__":
    unittest.main()
