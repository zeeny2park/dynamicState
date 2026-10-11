"""Automated tests for Evidence Schema, Versioning, Provenance, and Capture Quality.

Tests acceptance criteria 1, 2, and 3:
1. Evidence schema validation, versioning, and missing optional fields.
2. Provenance links from finding -> object/field -> snapshot/artifact.
3. Honest handling of partial/non-atomic captures and missing data.
"""

import json
import unittest

from extractor.evidence_ledger import (
    EVIDENCE_SCHEMA_VERSION,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_HYPOTHESIS,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
)
from extractor.snapshot_consistency import NON_ATOMIC, STOPPED, SnapshotConsistency


class TestEvidenceSchema(unittest.TestCase):
    """Test schema validation, versioning, and missing optional fields."""

    def test_schema_version_and_defaults(self):
        record = EvidenceRecord(
            evidence_id="ev_001",
            evidence_type=EVIDENCE_TYPE_RUNTIME_IDENTITY,
            source="test_source",
            observation="Observed executable identity",
        )
        self.assertEqual(record.schema_version, EVIDENCE_SCHEMA_VERSION)
        self.assertEqual(record.nature, NATURE_OBSERVATION)
        self.assertTrue(len(record.timestamp) > 0)

        # Serialization
        data = record.to_dict()
        self.assertEqual(data["schema_version"], "1.0.0")
        self.assertEqual(data["evidence_id"], "ev_001")
        # Ensure optional fields that are None are omitted
        self.assertNotIn("session_id", data)
        self.assertNotIn("target_identity", data)

        # Deserialization
        reconstructed = EvidenceRecord.from_dict(data)
        self.assertEqual(reconstructed.evidence_id, "ev_001")
        self.assertEqual(reconstructed.evidence_type, EVIDENCE_TYPE_RUNTIME_IDENTITY)

    def test_backward_compatibility_missing_fields(self):
        # Emulate older schema payload with minimal fields
        old_payload = {
            "evidence_id": "ev_legacy_42",
            "evidence_type": "OBJECT_STATE",
            "observation": "Legacy snapshot observation",
        }
        record = EvidenceRecord.from_dict(old_payload)
        self.assertEqual(record.evidence_id, "ev_legacy_42")
        self.assertEqual(record.nature, NATURE_OBSERVATION)
        self.assertEqual(record.source, "unknown")
        self.assertIsNone(record.target_identity)
        self.assertIsNone(record.static_code_link)

    def test_nature_classification_distinguishes_observation_from_inference(self):
        obs_rec = EvidenceRecord(
            evidence_id="ev_obs_1",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            observation="Observed counter value = 42 directly in memory",
        )
        inf_rec = EvidenceRecord(
            evidence_id="ev_inf_1",
            evidence_type=EVIDENCE_TYPE_HYPOTHESIS,
            nature=NATURE_INFERENCE,
            observation="Inferred counter was incremented by worker thread A",
        )
        hypo_rec = EvidenceRecord(
            evidence_id="ev_hypo_1",
            evidence_type=EVIDENCE_TYPE_HYPOTHESIS,
            nature=NATURE_HYPOTHESIS,
            observation="Hypothesized race condition on counter field",
        )

        self.assertEqual(obs_rec.nature, "observation")
        self.assertEqual(inf_rec.nature, "inference")
        self.assertEqual(hypo_rec.nature, "hypothesis")
        self.assertNotEqual(obs_rec.nature, inf_rec.nature)

    def test_invalid_nature_normalizes_safely(self):
        record = EvidenceRecord(
            evidence_id="ev_inv_nature",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature="unsupported_wild_guess",
        )
        self.assertEqual(record.nature, NATURE_OBSERVATION)


class TestEvidenceProvenanceAndLedger(unittest.TestCase):
    """Test provenance tracing and ledger queries."""

    def setUp(self):
        self.ledger = EvidenceLedger(session_id="inv_test_session_1")

    def test_provenance_chain_from_finding_to_artifact(self):
        finding_id = "fnd_counter_drift_01"
        object_id = "obj_worker_01"

        # 1. Identity evidence
        ev_id = self.ledger.add_record(EvidenceRecord(
            evidence_id="ev_target_id",
            evidence_type=EVIDENCE_TYPE_RUNTIME_IDENTITY,
            nature=NATURE_OBSERVATION,
            source="elf_header",
            target_identity={"executable": "/usr/bin/app", "build_id": "abc123def456"},
            provenance={"file": "/usr/bin/app", "offset": 0},
        ))

        # 2. Snapshot capture evidence
        ev_snap = self.ledger.add_record(EvidenceRecord(
            evidence_id="ev_snap_01",
            evidence_type=EVIDENCE_TYPE_CAPTURE_QUALITY,
            nature=NATURE_OBSERVATION,
            source="process_vm_readv",
            snapshot_ref={"snapshot_id": "snap_001", "path": "corpus/memory_snapshots/snap_001"},
            capture_quality={"consistency_level": NON_ATOMIC, "partial_reads": 0},
            provenance={"snapshot_file": "corpus/memory_snapshots/snap_001/manifest.json"},
        ))

        # 3. Object field observation linked to finding
        ev_field = self.ledger.add_record(EvidenceRecord(
            evidence_id="ev_field_obs_01",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="typed_memory_reader",
            finding_id=finding_id,
            object_observation={"object_id": object_id, "type": "Worker", "address": 0x7fffffffe000},
            field_observation={"object_id": object_id, "field": "counter", "value": 999},
            provenance={"memory_region": "0x7fffffffe000-0x7ffffffff000", "offset": 0x18, "snapshot_id": "snap_001"},
        ))

        # Trace provenance chain for finding
        chain = self.ledger.get_provenance_chain(finding_id=finding_id)
        self.assertEqual(len(chain), 1)
        step = chain[0]
        self.assertEqual(step["evidence_id"], "ev_field_obs_01")
        self.assertEqual(step["provenance"]["snapshot_id"], "snap_001")
        self.assertEqual(step["object_info"]["object_id"], object_id)

    def test_ledger_querying_by_type_and_object(self):
        self.ledger.add_record(EvidenceRecord(
            evidence_id="ev_1",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            object_observation={"object_id": "obj_A", "type": "Session"},
        ))
        self.ledger.add_record(EvidenceRecord(
            evidence_id="ev_2",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            field_observation={"object_id": "obj_A", "field": "worker_count", "value": 4},
        ))
        self.ledger.add_record(EvidenceRecord(
            evidence_id="ev_3",
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            object_observation={"object_id": "obj_B", "type": "Worker"},
        ))

        res_a = self.ledger.query(object_id="obj_A")
        self.assertEqual(len(res_a), 2)

        res_types = self.ledger.query(evidence_type=EVIDENCE_TYPE_OBJECT_STATE)
        self.assertEqual(len(res_types), 2)


class TestCaptureQualityAndHonestReporting(unittest.TestCase):
    """Test honest handling of partial / non-atomic captures and missing data."""

    def test_non_atomic_consistency_warning_included(self):
        consistency = SnapshotConsistency(level=NON_ATOMIC, partial_reads=2, failed_reads=1)
        d = consistency.to_dict()
        self.assertEqual(d["level"], "NON_ATOMIC")
        self.assertIsNotNone(d["warning"])
        self.assertIn("not a globally consistent", d["warning"])
        self.assertEqual(d["partial_reads"], 2)
        self.assertEqual(d["failed_reads"], 1)

    def test_evidence_ledger_preserves_capture_limitations(self):
        ledger = EvidenceLedger()
        ev = ledger.add_record(EvidenceRecord(
            evidence_id="ev_cap_qual",
            evidence_type=EVIDENCE_TYPE_CAPTURE_QUALITY,
            nature=NATURE_OBSERVATION,
            source="process_vm_readv",
            capture_quality={
                "consistency_level": NON_ATOMIC,
                "partial_reads": 3,
                "failed_reads": 2,
                "missing_regions_count": 2,
                "limitations": [
                    "process_vm_readv zero-stop capture is potentially NON_ATOMIC across multiple memory regions.",
                    "Stack region of worker thread 3 could not be read (EFAULT).",
                ],
            },
        ))
        self.assertEqual(ev.capture_quality["consistency_level"], NON_ATOMIC)
        self.assertEqual(ev.capture_quality["partial_reads"], 3)
        self.assertEqual(len(ev.capture_quality["limitations"]), 2)
        self.assertIn("EFAULT", ev.capture_quality["limitations"][1])


if __name__ == "__main__":
    unittest.main()
