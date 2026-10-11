"""Automated tests for Semantic Observation Comparison.

Tests acceptance criterion 5:
5. Semantic comparison across two snapshots, including missing objects and changed fields.
"""

import os
import shutil
import tempfile
import unittest

from extractor.evidence_ledger import EVIDENCE_TYPE_COMPARISON
from extractor.investigation import InvestigationManager
from extractor.snapshot import RuntimeSnapshot
from extractor.snapshot_consistency import NON_ATOMIC, STOPPED


class TestInvestigationComparison(unittest.TestCase):
    """Test cross-snapshot semantic comparison, uncertainty tracking, and findings generation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="dynstate_cmp_test_")
        self.mgr = InvestigationManager(corpus_dir=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_semantic_comparison_changed_fields_and_missing_objects(self):
        # Create Snapshot A (Parent)
        snap_a = {
            "snapshot_id": "snap_alpha",
            "timestamp": "2026-10-11T00:00:00Z",
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_session",
                        "type": "Session",
                        "address": 0x1000,
                        "fields": [
                            {"name": "status", "type": "int", "value": 1},
                            {"name": "worker_count", "type": "int", "value": 2},
                        ],
                    },
                    {
                        "object_id": "obj_worker_to_be_deleted",
                        "type": "Worker",
                        "address": 0x2000,
                        "fields": [
                            {"name": "id", "type": "int", "value": 99},
                        ],
                    },
                ]
            },
            "execution": {"threads": []},
            "consistency": {"level": STOPPED},
        }

        # Create Snapshot B (Child - with field value change, deleted object, and added object)
        snap_b = {
            "snapshot_id": "snap_beta",
            "timestamp": "2026-10-11T00:01:00Z",
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_session",
                        "type": "Session",
                        "address": 0x1000,
                        "fields": [
                            {"name": "status", "type": "int", "value": 2},  # Modified value
                            {"name": "worker_count", "type": "int", "value": 3},  # Modified value
                        ],
                    },
                    {
                        "object_id": "obj_worker_new",
                        "type": "Worker",
                        "address": 0x3000,  # Added object
                        "fields": [
                            {"name": "id", "type": "int", "value": 100},
                        ],
                    },
                ]
            },
            "execution": {"threads": []},
            "consistency": {"level": NON_ATOMIC},  # Triggers uncertainty note!
        }

        # Save snapshots in corpus
        self.mgr.corpus.add(snap_a)
        self.mgr.corpus.add(snap_b)

        # Start an investigation
        session_info = self.mgr.start_investigation(
            goal="Investigate state transition between alpha and beta",
            snapshot_id="snap_alpha",
        )
        inv_id = session_info["investigation_id"]

        # Run comparison
        res = self.mgr.compare_observations(inv_id, "snap_alpha", "snap_beta")

        # Verify summary
        summary = res["summary"]
        self.assertEqual(summary["value_changes"], 2)
        self.assertEqual(summary["objects_created"], 1)
        self.assertEqual(summary["objects_removed"], 1)

        # Verify uncertainty tracking due to NON_ATOMIC snapshot
        self.assertIsNotNone(res["uncertainty"])
        self.assertIn("non-atomically", res["uncertainty"])

        # Verify comparison evidence in ledger
        evidence_id = res["evidence_id"]
        ev = self.mgr.sessions[inv_id].ledger.get_record(evidence_id)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.evidence_type, EVIDENCE_TYPE_COMPARISON)
        self.assertEqual(ev.nature, "observation")
        self.assertEqual(ev.comparison_observation["summary"]["value_changes"], 2)

        # Verify findings generated for value changes
        findings = self.mgr.sessions[inv_id].findings
        fact_findings = [f for f in findings if f.category == "fact" and "value change" in f.title.lower()]
        self.assertGreaterEqual(len(fact_findings), 2)
        paths = [f.c_type_path for f in fact_findings]
        self.assertIn("Session.status", paths)
        self.assertIn("Session.worker_count", paths)

    def test_identical_snapshots_comparison(self):
        snap = {
            "snapshot_id": "snap_same",
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_1",
                        "type": "Data",
                        "address": 0x4000,
                        "fields": [{"name": "val", "type": "int", "value": 10}],
                    }
                ]
            },
            "execution": {"threads": []},
            "consistency": {"level": STOPPED},
        }
        self.mgr.corpus.add(snap)

        session_info = self.mgr.start_investigation(
            goal="Verify identical snapshot comparison",
            snapshot_id="snap_same",
        )
        inv_id = session_info["investigation_id"]

        res = self.mgr.compare_observations(inv_id, "snap_same", "snap_same")
        self.assertEqual(res["summary"]["value_changes"], 0)
        self.assertEqual(res["summary"]["objects_created"], 0)
        self.assertEqual(res["summary"]["objects_removed"], 0)
        self.assertIsNone(res["uncertainty"])


if __name__ == "__main__":
    unittest.main()
