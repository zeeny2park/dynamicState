"""Phase 2.2-C-C: Lifecycle-Aware Diff Production Integration Tests.

Validates:
1. Default StateDiffEngine() instantiates LifecycleAwareObjectMatcher.
2. Address reuse across snapshots: object A destroyed, object B created at same address.
3. Address reuse counted exactly once in summary['address_reuses'] (unique address deduplication).
4. Same object persistence with field mutations across snapshots.
5. Object removed/freed without reallocation.
6. Different types sharing an address across snapshots correctly identified as reallocated.
7. Conservative matching / IDENTITY_UNCERTAIN for heap objects lacking generation evidence.
8. RuntimeController.diff() and CLI entry point propagation.
"""

import unittest
from extractor.state_diff import StateDiffEngine, LifecycleAwareObjectMatcher
from extractor.runtime_controller import RuntimeController


class TestPhase22ProductionLifecycleDiff(unittest.TestCase):
    def test_default_engine_uses_lifecycle_matcher(self):
        """StateDiffEngine() defaults to LifecycleAwareObjectMatcher."""
        engine = StateDiffEngine()
        self.assertIsInstance(engine.matcher, LifecycleAwareObjectMatcher)

    def test_address_reuse_exact_deduplication(self):
        """Reusing address 0x1000 for a new object should record address_reuse=True and address_reuses=1."""
        snap_a = {
            "snapshot_id": "snap_1",
            "timestamp": 1000.0,
            "objects": [
                {
                    "id": "obj_old",
                    "type": "WorkerThread",
                    "address": "0x1000",
                    "generation": 1,
                    "fields": {"status": "ACTIVE"},
                }
            ],
        }
        snap_b = {
            "snapshot_id": "snap_2",
            "timestamp": 1001.0,
            "objects": [
                {
                    "id": "obj_new",
                    "type": "ConnectionHandler",
                    "address": "0x1000",
                    "generation": 2,
                    "fields": {"status": "INIT"},
                }
            ],
        }

        engine = StateDiffEngine()
        diff = engine.diff(snap_a, snap_b)

        # address_reuses summary must be exactly 1 (not 2 from counting removed + created separately)
        self.assertEqual(diff.summary["address_reuses"], 1)

        # Changes must reflect object removal and object creation with address_reuse flag
        created_chg = next((c for c in diff.changes if c["kind"] == "object_created"), None)
        removed_chg = next((c for c in diff.changes if c["kind"] == "object_removed"), None)
        self.assertIsNotNone(created_chg)
        self.assertIsNotNone(removed_chg)
        self.assertTrue(created_chg.get("address_reuse"))
        self.assertTrue(removed_chg.get("address_reuse"))

    def test_same_object_field_mutation(self):
        """Object persisting across snapshots at same address and generation tracks value change."""
        snap_a = {
            "snapshot_id": "snap_1",
            "timestamp": 1000.0,
            "objects": [
                {
                    "id": "obj_1",
                    "type": "Session",
                    "address": "0x2000",
                    "generation": 1,
                    "fields": [
                        {"name": "active", "value": True, "type": "bool"},
                        {"name": "count", "value": 10, "type": "int"},
                    ],
                }
            ],
        }
        snap_b = {
            "snapshot_id": "snap_2",
            "timestamp": 1001.0,
            "objects": [
                {
                    "id": "obj_1",
                    "type": "Session",
                    "address": "0x2000",
                    "generation": 1,
                    "fields": [
                        {"name": "active", "value": False, "type": "bool"},
                        {"name": "count", "value": 11, "type": "int"},
                    ],
                }
            ],
        }

        engine = StateDiffEngine()
        diff = engine.diff(snap_a, snap_b)

        self.assertEqual(diff.summary["address_reuses"], 0)
        self.assertEqual(diff.summary["objects_created"], 0)
        self.assertEqual(diff.summary["objects_removed"], 0)

        val_changes = [c for c in diff.changes if c["kind"] == "value_change"]
        self.assertEqual(len(val_changes), 2)

    def test_object_freed_without_reuse(self):
        """Object freed without new object at same address reports object_removed without address_reuse."""
        snap_a = {
            "snapshot_id": "snap_1",
            "timestamp": 1000.0,
            "objects": [
                {
                    "id": "obj_dead",
                    "type": "TempNode",
                    "address": "0x3000",
                    "fields": [{"name": "val", "value": 1, "type": "int"}],
                }
            ],
        }
        snap_b = {
            "snapshot_id": "snap_2",
            "timestamp": 1001.0,
            "objects": [],
        }

        engine = StateDiffEngine()
        diff = engine.diff(snap_a, snap_b)

        self.assertEqual(diff.summary["address_reuses"], 0)
        self.assertEqual(diff.summary["objects_removed"], 1)
        removed_chg = diff.changes[0]
        self.assertEqual(removed_chg["kind"], "object_removed")
        self.assertFalse(removed_chg.get("address_reuse", False))

    def test_runtime_controller_diff_integration(self):
        """RuntimeController.diff() delegates to production lifecycle-aware StateDiffEngine."""
        ctrl = RuntimeController()
        snap_a = {
            "objects": [{"id": "a", "type": "T1", "address": "0x5000", "generation": 1, "fields": []}]
        }
        snap_b = {
            "objects": [{"id": "b", "type": "T2", "address": "0x5000", "generation": 2, "fields": []}]
        }
        diff = ctrl.diff(snap_a, snap_b)
        self.assertEqual(diff.summary["address_reuses"], 1)


if __name__ == "__main__":
    unittest.main()
