"""Phase 2.2-D Temporal Object Identity Integration Tests (GAP-P2-01).

Validates:
1. Same object across snapshots maintains identity and tracks field deltas.
2. Object freed between snapshots correctly reports object_removed.
3. Different object allocated at same address (address reuse) detects destruction & reallocation.
4. Heap object without allocation lifecycle evidence reports IDENTITY_UNCERTAIN.
5. Different object types allocated at same address correctly detects address reuse across types.
"""

import unittest
from extractor.state_diff import StateDiffEngine, LifecycleAwareObjectMatcher, AddressTypeObjectMatcher


class TestPhase22TemporalObjectIdentity(unittest.TestCase):
    def setUp(self):
        self.engine = StateDiffEngine(matcher=LifecycleAwareObjectMatcher())

    def test_same_object_across_snapshots(self):
        """Identical object across snapshots tracks field mutation without address reuse."""
        snap_a = {
            "objects": [
                {
                    "object_id": "obj_001",
                    "type": "WorkerContext",
                    "address": 0x1000,
                    "storage": "heap",
                    "allocation_id": "alloc_epoch_100",
                    "fields": [{"name": "tasks_completed", "value": 10}],
                }
            ]
        }
        snap_b = {
            "objects": [
                {
                    "object_id": "obj_001",
                    "type": "WorkerContext",
                    "address": 0x1000,
                    "storage": "heap",
                    "allocation_id": "alloc_epoch_100",
                    "fields": [{"name": "tasks_completed", "value": 15}],
                }
            ]
        }
        diff = self.engine.diff(snap_a, snap_b)
        self.assertEqual(diff.summary["objects_created"], 0)
        self.assertEqual(diff.summary["objects_removed"], 0)
        self.assertEqual(diff.summary["value_changes"], 1)
        self.assertEqual(diff.summary["address_reuses"], 0)

        chg = diff.changes[0]
        self.assertEqual(chg["kind"], "value_change")
        self.assertEqual(chg["before"], 10)
        self.assertEqual(chg["after"], 15)
        self.assertEqual(chg["identity_status"], "IDENTITY_CONFIRMED")
        self.assertEqual(chg["identity_confidence"], "high")

    def test_object_freed_between_snapshots(self):
        """Object present in snapshot A but absent in snapshot B is reported as removed."""
        snap_a = {
            "objects": [
                {
                    "object_id": "obj_001",
                    "type": "Connection",
                    "address": 0x2000,
                    "storage": "heap",
                    "fields": [{"name": "fd", "value": 5}],
                }
            ]
        }
        snap_b = {
            "objects": []
        }
        diff = self.engine.diff(snap_a, snap_b)
        self.assertEqual(diff.summary["objects_removed"], 1)
        self.assertEqual(diff.summary["objects_created"], 0)
        chg = diff.changes[0]
        self.assertEqual(chg["kind"], "object_removed")
        self.assertEqual(chg["address"], 0x2000)

    def test_address_reuse_same_type_reallocated(self):
        """Object freed and new object of same type allocated at same address is recognized as reallocation."""
        snap_a = {
            "objects": [
                {
                    "object_id": "obj_001",
                    "type": "Buffer",
                    "address": 0x3000,
                    "storage": "heap",
                    "allocation_id": "gen_1",
                    "fields": [{"name": "capacity", "value": 1024}],
                }
            ]
        }
        snap_b = {
            "objects": [
                {
                    "object_id": "obj_002",
                    "type": "Buffer",
                    "address": 0x3000,
                    "storage": "heap",
                    "allocation_id": "gen_2",  # Different lifecycle counter!
                    "fields": [{"name": "capacity", "value": 4096}],
                }
            ]
        }
        diff = self.engine.diff(snap_a, snap_b)
        self.assertEqual(diff.summary["address_reuses"], 1)

        # Must detect object reallocation, not a simple field mutation!
        realloc_chg = next((c for c in diff.changes if c["kind"] == "object_reallocated_at_same_address"), None)
        self.assertIsNotNone(realloc_chg)
        self.assertTrue(realloc_chg.get("address_reuse"))
        self.assertEqual(realloc_chg.get("identity_status"), "DESTROYED_AND_REALLOCATED")
        self.assertEqual(realloc_chg.get("before_allocation_id"), "gen_1")
        self.assertEqual(realloc_chg.get("after_allocation_id"), "gen_2")

    def test_address_reuse_different_type(self):
        """Different types at the exact same address detect address reuse."""
        snap_a = {
            "objects": [
                {
                    "object_id": "obj_old",
                    "type": "UserSession",
                    "address": 0x4000,
                    "storage": "heap",
                }
            ]
        }
        snap_b = {
            "objects": [
                {
                    "object_id": "obj_new",
                    "type": "PacketHeader",
                    "address": 0x4000,
                    "storage": "heap",
                }
            ]
        }
        diff = self.engine.diff(snap_a, snap_b)
        self.assertEqual(diff.summary["address_reuses"], 1)  # Distinct address reuse count
        new_chg = next((c for c in diff.changes if c["kind"] == "object_created"), None)
        self.assertIsNotNone(new_chg)
        self.assertTrue(new_chg.get("address_reuse"))
        self.assertEqual(new_chg.get("identity_status"), "ADDRESS_REUSED_DIFFERENT_TYPE")

    def test_heap_object_without_lifecycle_evidence_is_uncertain(self):
        """Heap object without allocation evidence is truthfully reported as IDENTITY_UNCERTAIN."""
        snap_a = {
            "objects": [
                {
                    "object_id": "obj_anon",
                    "type": "Packet",
                    "address": 0x5000,
                    "storage": "heap",
                    "fields": [{"name": "seq", "value": 1}],
                }
            ]
        }
        snap_b = {
            "objects": [
                {
                    "object_id": "obj_anon",
                    "type": "Packet",
                    "address": 0x5000,
                    "storage": "heap",
                    "fields": [{"name": "seq", "value": 2}],
                }
            ]
        }
        diff = self.engine.diff(snap_a, snap_b)
        self.assertGreater(diff.summary["identity_ambiguities"], 0)
        chg = diff.changes[0]
        self.assertEqual(chg["identity_status"], "IDENTITY_UNCERTAIN")
        self.assertEqual(chg["identity_confidence"], "uncertain")


if __name__ == "__main__":
    unittest.main()
