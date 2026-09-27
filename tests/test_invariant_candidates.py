"""Unit tests for Phase 5 InvariantDetector."""

import unittest

from extractor.invariant_detector import InvariantDetector


class InvariantDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = InvariantDetector()

    def test_detect_structural_bounds_and_range(self):
        snapshot = {
            "snapshot_id": "S001",
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_0001",
                        "type": "Session",
                        "fields": [
                            {"name": "retry", "type": "uint32_t", "value": 2},
                            {"name": "packet_count", "type": "uint32_t", "value": 10},
                            {"name": "buffer", "type": "Buffer*", "value": "0x1000", "object_ref": "obj_0002"},
                        ]
                    },
                    {
                        "object_id": "obj_0002",
                        "type": "Buffer",
                        "fields": [
                            {"name": "length", "type": "uint32_t", "value": 64},
                            {"name": "capacity", "type": "uint32_t", "value": 256},
                            {"name": "data", "type": "char*", "value": "0x2000"},
                        ]
                    }
                ]
            }
        }

        candidates = self.detector.detect(snapshot)
        self.assertGreaterEqual(len(candidates), 3)

        expressions = [c.expression for c in candidates]

        # 1. Bounds candidate
        self.assertIn("Buffer.length <= Buffer.capacity", expressions)
        bound_cand = next(c for c in candidates if c.expression == "Buffer.length <= Buffer.capacity")
        self.assertEqual(bound_cand.category, "bounds")
        self.assertEqual(bound_cand.status, "unconfirmed_candidate")
        self.assertEqual(bound_cand.type, "invariant_candidate")

        # 2. Range candidate
        self.assertIn("Session.retry >= 0", expressions)
        range_cand = next(c for c in candidates if c.expression == "Session.retry >= 0")
        self.assertEqual(range_cand.category, "range")

        # 3. Pointer validity candidate
        self.assertIn("Session.buffer != nullptr", expressions)


if __name__ == "__main__":
    unittest.main()
