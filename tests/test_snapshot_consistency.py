"""Unit tests for snapshot consistency model and metadata."""

import unittest

from extractor.snapshot_consistency import (
    ATOMIC,
    COOPERATIVE,
    NON_ATOMIC,
    NON_ATOMIC_WARNING,
    STOPPED,
    SnapshotConsistency,
)


class SnapshotConsistencyTests(unittest.TestCase):
    def test_default_consistency_level(self):
        c = SnapshotConsistency()
        self.assertEqual(c.level, NON_ATOMIC)
        self.assertEqual(c.warning, NON_ATOMIC_WARNING)
        d = c.to_dict()
        self.assertEqual(d["level"], "NON_ATOMIC")
        self.assertIn("not a globally consistent", d["warning"])

    def test_valid_levels_and_serialization(self):
        for lvl in [NON_ATOMIC, COOPERATIVE, STOPPED, ATOMIC]:
            c = SnapshotConsistency(level=lvl, duration_us=123.456, partial_reads=1)
            self.assertEqual(c.level, lvl)
            d = c.to_dict()
            c2 = SnapshotConsistency.from_dict(d)
            self.assertEqual(c2.level, lvl)
            self.assertEqual(c2.duration_us, 123.456)
            self.assertEqual(c2.partial_reads, 1)

    def test_invalid_level_raises(self):
        with self.assertRaises(ValueError):
            SnapshotConsistency(level="MAGIC_ATOMIC")


if __name__ == "__main__":
    unittest.main()
