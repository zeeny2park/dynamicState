"""Unit tests for SnapshotMemoryReader."""

import os
import shutil
import struct
import tempfile
import unittest

from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
from extractor.offline_analyzer import SnapshotMemoryReader


class SnapshotMemoryReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_snap_reader_")
        mem_dir = os.path.join(self.tmp_dir, "memory")
        os.makedirs(mem_dir, exist_ok=True)

        # Prepare synthetic memory block for Region 1: 0x1000 - 0x1100 (256 bytes)
        # Offset 0: int32 (42)
        # Offset 4: uint32 (3000000000)
        # Offset 8: ptr (0x2050)
        # Offset 16: double (3.14159)
        # Offset 24: float (2.718)
        # Offset 28: bool (1)
        # Offset 32: string ("Hello dynamicState\x00")
        buf = bytearray(256)
        struct.pack_into("<i", buf, 0, -42)
        struct.pack_into("<I", buf, 4, 3000000000)
        struct.pack_into("<Q", buf, 8, 0x2050)
        struct.pack_into("<d", buf, 16, 3.14159)
        struct.pack_into("<f", buf, 24, 2.718)
        buf[28] = 1
        buf[32:32 + 19] = b"Hello dynamicState\x00"

        bin_path = os.path.join(mem_dir, "region_000001.bin")
        with open(bin_path, "wb") as f:
            f.write(buf)

        self.region1 = CapturedRegion(
            region_id="R000001",
            start=0x1000,
            end=0x1100,
            size=256,
            permissions="rw-p",
            category="heap",
            pathname="[heap]",
            requested=256,
            captured=256,
            status="COMPLETE",
            filename="memory/region_000001.bin"
        )

        self.raw_snap = RawMemorySnapshot(
            snapshot_id="M_SYNTHETIC",
            pid=1234,
            binary="/bin/test",
            timestamp_ns=1000000,
            output_dir=self.tmp_dir,
            regions=[self.region1]
        )
        self.reader = SnapshotMemoryReader(self.raw_snap)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_read_primitive_types(self):
        # Signed int
        val_i = self.reader.read_int(0x1000, size=4, signed=True)
        self.assertEqual(val_i, -42)

        # Unsigned int
        val_u = self.reader.read_int(0x1004, size=4, signed=False)
        self.assertEqual(val_u, 3000000000)

        # Pointer
        ptr = self.reader.read_ptr(0x1008)
        self.assertEqual(ptr, 0x2050)

        # Double
        val_d = self.reader.read_double(0x1010)
        self.assertAlmostEqual(val_d, 3.14159, places=4)

        # Float
        val_f = self.reader.read_float(0x1018)
        self.assertAlmostEqual(val_f, 2.718, places=3)

        # Bool
        val_b = self.reader.read_bool(0x101C)
        self.assertTrue(val_b)

        # String
        val_s = self.reader.read_string(0x1020)
        self.assertEqual(val_s, "Hello dynamicState")

    def test_unreadable_and_out_of_bounds(self):
        # Out of bounds address
        self.assertIsNone(self.reader.read(0x5000, 4))
        self.assertIsNone(self.reader.read_ptr(0x5000))
        self.assertFalse(self.reader.is_readable(0x5000, 4))

        # Partial span overflowing region end
        self.assertIsNone(self.reader.read(0x10FE, 8))


if __name__ == "__main__":
    unittest.main()
