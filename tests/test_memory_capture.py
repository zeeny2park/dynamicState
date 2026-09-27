"""Unit tests for MemoryCapture engine using process_vm_readv."""

import os
import shutil
import tempfile
import unittest

from extractor.memory_capture import MemoryCapture
from extractor.memory_snapshot import RawMemorySnapshot
from extractor.snapshot_regions import POLICY_HEAP, POLICY_STACK


class MemoryCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_dynstate_cap_")
        self.capturer = MemoryCapture()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_capture_support(self):
        self.assertTrue(self.capturer.is_supported, "process_vm_readv should be supported on Linux")

    def test_invalid_pid_validation(self):
        with self.assertRaises(ValueError):
            self.capturer.capture(pid=0, output_dir=self.tmp_dir)

        with self.assertRaises(ValueError):
            self.capturer.capture(pid=-123, output_dir=self.tmp_dir)

        # Non-existent high PID
        with self.assertRaises(ProcessLookupError):
            self.capturer.capture(pid=9999999, output_dir=self.tmp_dir)

    def test_capture_self_process_stack_and_heap(self):
        # Capture our own process stack/heap
        my_pid = os.getpid()
        raw_snap = self.capturer.capture(
            pid=my_pid,
            policy=POLICY_STACK,
            output_dir=self.tmp_dir,
            snapshot_id="M_TEST_SELF"
        )

        self.assertIsInstance(raw_snap, RawMemorySnapshot)
        self.assertEqual(raw_snap.snapshot_id, "M_TEST_SELF")
        self.assertEqual(raw_snap.pid, my_pid)
        self.assertIn(raw_snap.status, ("COMPLETE", "PARTIAL"))
        self.assertGreater(raw_snap.bytes_captured, 0)
        self.assertGreater(raw_snap.regions_captured, 0)
        self.assertGreater(raw_snap.duration_us, 0)

        # Verify disk artifacts
        self.assertTrue(os.path.exists(os.path.join(self.tmp_dir, "metadata.json")))
        self.assertTrue(os.path.exists(os.path.join(self.tmp_dir, "manifest.json")))
        self.assertTrue(os.path.exists(os.path.join(self.tmp_dir, "maps.json")))
        mem_dir = os.path.join(self.tmp_dir, "memory")
        self.assertTrue(os.path.exists(mem_dir))
        self.assertGreater(len(os.listdir(mem_dir)), 0)

        # Test reload from disk
        loaded = RawMemorySnapshot.load(self.tmp_dir)
        self.assertEqual(loaded.snapshot_id, "M_TEST_SELF")
        self.assertEqual(loaded.pid, my_pid)
        self.assertEqual(loaded.bytes_captured, raw_snap.bytes_captured)
        self.assertEqual(len(loaded.regions), len(raw_snap.regions))


if __name__ == "__main__":
    unittest.main()
