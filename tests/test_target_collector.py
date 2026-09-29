"""Integration test for Native Target-Side C99 Memory Collector.

Tests:
1. Native compilation of target/collector with gcc/make.
2. CLI argument validation and help screen.
3. Live process memory capture using native collector.
4. Interoperability with host-side RawMemorySnapshot.load() and build_memory_snapshot_summary().
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.memory_snapshot import RawMemorySnapshot
from extractor.memory_snapshot_summary import build_memory_snapshot_summary


class TargetCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cls.collector_dir = os.path.join(cls.repo_root, "target", "collector")
        cls.collector_bin = os.path.join(cls.collector_dir, "dynamicstate-collector")

        # Compile collector
        res = subprocess.run(["make", "-C", cls.collector_dir], capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to build dynamicstate-collector: {res.stderr}")

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_c_collector_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_binary_exists_and_runs_help(self):
        self.assertTrue(os.path.isfile(self.collector_bin), "Collector binary must exist")
        res = subprocess.run([self.collector_bin, "--help"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Usage:", res.stderr)
        self.assertIn("--pid", res.stderr)

    def test_02_invalid_pid_rejected(self):
        res = subprocess.run([self.collector_bin, "-p", "-1"], capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0)

    def test_03_capture_live_process_and_load_snapshot(self):
        # Create a small C program that sets PR_SET_PTRACER so the collector has permission to read it
        target_src = os.path.join(self.tmp_dir, "target.c")
        target_bin = os.path.join(self.tmp_dir, "target_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <sys/prctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

volatile int global_counter = 42;

int main() {
    prctl(0x59616d61, -1, 0, 0, 0); /* PR_SET_PTRACER_ANY */
    char *buf = (char *)malloc(1024);
    strcpy(buf, "DYNAMICSTATE_TEST_PAYLOAD");
    while (1) {
        pause();
    }
    return 0;
}
""")
        # Compile target app
        comp = subprocess.run(["gcc", target_src, "-o", target_bin], capture_output=True, text=True)
        self.assertEqual(comp.returncode, 0, f"Compilation failed: {comp.stderr}")

        # Start target app
        proc = subprocess.Popen([target_bin])
        self.assertIsNotNone(proc.pid)
        time.sleep(0.1)

        out_snap_dir = os.path.join(self.tmp_dir, "snap_out")
        try:
            # Run collector
            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", out_snap_dir, "--policy", "all"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"Collector failed: {res.stderr}\nStdout: {res.stdout}")

            # Verify files on disk
            self.assertTrue(os.path.isfile(os.path.join(out_snap_dir, "metadata.json")))
            self.assertTrue(os.path.isfile(os.path.join(out_snap_dir, "manifest.json")))
            self.assertTrue(os.path.isfile(os.path.join(out_snap_dir, "maps.json")))
            self.assertTrue(os.path.isfile(os.path.join(out_snap_dir, "maps.txt")))
            self.assertTrue(os.path.isdir(os.path.join(out_snap_dir, "memory")))

            # Load via host-side RawMemorySnapshot
            snap = RawMemorySnapshot.load(out_snap_dir)
            self.assertEqual(snap.pid, proc.pid)
            self.assertEqual(snap.status, "COMPLETE")
            self.assertGreater(snap.regions_captured, 0)
            self.assertGreater(snap.bytes_captured, 0)
            self.assertIn(snap.architecture, ("aarch64", "x86_64", "arm", "arm64"))

            # Build memory summary
            summary = build_memory_snapshot_summary(
                snapshot_data={"snapshot_id": snap.snapshot_id},
                raw_memory_snapshot=snap,
            )
            self.assertEqual(summary.status, "COMPLETE")
            self.assertGreater(summary.captured_bytes, 0)
            self.assertGreater(len(summary.regions), 0)
            self.assertEqual(summary.quality.completeness, "COMPLETE")
        finally:
            proc.terminate()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
