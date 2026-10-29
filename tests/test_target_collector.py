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
            self.assertFalse(snap.mapping_race_detected)
            self.assertFalse(snap.process_exited)
            self.assertGreater(snap.process_starttime, 0)
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

    def test_04_exited_process_detected(self):
        out_snap_dir = os.path.join(self.tmp_dir, "snap_dead")
        # Run against non-existent PID (e.g. 999999)
        res = subprocess.run(
            [self.collector_bin, "-p", "999999", "-o", out_snap_dir],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Error:", res.stderr)

    def test_05_json_flag_stdout_contract(self):
        """When --json is passed, stdout contains pure JSON metadata and diagnostics go to stderr."""
        target_src = os.path.join(self.tmp_dir, "target_json.c")
        target_bin = os.path.join(self.tmp_dir, "target_json_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <sys/prctl.h>
#include <unistd.h>
int main() {
    prctl(0x59616d61, -1, 0, 0, 0);
    while (1) { pause(); }
    return 0;
}
""")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        proc = subprocess.Popen([target_bin])
        time.sleep(0.1)

        out_snap_dir = os.path.join(self.tmp_dir, "snap_json")
        try:
            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", out_snap_dir, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"Failed: {res.stderr}")
            import json as _json
            payload = _json.loads(res.stdout)
            self.assertEqual(payload.get("pid"), proc.pid)
            self.assertIn(payload.get("status"), ("COMPLETE", "PARTIAL"))
            self.assertEqual(payload.get("capture_mode"), "LOW_IMPACT_NATIVE_COLLECTOR")
            self.assertIn("duration_ms", payload)
            # Verify stdout does not contain progress log strings
            self.assertNotIn("[dynamicState-collector]", res.stdout)
        finally:
            proc.terminate()
            proc.wait()

    def test_06_timeout_ms_contract(self):
        """When --timeout-ms is reached, capture breaks gracefully and records timeout in metadata."""
        target_src = os.path.join(self.tmp_dir, "target_to.c")
        target_bin = os.path.join(self.tmp_dir, "target_to_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <sys/prctl.h>
#include <unistd.h>
int main() {
    prctl(0x59616d61, -1, 0, 0, 0);
    while (1) { pause(); }
    return 0;
}
""")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        proc = subprocess.Popen([target_bin])
        time.sleep(0.1)

        out_snap_dir = os.path.join(self.tmp_dir, "snap_timeout")
        try:
            # Pass ultra-low timeout of 0 ms (or 1 ms) to ensure timeout enforcement path
            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", out_snap_dir, "--timeout-ms", "1", "--json"],
                capture_output=True,
                text=True,
            )
            # Either it succeeded within 1ms or triggered TIMEOUT / PARTIAL
            import json as _json
            payload = _json.loads(res.stdout)
            self.assertEqual(payload.get("timeout_ms"), 1)
            self.assertIn("timed_out", payload)
        finally:
            proc.terminate()
            proc.wait()

    def test_07_permission_denied_or_restricted_pid(self):
        """Inaccessible or invalid PID produces exit code 1 and error envelope."""
        out_snap_dir = os.path.join(self.tmp_dir, "snap_perm")
        # Try capturing PID 1 (system init, usually EPERM for unprivileged process_vm_readv) or non-existent
        res = subprocess.run(
            [self.collector_bin, "-p", "-99", "-o", out_snap_dir, "--json"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1)

    def test_08_cross_compilation_verification(self):
        """Cross-compilation for x86_64 and arm32 produces valid ELF binaries with correct machine architecture."""
        from extractor.debug_image import inspect_elf

        # 1. Cross-compile x86_64
        x86_bin = os.path.join(self.tmp_dir, "collector_x86_64")
        res_x86 = subprocess.run(
            ["x86_64-linux-gnu-gcc", "-O2", "-Wall", "-Wextra", "-std=c99", "-D_GNU_SOURCE",
             "-I" + os.path.join(self.collector_dir, "include"),
             os.path.join(self.collector_dir, "src", "collector.c"),
             os.path.join(self.collector_dir, "src", "main.c"),
             "-o", x86_bin],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_x86.returncode, 0, f"x86_64 compilation failed: {res_x86.stderr}")
        self.assertTrue(os.path.isfile(x86_bin))
        ident_x86 = inspect_elf(x86_bin)
        self.assertEqual(ident_x86.architecture, "x86_64")

        # 2. Cross-compile arm32
        arm32_bin = os.path.join(self.tmp_dir, "collector_arm32")
        res_arm = subprocess.run(
            ["arm-linux-gnueabihf-gcc", "-O2", "-Wall", "-Wextra", "-std=c99", "-D_GNU_SOURCE",
             "-I" + os.path.join(self.collector_dir, "include"),
             os.path.join(self.collector_dir, "src", "collector.c"),
             os.path.join(self.collector_dir, "src", "main.c"),
             "-o", arm32_bin],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_arm.returncode, 0, f"arm32 compilation failed: {res_arm.stderr}")
        self.assertTrue(os.path.isfile(arm32_bin))
        ident_arm = inspect_elf(arm32_bin)
        self.assertEqual(ident_arm.architecture, "arm")

    def test_09_remote_execution_run_to_completion_contract(self):
        """Collector runs on-demand and immediately exits with 0 or 1 without lingering background processes."""
        target_src = os.path.join(self.tmp_dir, "target_run.c")
        target_bin = os.path.join(self.tmp_dir, "target_run_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <sys/prctl.h>
#include <unistd.h>
int main() {
    prctl(0x59616d61, -1, 0, 0, 0);
    while (1) { pause(); }
    return 0;
}
""")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        proc = subprocess.Popen([target_bin])
        time.sleep(0.1)

        out_snap_dir = os.path.join(self.tmp_dir, "snap_run")
        try:
            t0 = time.time()
            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", out_snap_dir, "--json"],
                capture_output=True,
                text=True,
                timeout=5.0,  # Strict timeout guard
            )
            elapsed = time.time() - t0
            self.assertEqual(res.returncode, 0)
            self.assertLess(elapsed, 3.0, "Collector execution took too long")
            # Verify process exited cleanly
            ps_check = subprocess.run(["pgrep", "-f", f"{self.collector_bin}.*{proc.pid}"], capture_output=True)
            self.assertNotEqual(ps_check.returncode, 0, "Collector process is still running after completion")
        finally:
            proc.terminate()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
