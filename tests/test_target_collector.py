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
        """When --timeout-ms is reached on a memory-intensive target, capture deterministically breaks and records PARTIAL + timed_out."""
        target_src = os.path.join(self.tmp_dir, "target_to.c")
        target_bin = os.path.join(self.tmp_dir, "target_to_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <sys/prctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main() {
    prctl(0x59616d61, -1, 0, 0, 0);
    size_t sz = 64 * 1024 * 1024;
    char *p = malloc(sz);
    if (p) {
        memset(p, 0x5a, sz);
    }
    while (1) { pause(); }
    return 0;
}
""")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        proc = subprocess.Popen([target_bin])
        time.sleep(0.15)

        out_snap_dir = os.path.join(self.tmp_dir, "snap_timeout")
        try:
            # Pass strict 1ms timeout on a 64MB memory capture
            t0 = time.time()
            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", out_snap_dir, "--timeout-ms", "1", "--max-mb", "64", "--json"],
                capture_output=True,
                text=True,
            )
            elapsed_sec = time.time() - t0
            self.assertEqual(res.returncode, 0, f"Collector failed: {res.stderr}")
            import json as _json
            payload = _json.loads(res.stdout)
            # Verify deterministic timeout occurrence
            self.assertEqual(payload.get("timeout_ms"), 1)
            self.assertTrue(payload.get("timed_out"), "Collector should have marked timed_out=True")
            self.assertEqual(payload.get("status"), "PARTIAL", "Partial memory should have status=PARTIAL")
            self.assertGreater(payload.get("bytes_captured", 0), 0)
            self.assertLess(payload.get("bytes_captured", 0), payload.get("bytes_requested", 0))
            self.assertGreater(payload.get("partial_reads", 0), 0)

            # Verify on-disk file integrity and manifest consistency
            meta_file = os.path.join(out_snap_dir, "metadata.json")
            manifest_file = os.path.join(out_snap_dir, "manifest.json")
            self.assertTrue(os.path.isfile(meta_file))
            self.assertTrue(os.path.isfile(manifest_file))
            with open(manifest_file) as mf:
                manifest_items = _json.load(mf)
            self.assertGreater(len(manifest_items), 0)
            # Find the partial chunk region
            partial_items = [item for item in manifest_items if item.get("status") == "PARTIAL"]
            self.assertGreater(len(partial_items), 0)
            self.assertTrue(partial_items[0]["error"].startswith("PARTIAL_READ_"))
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

    def test_10_json_verbose_stdout_purity(self):
        """When --json and --verbose are passed together, stdout contains ONLY valid JSON and all debug messages go to stderr."""
        target_src = os.path.join(self.tmp_dir, "target_verb.c")
        target_bin = os.path.join(self.tmp_dir, "target_verb_app")
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

        out_snap_dir = os.path.join(self.tmp_dir, "snap_verb")
        try:
            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", out_snap_dir, "--json", "--verbose"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"Verbose execution failed: {res.stderr}")
            # stdout must parse as valid JSON
            import json as _json
            payload = _json.loads(res.stdout)
            self.assertTrue(payload.get("success"))
            self.assertEqual(payload.get("status"), "COMPLETE")
            self.assertEqual(payload.get("pid"), proc.pid)
            # stderr must contain the [debug] log messages
            self.assertIn("[debug]", res.stderr)
            # stdout must not contain [debug]
            self.assertNotIn("[debug]", res.stdout)
        finally:
            proc.terminate()
            proc.wait()

    def test_11_output_directory_failure(self):
        """Failure to create or write to output directory returns exit code 1 and valid JSON error envelope on stdout."""
        target_src = os.path.join(self.tmp_dir, "target_outfail.c")
        target_bin = os.path.join(self.tmp_dir, "target_outfail_app")
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

        try:
            # Unwritable directory path (e.g. inside /proc or /nonexistent_root_dir)
            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", "/proc/unwritable_snap_test", "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 1)
            import json as _json
            payload = _json.loads(res.stdout)
            self.assertFalse(payload.get("success"))
            self.assertEqual(payload.get("status"), "FAILED")
            self.assertIn("[dynamicState-collector] Error:", res.stderr)
        finally:
            proc.terminate()
            proc.wait()

    def test_12_timeout_validation_variants(self):
        """Negative, non-numeric, or out-of-range timeout values are rejected with exit code 1 and JSON error."""
        import json as _json
        for bad_to in ["-50", "abc", "99999999999999"]:
            res = subprocess.run(
                [self.collector_bin, "-p", "1234", "-t", bad_to, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 1)
            payload = _json.loads(res.stdout)
            self.assertFalse(payload.get("success"))
            self.assertEqual(payload.get("error"), "INVALID_TIMEOUT")
            self.assertIn("Error: Invalid timeout-ms", res.stderr)

    def test_13_pid_validation_variants(self):
        """Negative, non-numeric, or missing PIDs are rejected with exit code 1 and JSON error."""
        import json as _json
        for bad_pid_args in [["-p", "-1", "--json"], ["-p", "abc", "--json"], ["--json"]]:
            res = subprocess.run(
                [self.collector_bin] + bad_pid_args,
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 1)
            payload = _json.loads(res.stdout)
            self.assertFalse(payload.get("success"))
            self.assertIn(payload.get("error"), ("INVALID_PID", "MISSING_PID"))

    def test_14_remote_adapter_capture_snapshot_and_quality_warning(self):
        """RemoteSshTargetAdapter.capture_snapshot_via_collector parses JSON stdout and flags partial capture."""
        from extractor.target_adapter import RemoteSshTargetAdapter

        # Case 1: Collector binary not set
        no_coll_adapter = RemoteSshTargetAdapter(host="10.0.0.1", collector_path=None)
        res_no = no_coll_adapter.capture_snapshot_via_collector(pid=1234, remote_output_dir="/tmp/snap")
        self.assertFalse(res_no["success"])
        self.assertEqual(res_no["status"], "FAILED")

        # Case 2: Mock SSH runner returning partial capture
        mock_partial_json = (
            '{"success":true,"status":"PARTIAL","timed_out":true,"timeout_ms":50,'
            '"regions":2,"regions_requested":5,"bytes_captured":8192}\n'
        )
        def mock_runner_partial(cmd, timeout):
            return 0, mock_partial_json, ""

        part_adapter = RemoteSshTargetAdapter(
            host="10.0.0.1",
            collector_path="/tmp/collector",
            command_runner=mock_runner_partial,
        )
        res_part = part_adapter.capture_snapshot_via_collector(pid=1234, remote_output_dir="/tmp/snap")
        self.assertTrue(res_part["success"])
        self.assertEqual(res_part["status"], "PARTIAL")
        self.assertIn("quality_warning", res_part)
        self.assertIn("PARTIAL_CAPTURE", res_part["quality_warning"])

        # Case 3: Mock SSH runner with transport failure / connection drop
        def mock_runner_fail(cmd, timeout):
            return 255, "", "ssh: connect to host 10.0.0.1 port 22: Connection refused"

        fail_adapter = RemoteSshTargetAdapter(
            host="10.0.0.1",
            collector_path="/tmp/collector",
            command_runner=mock_runner_fail,
        )
        res_fail = fail_adapter.capture_snapshot_via_collector(pid=1234, remote_output_dir="/tmp/snap")
        self.assertFalse(res_fail["success"])
        self.assertEqual(res_fail["status"], "SSH_FAILURE")
        self.assertIn("Connection refused", res_fail["error"])

    def test_15_remote_termination_contract_combinations(self):
        """Verifies all combinations of SSH returncode (0/1/255) and JSON status, reconciling contradictions."""
        from extractor.target_adapter import RemoteSshTargetAdapter

        # Subcase A: rc=0, status=COMPLETE -> success=True
        def runner_c0(cmd, t):
            return 0, '{"success":true,"status":"COMPLETE","regions":10,"bytes_captured":1024}\n', ""
        a_c0 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_c0)
        res = a_c0.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "COMPLETE")

        # Subcase B: rc=0, status=PARTIAL -> success=True, quality_warning present
        def runner_p0(cmd, t):
            return 0, '{"success":true,"status":"PARTIAL","regions":3,"bytes_captured":512}\n', ""
        a_p0 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_p0)
        res = a_p0.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "PARTIAL")
        self.assertIn("PARTIAL_CAPTURE", res.get("quality_warning", ""))

        # Subcase C: rc=0, status=FAILED -> success=False
        def runner_f0(cmd, t):
            return 0, '{"success":false,"status":"FAILED","error":"EFAULT"}\n', ""
        a_f0 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_f0)
        res = a_f0.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "FAILED")

        # Subcase D: rc=1, status=TIMEOUT -> success=False
        def runner_t1(cmd, t):
            return 1, '{"success":false,"status":"TIMEOUT","timed_out":true,"regions":0}\n', ""
        a_t1 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_t1)
        res = a_t1.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "TIMEOUT")

        # Subcase E: Contradiction! rc=1, but JSON says status=COMPLETE -> downgraded to PARTIAL/FAILED
        def runner_c1(cmd, t):
            return 1, '{"success":true,"status":"COMPLETE","regions":5,"bytes_captured":4096}\n', ""
        a_c1 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_c1)
        res = a_c1.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertEqual(res["status"], "PARTIAL")
        self.assertIn("quality_warning", res)
        self.assertIn("contradicts COMPLETE", res["quality_warning"])

        # Subcase F: rc=1, status=PARTIAL with regions -> partial preserved with warning
        def runner_p1(cmd, t):
            return 1, '{"success":true,"status":"PARTIAL","regions":2,"bytes_captured":2048}\n', ""
        a_p1 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_p1)
        res = a_p1.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertEqual(res["status"], "PARTIAL")
        self.assertIn("partial snapshot data preserved", res.get("quality_warning", ""))

        # Subcase G: SSH Timeout (rc=-1) with empty stdout -> status=SSH_TIMEOUT
        def runner_to(cmd, t):
            return -1, "", "SSH command timed out after 5.0s"
        a_to = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_to)
        res = a_to.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "SSH_TIMEOUT")

        # Subcase H: Malformed JSON output -> status=MALFORMED_OUTPUT
        def runner_bad(cmd, t):
            return 0, "Corrupted binary output without json\n", ""
        a_bad = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_bad)
        res = a_bad.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "MALFORMED_OUTPUT")

    def test_16_atomic_json_file_integrity(self):
        """Metadata, manifest, and maps are written atomically without leaving dangling .tmp files."""
        target_src = os.path.join(self.tmp_dir, "target_atom.c")
        target_bin = os.path.join(self.tmp_dir, "target_atom_app")
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

        out_snap_dir = os.path.join(self.tmp_dir, "snap_atom")
        try:
            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", out_snap_dir, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            # Verify primary files exist
            self.assertTrue(os.path.isfile(os.path.join(out_snap_dir, "metadata.json")))
            self.assertTrue(os.path.isfile(os.path.join(out_snap_dir, "manifest.json")))
            self.assertTrue(os.path.isfile(os.path.join(out_snap_dir, "maps.json")))
            # Verify no temporary files are left over
            self.assertFalse(os.path.exists(os.path.join(out_snap_dir, "metadata.json.tmp")))
            self.assertFalse(os.path.exists(os.path.join(out_snap_dir, "manifest.json.tmp")))
            self.assertFalse(os.path.exists(os.path.join(out_snap_dir, "maps.json.tmp")))
        finally:
            proc.terminate()
            proc.wait()

    def test_17_offline_analyzer_partial_snapshot_propagation(self):
        """OfflineMemoryAnalyzer accurately reflects PARTIAL capture quality, missing regions, and warnings."""
        from extractor.memory_snapshot import RawMemorySnapshot, CapturedRegion
        from extractor.offline_analyzer import OfflineMemoryAnalyzer

        # Create synthetic partial snapshot
        snap_dir = os.path.join(self.tmp_dir, "synth_partial")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)
        # Write dummy region
        bin_rel = "memory/region_000001.bin"
        with open(os.path.join(snap_dir, bin_rel), "wb") as bf:
            bf.write(b"\x00" * 4096)

        reg1 = CapturedRegion("R000001", 0x1000, 0x2000, 4096, "r--p", "code", "/bin/app", 4096, 4096, "COMPLETE", bin_rel)
        reg2 = CapturedRegion("R000002", 0x2000, 0x10000, 57344, "rw-p", "heap", "[heap]", 57344, 0, "FAILED", None, "EFAULT_OR_READ_ERROR")

        raw = RawMemorySnapshot(
            snapshot_id="SNAP_SYNTH_PARTIAL",
            pid=4242,
            binary="/bin/app",
            timestamp_ns=1000000,
            status="PARTIAL",
            regions_requested=2,
            regions_captured=1,
            bytes_requested=61440,
            bytes_captured=4096,
            partial_reads=0,
            failed_reads=1,
            output_dir=snap_dir,
            regions=[reg1, reg2],
        )

        analyzer = OfflineMemoryAnalyzer()
        semantic_snap = analyzer.analyze(raw, optional_symbol_context={"types": {}, "globals": {}})
        meta = semantic_snap.metadata
        prov = semantic_snap.provenance

        # Assert full quality propagation
        self.assertEqual(meta["capture_status"], "PARTIAL")
        self.assertEqual(meta["regions_requested"], 2)
        self.assertEqual(meta["regions_captured"], 1)
        self.assertEqual(meta["bytes_requested"], 61440)
        self.assertEqual(meta["bytes_captured"], 4096)
        self.assertEqual(meta["failed_reads"], 1)
        self.assertEqual(prov["capture_status"], "PARTIAL")
        self.assertIn("PARTIAL_CAPTURE", prov.get("quality_warning", ""))

        # Verify unmapped memory returns unreadable / None
        from extractor.offline_analyzer import SnapshotMemoryReader
        reader = SnapshotMemoryReader(raw)
        self.assertTrue(reader.is_readable(0x1000, 4))
        self.assertFalse(reader.is_readable(0x2000, 4))
        self.assertIsNone(reader.read(0x2000, 4))


if __name__ == "__main__":
    unittest.main()
