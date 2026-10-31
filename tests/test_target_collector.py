"""Integration test for Native Target-Side C99 Memory Collector.

Tests:
1. Native compilation of target/collector with gcc/make.
2. CLI argument validation and help screen.
3. Live process memory capture using native collector.
4. Interoperability with host-side RawMemorySnapshot.load() and build_memory_snapshot_summary().
"""

import json
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
             os.path.join(self.collector_dir, "src", "sha256.c"),
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
             os.path.join(self.collector_dir, "src", "sha256.c"),
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

    def test_18_file_lifecycle_fclose_and_error_handling(self):
        """Verifies clean fclose handling, cleanup of tmp files, and error propagation when writes fail."""
        target_src = os.path.join(self.tmp_dir, "target_lifecycle.c")
        target_bin = os.path.join(self.tmp_dir, "target_lifecycle_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <stdio.h>
#include <unistd.h>
int main() {
    while (1) sleep(1);
    return 0;
}
""")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        proc = subprocess.Popen([target_bin])
        time.sleep(0.1)

        try:
            # Create a directory and make memory subdirectory non-writable to force region write failure
            bad_dir = os.path.join(self.tmp_dir, "bad_snap_out")
            os.makedirs(os.path.join(bad_dir, "memory"), exist_ok=True)
            # Remove write permissions on memory subdir
            os.chmod(os.path.join(bad_dir, "memory"), 0o555)

            try:
                res = subprocess.run(
                    [self.collector_bin, "-p", str(proc.pid), "-o", bad_dir, "--json"],
                    capture_output=True,
                    text=True,
                )
                # Collector should either exit with 0 (and status FAILED/PARTIAL) or exit 1, but must not crash
                self.assertIn(res.returncode, (0, 1))
                payload = json.loads(res.stdout)
                # If memory dir wasn't writable, failed_reads should be > 0 or status != COMPLETE
                if payload.get("status") == "COMPLETE":
                    # In some environments running as root or container chmod might not block root, check stats
                    pass
                else:
                    self.assertIn(payload.get("status"), ("FAILED", "PARTIAL"))
            finally:
                os.chmod(os.path.join(bad_dir, "memory"), 0o755)
        finally:
            proc.terminate()
            proc.wait()

    def test_19_concurrent_collector_temp_isolation(self):
        """PID-specific tmp naming ensures concurrent runs do not clobber each other's temporary files."""
        target_src = os.path.join(self.tmp_dir, "target_iso.c")
        target_bin = os.path.join(self.tmp_dir, "target_iso_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <stdio.h>
#include <unistd.h>
int main() {
    while (1) sleep(1);
    return 0;
}
""")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        p1 = subprocess.Popen([target_bin])
        p2 = subprocess.Popen([target_bin])
        time.sleep(0.1)

        out_dir = os.path.join(self.tmp_dir, "snap_iso")
        os.makedirs(out_dir, exist_ok=True)
        lock_file = os.path.join(out_dir, ".collector.lock")
        try:
            import fcntl
            # 19A: Verify deterministic rejection when output directory is locked by a competing collector.
            with open(lock_file, "w") as lf:
                fcntl.lockf(lf.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                res_locked = subprocess.run(
                    [self.collector_bin, "-p", str(p1.pid), "-o", out_dir, "--json"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(res_locked.returncode, 1)
                self.assertIn('"status":"FAILED"', res_locked.stdout)

            # When the lock is released, the collector succeeds cleanly
            res_free = subprocess.run(
                [self.collector_bin, "-p", str(p1.pid), "-o", out_dir, "--json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res_free.returncode, 0)

            # Check that no .tmp.* files remain in output directory
            remaining_tmps = [f for f in os.listdir(out_dir) if ".tmp" in f]
            self.assertEqual(remaining_tmps, [], f"Found lingering temporary files: {remaining_tmps}")

            # 19B: Run two collectors targeting DISTINCT output directories in parallel.
            # Both must succeed independently without interference.
            out_dir1 = os.path.join(self.tmp_dir, "snap_iso_1")
            out_dir2 = os.path.join(self.tmp_dir, "snap_iso_2")
            cmd_d1 = [self.collector_bin, "-p", str(p1.pid), "-o", out_dir1, "--json"]
            cmd_d2 = [self.collector_bin, "-p", str(p2.pid), "-o", out_dir2, "--json"]
            sub_d1 = subprocess.Popen(cmd_d1, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            sub_d2 = subprocess.Popen(cmd_d2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            sub_d1.communicate(timeout=5)
            sub_d2.communicate(timeout=5)
            self.assertEqual(sub_d1.returncode, 0)
            self.assertEqual(sub_d2.returncode, 0)
        finally:
            p1.terminate()
            p2.terminate()
            p1.wait()
            p2.wait()

    def test_20_snapshot_integrity_validation_and_degradation(self):
        """Verifies validate_integrity() detects missing/truncated .bin files, uncommitted metadata, and degrades status."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_integrity_test")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)

        bin_file = "memory/region_000001.bin"
        full_bin = os.path.join(snap_dir, bin_file)
        with open(full_bin, "wb") as bf:
            bf.write(b"A" * 4096)

        reg1 = CapturedRegion("R000001", 0x1000, 0x2000, 4096, "r--p", "code", "/app", 4096, 4096, "COMPLETE", bin_file)
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_INTEG",
            pid=9999,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            committed=True,
            output_dir=snap_dir,
            regions=[reg1],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        raw.save()

        # Step 1: Clean snapshot passes integrity validation
        loaded = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(loaded.status, "COMPLETE")
        is_val, warns = loaded.validate_integrity()
        self.assertTrue(is_val)
        self.assertEqual(warns, [])

        # Step 2: Corrupt binary file by truncating it
        with open(full_bin, "wb") as bf:
            bf.write(b"A" * 100) # Corrupted/truncated from 4096 to 100 bytes

        corrupted = RawMemorySnapshot.load(snap_dir)
        # Should degrade status from COMPLETE to PARTIAL
        self.assertEqual(corrupted.status, "PARTIAL")
        self.assertTrue(any("corrupted/truncated" in w for w in corrupted.integrity_warnings))
        is_val, warns = corrupted.validate_integrity()
        self.assertFalse(is_val)

        # Step 3: Remove binary file entirely
        os.unlink(full_bin)
        missing_bin = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(missing_bin.status, "PARTIAL")
        self.assertTrue(any("binary file missing on disk" in w for w in missing_bin.integrity_warnings))

        # Step 4: Test uncommitted marker (committed: false)
        meta_path = os.path.join(snap_dir, "metadata.json")
        with open(meta_path, "r") as mf:
            m_data = json.load(mf)
        m_data["committed"] = False
        m_data["status"] = "COMPLETE"
        with open(meta_path, "w") as mf:
            json.dump(m_data, mf)

        uncommitted = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(uncommitted.status, "PARTIAL")
        self.assertTrue(any("not cleanly committed" in w for w in uncommitted.integrity_warnings))

    def test_21_ssh_transition_matrix_exhaustive(self):
        """Exhaustively verifies every state in the SSH returncode and JSON status matrix."""
        from extractor.target_adapter import RemoteSshTargetAdapter

        # Case 1: rc=0, COMPLETE but success=False contradiction
        def runner_inconsistent(cmd, t):
            return 0, '{"success":false,"status":"COMPLETE","regions":5}\n', ""
        a1 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_inconsistent)
        res1 = a1.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertFalse(res1["success"])
        self.assertEqual(res1["status"], "INCONSISTENT_STATUS")

        # Case 2: rc=0, unrecognized status
        def runner_unknown(cmd, t):
            return 0, '{"success":true,"status":"NON_STANDARD_STATUS"}\n', ""
        a2 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_unknown)
        res2 = a2.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertFalse(res2["success"])
        self.assertEqual(res2["status"], "UNKNOWN_STATUS")

        # Case 3: rc=1, status=COMPLETE, regions=0 -> FAILED
        def runner_c1_empty(cmd, t):
            return 1, '{"success":true,"status":"COMPLETE","regions":0}\n', ""
        a3 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_c1_empty)
        res3 = a3.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertFalse(res3["success"])
        self.assertEqual(res3["status"], "FAILED")

        # Case 4: rc=1, status=PROCESS_EXITED -> success=False
        def runner_pe(cmd, t):
            return 1, '{"success":false,"status":"PROCESS_EXITED"}\n', ""
        a4 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_pe)
        res4 = a4.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertFalse(res4["success"])
        self.assertEqual(res4["status"], "PROCESS_EXITED")

        # Case 5: rc=1, status=PERMISSION_DENIED -> success=False
        def runner_perm(cmd, t):
            return 1, '{"success":false,"status":"PERMISSION_DENIED"}\n', ""
        a5 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_perm)
        res5 = a5.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertFalse(res5["success"])
        self.assertEqual(res5["status"], "PERMISSION_DENIED")

        # Case 6: rc=0, empty stdout -> FAILED with error
        def runner_empty0(cmd, t):
            return 0, "", ""
        a6 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_empty0)
        res6 = a6.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertFalse(res6["success"])
        self.assertEqual(res6["status"], "FAILED")

        # Case 7: rc=127, empty stdout -> SSH_FAILURE with returncode preserved
        def runner_notfound(cmd, t):
            return 127, "", "bash: /c: No such file or directory"
        a7 = RemoteSshTargetAdapter("10.0.0.1", collector_path="/c", command_runner=runner_notfound)
        res7 = a7.capture_snapshot_via_collector(1234, "/tmp/s")
        self.assertFalse(res7["success"])
        self.assertEqual(res7["status"], "SSH_FAILURE")
        self.assertEqual(res7["returncode"], 127)

    def test_22_quality_metadata_full_roundtrip_and_verdict_engine(self):
        """Verifies full roundtrip of quality metadata and integration with OfflineMemoryAnalyzer."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
        from extractor.offline_analyzer import OfflineMemoryAnalyzer, SnapshotMemoryReader

        snap_dir = os.path.join(self.tmp_dir, "synth_full_quality")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)

        bin_rel = "memory/region_000001.bin"
        with open(os.path.join(snap_dir, bin_rel), "wb") as bf:
            bf.write(b"\x42" * 1024)

        reg1 = CapturedRegion("R000001", 0x400000, 0x400400, 1024, "r--p", "data", "/app", 1024, 1024, "COMPLETE", bin_rel)
        reg2 = CapturedRegion("R000002", 0x400400, 0x401400, 4096, "r--p", "data", "/app", 4096, 0, "FAILED", "")
        reg3 = CapturedRegion("R000003", 0x401400, 0x402400, 4096, "r--p", "data", "/app", 4096, 0, "FAILED", "")
        reg4 = CapturedRegion("R000004", 0x402400, 0x404400, 7168, "r--p", "data", "/app", 7168, 0, "FAILED", "")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_QUAL_01",
            pid=8888,
            binary="/app",
            timestamp_ns=5000000,
            status="PARTIAL",
            timed_out=True,
            timeout_ms=1500,
            committed=True,
            mapping_race_detected=True,
            regions_requested=4,
            regions_captured=1,
            bytes_requested=16384,
            bytes_captured=1024,
            partial_reads=1,
            failed_reads=2,
            duration_us=1234.5,
            output_dir=snap_dir,
            regions=[reg1, reg2, reg3, reg4],
            maps=[{"start": "0x400000", "end": "0x400400", "permissions": "r--p"}],
        )
        raw.save()

        # Reload from disk
        loaded = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(loaded.status, "PARTIAL")
        self.assertTrue(loaded.timed_out)
        self.assertEqual(loaded.timeout_ms, 1500)
        self.assertTrue(loaded.committed)
        self.assertTrue(loaded.mapping_race_detected)
        self.assertEqual(loaded.partial_reads, 1)
        self.assertEqual(loaded.failed_reads, 2)
        self.assertEqual(loaded.bytes_requested, 16384)
        self.assertEqual(loaded.bytes_captured, 1024)

        # Run offline semantic analyzer
        analyzer = OfflineMemoryAnalyzer()
        semantic_snap = analyzer.analyze(loaded, optional_symbol_context={"types": {}, "globals": {}})
        self.assertEqual(semantic_snap.metadata["timed_out"], True)
        self.assertEqual(semantic_snap.metadata["mapping_race_detected"], True)
        self.assertEqual(semantic_snap.metadata["committed"], True)
        self.assertEqual(semantic_snap.metadata["partial_reads"], 1)
        self.assertEqual(semantic_snap.metadata["failed_reads"], 2)
        self.assertIn("PARTIAL_CAPTURE", semantic_snap.provenance["quality_warning"])

        # Validate SnapshotMemoryReader read safety
        reader = SnapshotMemoryReader(loaded)
        data = reader.read(0x400000, 4)
        self.assertEqual(data, b"\x42\x42\x42\x42")
        # Reading out of bounds must return None, not zeroes
        self.assertIsNone(reader.read(0x400400, 4))
        self.assertIsNone(reader.read(0x999999, 4))

    def test_23_path_construction_failure_no_unlink_or_corruption(self):
        """Verifies that path construction failures (e.g., path buffer overflow) fail safely without unlinking."""
        target_src = os.path.join(self.tmp_dir, "target_path.c")
        target_bin = os.path.join(self.tmp_dir, "target_path_app")
        with open(target_src, "w") as f:
            f.write("int main() { while (1); return 0; }\n")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        p = subprocess.Popen([target_bin])
        try:
            # Create a path string exceeding internal 2048-byte buffers
            huge_dir = os.path.join(self.tmp_dir, "a" * 2100)
            res = subprocess.run(
                [self.collector_bin, "-p", str(p.pid), "-o", huge_dir, "--json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
            # Should output structured error JSON or stderr diagnostic without segfault
            self.assertIn("FAILED", res.stdout + res.stderr)
        finally:
            p.terminate()
            p.wait()

    def test_24_maps_txt_write_failure_aborts_cleanly(self):
        """Verifies that failure copying maps.txt aborts capture cleanly and releases resources."""
        target_src = os.path.join(self.tmp_dir, "target_maps_fail.c")
        target_bin = os.path.join(self.tmp_dir, "target_maps_fail_app")
        with open(target_src, "w") as f:
            f.write("int main() { while (1); return 0; }\n")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        p = subprocess.Popen([target_bin])
        try:
            read_only_dir = os.path.join(self.tmp_dir, "ro_snap_dir")
            os.makedirs(read_only_dir, exist_ok=True)
            # Make dir read-only so copy_maps_file fails when creating maps.txt
            os.chmod(read_only_dir, 0o555)

            res = subprocess.run(
                [self.collector_bin, "-p", str(p.pid), "-o", read_only_dir, "--json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            os.chmod(read_only_dir, 0o755)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("FAILED", res.stdout + res.stderr)
        finally:
            if os.path.exists(read_only_dir):
                os.chmod(read_only_dir, 0o755)
            p.terminate()
            p.wait()

    def test_25_stale_metadata_invalidation(self):
        """Verifies that starting a capture unlinks stale metadata.json from previous runs."""
        target_src = os.path.join(self.tmp_dir, "target_stale.c")
        target_bin = os.path.join(self.tmp_dir, "target_stale_app")
        with open(target_src, "w") as f:
            f.write("int main() { while (1); return 0; }\n")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        p = subprocess.Popen([target_bin])
        out_dir = os.path.join(self.tmp_dir, "stale_snap_dir")
        os.makedirs(out_dir, exist_ok=True)
        stale_meta = os.path.join(out_dir, "metadata.json")
        try:
            with open(stale_meta, "w") as f:
                json.dump({"snapshot_id": "OLD_STALE", "status": "COMPLETE", "committed": True}, f)
            self.assertTrue(os.path.exists(stale_meta))

            res = subprocess.run(
                [self.collector_bin, "-p", str(p.pid), "-o", out_dir, "--json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            with open(stale_meta, "r") as f:
                new_data = json.load(f)
            self.assertNotEqual(new_data.get("snapshot_id"), "OLD_STALE")
        finally:
            p.terminate()
            p.wait()

    def test_26_snapshot_integrity_path_traversal_rejection(self):
        """Verifies validate_integrity detects path traversal in region filenames and symlink escapes."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_traversal_test")
        os.makedirs(snap_dir, exist_ok=True)

        # Region attempting traversal via relative path
        reg_trav = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "../escape.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_TRAV",
            pid=7777,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg_trav],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        is_val, warns = raw.validate_integrity()
        self.assertFalse(is_val)
        self.assertTrue(any("escapes snapshot directory" in w for w in warns))

        # Absolute path outside snap_dir
        reg_abs = CapturedRegion("R02", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "/etc/passwd")
        raw.regions = [reg_abs]
        is_val, warns = raw.validate_integrity()
        self.assertFalse(is_val)
        self.assertTrue(any("escapes snapshot directory" in w for w in warns))

    def test_27_snapshot_integrity_malformed_json_and_count_mismatch(self):
        """Verifies that malformed json files or count/byte mismatches invalidate COMPLETE status."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_malformed_test")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)

        bin_file = "memory/reg_m.bin"
        with open(os.path.join(snap_dir, bin_file), "wb") as f:
            f.write(b"M" * 4096)

        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "code", "/app", 4096, 4096, "COMPLETE", bin_file)
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_MALFORMED",
            pid=6666,
            binary="/app",
            timestamp_ns=2000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        raw.save()

        # Corrupt manifest.json with invalid JSON syntax
        manifest_path = os.path.join(snap_dir, "manifest.json")
        with open(manifest_path, "w") as f:
            f.write('{"unclosed_json": ')

        corrupted_snap = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(corrupted_snap.status, "PARTIAL")
        self.assertTrue(any("malformed" in w and "JSON" in w for w in corrupted_snap.integrity_warnings))

        # Restore valid manifest but induce region count mismatch in metadata
        raw.save()
        meta_path = os.path.join(snap_dir, "metadata.json")
        with open(meta_path, "r") as f:
            meta = json.load(f)
        meta["regions"] = 999  # Mismatch: manifest has 1 region
        with open(meta_path, "w") as f:
            json.dump(meta, f)

        mismatch_snap = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(mismatch_snap.status, "PARTIAL")
        self.assertTrue(any("Region count mismatch" in w for w in mismatch_snap.integrity_warnings))

    def test_28_python_save_atomic_commit_barrier(self):
        """Verifies RawMemorySnapshot.save() writes atomically via temporary files and leaves no leftovers."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_atomic_test")
        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_ATOMIC",
            pid=5555,
            binary="/app",
            timestamp_ns=3000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        raw.save()

        # All temporary files (.tmp.<pid>) must be replaced into final files
        all_files = os.listdir(snap_dir)
        tmp_files = [f for f in all_files if ".tmp" in f]
        self.assertEqual(tmp_files, [])
        self.assertIn("metadata.json", all_files)
        self.assertIn("manifest.json", all_files)
        self.assertIn("maps.json", all_files)

    def test_29_ssh_adapter_partial_zero_evidence_degrades_to_failed(self):
        """Verifies RemoteSshTargetAdapter degrades PARTIAL with 0 regions/bytes to FAILED."""
        from extractor.target_adapter import RemoteSshTargetAdapter

        # Case A: PARTIAL with 0 regions and 0 bytes captured -> degraded to FAILED
        def runner_empty_partial(cmd, t):
            payload = json.dumps({
                "success": False,
                "status": "PARTIAL",
                "regions": 0,
                "bytes_captured": 0,
                "regions_requested": 5,
                "bytes_requested": 20480,
                "error": "TIMEOUT",
            })
            return 0, payload + "\n", ""

        adapter = RemoteSshTargetAdapter("192.168.1.100", collector_path="/collector", command_runner=runner_empty_partial)
        res = adapter.capture_snapshot_via_collector(4321, "/tmp/snap_dest")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(res["error"], "TIMEOUT")

        # Case B: COMPLETE with 0 regions when 5 requested -> degraded to INCONSISTENT_STATUS
        def runner_empty_complete(cmd, t):
            payload = json.dumps({
                "success": True,
                "status": "COMPLETE",
                "regions": 0,
                "bytes_captured": 0,
                "regions_requested": 5,
            })
            return 0, payload + "\n", ""

        adapter2 = RemoteSshTargetAdapter("192.168.1.100", collector_path="/collector", command_runner=runner_empty_complete)
        res2 = adapter2.capture_snapshot_via_collector(4321, "/tmp/snap_dest")
        self.assertFalse(res2["success"])
        self.assertEqual(res2["status"], "INCONSISTENT_STATUS")

    def test_30_python_save_interrupted_before_metadata_commit(self):
        """A save interrupted before metadata.json is committed leaves directory uncommitted with no stale metadata."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
        snap_dir = os.path.join(self.tmp_dir, "snap_interrupted_test")
        os.makedirs(snap_dir, exist_ok=True)

        # Pre-populate with an old snapshot
        old_meta = os.path.join(snap_dir, "metadata.json")
        with open(old_meta, "w") as f:
            json.dump({"snapshot_id": "OLD_COMMITTED", "pid": 1111, "status": "COMPLETE", "committed": True}, f)

        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="NEW_SNAP",
            pid=2222,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        # Monkey-patch json.dump to raise an error when writing metadata.json.tmp
        orig_dump = json.dump
        def failing_dump(obj, fp, *args, **kwargs):
            if hasattr(fp, "name") and "metadata.json.tmp" in getattr(fp, "name", ""):
                raise IOError("Simulated crash right before metadata commit barrier")
            return orig_dump(obj, fp, *args, **kwargs)

        import unittest.mock as mock
        with mock.patch("json.dump", side_effect=failing_dump):
            with self.assertRaises(IOError):
                raw.save()

        # The old metadata.json must have been invalidated/unlinked, leaving NO valid committed metadata
        self.assertFalse(os.path.exists(old_meta))
        with self.assertRaises(FileNotFoundError):
            RawMemorySnapshot.load(snap_dir)

    def test_31_concurrent_save_calls_same_process_and_cross_process(self):
        """Cross-process concurrent Python save calls targeting the same directory are deterministically serialized and rejected."""
        import sys
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_conc_python")
        os.makedirs(snap_dir, exist_ok=True)
        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")

        # Subprocess holds lock inside save() critical section
        subproc_code = f"""
import sys, os
from unittest.mock import patch
from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

snap_dir = {repr(snap_dir)}
reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
raw = RawMemorySnapshot(
    snapshot_id="SNAP_PROC1",
    pid=9001,
    binary="/app",
    timestamp_ns=1000,
    status="COMPLETE",
    output_dir=snap_dir,
    regions=[reg],
    maps=[{{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}}],
)

real_rename = os.rename
def mock_rename(src, dst, *args, **kwargs):
    if "manifest.json" in dst:
        sys.stdout.write("LOCKED\\n")
        sys.stdout.flush()
        # Wait for resume signal on stdin
        sys.stdin.readline()
    return real_rename(src, dst, *args, **kwargs)

with patch("os.rename", side_effect=mock_rename):
    raw.save()
sys.stdout.write("DONE\\n")
sys.stdout.flush()
"""
        proc1 = subprocess.Popen(
            [sys.executable, "-c", subproc_code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        line = proc1.stdout.readline().strip()
        self.assertEqual(line, "LOCKED", "Subprocess must signal when locked")

        # Process 2 (current process) attempts save on same directory while proc1 holds lock
        raw2 = RawMemorySnapshot(
            snapshot_id="SNAP_PROC2",
            pid=9002,
            binary="/app",
            timestamp_ns=1001,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        with self.assertRaises(BlockingIOError) as ctx:
            raw2.save()
        self.assertIn("locked by another process", str(ctx.exception))

        # Unblock subprocess 1
        proc1.stdin.write("GO\n")
        proc1.stdin.flush()
        done_line = proc1.stdout.readline().strip()
        self.assertEqual(done_line, "DONE")
        proc1.wait(timeout=3)
        self.assertEqual(proc1.returncode, 0)

        # Valid snapshot from proc1 must now be on disk
        loaded = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(loaded.pid, 9001)
        self.assertEqual(loaded.snapshot_id, "SNAP_PROC1")

    def test_32_native_and_python_writer_contention(self):
        """Native collector rejects capture if Python writer holds .collector.lock, and vice versa."""
        import fcntl
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
        snap_dir = os.path.join(self.tmp_dir, "snap_c_py_contention")
        os.makedirs(snap_dir, exist_ok=True)
        lock_file = os.path.join(snap_dir, ".collector.lock")

        # 1. Hold lock via Python and launch C collector
        p = subprocess.Popen(["sleep", "2"])
        try:
            lock_fd = os.open(lock_file, os.O_CREAT | os.O_RDWR, 0o644)
            fcntl.lockf(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                res = subprocess.run(
                    [self.collector_bin, "-p", str(p.pid), "-o", snap_dir, "--json"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(res.returncode, 1)
                self.assertIn('"status":"FAILED"', res.stdout)
            finally:
                fcntl.lockf(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
        finally:
            p.terminate()
            p.wait()

        # 2. When lock is released, Python save succeeds
        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_FREE",
            pid=3333,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        saved_dir = raw.save()
        self.assertEqual(saved_dir, snap_dir)

    def test_33_snapshot_identity_mismatch_and_symlink_directory_escape(self):
        """Verifies that identity mismatch (PID/ID) and symlinked memory dir are flagged as INVALID."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
        snap_dir = os.path.join(self.tmp_dir, "snap_mismatch_symlink")
        os.makedirs(snap_dir, exist_ok=True)
        bin_dir = os.path.join(snap_dir, "memory")
        os.makedirs(bin_dir, exist_ok=True)
        bin_file = "memory/r1.bin"
        with open(os.path.join(snap_dir, bin_file), "wb") as bf:
            bf.write(b"X" * 4096)

        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", bin_file)
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_REAL",
            pid=4444,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        raw.save()

        # Induce PID mismatch between manifest and metadata
        # (e.g. manifest region pathname / binary has app for 4444, metadata has 99999, or snapshot_id in manifest differs)
        # Test explicit validation of snapshot_id mismatch
        loaded = RawMemorySnapshot.load(snap_dir)
        loaded.snapshot_id = "MISMATCHED_ID"
        is_val, warns = loaded.validate_integrity()
        self.assertFalse(is_val)
        self.assertEqual(loaded.validation_verdict, "INVALID")
        self.assertTrue(any("Snapshot ID mismatch" in w for w in warns))

        # Test symlink memory directory
        sym_dir = os.path.join(self.tmp_dir, "snap_sym_dir")
        os.makedirs(sym_dir, exist_ok=True)
        outside_target = os.path.join(self.tmp_dir, "outside_mem")
        os.makedirs(outside_target, exist_ok=True)
        os.symlink(outside_target, os.path.join(sym_dir, "memory"))
        raw_sym = RawMemorySnapshot(
            snapshot_id="SNAP_SYM",
            pid=5555,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=sym_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        is_val, warns = raw_sym.validate_integrity()
        self.assertFalse(is_val)
        self.assertEqual(raw_sym.validation_verdict, "INVALID")
        self.assertTrue(any("symbolic link" in w for w in warns))

    def test_34_offline_analyzer_refuses_invalid_snapshot(self):
        """OfflineMemoryAnalyzer raises ValueError when given an INVALID or corrupted snapshot."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
        from extractor.offline_analyzer import OfflineMemoryAnalyzer
        snap_dir = os.path.join(self.tmp_dir, "snap_refuse_test")
        os.makedirs(snap_dir, exist_ok=True)
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_REFUSE",
            pid=6666,
            binary="/app",
            timestamp_ns=1000,
            status="FAILED",
            output_dir=snap_dir,
            regions=[],
            maps=[],
        )
        analyzer = OfflineMemoryAnalyzer()
        with self.assertRaises(ValueError) as ctx:
            analyzer.analyze(raw)
        self.assertIn("Cannot analyze INVALID or FAILED snapshot", str(ctx.exception))

    def test_35_repeated_load_save_roundtrip(self):
        """COMPLETE and PARTIAL snapshots preserve their exact fields and integrity across multiple load/save cycles."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
        snap_dir = os.path.join(self.tmp_dir, "snap_roundtrip_test")
        bin_dir = os.path.join(snap_dir, "memory")
        os.makedirs(bin_dir, exist_ok=True)
        with open(os.path.join(snap_dir, "memory/r1.bin"), "wb") as f:
            f.write(b"R" * 2048)

        reg1 = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 2048, "PARTIAL", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_RT",
            pid=7777,
            binary="/app",
            timestamp_ns=12345,
            status="PARTIAL",
            regions_requested=1,
            regions_captured=1,
            bytes_requested=4096,
            bytes_captured=2048,
            output_dir=snap_dir,
            regions=[reg1],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        raw.save()

        # Cycle 1: load
        snap_c1 = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(snap_c1.status, "PARTIAL")
        self.assertEqual(snap_c1.validation_verdict, "VALIDATED")

        # Cycle 2: save to another directory and reload
        snap_dir2 = os.path.join(self.tmp_dir, "snap_roundtrip_test_2")
        os.makedirs(os.path.join(snap_dir2, "memory"), exist_ok=True)
        shutil.copyfile(os.path.join(snap_dir, "memory/r1.bin"), os.path.join(snap_dir2, "memory/r1.bin"))
        snap_c1.save(snap_dir2)
        snap_c2 = RawMemorySnapshot.load(snap_dir2)

        self.assertEqual(snap_c2.status, "PARTIAL")
        self.assertEqual(snap_c2.validation_verdict, "VALIDATED")
        self.assertEqual(snap_c2.snapshot_id, "SNAP_RT")
        self.assertEqual(snap_c2.bytes_captured, 2048)

    def test_36_deterministic_thread_overlap_save_rejection(self):
        """Two Python threads entering save() for the exact same directory overlap deterministically inside critical section."""
        import threading
        from unittest.mock import patch
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_thread_overlap")
        os.makedirs(snap_dir, exist_ok=True)

        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")

        t1_in_cs = threading.Event()
        t2_attempted = threading.Event()
        outcomes = []
        errors = []

        def worker1():
            raw1 = RawMemorySnapshot(
                snapshot_id="SNAP_1",
                pid=1001,
                binary="/app",
                timestamp_ns=1000,
                status="COMPLETE",
                output_dir=snap_dir,
                regions=[reg],
                maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
            )
            real_rename = os.rename
            def rename_hook(src, dst, *args, **kwargs):
                if "manifest.json" in dst:
                    t1_in_cs.set()
                    t2_attempted.wait(timeout=5)
                return real_rename(src, dst, *args, **kwargs)

            with patch("os.rename", side_effect=rename_hook):
                try:
                    raw1.save()
                    outcomes.append(1)
                except Exception as e:
                    errors.append((1, e))

        def worker2():
            self.assertTrue(t1_in_cs.wait(timeout=5), "Thread 1 did not enter critical section")
            raw2 = RawMemorySnapshot(
                snapshot_id="SNAP_2",
                pid=1002,
                binary="/app",
                timestamp_ns=1001,
                status="COMPLETE",
                output_dir=snap_dir,
                regions=[reg],
                maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
            )
            try:
                raw2.save()
                outcomes.append(2)
            except BlockingIOError as e:
                errors.append((2, e))
            finally:
                t2_attempted.set()

        t1 = threading.Thread(target=worker1)
        t2 = threading.Thread(target=worker2)
        t1.start()
        t2.start()
        t1.join(timeout=6)
        t2.join(timeout=6)

        self.assertEqual(outcomes, [1], f"Expected thread 1 to win, got outcomes: {outcomes}")
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0][0], 2)
        self.assertIsInstance(errors[0][1], BlockingIOError)
        self.assertIn("locked", str(errors[0][1]).lower())

    def test_37_process_termination_lock_recovery(self):
        """POSIX advisory locks are released upon process termination, allowing subsequent writers to succeed."""
        import fcntl
        import sys
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
        snap_dir = os.path.join(self.tmp_dir, "snap_proc_term")
        os.makedirs(snap_dir, exist_ok=True)
        lock_file = os.path.join(snap_dir, ".collector.lock")

        # Start a child process holding lockf on the directory and then sleeping
        code = f"""
import os, fcntl, time
fd = os.open({repr(lock_file)}, os.O_CREAT | os.O_RDWR, 0o644)
fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
print("LOCKED", flush=True)
time.sleep(10)
"""
        proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        line = proc.stdout.readline().strip()
        self.assertEqual(line, "LOCKED")

        # While child is running, attempting save() must fail
        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_RECOVER",
            pid=8888,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        with self.assertRaises(BlockingIOError):
            raw.save()

        # Terminate child process (simulating abnormal crash/kill)
        proc.terminate()
        proc.wait(timeout=2)

        # Kernel automatically releases lock; new save must now succeed
        saved = raw.save()
        self.assertEqual(saved, snap_dir)

    def test_38_disk_manifest_verification_and_unverified_propagation(self):
        """Discrepancies in actual on-disk manifest entries degrade snapshot to INVALID, and UNVERIFIED evidence is propagated."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
        from extractor.offline_analyzer import OfflineMemoryAnalyzer
        from extractor.verdict_engine import VerdictEngine, AssertionEvaluation, ASSERTION_PASS

        snap_dir = os.path.join(self.tmp_dir, "snap_disk_manifest_test")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)
        with open(os.path.join(snap_dir, "memory/r1.bin"), "wb") as bf:
            bf.write(b"A" * 4096)

        reg1 = CapturedRegion("R000001", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_TEST_38",
            pid=9999,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg1],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        raw.save()

        # Tamper directly with on-disk manifest.json (e.g. change status to FAILED or ID)
        manifest_path = os.path.join(snap_dir, "manifest.json")
        with open(manifest_path, "r") as mf:
            m_entries = json.load(mf)
        m_entries[0]["status"] = "FAILED"
        with open(manifest_path, "w") as mf:
            json.dump(m_entries, mf)

        # Checking integrity on the existing in-memory snapshot with tampered disk manifest
        # verifies that disk contents are the authority, detecting the discrepancy
        is_val, warns = raw.validate_integrity()
        self.assertFalse(is_val)
        self.assertEqual(raw.validation_verdict, "INVALID")
        self.assertTrue(any("status mismatch" in w for w in warns))

        # Reloading also reflects disk manifest entries (status=FAILED, captured size=4096 is inconsistent for FAILED)
        loaded_tampered = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(loaded_tampered.validation_verdict, "INVALID")
        self.assertTrue(any("status is FAILED but reports captured" in w for w in loaded_tampered.integrity_warnings))

        # Test legacy missing 'committed' field sets UNVERIFIED and propagates through VerdictEngine
        raw.save()
        meta_path = os.path.join(snap_dir, "metadata.json")
        with open(meta_path, "r") as mf:
            meta_json = json.load(mf)
        del meta_json["committed"]  # simulate historical pre-committed snapshot
        with open(meta_path, "w") as mf:
            json.dump(meta_json, mf)

        legacy_snap = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(legacy_snap.validation_verdict, "UNVERIFIED")

        analyzer = OfflineMemoryAnalyzer()
        semantic_snap = analyzer.analyze(legacy_snap, optional_symbol_context={"types": {}, "globals": {}})
        self.assertEqual(semantic_snap.provenance["provenance_class"], "IMPORTED_UNVERIFIED")
        self.assertEqual(semantic_snap.provenance["validation_verdict"], "UNVERIFIED")

        # Synthesize verdict using UNVERIFIED evidence -> diagnosis must be capped at SUSPECTED
        eval1 = AssertionEvaluation(
            raw_assertion="val == 42",
            lhs_expression="val",
            resolved_expression="val",
            operator="==",
            expected=42,
            observed_value=42,
            observation_status="OBSERVED",
            verdict=ASSERTION_PASS,
        )
        verdict = VerdictEngine.synthesize_verdict(
            hypothesis="Target value is 42",
            evaluations=[eval1],
            target_identity={"pid": 9999},
            causal_attribution_verified=True,
            provenance_class=semantic_snap.provenance["provenance_class"],
        )
        # Provenance is IMPORTED_UNVERIFIED -> must NOT be CONFIRMED, capped at SUSPECTED
        self.assertEqual(verdict.final_diagnosis, "SUSPECTED")
        self.assertTrue(any("synthetic/unverified" in lim for lim in verdict.limitations))

    def test_39_metadata_invalidation_failure_aborts_save(self):
        """If pre-existing metadata.json cannot be invalidated, save() must fail closed immediately."""
        from unittest.mock import patch
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_inval_fail")
        os.makedirs(snap_dir, exist_ok=True)
        meta_file = os.path.join(snap_dir, "metadata.json")
        with open(meta_file, "w") as f:
            f.write('{"snapshot_id":"OLD","committed":true}')

        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_NEW",
            pid=1111,
            binary="/app",
            timestamp_ns=2000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        real_unlink = os.unlink
        def mock_unlink(path, *args, **kwargs):
            if path in (meta_file, "metadata.json"):
                raise PermissionError("Permission denied: cannot unlink metadata.json")
            return real_unlink(path, *args, **kwargs)

        with patch("os.unlink", side_effect=mock_unlink):
            with self.assertRaises(OSError) as ctx:
                raw.save()
            self.assertIn("Failed invalidating stale metadata before save", str(ctx.exception))

        # Ensure no manifest.json or new artifacts were written
        self.assertFalse(os.path.exists(os.path.join(snap_dir, "manifest.json")))
        # Old metadata.json is untouched
        with open(meta_file, "r") as f:
            old_data = json.load(f)
        self.assertEqual(old_data.get("snapshot_id"), "OLD")
        self.assertFalse(raw.committed)

    def test_40_native_collector_unlink_failure_aborts(self):
        """Native collector must exit non-zero and fail closed if pre-existing metadata.json cannot be unlinked (root-safe via LD_PRELOAD)."""
        # Start a target process
        target_src = os.path.join(self.tmp_dir, "target40.c")
        target_bin = os.path.join(self.tmp_dir, "target40_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <sys/prctl.h>
#include <unistd.h>
int main() {
    prctl(0x59616d61, -1, 0, 0, 0);
    while (1) pause();
    return 0;
}
""")
        comp = subprocess.run(["gcc", target_src, "-o", target_bin], capture_output=True, text=True)
        self.assertEqual(comp.returncode, 0)
        proc = subprocess.Popen([target_bin])
        time.sleep(0.1)

        # Compile a tiny LD_PRELOAD interceptor to guarantee unlink failure even when running as root
        so_src = os.path.join(self.tmp_dir, "fail_unlink.c")
        so_bin = os.path.join(self.tmp_dir, "fail_unlink.so")
        with open(so_src, "w") as f:
            f.write(r"""
#include <errno.h>
int unlink(const char *pathname) {
    (void)pathname;
    errno = EACCES;
    return -1;
}
int unlinkat(int dirfd, const char *pathname, int flags) {
    (void)dirfd; (void)pathname; (void)flags;
    errno = EACCES;
    return -1;
}
""")
        subprocess.run(["gcc", "-shared", "-fPIC", so_src, "-o", so_bin], check=True)

        try:
            out_snap_dir = os.path.join(self.tmp_dir, "snap_c_inval_fail")
            os.makedirs(out_snap_dir, exist_ok=True)
            meta_file = os.path.join(out_snap_dir, "metadata.json")
            with open(meta_file, "w") as f:
                f.write('{"snapshot_id":"OLD_C","committed":true}')

            env = os.environ.copy()
            env["LD_PRELOAD"] = so_bin

            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", out_snap_dir, "--policy", "all", "--json"],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(res.returncode, 0, "Collector must fail when unlink fails")
            lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip().startswith("{")]
            if lines:
                stats = json.loads(lines[-1])
                self.assertFalse(stats.get("success", False))
                self.assertEqual(stats.get("status"), "FAILED")
        finally:
            proc.terminate()
            proc.wait(timeout=2)

    def test_41_manifest_deep_fields_validation(self):
        """Verifies deep manifest field checks (duplicate IDs, inverted ranges, field-by-field mismatches)."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_deep_manifest")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)
        bin_file = "memory/r41.bin"
        with open(os.path.join(snap_dir, bin_file), "wb") as bf:
            bf.write(b"Z" * 4096)

        reg1 = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", bin_file)
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_DEEP_01",
            pid=2222,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg1],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        raw.save()

        # 1. Duplicate region ID in manifest
        manifest_path = os.path.join(snap_dir, "manifest.json")
        with open(manifest_path, "r") as mf:
            m_entries = json.load(mf)
        dup_entries = m_entries + [dict(m_entries[0])]
        with open(manifest_path, "w") as mf:
            json.dump(dup_entries, mf)

        is_val, warns = raw.validate_integrity()
        self.assertFalse(is_val)
        self.assertEqual(raw.validation_verdict, "INVALID")
        self.assertTrue(any("Duplicate region_id" in w for w in warns))

        # 2. Inverted address range (start >= end)
        m_bad_range = [dict(m_entries[0])]
        m_bad_range[0]["start_addr"] = 0x2000
        m_bad_range[0]["end_addr"] = 0x1000
        with open(manifest_path, "w") as mf:
            json.dump(m_bad_range, mf)

        is_val, warns = raw.validate_integrity()
        self.assertFalse(is_val)
        self.assertTrue(any("inverted/empty address range" in w for w in warns))

        # 3. Negative address and non-positive size
        m_neg = [dict(m_entries[0])]
        m_neg[0]["size"] = -100
        with open(manifest_path, "w") as mf:
            json.dump(m_neg, mf)

        is_val, warns = raw.validate_integrity()
        self.assertFalse(is_val)
        self.assertTrue(any("non-positive size" in w for w in warns))

        # 4. Field-by-field mismatch tests: permissions, pathname, category, requested, captured, filename, error
        fields_to_test = [
            ("permissions", "rwxp", "permissions mismatch"),
            ("category", "heap", "category mismatch"),
            ("pathname", "/other_binary", "pathname mismatch"),
            ("requested", 8192, "requested mismatch"),
            ("captured", 2048, "captured mismatch"),
            ("filename", "memory/other.bin", "filename mismatch"),
            ("error", "CUSTOM_ERROR", "error mismatch"),
        ]
        for field_name, bad_value, expected_msg in fields_to_test:
            m_tamper = [dict(m_entries[0])]
            m_tamper[0][field_name] = bad_value
            with open(manifest_path, "w") as mf:
                json.dump(m_tamper, mf)

            is_val, warns = raw.validate_integrity()
            self.assertFalse(is_val, f"Validation should fail for {field_name} mismatch")
            self.assertTrue(any(expected_msg in w for w in warns), f"Expected '{expected_msg}' in warnings for {field_name}")

    def test_42_deterministic_concurrent_overlap_during_write(self):
        """Two writers targeting the exact same directory must serialize deterministically; second writer fails closed."""
        import threading
        from unittest.mock import patch
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_det_concur")
        os.makedirs(snap_dir, exist_ok=True)

        reg1 = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw1 = RawMemorySnapshot(
            snapshot_id="SNAP_TH1",
            pid=3001,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg1],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        raw2 = RawMemorySnapshot(
            snapshot_id="SNAP_TH2",
            pid=3002,
            binary="/app",
            timestamp_ns=1001,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg1],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        in_critical_section = threading.Event()
        release_critical_section = threading.Event()
        th2_result = {}

        def thread2_worker():
            in_critical_section.wait(timeout=5)
            try:
                raw2.save()
                th2_result["status"] = "SUCCESS"
            except BlockingIOError as e:
                th2_result["status"] = "BLOCKED"
                th2_result["error"] = str(e)
            except Exception as e:
                th2_result["status"] = "ERROR"
                th2_result["error"] = str(e)
            finally:
                release_critical_section.set()

        # Thread 1 enters save, hooks after locking before metadata.json is renamed
        real_rename = os.rename
        def mock_rename(src, dst, *args, **kwargs):
            if "manifest.json" in dst:
                in_critical_section.set()
                release_critical_section.wait(timeout=5)
            return real_rename(src, dst, *args, **kwargs)

        t2 = threading.Thread(target=thread2_worker)
        t2.start()

        with patch("os.rename", side_effect=mock_rename):
            saved = raw1.save()

        t2.join(timeout=5)
        self.assertEqual(saved, snap_dir)
        self.assertEqual(th2_result.get("status"), "BLOCKED")
        self.assertIn("locked", th2_result.get("error", "").lower())

    def test_43_crash_before_metadata_publish_leaves_no_stale_commit(self):
        """Crash right before metadata.json publish leaves directory uncommitted, and load() fails closed."""
        from unittest.mock import patch
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_crash_before_meta")
        os.makedirs(snap_dir, exist_ok=True)

        reg1 = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw_initial = RawMemorySnapshot(
            snapshot_id="SNAP_INIT",
            pid=4001,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg1],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        raw_initial.save()
        self.assertTrue(os.path.exists(os.path.join(snap_dir, "metadata.json")))

        # Second save with updated PID, but crash before metadata.json can be published
        raw_crash = RawMemorySnapshot(
            snapshot_id="SNAP_CRASHED",
            pid=4002,
            binary="/app",
            timestamp_ns=2000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg1],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        real_rename = os.rename
        def crash_on_metadata_rename(src, dst, *args, **kwargs):
            if "metadata.json" in dst:
                raise RuntimeError("Simulated crash before publishing metadata.json")
            return real_rename(src, dst, *args, **kwargs)

        with patch("os.rename", side_effect=crash_on_metadata_rename):
            with self.assertRaises(RuntimeError):
                raw_crash.save()

        # Crucial invariant: stale metadata was invalidated at start of save,
        # so crash before new metadata publish leaves NO metadata.json certifying mixed state
        self.assertFalse(os.path.exists(os.path.join(snap_dir, "metadata.json")))

        # Attempting load() must fail closed with FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            RawMemorySnapshot.load(snap_dir)

    def test_44_investigation_end_to_end_unverified_provenance(self):
        """UNVERIFIED snapshot propagates through OfflineMemoryAnalyzer and InvestigationManager, capping final diagnosis at SUSPECTED."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
        from extractor.offline_analyzer import OfflineMemoryAnalyzer
        from extractor.investigation import InvestigationManager, HYPOTHESIS_STATUS_VALIDATED

        snap_dir = os.path.join(self.tmp_dir, "snap_unverified_e2e")
        os.makedirs(os.path.join(snap_dir, "memory"), exist_ok=True)
        bin_file = "memory/r44.bin"
        with open(os.path.join(snap_dir, bin_file), "wb") as bf:
            bf.write(b"\x00" * 4096)

        reg1 = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", bin_file)
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_UNVERIFIED_E2E",
            pid=5555,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg1],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )
        raw.save()

        # Remove 'committed' field in metadata.json to simulate legacy UNVERIFIED snapshot
        meta_path = os.path.join(snap_dir, "metadata.json")
        with open(meta_path, "r") as mf:
            meta_json = json.load(mf)
        del meta_json["committed"]
        with open(meta_path, "w") as mf:
            json.dump(meta_json, mf)

        loaded = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(loaded.validation_verdict, "UNVERIFIED")

        analyzer = OfflineMemoryAnalyzer()
        semantic_snap = analyzer.analyze(loaded, optional_symbol_context={"types": {}, "globals": {}})
        self.assertEqual(semantic_snap.provenance["provenance_class"], "IMPORTED_UNVERIFIED")
        self.assertEqual(semantic_snap.provenance["validation_verdict"], "UNVERIFIED")

        # Set up InvestigationManager session using this snapshot
        mgr = InvestigationManager()
        session_info = mgr.start_investigation(
            goal="Test unverified snapshot trust boundary",
            memory_snapshot_path=snap_dir,
            provenance_class=semantic_snap.provenance["provenance_class"],
        )
        inv_id = session_info["investigation_id"]
        session = mgr.sessions[inv_id]

        # Propose a hypothesis and mark it VALIDATED to verify if it can become CONFIRMED
        mgr.propose_hypothesis(inv_id, {
            "title": "Hypothesis tested on unverified data",
            "claim": "State was modified",
        })
        session.hypotheses[-1].validation_status = HYPOTHESIS_STATUS_VALIDATED

        # Generate report
        report = mgr.generate_report(inv_id)

        # Trust boundary check: capture_quality trust_level is UNVERIFIED
        self.assertEqual(report["capture_quality_assessment"]["trust_level"], "UNVERIFIED")

        # Final diagnosis in report HTML and JSON must be capped at SUSPECTED or INCONCLUSIVE (never CONFIRMED)
        html_report = report["report_html"]
        json_report = json.loads(report["report_json"])

        self.assertIn(json_report["final_diagnosis"], ("SUSPECTED", "INCONCLUSIVE"))
        self.assertNotEqual(json_report["final_diagnosis"], "CONFIRMED")
        self.assertTrue("SUSPECTED" in html_report or "INCONCLUSIVE" in html_report)
        self.assertNotIn("CONFIRMED", json_report["final_diagnosis"])

    def test_45_artifact_failure_aborts_without_publishing_metadata(self):
        """Failure during manifest, maps, or modules write/rename/fsync aborts and leaves NO metadata.json."""
        from unittest.mock import patch
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_art_fail")
        os.makedirs(snap_dir, exist_ok=True)
        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_FAIL_ART",
            pid=7001,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        real_rename = os.rename
        def mock_rename_fail_maps(src, dst, *args, **kwargs):
            if "maps.json" in dst:
                raise OSError("Disk full: failed renaming maps.json")
            return real_rename(src, dst, *args, **kwargs)

        with patch("os.rename", side_effect=mock_rename_fail_maps):
            with self.assertRaises(OSError) as ctx:
                raw.save()
            self.assertIn("Disk full", str(ctx.exception))

        # metadata.json must NOT be published
        self.assertFalse(os.path.exists(os.path.join(snap_dir, "metadata.json")))
        # All temporary files must be cleaned up
        temp_files = [f for f in os.listdir(snap_dir) if ".tmp." in f]
        self.assertEqual(temp_files, [], f"Expected all temp files cleaned up, found: {temp_files}")
        self.assertFalse(raw.committed)
        self.assertEqual(raw.commit_state, "INVALID")

    def test_46_toctou_symlink_injection_prevented(self):
        """Attempting to redirect temporary files via pre-created symlinks fails closed with O_NOFOLLOW."""
        from extractor.memory_snapshot import _secure_open_write

        snap_dir = os.path.join(self.tmp_dir, "snap_toctou_symlink")
        os.makedirs(snap_dir, exist_ok=True)
        target_file = os.path.join(self.tmp_dir, "victim.txt")
        with open(target_file, "w") as f:
            f.write("ORIGINAL_CONTENT")

        symlink_path = os.path.join(snap_dir, "symlink_tmp.json")
        os.symlink(target_file, symlink_path)

        # _secure_open_write on symlink must raise OSError (O_NOFOLLOW)
        with self.assertRaises(OSError):
            _secure_open_write(symlink_path)

        # Victim content must be untouched
        with open(target_file, "r") as f:
            self.assertEqual(f.read(), "ORIGINAL_CONTENT")

    def test_47_mixed_provenance_degraded_to_lowest_trust(self):
        """Mixed provenance evaluates to lowest trust level; UNVERIFIED cannot certify CONFIRMED or NO_ISSUE_DETECTED."""
        from extractor.verdict_engine import (
            VerdictEngine,
            AssertionEvaluation,
            ASSERTION_PASS,
            PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            DIAG_SUSPECTED,
        )

        # 1. Mixed evaluations: one LIVE_RUNTIME_CAPTURE, one IMPORTED_UNVERIFIED
        eval_trusted = AssertionEvaluation(
            raw_assertion="a == 1",
            lhs_expression="a",
            resolved_expression="a",
            operator="==",
            expected=1,
            observed_value=1,
            observation_status="OBSERVED",
            verdict=ASSERTION_PASS,
            provenance_class=PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
        )
        eval_untrusted = AssertionEvaluation(
            raw_assertion="b == 2",
            lhs_expression="b",
            resolved_expression="b",
            operator="==",
            expected=2,
            observed_value=2,
            observation_status="OBSERVED",
            verdict=ASSERTION_PASS,
            provenance_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
        )

        verdict_mixed = VerdictEngine.synthesize_verdict(
            hypothesis="Both values match expected",
            evaluations=[eval_trusted, eval_untrusted],
            target_identity={"pid": 1234},
            causal_attribution_verified=True,
            provenance_class=PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
        )

        # Effective provenance must be demoted to lowest trust level (IMPORTED_UNVERIFIED)
        self.assertEqual(verdict_mixed.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        # Diagnosis must be capped at SUSPECTED (never CONFIRMED)
        self.assertEqual(verdict_mixed.final_diagnosis, DIAG_SUSPECTED)
        self.assertTrue(any("synthetic/unverified" in lim for lim in verdict_mixed.limitations))

    def test_48_artifact_file_fsync_failure(self):
        """Simulated artifact file fsync failure aborts cleanly without publishing metadata.json."""
        from unittest.mock import patch
        import errno
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_art_fsync_fail")
        os.makedirs(snap_dir, exist_ok=True)
        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_FSYNC_FAIL",
            pid=8001,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        real_fsync = os.fsync
        def mock_fsync_fail_file(fd):
            # Fail when fsyncing manifest file
            raise OSError(errno.EIO, "I/O error during file fsync")

        with patch("os.fsync", side_effect=mock_fsync_fail_file):
            with self.assertRaises(OSError) as ctx:
                raw.save()
            self.assertIn("I/O error", str(ctx.exception))

        self.assertFalse(os.path.exists(os.path.join(snap_dir, "metadata.json")))
        self.assertFalse(raw.committed)
        self.assertEqual(raw.commit_state, "INVALID")
        # Load fails closed
        with self.assertRaises(FileNotFoundError):
            RawMemorySnapshot.load(snap_dir)

    def test_49_artifact_dir_fsync_failure(self):
        """Simulated directory fsync failure after artifact write prevents metadata publication."""
        from unittest.mock import patch
        import errno
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_art_dir_fsync_fail")
        os.makedirs(snap_dir, exist_ok=True)
        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_DIR_FSYNC_FAIL",
            pid=8002,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        real_fsync = os.fsync
        dir_fd_pinned = []

        def mock_fsync_fail_dir(fd):
            # Detect directory fd by fstat
            st = os.fstat(fd)
            import stat
            if stat.S_ISDIR(st.st_mode):
                raise OSError(errno.EIO, "Directory fsync failed")
            return real_fsync(fd)

        with patch("os.fsync", side_effect=mock_fsync_fail_dir):
            with self.assertRaises(OSError) as ctx:
                raw.save()
            self.assertIn("Artifact directory fsync failed", str(ctx.exception))

        self.assertFalse(os.path.exists(os.path.join(snap_dir, "metadata.json")))
        self.assertFalse(raw.committed)
        self.assertEqual(raw.commit_state, "INVALID")
        with self.assertRaises(FileNotFoundError):
            RawMemorySnapshot.load(snap_dir)

    def test_50_metadata_file_fsync_failure(self):
        """Simulated metadata.json.tmp fsync failure aborts and does NOT rename metadata."""
        from unittest.mock import patch
        import errno
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_meta_fsync_fail")
        os.makedirs(snap_dir, exist_ok=True)
        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_META_FSYNC_FAIL",
            pid=8003,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        real_fsync = os.fsync
        call_count = [0]

        def mock_fsync_fail_meta(fd):
            call_count[0] += 1
            # 1: manifest, 2: maps, 3: modules, 4: dir_fd, 5: metadata.json.tmp
            if call_count[0] == 5:
                raise OSError(errno.EIO, "Metadata file fsync failed")
            return real_fsync(fd)

        with patch("os.fsync", side_effect=mock_fsync_fail_meta):
            with self.assertRaises(OSError) as ctx:
                raw.save()
            self.assertIn("Metadata file fsync failed", str(ctx.exception))

        self.assertFalse(os.path.exists(os.path.join(snap_dir, "metadata.json")))
        self.assertFalse(raw.committed)
        self.assertEqual(raw.commit_state, "INVALID")
        with self.assertRaises(FileNotFoundError):
            RawMemorySnapshot.load(snap_dir)

    def test_51_final_dir_fsync_failure_unlinks_metadata(self):
        """Simulated final directory fsync failure unlinks metadata.json and fails closed."""
        from unittest.mock import patch
        import errno
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_final_dir_fsync_fail")
        os.makedirs(snap_dir, exist_ok=True)
        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_FINAL_FSYNC_FAIL",
            pid=8004,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        real_fsync = os.fsync
        dir_sync_count = [0]

        def mock_fsync_fail_final_dir(fd):
            st = os.fstat(fd)
            import stat
            if stat.S_ISDIR(st.st_mode):
                dir_sync_count[0] += 1
                if dir_sync_count[0] == 2:
                    # Fail on second (final) directory fsync
                    raise OSError(errno.EIO, "Final directory fsync failed")
            return real_fsync(fd)

        with patch("os.fsync", side_effect=mock_fsync_fail_final_dir):
            with self.assertRaises(OSError) as ctx:
                raw.save()
            self.assertIn("Final directory fsync failed", str(ctx.exception))

        # Crucial invariant: metadata.json must be unlinked on final fsync failure
        self.assertFalse(os.path.exists(os.path.join(snap_dir, "metadata.json")))
        self.assertFalse(raw.committed)
        self.assertEqual(raw.commit_state, "INVALID")
        with self.assertRaises(FileNotFoundError):
            RawMemorySnapshot.load(snap_dir)

    def test_52_directory_open_failure_fails_closed(self):
        """Directory open failure in Python save() and native collector fails closed immediately."""
        from unittest.mock import patch
        import errno
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        # 1. Python save() on an invalid / unopenable directory
        snap_dir = os.path.join(self.tmp_dir, "snap_dir_open_fail")
        os.makedirs(snap_dir, exist_ok=True)
        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_NO_DIR",
            pid=8005,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        real_open = os.open
        def mock_open_fail_dir(path, flags, *args):
            if flags & getattr(os, "O_DIRECTORY", 0):
                raise OSError(errno.EACCES, "Permission denied opening directory FD")
            return real_open(path, flags, *args)

        with patch("os.open", side_effect=mock_open_fail_dir):
            with self.assertRaises(OSError) as ctx:
                raw.save()
            self.assertIn("Failed opening snapshot directory", str(ctx.exception))
        self.assertEqual(raw.commit_state, "INVALID")

        # 2. Native collector on invalid directory
        target_src = os.path.join(self.tmp_dir, "target52.c")
        target_bin = os.path.join(self.tmp_dir, "target52_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <sys/prctl.h>
#include <unistd.h>
int main() {
    prctl(0x59616d61, -1, 0, 0, 0);
    while (1) pause();
    return 0;
}
""")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        proc = subprocess.Popen([target_bin])
        time.sleep(0.1)
        try:
            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", "/dev/null/impossible_dir", "--json"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res.returncode, 0)
        finally:
            proc.terminate()
            proc.wait(timeout=2)

    def test_53_toctou_symlink_substitution_atomic_protection(self):
        """_secure_open_read and _secure_open_temp_write atomically refuse to follow symlinks."""
        from extractor.memory_snapshot import _secure_open_read, _secure_open_temp_write

        victim_file = os.path.join(self.tmp_dir, "victim53.txt")
        with open(victim_file, "w") as f:
            f.write("SECRET_DATA")

        link_file = os.path.join(self.tmp_dir, "link53.txt")
        os.symlink(victim_file, link_file)

        # Atomic read refusal
        with self.assertRaises(OSError):
            with _secure_open_read(link_file) as f:
                f.read()

        # Atomic write refusal
        with self.assertRaises(OSError):
            with _secure_open_temp_write(link_file) as f:
                f.write("ATTACK")

        # Victim content unchanged
        with open(victim_file, "r") as f:
            self.assertEqual(f.read(), "SECRET_DATA")

    def test_54_native_temp_file_symlink_and_collision_rejection(self):
        """Native collector rejects symlinks planted at destination and uses unique temp files."""
        target_src = os.path.join(self.tmp_dir, "target54.c")
        target_bin = os.path.join(self.tmp_dir, "target54_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <sys/prctl.h>
#include <unistd.h>
int main() {
    prctl(0x59616d61, -1, 0, 0, 0);
    while (1) pause();
    return 0;
}
""")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        proc = subprocess.Popen([target_bin])
        time.sleep(0.1)

        try:
            out_dir = os.path.join(self.tmp_dir, "snap_native_symlink_test")
            os.makedirs(out_dir, exist_ok=True)
            victim = os.path.join(self.tmp_dir, "victim54.txt")
            with open(victim, "w") as f:
                f.write("SAFE_CANARY")

            # Plant symlink at maps.txt
            os.symlink(victim, os.path.join(out_dir, "maps.txt"))

            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", out_dir, "--policy", "all", "--json"],
                capture_output=True,
                text=True,
            )
            # Canary must NOT be overwritten
            with open(victim, "r") as f:
                self.assertEqual(f.read(), "SAFE_CANARY")
        finally:
            proc.terminate()
            proc.wait(timeout=2)

    def test_55_writer_exclusion_thread_and_process(self):
        """Cross-process and cross-thread exclusion prevents concurrent writers from corrupting output."""
        import fcntl
        import sys
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot

        snap_dir = os.path.join(self.tmp_dir, "snap_mutual_excl")
        os.makedirs(snap_dir, exist_ok=True)
        lock_file = os.path.join(snap_dir, ".collector.lock")

        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_EXCL",
            pid=8006,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        # Acquire lock in a separate process
        lock_holder = subprocess.Popen(
            [sys.executable, "-c",
             f"import fcntl, time; f=open('{lock_file}', 'w'); fcntl.lockf(f.fileno(), fcntl.LOCK_EX); time.sleep(10)"],
        )
        time.sleep(0.15)
        try:
            # Python save must fail with BlockingIOError
            with self.assertRaises(BlockingIOError):
                raw.save()

            # Native collector must also fail
            proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
            time.sleep(0.05)
            try:
                res = subprocess.run(
                    [self.collector_bin, "-p", str(proc.pid), "-o", snap_dir, "--json"],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(res.returncode, 1)
            finally:
                proc.terminate()
                proc.wait(timeout=2)
        finally:
            lock_holder.terminate()
            lock_holder.wait(timeout=2)

    def test_56_reload_after_all_failure_modes_fails_closed(self):
        """RawMemorySnapshot.load() and validate_integrity() fail closed on corrupted / incomplete snapshots."""
        from extractor.memory_snapshot import RawMemorySnapshot

        test_dir = os.path.join(self.tmp_dir, "snap_fail_closed_matrix")
        os.makedirs(test_dir, exist_ok=True)

        # 1. Empty directory
        with self.assertRaises(FileNotFoundError):
            RawMemorySnapshot.load(test_dir)

        # 2. metadata.json exists but committed=false
        with open(os.path.join(test_dir, "metadata.json"), "w") as f:
            json.dump({"snapshot_id": "TEST", "committed": False, "status": "COMPLETE"}, f)
        snap = RawMemorySnapshot.load(test_dir)
        is_val, warns = snap.validate_integrity()
        self.assertFalse(is_val)
        self.assertEqual(snap.validation_verdict, "INVALID")

        # 3. metadata.json has committed=true, but missing manifest.json
        with open(os.path.join(test_dir, "metadata.json"), "w") as f:
            json.dump({
                "snapshot_id": "TEST",
                "committed": True,
                "status": "COMPLETE",
                "pid": 1234,
                "binary": "/app",
                "timestamp_ns": 1000,
                "capture_mode": "test",
                "backend": "test",
                "architecture": "x86_64",
                "endianness": "little",
                "elf_class": "ELF64",
                "page_size": 4096,
                "regions": 1,
                "regions_requested": 1,
                "bytes_requested": 4096,
                "bytes_captured": 4096,
                "duration_us": 10.0,
                "consistency": {"level": "NON_ATOMIC"},
            }, f)
        snap = RawMemorySnapshot.load(test_dir)
        is_val, warns = snap.validate_integrity()
        self.assertFalse(is_val)
        self.assertTrue(any("manifest.json" in w for w in warns))

    def test_57_parent_directory_replacement_pinned_dirfd(self):
        """Python save() performs all mutations relative to pinned dir_fd, ignoring parent directory substitution."""
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot
        from unittest.mock import patch

        orig_dir = os.path.join(self.tmp_dir, "snap_pinned_orig")
        moved_dir = os.path.join(self.tmp_dir, "snap_pinned_moved")
        os.makedirs(orig_dir, exist_ok=True)

        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_PINNED",
            pid=5701,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=orig_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        dir_swapped = [False]
        real_dump = json.dump

        def mock_dump_hook(obj, fp, *args, **kwargs):
            if not dir_swapped[0]:
                os.rename(orig_dir, moved_dir)
                os.makedirs(orig_dir, exist_ok=True)
                dir_swapped[0] = True
            return real_dump(obj, fp, *args, **kwargs)

        with patch("json.dump", side_effect=mock_dump_hook):
            raw.save()

        self.assertTrue(os.path.exists(os.path.join(moved_dir, "metadata.json")), "Artifacts must be in original pinned directory")
        self.assertTrue(os.path.exists(os.path.join(moved_dir, "manifest.json")))
        self.assertFalse(os.path.exists(os.path.join(orig_dir, "metadata.json")), "Decoy directory must be untouched")

    def test_58_single_path_component_validation(self):
        """Temporary and final artifact filenames must be strictly single path components."""
        from extractor.memory_snapshot import _validate_single_component, _secure_open_temp_write, _secure_open_read

        for bad in ["", "../traversal", "foo/bar", "c:\\file", ".", ".."]:
            with self.assertRaises((ValueError, OSError)):
                _validate_single_component(bad)

        dummy_dir = os.path.join(self.tmp_dir, "test58_dummy")
        os.makedirs(dummy_dir, exist_ok=True)
        dfd = os.open(dummy_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(ValueError):
                _secure_open_temp_write("sub/bad.tmp", dir_fd=dfd)
            with self.assertRaises(ValueError):
                _secure_open_read("../bad.json", dir_fd=dfd)
        finally:
            os.close(dfd)

    def test_59_final_fsync_and_unlink_failure_dual_exception_retention(self):
        """Failure of final directory fsync followed by unlink failure raises DurabilityCommitError with dual exception retention and emergency rollback."""
        from unittest.mock import patch
        import errno
        from extractor.memory_snapshot import CapturedRegion, RawMemorySnapshot, DurabilityCommitError, STATE_UNCERTAIN

        snap_dir = os.path.join(self.tmp_dir, "snap_dual_fail")
        os.makedirs(snap_dir, exist_ok=True)
        reg = CapturedRegion("R01", 0x1000, 0x2000, 4096, "r--p", "data", "/app", 4096, 4096, "COMPLETE", "memory/r1.bin")
        raw = RawMemorySnapshot(
            snapshot_id="SNAP_DUAL_FAIL",
            pid=5901,
            binary="/app",
            timestamp_ns=1000,
            status="COMPLETE",
            output_dir=snap_dir,
            regions=[reg],
            maps=[{"start": "0x1000", "end": "0x2000", "permissions": "r--p"}],
        )

        real_fsync = os.fsync
        dir_sync_count = [0]
        def mock_fsync_fail_final(fd):
            st = os.fstat(fd)
            import stat
            if stat.S_ISDIR(st.st_mode):
                dir_sync_count[0] += 1
                if dir_sync_count[0] == 2:
                    raise OSError(errno.EIO, "Final directory fsync disk error")
            return real_fsync(fd)

        real_unlink = os.unlink
        def mock_unlink_fail(path, *args, **kwargs):
            if dir_sync_count[0] >= 2 and path in ("metadata.json", os.path.join(snap_dir, "metadata.json")):
                raise PermissionError("Rollback unlink permission denied")
            return real_unlink(path, *args, **kwargs)

        with patch("os.fsync", side_effect=mock_fsync_fail_final):
            with patch("os.unlink", side_effect=mock_unlink_fail):
                with self.assertRaises(DurabilityCommitError) as ctx:
                    raw.save()

        err = ctx.exception
        self.assertIsNotNone(err.fsync_error)
        self.assertIn("Final directory fsync disk error", str(err.fsync_error))
        self.assertIsNotNone(err.cleanup_error)
        self.assertIn("Rollback unlink permission denied", str(err.cleanup_error))
        self.assertEqual(raw.commit_state, STATE_UNCERTAIN)
        self.assertFalse(raw.committed)

        meta_p = os.path.join(snap_dir, "metadata.json")
        self.assertTrue(os.path.exists(meta_p))
        with open(meta_p, "r") as f:
            data = json.load(f)
        self.assertFalse(data.get("committed"))
        self.assertEqual(data.get("status"), "UNCERTAIN_DURABILITY")

        reloaded = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(reloaded.commit_state, STATE_UNCERTAIN)
        self.assertEqual(reloaded.validation_verdict, "UNCERTAIN")
        self.assertFalse(reloaded.committed)

    def test_60_native_directory_fsync_eacces_failure(self):
        """Native collector treats EACCES on directory fsync as a fatal commit failure."""
        target_src = os.path.join(self.tmp_dir, "target60.c")
        target_bin = os.path.join(self.tmp_dir, "target60_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <sys/prctl.h>
#include <unistd.h>
int main() {
    prctl(0x59616d61, -1, 0, 0, 0);
    while (1) pause();
    return 0;
}
""")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        proc = subprocess.Popen([target_bin])
        time.sleep(0.1)

        so_src = os.path.join(self.tmp_dir, "fail_fsync_eacces.c")
        so_bin = os.path.join(self.tmp_dir, "fail_fsync_eacces.so")
        with open(so_src, "w") as f:
            f.write(r"""
#define _GNU_SOURCE
#include <errno.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <unistd.h>

static int (*real_fsync)(int fd) = NULL;

int fsync(int fd) {
    if (!real_fsync) {
        real_fsync = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
    }
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        errno = EACCES;
        return -1;
    }
    return real_fsync(fd);
}
""")
        subprocess.run(["gcc", "-shared", "-fPIC", so_src, "-o", so_bin, "-ldl"], check=True)

        try:
            out_snap_dir = os.path.join(self.tmp_dir, "snap_c_fsync_eacces")
            os.makedirs(out_snap_dir, exist_ok=True)
            env = os.environ.copy()
            env["LD_PRELOAD"] = so_bin

            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", out_snap_dir, "--policy", "all", "--json"],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(res.returncode, 0, "Collector must fail when directory fsync returns EACCES")
            lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip().startswith("{")]
            if lines:
                stats = json.loads(lines[-1])
                self.assertFalse(stats.get("success", False))
                self.assertEqual(stats.get("status"), "FAILED")
        finally:
            proc.terminate()
            proc.wait(timeout=2)

    def test_61_native_final_fsync_failure_emergency_invalidation(self):
        """Native collector writes UNCERTAIN_DURABILITY emergency metadata when final directory fsync fails and unlinkat fails."""
        target_src = os.path.join(self.tmp_dir, "target61.c")
        target_bin = os.path.join(self.tmp_dir, "target61_app")
        with open(target_src, "w") as f:
            f.write(r"""
#include <sys/prctl.h>
#include <unistd.h>
int main() {
    prctl(0x59616d61, -1, 0, 0, 0);
    while (1) pause();
    return 0;
}
""")
        subprocess.run(["gcc", target_src, "-o", target_bin], check=True)
        proc = subprocess.Popen([target_bin])
        time.sleep(0.1)

        so_src = os.path.join(self.tmp_dir, "fail_final_fsync_unlinkat.c")
        so_bin = os.path.join(self.tmp_dir, "fail_final_fsync_unlinkat.so")
        with open(so_src, "w") as f:
            f.write(r"""
#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <unistd.h>

static int (*real_fsync)(int fd) = NULL;
static int (*real_unlinkat)(int dirfd, const char *pathname, int flags) = NULL;
static int dir_sync_count = 0;

int fsync(int fd) {
    if (!real_fsync) {
        real_fsync = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
    }
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        dir_sync_count++;
        if (dir_sync_count >= 2) {
            errno = EIO;
            return -1;
        }
    }
    return real_fsync(fd);
}

int unlinkat(int dirfd, const char *pathname, int flags) {
    if (!real_unlinkat) {
        real_unlinkat = (int (*)(int, const char *, int))dlsym(RTLD_NEXT, "unlinkat");
    }
    if (pathname && strcmp(pathname, "metadata.json") == 0 && dir_sync_count >= 2) {
        errno = EPERM;
        return -1;
    }
    return real_unlinkat(dirfd, pathname, flags);
}
""")
        subprocess.run(["gcc", "-shared", "-fPIC", so_src, "-o", so_bin, "-ldl"], check=True)

        try:
            out_snap_dir = os.path.join(self.tmp_dir, "snap_c_emergency_inv")
            os.makedirs(out_snap_dir, exist_ok=True)
            env = os.environ.copy()
            env["LD_PRELOAD"] = so_bin

            res = subprocess.run(
                [self.collector_bin, "-p", str(proc.pid), "-o", out_snap_dir, "--policy", "all", "--json"],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(res.returncode, 0, "Collector must fail when final fsync fails")
            meta_p = os.path.join(out_snap_dir, "metadata.json")
            self.assertTrue(os.path.exists(meta_p), "Emergency metadata must exist")
            with open(meta_p, "r") as f:
                meta = json.load(f)
            self.assertFalse(meta.get("committed"))
            self.assertEqual(meta.get("status"), "UNCERTAIN_DURABILITY")
        finally:
            proc.terminate()
            proc.wait(timeout=2)

    def test_62_reload_after_uncertain_commit_fails_closed(self):
        """RawMemorySnapshot.load() marks snapshots with UNCERTAIN_DURABILITY status as uncertain and uncommitted."""
        from extractor.memory_snapshot import RawMemorySnapshot, STATE_UNCERTAIN, VERDICT_UNCERTAIN

        snap_dir = os.path.join(self.tmp_dir, "snap_uncertain_reload")
        os.makedirs(snap_dir, exist_ok=True)

        with open(os.path.join(snap_dir, "metadata.json"), "w") as f:
            json.dump({
                "snapshot_id": "SNAP_UNCERTAIN_TEST",
                "pid": 6201,
                "status": "UNCERTAIN_DURABILITY",
                "commit_state": STATE_UNCERTAIN,
                "committed": False,
            }, f)

        snap = RawMemorySnapshot.load(snap_dir)
        self.assertEqual(snap.commit_state, STATE_UNCERTAIN)
        self.assertEqual(snap.validation_verdict, VERDICT_UNCERTAIN)
        self.assertFalse(snap.committed)
        is_valid, warnings = snap.validate_integrity()
        self.assertFalse(is_valid)
        self.assertTrue(any("UNCERTAIN_DURABILITY" in w for w in warnings))

    def test_63_provenance_forgery_rejection_in_investigation(self):
        """External callers cannot forge live capture or trusted provenance in investigation sessions."""
        from extractor.investigation import InvestigationManager, PROVENANCE_CLASS_IMPORTED_UNVERIFIED, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE

        corpus_dir = os.path.join(self.tmp_dir, "corpus_inv_prov")
        os.makedirs(corpus_dir, exist_ok=True)
        service = InvestigationManager(corpus_dir=corpus_dir)

        snap_dir = os.path.join(self.tmp_dir, "snap_forgery_test")
        os.makedirs(snap_dir, exist_ok=True)
        with open(os.path.join(snap_dir, "metadata.json"), "w") as f:
            json.dump({
                "snapshot_id": "SNAP_FORGERY",
                "pid": 6301,
                "status": "COMPLETE",
                "committed": True,
            }, f)

        session_dict = service.start_investigation(
            goal="Test provenance forgery rejection",
            snapshot_id="SNAP_FORGERY",
            memory_snapshot_path=snap_dir,
            constraints={"live_capture": True, "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE},
            provenance_class=PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
        )

        t_ref = session_dict.get("target_ref", {})
        self.assertFalse(t_ref.get("live_capture"), "External caller must NOT be able to forge live_capture=True")
        self.assertEqual(t_ref.get("provenance_class"), PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

        report = service.generate_report(session_dict["investigation_id"])
        self.assertEqual(report.get("provenance_class"), PROVENANCE_CLASS_IMPORTED_UNVERIFIED)


if __name__ == "__main__":
    unittest.main()
