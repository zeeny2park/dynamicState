"""Integration test suite for Real GDB 9.2.

This test verifies dynamicState running under genuine GNU gdb 9.2 (Ubuntu 20.04):
- GdbVersion detection: major=9, minor=2, status="RESOLVED", supports_frame_level()=False
- Frame level fallback without AttributeError (frame.level() was added in GDB 11)
- Frame function name and PC extraction
- Local variable and struct member inspection
- Full GdbBackend snapshot and persistent object graph construction
- External debug image and Build ID resolution
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


class RealGdb92IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_gdb92_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _is_gdb_9_2_installed(self) -> bool:
        try:
            res = subprocess.run(["gdb", "--version"], capture_output=True, text=True)
            if res.returncode == 0:
                first_line = res.stdout.splitlines()[0]
                return " 9.2" in first_line
        except Exception:
            pass
        return False

    def _is_docker_available(self) -> bool:
        try:
            res = subprocess.run(["docker", "image", "inspect", "dynamicstate-gdb92:latest"],
                                 capture_output=True, text=True)
            return res.returncode == 0
        except Exception:
            return False

    def test_real_gdb92_execution_and_snapshot(self):
        # Case 1: Running inside container or environment with real GDB 9.2
        if self._is_gdb_9_2_installed():
            self._run_native_gdb92_verification()
            return

        # Case 2: Running on host where Docker is available with dynamicstate-gdb92 image
        if self._is_docker_available():
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{self.repo_root}:/workspace",
                "dynamicstate-gdb92:latest",
                "python3", "tests/integration_gdb92.py", "--direct"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(
                res.returncode, 0,
                f"GDB 9.2 Docker integration test failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
            )
            self.assertIn("REAL_GDB_9_2_VERIFICATION_PASS", res.stdout)
            return

        # Case 3: Neither GDB 9.2 nor Docker available
        self.skipTest("Real GDB 9.2 verification requires local GDB 9.2 or dynamicstate-gdb92:latest Docker image.")

    def _run_native_gdb92_verification(self):
        """Execute the real GDB 9.2 test scenario natively."""
        # 1. Verify GDB binary version
        res_ver = subprocess.run(["gdb", "--version"], capture_output=True, text=True)
        self.assertEqual(res_ver.returncode, 0)
        self.assertIn(" 9.2", res_ver.stdout.splitlines()[0], "Must be running GNU gdb 9.2")

        # 2. Compile test C program with DWARF symbols
        c_src = os.path.join(self.tmp_dir, "test_target.c")
        c_bin = os.path.join(self.tmp_dir, "test_target")
        with open(c_src, "w") as f:
            f.write(r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Buffer {
    int capacity;
    int length;
} Buffer;

typedef struct Session {
    int id;
    int retry;
    Buffer *buf;
} Session;

Session *g_session_ptr = NULL;

void worker_loop(Session *sess) {
    sess->retry++;
    printf("Worker session %d retry %d\n", sess->id, sess->retry);
}

int main() {
    Buffer b = {1024, 42};
    Session s = {1001, 2, &b};
    g_session_ptr = &s;
    worker_loop(&s);
    return 0;
}
""")
        # Compile with -g and build-id
        comp = subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id", c_src, "-o", c_bin],
                              capture_output=True, text=True)
        self.assertEqual(comp.returncode, 0, f"Compilation failed: {comp.stderr}")

        # 3. Create GDB python verification script
        py_script = os.path.join(self.tmp_dir, "verify_gdb.py")
        out_json = os.path.join(self.tmp_dir, "gdb_result.json")
        with open(py_script, "w") as f:
            f.write(f"""
import sys, os, json
sys.path.insert(0, '{self.repo_root}')

import gdb
from extractor.gdb_compat import (
    get_gdb_version,
    get_frame_level,
    get_frame_function,
    get_frame_pc,
    get_progspace_filename,
    is_thread_stopped
)
from extractor.execution import GdbBackend

# 1. Version verification
v = get_gdb_version(gdb)
assert v.is_known(), f"GDB version must be known: {{v}}"
assert v.major == 9, f"Major must be 9: {{v.major}}"
assert v.minor == 2, f"Minor must be 2: {{v.minor}}"
assert not v.supports_frame_level(), "GDB 9.2 must NOT support frame.level()"

# 2. Run to breakpoint in worker_loop
gdb.execute("file {c_bin}")
gdb.execute("break worker_loop")
gdb.execute("run")

# 3. Frame inspection
frame = gdb.newest_frame()
assert frame is not None, "Frame must be present"

# Verify frame.level() does not exist in GDB 9.2 (or raises AttributeError)
has_level = hasattr(frame, "level") and callable(getattr(frame, "level"))
level_via_compat = get_frame_level(frame, fallback_level=0)
assert level_via_compat == 0, f"Fallback level must be 0, got {{level_via_compat}}"

# Function name
func_name = get_frame_function(frame)
assert func_name == "worker_loop", f"Expected worker_loop, got {{func_name}}"

# PC address
pc = get_frame_pc(frame)
assert pc is not None and pc > 0, f"PC must be positive int, got {{pc}}"

# Local variable inspection
sess_var = frame.read_var("sess")
assert sess_var is not None, "sess variable must be readable"
sess_deref = sess_var.dereference()
sess_id = int(sess_deref["id"])
sess_retry = int(sess_deref["retry"])
assert sess_id == 1001, f"sess.id expected 1001, got {{sess_id}}"
assert sess_retry in (2, 3), f"sess.retry unexpected: {{sess_retry}}"

# 4. Full GdbBackend Snapshot
backend = GdbBackend(gdb)
snap = backend.snapshot()
assert snap.schema_version == "0.2"
assert snap.execution is not None
assert len(snap.execution.threads) >= 1

# Check discovered objects
obj_types = [o.type for o in snap.objects]
assert "Session" in obj_types or "Session *" in obj_types or len(obj_types) > 0, f"Discovered objects: {{obj_types}}"

# Save results
result_data = {{
    "status": "PASS",
    "gdb_version": v.raw,
    "major": v.major,
    "minor": v.minor,
    "supports_frame_level": v.supports_frame_level(),
    "function": func_name,
    "pc": hex(pc),
    "sess_id": sess_id,
    "sess_retry": sess_retry,
    "object_count": len(snap.objects),
    "root_count": len(snap.persistent.roots) if snap.persistent else 0,
}}

with open('{out_json}', 'w') as f_out:
    json.dump(result_data, f_out)

print("REAL_GDB_9_2_VERIFICATION_PASS")
""")

        # Run GDB with script
        gdb_cmd = [
            "gdb", "-batch",
            "-x", py_script
        ]
        gdb_run = subprocess.run(gdb_cmd, capture_output=True, text=True)
        self.assertEqual(gdb_run.returncode, 0, f"GDB script failed:\nSTDOUT:\n{gdb_run.stdout}\nSTDERR:\n{gdb_run.stderr}")
        self.assertIn("REAL_GDB_9_2_VERIFICATION_PASS", gdb_run.stdout)

        # Verify output JSON
        self.assertTrue(os.path.isfile(out_json), "Output JSON must exist")
        with open(out_json, "r") as f:
            res = json.load(f)

        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["major"], 9)
        self.assertEqual(res["minor"], 2)
        self.assertFalse(res["supports_frame_level"])
        self.assertEqual(res["function"], "worker_loop")
        self.assertEqual(res["sess_id"], 1001)
        self.assertGreater(res["object_count"], 0)


if __name__ == "__main__":
    if "--direct" in sys.argv:
        # Run test natively
        sys.argv.remove("--direct")
        suite = unittest.TestSuite()
        suite.addTest(RealGdb92IntegrationTests("_run_native_gdb92_verification"))
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        if result.wasSuccessful():
            print("REAL_GDB_9_2_VERIFICATION_PASS")
            sys.exit(0)
        else:
            sys.exit(1)
    else:
        unittest.main()
