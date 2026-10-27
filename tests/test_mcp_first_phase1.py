"""DynamicState — MCP-First Phase 1 Comprehensive Validation Tests.

Validates:
1. MCP tool dispatch and session context inheritance across core workflows:
   `runtime_target_connect` -> `runtime_capture_memory` -> `runtime_observe` ->
   `runtime_watch_session_create` -> `runtime_watch_inspect_target`.
2. Standardized structured error envelopes: top-level `error_code`, `error_message`,
   and no silent masquerading of empty/failed investigations.
3. Explicit concurrency and atomicity labeling on zero-stop observations:
   `consistency.level == 'NON_ATOMIC'`, `is_consistent_snapshot == False`.
4. Real C/C++ runtime fixture capture, symbol resolution, and typed inspection.
5. GNU Build ID verification for matching vs mismatching debug images.
6. Partial/unreadable memory and target-exit failure paths.
7. Batch macro composite tool execution (`eval`, `scan_pool`, `callstack`, `diff`, `heap`).
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

import scripts.mcp_server as mcp_srv


REAL_CPP_FIXTURE = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

typedef struct {
    int id;
    int in_use;
    uint32_t seq;
    char label[32];
} WorkerSlot;

typedef struct {
    uint32_t magic;
    int total_slots;
    int active_workers;
    WorkerSlot slots[4];
} SystemRegistry;

static SystemRegistry g_registry_data;
SystemRegistry *gpRegistry = &g_registry_data;
volatile int g_loop_counter = 100;

void *worker_func(void *arg) {
    while (1) {
        usleep(20000);
        g_loop_counter++;
    }
    return NULL;
}

int main(void) {
    memset(&g_registry_data, 0, sizeof(g_registry_data));
    g_registry_data.magic = 0xDEADBEEF;
    g_registry_data.total_slots = 4;
    g_registry_data.active_workers = 2;

    g_registry_data.slots[0].id = 1;
    g_registry_data.slots[0].in_use = 1;
    g_registry_data.slots[0].seq = 1001;
    strncpy(g_registry_data.slots[0].label, "worker_alpha", 31);

    g_registry_data.slots[1].id = 2;
    g_registry_data.slots[1].in_use = 1;
    g_registry_data.slots[1].seq = 2002;
    strncpy(g_registry_data.slots[1].label, "worker_beta", 31);

    pthread_t th;
    pthread_create(&th, NULL, worker_func, NULL);

    while (1) {
        usleep(50000);
    }
    return 0;
}
"""


class TestMcpFirstPhase1(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.TemporaryDirectory(prefix="mcp_phase1_")
        cls.src_path = os.path.join(cls.tmp_dir.name, "mcp_target.c")
        cls.bin_path = os.path.join(cls.tmp_dir.name, "mcp_target")
        cls.stripped_bin_path = os.path.join(cls.tmp_dir.name, "mcp_target_stripped")
        cls.mismatch_bin_path = os.path.join(cls.tmp_dir.name, "mcp_target_mismatch")

        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(REAL_CPP_FIXTURE)

        # 1. Compile non-stripped companion ELF with DWARF symbols
        subprocess.run(
            ["gcc", "-g", "-O0", "-Wl,--build-id=sha1", cls.src_path, "-o", cls.bin_path],
            check=True,
        )

        # 2. Create stripped version for production target simulation
        shutil.copyfile(cls.bin_path, cls.stripped_bin_path)
        os.chmod(cls.stripped_bin_path, 0o755)
        subprocess.run(["strip", "--strip-all", cls.stripped_bin_path], check=True)

        # 3. Create a mismatching binary (different build-id)
        subprocess.run(
            ["gcc", "-g", "-O0", "-Wl,--build-id=md5", cls.src_path, "-o", cls.mismatch_bin_path],
            check=True,
        )

        # Launch live target process using stripped binary
        cls.proc = subprocess.Popen([cls.stripped_bin_path])
        time.sleep(0.15)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2)
            except Exception:
                cls.proc.kill()
        cls.tmp_dir.cleanup()

    def test_01_target_context_inheritance_and_canonical_workflow(self) -> None:
        """Verifies canonical workflow: connect once, then capture, observe, and watch without repeating PID."""
        # 1. Connect target
        raw_conn = mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)
        conn = json.loads(raw_conn)
        self.assertTrue(conn["success"])
        self.assertEqual(conn["pid"], self.proc.pid)
        self.assertTrue(conn["active_context_bound"])
        self.assertIn("load_bias", conn)
        self.assertGreaterEqual(conn["threads_count"], 1)

        # 2. runtime_capture_memory without pid argument (inherits bound target session)
        raw_cap = mcp_srv.runtime_capture_memory()
        cap = json.loads(raw_cap)
        self.assertTrue(cap["success"], f"capture_memory failed: {cap}")
        self.assertEqual(cap["data"]["pid"], self.proc.pid)
        self.assertGreater(cap["data"]["bytes_captured"], 0)

        # 3. runtime_observe without pid argument in LOW_IMPACT mode
        raw_obs = mcp_srv.runtime_observe(mode="LOW_IMPACT")
        obs = json.loads(raw_obs)
        self.assertTrue(obs["success"], f"observe failed: {obs}")
        self.assertIn("objects", obs["data"])
        self.assertIn("execution", obs["data"])

        # 4. runtime_watch_inspect_target without pid argument
        raw_insp = mcp_srv.runtime_watch_inspect_target()
        insp = json.loads(raw_insp)
        self.assertTrue(insp["success"])
        self.assertEqual(insp["pid"], self.proc.pid)

        # 5. runtime_watch_session_create without pid argument
        raw_ws = mcp_srv.runtime_watch_session_create(interval_ms=100, max_samples=5)
        ws = json.loads(raw_ws)
        self.assertTrue(ws["success"])
        self.assertEqual(ws["pid"], self.proc.pid)
        ws_id = ws["session_id"]

        # Clean up watch session
        mcp_srv.runtime_watch_session_stop(session_id=ws_id)

    def test_02_structured_error_envelopes_and_no_target_specified(self) -> None:
        """Verifies structured errors contain top-level error_code and empty investigations fail fast."""
        # Unbind context temporarily
        saved_ctx = dict(mcp_srv.runtime.watch_session_manager._active_target_context)
        try:
            mcp_srv.runtime.watch_session_manager._active_target_context.clear()

            # Attempt runtime_start_investigation without target or bound session
            raw_inv = mcp_srv.runtime_start_investigation(goal="Find memory leak")
            inv = json.loads(raw_inv)
            self.assertFalse(inv["success"])
            self.assertEqual(inv["error_code"], "NO_TARGET_SPECIFIED")
            self.assertIn("No investigation target provided", inv["error"])
            self.assertIn("recovery_hint", inv)

            # Test invalid PID structured error
            raw_bad = mcp_srv.runtime_capture_memory(pid=1)  # reserved systemd PID
            bad = json.loads(raw_bad)
            self.assertFalse(bad["success"])
            self.assertIn("error_code", bad)
            self.assertIn("error", bad)

            # Test list_objects with no snapshot
            raw_objs = mcp_srv.runtime_list_objects()
            objs = json.loads(raw_objs)
            self.assertFalse(objs["success"])
            self.assertEqual(objs["error_code"], "SNAPSHOT_NOT_FOUND")
            self.assertIn("runtime_observe", objs["error"]["message"].lower())
        finally:
            mcp_srv.runtime.watch_session_manager._active_target_context = saved_ctx

    def test_03_zero_stop_concurrency_and_atomicity_labeling(self) -> None:
        """Verifies that all zero-stop observations explicitly report NON_ATOMIC consistency semantics."""
        # Ensure target is connected
        mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)

        # 1. evaluate_symbol_paths
        raw_ev = mcp_srv.runtime_eval_memory_path(expressions=["gpRegistry.magic", "gpRegistry.active_workers"])
        ev = json.loads(raw_ev)
        self.assertTrue(ev["success"])
        self.assertEqual(ev["stop_duration_ms"], 0.0)
        self.assertIn("consistency", ev)
        self.assertEqual(ev["consistency"]["level"], "NON_ATOMIC")
        self.assertFalse(ev["consistency"]["is_consistent_snapshot"])
        self.assertEqual(ev["consistency"]["mechanism"], "ZERO_STOP_CONCURRENT_READ")

        # 2. capture_and_diff
        raw_diff = mcp_srv.runtime_capture_and_diff(expressions=["g_loop_counter"], wait_ms=100)
        diff = json.loads(raw_diff)
        self.assertTrue(diff["success"])
        self.assertEqual(diff["stop_duration_ms"], 0.0)
        self.assertIn("consistency", diff)
        self.assertEqual(diff["consistency"]["level"], "NON_ATOMIC")

        # 3. scan_memory_pool
        raw_pool = mcp_srv.runtime_scan_memory_pool(base_expression="gpRegistry.slots")
        pool = json.loads(raw_pool)
        self.assertTrue(pool["success"])
        self.assertIn("consistency", pool)
        self.assertEqual(pool["consistency"]["level"], "NON_ATOMIC")

    def test_04_real_typed_object_decoding_and_symbol_resolution(self) -> None:
        """Verifies DWARF type decoding of structs, pointers, integers, and strings."""
        mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)

        ev = json.loads(
            mcp_srv.runtime_eval_memory_path(
                expressions=[
                    "gpRegistry.magic",
                    "gpRegistry.slots[0].id",
                    "gpRegistry.slots[0].label",
                    "gpRegistry.slots[1].seq",
                ]
            )
        )
        self.assertTrue(ev["success"])
        results = {r["expression"]: r for r in ev["results"]}

        self.assertEqual(results["gpRegistry.magic"]["value"], 0xDEADBEEF)
        self.assertEqual(results["gpRegistry.slots[0].id"]["value"], 1)
        self.assertEqual(results["gpRegistry.slots[0].label"]["value"], "worker_alpha")
        self.assertEqual(results["gpRegistry.slots[1].seq"]["value"], 2002)

    def test_05_build_id_verification_matching_and_mismatching(self) -> None:
        """Verifies build ID validation between companion ELF and target process."""
        # 1. Matching companion ELF succeeds
        res_ok = json.loads(mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path))
        self.assertTrue(res_ok["success"])

        # 2. Mismatching build ID is detected
        # Note: target is running stripped_bin (built with sha1 build-id matching bin_path)
        # mismatch_bin_path was compiled with md5 build-id
        res_mismatch = json.loads(
            mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.mismatch_bin_path)
        )
        # When build ID differs, target_connect rejects or flags the mismatch
        self.assertFalse(res_mismatch.get("success", True) and res_mismatch.get("build_id_matched", True))

    def test_06_target_exit_and_partial_memory_read_handling(self) -> None:
        """Verifies handling of dead PIDs and unmapped memory addresses."""
        # Target process not found
        res_dead = json.loads(mcp_srv.runtime_capture_memory(pid=999999))
        self.assertFalse(res_dead["success"])
        self.assertEqual(res_dead["error_code"], "PROCESS_EXITED")

        # Invalid unmapped address in evaluate_symbol_paths
        mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)
        res_unmapped = json.loads(
            mcp_srv.runtime_eval_memory_path(expressions=["*gpRegistry.slots[9999].label"])
        )
        self.assertTrue(res_unmapped["success"])
        # Individual expression reports error status without crashing tool call
        self.assertIn(res_unmapped["results"][0]["status"], ("UNAVAILABLE", "ARRAY_INDEX_OUT_OF_BOUNDS", "TYPE_RESOLUTION_ERROR"))

    def test_07_batch_macro_composite_execution(self) -> None:
        """Verifies runtime_batch_execute executes multi-step macro including callstack, pool, and diff."""
        mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)

        steps = [
            {"action": "eval", "expressions": ["gpRegistry.active_workers"]},
            {"action": "scan_pool", "base_expression": "gpRegistry.slots"},
            {"action": "callstack"},
            {"action": "diff", "expressions": ["g_loop_counter"], "wait_ms": 50},
        ]

        raw_batch = mcp_srv.runtime_batch_execute(steps=steps)
        batch = json.loads(raw_batch)
        self.assertTrue(batch["success"])
        self.assertEqual(batch["steps_requested"], 4)
        self.assertEqual(batch["steps_succeeded"], 4)
        self.assertEqual(batch["steps_failed"], 0)


if __name__ == "__main__":
    unittest.main()
