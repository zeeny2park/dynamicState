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

    def test_08_target_context_switching_and_precedence(self) -> None:
        """Verifies target switching (A -> B), explicit args precedence, and debug image isolation."""
        # Connect target A
        mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)

        # Launch target B with mismatching binary
        proc_b = subprocess.Popen([self.mismatch_bin_path])
        try:
            time.sleep(0.1)

            # 1. Calling tool with explicit target B arguments must use target B (precedence)
            res_b = json.loads(
                mcp_srv.runtime_eval_memory_path(
                    pid=proc_b.pid,
                    companion_elf=self.mismatch_bin_path,
                    expressions=["gpRegistry.magic"],
                )
            )
            self.assertTrue(res_b["success"])
            self.assertEqual(res_b["pid"], proc_b.pid)

            # 2. Explicit PID of B without companion ELF must NOT leak target A's companion ELF if Build IDs differ
            res_leak = json.loads(
                mcp_srv.runtime_eval_memory_path(
                    pid=proc_b.pid,
                    expressions=["gpRegistry.magic"],
                )
            )
            # proc_b has md5 build id while target A has sha1 build id; if companion ELF could not be resolved from exe,
            # it must reject rather than silently using target A's companion ELF
            if not res_leak["success"]:
                self.assertIn(res_leak["error_code"], ("DEBUG_IMAGE_NOT_FOUND", "BUILD_ID_MISMATCH", "NO_TARGET_SPECIFIED"))

            # 3. Switching bound target to B: subsequent calls without PID must use B
            conn_b = json.loads(
                mcp_srv.runtime_target_connect(pid=proc_b.pid, companion_elf=self.mismatch_bin_path)
            )
            self.assertTrue(conn_b["success"])
            self.assertEqual(conn_b["pid"], proc_b.pid)

            res_switched = json.loads(mcp_srv.runtime_eval_memory_path(expressions=["gpRegistry.magic"]))
            self.assertTrue(res_switched["success"])
            self.assertEqual(res_switched["pid"], proc_b.pid)
        finally:
            if proc_b.poll() is None:
                proc_b.terminate()
                try:
                    proc_b.wait(timeout=2)
                except Exception:
                    proc_b.kill()
            # Restore target A context
            mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)

    def test_09_input_boundaries_rejection(self) -> None:
        """Verifies strict boundary validation: booleans, fractional floats, and missing target errors."""
        # 1. Booleans must be rejected as PIDs
        res_bool_t = json.loads(mcp_srv.runtime_capture_memory(pid=True))
        self.assertFalse(res_bool_t["success"])
        self.assertEqual(res_bool_t["error_code"], "INVALID_PID")
        self.assertIn("boolean", res_bool_t["error"].lower())

        res_bool_f = json.loads(mcp_srv.runtime_capture_memory(pid=False))
        self.assertFalse(res_bool_f["success"])
        self.assertEqual(res_bool_f["error_code"], "INVALID_PID")

        # 2. Fractional numeric PIDs must be rejected rather than truncated
        res_float = json.loads(mcp_srv.runtime_capture_memory(pid=123.45))
        self.assertFalse(res_float["success"])
        self.assertEqual(res_float["error_code"], "INVALID_PID")
        self.assertIn("fractional", res_float["error"].lower())

        res_float_str = json.loads(mcp_srv.runtime_capture_memory(pid="123.45"))
        self.assertFalse(res_float_str["success"])
        self.assertEqual(res_float_str["error_code"], "INVALID_PID")

        # 3. Missing target context produces NO_TARGET_SPECIFIED rather than generic INVALID_PID
        saved_ctx = dict(mcp_srv.runtime.watch_session_manager._active_target_context)
        try:
            mcp_srv.runtime.watch_session_manager._active_target_context.clear()
            res_none = json.loads(mcp_srv.runtime_capture_memory())
            self.assertFalse(res_none["success"])
            self.assertEqual(res_none["error_code"], "NO_TARGET_SPECIFIED")
            self.assertIn("recovery_hint", res_none)
        finally:
            mcp_srv.runtime.watch_session_manager._active_target_context = saved_ctx

    def test_10_consistency_semantics_fields(self) -> None:
        """Verifies explicit ZERO_STOP concurrency metadata: process_stopped, is_atomic_read, causal_guarantee."""
        mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)
        raw_ev = mcp_srv.runtime_eval_memory_path(expressions=["gpRegistry.magic"])
        ev = json.loads(raw_ev)
        self.assertTrue(ev["success"])
        c = ev["consistency"]
        self.assertEqual(c["level"], "NON_ATOMIC")
        self.assertFalse(c["is_consistent_snapshot"])
        self.assertFalse(c["process_stopped"])
        self.assertFalse(c["is_atomic_read"])
        self.assertEqual(c["mechanism"], "ZERO_STOP_CONCURRENT_READ")
        self.assertEqual(c["causal_guarantee"], "NONE")

    def test_11_batch_macro_failures_and_unknown_actions(self) -> None:
        """Verifies runtime_batch_execute fails cleanly on unknown actions and sets partial_success appropriately."""
        mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)

        # 1. Unknown action does NOT fall back to natural language question; reports unsupported action error
        raw_unk = mcp_srv.runtime_batch_execute(
            steps=[{"action": "unknown_action_xyz_123", "data": "bad"}]
        )
        unk = json.loads(raw_unk)
        self.assertFalse(unk["success"])
        self.assertEqual(unk["steps_failed"], 1)
        self.assertEqual(unk["error_code"], "ALL_STEPS_FAILED")
        self.assertIn("unsupported batch action", unk["step_results"][0]["error"].lower())

        # 2. Mixed batch: 1 succeeding step, 1 failing step
        raw_mixed = mcp_srv.runtime_batch_execute(
            steps=[
                {"action": "eval", "expressions": ["gpRegistry.magic"]},
                {"action": "unknown_nonexistent_tool"},
            ]
        )
        mixed = json.loads(raw_mixed)
        self.assertFalse(mixed["success"])
        self.assertTrue(mixed["partial_success"])
        self.assertEqual(mixed["error_code"], "PARTIAL_BATCH_FAILURE")
        self.assertEqual(mixed["steps_succeeded"], 1)
        self.assertEqual(mixed["steps_failed"], 1)
        self.assertIn("recovery_hint", mixed)

    def test_12_session_and_error_contract_standardization(self) -> None:
        """Verifies domain error codes (SESSION_NOT_FOUND) and context inheritance for baseline save."""
        # 1. Non-existent session returns SESSION_NOT_FOUND error code
        res_obs = json.loads(mcp_srv.runtime_watch_session_observations(session_id="non_existent_session_id_404"))
        self.assertFalse(res_obs["success"])
        self.assertEqual(res_obs["error_code"], "SESSION_NOT_FOUND")
        self.assertIn("recovery_hint", res_obs)

        res_get = json.loads(mcp_srv.runtime_watch_session_get(session_id="non_existent_session_id_404"))
        self.assertFalse(res_get["success"])
        self.assertEqual(res_get["error_code"], "SESSION_NOT_FOUND")

        # 2. runtime_golden_baseline_save without PID inherits bound target context
        mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)
        res_save = json.loads(mcp_srv.runtime_golden_baseline_save(label="Test Baseline"))
        self.assertTrue(res_save["success"])
        self.assertEqual(res_save["pid"], self.proc.pid)
        self.assertIn("baseline_id", res_save)


if __name__ == "__main__":
    unittest.main()
