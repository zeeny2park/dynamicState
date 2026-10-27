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
        cls.mismatch_stripped_bin_path = os.path.join(cls.tmp_dir.name, "mcp_target_mismatch_stripped")

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
        shutil.copyfile(cls.mismatch_bin_path, cls.mismatch_stripped_bin_path)
        os.chmod(cls.mismatch_stripped_bin_path, 0o755)
        subprocess.run(["strip", "--strip-all", cls.mismatch_stripped_bin_path], check=True)

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
        # Connect target A (compiled with sha1 build-id)
        conn_a = json.loads(mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path))
        self.assertTrue(conn_a["success"])

        # Launch target B_stripped (compiled with md5 build-id, stripped of DWARF)
        proc_b_stripped = subprocess.Popen([self.mismatch_stripped_bin_path])
        # Launch target B_debug (compiled with md5 build-id, with DWARF symbols)
        proc_b_debug = subprocess.Popen([self.mismatch_bin_path])
        try:
            time.sleep(0.15)

            # 1. While target A is bound, calling tool with explicit PID of stripped target B
            # without companion ELF MUST NOT leak target A's companion ELF!
            # Since B has no DWARF and its Build ID (md5) differs from A (sha1), it must definitively fail with DEBUG_IMAGE_NOT_FOUND
            res_leak = json.loads(
                mcp_srv.runtime_eval_memory_path(
                    pid=proc_b_stripped.pid,
                    expressions=["gpRegistry.magic"],
                )
            )
            self.assertFalse(res_leak["success"])
            self.assertEqual(res_leak["error_code"], "DEBUG_IMAGE_NOT_FOUND")

            # 2. Calling tool with explicit target B arguments must use target B (precedence)
            res_b = json.loads(
                mcp_srv.runtime_eval_memory_path(
                    pid=proc_b_debug.pid,
                    companion_elf=self.mismatch_bin_path,
                    expressions=["gpRegistry.magic"],
                )
            )
            self.assertTrue(res_b["success"])
            self.assertEqual(res_b["pid"], proc_b_debug.pid)
            self.assertEqual(res_b["companion_elf"], self.mismatch_bin_path)

            # 3. Explicit PID of unstripped target B without companion ELF auto-discovers B's own image, never A's
            res_autodisc = json.loads(
                mcp_srv.runtime_eval_memory_path(
                    pid=proc_b_debug.pid,
                    expressions=["gpRegistry.magic"],
                )
            )
            self.assertTrue(res_autodisc["success"])
            self.assertEqual(res_autodisc["pid"], proc_b_debug.pid)
            self.assertNotEqual(res_autodisc["companion_elf"], self.bin_path)

            # 4. Switching bound target to B: subsequent calls without PID must use B
            conn_b = json.loads(
                mcp_srv.runtime_target_connect(pid=proc_b_debug.pid, companion_elf=self.mismatch_bin_path)
            )
            self.assertTrue(conn_b["success"])
            self.assertEqual(conn_b["pid"], proc_b_debug.pid)

            res_switched = json.loads(mcp_srv.runtime_eval_memory_path(expressions=["gpRegistry.magic"]))
            self.assertTrue(res_switched["success"])
            self.assertEqual(res_switched["pid"], proc_b_debug.pid)

            # 5. Remote target isolation: bind remote target A context, verify local target B does not inherit remote params
            mcp_srv.runtime.watch_session_manager._active_target_context["pid"] = self.proc.pid
            mcp_srv.runtime.watch_session_manager._active_target_context["remote_host"] = "192.0.2.1"
            mcp_srv.runtime.watch_session_manager._active_target_context["ssh_user"] = "remote_admin"
            res_remote_iso = json.loads(
                mcp_srv.runtime_eval_memory_path(
                    pid=proc_b_debug.pid,
                    companion_elf=self.mismatch_bin_path,
                    expressions=["gpRegistry.magic"],
                )
            )
            self.assertTrue(res_remote_iso["success"])
            self.assertFalse(res_remote_iso.get("is_remote", False))

            # 6. Verify stale, missing, or mismatched target context produces actionable errors:
            # 6a. Stale/terminated process produces PROCESS_EXITED
            proc_dead = subprocess.Popen(["true"])
            proc_dead.wait()
            res_stale = json.loads(mcp_srv.runtime_capture_memory(pid=proc_dead.pid))
            self.assertFalse(res_stale["success"])
            self.assertEqual(res_stale["error_code"], "PROCESS_EXITED")

            # 6b. Mismatched companion ELF produces BUILD_ID_MISMATCH
            res_mismatch = json.loads(
                mcp_srv.runtime_eval_memory_path(
                    pid=self.proc.pid,
                    companion_elf=self.mismatch_bin_path,
                    expressions=["gpRegistry.magic"],
                )
            )
            self.assertFalse(res_mismatch["success"])
            self.assertEqual(res_mismatch["error_code"], "BUILD_ID_MISMATCH")
        finally:
            for p in (proc_b_stripped, proc_b_debug):
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=2)
                    except Exception:
                        p.kill()
            # Restore target A context
            mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)

    def test_09_input_boundaries_rejection(self) -> None:
        """Verifies strict boundary validation: booleans, fractional floats, integral floats, and unexpected types."""
        # 1. Booleans must be rejected as PIDs across public MCP entry points
        for bad_bool in (True, False):
            res_bool = json.loads(mcp_srv.runtime_capture_memory(pid=bad_bool))
            self.assertFalse(res_bool["success"])
            self.assertEqual(res_bool["error_code"], "INVALID_PID")
            self.assertIn("boolean", res_bool["error"].lower())

            res_eval_bool = json.loads(mcp_srv.runtime_eval_memory_path(pid=bad_bool, expressions=["x"]))
            self.assertFalse(res_eval_bool["success"])
            self.assertEqual(res_eval_bool["error_code"], "INVALID_PID")

        # 2. Fractional numeric PIDs must be rejected rather than truncated
        for bad_float in (123.45, "123.45", -10.5):
            res_float = json.loads(mcp_srv.runtime_capture_memory(pid=bad_float))
            self.assertFalse(res_float["success"])
            self.assertEqual(res_float["error_code"], "INVALID_PID")
            self.assertIn("fractional", res_float["error"].lower())

        # 3. Integral floats and decimal strings are accepted as valid integers per compatibility policy
        # (Pass through PID validation without error; they fail downstream on dead PID 999999)
        res_int_float = json.loads(mcp_srv.runtime_capture_memory(pid=999999.0))
        self.assertFalse(res_int_float["success"])
        self.assertEqual(res_int_float["error_code"], "PROCESS_EXITED")

        res_int_str = json.loads(mcp_srv.runtime_capture_memory(pid="999999.0"))
        self.assertFalse(res_int_str["success"])
        self.assertEqual(res_int_str["error_code"], "PROCESS_EXITED")

        # 4. Zero, negative, and reserved PID 1 must be rejected
        for bad_pid in (0, -1, -99, 1, "0", "-5", "1"):
            res_bad = json.loads(mcp_srv.runtime_capture_memory(pid=bad_pid))
            self.assertFalse(res_bad["success"])
            self.assertEqual(res_bad["error_code"], "INVALID_PID")

        # 5. Malformed strings and unexpected types (list, dict)
        for bad_type in ("not_a_number", [123], {"pid": 123}):
            res_type = json.loads(mcp_srv.runtime_capture_memory(pid=bad_type))
            self.assertFalse(res_type["success"])
            self.assertEqual(res_type["error_code"], "INVALID_PID")

        # 6. Missing target context produces NO_TARGET_SPECIFIED rather than generic INVALID_PID
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
        self.assertFalse(c["has_causal_guarantee"])
        self.assertEqual(c["data_completeness"], "BEST_EFFORT_NON_ATOMIC")

    def test_11_batch_macro_failures_and_unknown_actions(self) -> None:
        """Verifies runtime_batch_execute fails cleanly on unknown actions, structured step failures, and malformed inputs."""
        mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)

        # 1. Unknown action does NOT fall back to natural language question; reports unsupported action error
        raw_unk = mcp_srv.runtime_batch_execute(
            steps=[{"action": "unknown_action_xyz_123", "data": "bad"}]
        )
        unk = json.loads(raw_unk)
        self.assertFalse(unk["success"])
        self.assertFalse(unk["partial_success"])
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

        # 3. All steps succeed
        raw_all_ok = mcp_srv.runtime_batch_execute(
            steps=[
                {"action": "eval", "expressions": ["gpRegistry.magic"]},
                {"action": "callstack"},
            ]
        )
        all_ok = json.loads(raw_all_ok)
        self.assertTrue(all_ok["success"])
        self.assertFalse(all_ok["partial_success"])
        self.assertEqual(all_ok["steps_succeeded"], 2)
        self.assertEqual(all_ok["steps_failed"], 0)

        # 4. Malformed step input in list (e.g. integer or invalid item format)
        raw_malformed = mcp_srv.runtime_batch_execute(
            steps=[
                {"action": "eval", "expressions": ["gpRegistry.magic"]},
                99999,  # Malformed item in step array
            ]
        )
        malformed = json.loads(raw_malformed)
        self.assertFalse(malformed["success"])
        self.assertTrue(malformed["partial_success"])
        self.assertEqual(malformed["steps_requested"], 2)
        self.assertEqual(malformed["steps_succeeded"], 1)
        self.assertEqual(malformed["steps_failed"], 1)
        self.assertIn("invalid step format", malformed["step_results"][1]["error"].lower())

        # 5. Output-budget compact mode
        raw_compact = mcp_srv.runtime_batch_execute(
            steps=[{"action": "eval", "expressions": ["gpRegistry.magic"]}],
            compact=True,
            max_tokens_per_step=100,
        )
        compact_res = json.loads(raw_compact)
        self.assertTrue(compact_res["success"])
        self.assertTrue(compact_res["compact_mode"])

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

    def test_13_error_classification_determinism_table(self) -> None:
        """Table-driven verification of _normalize_mcp_error determinism, collisions, and explicit code precedence."""
        test_cases = [
            # 1. Explicit domain codes must ALWAYS be preserved
            ("Explicit INVALID_PID preserved", "Target PID is required", "INVALID_PID", "INVALID_PID"),
            ("Explicit NO_TARGET_SPECIFIED preserved", "Invalid target PID", "NO_TARGET_SPECIFIED", "NO_TARGET_SPECIFIED"),
            ("Explicit BUILD_ID_MISMATCH preserved", "Debug image not found", "BUILD_ID_MISMATCH", "BUILD_ID_MISMATCH"),
            ("Explicit SESSION_NOT_FOUND preserved", "Snapshot not found", "SESSION_NOT_FOUND", "SESSION_NOT_FOUND"),

            # 2. Heuristic resolution of collisions
            ("Missing target PID", "No target PID provided and no target session bound", "ValueError", "NO_TARGET_SPECIFIED"),
            ("Target PID required", "Target PID is required and must be an integer > 1", None, "NO_TARGET_SPECIFIED"),
            ("Invalid boolean PID", "Invalid target PID: boolean values are not valid PIDs", "ValueError", "INVALID_PID"),
            ("Fractional PID", "Invalid fractional PID 123.45: PID must be an integer > 1", "ValueError", "INVALID_PID"),
            ("Reserved PID", "Invalid or reserved system PID 1: PID must be an integer > 1", "ValueError", "INVALID_PID"),
            ("Unsupported PID type", "Unsupported PID type: list", "ValueError", "INVALID_PID"),

            # 3. Build-id mismatch vs Debug image not found
            ("Build-id mismatch format", "Target process '123' running executable has build-id 'abc', but companion image 'x' has build-id 'def'. Mismatched symbols rejected.", "ValueError", "BUILD_ID_MISMATCH"),
            ("Companion ELF not found", "Companion ELF with DWARF debug info could not be resolved for PID 123.", "ValueError", "DEBUG_IMAGE_NOT_FOUND"),
            ("Debug image missing file", "Debug image not found at '/tmp/foo'", "FileNotFoundError", "DEBUG_IMAGE_NOT_FOUND"),

            # 4. Session vs Snapshot vs Object
            ("Session not found", "Session 'sess_999' not found", "ValueError", "SESSION_NOT_FOUND"),
            ("Snapshot not found", "Snapshot 'snap_888' not found", "ValueError", "SNAPSHOT_NOT_FOUND"),
            ("Object not found", "Object 'obj_777' not found", "ValueError", "OBJECT_NOT_FOUND"),

            # 5. Process exit vs Permission denied
            ("Process exited", "Process 123 exited with status 0", "RuntimeError", "PROCESS_EXITED"),
            ("Permission denied", "Permission denied: unable to access /proc/123/mem", "PermissionError", "PERMISSION_DENIED"),

            # 6. Unsupported capability
            ("Unsupported batch action", "Unsupported batch action 'bad_act'. Supported actions: ...", "ValueError", "UNSUPPORTED_CAPABILITY"),

            # 7. Timeout vs incidental word in variable name
            ("Real timeout", "Operation timed out after 5000ms", "TimeoutError", "TIMEOUT"),
            ("Incidental timeout substring", "Syntax error near token timeout_counter", "SyntaxError", "SyntaxError"),

            # 8. Distinguishable unknown exceptions
            ("Unknown disk error", "Disk quota exceeded", "IOError", "IOError"),
            ("Empty message with custom code", "", "CustomDriverException", "CustomDriverException"),
        ]

        for desc, msg, explicit_code, expected_code in test_cases:
            code, hint = mcp_srv._normalize_mcp_error(msg, explicit_code=explicit_code)
            self.assertEqual(code, expected_code, f"Failed on case '{desc}': expected {expected_code}, got {code}")
            if expected_code in ("IOError", "CustomDriverException", "SyntaxError"):
                self.assertIsNone(hint, f"Case '{desc}' should not fabricate a recovery hint")
            else:
                self.assertIsNotNone(hint, f"Case '{desc}' should provide a recovery hint for domain code {expected_code}")

    def test_14_golden_baseline_context_behavior(self) -> None:
        """Verifies golden baseline context resolution, Build ID compatibility, and serialization immutability."""
        # 1. Bound target context: save baseline with no explicit PID or image
        mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)
        raw_b1 = mcp_srv.runtime_golden_baseline_save(label="Baseline_1")
        b1 = json.loads(raw_b1)
        self.assertTrue(b1["success"])
        self.assertEqual(b1["pid"], self.proc.pid)
        base_id = b1["baseline_id"]

        # 2. Compare baseline with valid bound target
        raw_cmp = mcp_srv.runtime_golden_baseline_compare(baseline_id=base_id)
        cmp_res = json.loads(raw_cmp)
        self.assertTrue(cmp_res["success"])
        self.assertEqual(cmp_res["pid"], self.proc.pid)

        # 3. Explicit PID with no image inherits bound image
        raw_pid_only = mcp_srv.runtime_golden_baseline_save(pid=self.proc.pid, label="PID_Only")
        res_pid_only = json.loads(raw_pid_only)
        self.assertTrue(res_pid_only["success"])
        self.assertEqual(res_pid_only["pid"], self.proc.pid)

        # 4. Explicit image with no PID inherits bound PID
        raw_img_only = mcp_srv.runtime_golden_baseline_save(companion_elf=self.bin_path, label="Img_Only")
        res_img_only = json.loads(raw_img_only)
        self.assertTrue(res_img_only["success"])
        self.assertEqual(res_img_only["pid"], self.proc.pid)

        # 5. Explicit PID and image matching bound target
        raw_match = mcp_srv.runtime_golden_baseline_save(pid=self.proc.pid, companion_elf=self.bin_path, label="Match_Both")
        res_match = json.loads(raw_match)
        self.assertTrue(res_match["success"])
        self.assertEqual(res_match["pid"], self.proc.pid)

        # 6. Explicit PID and image differing from bound target (Target B)
        proc_b_debug = subprocess.Popen([self.mismatch_bin_path])
        try:
            time.sleep(0.1)
            raw_diff = mcp_srv.runtime_golden_baseline_save(
                pid=proc_b_debug.pid,
                companion_elf=self.mismatch_bin_path,
                label="Baseline_Target_B",
            )
            res_diff = json.loads(raw_diff)
            self.assertTrue(res_diff["success"])
            self.assertEqual(res_diff["pid"], proc_b_debug.pid)
        finally:
            proc_b_debug.terminate()
            try:
                proc_b_debug.wait(timeout=2)
            except Exception:
                proc_b_debug.kill()
            # Restore target A context
            mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)

        # 7. Explicit mismatching image must reject with BUILD_ID_MISMATCH
        raw_mismatch = mcp_srv.runtime_golden_baseline_save(
            pid=self.proc.pid,
            companion_elf=self.mismatch_bin_path,
            label="Baseline_Mismatch",
        )
        res_mismatch = json.loads(raw_mismatch)
        self.assertFalse(res_mismatch["success"])
        self.assertEqual(res_mismatch["error_code"], "BUILD_ID_MISMATCH")

        # 8. Missing target context when unbound must reject with NO_TARGET_SPECIFIED
        saved_ctx = dict(mcp_srv.runtime.watch_session_manager._active_target_context)
        try:
            mcp_srv.runtime.watch_session_manager._active_target_context.clear()
            raw_unbound = mcp_srv.runtime_golden_baseline_save(label="Unbound")
            unbound = json.loads(raw_unbound)
            self.assertFalse(unbound["success"])
            self.assertEqual(unbound["error_code"], "NO_TARGET_SPECIFIED")
        finally:
            mcp_srv.runtime.watch_session_manager._active_target_context = saved_ctx

        # 9. Immutability of caller-owned dictionary during serialization
        caller_dict = {"success": False, "error": "Test failure", "original_key": 42}
        _ = mcp_srv._format_watch_result(caller_dict)
        self.assertNotIn("error_code", caller_dict, "Serialization must not mutate caller-owned dictionary in place")
        self.assertEqual(caller_dict["original_key"], 42)


if __name__ == "__main__":
    unittest.main()
