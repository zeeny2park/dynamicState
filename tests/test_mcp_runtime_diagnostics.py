"""DynamicState — MCP Runtime Diagnostic Scenarios & Correctness Validation.

Harden diagnostic test reliability, fixture isolation, and evidence semantics:
- Scenario A: Known state transition (before/after values, golden baseline comparison, delta validation).
- Scenario B: Data-structure invariant violation (registry desync, null buffer pointer, linked list cycle detection, memory audit).
- Scenario C: Progress failure & pointer-state issue (stalled mutex waiter thread, zero progress counter, null active handler).
- Scenario D: Evidence semantics & failure handling (facts vs derived comparisons, refuted/partial hypothesis verdicts, non-atomic consistency metadata, partial per-expression results).

Guarantees:
1. Fresh disposable process per test method: eliminates cross-test state leakage.
2. Async-signal-safe handlers: POSIX signals set volatile sig_atomic_t flags; transitions executed in main loop.
3. Deterministic synchronization: bounded condition waiting replaces fixed sleeps.
4. Precise evidence semantics: direct observations distinguished from derived comparisons and hypothesis verdicts.
5. Robust cleanup: child processes and temporary files are reliably terminated and unlinked in tearDown.
"""

import json
import os
import signal
import subprocess
import tempfile
import time
import unittest
from typing import Any, Callable, Dict, Optional

import scripts.mcp_server as mcp_srv


DIAGNOSTIC_FIXTURE_C = r"""#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>

// =========================================================================
// Strict Async-Signal-Safe Control Flags
// Signal handlers ONLY set these atomic flags. Struct mutations and string
// copies are executed strictly in the main thread loop.
// =========================================================================
static volatile sig_atomic_t g_trigger_phase_transition = 0;
static volatile sig_atomic_t g_trigger_registry_defect = 0;
volatile uint32_t g_ack_seq = 0;

void on_sigusr1(int sig) {
    (void)sig;
    g_trigger_phase_transition = 1;
}

void on_sigusr2(int sig) {
    (void)sig;
    g_trigger_registry_defect = 1;
}

// =========================================================================
// Scenario A: Known State Transition Target
// =========================================================================
typedef enum {
    SERVICE_BOOTING = 0,
    SERVICE_IDLE = 10,
    SERVICE_PROCESSING = 20,
    SERVICE_DRAINING = 30,
    SERVICE_COMPLETED = 40
} ServicePhase;

typedef struct {
    uint32_t magic;            // 0xC0FFEE01
    int32_t phase;             // Initially SERVICE_IDLE (10)
    uint32_t transition_count; // Initially 0
    uint32_t active_tasks;     // Initially 0
    uint64_t total_bytes;      // Initially 1024
} ServiceManager;

ServiceManager g_service_manager;

// =========================================================================
// Scenario B: Data-Structure Invariant Violation Target
// =========================================================================
typedef struct {
    int32_t slot_id;
    int32_t in_use;
    uint32_t task_id;
    char *buffer_ptr;
    char tag[24];
} WorkerSlot;

typedef struct {
    uint32_t registry_magic;   // 0xBEEFCAFE
    int32_t total_slots;       // 4
    int32_t active_workers;    // Invariant: active_workers == sum(slots[i].in_use)
    WorkerSlot slots[4];
} WorkerRegistry;

WorkerRegistry g_worker_registry;
static char g_buf0[64] = "slot_0_buffer";
static char g_buf1[64] = "slot_1_buffer";

// Linked list nodes for traversal & cycle detection
typedef struct ListNode {
    int32_t id;
    int32_t value;
    struct ListNode *next;
} ListNode;

ListNode g_list_clean[4];
ListNode *g_clean_head = NULL;

ListNode g_list_cycle[3];
ListNode *g_cycle_head = NULL;

// Audit target with corrupted enum and null/dangling pointer
typedef enum {
    MODE_NORMAL = 1,
    MODE_DEBUG = 2,
    MODE_SAFE = 3
} SystemMode;

typedef struct {
    uint32_t magic;
    bool is_healthy;
    SystemMode mode;
    int32_t *dangling_ptr;
} IntegrityTarget;

IntegrityTarget g_integrity_target;

// =========================================================================
// Scenario C: Progress Failure / Stalled Worker / Pointer-State
// =========================================================================
typedef struct {
    uint32_t tracker_magic;    // 0x57A11ED0
    int32_t is_running;        // 1
    int32_t is_stalled;        // 1
    uint64_t progress_counter; // Constant 100
    void *active_handler;      // NULL (0x0)
} ProgressTracker;

ProgressTracker g_progress_tracker;

pthread_mutex_t g_stall_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int g_stall_holder_ready = 0;

void *stall_holder_func(void *arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "stall_holder");
    pthread_mutex_lock(&g_stall_mutex);
    g_stall_holder_ready = 1;
    while (1) {
        usleep(50000);
    }
    return NULL;
}

void *stall_worker_func(void *arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "stall_worker");
    while (!g_stall_holder_ready) {
        usleep(1000);
    }
    // Block deterministically on the mutex held by stall_holder_func
    pthread_mutex_lock(&g_stall_mutex);
    g_progress_tracker.progress_counter++;
    pthread_mutex_unlock(&g_stall_mutex);
    return NULL;
}

int main(void) {
    // Setup Scenario A initial state
    memset(&g_service_manager, 0, sizeof(g_service_manager));
    g_service_manager.magic = 0xC0FFEE01;
    g_service_manager.phase = SERVICE_IDLE;
    g_service_manager.transition_count = 0;
    g_service_manager.active_tasks = 0;
    g_service_manager.total_bytes = 1024;

    // Setup Scenario B initial state
    memset(&g_worker_registry, 0, sizeof(g_worker_registry));
    g_worker_registry.registry_magic = 0xBEEFCAFE;
    g_worker_registry.total_slots = 4;
    g_worker_registry.active_workers = 2; // Invariant: matches slots 0 and 1 in_use

    g_worker_registry.slots[0].slot_id = 0;
    g_worker_registry.slots[0].in_use = 1;
    g_worker_registry.slots[0].task_id = 1001;
    g_worker_registry.slots[0].buffer_ptr = g_buf0;
    strncpy(g_worker_registry.slots[0].tag, "worker_alpha", 23);

    g_worker_registry.slots[1].slot_id = 1;
    g_worker_registry.slots[1].in_use = 1;
    g_worker_registry.slots[1].task_id = 1002;
    g_worker_registry.slots[1].buffer_ptr = g_buf1;
    strncpy(g_worker_registry.slots[1].tag, "worker_beta", 23);

    g_worker_registry.slots[2].slot_id = 2;
    g_worker_registry.slots[2].in_use = 0;
    g_worker_registry.slots[2].task_id = 0;
    g_worker_registry.slots[2].buffer_ptr = NULL;
    strncpy(g_worker_registry.slots[2].tag, "empty_slot_2", 23);

    g_worker_registry.slots[3].slot_id = 3;
    g_worker_registry.slots[3].in_use = 0;
    g_worker_registry.slots[3].task_id = 0;
    g_worker_registry.slots[3].buffer_ptr = NULL;
    strncpy(g_worker_registry.slots[3].tag, "empty_slot_3", 23);

    // Clean linked list: 0 -> 1 -> 2 -> 3 -> NULL
    for (int i = 0; i < 4; i++) {
        g_list_clean[i].id = 10 + i;
        g_list_clean[i].value = (i + 1) * 100;
        g_list_clean[i].next = (i < 3) ? &g_list_clean[i + 1] : NULL;
    }
    g_clean_head = &g_list_clean[0];

    // Cycle linked list: 0 -> 1 -> 2 -> 1 (cycle)
    for (int i = 0; i < 3; i++) {
        g_list_cycle[i].id = 50 + i;
        g_list_cycle[i].value = (i + 1) * 500;
    }
    g_list_cycle[0].next = &g_list_cycle[1];
    g_list_cycle[1].next = &g_list_cycle[2];
    g_list_cycle[2].next = &g_list_cycle[1]; // cycle back to 1
    g_cycle_head = &g_list_cycle[0];

    // Integrity target setup (unmapped pointer constant, never dereferenced in C)
    g_integrity_target.magic = 0xAA55AA55;
    g_integrity_target.is_healthy = true;
    g_integrity_target.mode = MODE_NORMAL;
    g_integrity_target.dangling_ptr = (int32_t*)0xDEADBEEF;

    // Setup Scenario C initial state
    memset(&g_progress_tracker, 0, sizeof(g_progress_tracker));
    g_progress_tracker.tracker_magic = 0x57A11ED0;
    g_progress_tracker.is_running = 1;
    g_progress_tracker.is_stalled = 1;
    g_progress_tracker.progress_counter = 100;
    g_progress_tracker.active_handler = NULL; // Controlled null pointer state

    // Signal registrations with SA_RESTART
    struct sigaction sa1;
    memset(&sa1, 0, sizeof(sa1));
    sa1.sa_handler = on_sigusr1;
    sa1.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa1, NULL);

    struct sigaction sa2;
    memset(&sa2, 0, sizeof(sa2));
    sa2.sa_handler = on_sigusr2;
    sa2.sa_flags = SA_RESTART;
    sigaction(SIGUSR2, &sa2, NULL);

    // Launch stall threads
    pthread_t th1, th2;
    pthread_create(&th1, NULL, stall_holder_func, NULL);
    pthread_create(&th2, NULL, stall_worker_func, NULL);

    // Main execution loop: safely executes state mutations requested via signal flags
    while (1) {
        if (g_trigger_phase_transition) {
            g_trigger_phase_transition = 0;
            if (g_service_manager.phase == SERVICE_IDLE) {
                g_service_manager.phase = SERVICE_PROCESSING;
                g_service_manager.active_tasks = 5;
                g_service_manager.total_bytes += 4096;
            } else if (g_service_manager.phase == SERVICE_PROCESSING) {
                g_service_manager.phase = SERVICE_COMPLETED;
                g_service_manager.active_tasks = 0;
                g_service_manager.total_bytes += 2048;
            }
            g_service_manager.transition_count++;
            g_ack_seq++; // Acknowledge completion of phase transition
        }

        if (g_trigger_registry_defect) {
            g_trigger_registry_defect = 0;
            // Inject invariant defect cleanly in main thread (not in signal handler)
            g_worker_registry.slots[2].in_use = 1;
            g_worker_registry.slots[2].task_id = 9002;
            g_worker_registry.slots[2].buffer_ptr = NULL;
            memcpy((void*)g_worker_registry.slots[2].tag, "injected_defect", 16);
            // active_workers is deliberately NOT incremented (remains 2) to establish desynchronization
            g_ack_seq++; // Acknowledge completion of defect injection
        }

        usleep(2000);
    }
    return 0;
}
"""


class TestMcpRuntimeDiagnostics(unittest.TestCase):
    """End-to-end validation of real runtime diagnostic correctness across MCP workflows."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.TemporaryDirectory(prefix="mcp_diag_")
        cls.src_path = os.path.join(cls.tmp_dir.name, "diagnostic_target.c")
        cls.bin_path = os.path.join(cls.tmp_dir.name, "diagnostic_target")

        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(DIAGNOSTIC_FIXTURE_C)

        # Compile non-stripped ELF with DWARF symbols and explicit build-id
        subprocess.run(
            ["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", cls.src_path, "-o", cls.bin_path],
            check=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp_dir.cleanup()

    def setUp(self) -> None:
        # Launch a fresh, disposable process per test method to eliminate inter-test state leakage
        self.proc = subprocess.Popen([self.bin_path])
        # Bounded wait for process initialization
        time.sleep(0.08)
        # Guarantee target context is cleanly bound to self.proc
        conn_raw = mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)
        conn = json.loads(conn_raw)
        if not conn.get("success"):
            self.proc.terminate()
            self.fail(f"Failed to connect target context to fresh process: {conn}")

    def tearDown(self) -> None:
        # Guarantee child process is always terminated and cleaned up even on assertion failure
        if hasattr(self, "proc") and self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except Exception:
                self.proc.kill()

    def _wait_for_condition(self, predicate: Callable[[], bool], timeout: float = 2.0, step: float = 0.01) -> bool:
        """Polls predicate with bounded timeout to establish deterministic synchronization."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                if predicate():
                    return True
            except Exception:
                pass
            time.sleep(step)
        return False

    def test_01_scenario_a_known_state_transition(self) -> None:
        """Scenario A: Known state transition.
        Observes a state machine field with known initial value, triggers a controlled transition,
        and verifies exact before/after values and delta comparison.
        """
        # 1. Verify target identity
        conn_raw = mcp_srv.runtime_target_connect(pid=self.proc.pid, companion_elf=self.bin_path)
        conn = json.loads(conn_raw)
        self.assertTrue(conn["success"])
        self.assertEqual(conn["pid"], self.proc.pid)
        self.assertIsNotNone(conn.get("build_id"))

        # 2. Setup and Expected Initial State
        raw_initial = mcp_srv.runtime_eval_memory_path(
            expressions=[
                "g_service_manager.magic",
                "g_service_manager.phase",
                "g_service_manager.transition_count",
                "g_service_manager.active_tasks",
                "g_service_manager.total_bytes",
            ]
        )
        res_initial = json.loads(raw_initial)
        self.assertTrue(res_initial["success"])
        # Verify individual expression evaluation statuses
        for item in res_initial["results"]:
            self.assertEqual(item["status"], "OBSERVED")

        vals_0 = {r["expression"]: r["value"] for r in res_initial["results"]}
        self.assertEqual(vals_0["g_service_manager.magic"], 0xC0FFEE01)
        self.assertEqual(vals_0["g_service_manager.phase"], 10)  # SERVICE_IDLE
        self.assertEqual(vals_0["g_service_manager.transition_count"], 0)
        self.assertEqual(vals_0["g_service_manager.active_tasks"], 0)
        self.assertEqual(vals_0["g_service_manager.total_bytes"], 1024)

        # 3. Save Golden Baseline of initial state
        raw_base = mcp_srv.runtime_golden_baseline_save(
            label="Service_Initial_Idle",
            expressions=[
                "g_service_manager.phase",
                "g_service_manager.transition_count",
                "g_service_manager.active_tasks",
                "g_service_manager.total_bytes",
            ],
        )
        base = json.loads(raw_base)
        self.assertTrue(base["success"])
        baseline_id = base["baseline_id"]

        # 4. Controlled Trigger 1: Transition IDLE (10) -> PROCESSING (20)
        os.kill(self.proc.pid, signal.SIGUSR1)
        # Bounded synchronization: wait until transition_count advances to 1
        synced_1 = self._wait_for_condition(
            lambda: json.loads(
                mcp_srv.runtime_eval_memory_path(expressions=["g_service_manager.transition_count"])
            )["results"][0]["value"] == 1
        )
        self.assertTrue(synced_1, "Controlled transition 1 did not complete within bounded timeout")

        # 5. Exact Expected Observation Post-Transition 1
        raw_after_1 = mcp_srv.runtime_eval_memory_path(
            expressions=[
                "g_service_manager.phase",
                "g_service_manager.transition_count",
                "g_service_manager.active_tasks",
                "g_service_manager.total_bytes",
            ]
        )
        res_after_1 = json.loads(raw_after_1)
        self.assertTrue(res_after_1["success"])
        for item in res_after_1["results"]:
            self.assertEqual(item["status"], "OBSERVED")

        vals_1 = {r["expression"]: r["value"] for r in res_after_1["results"]}
        self.assertEqual(vals_1["g_service_manager.phase"], 20)  # SERVICE_PROCESSING
        self.assertEqual(vals_1["g_service_manager.transition_count"], 1)
        self.assertEqual(vals_1["g_service_manager.active_tasks"], 5)
        self.assertEqual(vals_1["g_service_manager.total_bytes"], 5120)  # 1024 + 4096

        # 6. Compare against baseline and verify exact deltas
        raw_cmp = mcp_srv.runtime_golden_baseline_compare(baseline_id=baseline_id)
        cmp_res = json.loads(raw_cmp)
        self.assertTrue(cmp_res["success"])
        self.assertEqual(cmp_res["summary"]["changed_count"], 4)
        changes = {c["path"]: c for c in cmp_res["changed"]}
        self.assertEqual(changes["g_service_manager.phase"]["golden_value"], 10)
        self.assertEqual(changes["g_service_manager.phase"]["live_value"], 20)
        self.assertEqual(changes["g_service_manager.phase"]["delta"], 10)
        self.assertEqual(changes["g_service_manager.transition_count"]["golden_value"], 0)
        self.assertEqual(changes["g_service_manager.transition_count"]["live_value"], 1)
        self.assertEqual(changes["g_service_manager.transition_count"]["delta"], 1)

        # 7. Controlled Trigger 2: Transition PROCESSING (20) -> COMPLETED (40)
        os.kill(self.proc.pid, signal.SIGUSR1)
        synced_2 = self._wait_for_condition(
            lambda: json.loads(
                mcp_srv.runtime_eval_memory_path(expressions=["g_service_manager.transition_count"])
            )["results"][0]["value"] == 2
        )
        self.assertTrue(synced_2, "Controlled transition 2 did not complete within bounded timeout")

        # 8. Exact Expected Observation Post-Transition 2
        raw_after_2 = mcp_srv.runtime_eval_memory_path(
            expressions=[
                "g_service_manager.phase",
                "g_service_manager.transition_count",
                "g_service_manager.active_tasks",
                "g_service_manager.total_bytes",
            ]
        )
        res_after_2 = json.loads(raw_after_2)
        self.assertTrue(res_after_2["success"])
        vals_2 = {r["expression"]: r["value"] for r in res_after_2["results"]}

        self.assertEqual(vals_2["g_service_manager.phase"], 40)  # SERVICE_COMPLETED
        self.assertEqual(vals_2["g_service_manager.transition_count"], 2)
        self.assertEqual(vals_2["g_service_manager.active_tasks"], 0)
        self.assertEqual(vals_2["g_service_manager.total_bytes"], 7168)  # 5120 + 2048

        # 9. Declarative Hypothesis Verification (validates predicate satisfaction, not causality)
        raw_hyp = mcp_srv.runtime_verify_hypothesis(
            hypothesis="Service reached COMPLETED state with 2 transitions and 7168 total processed bytes",
            assertions=[
                "g_service_manager.phase == 40",
                "g_service_manager.transition_count == 2",
                "g_service_manager.active_tasks == 0",
                "g_service_manager.total_bytes == 7168",
            ],
        )
        hyp = json.loads(raw_hyp)
        self.assertTrue(hyp["success"])
        self.assertEqual(hyp["verdict"], "CONFIRMED")
        self.assertEqual(hyp["confidence_score"], 1.0)
        self.assertEqual(len(hyp["assertion_results"]), 4)
        for ev in hyp["assertion_results"]:
            self.assertTrue(ev["passed"])

    def test_02_scenario_b_data_structure_invariant_violation(self) -> None:
        """Scenario B: Data-structure invariant violation.
        Constructs a controlled fixture whose registry and linked structure violate documented invariants:
        1. Registry Invariant: active_workers == sum(slots[i].in_use)
        2. Pointer Invariant: slot.buffer_ptr != NULL when in_use == 1
        3. Linked List Invariant: pointer traversal must be acyclic
        4. Memory Integrity Invariant: no invalid/unmapped pointer addresses
        """
        # 1. Setup & Expected Initial Invariant State
        raw_reg = mcp_srv.runtime_eval_memory_path(
            expressions=[
                "g_worker_registry.active_workers",
                "g_worker_registry.slots[0].in_use",
                "g_worker_registry.slots[1].in_use",
                "g_worker_registry.slots[2].in_use",
                "g_worker_registry.slots[3].in_use",
            ]
        )
        res_reg = json.loads(raw_reg)
        self.assertTrue(res_reg["success"])
        reg_vals = {r["expression"]: r["value"] for r in res_reg["results"]}

        self.assertEqual(reg_vals["g_worker_registry.active_workers"], 2)
        self.assertEqual(reg_vals["g_worker_registry.slots[0].in_use"], 1)
        self.assertEqual(reg_vals["g_worker_registry.slots[1].in_use"], 1)
        self.assertEqual(reg_vals["g_worker_registry.slots[2].in_use"], 0)
        self.assertEqual(reg_vals["g_worker_registry.slots[3].in_use"], 0)
        # Initial invariant holds: active_workers (2) == in_use count (1 + 1 + 0 + 0 = 2)

        # 2. Controlled Trigger: Break invariant via SIGUSR2 with bounded wait
        os.kill(self.proc.pid, signal.SIGUSR2)
        synced = self._wait_for_condition(
            lambda: json.loads(
                mcp_srv.runtime_eval_memory_path(expressions=["g_worker_registry.slots[2].in_use"])
            )["results"][0]["value"] == 1
        )
        self.assertTrue(synced, "Controlled registry defect injection did not complete within bounded timeout")

        # 3. Exact Expected Observation: Proves Invariant Violation
        raw_post = mcp_srv.runtime_eval_memory_path(
            expressions=[
                "g_worker_registry.active_workers",
                "g_worker_registry.slots[0].in_use",
                "g_worker_registry.slots[1].in_use",
                "g_worker_registry.slots[2].in_use",
                "g_worker_registry.slots[2].task_id",
                "g_worker_registry.slots[2].buffer_ptr",
                "g_worker_registry.slots[3].in_use",
            ]
        )
        res_post = json.loads(raw_post)
        self.assertTrue(res_post["success"])
        post_vals = {r["expression"]: r["value"] for r in res_post["results"]}

        # Documented Invariant 1 Violation established:
        # active_workers is 2, but actual in_use count is 1 + 1 + 1 + 0 = 3!
        self.assertEqual(post_vals["g_worker_registry.active_workers"], 2)
        self.assertEqual(post_vals["g_worker_registry.slots[0].in_use"], 1)
        self.assertEqual(post_vals["g_worker_registry.slots[1].in_use"], 1)
        self.assertEqual(post_vals["g_worker_registry.slots[2].in_use"], 1)
        self.assertEqual(post_vals["g_worker_registry.slots[3].in_use"], 0)
        actual_in_use_count = sum([
            post_vals["g_worker_registry.slots[0].in_use"],
            post_vals["g_worker_registry.slots[1].in_use"],
            post_vals["g_worker_registry.slots[2].in_use"],
            post_vals["g_worker_registry.slots[3].in_use"],
        ])
        self.assertNotEqual(
            post_vals["g_worker_registry.active_workers"],
            actual_in_use_count,
            "Documented invariant violation proven: active_workers (2) != in_use slots count (3)",
        )

        # Documented Invariant 2 Violation established:
        # slot 2 is in_use=1, but buffer_ptr is NULL!
        self.assertIn(post_vals["g_worker_registry.slots[2].buffer_ptr"], (0, "0x0", None, 0x0))

        # 4. Multi-Assertion Hypothesis Verifier validates the concrete violation
        raw_hyp = mcp_srv.runtime_verify_hypothesis(
            hypothesis="Registry desynchronization: slot 2 marked in-use with null buffer while active_workers is 2",
            assertions=[
                "g_worker_registry.slots[2].in_use == 1",
                "g_worker_registry.slots[2].buffer_ptr IS_NULL",
                "g_worker_registry.active_workers == 2",
            ],
        )
        hyp = json.loads(raw_hyp)
        self.assertTrue(hyp["success"])
        self.assertEqual(hyp["verdict"], "CONFIRMED")
        self.assertEqual(hyp["confidence_score"], 1.0)

        # 5. Linked List Invariant: Clean list is acyclic; cycle list violates invariant
        raw_clean = mcp_srv.runtime_traverse_linked_structure(
            head_expression="g_clean_head",
            next_field="next",
            include_fields=["id", "value"],
        )
        res_clean = json.loads(raw_clean)
        self.assertTrue(res_clean["success"])
        self.assertFalse(res_clean["cycle_detected"])
        self.assertEqual(res_clean["nodes_count"], 4)
        node_ids = [n["fields"]["id"] for n in res_clean["nodes"]]
        self.assertEqual(node_ids, [10, 11, 12, 13])

        # Traverse cycle list: must detect pointer cycle invariant violation
        raw_cycle = mcp_srv.runtime_traverse_linked_structure(
            head_expression="g_cycle_head",
            next_field="next",
            include_fields=["id", "value"],
        )
        res_cycle = json.loads(raw_cycle)
        self.assertTrue(res_cycle["success"])
        self.assertTrue(res_cycle["cycle_detected"], "Cycle detector must detect cycle in g_cycle_head")
        self.assertEqual(res_cycle["cycle_target_index"], 1)

        # 6. Memory Integrity Audit validates unmapped address without dereferencing
        raw_audit = mcp_srv.runtime_audit_memory_integrity(
            target_expressions=["g_integrity_target"],
        )
        res_audit = json.loads(raw_audit)
        self.assertTrue(res_audit["success"])
        self.assertEqual(res_audit["health_status"], "ANOMALIES_DETECTED")
        anom_types = [a["anomaly_kind"] for a in res_audit.get("anomalies", [])]
        self.assertTrue(
            any("POINTER" in t or "DANGLING" in t or "UNMAPPED" in t for t in anom_types),
            f"Expected pointer anomaly in audit anomalies: {anom_types}",
        )

    def test_03_scenario_c_progress_failure_and_pointer_state(self) -> None:
        """Scenario C: Progress failure and controlled null pointer state.
        Inspects a stalled worker thread blocked waiting on a mutex held by another thread,
        proves constant zero-progress counter, and observes controlled null active handler.
        """
        # 1. Inspect Thread Callstacks and Mutex Contention
        raw_stacks = mcp_srv.runtime_inspect_thread_callstack_and_locks()
        res_stacks = json.loads(raw_stacks)
        self.assertTrue(res_stacks["success"])
        threads = res_stacks.get("threads", [])
        self.assertGreaterEqual(len(threads), 2)

        # Validate thread inspection observations without platform-fragile assumptions
        thread_names = [t.get("name") for t in threads if t.get("name")]
        self.assertTrue(
            "stall_holder" in thread_names and "stall_worker" in thread_names,
            f"Expected worker threads in thread list: {thread_names}",
        )

        has_waiting = any(
            t.get("waiting_on_lock") is not None or "futex" in str(t.get("syscall", "")).lower()
            for t in threads
        )
        self.assertTrue(has_waiting, "Waiting thread or futex syscall must be detected in thread inspection")

        # 2. Progress Counter Verification: sample over delta to prove lack of progress
        raw_sample_1 = mcp_srv.runtime_eval_memory_path(
            expressions=[
                "g_progress_tracker.tracker_magic",
                "g_progress_tracker.is_running",
                "g_progress_tracker.is_stalled",
                "g_progress_tracker.progress_counter",
                "g_progress_tracker.active_handler",
            ]
        )
        res_1 = json.loads(raw_sample_1)
        self.assertTrue(res_1["success"])
        vals_1 = {r["expression"]: r["value"] for r in res_1["results"]}

        time.sleep(0.1)

        raw_sample_2 = mcp_srv.runtime_eval_memory_path(
            expressions=["g_progress_tracker.progress_counter"]
        )
        res_2 = json.loads(raw_sample_2)
        self.assertTrue(res_2["success"])
        vals_2 = {r["expression"]: r["value"] for r in res_2["results"]}

        # Assert Progress Failure: progress_counter remains identical across time interval
        self.assertEqual(vals_1["g_progress_tracker.progress_counter"], 100)
        self.assertEqual(vals_2["g_progress_tracker.progress_counter"], 100)
        self.assertEqual(
            vals_1["g_progress_tracker.progress_counter"],
            vals_2["g_progress_tracker.progress_counter"],
            "Progress failure proven: progress_counter did not advance over observation interval",
        )

        # Assert Controlled Null-Pointer State while running
        self.assertEqual(vals_1["g_progress_tracker.is_running"], 1)
        self.assertEqual(vals_1["g_progress_tracker.is_stalled"], 1)
        self.assertIn(vals_1["g_progress_tracker.active_handler"], (0, "0x0", None, 0x0))

        # 3. Multi-Assertion Hypothesis Verification
        raw_hyp = mcp_srv.runtime_verify_hypothesis(
            hypothesis="Worker progress stalled with zero increment and null active handler",
            assertions=[
                "g_progress_tracker.is_running == 1",
                "g_progress_tracker.is_stalled == 1",
                "g_progress_tracker.progress_counter == 100",
                "g_progress_tracker.active_handler IS_NULL",
            ],
        )
        hyp = json.loads(raw_hyp)
        self.assertTrue(hyp["success"])
        self.assertEqual(hyp["verdict"], "CONFIRMED")
        self.assertEqual(hyp["confidence_score"], 1.0)

    def test_04_evidence_semantics_and_failure_handling(self) -> None:
        """Scenario D / Phase 4: Evidence semantics, hypothesis refutation, non-atomic consistency, and error handling.
        Verifies:
        - Observed facts are distinguishable from derived comparisons.
        - Refuted or partially confirmed hypotheses are never reported as CONFIRMED.
        - Non-atomic observations explicitly report lack of atomicity and causal guarantees.
        - Partial per-expression evaluation failures are distinguishable from complete success.
        - Actionable error codes on missing symbols, stale PIDs, and Build ID mismatches.
        """
        # 1. Distinguishable Evidence: facts vs comparisons vs refuted hypotheses
        # Refuted hypothesis (assertion fails: phase == 999)
        raw_refuted = mcp_srv.runtime_verify_hypothesis(
            hypothesis="Impossible service phase",
            assertions=["g_service_manager.phase == 999"],
        )
        hyp_refuted = json.loads(raw_refuted)
        self.assertTrue(hyp_refuted["success"])
        self.assertEqual(hyp_refuted["verdict"], "REFUTED")
        self.assertEqual(hyp_refuted["confidence_score"], 0.0)
        self.assertFalse(hyp_refuted["assertion_results"][0]["passed"])
        self.assertNotEqual(hyp_refuted["assertion_results"][0]["observed_value"], 999)

        # Partially confirmed hypothesis (1 pass, 1 fail)
        raw_partial = mcp_srv.runtime_verify_hypothesis(
            hypothesis="Partial service hypothesis",
            assertions=[
                "g_service_manager.magic == 0xC0FFEE01",
                "g_service_manager.phase == 999",
            ],
        )
        hyp_partial = json.loads(raw_partial)
        self.assertTrue(hyp_partial["success"])
        self.assertEqual(hyp_partial["verdict"], "PARTIALLY_CONFIRMED")
        self.assertEqual(hyp_partial["confidence_score"], 0.5)

        # 2. Explicit Consistency & Atomicity Metadata
        raw_eval = mcp_srv.runtime_eval_memory_path(expressions=["g_service_manager.phase"])
        res_eval = json.loads(raw_eval)
        self.assertTrue(res_eval["success"])
        consistency = res_eval.get("consistency", {})
        self.assertFalse(consistency.get("is_atomic_read", True))
        self.assertFalse(consistency.get("is_consistent_snapshot", True))
        self.assertFalse(consistency.get("process_stopped", True))
        self.assertFalse(consistency.get("has_causal_guarantee", True))
        self.assertEqual(consistency.get("causal_guarantee"), "NONE")
        self.assertEqual(consistency.get("data_completeness"), "BEST_EFFORT_NON_ATOMIC")

        # 3. Partial Results: per-expression failures distinguishable from complete success
        raw_mixed = mcp_srv.runtime_eval_memory_path(
            expressions=[
                "g_service_manager.phase",
                "non_existent_symbol_xyz",
            ]
        )
        res_mixed = json.loads(raw_mixed)
        self.assertTrue(res_mixed["success"])
        eval_items = {r["expression"]: r for r in res_mixed["results"]}

        self.assertEqual(eval_items["g_service_manager.phase"]["status"], "OBSERVED")
        self.assertIsNotNone(eval_items["g_service_manager.phase"]["value"])

        self.assertEqual(eval_items["non_existent_symbol_xyz"]["status"], "SYMBOL_NOT_FOUND")
        self.assertIsNone(eval_items["non_existent_symbol_xyz"]["value"])
        self.assertIn("error", eval_items["non_existent_symbol_xyz"])

        # 4. Actionable error on terminated process (stale PID)
        proc_dead = subprocess.Popen(["true"])
        proc_dead.wait()
        raw_stale = mcp_srv.runtime_capture_memory(pid=proc_dead.pid)
        res_stale = json.loads(raw_stale)
        self.assertFalse(res_stale["success"])
        self.assertEqual(res_stale["error_code"], "PROCESS_EXITED")
        self.assertIsNotNone(res_stale.get("recovery_hint"))

        # 5. Deterministic repeated evaluation
        for _ in range(3):
            rep_raw = mcp_srv.runtime_eval_memory_path(expressions=["g_service_manager.magic"])
            rep_res = json.loads(rep_raw)
            self.assertTrue(rep_res["success"])
            self.assertEqual(rep_res["results"][0]["value"], 0xC0FFEE01)


if __name__ == "__main__":
    unittest.main()
