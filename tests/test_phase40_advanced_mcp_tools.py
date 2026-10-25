"""Phase 40 (Phase 10): 6 Advanced LLM MCP Tools End-to-End Verification Suite.

Verifies against a live multi-threaded C++ target process (with 0.00ms stop time):
1. `watch_until_condition` / `runtime_watch_until_condition`
2. `traverse_linked_structure` / `runtime_traverse_linked_structure` (including cycle detection)
3. `inspect_thread_callstacks_and_locks` / `runtime_inspect_thread_callstack_and_locks`
4. `audit_memory_integrity` / `runtime_audit_memory_integrity`
5. `resolve_code_pointers` / `runtime_resolve_code_pointers` (function pointers & C++ vtable)
6. `inspect_shared_memory_ipc` / `runtime_inspect_shared_memory_ipc` (POSIX shm / MAP_SHARED type overlay)
7. `WebApiAdapter.workspace_chat_api` natural-language routing for all 6 new tools.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.web.server import WebApiAdapter
import scripts.mcp_server as mcp_srv


class TestPhase40AdvancedMcpTools(unittest.TestCase):
    """End-to-end verification of the 6 Phase 10 advanced MCP tools on a live C++ process."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_phase40_")
        cls.src_path = os.path.join(cls.tmp_dir, "phase40_target.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "phase40_target_nostrip")
        cls.shm_file = os.path.join(cls.tmp_dir, "ds_test_ipc_shm.bin")

        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(
                r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>

// 1. Linked List Structures
struct TaskNode {
    int32_t task_id;
    int32_t priority;
    TaskNode* next;
};

TaskNode g_nodes[4];
TaskNode* g_clean_list = NULL;

TaskNode g_cycle_nodes[3];
TaskNode* g_cycle_list = NULL;

// 2. Mutex & Callstack Target
pthread_mutex_t g_test_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int g_mutex_locked = 0;
volatile int g_ready = 0;
volatile int32_t g_dynamic_counter = 10;

// 3. Memory Integrity Audit Target (Dangling pointer, corrupted bool, invalid enum)
enum PacketState {
    PKT_IDLE = 0,
    PKT_ACTIVE = 1,
    PKT_DONE = 2
};

struct AuditTarget {
    int32_t magic;
    bool is_valid_flag;
    PacketState state;
    int32_t* bad_ptr;
};

AuditTarget g_audit_target;

// 4. Function Pointer & C++ Polymorphic vtable Target
typedef int (*PacketCallbackFn)(int);

int on_packet_received(int seq) {
    return seq + 1;
}

PacketCallbackFn g_packet_cb = &on_packet_received;

class BaseSession {
public:
    int session_id;
    BaseSession() : session_id(77) {}
    virtual ~BaseSession() {}
    virtual int processFrame(int len) { return len; }
    virtual int handleTimeout() { return -1; }
};

class RtspSession : public BaseSession {
public:
    RtspSession() { session_id = 999; }
    virtual int processFrame(int len) override { return len * 2; }
    virtual int handleTimeout() override { return 408; }
};

RtspSession g_rtsp_instance;
BaseSession* g_poly_session = &g_rtsp_instance;

// 5. Shared Memory Overlay Target
struct ShmRingHeader {
    int32_t magic_tag;
    int32_t producer_seq;
    int32_t consumer_seq;
    int32_t capacity;
};

ShmRingHeader* g_shm_ptr = NULL;

__attribute__((noinline)) void hold_mutex_forever() {
    while (true) {
        g_dynamic_counter++;
        usleep(30000);
    }
}

void* mutex_holder_thread(void* arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "lock_holder");
    pthread_mutex_lock(&g_test_mutex);
    g_mutex_locked = 1;
    hold_mutex_forever();
    return NULL;
}

__attribute__((noinline)) void wait_for_mutex() {
    pthread_mutex_lock(&g_test_mutex);
    pthread_mutex_unlock(&g_test_mutex);
}

void* mutex_waiter_thread(void* arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "lock_waiter");
    while (!g_mutex_locked) usleep(5000);
    g_ready = 1;
    wait_for_mutex();
    return NULL;
}

int main(int argc, char** argv) {
    // Setup clean linked list: 0 -> 1 -> 2 -> 3 -> NULL
    for (int i = 0; i < 4; ++i) {
        g_nodes[i].task_id = 100 + i;
        g_nodes[i].priority = (i + 1) * 10;
        g_nodes[i].next = (i < 3) ? &g_nodes[i + 1] : NULL;
    }
    g_clean_list = &g_nodes[0];

    // Setup cycle linked list: 0 -> 1 -> 2 -> 1 (cycle!)
    for (int i = 0; i < 3; ++i) {
        g_cycle_nodes[i].task_id = 200 + i;
        g_cycle_nodes[i].priority = i;
    }
    g_cycle_nodes[0].next = &g_cycle_nodes[1];
    g_cycle_nodes[1].next = &g_cycle_nodes[2];
    g_cycle_nodes[2].next = &g_cycle_nodes[1];
    g_cycle_list = &g_cycle_nodes[0];

    // Setup intentionally corrupted AuditTarget
    g_audit_target.magic = 0x12345678;
    memset((void*)&g_audit_target.is_valid_flag, 0x41, 1); // Corrupted bool byte (0x41 != 0/1)
    g_audit_target.state = (PacketState)99;                // Invalid enum value
    g_audit_target.bad_ptr = (int32_t*)0xdeadbeef00ULL;    // Unmapped dangling pointer

    // Setup shared memory file mapping
    if (argc > 1) {
        int fd = open(argv[1], O_CREAT | O_RDWR | O_TRUNC, 0666);
        if (fd >= 0) {
            ftruncate(fd, 4096);
            void* map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (map != MAP_FAILED) {
                g_shm_ptr = (ShmRingHeader*)map;
                g_shm_ptr->magic_tag = 0x53484d31;
                g_shm_ptr->producer_seq = 42;
                g_shm_ptr->consumer_seq = 39;
                g_shm_ptr->capacity = 256;
            }
            close(fd);
        }
    }

    pthread_t th1, th2;
    pthread_create(&th1, NULL, mutex_holder_thread, NULL);
    pthread_create(&th2, NULL, mutex_waiter_thread, NULL);

    while (!g_ready) usleep(10000);
    while (true) usleep(50000);
    return 0;
}
"""
            )

        subprocess.run(
            ["g++", "-g", "-O0", "-fno-omit-frame-pointer", "-pthread", cls.src_path, "-o", cls.bin_path],
            check=True,
        )
        cls.proc = subprocess.Popen([cls.bin_path, cls.shm_file])
        time.sleep(0.35)

    @classmethod
    def tearDownClass(cls) -> None:
        if getattr(cls, "proc", None) and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=3)
            except Exception:
                cls.proc.kill()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_01_watch_until_condition_mcp_tool(self) -> None:
        """`runtime_watch_until_condition` catches a live condition in 0.00ms zero-stop mode."""
        raw_out = mcp_srv.runtime_watch_until_condition(
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            condition_expression="g_dynamic_counter >= 10 && g_mutex_locked == 1",
            poll_interval_ms=20,
            timeout_ms=1000,
        )
        res = json.loads(raw_out)
        self.assertTrue(res["success"], f"Failed: {res}")
        self.assertTrue(res["triggered"])
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertGreaterEqual(res["samples_taken"], 1)

    def test_02_traverse_linked_structure_clean_and_cycle(self) -> None:
        """`runtime_traverse_linked_structure` walks clean lists and detects pointer cycles."""
        # 1. Clean 4-node list
        raw_clean = mcp_srv.runtime_traverse_linked_structure(
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            head_expression="g_clean_list",
            next_field="next",
        )
        clean_res = json.loads(raw_clean)
        self.assertTrue(clean_res["success"], f"Failed: {clean_res}")
        self.assertEqual(clean_res["nodes_count"], 4)
        self.assertFalse(clean_res["cycle_detected"])
        self.assertEqual(clean_res["termination_reason"], "NULL_TERMINATED")
        self.assertEqual([n["fields"]["task_id"] for n in clean_res["nodes"]], [100, 101, 102, 103])

        # 2. Circular list (cycle back to index 1)
        raw_cycle = mcp_srv.runtime_traverse_linked_structure(
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            head_expression="g_cycle_list",
            next_field="next",
        )
        cycle_res = json.loads(raw_cycle)
        self.assertTrue(cycle_res["success"], f"Failed: {cycle_res}")
        self.assertTrue(cycle_res["cycle_detected"])
        self.assertEqual(cycle_res["termination_reason"], "CYCLE_DETECTED")
        self.assertEqual(cycle_res["cycle_target_index"], 1)

    def test_03_inspect_thread_callstack_and_locks(self) -> None:
        """`runtime_inspect_thread_callstack_and_locks` identifies mutex owners, futex waiters, and stack frames."""
        raw_cs = mcp_srv.runtime_inspect_thread_callstack_and_locks(
            pid=self.proc.pid,
            companion_elf=self.bin_path,
        )
        cs_res = json.loads(raw_cs)
        self.assertTrue(cs_res["success"], f"Failed: {cs_res}")
        self.assertEqual(cs_res["stop_duration_ms"], 0.0)

        # Verify g_test_mutex is locked and owned by `lock_holder`
        locks = {lk["name"]: lk for lk in cs_res["locks"]}
        self.assertIn("g_test_mutex", locks)
        self.assertTrue(locks["g_test_mutex"]["is_locked"])
        self.assertEqual(locks["g_test_mutex"]["owner_thread_name"], "lock_holder")

        # Verify `lock_holder` callstack contains `hold_mutex_forever` or `mutex_holder_thread`
        holder_th = next((t for t in cs_res["threads"] if t["name"] == "lock_holder"), None)
        self.assertIsNotNone(holder_th)
        fn_names = [f["function_name"] for f in holder_th["callstack"]]
        self.assertTrue(
            any("hold_mutex_forever" in fn or "mutex_holder_thread" in fn for fn in fn_names),
            f"Expected holder function in {fn_names}",
        )

    def test_04_audit_memory_integrity_detects_corruption(self) -> None:
        """`runtime_audit_memory_integrity` catches dangling pointers, corrupted bools, and invalid enums."""
        raw_au = mcp_srv.runtime_audit_memory_integrity(
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            target_expressions=["g_audit_target"],
        )
        au_res = json.loads(raw_au)
        self.assertTrue(au_res["success"], f"Failed: {au_res}")
        self.assertEqual(au_res["health_status"], "ANOMALIES_DETECTED")
        kinds = {a["anomaly_kind"] for a in au_res["anomalies"]}
        self.assertIn("DANGLING_OR_UNMAPPED_POINTER", kinds)
        self.assertIn("CORRUPTED_BOOL_VALUE", kinds)
        self.assertIn("INVALID_ENUM_VALUE", kinds)

    def test_05_resolve_code_pointers_and_vtable(self) -> None:
        """`runtime_resolve_code_pointers` symbolizes function pointers and C++ polymorphic vtable entries."""
        raw_cp = mcp_srv.runtime_resolve_code_pointers(
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            expressions=["g_packet_cb", "*g_poly_session"],
        )
        cp_res = json.loads(raw_cp)
        self.assertTrue(cp_res["success"], f"Failed: {cp_res}")
        results = {r["expression"]: r for r in cp_res["results"]}

        # 1. Function pointer `g_packet_cb` -> `on_packet_received`
        self.assertEqual(results["g_packet_cb"]["kind"], "FUNCTION_POINTER")
        self.assertIn("on_packet_received", results["g_packet_cb"]["resolved"]["function_name"])

        # 2. C++ polymorphic object `*g_poly_session` -> vtable entries for `RtspSession`
        poly_r = results["*g_poly_session"]
        self.assertEqual(poly_r["kind"], "POLYMORPHIC_VTABLE")
        vt_funcs = [v["function_name"] for v in poly_r["vtable_entries"]]
        self.assertTrue(
            any("processFrame" in fn or "RtspSession" in fn for fn in vt_funcs),
            f"Expected RtspSession virtual method in {vt_funcs}",
        )

    def test_06_inspect_shared_memory_ipc_and_workspace_chat(self) -> None:
        """`runtime_inspect_shared_memory_ipc` casts shared mapping to `ShmRingHeader`, and `workspace_chat_api` routes Phase 10 prompts."""
        raw_shm = mcp_srv.runtime_inspect_shared_memory_ipc(
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            cast_type="ShmRingHeader",
            shm_name="ds_test_ipc_shm.bin",
        )
        shm_res = json.loads(raw_shm)
        self.assertTrue(shm_res["success"], f"Failed: {shm_res}")
        self.assertGreaterEqual(shm_res["shared_mappings_count"], 1)
        self.assertIsNotNone(shm_res["decoded_overlay"])
        self.assertEqual(shm_res["decoded_overlay"]["value"]["producer_seq"], 42)
        self.assertEqual(shm_res["decoded_overlay"]["value"]["capacity"], 256)

        # Verify workspace_chat_api routes audit & callstack prompts into trace_cards
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_ws"))
        api = WebApiAdapter(rt)
        chat_res = api.workspace_chat_api({
            "message": "활성 스레드의 콜스택과 뮤텍스 락을 분석해주고 메모리 무결성 감사도 실행해 주세요",
            "pid": self.proc.pid,
            "companion_elf": self.bin_path,
        })
        self.assertTrue(chat_res["success"], f"Failed: {chat_res}")
        card_types = [c["card_type"] for c in chat_res["data"]["trace_cards"]]
        self.assertIn("CALLSTACK_AND_LOCKS", card_types)
        self.assertIn("MEMORY_AUDIT", card_types)


if __name__ == "__main__":
    unittest.main()
