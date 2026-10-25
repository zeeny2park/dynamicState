"""Phase 41 (Phase 11): 1-Call Composite Auto-Triage & Zero-Stop Stack Frame Local/Parameter Decoder Tests.

Verifies:
1. `runtime_inspect_thread_locals_and_frame_vars` decodes formal parameters (`DW_TAG_formal_parameter`)
   and local variables (`DW_TAG_variable`) on active thread callstacks via DWARF `DW_OP_fbreg` in 0.00ms stop mode.
2. `runtime_auto_triage_incident` performs a 1-call composite root-cause sweep combining Memory Integrity Audit,
   Thread Callstacks & Mutex Contention, Memory Pool Sweep, and Linked-List Cycle Detection.
3. `WebApiAdapter.workspace_chat_api` routes natural-language prompts to `AUTO_TRIAGE` and `FRAME_LOCALS` trace cards.
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


class TestPhase41AutoTriageAndFrameLocals(unittest.TestCase):
    """End-to-end verification of Phase 11 Auto-Triage and Stack Frame Local Variable Decoder."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_phase41_")
        cls.src_path = os.path.join(cls.tmp_dir, "phase41_target.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "phase41_target_nostrip")

        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(
                r"""
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

struct ListNode {
    int32_t id;
    ListNode* next;
};

ListNode g_cycle_nodes[3];
ListNode* g_bad_cycle_head = NULL;

struct CorruptRecord {
    int32_t id;
    bool healthy_flag;
    int32_t* dangling_ptr;
};

CorruptRecord g_corrupt_record;
pthread_mutex_t g_triage_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int g_ready = 0;

__attribute__((noinline)) void inner_worker_loop(int32_t param_tag, int32_t* ptr_arg) {
    volatile int32_t inner_local_magic = 888888;
    while (true) {
        if (inner_local_magic == -1 || param_tag == -1 || *ptr_arg == -1) break;
        usleep(40000);
    }
}

__attribute__((noinline)) void* triage_worker_fn(void* arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "triage_worker");
    pthread_mutex_lock(&g_triage_mutex);
    int32_t outer_local_magic = 777777;
    g_ready = 1;
    inner_worker_loop(4242, &outer_local_magic);
    return NULL;
}

int main() {
    // 1. Setup circular linked list (0 -> 1 -> 2 -> 1)
    for (int i = 0; i < 3; ++i) {
        g_cycle_nodes[i].id = 300 + i;
    }
    g_cycle_nodes[0].next = &g_cycle_nodes[1];
    g_cycle_nodes[1].next = &g_cycle_nodes[2];
    g_cycle_nodes[2].next = &g_cycle_nodes[1];
    g_bad_cycle_head = &g_cycle_nodes[0];

    // 2. Setup memory corruption record
    g_corrupt_record.id = 1;
    memset((void*)&g_corrupt_record.healthy_flag, 0x55, 1); // Corrupted bool byte
    g_corrupt_record.dangling_ptr = (int32_t*)0xdeadbeef00ULL;

    pthread_t th;
    pthread_create(&th, NULL, triage_worker_fn, NULL);
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
        cls.proc = subprocess.Popen([cls.bin_path])
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

    def test_01_inspect_thread_locals_and_frame_vars(self) -> None:
        """`runtime_inspect_thread_locals_and_frame_vars` decodes live stack parameters and locals in 0.00ms stop mode."""
        raw_out = mcp_srv.runtime_inspect_thread_locals_and_frame_vars(
            pid=self.proc.pid,
            companion_elf=self.bin_path,
        )
        res = json.loads(raw_out)
        self.assertTrue(res["success"], f"Failed: {res}")
        self.assertEqual(res["stop_duration_ms"], 0.0)

        worker_th = next((t for t in res["threads"] if t["name"] == "triage_worker"), None)
        self.assertIsNotNone(worker_th, f"triage_worker not found in {res['threads']}")

        # Collect all decoded parameter and local variable values across the worker thread's frames
        all_vars = {}
        for fr in worker_th["frames"]:
            for p in fr.get("parameters", []):
                all_vars[p["name"]] = p["value"]
            for loc in fr.get("locals", []):
                all_vars[loc["name"]] = loc["value"]

        self.assertEqual(all_vars.get("param_tag"), 4242, f"Expected param_tag=4242 in {all_vars}")
        self.assertEqual(all_vars.get("inner_local_magic"), 888888, f"Expected inner_local_magic=888888 in {all_vars}")
        self.assertEqual(all_vars.get("outer_local_magic"), 777777, f"Expected outer_local_magic=777777 in {all_vars}")

    def test_02_auto_triage_incident_one_call_root_cause(self) -> None:
        """`runtime_auto_triage_incident` detects mutex hold, memory corruption, and linked-list cycle in 1 call."""
        raw_out = mcp_srv.runtime_auto_triage_incident(
            pid=self.proc.pid,
            companion_elf=self.bin_path,
        )
        res = json.loads(raw_out)
        self.assertTrue(res["success"], f"Failed: {res}")
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertEqual(res["overall_status"], "CRITICAL_ISSUES_FOUND")

        categories = {f["category"] for f in res["findings"]}
        self.assertIn("MEMORY_CORRUPTION", categories)
        self.assertIn("MUTEX_LOCK_HELD", categories)
        self.assertIn("LINKED_LIST_CYCLE", categories)

    def test_03_workspace_chat_api_auto_triage_and_frame_locals(self) -> None:
        """`workspace_chat_api` routes Korean prompts for Auto-Triage and Frame Locals to visual trace cards."""
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_ws"))
        api = WebApiAdapter(rt)

        r1 = api.workspace_chat_api({
            "message": "프로세스 전체 상태를 원클릭 종합 진단 해주세요",
            "pid": self.proc.pid,
            "companion_elf": self.bin_path,
        })
        self.assertTrue(r1["success"], f"Failed: {r1}")
        self.assertEqual(r1["data"]["trace_cards"][0]["card_type"], "AUTO_TRIAGE")

        r2 = api.workspace_chat_api({
            "message": "활성 스레드의 스택 지역변수와 파라미터 인자를 해독해 주세요",
            "pid": self.proc.pid,
            "companion_elf": self.bin_path,
        })
        self.assertTrue(r2["success"], f"Failed: {r2}")
        self.assertEqual(r2["data"]["trace_cards"][0]["card_type"], "FRAME_LOCALS")


if __name__ == "__main__":
    unittest.main()
