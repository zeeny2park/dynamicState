"""Phase 38 (Phase 8): Memory Pool Map Scanner & Thread Ownership Reverse-Lookup Tests.

Directly verifies the two real-world user scenarios:
1. "memory pool *gpMem의 메모리 buffer개의 할당 현황을 맵 차트로 그려주세요"
   (`scan_memory_pool_or_array` / `runtime_scan_memory_pool`)
2. "gpMem 9번 인덱스를 사용 중인 쓰레드를 찾아주세요"
   (`find_symbol_owners_and_threads` / `runtime_find_symbol_owners`)
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.watch_session import WatchSessionManager
from extractor.web.server import WebApiAdapter


class TestPhase38PoolScannerAndThreadOwnerLookup(unittest.TestCase):
    """End-to-end tests against a real multi-threaded C++ process with `MemPool *gpMem`."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_phase38_")
        cls.src_path = os.path.join(cls.tmp_dir, "pool_target.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "pool_target_nostrip")

        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(
                r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>

struct BufferSlot {
    int32_t in_use;
    int32_t size;
    int32_t owner_tid;
    int32_t seq;
    char* data_ptr;
};

struct MemPool {
    int32_t total_buffers;
    int32_t active_buffers;
    BufferSlot buffers[32];
};

struct WorkerContext {
    int32_t worker_id;
    int32_t tid;
    BufferSlot* active_buf;
};

MemPool g_pool_storage;
MemPool* gpMem = &g_pool_storage;
WorkerContext g_workers[4];
volatile int g_ready = 0;

// Prevent compiler from optimizing away the stack-local pointer to gpMem->buffers[9]
__attribute__((noinline)) void hold_buffer_on_stack(BufferSlot* volatile* stack_slot_holder) {
    while (true) {
        if ((*stack_slot_holder)->in_use == 999999) {
            break;
        }
        usleep(50000);
    }
}

void* worker_thread_func(void* arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "buf9_worker");
    pid_t my_tid = (pid_t)syscall(SYS_gettid);

    // Worker 1 holds buffer 14 in global worker table
    g_workers[1].worker_id = 1;
    g_workers[1].tid = (int32_t)my_tid;
    g_workers[1].active_buf = &gpMem->buffers[14];

    // Hold pointer to gpMem->buffers[9] purely as a local variable on this thread's stack!
    BufferSlot* volatile local_buf_ptr = &gpMem->buffers[9];
    g_ready = 1;
    hold_buffer_on_stack(&local_buf_ptr);
    return NULL;
}

int main() {
    memset(&g_pool_storage, 0, sizeof(g_pool_storage));
    memset(g_workers, 0, sizeof(g_workers));
    gpMem->total_buffers = 32;
    gpMem->active_buffers = 7;

    int allocated[] = {0, 2, 5, 9, 14, 21, 30};
    for (int i = 0; i < 7; ++i) {
        int idx = allocated[i];
        gpMem->buffers[idx].in_use = 1;
        gpMem->buffers[idx].size = (idx + 1) * 128;
        gpMem->buffers[idx].seq = 100 + idx;
        gpMem->buffers[idx].data_ptr = (char*)malloc(64);
    }

    // Slot 5 explicitly records main thread TID in owner_tid
    gpMem->buffers[5].owner_tid = (int32_t)syscall(SYS_gettid);

    pthread_t th;
    pthread_create(&th, NULL, worker_thread_func, NULL);

    while (!g_ready) {
        usleep(10000);
    }
    while (true) {
        usleep(50000);
    }
    return 0;
}
"""
            )

        subprocess.run(
            ["g++", "-g", "-O0", "-pthread", cls.src_path, "-o", cls.bin_path],
            check=True,
        )
        cls.proc = subprocess.Popen([cls.bin_path])
        # Wait until worker thread has initialized its stack frame and set g_ready
        time.sleep(0.25)

    @classmethod
    def tearDownClass(cls) -> None:
        if getattr(cls, "proc", None) and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=3)
            except Exception:
                cls.proc.kill()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_01_scan_memory_pool_star_gpMem_and_map_chart(self) -> None:
        """`scan_memory_pool_or_array` scans all 32 buffers of `*gpMem` in a single batch read and builds map chart."""
        wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_1"))

        for expr in ("*gpMem", "gpMem", "gpMem->buffers"):
            res = wm.scan_memory_pool_or_array(
                pid=self.proc.pid,
                companion_elf_path=self.bin_path,
                base_expression=expr,
            )
            summary = res["pool_summary"]
            self.assertEqual(summary["total_slots"], 32, f"Failed for expr={expr}")
            self.assertEqual(summary["allocated_count"], 7, f"Failed for expr={expr}")
            self.assertEqual(summary["free_count"], 25, f"Failed for expr={expr}")
            self.assertEqual(summary["allocated_indices"], [0, 2, 5, 9, 14, 21, 30])
            self.assertEqual(len(res["allocation_bitmap"]), 32)
            self.assertEqual(res["allocation_bitmap"][9], "1")
            self.assertEqual(res["allocation_bitmap"][8], "0")
            self.assertIn("[000..015]", res["ascii_map_chart"])
            self.assertIn("[016..031]", res["ascii_map_chart"])
            self.assertEqual(res["slots"][9]["status"], "IN_USE")
            self.assertEqual(res["slots"][9]["fields"]["size"], 1280)

    def test_02_find_thread_using_gpMem_index_9_via_stack_pointer(self) -> None:
        """`find_symbol_owners_and_threads` finds `buf9_worker` holding `&gpMem->buffers[9]` on its thread stack."""
        wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_2"))

        for expr in ("gpMem->buffers[9]", "gpMem[9]"):
            res = wm.find_symbol_owners_and_threads(
                pid=self.proc.pid,
                companion_elf_path=self.bin_path,
                target_expression=expr,
            )
            self.assertGreaterEqual(res["matched_threads_count"], 1, f"No thread found for {expr}: {res}")
            thread_names = [m["thread_name"] for m in res["matched_threads"]]
            self.assertIn("buf9_worker", thread_names, f"Expected buf9_worker in {res['matched_threads']}")
            ev_kinds = [
                ev["evidence_kind"]
                for m in res["matched_threads"]
                if m["thread_name"] == "buf9_worker"
                for ev in m["evidence"]
            ]
            self.assertTrue(
                any("STACK_POINTER_REFERENCE" in k for k in ev_kinds),
                f"Expected stack pointer reference evidence, got {ev_kinds}",
            )

    def test_03_find_thread_via_struct_owner_tid_and_global_worker_table(self) -> None:
        """`find_symbol_owners_and_threads` detects Stage 1 (`owner_tid`) and Stage 2 (`g_workers[]`)."""
        wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_3"))

        # Slot 5 has owner_tid == main thread PID
        res5 = wm.find_symbol_owners_and_threads(
            pid=self.proc.pid,
            companion_elf_path=self.bin_path,
            target_expression="gpMem->buffers[5]",
        )
        matched_tids_5 = [m["tid"] for m in res5["matched_threads"]]
        self.assertIn(self.proc.pid, matched_tids_5)

        # Slot 14 is referenced by g_workers[1].active_buf bound to buf9_worker TID
        res14 = wm.find_symbol_owners_and_threads(
            pid=self.proc.pid,
            companion_elf_path=self.bin_path,
            target_expression="gpMem->buffers[14]",
        )
        thread_names_14 = [m["thread_name"] for m in res14["matched_threads"]]
        self.assertIn("buf9_worker", thread_names_14)
        self.assertTrue(any("g_workers[1]" in r["symbol"] for r in res14["global_references"]))

    def test_04_xray_blueprint_and_web_api_endpoints(self) -> None:
        """`get_process_xray_blueprint` and WebApiAdapter endpoints return categorized pools and owner results."""
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_4"))
        api = WebApiAdapter(rt)

        bp_res = api.get_xray_blueprint_api({"pid": self.proc.pid, "companion_elf": self.bin_path})
        self.assertTrue(bp_res["success"])
        pools = bp_res["data"]["categories"]["memory_pools_and_buffers"]
        pool_names = [p["name"] for p in pools]
        self.assertIn("gpMem", pool_names)

        scan_res = api.scan_memory_pool_api({
            "pid": self.proc.pid,
            "companion_elf": self.bin_path,
            "base_expression": "*gpMem",
        })
        self.assertTrue(scan_res["success"])
        self.assertEqual(scan_res["data"]["pool_summary"]["allocated_count"], 7)

        own_res = api.find_symbol_owners_api({
            "pid": self.proc.pid,
            "companion_elf": self.bin_path,
            "target_expression": "gpMem[9]",
        })
        self.assertTrue(own_res["success"])
        self.assertIn("buf9_worker", [m["thread_name"] for m in own_res["data"]["matched_threads"]])


if __name__ == "__main__":
    unittest.main()
