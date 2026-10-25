"""Phase 42 (Phase 12): Multi-Process IPC Pipeline Bottleneck Tracer & DWARF/vtable Heap Object Scanner Tests.

Verifies:
1. `runtime_trace_ipc_pipeline` across two live processes sharing a `MAP_SHARED` region (`ShmChannelRing`),
   confirming peer PID discovery, automatic struct type overlay, and `PIPELINE_STALLED_OR_FULL` backlog detection.
2. `runtime_scan_heap_objects` scanning `[heap]` for C++ polymorphic `vtable` (`_ZTV*`) instances,
   distinguishing referenced heap objects from unreachable/leaked heap objects (`is_leaked_candidate = True`).
3. `WebApiAdapter.workspace_chat_api` routing natural-language prompts to `IPC_PIPELINE` and `HEAP_SCANNER` trace cards.
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


class TestPhase42IpcPipelineAndHeapScanner(unittest.TestCase):
    """End-to-end verification of Phase 12 Multi-Process IPC Pipeline Tracer & Heap Object/Leak Scanner."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_phase42_")
        cls.src_path = os.path.join(cls.tmp_dir, "phase42_target.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "phase42_target_nostrip")
        cls.shm_file = os.path.join(cls.tmp_dir, "ds_phase42_ipc_ring.shm")

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

// 1. Shared Memory IPC Pipeline Header
struct ShmChannelRing {
    int32_t magic;
    int32_t producer_seq;
    int32_t consumer_seq;
    int32_t capacity;
    int32_t owner_pid;
};

ShmChannelRing* g_shm_channel = NULL;

// 2. Polymorphic C++ Class for Heap Object Census & Leak Detection
class BaseWorkerObj {
public:
    int32_t worker_kind;
    BaseWorkerObj() : worker_kind(1) {}
    virtual ~BaseWorkerObj() {}
    virtual int32_t tick() { return 0; }
};

class MediaWorkerSession : public BaseWorkerObj {
public:
    int32_t session_id;
    int32_t processed_frames;
    MediaWorkerSession(int32_t sid, int32_t frames) : session_id(sid), processed_frames(frames) {
        worker_kind = 2;
    }
    virtual int32_t tick() override { return processed_frames + 1; }
};

MediaWorkerSession* g_referenced_heap_session = NULL;
volatile uintptr_t g_hidden_leaked_addr_xor = 0;

__attribute__((noinline)) void alloc_leaked_session() {
    MediaWorkerSession* leaked = new MediaWorkerSession(9999, 0);
    g_hidden_leaked_addr_xor = ((uintptr_t)leaked) ^ 0x5a5a5a5a5a5a5a5aULL;
}

__attribute__((noinline)) void scrub_dead_stack() {
    volatile uint64_t zero_buf[128];
    for (int i = 0; i < 128; ++i) zero_buf[i] = 0;
}

int main(int argc, char** argv) {
    const char* mode = (argc > 1) ? argv[1] : "producer";
    const char* shm_path = (argc > 2) ? argv[2] : "/tmp/ds_phase42.shm";

    int fd = open(shm_path, O_CREAT | O_RDWR, 0666);
    if (fd >= 0) {
        ftruncate(fd, 4096);
        void* map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (map != MAP_FAILED) {
            g_shm_channel = (ShmChannelRing*)map;
            if (strcmp(mode, "producer") == 0) {
                g_shm_channel->magic = 0x52494e47;
                g_shm_channel->producer_seq = 95;
                g_shm_channel->consumer_seq = 10;
                g_shm_channel->capacity = 100;
                g_shm_channel->owner_pid = getpid();
            }
        }
        close(fd);
    }

    if (strcmp(mode, "producer") == 0) {
        g_referenced_heap_session = new MediaWorkerSession(1001, 50);
        alloc_leaked_session();
        scrub_dead_stack();
    }

    while (true) {
        usleep(50000);
    }
    return 0;
}
"""
            )

        subprocess.run(
            ["g++", "-g", "-O0", "-fno-omit-frame-pointer", cls.src_path, "-o", cls.bin_path],
            check=True,
        )
        cls.producer_proc = subprocess.Popen([cls.bin_path, "producer", cls.shm_file])
        cls.consumer_proc = subprocess.Popen([cls.bin_path, "consumer", cls.shm_file])
        time.sleep(0.35)

    @classmethod
    def tearDownClass(cls) -> None:
        for p_attr in ("producer_proc", "consumer_proc"):
            proc = getattr(cls, p_attr, None)
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_01_trace_ipc_pipeline_cross_process_bottleneck(self) -> None:
        """`runtime_trace_ipc_pipeline` detects cross-process peer PID and 85% ring buffer backlog."""
        raw_out = mcp_srv.runtime_trace_ipc_pipeline(
            pid=self.producer_proc.pid,
            companion_elf=self.bin_path,
            shm_name="ds_phase42_ipc_ring.shm",
        )
        res = json.loads(raw_out)
        self.assertTrue(res["success"], f"Failed: {res}")
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertEqual(res["pipeline_health"], "PIPELINE_STALLED_OR_FULL")
        self.assertEqual(res["metrics"]["producer_seq"], 95)
        self.assertEqual(res["metrics"]["consumer_seq"], 10)
        self.assertEqual(res["metrics"]["pending_backlog"], 85)
        self.assertEqual(res["metrics"]["backlog_utilization_pct"], 85.0)

        peer_pids = [p["peer_pid"] for p in res["peer_processes"]]
        self.assertIn(self.consumer_proc.pid, peer_pids)

    def test_02_scan_heap_objects_and_detect_leaked_instance(self) -> None:
        """`runtime_scan_heap_objects` locates `MediaWorkerSession` heap instances and flags the unreferenced leak."""
        raw_out = mcp_srv.runtime_scan_heap_objects(
            pid=self.producer_proc.pid,
            companion_elf=self.bin_path,
            class_filter="MediaWorkerSession",
        )
        res = json.loads(raw_out)
        self.assertTrue(res["success"], f"Failed: {res}")
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertGreaterEqual(res["total_objects_found"], 2)
        self.assertGreaterEqual(res["leaked_candidates_count"], 1)

        by_sid = {
            obj["fields"]["session_id"]: obj
            for obj in res["objects"]
            if isinstance(obj.get("fields"), dict) and "session_id" in obj["fields"]
        }
        self.assertIn(1001, by_sid)
        self.assertIn(9999, by_sid)
        self.assertFalse(by_sid[1001]["is_leaked_candidate"])
        self.assertTrue(by_sid[9999]["is_leaked_candidate"])

    def test_03_workspace_chat_api_ipc_pipeline_and_heap_scanner(self) -> None:
        """`workspace_chat_api` routes Korean prompts for IPC pipeline and Heap Scanner into trace cards."""
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_ws"))
        api = WebApiAdapter(rt)

        r1 = api.workspace_chat_api({
            "message": "멀티 프로세스 공유 메모리 프로듀서/컨슈머 파이프라인 병목을 진단해 주세요",
            "pid": self.producer_proc.pid,
            "companion_elf": self.bin_path,
        })
        self.assertTrue(r1["success"], f"Failed: {r1}")
        self.assertEqual(r1["data"]["trace_cards"][0]["card_type"], "IPC_PIPELINE")

        r2 = api.workspace_chat_api({
            "message": "힙 영역의 C++ 객체와 메모리 누수 의심 인스턴스를 스캔해 주세요",
            "pid": self.producer_proc.pid,
            "companion_elf": self.bin_path,
        })
        self.assertTrue(r2["success"], f"Failed: {r2}")
        self.assertEqual(r2["data"]["trace_cards"][0]["card_type"], "HEAP_SCANNER")


if __name__ == "__main__":
    unittest.main()
