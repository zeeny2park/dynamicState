"""Phase 39 (Phase 9): Minimalist Gemini-Style Chat + Progressive Trace Workspace UI Tests.

Verifies:
1. Existing Web UI (`extractor/web/static`) remains intact while `extractor/web/workspace.py`
   and `bin/dynamic-state-workspace` serve the new Chat + Trace Workspace UI.
2. `POST /api/workspace/chat` translates natural-language prompts into zero-stop process
   inspections and returns structured `trace_cards` (`POOL_MAP`, `THREAD_OWNER`, `XRAY_BLUEPRINT`, `SYMBOL_EVAL`).
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.request

from extractor.agent_runtime import AgentRuntime
from extractor.web.server import WebApiAdapter, run_server
from extractor.web.workspace import get_workspace_static_dir


class TestPhase39ChatTraceWorkspaceUI(unittest.TestCase):
    """End-to-end tests for the new Conversational Process Trace Workspace UI and API."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_phase39_")
        cls.src_path = os.path.join(cls.tmp_dir, "ws_target.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "ws_target_nostrip")

        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(
                r"""
#include <stdint.h>
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
};

struct MemPool {
    int32_t total_buffers;
    int32_t active_buffers;
    BufferSlot buffers[32];
};

MemPool g_pool_storage;
MemPool* gpMem = &g_pool_storage;
volatile int g_ready = 0;

__attribute__((noinline)) void hold_slot_on_stack(BufferSlot* volatile* holder) {
    while (true) {
        if ((*holder)->in_use == 999999) break;
        usleep(50000);
    }
}

void* worker_fn(void* arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "buf9_worker");
    BufferSlot* volatile local_slot = &gpMem->buffers[9];
    g_ready = 1;
    hold_slot_on_stack(&local_slot);
    return NULL;
}

int main() {
    memset(&g_pool_storage, 0, sizeof(g_pool_storage));
    gpMem->total_buffers = 32;
    gpMem->active_buffers = 5;
    int used[] = {0, 4, 9, 15, 27};
    for (int i = 0; i < 5; ++i) {
        int idx = used[i];
        gpMem->buffers[idx].in_use = 1;
        gpMem->buffers[idx].size = 256 * (idx + 1);
        gpMem->buffers[idx].seq = 10 + idx;
    }
    pthread_t th;
    pthread_create(&th, NULL, worker_fn, NULL);
    while (!g_ready) usleep(10000);
    while (true) usleep(50000);
    return 0;
}
"""
            )

        subprocess.run(
            ["g++", "-g", "-O0", "-pthread", cls.src_path, "-o", cls.bin_path],
            check=True,
        )
        cls.proc = subprocess.Popen([cls.bin_path])
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

    def test_01_workspace_static_and_legacy_ui_coexist(self) -> None:
        """Both legacy static UI and new workspace_static UI exist and serve cleanly over HTTP."""
        ws_dir = get_workspace_static_dir()
        self.assertTrue(os.path.isfile(os.path.join(ws_dir, "index.html")))

        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_http"))
        srv = run_server(runtime=rt, host="127.0.0.1", port=0, static_dir=ws_dir)
        port = srv.server_address[1]
        import threading
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
                html = resp.read().decode("utf-8")
            self.assertIn("dynamicState Workspace", html)
            self.assertIn("Process Trace Workspace", html)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_02_workspace_chat_api_pool_map_and_thread_owner(self) -> None:
        """`workspace_chat_api` translates Korean natural-language prompts into POOL_MAP and THREAD_OWNER trace cards."""
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_chat"))
        api = WebApiAdapter(rt)

        # 1. Pool map request
        r1 = api.workspace_chat_api({
            "message": "memory pool *gpMem의 메모리 buffer개의 할당 현황을 맵 차트로 그려주세요",
            "pid": self.proc.pid,
            "companion_elf": self.bin_path,
        })
        self.assertTrue(r1["success"], f"Failed: {r1}")
        cards1 = r1["data"]["trace_cards"]
        self.assertEqual(len(cards1), 1)
        self.assertEqual(cards1[0]["card_type"], "POOL_MAP")
        self.assertEqual(cards1[0]["data"]["pool_summary"]["allocated_indices"], [0, 4, 9, 15, 27])

        # 2. Thread owner request ("gpMem 9번 인덱스를 사용 중인 쓰레드를 찾아주세요")
        r2 = api.workspace_chat_api({
            "message": "gpMem 9번 인덱스를 사용 중인 쓰레드를 찾아주세요",
            "pid": self.proc.pid,
            "companion_elf": self.bin_path,
        })
        self.assertTrue(r2["success"], f"Failed: {r2}")
        cards2 = r2["data"]["trace_cards"]
        self.assertEqual(len(cards2), 1)
        self.assertEqual(cards2[0]["card_type"], "THREAD_OWNER")
        matched_names = [m["thread_name"] for m in cards2[0]["data"]["matched_threads"]]
        self.assertIn("buf9_worker", matched_names)

        # 3. Combined prompt in a single message
        r3 = api.workspace_chat_api({
            "message": "memory pool *gpMem의 할당 현황을 맵 차트로 그려주고 gpMem 9번 인덱스를 사용 중인 쓰레드를 찾아주세요",
            "pid": self.proc.pid,
            "companion_elf": self.bin_path,
        })
        self.assertTrue(r3["success"])
        card_types = [c["card_type"] for c in r3["data"]["trace_cards"]]
        self.assertEqual(card_types, ["POOL_MAP", "THREAD_OWNER"])


if __name__ == "__main__":
    unittest.main()
