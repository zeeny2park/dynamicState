import json
import os
import subprocess
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.watch_session import WatchSessionManager
from extractor.web.server import WebApiAdapter


PHASE43_TARGET_CPP = r"""
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

struct BufferSlot {
    int32_t in_use;
    int32_t owner_tid;
    int64_t seq;
    void* data_ptr;
};

struct MemPool {
    int32_t total_buffers;
    int32_t active_buffers;
    BufferSlot buffers[8];
};

MemPool g_pool_storage;
MemPool* gpMem = &g_pool_storage;
pthread_mutex_t g_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int g_keep_running = 1;
volatile int g_ready = 0;

__attribute__((noinline)) void hold_slot_and_lock(BufferSlot* held_slot, int spin_budget) {
    volatile int local_counter = spin_budget + 10;
    pthread_mutex_lock(&g_pool_mutex);
    g_ready = 1;
    while (g_keep_running && local_counter > 0) {
        usleep(20000);
    }
    pthread_mutex_unlock(&g_pool_mutex);
}

void* blocker_worker_fn(void* arg) {
    (void)arg;
    prctl(PR_SET_NAME, "blocker_worker", 0, 0, 0);
    BufferSlot* my_slot = &gpMem->buffers[3];
    hold_slot_and_lock(my_slot, 77);
    return NULL;
}

int main() {
    memset(&g_pool_storage, 0, sizeof(g_pool_storage));
    g_pool_storage.total_buffers = 8;
    g_pool_storage.active_buffers = 2;

    g_pool_storage.buffers[3].in_use = 1;
    g_pool_storage.buffers[3].owner_tid = 0; // held on stack by blocker_worker
    g_pool_storage.buffers[3].seq = 303;
    g_pool_storage.buffers[3].data_ptr = &g_pool_storage.buffers[3];

    // Intentional dangling pointer in slot 5 for composite symptom detection
    g_pool_storage.buffers[5].in_use = 1;
    g_pool_storage.buffers[5].owner_tid = 0;
    g_pool_storage.buffers[5].seq = 505;
    g_pool_storage.buffers[5].data_ptr = (void*)0xdeadbeef00ULL;

    pthread_t th;
    pthread_create(&th, NULL, blocker_worker_fn, NULL);

    while (g_keep_running) {
        usleep(30000);
    }
    g_keep_running = 0;
    pthread_join(th, NULL);
    return 0;
}
"""


class TestPhase43SymptomInvestigatorAndDependencyGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_phase43_")
        cls.cpp_path = os.path.join(cls.tmp_dir, "phase43_target.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "phase43_target_nostrip")
        with open(cls.cpp_path, "w", encoding="utf-8") as f:
            f.write(PHASE43_TARGET_CPP)

        subprocess.run(
            ["g++", "-g", "-O0", "-fno-omit-frame-pointer", "-pthread", cls.cpp_path, "-o", cls.bin_path],
            check=True,
        )
        cls.proc = subprocess.Popen([cls.bin_path])
        cls.pid = cls.proc.pid

        cls.wm = WatchSessionManager(corpus_dir=os.path.join(cls.tmp_dir, "corpus"))
        for _ in range(40):
            res = cls.wm.evaluate_symbol_paths(
                pid=cls.pid,
                companion_elf_path=cls.bin_path,
                expressions=["g_ready"],
            )
            if res["results"] and res["results"][0].get("value") == 1:
                break
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "proc") and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2)
            except Exception:
                cls.proc.kill()

    def test_01_build_dependency_graph(self):
        res = self.wm.build_dependency_graph(
            pid=self.pid,
            companion_elf_path=self.bin_path,
        )
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertGreaterEqual(res["nodes_count"], 3)
        self.assertGreaterEqual(res["edges_count"], 2)

        kinds = {n["kind"] for n in res["nodes"]}
        self.assertIn("PROCESS", kinds)
        self.assertIn("THREAD", kinds)
        self.assertIn("MUTEX_LOCK", kinds)

        relations = {e["relation"] for e in res["edges"]}
        self.assertIn("HELD_BY_THREAD", relations)

    def test_02_correlate_source_and_state(self):
        res = self.wm.correlate_source_and_state(
            pid=self.pid,
            companion_elf_path=self.bin_path,
            context_lines=6,
        )
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertGreaterEqual(res["snippets_count"], 1)
        sn = res["snippets"][0]
        self.assertTrue(sn["resolved_source_path"].endswith("phase43_target.cpp"))
        self.assertGreater(len(sn["annotated_lines"]), 0)
        # Verify inline [LIVE] variable annotations appear in the formatted snippet
        self.assertIn("[LIVE]", sn["annotated_code_block"])

    def test_03_investigate_symptom_and_workspace_chat(self):
        res = self.wm.investigate_symptom(
            pid=self.pid,
            companion_elf_path=self.bin_path,
            symptom_query="지금 프로세스가 왜 멈췄고 어디가 문제인지 종합 분석해줘",
        )
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertEqual(res["classified_symptom"], "HANG_OR_DEADLOCK")
        self.assertGreater(res["findings_count"], 0)
        self.assertTrue(res["root_cause_hypothesis"])
        self.assertGreater(len(res["annotated_source_snippets"]), 0)

        # Test Workspace Chat natural-language router for Phase 13 cards
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_ws"))
        api = WebApiAdapter(rt)
        chat_res = api.workspace_chat_api({
            "pid": self.pid,
            "companion_elf": self.bin_path,
            "message": "왜 멈췄지? 인과 종속성 그래프와 소스 코드 변수 매핑까지 같이 보여줘",
        })
        self.assertTrue(chat_res["success"])
        card_types = [c["card_type"] for c in chat_res["data"]["trace_cards"]]
        self.assertIn("SYMPTOM_INVESTIGATION", card_types)
        self.assertIn("DEPENDENCY_GRAPH", card_types)
        self.assertIn("SOURCE_CORRELATION", card_types)


if __name__ == "__main__":
    unittest.main()
