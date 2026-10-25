import os
import subprocess
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.watch_session import WatchSessionManager
from extractor.web.server import WebApiAdapter


PHASE44_TARGET_CPP = r"""
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
};

struct MemPool {
    int32_t total_buffers;
    int32_t active_buffers;
    BufferSlot buffers[8];
};

struct WorkerContext {
    int32_t tid;
    int32_t is_healthy;
    int64_t processed_count;
};

MemPool g_pool_storage;
MemPool* gpMem = &g_pool_storage;
WorkerContext g_workers[2];
volatile int64_t g_total_packets_count = 0;
volatile int g_keep_running = 1;
volatile int g_ready = 0;

__attribute__((noinline)) void busy_hotspot_compute(int iterations) {
    for (int i = 0; i < iterations; ++i) {
        g_total_packets_count++;
    }
    usleep(5000);
}

void* hot_worker_fn(void* arg) {
    (void)arg;
    prctl(PR_SET_NAME, "hot_worker", 0, 0, 0);
    g_ready = 1;
    while (g_keep_running) {
        busy_hotspot_compute(2000);
    }
    return NULL;
}

int main() {
    memset(&g_pool_storage, 0, sizeof(g_pool_storage));
    g_pool_storage.total_buffers = 8;
    g_pool_storage.active_buffers = 3;
    g_workers[0].tid = getpid();
    g_workers[0].is_healthy = 1;
    g_workers[0].processed_count = 42;

    pthread_t th;
    pthread_create(&th, NULL, hot_worker_fn, NULL);

    while (g_keep_running) {
        usleep(30000);
    }
    pthread_join(th, NULL);
    return 0;
}
"""


class TestPhase44StatisticalHotspotsAndFuzzyIntent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_phase44_")
        cls.cpp_path = os.path.join(cls.tmp_dir, "phase44_target.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "phase44_target_nostrip")
        with open(cls.cpp_path, "w", encoding="utf-8") as f:
            f.write(PHASE44_TARGET_CPP)

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

    def test_01_sample_statistical_hotspots(self):
        res = self.wm.sample_statistical_hotspots(
            pid=self.pid,
            companion_elf_path=self.bin_path,
            samples_count=5,
            interval_ms=20,
        )
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertEqual(res["samples_taken"], 5)
        self.assertGreaterEqual(len(res["thread_cpu_profiles"]), 2)
        self.assertGreaterEqual(len(res["hotspot_functions"]), 1)

        fn_names = {f["function_name"] for f in res["hotspot_functions"]}
        self.assertTrue("busy_hotspot_compute" in fn_names or "hot_worker_fn" in fn_names or "main" in fn_names)

        # Verify counter velocity tracking captured `g_total_packets_count`
        rate_exprs = {c["expression"] for c in res["counter_rates"]}
        self.assertIn("g_total_packets_count", rate_exprs)

    def test_02_resolve_fuzzy_symbol_intent(self):
        res = self.wm.resolve_fuzzy_symbol_intent(
            pid=self.pid,
            companion_elf_path=self.bin_path,
            natural_query="버퍼 풀과 워커 스레드 상태 관련된 심볼을 찾아줘",
            limit=5,
        )
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertGreaterEqual(res["matches_count"], 2)
        matched_syms = {m["symbol_name"] for m in res["matches"]}
        self.assertTrue("gpMem" in matched_syms or "g_pool_storage" in matched_syms)
        self.assertIn("g_workers", matched_syms)

        # Check live_value was populated
        gp_match = next(m for m in res["matches"] if m["symbol_name"] in ("gpMem", "g_pool_storage"))
        self.assertIsNotNone(gp_match.get("live_value"))

    def test_03_workspace_chat_phase14_routing(self):
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_ws"))
        api = WebApiAdapter(rt)
        chat_res = api.workspace_chat_api({
            "pid": self.pid,
            "companion_elf": self.bin_path,
            "message": "통계적 샘플링으로 CPU 핫스팟 프로파일링 해주고 퍼지 의미 매칭으로 버퍼 풀 심볼도 찾아줘",
        })
        self.assertTrue(chat_res["success"])
        card_types = [c["card_type"] for c in chat_res["data"]["trace_cards"]]
        self.assertIn("STATISTICAL_HOTSPOTS", card_types)
        self.assertIn("FUZZY_INTENT_RESOLVER", card_types)


if __name__ == "__main__":
    unittest.main()
