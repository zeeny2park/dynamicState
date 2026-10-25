import os
import subprocess
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.watch_session import WatchSessionManager
from extractor.web.server import WebApiAdapter


PHASE45_TARGET_CPP = r"""
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

MemPool g_pool_storage;
MemPool* gpMem = &g_pool_storage;
pthread_mutex_t g_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int32_t g_transient_spike_flag = 0;
volatile int32_t g_drift_mode = 0;
volatile int g_keep_running = 1;
volatile int g_ready = 0;

void* spike_and_drift_worker(void* arg) {
    (void)arg;
    prctl(PR_SET_NAME, "spike_worker", 0, 0, 0);
    g_ready = 1;
    int tick = 0;
    while (g_keep_running) {
        tick++;
        // Toggle transient spike every alternate 25ms window so Flight Recorder sees 0 -> 999 -> 0
        if (tick % 2 == 1) {
            g_transient_spike_flag = 999;
        } else {
            g_transient_spike_flag = 0;
        }
        if (g_drift_mode) {
            pthread_mutex_lock(&g_pool_mutex);
            g_pool_storage.active_buffers = 6;
            for (int i = 0; i < 6; ++i) {
                g_pool_storage.buffers[i].in_use = 1;
            }
            usleep(20000);
            pthread_mutex_unlock(&g_pool_mutex);
        } else {
            usleep(20000);
        }
    }
    return NULL;
}

int main() {
    memset(&g_pool_storage, 0, sizeof(g_pool_storage));
    g_pool_storage.total_buffers = 8;
    g_pool_storage.active_buffers = 1;
    g_pool_storage.buffers[0].in_use = 1;

    pthread_t th;
    pthread_create(&th, NULL, spike_and_drift_worker, NULL);

    while (g_keep_running) {
        usleep(30000);
    }
    pthread_join(th, NULL);
    return 0;
}
"""


class TestPhase45FlightRecorderAndBehavioralDrift(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_phase45_")
        cls.cpp_path = os.path.join(cls.tmp_dir, "phase45_target.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "phase45_target_nostrip")
        with open(cls.cpp_path, "w", encoding="utf-8") as f:
            f.write(PHASE45_TARGET_CPP)

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

    def test_01_flight_recorder_time_machine(self):
        res = self.wm.flight_recorder_time_machine(
            pid=self.pid,
            companion_elf_path=self.bin_path,
            frames_count=6,
            interval_ms=22,
            watch_expressions=["g_transient_spike_flag", "*gpMem"],
        )
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertEqual(res["frames_recorded"], 6)
        self.assertIn("pre_anomaly_frame", res["time_machine_triad"])
        self.assertIn("peak_anomaly_frame", res["time_machine_triad"])
        self.assertIn("post_anomaly_frame", res["time_machine_triad"])
        # Verify transient spike was recorded in the timeline
        self.assertGreaterEqual(res["transient_glitches_count"], 1)
        glitch_paths = {g["path"] for g in res["transient_glitches"]}
        self.assertIn("g_transient_spike_flag", glitch_paths)

    def test_02_detect_behavioral_drift(self):
        # 1. Capture healthy baseline
        base_res = self.wm.detect_behavioral_drift(
            pid=self.pid,
            companion_elf_path=self.bin_path,
            save_as_new_baseline=True,
        )
        self.assertEqual(base_res["stop_duration_ms"], 0.0)
        self.assertEqual(base_res["drift_status"], "STABLE_ON_BASELINE")

        # 2. Mutate synthetic baseline pool utilization to simulate behavioral drift
        self.wm._learned_behavioral_profiles[self.pid]["pools"]["gpMem->buffers"]["utilization_pct"] = 0.0
        self.wm._learned_behavioral_profiles[self.pid]["pools"]["gpMem->buffers"]["allocated_count"] = 0
        self.wm._learned_behavioral_profiles[self.pid]["scalars"]["g_ready"] = 0

        drift_res = self.wm.detect_behavioral_drift(
            pid=self.pid,
            companion_elf_path=self.bin_path,
            save_as_new_baseline=False,
        )
        self.assertEqual(drift_res["stop_duration_ms"], 0.0)
        self.assertGreater(drift_res["drift_score"], 0)
        self.assertGreaterEqual(drift_res["drifted_dimensions_count"], 1)

    def test_03_workspace_chat_phase15_routing(self):
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_ws"))
        api = WebApiAdapter(rt)
        chat_res = api.workspace_chat_api({
            "pid": self.pid,
            "companion_elf": self.bin_path,
            "message": "방금 잠깐 튀었는데 타임머신 플라이트 레코더로 확인하고 평소 대비 행동 편차(Drift)도 알려줘",
        })
        self.assertTrue(chat_res["success"])
        card_types = [c["card_type"] for c in chat_res["data"]["trace_cards"]]
        self.assertIn("FLIGHT_RECORDER", card_types)
        self.assertIn("BEHAVIORAL_DRIFT", card_types)


if __name__ == "__main__":
    unittest.main()
