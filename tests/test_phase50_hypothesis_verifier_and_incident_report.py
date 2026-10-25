import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.watch_session import WatchSessionManager
from extractor.web.server import WebApiAdapter


PHASE50_CPP_SOURCE = r"""
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

struct BufferSlot {
    int32_t in_use;
    int32_t owner_tid;
    uint64_t seq;
    void* data_ptr;
};

struct MemPool {
    int32_t total_buffers;
    int32_t active_buffers;
    BufferSlot buffers[16];
};

MemPool g_pool_storage;
MemPool* gpMem = &g_pool_storage;
MemPool* g_null_pool_ptr = nullptr;
std::atomic<bool> g_running{true};
std::atomic<bool> g_worker_ready{false};

static pid_t get_tid() {
    return static_cast<pid_t>(syscall(SYS_gettid));
}

void* slot3_worker_fn(void* arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "slot3_worker");
    pid_t my_tid = get_tid();

    g_pool_storage.buffers[3].in_use = 1;
    g_pool_storage.buffers[3].owner_tid = static_cast<int32_t>(my_tid);
    g_pool_storage.buffers[3].seq = 3003ULL;
    g_pool_storage.buffers[3].data_ptr = reinterpret_cast<void*>(0xdeadbeef00ULL);

    volatile BufferSlot* ref_slot3 = &g_pool_storage.buffers[3];
    g_worker_ready.store(true);

    while (g_running.load(std::memory_order_relaxed)) {
        if (ref_slot3->seq == 99999999ULL) {
            break;
        }
        usleep(10000);
    }
    return nullptr;
}

int main() {
    std::memset(&g_pool_storage, 0, sizeof(g_pool_storage));
    g_pool_storage.total_buffers = 16;
    g_pool_storage.active_buffers = 2;

    g_pool_storage.buffers[0].in_use = 1;
    g_pool_storage.buffers[0].owner_tid = static_cast<int32_t>(get_tid());
    g_pool_storage.buffers[0].seq = 1000ULL;

    pthread_t th;
    pthread_create(&th, nullptr, slot3_worker_fn, nullptr);

    while (!g_worker_ready.load()) {
        usleep(1000);
    }

    std::printf("READY pid=%d\n", static_cast<int>(getpid()));
    std::fflush(stdout);

    while (g_running.load()) {
        usleep(20000);
    }

    pthread_join(th, nullptr);
    return 0;
}
"""


class TestPhase50HypothesisVerifierAndIncidentReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="dynstate_phase50_")
        cls.cpp_path = os.path.join(cls.tmp_dir, "phase50_target.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "phase50_target_nostrip")

        with open(cls.cpp_path, "w", encoding="utf-8") as f:
            f.write(PHASE50_CPP_SOURCE)

        subprocess.run(
            ["g++", "-g", "-O0", "-fno-omit-frame-pointer", "-pthread", cls.cpp_path, "-o", cls.bin_path],
            check=True,
        )

        cls.proc = subprocess.Popen(
            [cls.bin_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + 5.0
        ready = False
        while time.time() < deadline:
            line = cls.proc.stdout.readline()
            if "READY" in line:
                ready = True
                break
        if not ready:
            raise RuntimeError("Phase 50 target failed to start")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None):
            if cls.proc.stdout:
                cls.proc.stdout.close()
            if cls.proc.stderr:
                cls.proc.stderr.close()
            if cls.proc.poll() is None:
                cls.proc.terminate()
                try:
                    cls.proc.wait(timeout=2)
                except Exception:
                    cls.proc.kill()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_01_verify_runtime_hypothesis_confirmed_partial_and_refuted(self):
        """Verify declarative multi-assertion hypothesis verifier with forgiving expressions and owner correlation."""
        wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_1"))
        wm.bind_target_context(pid=self.proc.pid)

        # 1. CONFIRMED verdict (5/5 assertions pass + automatic slot owner correlation)
        res_conf = wm.verify_runtime_hypothesis(
            hypothesis="Slot #3 is actively held by slot3_worker with seq 3003 while g_null_pool_ptr is NULL",
            assertions=[
                "gpMem.active_buffers >= 2",
                "buffers[3].in_use == 1",
                "buffers[3].seq == 3003",
                "g_null_pool_ptr IS_NULL",
                "gpMem NOT_NULL",
            ],
            correlate_owners=True,
        )
        self.assertEqual(res_conf["stop_duration_ms"], 0.0)
        self.assertEqual(res_conf["verdict"], "CONFIRMED")
        self.assertEqual(res_conf["confidence_score"], 1.0)
        self.assertEqual(res_conf["passed_assertions"], 5)
        self.assertIn("gpMem->buffers[3]", res_conf["correlated_slot_owners"])
        owners = [o["thread_name"] for o in res_conf["correlated_slot_owners"]["gpMem->buffers[3]"]]
        self.assertIn("slot3_worker", owners)

        # 2. PARTIALLY_CONFIRMED verdict (1 pass, 1 fail)
        res_part = wm.verify_runtime_hypothesis(
            hypothesis="Partial match check",
            assertions=[
                "buffers[3].seq == 3003",
                "buffers[3].seq == 9999",
            ],
            correlate_owners=False,
        )
        self.assertEqual(res_part["verdict"], "PARTIALLY_CONFIRMED")
        self.assertEqual(res_part["confidence_score"], 0.5)

        # 3. REFUTED verdict (0 pass)
        res_ref = wm.verify_runtime_hypothesis(
            hypothesis="Refuted hypothesis",
            assertions=["gpMem.active_buffers == 99"],
            correlate_owners=False,
        )
        self.assertEqual(res_ref["verdict"], "REFUTED")
        self.assertEqual(res_ref["confidence_score"], 0.0)

    def test_02_export_incident_report_and_web_api_endpoints(self):
        """Verify 1-call incident report exporter and WebApiAdapter endpoints."""
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_2"))
        api = WebApiAdapter(rt)
        api.get_active_context_api({"pid": self.proc.pid})

        vh_resp = api.verify_hypothesis_api({
            "hypothesis": "Slot 3 is active",
            "assertions": ["buffers[3].in_use == 1", "buffers[3].seq == 3003"],
        })
        self.assertTrue(vh_resp["success"])
        self.assertEqual(vh_resp["data"]["verdict"], "CONFIRMED")

        report_file = os.path.join(self.tmp_dir, "incident_report_pid.md")
        er_resp = api.export_incident_report_api({
            "title": "Phase 20 Production Incident Report",
            "hypothesis": "Slot 3 corruption & ownership hypothesis",
            "assertions": ["buffers[3].in_use == 1", "buffers[3].seq == 3003"],
            "output_path": report_file,
        })
        self.assertTrue(er_resp["success"])
        rep_data = er_resp["data"]
        self.assertEqual(rep_data["stop_duration_ms"], 0.0)
        self.assertTrue(os.path.isfile(report_file))
        self.assertIn("## 1. Target Identity & Zero-Stop Telemetry", rep_data["report_markdown"])
        self.assertIn("## 2. Root-Cause Findings", rep_data["report_markdown"])
        self.assertIn("## 3. Hypothesis Verification (`CONFIRMED`", rep_data["report_markdown"])
        self.assertIn("## 5. Remediation Checklist", rep_data["report_markdown"])


if __name__ == "__main__":
    unittest.main()
