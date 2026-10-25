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


PHASE48_CPP_SOURCE = r"""
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
    char label[16];
};

struct MemPool {
    int32_t total_buffers;
    int32_t active_buffers;
    BufferSlot buffers[8];
};

struct rte_ring {
    char name[32];
    uint32_t capacity;
    uint32_t prod_head;
    uint32_t prod_tail;
    uint32_t cons_head;
    uint32_t cons_tail;
};

MemPool g_pool_storage;
MemPool* gpMem = &g_pool_storage;
rte_ring g_dpdk_rx_ring;
std::atomic<bool> g_running{true};
std::atomic<bool> g_worker_ready{false};

static pid_t get_tid() {
    return static_cast<pid_t>(syscall(SYS_gettid));
}

void* worker_fn(void* arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "slot2_worker");
    pid_t my_tid = get_tid();

    g_pool_storage.buffers[2].in_use = 1;
    g_pool_storage.buffers[2].owner_tid = static_cast<int32_t>(my_tid);
    g_pool_storage.buffers[2].seq = 2002ULL;
    std::snprintf(g_pool_storage.buffers[2].label, sizeof(g_pool_storage.buffers[2].label), "SLOT_2_LIVE");

    volatile BufferSlot* stack_slot_ref = &g_pool_storage.buffers[2];
    g_worker_ready.store(true);

    while (g_running.load(std::memory_order_relaxed)) {
        if (stack_slot_ref->seq == 99999999ULL) {
            break;
        }
        usleep(10000);
    }
    return nullptr;
}

int main() {
    std::memset(&g_pool_storage, 0, sizeof(g_pool_storage));
    g_pool_storage.total_buffers = 8;
    g_pool_storage.active_buffers = 2;
    g_pool_storage.buffers[0].in_use = 1;
    g_pool_storage.buffers[0].owner_tid = static_cast<int32_t>(get_tid());
    g_pool_storage.buffers[0].seq = 1001ULL;
    std::snprintf(g_pool_storage.buffers[0].label, sizeof(g_pool_storage.buffers[0].label), "SLOT_0_MAIN");

    std::memset(&g_dpdk_rx_ring, 0, sizeof(g_dpdk_rx_ring));
    std::snprintf(g_dpdk_rx_ring.name, sizeof(g_dpdk_rx_ring.name), "RX_RING_0");
    g_dpdk_rx_ring.capacity = 1024;
    g_dpdk_rx_ring.prod_head = 888;
    g_dpdk_rx_ring.prod_tail = 888;
    g_dpdk_rx_ring.cons_head = 880;
    g_dpdk_rx_ring.cons_tail = 880;

    pthread_t th;
    pthread_create(&th, nullptr, worker_fn, nullptr);

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


class TestPhase48StatefulContextAndForgivingExpressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="dynstate_phase48_")
        cls.cpp_path = os.path.join(cls.tmp_dir, "phase48_target.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "phase48_target_nostrip")

        with open(cls.cpp_path, "w", encoding="utf-8") as f:
            f.write(PHASE48_CPP_SOURCE)

        compile_cmd = [
            "g++", "-g", "-O0", "-fno-omit-frame-pointer", "-pthread",
            cls.cpp_path, "-o", cls.bin_path,
        ]
        subprocess.run(compile_cmd, check=True)
        cls.proc = cls._spawn_target()

    @classmethod
    def _spawn_target(cls) -> subprocess.Popen:
        p = subprocess.Popen(
            [cls.bin_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + 5.0
        while time.time() < deadline:
            line = p.stdout.readline()
            if "READY" in line:
                return p
        raise RuntimeError("Target process failed to become READY")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None):
            if cls.proc.stdout:
                cls.proc.stdout.close()
            if cls.proc.stderr:
                cls.proc.stderr.close()
        if getattr(cls, "proc", None) and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2)
            except Exception:
                cls.proc.kill()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_01_zero_path_elf_autodiscovery_and_stateful_context(self):
        """Verify connecting with ONLY `pid` auto-discovers `/proc/<pid>/exe` DWARF ELF and binds active context."""
        wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_1"))

        # Bind with ONLY pid (companion_elf_path=None!)
        ctx = wm.bind_target_context(pid=self.proc.pid, companion_elf_path=None)
        self.assertEqual(ctx["pid"], self.proc.pid)
        self.assertTrue(ctx["elf_auto_discovered"])
        self.assertEqual(os.path.abspath(ctx["companion_elf_path"]), os.path.abspath(self.bin_path))

        active = wm.get_active_target_context()
        self.assertTrue(active["has_active_context"])
        self.assertEqual(active["pid"], self.proc.pid)

        # Subsequent call with pid=None, companion_elf_path=None inherits bound context
        eval_res = wm.evaluate_symbol_paths(
            pid=None,
            companion_elf_path=None,
            expressions=["gpMem->buffers[2].seq"],
        )
        self.assertEqual(eval_res["pid"], self.proc.pid)
        self.assertEqual(eval_res["stop_duration_ms"], 0.0)
        self.assertEqual(eval_res["results"][0]["status"], "OBSERVED")
        self.assertEqual(eval_res["results"][0]["value"], 2002)

    def test_02_forgiving_expression_auto_coercer(self):
        """Verify `.` <-> `->`, bare member promotion, container index pivot, and symbol typo auto-coercion."""
        wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_2"))
        wm.bind_target_context(pid=self.proc.pid, companion_elf_path=self.bin_path)

        forgiving_exprs = [
            "gpMem.buffers[2].seq",           # '.' used on pointer gpMem (MemPool*) -> gpMem->buffers[2].seq
            "g_pool_storage->active_buffers", # '->' used on struct g_pool_storage -> g_pool_storage.active_buffers
            "buffers[2].seq",                 # Bare member without root global -> gpMem->buffers[2].seq
            "prod_tail",                      # Bare struct field -> g_dpdk_rx_ring.prod_tail
            "gpMem[2].seq",                   # Indexing pool pointer directly -> gpMem->buffers[2].seq
            "g_pol_storage.active_buffers",   # Root symbol typo -> g_pool_storage.active_buffers
            "g_rx_ring.prod_tail",            # Omitted middle token in root symbol -> g_dpdk_rx_ring.prod_tail
        ]

        res = wm.evaluate_symbol_paths(expressions=forgiving_exprs)
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertEqual(len(res["results"]), len(forgiving_exprs))
        by_expr = {item["expression"]: item for item in res["results"]}

        # 1. gpMem.buffers[2].seq -> gpMem->buffers[2].seq
        self.assertEqual(by_expr["gpMem.buffers[2].seq"]["status"], "OBSERVED")
        self.assertTrue(by_expr["gpMem.buffers[2].seq"]["was_coerced"])
        self.assertEqual(by_expr["gpMem.buffers[2].seq"]["resolved_expression"], "gpMem->buffers[2].seq")
        self.assertEqual(by_expr["gpMem.buffers[2].seq"]["value"], 2002)

        # 2. g_pool_storage->active_buffers -> g_pool_storage.active_buffers
        self.assertEqual(by_expr["g_pool_storage->active_buffers"]["status"], "OBSERVED")
        self.assertTrue(by_expr["g_pool_storage->active_buffers"]["was_coerced"])
        self.assertEqual(by_expr["g_pool_storage->active_buffers"]["resolved_expression"], "g_pool_storage.active_buffers")
        self.assertEqual(by_expr["g_pool_storage->active_buffers"]["value"], 2)

        # 3. buffers[2].seq -> gpMem->buffers[2].seq
        self.assertEqual(by_expr["buffers[2].seq"]["status"], "OBSERVED")
        self.assertTrue(by_expr["buffers[2].seq"]["was_coerced"])
        self.assertEqual(by_expr["buffers[2].seq"]["resolved_expression"], "gpMem->buffers[2].seq")
        self.assertEqual(by_expr["buffers[2].seq"]["value"], 2002)

        # 4. prod_tail -> g_dpdk_rx_ring.prod_tail
        self.assertEqual(by_expr["prod_tail"]["status"], "OBSERVED")
        self.assertTrue(by_expr["prod_tail"]["was_coerced"])
        self.assertEqual(by_expr["prod_tail"]["resolved_expression"], "g_dpdk_rx_ring.prod_tail")
        self.assertEqual(by_expr["prod_tail"]["value"], 888)

        # 5. gpMem[2].seq -> gpMem->buffers[2].seq
        self.assertEqual(by_expr["gpMem[2].seq"]["status"], "OBSERVED")
        self.assertTrue(by_expr["gpMem[2].seq"]["was_coerced"])
        self.assertEqual(by_expr["gpMem[2].seq"]["resolved_expression"], "gpMem->buffers[2].seq")
        self.assertEqual(by_expr["gpMem[2].seq"]["value"], 2002)

        # 6. g_pol_storage.active_buffers -> g_pool_storage.active_buffers
        self.assertEqual(by_expr["g_pol_storage.active_buffers"]["status"], "OBSERVED")
        self.assertTrue(by_expr["g_pol_storage.active_buffers"]["was_coerced"])
        self.assertEqual(by_expr["g_pol_storage.active_buffers"]["resolved_expression"], "g_pool_storage.active_buffers")
        self.assertEqual(by_expr["g_pol_storage.active_buffers"]["value"], 2)

        # 7. g_rx_ring.prod_tail -> g_dpdk_rx_ring.prod_tail
        self.assertEqual(by_expr["g_rx_ring.prod_tail"]["status"], "OBSERVED")
        self.assertTrue(by_expr["g_rx_ring.prod_tail"]["was_coerced"])
        self.assertEqual(by_expr["g_rx_ring.prod_tail"]["resolved_expression"], "g_dpdk_rx_ring.prod_tail")
        self.assertEqual(by_expr["g_rx_ring.prod_tail"]["value"], 888)

    def test_03_universal_ask_gateway_and_web_api(self):
        """Verify 1-call `ask_runtime_question` and WebApiAdapter `/api/watch/ask` & `/api/watch/coerce-expression`."""
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_3"))
        api = WebApiAdapter(rt)

        # Bind active context via Web API with only PID
        ctx_resp = api.get_active_context_api({"pid": self.proc.pid})
        self.assertTrue(ctx_resp["success"])
        self.assertEqual(ctx_resp["data"]["pid"], self.proc.pid)

        # Coerce expression via Web API without repeating pid/companion_elf
        c_resp = api.coerce_expression_api({"expression": "buffers[2].seq"})
        self.assertTrue(c_resp["success"])
        self.assertEqual(c_resp["data"]["resolved_expression"], "gpMem->buffers[2].seq")

        # Ask 1: forgiving expression evaluation via ask gateway without pid/companion_elf
        ask1 = api.ask_runtime_question_api({"question": "gpMem.buffers[2].seq"})
        self.assertTrue(ask1["success"])
        self.assertEqual(ask1["data"]["routed_tool"], "runtime_eval_memory_path")
        self.assertEqual(ask1["data"]["results"][0]["value"], 2002)

        # Ask 2: thread owner lookup with bare expression via ask gateway
        ask2 = api.ask_runtime_question_api({"question": "buffers[2] 누가 잡고 있어?"})
        self.assertTrue(ask2["success"])
        self.assertEqual(ask2["data"]["routed_tool"], "runtime_find_symbol_owners")
        self.assertGreaterEqual(ask2["data"]["matched_threads_count"], 1)
        t_names = [t["thread_name"] for t in ask2["data"]["matched_threads"]]
        self.assertIn("slot2_worker", t_names)

    def test_04_auto_heal_pid_on_process_restart(self):
        """Verify automatic PID self-healing when the bound target process restarts under a new PID."""
        wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_4"))
        old_pid = self.proc.pid
        wm.bind_target_context(pid=old_pid, companion_elf_path=None)

        # Terminate original process and spawn a fresh instance with a new PID
        if self.__class__.proc.stdout:
            self.__class__.proc.stdout.close()
        if self.__class__.proc.stderr:
            self.__class__.proc.stderr.close()
        self.__class__.proc.terminate()
        self.__class__.proc.wait(timeout=3)
        self.__class__.proc = self._spawn_target()
        new_pid = self.__class__.proc.pid
        self.assertNotEqual(old_pid, new_pid)

        # Call evaluate_symbol_paths without passing new_pid (or even passing stale old_pid!)
        healed_res = wm.evaluate_symbol_paths(
            pid=old_pid,
            companion_elf_path=None,
            expressions=["buffers[2].seq"],
        )
        self.assertTrue(healed_res["auto_healed_pid"])
        self.assertEqual(healed_res["previous_pid"], old_pid)
        self.assertEqual(healed_res["pid"], new_pid)
        self.assertEqual(healed_res["results"][0]["value"], 2002)

        active = wm.get_active_target_context()
        self.assertEqual(active["pid"], new_pid)
        self.assertGreaterEqual(active["auto_healed_count"], 1)


if __name__ == "__main__":
    unittest.main()
