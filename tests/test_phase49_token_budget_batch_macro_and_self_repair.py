import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.watch_session import WatchSessionManager
from extractor.web.server import WebApiAdapter


PHASE49_CPP_SOURCE = r"""
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
    uint64_t zero_pad_a;
    uint64_t zero_pad_b;
    char label[24];
};

struct MemPool {
    int32_t total_buffers;
    int32_t active_buffers;
    BufferSlot buffers[64];
};

MemPool g_pool_storage;
MemPool* gpMem = &g_pool_storage;
MemPool* g_null_pool_ptr = nullptr;
std::atomic<bool> g_running{true};
std::atomic<bool> g_worker_ready{false};

static pid_t get_tid() {
    return static_cast<pid_t>(syscall(SYS_gettid));
}

void* slot5_worker_fn(void* arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "slot5_worker");
    pid_t my_tid = get_tid();

    g_pool_storage.buffers[5].in_use = 1;
    g_pool_storage.buffers[5].owner_tid = static_cast<int32_t>(my_tid);
    g_pool_storage.buffers[5].seq = 5005ULL;
    std::snprintf(g_pool_storage.buffers[5].label, sizeof(g_pool_storage.buffers[5].label), "ACTIVE_SLOT_5");

    g_pool_storage.buffers[19].in_use = 1;
    g_pool_storage.buffers[19].owner_tid = static_cast<int32_t>(my_tid);
    g_pool_storage.buffers[19].seq = 19019ULL;
    std::snprintf(g_pool_storage.buffers[19].label, sizeof(g_pool_storage.buffers[19].label), "ACTIVE_SLOT_19");

    volatile BufferSlot* ref_slot5 = &g_pool_storage.buffers[5];
    g_worker_ready.store(true);

    while (g_running.load(std::memory_order_relaxed)) {
        if (ref_slot5->seq == 99999999ULL) {
            break;
        }
        usleep(10000);
    }
    return nullptr;
}

int main() {
    std::memset(&g_pool_storage, 0, sizeof(g_pool_storage));
    g_pool_storage.total_buffers = 64;
    g_pool_storage.active_buffers = 3;

    g_pool_storage.buffers[0].in_use = 1;
    g_pool_storage.buffers[0].owner_tid = static_cast<int32_t>(get_tid());
    g_pool_storage.buffers[0].seq = 1000ULL;
    std::snprintf(g_pool_storage.buffers[0].label, sizeof(g_pool_storage.buffers[0].label), "ACTIVE_SLOT_0");

    pthread_t th;
    pthread_create(&th, nullptr, slot5_worker_fn, nullptr);

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


class TestPhase49TokenBudgetBatchMacroAndSelfRepair(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="dynstate_phase49_")
        cls.cpp_path = os.path.join(cls.tmp_dir, "phase49_target.cpp")
        cls.bin_path = os.path.join(cls.tmp_dir, "phase49_target_nostrip")

        with open(cls.cpp_path, "w", encoding="utf-8") as f:
            f.write(PHASE49_CPP_SOURCE)

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
            raise RuntimeError("Phase 49 target failed to start")

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

    def test_01_self_repairing_diagnostics_on_symbol_member_and_null_errors(self):
        """Verify SYMBOL_NOT_FOUND, MEMBER_NOT_FOUND, and NULL_POINTER return actionable `self_repair` payloads."""
        wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_1"))
        wm.bind_target_context(pid=self.proc.pid)

        res = wm.evaluate_symbol_paths(
            expressions=[
                "g_nonexistent_symbol",
                "g_pool_storage.nonexistent_field_xyz",
                "g_null_pool_ptr->active_buffers",
            ]
        )
        by_expr = {item["expression"]: item for item in res["results"]}

        # 1. SYMBOL_NOT_FOUND self-repair
        sym_err = by_expr["g_nonexistent_symbol"]
        self.assertEqual(sym_err["status"], "SYMBOL_NOT_FOUND")
        self.assertIn("self_repair", sym_err)
        closest_names = [c["name"] for c in sym_err["self_repair"]["closest_symbols"]]
        self.assertTrue(any(n in closest_names for n in ("gpMem", "g_pool_storage")))
        self.assertEqual(sym_err["self_repair"]["suggested_mcp_call"]["tool"], "runtime_eval_memory_path")

        # 2. MEMBER_NOT_FOUND self-repair
        mem_err = by_expr["g_pool_storage.nonexistent_field_xyz"]
        self.assertEqual(mem_err["status"], "MEMBER_NOT_FOUND")
        self.assertIn("self_repair", mem_err)
        avail_names = [m["name"] for m in mem_err["self_repair"]["available_members"]]
        self.assertIn("active_buffers", avail_names)
        self.assertIn("buffers", avail_names)

        # 3. NULL_POINTER self-repair (discovers non-null `g_pool_storage` of the same `MemPool` struct type!)
        null_err = by_expr["g_null_pool_ptr->active_buffers"]
        self.assertEqual(null_err["status"], "NULL_POINTER")
        self.assertIn("self_repair", null_err)
        alt_names = [a["name"] for a in null_err["self_repair"]["alternative_same_type_globals"]]
        self.assertIn("g_pool_storage", alt_names)

    def test_02_llm_token_budget_compactor_and_cursor_pagination(self):
        """Verify anomaly-first smart compaction collapses 61 FREE slots, paginates 3 IN_USE slots, and saves >60% tokens."""
        wm = WatchSessionManager(corpus_dir=os.path.join(self.tmp_dir, "corpus_2"))
        wm.bind_target_context(pid=self.proc.pid)

        # Page 1: cursor_offset=0, page_size=2 -> returns active slots #0 and #5
        page1 = wm.smart_compact_query(
            query_or_expression="*gpMem",
            mode="pool",
            max_tokens=400,
            drop_zero_or_free=True,
            cursor_offset=0,
            page_size=2,
        )
        self.assertEqual(page1["collapsed_free_slots_count"], 61)
        self.assertEqual(len(page1["slots"]), 2)
        self.assertEqual([s["index"] for s in page1["slots"]], [0, 5])

        meta1 = page1["token_budget_meta"]
        self.assertTrue(meta1["anomaly_first_preserved"])
        self.assertGreater(meta1["token_reduction_pct"], 60.0)
        self.assertTrue(meta1["pagination"]["has_more"])
        self.assertEqual(meta1["pagination"]["next_cursor_offset"], 2)

        # Page 2: cursor_offset=2, page_size=2 -> returns active slot #19 and has_more=False
        page2 = wm.smart_compact_query(
            query_or_expression="*gpMem",
            mode="pool",
            max_tokens=400,
            drop_zero_or_free=True,
            cursor_offset=2,
            page_size=2,
        )
        self.assertEqual(len(page2["slots"]), 1)
        self.assertEqual(page2["slots"][0]["index"], 19)
        self.assertFalse(page2["token_budget_meta"]["pagination"]["has_more"])
        self.assertIsNone(page2["token_budget_meta"]["pagination"]["next_cursor_offset"])

    def test_03_one_call_batch_macro_executor_and_web_api(self):
        """Verify 1-call `execute_batch_macro` and WebApiAdapter `/api/watch/batch-execute` & `/api/watch/smart-compact`."""
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_3"))
        api = WebApiAdapter(rt)
        api.get_active_context_api({"pid": self.proc.pid})

        sc_resp = api.smart_compact_query_api({
            "query": "*gpMem",
            "mode": "pool",
            "page_size": 5,
        })
        self.assertTrue(sc_resp["success"])
        self.assertEqual(len(sc_resp["data"]["slots"]), 3)
        self.assertEqual(sc_resp["data"]["collapsed_free_slots_count"], 61)

        batch_resp = api.batch_execute_api({
            "compact": True,
            "steps": [
                {"step_id": "eval_step", "action": "eval", "expressions": ["gpMem.buffers[5].seq", "buffers[19].seq"]},
                {"step_id": "pool_step", "action": "scan_pool", "base_expression": "*gpMem"},
                {"step_id": "owner_step", "action": "find_owners", "target_expression": "buffers[5]"},
            ],
        })
        self.assertTrue(batch_resp["success"])
        b_data = batch_resp["data"]
        self.assertEqual(b_data["stop_duration_ms"], 0.0)
        self.assertEqual(b_data["steps_requested"], 3)
        self.assertEqual(b_data["steps_succeeded"], 3)
        self.assertEqual(b_data["steps_failed"], 0)
        self.assertGreaterEqual(len(b_data["cross_step_highlights"]), 2)

        by_step = {s["step_id"]: s["output"] for s in b_data["step_results"]}
        self.assertEqual(by_step["eval_step"]["results"][0]["value"], 5005)
        self.assertEqual(by_step["eval_step"]["results"][1]["value"], 19019)
        self.assertEqual(len(by_step["pool_step"]["slots"]), 3)
        owner_threads = [t["thread_name"] for t in by_step["owner_step"]["matched_threads"]]
        self.assertIn("slot5_worker", owner_threads)


if __name__ == "__main__":
    unittest.main()
