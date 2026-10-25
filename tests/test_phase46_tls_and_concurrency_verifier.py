"""End-to-end verification for Phase 16 (Phase 46):
1. Zero-Stop Per-Thread TLS (`__thread` / `thread_local`) Variable Decoder (`inspect_thread_local_storage`)
2. Optimistic Seqlock Double-Read Concurrency Verifier (`verify_concurrent_read_consistency`)
3. Web API & Conversational Workspace Chat routing (`TLS_INSPECTOR`, `CONCURRENCY_VERIFIER`)
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.dwarf_indexer import DwarfIndexer
from extractor.agent_runtime import AgentRuntime
from extractor.watch_session import WatchSessionManager
from extractor.web.server import WebApiAdapter


CPP_SOURCE = r"""
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <unistd.h>

struct StaticConfig {
    int32_t magic;
    int32_t version;
    uint64_t flags;
};

StaticConfig g_static_config = {0x5A5A1234, 16, 0xCAFEBABEULL};
volatile uint64_t g_fast_mutating_counter = 0;
volatile int g_ready_threads = 0;

thread_local int32_t tls_worker_slot_id = 0;
__thread uint64_t tls_secret_token = 0;

void* tls_worker_fn(void* arg) {
    long idx = (long)arg;
    char tname[16];
    snprintf(tname, sizeof(tname), "tls_worker_%ld", idx);
    pthread_setname_np(pthread_self(), tname);

    tls_worker_slot_id = (int32_t)(200 + idx);
    tls_secret_token = (idx == 1) ? 0xAAAA0001BBBB0001ULL : 0xAAAA0002BBBB0002ULL;

    __sync_fetch_and_add(&g_ready_threads, 1);

    if (idx == 1) {
        // High-frequency mutator thread for g_fast_mutating_counter
        while (1) {
            for (int i = 0; i < 50000; ++i) {
                g_fast_mutating_counter++;
            }
            usleep(200);
        }
    } else {
        while (1) {
            usleep(50000);
        }
    }
    return nullptr;
}

int main() {
    tls_worker_slot_id = 100;
    tls_secret_token = 0x1111222233334444ULL;

    pthread_t t1, t2;
    pthread_create(&t1, nullptr, tls_worker_fn, (void*)1);
    pthread_create(&t2, nullptr, tls_worker_fn, (void*)2);

    while (g_ready_threads < 2) {
        usleep(10000);
    }

    printf("READY_PID=%d\n", getpid());
    fflush(stdout);

    while (1) {
        usleep(100000);
    }
    return 0;
}
"""


class TestPhase46TlsAndConcurrencyVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_phase46_")
        cls.cpp_path = os.path.join(cls.tmp_dir, "tls_target.cpp")
        cls.elf_path = os.path.join(cls.tmp_dir, "tls_target_nostrip")
        with open(cls.cpp_path, "w", encoding="utf-8") as f:
            f.write(CPP_SOURCE)

        subprocess.run(
            ["g++", "-g", "-O0", "-pthread", cls.cpp_path, "-o", cls.elf_path],
            check=True,
        )

        cls.proc = subprocess.Popen(
            [cls.elf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert cls.proc.stdout is not None
        ready_line = cls.proc.stdout.readline().strip()
        assert ready_line.startswith("READY_PID="), f"Unexpected startup output: {ready_line}"
        cls.pid = int(ready_line.split("=")[1])
        time.sleep(0.05)

        DwarfIndexer.clear_cache()
        cls.watch_mgr = WatchSessionManager(corpus_dir=os.path.join(cls.tmp_dir, "corpus"))

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None) is not None:
            try:
                cls.proc.terminate()
                cls.proc.wait(timeout=3)
            except Exception:
                try:
                    cls.proc.kill()
                except Exception:
                    pass
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_01_zero_stop_per_thread_tls_decoder(self):
        """Verifies ELF PT_TLS + DWARF DW_OP_form_tls_address + glibc TCB discovery decodes per-thread TLS variables."""
        res = self.watch_mgr.inspect_thread_local_storage(
            pid=self.pid,
            companion_elf_path=self.elf_path,
        )
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertGreaterEqual(res["tls_variables_discovered"], 2)
        self.assertEqual(res["threads_count"], 3)
        self.assertEqual(res["tcb_resolved_count"], 3)

        slot_values = set()
        token_values = set()
        for t in res["threads"]:
            self.assertIsNotNone(t["tcb_address"])
            self.assertIsNotNone(t["tls_block_base"])
            vars_map = {v["name"]: v["value"] for v in t["tls_variables"]}
            self.assertIn("tls_worker_slot_id", vars_map)
            self.assertIn("tls_secret_token", vars_map)
            slot_values.add(vars_map["tls_worker_slot_id"])
            token_values.add(vars_map["tls_secret_token"])

        self.assertEqual(slot_values, {100, 201, 202})
        self.assertEqual(
            token_values,
            {
                0x1111222233334444,
                0xAAAA0001BBBB0001,
                0xAAAA0002BBBB0002,
            },
        )

        # Verify variable_summaries marks per-thread divergence as True
        summaries_by_name = {s["name"]: s for s in res["variable_summaries"]}
        self.assertTrue(summaries_by_name["tls_worker_slot_id"]["has_per_thread_divergence"])
        self.assertTrue(summaries_by_name["tls_secret_token"]["has_per_thread_divergence"])

    def test_02_optimistic_seqlock_double_read_verifier(self):
        """Verifies atomic consistency on static structs vs active concurrent mutation detection on hot counters."""
        res = self.watch_mgr.verify_concurrent_read_consistency(
            pid=self.pid,
            companion_elf_path=self.elf_path,
            expressions=["g_static_config", "g_fast_mutating_counter"],
            retries=3,
            inter_read_delay_ms=6,
        )
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertEqual(res["symbols_checked_count"], 2)

        by_expr = {s["expression"]: s for s in res["symbols"]}
        self.assertEqual(by_expr["g_static_config"]["consistency_status"], "ATOMIC_CONSISTENT")
        self.assertEqual(by_expr["g_static_config"]["attempts_used"], 1)
        self.assertEqual(by_expr["g_static_config"]["verified_value"]["version"], 16)

        self.assertEqual(by_expr["g_fast_mutating_counter"]["consistency_status"], "CONCURRENTLY_MUTATING")
        self.assertEqual(res["overall_consistency_status"], "ACTIVE_CONCURRENT_MUTATIONS_DETECTED")

    def test_03_web_api_and_workspace_chat_integration(self):
        """Verifies REST endpoints and Korean natural-language chat router for TLS_INSPECTOR and CONCURRENCY_VERIFIER."""
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_web"))
        api = WebApiAdapter(rt)

        tls_api_res = api.inspect_thread_local_storage_api({
            "pid": self.pid,
            "companion_elf": self.elf_path,
        })
        self.assertTrue(tls_api_res["success"])
        self.assertEqual(tls_api_res["data"]["tcb_resolved_count"], 3)

        vc_api_res = api.verify_concurrent_read_consistency_api({
            "pid": self.pid,
            "companion_elf": self.elf_path,
            "expressions": ["g_static_config", "g_fast_mutating_counter"],
            "retries": 2,
            "inter_read_delay_ms": 5,
        })
        self.assertTrue(vc_api_res["success"])
        self.assertEqual(vc_api_res["data"]["symbols_checked_count"], 2)

        chat_res = api.workspace_chat_api({
            "pid": self.pid,
            "companion_elf": self.elf_path,
            "message": "스레드별 TLS(thread_local) 변수 값을 해독해주고 동시성 이중 읽기(Seqlock) 일관성도 검증해 주세요",
        })
        self.assertTrue(chat_res["success"], msg=str(chat_res))
        card_types = [c["card_type"] for c in chat_res["data"]["trace_cards"]]
        self.assertIn("TLS_INSPECTOR", card_types)
        self.assertIn("CONCURRENCY_VERIFIER", card_types)


if __name__ == "__main__":
    unittest.main()
