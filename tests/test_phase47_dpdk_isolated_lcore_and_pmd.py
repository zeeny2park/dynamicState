"""End-to-end verification for Phase 17 (Phase 47):
Zero-Stop Support for DPDK Isolated-Core (`isolcpus`) Dedicated Poll-Mode (PMD / lcore) Threads:
1. 100% user-space poll loop (`state == 'R'`, `/proc/<pid>/task/<tid>/syscall == "running"`, `kstkesp == 0`)
   with zero syscalls inside the loop.
2. Pure leaf function callstack unwinding (`LEAF_CALL_TARGET_RECOVERY` via `CALL rel32` target inspection)
   and DWARF stack frame parameter/local variable decoding on running lcores.
3. Stack-based mbuf/buffer slot owner discovery (`find_symbol_owners_and_threads`) on running lcores.
4. `inspect_dpdk_lcores_and_rings`:
   - Single-core CPU affinity (`pthread_setaffinity_np`), `per_lcore__lcore_id` & `per_lcore__rx_pkt_burst` TLS decoding
   - Distinguishing `PMD_POLLING_HEALTHY` (active packet/burst counter progress) vs `LCORE_STUCK_DEADLOOP` (frozen progress)
   - DPDK lockless `rte_ring` (`HEALTHY_FLOWING` vs `STUCK_PROD_INFLIGHT_RESERVATION`) and `rte_spinlock_t` (`CONTENDED_OR_STUCK_LOCKED`)
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.dwarf_indexer import DwarfIndexer
from extractor.watch_session import WatchSessionManager
from extractor.web.server import WebApiAdapter


DPDK_CPP_SOURCE = r"""
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

struct rte_mbuf_slot {
    int32_t in_use;
    int32_t lcore_owner;
    uint64_t pkt_len;
};

struct rte_ring {
    uint32_t capacity;
    uint32_t mask;
    volatile uint32_t prod_head;
    volatile uint32_t prod_tail;
    volatile uint32_t cons_head;
    volatile uint32_t cons_tail;
};

struct rte_spinlock_t {
    volatile int32_t locked;
};

rte_mbuf_slot g_mbuf_pool[8];
rte_ring g_dpdk_rx_ring = {1024, 1023, 100, 100, 100, 100};
rte_ring g_stalled_ring = {1024, 1023, 520, 512, 500, 500};
rte_spinlock_t g_tx_spinlock = {1};

__thread int32_t per_lcore__lcore_id = -1;
__thread uint64_t per_lcore__rx_pkt_burst = 0;

volatile int g_lcores_ready = 0;
volatile int g_keep_running = 1;

// Pure user-space leaf function: NO syscalls and NO function calls inside the while(1) poll loop!
__attribute__((noinline))
void pmd_poll_rx_tx_burst(rte_ring* rx_ring, rte_mbuf_slot* pinned_mbuf) {
    rte_mbuf_slot* active_mbuf = pinned_mbuf;
    int32_t local_burst_size = 32;
    __sync_fetch_and_add(&g_lcores_ready, 1);

    while (g_keep_running) {
        // Advance lockless ring and per-lcore TLS packet counter purely in user space
        uint32_t next_seq = rx_ring->prod_tail + 1;
        rx_ring->prod_head = next_seq;
        rx_ring->prod_tail = next_seq;
        rx_ring->cons_head = next_seq;
        rx_ring->cons_tail = next_seq;
        per_lcore__rx_pkt_burst += (uint64_t)local_burst_size;
        active_mbuf->pkt_len = per_lcore__rx_pkt_burst;
        for (int spin = 0; spin < 200; ++spin) {
            #if defined(__x86_64__) || defined(__i386__)
            __builtin_ia32_pause();
            #else
            asm volatile("" ::: "memory");
            #endif
        }
    }
}

// Pure user-space stuck leaf function: spins at 100% CPU in user space with frozen progress counters
__attribute__((noinline))
void pmd_stuck_enqueue_deadloop(rte_ring* stalled_ring) {
    int32_t stuck_retry_code = 409;
    __sync_fetch_and_add(&g_lcores_ready, 1);

    while (g_keep_running) {
        // Stalled waiting for stalled_ring->prod_tail == 512 while prod_head == 520
        if (stalled_ring->prod_tail == 99999999U) {
            per_lcore__rx_pkt_burst += (uint64_t)stuck_retry_code;
        }
        #if defined(__x86_64__) || defined(__i386__)
        __builtin_ia32_pause();
        #else
        asm volatile("" ::: "memory");
        #endif
    }
}

void* dpdk_eal_lcore_trampoline(void* arg) {
    long lcore_idx = (long)arg;
    char tname[16];
    snprintf(tname, sizeof(tname), "lcore-worker-%ld", lcore_idx);
    pthread_setname_np(pthread_self(), tname);

    // Pin dedicated lcore thread to a single CPU core
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int target_cpu = (num_cpus > 1) ? (int)(lcore_idx % num_cpus) : 0;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(target_cpu, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    per_lcore__lcore_id = (int32_t)lcore_idx;
    per_lcore__rx_pkt_burst = (lcore_idx == 1) ? 1000ULL : 500ULL;

    if (lcore_idx == 1) {
        pmd_poll_rx_tx_burst(&g_dpdk_rx_ring, &g_mbuf_pool[3]);
    } else {
        pmd_stuck_enqueue_deadloop(&g_stalled_ring);
    }
    return nullptr;
}

int main() {
    memset(g_mbuf_pool, 0, sizeof(g_mbuf_pool));
    g_mbuf_pool[3].in_use = 1;
    g_mbuf_pool[3].lcore_owner = 1;
    g_mbuf_pool[3].pkt_len = 64;

    per_lcore__lcore_id = 0;

    pthread_t th1, th2;
    pthread_create(&th1, nullptr, dpdk_eal_lcore_trampoline, (void*)1);
    pthread_create(&th2, nullptr, dpdk_eal_lcore_trampoline, (void*)2);

    while (g_lcores_ready < 2) {
        usleep(5000);
    }

    printf("READY_PID=%d\n", getpid());
    fflush(stdout);

    while (g_keep_running) {
        usleep(100000);
    }
    return 0;
}
"""


class TestPhase47DpdkIsolatedLcoreAndPmd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="ds_phase47_")
        cls.cpp_path = os.path.join(cls.tmp_dir, "dpdk_target.cpp")
        cls.elf_path = os.path.join(cls.tmp_dir, "dpdk_target_nostrip")
        with open(cls.cpp_path, "w", encoding="utf-8") as f:
            f.write(DPDK_CPP_SOURCE)

        subprocess.run(
            ["g++", "-g", "-O0", "-fno-omit-frame-pointer", "-pthread", cls.cpp_path, "-o", cls.elf_path],
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

    def test_01_pure_userspace_poll_loop_callstack_and_frame_locals(self):
        """Verifies that 100% user-space spinning DPDK lcores (syscall=='running', sp==0) unwind leaf functions and decode frame locals."""
        cs_res = self.watch_mgr.inspect_thread_callstacks_and_locks(
            pid=self.pid,
            companion_elf_path=self.elf_path,
        )
        self.assertEqual(cs_res["stop_duration_ms"], 0.0)
        by_name = {t["name"]: t for t in cs_res["threads"]}
        self.assertIn("lcore-worker-1", by_name)
        self.assertIn("lcore-worker-2", by_name)

        # Verify pure leaf functions (`pmd_poll_rx_tx_burst` and `pmd_stuck_enqueue_deadloop`) are recovered as Frame #0
        w1_funcs = [f["function_name"] for f in by_name["lcore-worker-1"]["callstack"]]
        w2_funcs = [f["function_name"] for f in by_name["lcore-worker-2"]["callstack"]]
        self.assertIn("pmd_poll_rx_tx_burst", w1_funcs)
        self.assertEqual(w1_funcs[0], "pmd_poll_rx_tx_burst")
        self.assertIn("pmd_stuck_enqueue_deadloop", w2_funcs)
        self.assertEqual(w2_funcs[0], "pmd_stuck_enqueue_deadloop")

        # Verify stack frame parameters & locals inside pure user-space leaf function
        fl_res = self.watch_mgr.inspect_thread_locals_and_frame_vars(
            pid=self.pid,
            companion_elf_path=self.elf_path,
        )
        fl_by_name = {t["name"]: t for t in fl_res["threads"]}
        w1_frames = {fr["function_name"]: fr for fr in fl_by_name["lcore-worker-1"]["frames"]}
        self.assertIn("pmd_poll_rx_tx_burst", w1_frames)
        leaf_fr = w1_frames["pmd_poll_rx_tx_burst"]
        locals_map = {v["name"]: v["value"] for v in leaf_fr["locals"]}
        self.assertEqual(locals_map.get("local_burst_size"), 32)
        self.assertIsNotNone(locals_map.get("active_mbuf"))

    def test_02_stack_pointer_owner_lookup_on_running_lcore(self):
        """Verifies find_symbol_owners_and_threads locates &g_mbuf_pool[3] on the stack of running lcore-worker-1."""
        own_res = self.watch_mgr.find_symbol_owners_and_threads(
            pid=self.pid,
            companion_elf_path=self.elf_path,
            target_expression="g_mbuf_pool[3]",
        )
        self.assertEqual(own_res["stop_duration_ms"], 0.0)
        matched_names = {m["thread_name"] for m in own_res["matched_threads"]}
        self.assertIn("lcore-worker-1", matched_names)

    def test_03_dpdk_lcores_and_rings_inspector(self):
        """Verifies inspect_dpdk_lcores_and_rings distinguishes healthy polling vs deadloop lcore and stuck rte_ring."""
        res = self.watch_mgr.inspect_dpdk_lcores_and_rings(
            pid=self.pid,
            companion_elf_path=self.elf_path,
            sample_window_ms=45,
        )
        self.assertEqual(res["stop_duration_ms"], 0.0)
        self.assertGreaterEqual(res["dedicated_pmd_lcores_count"], 2)

        lcores_by_name = {lc["name"]: lc for lc in res["lcores"]}
        lc1 = lcores_by_name["lcore-worker-1"]
        lc2 = lcores_by_name["lcore-worker-2"]

        self.assertTrue(lc1["is_single_core_pinned"])
        self.assertEqual(lc1["lcore_id"], 1)
        self.assertEqual(lc1["pmd_health_status"], "PMD_POLLING_HEALTHY")
        self.assertGreater(lc1["progress_delta"], 0)
        self.assertEqual(lc1["top_function"], "pmd_poll_rx_tx_burst")

        self.assertTrue(lc2["is_single_core_pinned"])
        self.assertEqual(lc2["lcore_id"], 2)
        self.assertEqual(lc2["pmd_health_status"], "LCORE_STUCK_DEADLOOP")
        self.assertEqual(lc2["top_function"], "pmd_stuck_enqueue_deadloop")

        rings_by_expr = {r["expression"]: r for r in res["lockless_rings"]}
        self.assertEqual(rings_by_expr["g_dpdk_rx_ring"]["ring_status"], "HEALTHY_FLOWING")
        self.assertEqual(rings_by_expr["g_stalled_ring"]["ring_status"], "STUCK_PROD_INFLIGHT_RESERVATION")

        spins_by_expr = {s["expression"]: s for s in res["spinlocks"]}
        self.assertEqual(spins_by_expr["g_tx_spinlock"]["spinlock_status"], "CONTENDED_OR_STUCK_LOCKED")

    def test_04_web_api_and_workspace_chat_dpdk_routing(self):
        """Verifies /api/watch/dpdk-lcores and Korean chat prompt routing for DPDK_LCORE_INSPECTOR."""
        rt = AgentRuntime(corpus_dir=os.path.join(self.tmp_dir, "corpus_web"))
        api = WebApiAdapter(rt)

        api_res = api.inspect_dpdk_lcores_and_rings_api({
            "pid": self.pid,
            "companion_elf": self.elf_path,
            "sample_window_ms": 30,
        })
        self.assertTrue(api_res["success"])
        self.assertGreaterEqual(api_res["data"]["dedicated_pmd_lcores_count"], 2)

        chat_res = api.workspace_chat_api({
            "pid": self.pid,
            "companion_elf": self.elf_path,
            "message": "DPDK 격리 코어(isolcpus)에서 동작하는 dedicated lcore 스레드와 rte_ring 상태를 진단해 주세요",
        })
        self.assertTrue(chat_res["success"], msg=str(chat_res))
        card_types = [c["card_type"] for c in chat_res["data"]["trace_cards"]]
        self.assertIn("DPDK_LCORE_INSPECTOR", card_types)


if __name__ == "__main__":
    unittest.main()
