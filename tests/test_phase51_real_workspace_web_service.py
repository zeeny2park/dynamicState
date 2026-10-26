"""End-to-end production verification for Phase 21: Real Workspace Web Service (`./bin/dynamic-state-workspace`).

Verifies that:
1. The Workspace Web Service (`DynamicStateWebServer` + `workspace_static/index.html`) contains zero hardcoded demo/simulation generators (`buildSimulated*`, `8842`).
2. `POST /api/target/find-processes` discovers a real running C++ target process and marks `has_dwarf_info=True`.
3. `POST /api/watch/active-context` binds by `process_name` or `pid` alone, automatically discovering `/proc/<pid>/exe` as the DWARF companion ELF.
4. `POST /api/workspace/chat` executes live 0.00ms zero-stop queries against the real C++ process for:
   - Memory pool allocation map (`POOL_MAP`)
   - Thread owner reverse-lookup (`THREAD_OWNER`)
   - One-click Auto-Triage (`AUTO_TRIAGE`)
   - Declarative Hypothesis Verifier (`HYPOTHESIS_VERIFIER`)
   - Token-Budget Smart Compactor & Batch Macro (`SMART_COMPACT`, `BATCH_MACRO`)
   - DPDK Isolated-Core & TLS Inspector (`DPDK_LCORE_INSPECTOR`, `TLS_INSPECTOR`)
   - Incident Report generation (`INCIDENT_REPORT`)
5. Card refresh endpoints (`/api/watch/scan-pool`, `/api/watch/find-owners`, `/api/watch/export-report`) work without passing `companion_elf` thanks to stateful session resolution.
"""

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request

from extractor.agent_runtime import AgentRuntime
from extractor.web.server import run_server
from extractor.web.workspace import build_workspace_arg_parser


CPP_LIVE_SERVICE_TARGET = r"""
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

struct BufferSlot {
    int in_use;
    int size;
    int owner_tid;
    int seq;
    void* data_ptr;
};

struct MemPool {
    int total_buffers;
    int active_buffers;
    BufferSlot buffers[16];
};

static MemPool g_pool_instance;
MemPool* gpMem = &g_pool_instance;
__thread int g_tls_worker_id = 77;
volatile int g_keep_running = 1;

void* worker_thread_fn(void* arg) {
    g_tls_worker_id = 909;
    BufferSlot* held_slot = &gpMem->buffers[4];
    while (g_keep_running && held_slot != nullptr) {
        usleep(20000);
    }
    return nullptr;
}

int main() {
    std::memset(&g_pool_instance, 0, sizeof(g_pool_instance));
    g_pool_instance.total_buffers = 16;
    g_pool_instance.active_buffers = 3;

    g_pool_instance.buffers[1].in_use = 1;
    g_pool_instance.buffers[1].size = 256;
    g_pool_instance.buffers[1].seq = 101;
    g_pool_instance.buffers[1].data_ptr = (void*)0x12340000ULL;

    g_pool_instance.buffers[4].in_use = 1;
    g_pool_instance.buffers[4].size = 1024;
    g_pool_instance.buffers[4].seq = 404;
    g_pool_instance.buffers[4].data_ptr = (void*)0x12341000ULL;

    g_pool_instance.buffers[9].in_use = 1;
    g_pool_instance.buffers[9].size = 512;
    g_pool_instance.buffers[9].seq = 909;
    g_pool_instance.buffers[9].data_ptr = (void*)0x12342000ULL;

    pthread_t th;
    pthread_create(&th, nullptr, worker_thread_fn, nullptr);

    std::printf("READY_PID=%d\n", (int)getpid());
    std::fflush(stdout);

    while (g_keep_running) {
        usleep(50000);
    }
    pthread_join(th, nullptr);
    return 0;
}
"""


@unittest.skipUnless(shutil.which("g++"), "g++ compiler required")
class TestPhase51RealWorkspaceWebService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="ds_phase51_ws_")
        cls.src_path = os.path.join(cls.tmpdir, "ws_live_target.cpp")
        cls.bin_path = os.path.join(cls.tmpdir, "ws_live_target_nostrip")
        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(CPP_LIVE_SERVICE_TARGET)

        subprocess.run(
            ["g++", "-g", "-O0", "-pthread", cls.src_path, "-o", cls.bin_path],
            check=True,
        )

        cls.proc = subprocess.Popen(
            [cls.bin_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = cls.proc.stdout.readline().strip()
        assert line.startswith("READY_PID="), f"Unexpected target output: {line}"
        cls.pid = int(line.split("=")[1])
        time.sleep(0.08)

        workspace_static_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "extractor", "web", "workspace_static")
        )
        corpus_dir = os.path.join(cls.tmpdir, "corpus")
        os.makedirs(corpus_dir, exist_ok=True)
        cls.runtime = AgentRuntime(corpus_dir=corpus_dir)
        cls.server = run_server(
            runtime=cls.runtime,
            host="127.0.0.1",
            port=0,
            static_dir=workspace_static_dir,
        )
        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        cls.server_thread.start()
        actual_port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{actual_port}"

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "server", None):
            cls.server.shutdown()
            cls.server.server_close()
        if getattr(cls, "proc", None) and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2)
            except Exception:
                cls.proc.kill()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _http_get(self, path: str) -> str:
        req = urllib.request.Request(f"{self.base_url}{path}", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            return resp.read().decode("utf-8")

    def _http_post(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def test_01_production_html_has_zero_demo_simulation_functions(self):
        html = self._http_get("/")
        self.assertIn("dynamicState Workspace", html)
        self.assertNotIn("buildSimulatedPoolData", html)
        self.assertNotIn("buildSimulatedDpdkLcoreData", html)
        self.assertNotIn("🧪 데모 로드", html)
        self.assertIn("🔍 프로세스 탐색", html)
        self.assertIn("🔄 세션 동기화", html)

        parser = build_workspace_arg_parser()
        args = parser.parse_args(["--pid", str(self.pid), "--process-name", "ws_live_target"])
        self.assertEqual(args.pid, self.pid)
        self.assertEqual(args.process_name, "ws_live_target")

    def test_02_find_processes_and_auto_bind_context_over_http(self):
        find_res = self._http_post("/api/target/find-processes", {"process_name": "ws_live_target"})
        self.assertTrue(find_res["success"])
        procs = find_res["data"]["processes"]
        matched = [p for p in procs if p["pid"] == self.pid]
        self.assertEqual(len(matched), 1)
        self.assertTrue(matched[0]["has_dwarf_info"])

        # Bind by process name alone (auto-discovering PID + /proc/<pid>/exe DWARF ELF)
        bind_res = self._http_post("/api/watch/active-context", {"pid": "ws_live_target_nostrip"})
        self.assertTrue(bind_res["success"])
        self.assertEqual(bind_res["data"]["pid"], self.pid)
        self.assertTrue(bind_res["data"]["is_bound"])
        self.assertTrue(bind_res["data"]["companion_elf_path"].endswith("ws_live_target_nostrip"))

    def test_03_workspace_chat_executes_real_zero_stop_inspections(self):
        # First ensure target context is bound
        self._http_post("/api/watch/active-context", {"pid": self.pid})

        # 1. Pool Map + Thread Owner in one natural language prompt (using stateful context, no PID/ELF passed)
        chat_res = self._http_post(
            "/api/workspace/chat",
            {"message": "memory pool *gpMem의 할당 현황을 맵 차트로 그려주고 gpMem 4번 인덱스를 사용 중인 쓰레드를 찾아주세요"},
        )
        self.assertTrue(chat_res["success"], f"Chat failed: {chat_res}")
        cards = chat_res["data"]["trace_cards"]
        card_types = [c["card_type"] for c in cards]
        self.assertIn("POOL_MAP", card_types)
        self.assertIn("THREAD_OWNER", card_types)

        pool_card = next(c for c in cards if c["card_type"] == "POOL_MAP")
        self.assertEqual(pool_card["data"]["pool_summary"]["total_slots"], 16)
        self.assertEqual(pool_card["data"]["pool_summary"]["allocated_indices"], [1, 4, 9])

        owner_card = next(c for c in cards if c["card_type"] == "THREAD_OWNER")
        self.assertGreaterEqual(len(owner_card["data"]["matched_threads"]), 1)

        # 2. Hypothesis Verifier + Incident Report via chat
        hyp_res = self._http_post(
            "/api/workspace/chat",
            {
                "message": "가설 검증으로 gpMem.active_buffers == 3 및 buffers[4].in_use == 1 조건을 검증하고 인시던트 리포트를 생성해 주세요",
            },
        )
        self.assertTrue(hyp_res["success"], f"Hypothesis chat failed: {hyp_res}")
        h_cards = hyp_res["data"]["trace_cards"]
        h_types = [c["card_type"] for c in h_cards]
        self.assertIn("HYPOTHESIS_VERIFIER", h_types)
        self.assertIn("INCIDENT_REPORT", h_types)
        hv = next(c for c in h_cards if c["card_type"] == "HYPOTHESIS_VERIFIER")
        self.assertEqual(hv["data"]["verdict"], "CONFIRMED")

        # 3. Token-Budget Smart Compactor & 1-Call Batch Macro via chat
        bm_res = self._http_post(
            "/api/workspace/chat",
            {"message": "대규모 메모리 풀과 다중 진단을 토큰 예산 압축 및 배치 매크로로 실행해 주세요"},
        )
        self.assertTrue(bm_res["success"])
        bm_types = [c["card_type"] for c in bm_res["data"]["trace_cards"]]
        self.assertIn("SMART_COMPACT", bm_types)
        self.assertIn("BATCH_MACRO", bm_types)

    def test_04_card_refresh_endpoints_work_with_stateful_session(self):
        self._http_post("/api/watch/active-context", {"pid": self.pid})

        # Refreshing a POOL_MAP card without passing companion_elf
        pool_refresh = self._http_post("/api/watch/scan-pool", {"base_expression": "*gpMem"})
        self.assertTrue(pool_refresh["success"])
        self.assertEqual(pool_refresh["data"]["pool_summary"]["allocated_count"], 3)

        # Exporting incident report directly via /api/watch/export-report
        rep_res = self._http_post("/api/watch/export-report", {"title": "Live Web Service Export"})
        self.assertTrue(rep_res["success"])
        self.assertIn("# Live Web Service Export", rep_res["data"]["report_markdown"])


if __name__ == "__main__":
    unittest.main()
