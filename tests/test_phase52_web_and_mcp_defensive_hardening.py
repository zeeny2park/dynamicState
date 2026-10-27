"""Phase 52 (Phase 22): Web Service & MCP Server Comprehensive Defensive Hardening Tests.

Verifies that:
1. All MCP tools (`scripts/mcp_server.py`) catch every exception, reject reserved/invalid PIDs
   (`pid=1`, `pid=0`, `pid=-1936537`, `pid=True`), coerce string/list/JSON parameters gracefully,
   and guard against writing reports to protected system paths (`/etc`, `/proc`, etc.).
2. All Web Service endpoints (`extractor/web/server.py`) safely handle malformed JSON, non-object
   JSON payloads (`[...]`, `"str"`), invalid numeric strings (`ssh_port="abc"`, `wait_ms="xyz"`),
   reserved/negative PIDs, and per-card partial failures in `/api/workspace/chat`.
3. The Workspace Web UI (`extractor/web/workspace_static/index.html`) includes `AbortController`
   request timeouts, non-JSON error handling, and live-polling re-entrancy/circuit-breaker guards.
"""

import http.client
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.web.server import run_server
import scripts.mcp_server as mcp_srv


TARGET_C_SRC = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int in_use;
    int owner_tid;
    uint32_t seq;
    uint32_t size;
} BufferSlot;

typedef struct {
    uint32_t magic;
    int active_buffers;
    int total_buffers;
    BufferSlot buffers[8];
} MemoryPool;

static MemoryPool g_pool_storage;
MemoryPool *gpMem = &g_pool_storage;

int main(void) {
    memset(&g_pool_storage, 0, sizeof(g_pool_storage));
    g_pool_storage.magic = 0xCAFEBABE;
    g_pool_storage.total_buffers = 8;
    g_pool_storage.active_buffers = 2;
    g_pool_storage.buffers[0].in_use = 1;
    g_pool_storage.buffers[0].owner_tid = (int)getpid();
    g_pool_storage.buffers[0].seq = 101;
    g_pool_storage.buffers[0].size = 256;
    g_pool_storage.buffers[3].in_use = 1;
    g_pool_storage.buffers[3].owner_tid = (int)getpid();
    g_pool_storage.buffers[3].seq = 303;
    g_pool_storage.buffers[3].size = 512;

    while (1) {
        usleep(50000);
    }
    return 0;
}
"""


class TestPhase52WebAndMcpDefensiveHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.TemporaryDirectory(prefix="dynstate_p52_")
        cls.src_path = os.path.join(cls.tmp_dir.name, "defensive_target.c")
        cls.bin_path = os.path.join(cls.tmp_dir.name, "defensive_target")
        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(TARGET_C_SRC)

        subprocess.run(
            ["gcc", "-g", "-O0", cls.src_path, "-o", cls.bin_path],
            check=True,
        )
        cls.target_proc = subprocess.Popen(
            [cls.bin_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.15)

        cls.corpus_dir = os.path.join(cls.tmp_dir.name, "corpus")
        cls.runtime = AgentRuntime(corpus_dir=cls.corpus_dir)
        cls.server = run_server(cls.runtime, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.server.shutdown()
            cls.server.server_close()
        except Exception:
            pass
        if cls.target_proc and cls.target_proc.poll() is None:
            cls.target_proc.terminate()
            try:
                cls.target_proc.wait(timeout=2)
            except Exception:
                cls.target_proc.kill()
        cls.tmp_dir.cleanup()

    def _http_post_raw(self, path: str, raw_body: bytes, headers: dict = None) -> tuple:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        conn.request("POST", path, body=raw_body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()
        return resp.status, json.loads(data)

    def test_01_mcp_rejects_reserved_and_invalid_pids_gracefully(self) -> None:
        """Verifies MCP tools never throw unhandled exceptions on pid=1, pid=0, negative PIDs, or booleans."""
        for bad_pid in (1, 0, -1, -1936537, True, False, "1", "-500", "invalid_pid"):
            for fn in (
                mcp_srv.runtime_capture_memory,
                mcp_srv.runtime_observe,
                mcp_srv.runtime_watch_session_create,
                mcp_srv.runtime_watch_inspect_target,
            ):
                raw_out = fn(pid=bad_pid)  # type: ignore[arg-type]
                parsed = json.loads(raw_out)
                self.assertFalse(parsed.get("success", True), f"Expected failure for {fn.__name__}(pid={bad_pid!r})")
                self.assertIn("error", parsed)

        # Also test runtime_target_connect and runtime_eval_memory_path with pid=1 and pid=-1936537
        for bad_pid in (1, -1936537, True):
            res_conn = json.loads(mcp_srv.runtime_target_connect(pid=bad_pid, companion_elf=self.bin_path))  # type: ignore[arg-type]
            self.assertFalse(res_conn["success"])
            res_eval = json.loads(mcp_srv.runtime_eval_memory_path(pid=bad_pid, companion_elf=self.bin_path, expressions=["*gpMem"]))  # type: ignore[arg-type]
            self.assertFalse(res_eval["success"])

    def test_02_mcp_coerces_strings_and_guards_system_output_paths(self) -> None:
        """Verifies MCP tools accept string expressions, JSON string batch steps, and block /etc output paths."""
        conn = json.loads(mcp_srv.runtime_target_connect(pid=self.target_proc.pid, companion_elf=self.bin_path))
        self.assertTrue(conn["success"])

        # Pass comma-separated string instead of List[str] to runtime_eval_memory_path
        ev = json.loads(mcp_srv.runtime_eval_memory_path(expressions="gpMem.active_buffers, gpMem.buffers[0].seq"))  # type: ignore[arg-type]
        self.assertTrue(ev["success"])
        self.assertEqual(len(ev["results"]), 2)
        self.assertEqual(ev["results"][0]["value"], 2)
        self.assertEqual(ev["results"][1]["value"], 101)

        # Pass JSON string instead of List[Dict] to runtime_batch_execute
        batch_json_str = json.dumps([
            {"action": "scan_pool", "expression": "*gpMem"},
            {"action": "eval", "expressions": "gpMem.active_buffers"},
        ])
        bm = json.loads(mcp_srv.runtime_batch_execute(steps=batch_json_str))  # type: ignore[arg-type]
        self.assertTrue(bm["success"])
        self.assertEqual(bm["steps_succeeded"], 2)

        # Pass comma-separated string to runtime_verify_hypothesis
        hyp = json.loads(
            mcp_srv.runtime_verify_hypothesis(
                hypothesis="Active buffers is 2 and slot 0 is in use",
                assertions="gpMem.active_buffers == 2, gpMem.buffers[0].in_use == 1",  # type: ignore[arg-type]
            )
        )
        self.assertTrue(hyp["success"])
        self.assertEqual(hyp["verdict"], "CONFIRMED")

        # Attempt to write incident report to protected /etc path
        rep = json.loads(
            mcp_srv.runtime_export_incident_report(
                title="Protected Path Test",
                output_path="/etc/dynamicstate_forbidden_test.md",
            )
        )
        self.assertTrue(rep["success"])
        self.assertIsNone(rep["saved_path"])
        self.assertIn("protected system path", rep.get("save_error") or "")
        self.assertIn("# Protected Path Test", rep["report_markdown"])

    def test_03_web_api_handles_malformed_json_and_adversarial_params(self) -> None:
        """Verifies Web API returns structured JSON errors on invalid JSON, non-dict bodies, and bad parameters."""
        # 1. Malformed JSON syntax
        st, body = self._http_post_raw("/api/workspace/chat", b"{not valid json")
        self.assertEqual(st, 400)
        self.assertFalse(body["success"])
        self.assertEqual(body["error"]["code"], "BAD_REQUEST")

        # 2. Non-object JSON payload (e.g. JSON array or string)
        for non_obj in (b"[1, 2, 3]", b'"just_a_string"', b"12345"):
            st, body = self._http_post_raw("/api/workspace/chat", non_obj)
            self.assertEqual(st, 400)
            self.assertFalse(body["success"])
            self.assertEqual(body["error"]["code"], "BAD_REQUEST")

        # 3. Reserved/negative PIDs rejected cleanly
        for bad_pid in (1, -1936537, True):
            st, body = self._http_post_raw(
                "/api/watch/scan-pool",
                json.dumps({"pid": bad_pid, "companion_elf": self.bin_path, "base_expression": "*gpMem"}).encode("utf-8"),
            )
            self.assertFalse(body["success"])

        # 4. Non-numeric parameter strings coerced safely to defaults without ValueError
        st, body = self._http_post_raw(
            "/api/watch/smart-compact",
            json.dumps({
                "pid": self.target_proc.pid,
                "companion_elf": self.bin_path,
                "query": "*gpMem",
                "max_tokens": "not_an_int",
                "cursor_offset": "invalid_offset",
                "page_size": "-999",
                "ssh_port": "invalid_port",
            }).encode("utf-8"),
        )
        self.assertEqual(st, 200)
        self.assertTrue(body["success"])
        self.assertEqual(body["data"]["pid"], self.target_proc.pid)

    def test_04_workspace_chat_isolates_per_card_errors_and_serves_hardened_ui(self) -> None:
        """Verifies /api/workspace/chat isolates per-card failures and /workspace serves hardened JS."""
        st, body = self._http_post_raw(
            "/api/workspace/chat",
            json.dumps({
                "pid": self.target_proc.pid,
                "companion_elf": self.bin_path,
                "message": "존재하지 않는 *gpNonExistentPool 메모리 풀 맵과 콜스택을 함께 보여주세요",
            }).encode("utf-8"),
        )
        self.assertEqual(st, 200)
        self.assertTrue(body["success"])
        cards = body["data"]["trace_cards"]
        self.assertGreaterEqual(len(cards), 1)

        # Verify /api/watch/callstack-locks alias works
        st2, body2 = self._http_post_raw(
            "/api/watch/callstack-locks",
            json.dumps({"pid": self.target_proc.pid, "companion_elf": self.bin_path}).encode("utf-8"),
        )
        self.assertEqual(st2, 200)
        self.assertTrue(body2["success"])

        # Verify /workspace HTML includes AbortController and _refreshInFlight guards
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/workspace")
        resp = conn.getresponse()
        html_text = resp.read().decode("utf-8")
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn("new AbortController()", html_text)
        self.assertIn("_refreshInFlight", html_text)


if __name__ == "__main__":
    unittest.main()
