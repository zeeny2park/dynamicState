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
from tests.support.fixture_process import fixture_popen


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
        cls.target_proc = fixture_popen(
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

    def _http_post_raw(self, path: str, raw_body: bytes, headers: dict = None, include_token: bool = True) -> tuple:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = {"Content-Type": "application/json"}
        if include_token:
            hdrs["X-Session-Token"] = self.server.session_token
        if headers:
            hdrs.update(headers)
        conn.request("POST", path, body=raw_body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, (json.loads(data) if data else {}), resp_headers

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
        self.assertNotEqual(bm.get("success"), False)  # batch macro reports its own batch-level success (all steps ok)
        self.assertEqual(bm["steps_failed"], 0)
        self.assertTrue(all(s["success"] for s in bm["step_results"]))
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
        st, body, _ = self._http_post_raw("/api/workspace/chat", b"{not valid json")
        self.assertEqual(st, 400)
        self.assertFalse(body["success"])
        self.assertEqual(body["error"]["code"], "BAD_REQUEST")

        # 2. Non-object JSON payload (e.g. JSON array or string)
        for non_obj in (b"[1, 2, 3]", b'"just_a_string"', b"12345"):
            st, body, _ = self._http_post_raw("/api/workspace/chat", non_obj)
            self.assertEqual(st, 400)
            self.assertFalse(body["success"])
            self.assertEqual(body["error"]["code"], "BAD_REQUEST")

        # 3. Reserved/negative PIDs rejected cleanly
        for bad_pid in (1, -1936537, True):
            st, body, _ = self._http_post_raw(
                "/api/watch/scan-pool",
                json.dumps({"pid": bad_pid, "companion_elf": self.bin_path, "base_expression": "*gpMem"}).encode("utf-8"),
            )
            self.assertFalse(body["success"])

        # 4. Non-numeric parameter strings coerced safely to defaults without ValueError
        st, body, _ = self._http_post_raw(
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
        st, body, _ = self._http_post_raw(
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
        st2, body2, _ = self._http_post_raw(
            "/api/watch/callstack-locks",
            json.dumps({"pid": self.target_proc.pid, "companion_elf": self.bin_path}).encode("utf-8"),
        )
        self.assertEqual(st2, 200)
        self.assertTrue(body2["success"])

        # Verify /workspace HTML includes AbortController and _refreshInFlight guards
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/legacy/workspace")
        resp = conn.getresponse()
        html_text = resp.read().decode("utf-8")
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn("new AbortController()", html_text)
        self.assertIn("_refreshInFlight", html_text)


    def test_05_imp019_default_runtime_is_low_impact_and_rejects_mutations(self) -> None:
        """IMP-019: Runtime started without options defaults to LOW_IMPACT and rejects all mutation/checkpoint actions."""
        default_rt = AgentRuntime(corpus_dir=self.corpus_dir)
        self.assertEqual(default_rt.observation_mode, "LOW_IMPACT")
        self.assertFalse(default_rt.allow_mutation)

        for mut_act in (
            {"action": "LIST_MUTATION_CANDIDATES"},
            {"action": "CHECKPOINT"},
            {"action": "RESTORE", "checkpoint_id": "cp_1"},
            {"action": "EXECUTE_TRANSITION", "candidate_id": "cand_1"},
            {"action": "EXPLORE"},
        ):
            res = default_rt.dispatch_action(mut_act)
            self.assertFalse(res.success, f"Expected {mut_act['action']} to be rejected in default LOW_IMPACT mode")
            self.assertEqual(res.error.code, "CAPABILITY_UNSUPPORTED")

        rep_res = default_rt.replay_mutation("snap_1", "obj_1", "field_a", 42)
        self.assertFalse(rep_res.success)
        self.assertEqual(rep_res.error.code, "CAPABILITY_UNSUPPORTED")

    def test_06_imp019_web_api_requires_session_token_and_rejects_unauthenticated(self) -> None:
        """IMP-019: API requests without a valid session token receive 401/403."""
        # 1. Unauthenticated GET /api/health -> 401
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/api/health")
        resp = conn.getresponse()
        body = json.loads(resp.read().decode("utf-8"))
        conn.close()
        self.assertIn(resp.status, (401, 403))
        self.assertFalse(body["success"])

        # 2. Wrong token on POST /api/workspace/chat -> 401
        st_bad, body_bad, _ = self._http_post_raw(
            "/api/workspace/chat",
            b"{}",
            headers={"X-Session-Token": "wrong_forged_token"},
            include_token=False,
        )
        self.assertIn(st_bad, (401, 403))
        self.assertFalse(body_bad["success"])

        # 3. Valid token via X-Session-Token -> 200
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/api/health", headers={"X-Session-Token": self.server.session_token})
        resp_ok = conn.getresponse()
        body_ok = json.loads(resp_ok.read().decode("utf-8"))
        conn.close()
        self.assertEqual(resp_ok.status, 200)
        self.assertEqual(body_ok["status"], "ok")

    def test_07_imp019_cors_origin_host_and_post_content_type_guards(self) -> None:
        """IMP-019: Cross-origin requests never receive wildcard CORS, bad Host is rejected, and POST requires JSON Content-Type."""
        # 1. Cross-origin request must be rejected (403) and must NOT have Access-Control-Allow-Origin: *
        st_orig, body_orig, hdrs_orig = self._http_post_raw(
            "/api/workspace/chat",
            b"{}",
            headers={"Origin": "https://evil.example.com"},
        )
        self.assertEqual(st_orig, 403)
        self.assertFalse(body_orig["success"])
        self.assertNotIn("access-control-allow-origin", hdrs_orig)

        # 2. OPTIONS preflight from external origin must NOT return wildcard CORS
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("OPTIONS", "/api/workspace/chat", headers={"Origin": "https://evil.example.com"})
        resp_opt = conn.getresponse()
        resp_opt.read()
        opt_hdrs = {k.lower(): v for k, v in resp_opt.getheaders()}
        conn.close()
        self.assertEqual(resp_opt.status, 403)
        self.assertNotIn("access-control-allow-origin", opt_hdrs)

        # 3. Untrusted Host header (DNS rebinding defense) -> 403
        st_host, body_host, _ = self._http_post_raw(
            "/api/workspace/chat",
            b"{}",
            headers={"Host": "rebind.attacker.com"},
        )
        self.assertEqual(st_host, 403)
        self.assertFalse(body_host["success"])

        # 4. POST without application/json Content-Type -> 415
        st_ct, body_ct, _ = self._http_post_raw(
            "/api/workspace/chat",
            b"pid=1234",
            headers={"Content-Type": "text/plain"},
        )
        self.assertIn(st_ct, (400, 415))
        self.assertFalse(body_ct["success"])

    def test_08_imp019_ui_receives_token_and_authorize_target_is_not_auto_enabled(self) -> None:
        """IMP-019: Existing UI receives session token via HTML/Cookie and works, and authorize_target is not auto-enabled by PID."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/legacy/workspace")
        resp = conn.getresponse()
        html_text = resp.read().decode("utf-8")
        set_cookie = resp.getheader("Set-Cookie") or ""
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn(self.server.session_token, html_text)
        self.assertIn(f"dynamicstate_session={self.server.session_token}", set_cookie)

        # Using the Cookie received by the UI works for API requests
        conn2 = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn2.request("GET", "/api/health", headers={"Cookie": f"dynamicstate_session={self.server.session_token}"})
        resp2 = conn2.getresponse()
        body2 = json.loads(resp2.read().decode("utf-8"))
        conn2.close()
        self.assertEqual(resp2.status, 200)
        self.assertEqual(body2["status"], "ok")

        # Providing pid without authorize_target=True must NOT auto-authorize live target capture
        st_inv, body_inv, _ = self._http_post_raw(
            "/api/investigation/start",
            json.dumps({"goal": "Test unauth PID", "pid": self.target_proc.pid}).encode("utf-8"),
        )
        self.assertEqual(st_inv, 200)
        self.assertEqual(body_inv["data"]["status"], "BLOCKED")
        self.assertFalse(body_inv["data"]["safety"]["target_authorized"])


if __name__ == "__main__":
    unittest.main()
