"""Phase 32 Test Suite: Remote Target Validation, Process Auto-Discovery, Deep Symbol Path Evaluation, and Intent-Driven MCP Tools."""

import base64
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from extractor.agent_runtime import AgentRuntime
from extractor.debug_image import inspect_elf
from extractor.dwarf_indexer import DwarfIndexer
from extractor.target_adapter import LocalTargetAdapter, RemoteSshTargetAdapter
from extractor.watch_session import WatchSessionManager
from extractor.web.server import WebApiAdapter
import scripts.mcp_server as mcp_srv


class TestPhase32RemoteAndMcpImprovements(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_p32_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        os.makedirs(cls.corpus_dir, exist_ok=True)

        cls.fixture_src = os.path.join(PROJECT_ROOT, "tests", "fixtures", "real_runtime", "main.cpp")
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
            ],
            check=True,
        )
        cls.stripped_bin = os.path.join(cls.work_dir, "app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

        cls.mismatched_bin = os.path.join(cls.work_dir, "mismatched.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-DMISMATCH_BUILD=1",
                "-Wl,--build-id=md5", cls.fixture_src, "-o", cls.mismatched_bin, "-lpthread"
            ],
            check=True,
        )

    def setUp(self):
        self._procs = []

    def tearDown(self):
        for p in self._procs:
            try:
                p.kill()
                p.wait(timeout=2)
            except Exception:
                pass
            for s in (p.stdin, p.stdout, p.stderr):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _start_target(self, bin_path: str) -> subprocess.Popen:
        p = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._procs.append(p)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            line = p.stdout.readline()
            if "READY" in line:
                break
        return p

    def test_01_remote_validate_target_and_process_discovery(self):
        """Verify validate_target supports remote_host and process_name without touching local /proc."""
        with open(self.stripped_bin, "rb") as f:
            hdr_b64 = base64.b64encode(f.read(65536)).decode("ascii")

        def mock_ssh_runner(cmd_args, timeout):
            remote_cmd = cmd_args[-1]
            if "for p in /proc/[0-9]*" in remote_cmd:
                return 0, "8842|app_prod|/opt/bin/app_prod.stripped|/opt/bin/app_prod.stripped --daemon\n", ""
            if "kill -0 8842" in remote_cmd:
                return 0, "ALIVE\n", ""
            if "readlink" in remote_cmd and "8842" in remote_cmd:
                return 0, "/opt/bin/app_prod.stripped\n", ""
            if "head -c 65536 /proc/8842/exe" in remote_cmd:
                return 0, hdr_b64 + "\n", ""
            return 0, "", ""

        rt = AgentRuntime(corpus_dir=self.corpus_dir)
        web = WebApiAdapter(rt)

        orig_resolve = web.watch_manager._resolve_adapter
        def custom_resolve(pid, remote_host=None, ssh_user=None, ssh_port=22, ssh_key=None, ssh_proxy_jump=None, ssh_proxy_command=None, adapter=None):
            if remote_host:
                return RemoteSshTargetAdapter(
                    host=remote_host,
                    user=ssh_user,
                    port=ssh_port,
                    key_file=ssh_key,
                    proxy_jump=ssh_proxy_jump,
                    command_runner=mock_ssh_runner,
                    use_control_master=True,
                )
            return orig_resolve(pid, remote_host, ssh_user, ssh_port, ssh_key, ssh_proxy_jump, ssh_proxy_command, adapter)

        with patch.object(web.watch_manager, "_resolve_adapter", side_effect=custom_resolve):
            res = web.validate_target({
                "process_name": "app_prod",
                "remote_host": "192.168.10.55",
                "ssh_user": "root",
                "debug_image": self.debug_bin,
                "locale": "ko",
            })
            self.assertTrue(res["success"])
            data = res["data"]
            self.assertTrue(data["valid"], f"Expected valid remote target, got: {data}")
            self.assertEqual(data["pid"], 8842)
            self.assertTrue(data["is_remote"])
            self.assertEqual(data["target_host"], "root@192.168.10.55")
            self.assertEqual(data["backend"], "remote_proc_mem")
            self.assertGreater(len(data.get("recommended_symbols", [])), 0)

            res_mismatch = web.validate_target({
                "pid": 8842,
                "remote_host": "192.168.10.55",
                "ssh_user": "root",
                "debug_image": self.mismatched_bin,
                "locale": "ko",
            })
            self.assertTrue(res_mismatch["success"])
            self.assertFalse(res_mismatch["data"]["valid"])
            self.assertEqual(res_mismatch["data"]["reason"], "BUILD_ID_MISMATCH")

    def test_02_deep_symbol_path_evaluator_and_pointer_chaining(self):
        """Verify evaluate_symbol_paths decodes structs, nested fields, heap pointers, and linked nodes."""
        proc = self._start_target(self.stripped_bin)
        mgr = WatchSessionManager(corpus_dir=self.corpus_dir)

        res = mgr.evaluate_symbol_paths(
            pid=proc.pid,
            companion_elf_path=self.debug_bin,
            expressions=[
                "g_session",
                "g_session.worker.state.counter",
                "g_heap_state->counter",
                "g_node_a.next->value",
                "g_session.worker.shared->next->value",
                "g_nonexistent_symbol",
            ],
        )
        self.assertEqual(res["pid"], proc.pid)
        self.assertEqual(res["stop_duration_ms"], 0.0)
        by_expr = {r["expression"]: r for r in res["results"]}

        self.assertEqual(by_expr["g_session"]["status"], "OBSERVED")
        self.assertIsInstance(by_expr["g_session"]["value"], dict)
        self.assertEqual(by_expr["g_session"]["value"]["worker"]["state"]["counter"], 42)
        self.assertEqual(by_expr["g_session"]["value"]["worker"]["state"]["flags"], 7)

        self.assertEqual(by_expr["g_session.worker.state.counter"]["status"], "OBSERVED")
        self.assertEqual(by_expr["g_session.worker.state.counter"]["value"], 42)

        self.assertEqual(by_expr["g_heap_state->counter"]["status"], "OBSERVED")
        self.assertEqual(by_expr["g_heap_state->counter"]["value"], 99)
        self.assertGreaterEqual(len(by_expr["g_heap_state->counter"]["pointer_chain"]), 3)

        self.assertEqual(by_expr["g_node_a.next->value"]["status"], "OBSERVED")
        self.assertEqual(by_expr["g_node_a.next->value"]["value"], 222)
        self.assertEqual(by_expr["g_session.worker.shared->next->value"]["status"], "OBSERVED")
        self.assertEqual(by_expr["g_session.worker.shared->next->value"]["value"], 222)

        self.assertEqual(by_expr["g_nonexistent_symbol"]["status"], "SYMBOL_NOT_FOUND")

    def test_03_capture_and_diff_expressions_and_mcp_tools(self):
        """Verify capture_and_diff_expressions and new high-level MCP tools against live C++ target."""
        proc = self._start_target(self.stripped_bin)
        old_runtime = mcp_srv.runtime
        mcp_srv.runtime = AgentRuntime(corpus_dir=self.corpus_dir)
        try:
            conn_raw = mcp_srv.runtime_target_connect(
                companion_elf=self.debug_bin,
                process_name="app_prod",
            )
            conn = json.loads(conn_raw)
            self.assertTrue(conn["success"], f"Connect failed: {conn}")
            self.assertEqual(conn["pid"], proc.pid)
            self.assertGreater(len(conn["recommended_symbols"]), 0)

            search_raw = mcp_srv.runtime_symbol_search(
                companion_elf=self.debug_bin,
                query="session",
                pid=proc.pid,
            )
            search_res = json.loads(search_raw)
            self.assertTrue(search_res["success"])
            names = [s["name"] for s in search_res["symbols"]]
            self.assertIn("g_session", names)

            eval_raw = mcp_srv.runtime_eval_memory_path(
                pid=proc.pid,
                companion_elf=self.debug_bin,
                expressions=["g_session.worker.state.counter", "g_heap_state->counter", "g_session.worker.shared->value"],
            )
            eval_res = json.loads(eval_raw)
            self.assertTrue(eval_res["success"])
            vals = {r["expression"]: r["value"] for r in eval_res["results"]}
            self.assertEqual(vals["g_session.worker.state.counter"], 42)
            self.assertEqual(vals["g_heap_state->counter"], 99)
            self.assertEqual(vals["g_session.worker.shared->value"], 111)

            def _delayed_mutate():
                time.sleep(0.12)
                try:
                    proc.stdin.write("MUTATE\n")
                    proc.stdin.flush()
                except Exception:
                    pass

            t = threading.Thread(target=_delayed_mutate, daemon=True)
            t.start()

            diff_raw = mcp_srv.runtime_capture_and_diff(
                pid=proc.pid,
                companion_elf=self.debug_bin,
                expressions=["g_session.worker.state", "g_session.worker.shared->value", "g_heap_state->counter"],
                wait_ms=300,
            )
            t.join(timeout=1.0)
            diff_res = json.loads(diff_raw)
            self.assertTrue(diff_res["success"])
            changed_paths = {c["path"]: (c["before"], c["after"]) for c in diff_res["changed"]}
            self.assertEqual(changed_paths.get("g_session.worker.state.counter"), (42, 100))
            self.assertEqual(changed_paths.get("g_session.worker.state.flags"), (7, 15))
            self.assertEqual(changed_paths.get("g_session.worker.shared->value"), (111, 999))
            unchanged_paths = {u["path"]: u["value"] for u in diff_res["unchanged"]}
            self.assertEqual(unchanged_paths.get("g_heap_state->counter"), 99)
        finally:
            mcp_srv.runtime = old_runtime

    def test_04_web_ui_html_and_api_routes(self):
        """Verify index.html exposes remote SSH / process discovery inputs and symbol path evaluator."""
        html_path = os.path.join(PROJECT_ROOT, "extractor", "web", "static", "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        for required_id in (
            "te-remote-host",
            "te-remote-user",
            "te-remote-port",
            "te-remote-jump",
            "te-process-name",
            "btn-find-target-pid",
            "te-eval-expr-input",
            "btn-te-eval-expr",
            "btn-te-diff-expr",
        ):
            self.assertIn(f'id="{required_id}"', html, f"Missing UI element #{required_id} in index.html")


if __name__ == "__main__":
    unittest.main()
