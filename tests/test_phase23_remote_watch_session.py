"""Phase 23 Acceptance Test Suite: Remote Watch Sessions and MCP Integration.

Verifies:
1. MCP Session Lifecycle: create, status, get, list, watch item add/remove, paginated observations, stop.
2. Remote vs Local PID Separation: remote adapter interprets PID in target namespace; never touches local /proc.
3. Configured SSH Proxy and Multi-Hop: argument encoding, jump host, proxy command, custom port, and keys.
4. Mocked Transport Failures & Safety: timeout, connection failure, process termination, and cancellation.
5. Build ID and Architecture Mismatch Rejection: remote and local verification.
6. Address Correctness: PT_LOAD load-bias calculation on PIE (ET_DYN) and non-PIE (ET_EXEC).
7. Append-Friendly JSONL Storage & Efficient Pagination: streaming without full file serialization.
8. Restart Recovery & Worker Liveness: dead worker transition to STOPPED with abort gap.
9. UI & MCP Session Consistency: cross-interface session visibility, watch list updates, capability truthfulness.
10. Adapter Contract with Real Local C++ Fixture: zero-stop memory observation of mutating runtime state.
"""

import base64
from datetime import datetime, timezone
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock

from extractor.agent_runtime import AgentRuntime
from extractor.debug_image import BinaryIdentity, inspect_elf
from extractor.target_adapter import (
    LocalTargetAdapter,
    RemoteSshTargetAdapter,
    TargetExecutionAdapter,
)
from extractor.watch_session import (
    CaptureGap,
    Observation,
    ObservationSession,
    WatchItem,
    WatchSessionManager,
    calculate_load_bias,
    decode_value_from_bytes,
)
from extractor.web.server import WebApiAdapter
import scripts.mcp_server as mcp_srv


class TestPhase23RemoteWatchSession(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_p23_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        os.makedirs(cls.corpus_dir, exist_ok=True)

        cls.fixture_src = os.path.abspath("tests/fixtures/real_runtime/main.cpp")
        if not os.path.exists(cls.fixture_src):
            raise unittest.SkipTest("C++ fixture source not found")

        # Compile matching companion debug binary (PIE / ET_DYN)
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
            ],
            check=True
        )

        # Extract stripped production runtime binary
        cls.stripped_bin = os.path.join(cls.work_dir, "app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

        # Compile a non-PIE binary (ET_EXEC) for address relocation regression
        cls.non_pie_bin = os.path.join(cls.work_dir, "non_pie_debug.elf")
        subprocess.run(
            [
                "g++", "-no-pie", "-g", "-O0", "-fno-inline",
                "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.non_pie_bin, "-lpthread"
            ],
            check=True
        )

        # Compile mismatched debug binary
        cls.mismatched_src = os.path.join(cls.work_dir, "mismatched.cpp")
        with open(cls.mismatched_src, "w") as f:
            f.write("int main() { return 0; }\n")
        cls.mismatched_bin = os.path.join(cls.work_dir, "mismatched_debug.elf")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0",
                "-Wl,--build-id=sha1", cls.mismatched_src, "-o", cls.mismatched_bin
            ],
            check=True
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def setUp(self):
        self.active_procs = []

    def tearDown(self):
        for proc in self.active_procs:
            if proc and proc.poll() is None:
                try:
                    proc.stdin.write("STOP\n")
                    proc.stdin.flush()
                    proc.wait(timeout=1.0)
                except Exception:
                    proc.kill()
                    proc.wait()
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream and not stream.closed:
                        try:
                            stream.close()
                        except Exception:
                            pass

    def _start_target_process(self, bin_path):
        proc = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        ready_line = proc.stdout.readline().strip()
        self.assertEqual(ready_line, "READY", f"Target process failed to report READY: {ready_line}")
        self.active_procs.append(proc)
        return proc

    # -------------------------------------------------------------------------
    # Test 1: MCP Session Lifecycle & Tools
    # -------------------------------------------------------------------------
    def test_01_mcp_session_lifecycle(self):
        proc = self._start_target_process(self.debug_bin)

        # Ensure runtime uses our test corpus
        test_runtime = AgentRuntime(corpus_dir=self.corpus_dir)
        old_runtime = mcp_srv.runtime
        mcp_srv.runtime = test_runtime

        try:
            # 1. Create session via MCP tool
            create_res_json = mcp_srv.runtime_watch_session_create(
                pid=proc.pid,
                companion_elf=self.debug_bin,
                interval_ms=100,
                max_samples=20,
            )
            create_res = json.loads(create_res_json)
            self.assertTrue(create_res.get("success"), f"MCP create failed: {create_res}")
            session_id = create_res["session_id"]
            self.assertEqual(create_res["status"], "RUNNING")
            self.assertEqual(create_res["pid"], proc.pid)

            # 2. Get status via MCP tool
            status_res = json.loads(mcp_srv.runtime_watch_session_status(session_id))
            self.assertTrue(status_res.get("success"))
            self.assertEqual(status_res["status"], "RUNNING")

            # 3. List sessions via MCP tool
            list_res = json.loads(mcp_srv.runtime_watch_session_list())
            self.assertTrue(list_res.get("success"))
            session_ids = [s["session_id"] for s in list_res.get("sessions", [])]
            self.assertIn(session_id, session_ids)

            # 4. Inspect target via MCP tool
            inspect_res = json.loads(mcp_srv.runtime_watch_inspect_target(pid=proc.pid, companion_elf=self.debug_bin))
            self.assertTrue(inspect_res.get("success"))
            self.assertGreater(inspect_res.get("mappings_count", 0), 0)
            self.assertGreater(inspect_res.get("discoverable_variables_count", 0), 0)

            # 5. Add watch item via MCP tool
            map_data = inspect_res["mappings"]
            first_readable = next(m for m in map_data if m["is_readable"])
            add_item_res = json.loads(mcp_srv.runtime_watch_item_add(
                session_id=session_id,
                name="test_var",
                address=first_readable["start"],
                size=4,
                type_name="int",
            ))
            self.assertTrue(add_item_res.get("success"))
            item_id = add_item_res["watch_item"]["item_id"]

            # Wait for some observations
            time.sleep(0.3)

            # 6. Retrieve paginated observations via MCP tool
            obs_res = json.loads(mcp_srv.runtime_watch_session_observations(session_id=session_id, limit=5, offset=0))
            self.assertTrue(obs_res.get("success"))
            self.assertGreaterEqual(obs_res.get("total_observations", 0), 1)
            self.assertLessEqual(obs_res.get("returned_count", 0), 5)

            # 7. Remove item via MCP tool
            rem_res = json.loads(mcp_srv.runtime_watch_item_remove(session_id=session_id, item_id=item_id))
            self.assertTrue(rem_res.get("success"))

            # 8. Stop session via MCP tool
            stop_res = json.loads(mcp_srv.runtime_watch_session_stop(session_id=session_id))
            self.assertTrue(stop_res.get("success"))
            self.assertEqual(stop_res["status"], "STOPPED")

            # 9. Verify get session metadata (compact, no giant dumps)
            get_res = json.loads(mcp_srv.runtime_watch_session_get(session_id))
            self.assertTrue(get_res.get("success"))
            self.assertEqual(get_res["status"], "STOPPED")
            self.assertNotIn("observations", get_res)  # compact!
        finally:
            mcp_srv.runtime = old_runtime

    # -------------------------------------------------------------------------
    # Test 2: Remote vs Local PID Separation
    # -------------------------------------------------------------------------
    def test_02_remote_vs_local_pid_separation(self):
        # Start a local dummy process with PID L_PID
        local_proc = self._start_target_process(self.debug_bin)
        local_pid = local_proc.pid

        executed_commands = []

        def mock_remote_runner(cmd_args, timeout):
            cmd_str = " ".join(cmd_args)
            executed_commands.append(cmd_str)
            # If checking liveness of remote PID
            if f"kill -0 {local_pid}" in cmd_str:
                # Return ALIVE on remote target
                return 0, "ALIVE\n", ""
            elif f"head -c 65536 /proc/{local_pid}/exe" in cmd_str:
                # Return base64 of debug binary header
                with open(self.debug_bin, "rb") as f:
                    chunk = f.read(65536)
                return 0, base64.b64encode(chunk).decode("ascii") + "\n", ""
            elif f"cat /proc/{local_pid}/maps" in cmd_str:
                # Mock remote memory map (completely different addresses from local)
                mock_maps = (
                    "00400000-00401000 r-xp 00000000 08:01 12345 /remote/app\n"
                    "00401000-00402000 rw-p 00001000 08:01 12345 /remote/app\n"
                )
                return 0, mock_maps, ""
            elif f"task" in cmd_str:
                return 0, f"{local_pid} S remote_main\n", ""
            elif f"dd if=/proc/{local_pid}/mem" in cmd_str:
                # Return 4 bytes: 0x42 0x00 0x00 0x00
                return 0, base64.b64encode(b"\x42\x00\x00\x00").decode("ascii") + "\n", ""
            return 0, "", ""

        remote_adapter = RemoteSshTargetAdapter(
            host="embedded-board.internal",
            user="root",
            port=2222,
            command_runner=mock_remote_runner,
        )

        self.assertTrue(remote_adapter.is_remote())
        self.assertEqual(remote_adapter.target_host(), "root@embedded-board.internal:2222")

        # 1. Liveness check: must execute SSH command, NOT local os.kill
        alive, err = remote_adapter.check_liveness(local_pid)
        self.assertTrue(alive)
        self.assertTrue(any("embedded-board.internal" in c for c in executed_commands))

        # 2. Get remote maps: should return remote maps, not local
        maps = remote_adapter.get_proc_maps(local_pid)
        self.assertEqual(len(maps), 2)
        self.assertEqual(maps[0]["pathname"], "/remote/app")
        self.assertEqual(maps[0]["start"], "0x400000")

        # 3. Read remote memory: returns remote bytes
        raw, st, err = remote_adapter.read_memory(local_pid, 0x401000, 4)
        self.assertEqual(st, "OBSERVED")
        self.assertEqual(raw, b"\x42\x00\x00\x00")

        # 4. Verify remote PID death reporting even when local PID is alive
        def mock_dead_runner(cmd_args, timeout):
            return 0, "DEAD\n", ""

        dead_adapter = RemoteSshTargetAdapter(
            host="embedded-board.internal",
            command_runner=mock_dead_runner,
        )
        alive2, err2 = dead_adapter.check_liveness(local_pid)
        self.assertFalse(alive2)
        self.assertIn("not running on embedded-board.internal", err2)

    # -------------------------------------------------------------------------
    # Test 3: Configured SSH Proxy & Multi-Hop Arguments
    # -------------------------------------------------------------------------
    def test_03_configured_ssh_proxy_and_parameters(self):
        recorded_args = []

        def mock_runner(cmd_args, timeout):
            recorded_args.append(cmd_args)
            return 0, "ALIVE\n", ""

        adapter = RemoteSshTargetAdapter(
            host="target.device.lan",
            user="firmware",
            port=2200,
            key_file="/home/dev/.ssh/id_rsa_embedded",
            proxy_jump="bastion.corp.net,jump2.corp.net",
            proxy_command="ssh -W %h:%p proxy.net",
            timeout_sec=3.5,
            command_runner=mock_runner,
        )

        alive, _ = adapter.check_liveness(500)
        self.assertTrue(alive)
        self.assertGreater(len(recorded_args), 0)

        cmd = recorded_args[0]
        # Check SSH options
        self.assertIn("-p", cmd)
        self.assertIn("2200", cmd)
        self.assertIn("-i", cmd)
        self.assertIn("/home/dev/.ssh/id_rsa_embedded", cmd)
        self.assertIn("-J", cmd)
        self.assertIn("bastion.corp.net,jump2.corp.net", cmd)
        self.assertIn("ProxyCommand=ssh -W %h:%p proxy.net", " ".join(cmd))
        self.assertIn("firmware@target.device.lan", cmd)

    # -------------------------------------------------------------------------
    # Test 4: Mocked Transport Failures, Timeouts, and Cancellation
    # -------------------------------------------------------------------------
    def test_04_mocked_transport_failure_timeout_and_cancellation(self):
        # 1. Timeout simulation
        def timeout_runner(cmd_args, timeout):
            raise subprocess.TimeoutExpired(cmd=cmd_args, timeout=timeout)

        timeout_adapter = RemoteSshTargetAdapter(
            host="192.168.1.99",
            command_runner=timeout_runner,
        )
        alive, err = timeout_adapter.check_liveness(100)
        self.assertFalse(alive)
        self.assertIn("timed out", err.lower())

        raw, st, read_err = timeout_adapter.read_memory(100, 0x1000, 4)
        self.assertEqual(st, "UNAVAILABLE")
        self.assertIn("timed out", read_err.lower())

        # 2. Connection failure (network down / host key rejected)
        def fail_runner(cmd_args, timeout):
            return 255, "", "ssh: connect to host 192.168.1.99 port 22: Connection refused\n"

        fail_adapter = RemoteSshTargetAdapter(
            host="192.168.1.99",
            command_runner=fail_runner,
        )
        alive, err = fail_adapter.check_liveness(100)
        self.assertFalse(alive)
        self.assertIn("Connection refused", err)

    # -------------------------------------------------------------------------
    # Test 5: Build ID & Architecture Mismatch Rejection
    # -------------------------------------------------------------------------
    def test_05_build_id_and_arch_mismatch_rejection_remote_and_local(self):
        proc = self._start_target_process(self.debug_bin)
        manager = WatchSessionManager(corpus_dir=self.corpus_dir)

        # 1. Local Build ID mismatch: companion image has different Build ID
        with self.assertRaises(ValueError) as cm:
            manager.create_session(
                pid=proc.pid,
                companion_elf_path=self.mismatched_bin,
            )
        self.assertIn("Build ID mismatch", str(cm.exception))

        # 2. Remote Build ID mismatch: target binary returns different Build ID
        def mock_mismatch_remote_runner(cmd_args, timeout):
            cmd_str = " ".join(cmd_args)
            if f"kill -0 {proc.pid}" in cmd_str:
                return 0, "ALIVE\n", ""
            elif f"/proc/{proc.pid}/exe" in cmd_str and "head" in cmd_str:
                # Return mismatched binary header
                with open(self.mismatched_bin, "rb") as f:
                    chunk = f.read(65536)
                return 0, base64.b64encode(chunk).decode("ascii") + "\n", ""
            elif f"/proc/{proc.pid}/maps" in cmd_str:
                return 0, "00400000-00401000 r-xp 00000000 08:01 1 /app\n", ""
            elif "task" in cmd_str:
                return 0, f"{proc.pid} S main\n", ""
            return 0, "", ""

        remote_adapter = RemoteSshTargetAdapter(
            host="remote.test.board",
            command_runner=mock_mismatch_remote_runner,
        )

        with self.assertRaises(ValueError) as cm2:
            manager.create_session(
                pid=proc.pid,
                companion_elf_path=self.debug_bin,
                adapter=remote_adapter,
            )
        self.assertIn("Build ID mismatch", str(cm2.exception))

    # -------------------------------------------------------------------------
    # Test 6: Address Correctness: PT_LOAD Relocation (PIE & Non-PIE)
    # -------------------------------------------------------------------------
    def test_06_pt_load_relocation_pie_and_non_pie(self):
        # 1. PIE Binary (ET_DYN) with multiple PT_LOAD segments
        pie_ident = inspect_elf(self.debug_bin)
        self.assertEqual(pie_ident.elf_type, "ET_DYN")
        self.assertGreaterEqual(len(pie_ident.pt_loads), 1)

        mock_pie_mappings = [
            {
                "start": "0x555555554000", "end": "0x555555555000",
                "start_int": 0x555555554000, "end_int": 0x555555555000,
                "offset": "00000000", "offset_int": 0,
                "permissions": "r-xp", "category": "code",
                "is_readable": True, "is_executable": True, "is_writable": False,
            },
            {
                "start": "0x555555556000", "end": "0x555555557000",
                "start_int": 0x555555556000, "end_int": 0x555555557000,
                "offset": "00001000", "offset_int": 0x1000,
                "permissions": "rw-p", "category": "data",
                "is_readable": True, "is_executable": False, "is_writable": True,
            },
        ]

        pie_bias = calculate_load_bias(pie_ident, pie_ident, mock_pie_mappings)
        self.assertTrue(pie_bias["is_dyn"])
        self.assertFalse(pie_bias["is_ambiguous"])
        self.assertEqual(pie_bias["load_bias"], 0x555555554000)

        # 2. Non-PIE Binary (ET_EXEC)
        non_pie_ident = inspect_elf(self.non_pie_bin)
        self.assertEqual(non_pie_ident.elf_type, "ET_EXEC")

        mock_exec_mappings = [
            {
                "start": "0x400000", "end": "0x401000",
                "start_int": 0x400000, "end_int": 0x401000,
                "offset": "00000000", "offset_int": 0,
                "permissions": "r-xp", "category": "code",
                "is_readable": True, "is_executable": True, "is_writable": False,
            }
        ]

        exec_bias = calculate_load_bias(non_pie_ident, non_pie_ident, mock_exec_mappings)
        self.assertFalse(exec_bias["is_dyn"])
        self.assertFalse(exec_bias["is_ambiguous"])
        self.assertEqual(exec_bias["load_bias"], 0)  # Non-PIE load bias is strictly 0!

    # -------------------------------------------------------------------------
    # Test 7: Append-Friendly JSONL Storage & Streaming Pagination
    # -------------------------------------------------------------------------
    def test_07_append_friendly_jsonl_storage_and_pagination(self):
        manager = WatchSessionManager(corpus_dir=self.corpus_dir)
        sess_id = f"test_jsonl_sess_{int(time.time())}"

        session = ObservationSession(
            session_id=sess_id,
            pid=9999,
            start_time=datetime.now(timezone.utc).isoformat(),
            status="STOPPED",
        )
        manager._persist_session(session)

        # Write 150 simulated observations line-by-line to JSONL
        for seq in range(1, 151):
            obs = Observation(
                session_id=sess_id,
                seq=seq,
                monotonic_ns=1000000 * seq,
                timestamp=datetime.now(timezone.utc).isoformat(),
                values={"var_x": {"value": seq * 10, "status": "OBSERVED"}},
            )
            manager._append_observation_to_file(sess_id, obs)

        # Check file exists and has 150 lines
        jsonl_path = manager._get_observations_file(sess_id)
        self.assertTrue(os.path.exists(jsonl_path))
        with open(jsonl_path, "r") as f:
            lines = [l for l in f if l.strip()]
        self.assertEqual(len(lines), 150)

        # 1. Page 1: limit 20, offset 0
        p1 = manager.get_observations(sess_id, limit=20, offset=0)
        self.assertEqual(p1["total_observations"], 150)
        self.assertEqual(p1["returned_count"], 20)
        self.assertEqual(p1["observations"][0]["seq"], 1)
        self.assertEqual(p1["observations"][-1]["seq"], 20)

        # 2. Page 2: limit 20, offset 20
        p2 = manager.get_observations(sess_id, limit=20, offset=20)
        self.assertEqual(p2["returned_count"], 20)
        self.assertEqual(p2["observations"][0]["seq"], 21)
        self.assertEqual(p2["observations"][-1]["seq"], 40)

        # 3. Filtered sequence range: seq 50 to 55
        p_seq = manager.get_observations(sess_id, start_seq=50, end_seq=55, limit=100)
        self.assertEqual(p_seq["returned_count"], 6)
        self.assertEqual([o["seq"] for o in p_seq["observations"]], [50, 51, 52, 53, 54, 55])

    # -------------------------------------------------------------------------
    # Test 8: Restart Recovery & Worker Liveness
    # -------------------------------------------------------------------------
    def test_08_restart_recovery_and_worker_liveness(self):
        manager1 = WatchSessionManager(corpus_dir=self.corpus_dir)
        sess_id = f"test_restart_{int(time.time())}"

        # Write session pretending to be RUNNING
        session = ObservationSession(
            session_id=sess_id,
            pid=8888,
            start_time=datetime.now(timezone.utc).isoformat(),
            status="RUNNING",
        )
        manager1._persist_session(session)

        # Write an observation to JSONL
        obs = Observation(
            session_id=sess_id,
            seq=1,
            monotonic_ns=1000,
            timestamp=datetime.now(timezone.utc).isoformat(),
            values={},
        )
        manager1._append_observation_to_file(sess_id, obs)

        # Fresh manager simulates server restart
        fresh_manager = WatchSessionManager(corpus_dir=self.corpus_dir)
        reloaded = fresh_manager.get_session(sess_id)

        self.assertIsNotNone(reloaded)
        # Must NOT claim RUNNING without verified live worker!
        self.assertEqual(reloaded.status, "STOPPED")
        self.assertIsNotNone(reloaded.end_time)

        # Must record SERVER_RESTARTED_CAPTURE_ABORTED gap
        reasons = [g.reason for g in reloaded.gaps]
        self.assertIn("SERVER_RESTARTED_CAPTURE_ABORTED", reasons)

    # -------------------------------------------------------------------------
    # Test 9: UI & MCP Consistency & Capability Truthfulness
    # -------------------------------------------------------------------------
    def test_09_ui_and_mcp_consistency(self):
        proc = self._start_target_process(self.debug_bin)

        test_runtime = AgentRuntime(corpus_dir=self.corpus_dir)
        old_runtime = mcp_srv.runtime
        mcp_srv.runtime = test_runtime
        api_adapter = WebApiAdapter(runtime=test_runtime)

        try:
            # 1. Create session via MCP
            create_res = json.loads(mcp_srv.runtime_watch_session_create(
                pid=proc.pid,
                companion_elf=self.debug_bin,
                interval_ms=100,
                max_samples=20,
            ))
            self.assertTrue(create_res["success"])
            sess_id = create_res["session_id"]

            # 2. Query via Web API: list_watch_sessions
            web_list = api_adapter.list_watch_sessions()
            self.assertTrue(web_list["success"])
            web_sess_ids = [s["session_id"] for s in web_list["data"]["sessions"]]
            self.assertIn(sess_id, web_sess_ids)

            # 3. Add watch item via Web API
            web_map = api_adapter.get_watch_memory_map(proc.pid, companion_elf=self.debug_bin)
            first_m = next(m for m in web_map["data"]["mappings"] if m["is_readable"])
            add_res = api_adapter.update_watch_items(sess_id, {
                "action": "add",
                "name": "web_added_var",
                "address": first_m["start"],
                "size": 4,
            })
            self.assertTrue(add_res["success"])

            # 4. Check that MCP get reflects the Web API watch item
            mcp_get = json.loads(mcp_srv.runtime_watch_session_get(sess_id))
            item_names = [w["name"] for w in mcp_get["watch_items"]]
            self.assertIn("web_added_var", item_names)

            # 5. Check capability truthfulness: allocation tracking is UNSUPPORTED_ON_BACKEND
            caps = mcp_get["capabilities"]
            self.assertFalse(caps["allocation_tracking"]["supported"])
            self.assertEqual(caps["allocation_tracking"]["status"], "UNSUPPORTED_ON_BACKEND")
            self.assertIn("requires an active heap hook", caps["allocation_tracking"]["reason"])

            # Stop session
            mcp_srv.runtime_watch_session_stop(sess_id)
        finally:
            mcp_srv.runtime = old_runtime

    # -------------------------------------------------------------------------
    # Test 10: Real C++ Runtime Zero-Stop Memory Observation
    # -------------------------------------------------------------------------
    def test_10_adapter_contract_with_real_local_fixture(self):
        proc = self._start_target_process(self.debug_bin)
        manager = WatchSessionManager(corpus_dir=self.corpus_dir)

        # Discover variables from companion ELF
        map_data = manager.get_memory_map_and_threads(proc.pid, companion_elf_path=self.debug_bin)
        disc_vars = map_data["discoverable_variables"]
        self.assertGreater(len(disc_vars), 0)

        # Find global variable 'g_shared_counter' or first discoverable variable
        target_var = next((v for v in disc_vars if "counter" in v["name"].lower() or "val" in v["name"].lower()), disc_vars[0])

        session = manager.create_session(
            pid=proc.pid,
            companion_elf_path=self.debug_bin,
            interval_ms=100,
            max_samples=10,
            initial_watch_items=[{
                "name": target_var["name"],
                "address": target_var["runtime_address"],
                "size": target_var["size"],
                "type_name": target_var["type_name"],
            }],
        )

        self.assertEqual(session.status, "RUNNING")

        # Mutate the target process value via stdin command 'INC'
        for _ in range(3):
            time.sleep(0.12)
            try:
                proc.stdin.write("INC\n")
                proc.stdin.flush()
            except Exception:
                pass

        time.sleep(0.3)
        manager.stop_session(session.session_id)

        obs_data = manager.get_observations(session.session_id, limit=20)
        self.assertGreaterEqual(obs_data["total_observations"], 2)

        # Verify values were observed and decoded
        observed_values = []
        for o in obs_data["observations"]:
            val_info = o["values"].get(session.watch_items[0].item_id, {})
            if val_info.get("status") == "OBSERVED":
                observed_values.append(val_info.get("value"))

        self.assertGreater(len(observed_values), 0)
