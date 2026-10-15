"""Phase 17: Process Isolation Hardening & Regression Test Suite.

Verifies:
1. Genuinely bounded stdout/stderr consumption without memory exhaustion during continuous flooding.
2. Concurrent non-blocking reading of stdout and stderr without pipe deadlock.
3. Clean termination and reaping of process groups (child and grandchild) on:
   - Output limit breach (ProviderOutputLimitExceededError)
   - Timeout (ProviderTimeoutError)
   - Cancellation (ProviderCancelledError)
4. Grandchild inheriting pipe handles does not cause indefinite hangs.
5. ACP initialization bounded timeout and malformed JSON-RPC handling.
6. Cancellation lifecycle race prevention: cancelled requests never commit hypotheses, observations, or timeline events.
7. Rejection of browser-supplied privileged CLI options (PRIVILEGED_CONFIG_FORBIDDEN).
8. Protection against self-termination when process group matches current or is <= 1.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from extractor.agent_runtime import AgentRuntime
from extractor.conversational_investigation import (
    ConversationalAnalysisService,
    StructuredAnalysisResult,
)
from extractor.investigation import InvestigationManager, InvestigationSession
from extractor.llm_provider import (
    BaseCLIProvider,
    DeterministicFallbackProvider,
    GeminiACPProvider,
    GenericCLIProvider,
    LLMProviderConfig,
    LLMProviderManager,
    LLMProviderStatus,
    ProviderCancelledError,
    ProviderExecutionError,
    ProviderOutputLimitExceededError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)
from extractor.web.server import WebApiAdapter


class TestPhase17ProcessIsolationRegression(unittest.TestCase):
    """Deep process isolation and regression tests with deterministic local subprocesses."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_phase17_iso_")
        self.manager = LLMProviderManager.reset_instance(
            LLMProviderConfig(provider_type="none", model="deterministic-engine")
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        LLMProviderManager.reset_instance()

    def test_stdout_stderr_bounded_memory_continuous_floods(self):
        """Streaming reader must terminate process group immediately upon exceeding max_output_bytes."""
        max_bytes = 32 * 1024  # 32 KB limit
        flood_script = os.path.join(self.tmp_dir, "flood.py")
        pid_file = os.path.join(self.tmp_dir, "flood.pid")

        # Script writes its PID and continuously pumps 10 MB in 4KB chunks
        with open(flood_script, "w") as f:
            f.write(
                f"import sys, os, time\n"
                f"with open(r'{pid_file}', 'w') as pf:\n"
                f"    pf.write(str(os.getpid()))\n"
                f"data = 'B' * 4096\n"
                f"for _ in range(2500):\n"
                f"    sys.stdout.write(data)\n"
                f"    sys.stdout.flush()\n"
                f"    time.sleep(0.001)\n"
            )

        cfg = LLMProviderConfig(
            provider_type="cli",
            cli_command=f"{sys.executable} {flood_script}",
            max_output_bytes=max_bytes,
        )
        prov = GenericCLIProvider(cfg)

        with self.assertRaises(ProviderOutputLimitExceededError) as ctx:
            prov._run_controlled_process([sys.executable, flood_script], timeout=5.0)

        self.assertIn("exceeded", str(ctx.exception).lower())

        # Verify child process was actually killed and reaped
        if os.path.exists(pid_file):
            with open(pid_file, "r") as pf:
                child_pid = int(pf.read().strip())
            time.sleep(0.2)
            try:
                os.kill(child_pid, 0)
                alive = True
            except OSError:
                alive = False
            self.assertFalse(alive, f"Child process {child_pid} should have been terminated on limit breach")

    def test_simultaneous_stdout_and_stderr_flooding_no_deadlock(self):
        """Simultaneous high-volume stdout and stderr writes must not deadlock pipe buffers."""
        deadlock_script = os.path.join(self.tmp_dir, "both_streams.py")
        chunk_size = 1024
        total_chunks = 100  # 100 KB on stdout, 100 KB on stderr = 200 KB total

        with open(deadlock_script, "w") as f:
            f.write(
                f"import sys\n"
                f"for i in range({total_chunks}):\n"
                f"    sys.stdout.write('O' * {chunk_size})\n"
                f"    sys.stderr.write('E' * {chunk_size})\n"
                f"sys.stdout.flush()\n"
                f"sys.stderr.flush()\n"
            )

        cfg = LLMProviderConfig(
            provider_type="cli",
            cli_command=f"{sys.executable} {deadlock_script}",
            max_output_bytes=1024 * 1024,  # 1 MB limit (accommodates 200 KB)
        )
        prov = GenericCLIProvider(cfg)

        t0 = time.monotonic()
        retcode, stdout_str, stderr_str = prov._run_controlled_process(
            [sys.executable, deadlock_script],
            timeout=5.0,
        )
        elapsed = time.monotonic() - t0

        self.assertEqual(retcode, 0)
        self.assertEqual(len(stdout_str), total_chunks * chunk_size)
        self.assertEqual(len(stderr_str), total_chunks * chunk_size)
        self.assertLess(elapsed, 4.0, "Concurrent consumption should finish swiftly without deadlock")

    def test_child_and_grandchild_cleanup_on_timeout(self):
        """Timeout must terminate both the parent process and any spawned grandchild descendants."""
        spawn_script = os.path.join(self.tmp_dir, "spawner.py")
        child_pid_file = os.path.join(self.tmp_dir, "child.pid")
        grandchild_pid_file = os.path.join(self.tmp_dir, "grandchild.pid")

        with open(spawn_script, "w") as f:
            f.write(
                f"import subprocess, sys, os, time\n"
                f"with open(r'{child_pid_file}', 'w') as pf:\n"
                f"    pf.write(str(os.getpid()))\n"
                f"gc = subprocess.Popen(['sleep', '120'])\n"
                f"with open(r'{grandchild_pid_file}', 'w') as gf:\n"
                f"    gf.write(str(gc.pid))\n"
                f"time.sleep(120)\n"
            )

        cfg = LLMProviderConfig(provider_type="cli", cli_command="dummy")
        prov = GenericCLIProvider(cfg)

        with self.assertRaises(ProviderTimeoutError):
            prov._run_controlled_process([sys.executable, spawn_script], timeout=0.6)

        # Confirm child and grandchild are terminated
        time.sleep(0.3)
        self.assertTrue(os.path.exists(child_pid_file))
        self.assertTrue(os.path.exists(grandchild_pid_file))

        with open(child_pid_file, "r") as f:
            c_pid = int(f.read().strip())
        with open(grandchild_pid_file, "r") as f:
            gc_pid = int(f.read().strip())

        try:
            os.kill(c_pid, 0)
            c_alive = True
        except OSError:
            c_alive = False

        try:
            os.kill(gc_pid, 0)
            gc_alive = True
        except OSError:
            gc_alive = False

        self.assertFalse(c_alive, f"Child process {c_pid} should have been terminated on timeout")
        self.assertFalse(gc_alive, f"Grandchild process {gc_pid} should have been terminated on timeout")

    def test_child_and_grandchild_cleanup_on_output_limit_breach(self):
        """Output limit breach must terminate the full process group including grandchildren."""
        spawner_flood = os.path.join(self.tmp_dir, "spawner_flood.py")
        gc_pid_file = os.path.join(self.tmp_dir, "gc_flood.pid")

        with open(spawner_flood, "w") as f:
            f.write(
                f"import subprocess, sys, os, time\n"
                f"gc = subprocess.Popen(['sleep', '120'])\n"
                f"with open(r'{gc_pid_file}', 'w') as gf:\n"
                f"    gf.write(str(gc.pid))\n"
                f"sys.stdout.write('X' * 50000)\n"
                f"sys.stdout.flush()\n"
                f"time.sleep(10)\n"
            )

        cfg = LLMProviderConfig(provider_type="cli", max_output_bytes=2048)
        prov = GenericCLIProvider(cfg)

        with self.assertRaises(ProviderOutputLimitExceededError):
            prov._run_controlled_process([sys.executable, spawner_flood], timeout=5.0)

        time.sleep(0.3)
        self.assertTrue(os.path.exists(gc_pid_file))
        with open(gc_pid_file, "r") as f:
            gc_pid = int(f.read().strip())

        try:
            os.kill(gc_pid, 0)
            gc_alive = True
        except OSError:
            gc_alive = False

        self.assertFalse(gc_alive, f"Grandchild process {gc_pid} should have been reaped on limit breach")

    def test_child_and_grandchild_cleanup_on_cancellation(self):
        """Calling cancel_process must terminate the active process group cleanly."""
        sleep_script = os.path.join(self.tmp_dir, "cancel_target.py")
        gc_pid_file = os.path.join(self.tmp_dir, "cancel_gc.pid")

        with open(sleep_script, "w") as f:
            f.write(
                f"import subprocess, sys, os, time\n"
                f"gc = subprocess.Popen(['sleep', '120'])\n"
                f"with open(r'{gc_pid_file}', 'w') as gf:\n"
                f"    gf.write(str(gc.pid))\n"
                f"time.sleep(120)\n"
            )

        cfg = LLMProviderConfig(provider_type="cli")
        prov = GenericCLIProvider(cfg)
        req_id = "test_cancel_pg_req"

        def _runner():
            try:
                prov._run_controlled_process([sys.executable, sleep_script], timeout=10.0, request_id=req_id)
            except Exception:
                pass

        th = threading.Thread(target=_runner)
        th.start()

        # Wait until grandchild pid file is written
        for _ in range(50):
            if os.path.exists(gc_pid_file):
                break
            time.sleep(0.05)

        with open(gc_pid_file, "r") as f:
            gc_pid = int(f.read().strip())

        # Issue cancellation
        canceled = prov.cancel_process(req_id)
        self.assertTrue(canceled)
        th.join(timeout=3.0)

        time.sleep(0.3)
        try:
            os.kill(gc_pid, 0)
            gc_alive = True
        except OSError:
            gc_alive = False

        self.assertFalse(gc_alive, f"Grandchild process {gc_pid} should have been terminated on cancellation")

    def test_grandchild_inheriting_pipe_handle_does_not_hang(self):
        """When child exits but rogue grandchild keeps pipes open, reader must not hang indefinitely."""
        inherit_script = os.path.join(self.tmp_dir, "inherit_pipe.py")
        with open(inherit_script, "w") as f:
            f.write(
                "import subprocess, sys, time\n"
                "# Grandchild inherits stdout/stderr and sleeps for 60 seconds\n"
                "subprocess.Popen(['sleep', '60'], stdout=sys.stdout, stderr=sys.stderr)\n"
                "print('PARENT_DONE')\n"
                "sys.stdout.flush()\n"
                "# Parent terminates immediately\n"
                "sys.exit(0)\n"
            )

        cfg = LLMProviderConfig(provider_type="cli", max_output_bytes=1024 * 1024)
        prov = GenericCLIProvider(cfg)

        t0 = time.monotonic()
        retcode, out, _ = prov._run_controlled_process([sys.executable, inherit_script], timeout=5.0)
        elapsed = time.monotonic() - t0

        self.assertEqual(retcode, 0)
        self.assertIn("PARENT_DONE", out)
        self.assertLess(elapsed, 3.0, "Reader must terminate gracefully within bounded drain window")

    def test_acp_initialization_timeout_and_malformed_json_rpc(self):
        """ACP health check must handle non-responsive servers and malformed JSON-RPC without hanging."""
        # 1. Non-responsive server that sleeps
        hang_script = os.path.join(self.tmp_dir, "hang_acp.py")
        with open(hang_script, "w") as f:
            f.write("import time\ntime.sleep(60)\n")

        # Create executable wrapper
        hang_exe = os.path.join(self.tmp_dir, "hang_acp.sh")
        with open(hang_exe, "w") as f:
            f.write(f"#!/bin/sh\nexec {sys.executable} {hang_script}\n")
        os.chmod(hang_exe, 0o755)

        cfg_hang = LLMProviderConfig(
            provider_type="acp",
            cli_command=hang_exe,
            timeout_seconds=1.5,
        )
        prov_hang = GeminiACPProvider(cfg_hang)

        t0 = time.monotonic()
        status_hang = prov_hang.check_health()
        elapsed = time.monotonic() - t0

        self.assertFalse(status_hang.reachable)
        self.assertEqual(status_hang.availability_status, "UNAVAILABLE")
        self.assertIn("timed out", status_hang.error.lower())
        self.assertLess(elapsed, 3.5, "Health check must not block indefinitely on uninitialized ACP server")

        # 2. Malformed JSON-RPC output
        malformed_script = os.path.join(self.tmp_dir, "malformed_acp.sh")
        with open(malformed_script, "w") as f:
            f.write("#!/bin/sh\necho 'NOT_VALID_JSON_RPC_LINE'\n")
        os.chmod(malformed_script, 0o755)

        cfg_mal = LLMProviderConfig(provider_type="acp", cli_command=malformed_script)
        prov_mal = GeminiACPProvider(cfg_mal)
        status_mal = prov_mal.check_health()

        self.assertFalse(status_mal.reachable)
        self.assertEqual(status_mal.availability_status, "UNAVAILABLE")
        self.assertIn("malformed", status_mal.error.lower())

    def test_cancellation_vs_completion_race_prevents_session_commit(self):
        """If request is cancelled before commit, session state must remain strictly unmutated."""
        session = InvestigationSession(
            investigation_id="inv_test_cancel_race",
            goal="Test race immunity",
            corpus_dir=self.tmp_dir,
        )
        self.assertEqual(len(session.hypotheses), 0)
        self.assertEqual(len(session.follow_up_observations), 0)

        req_id = "req_race_cancelled"
        # Pre-mark request as cancelled
        LLMProviderManager.get_instance().mark_cancelled(req_id)
        self.assertTrue(LLMProviderManager.get_instance().is_cancelled(req_id))

        service = ConversationalAnalysisService()
        with self.assertRaises(ProviderCancelledError):
            service.analyze_investigation(
                session=session,
                user_message="Should not be committed",
                request_id=req_id,
            )

        # Verification: session state must be completely untouched
        self.assertEqual(len(session.hypotheses), 0)
        self.assertEqual(len(session.follow_up_observations), 0)
        self.assertEqual(len(session.chat_history), 0)
        self.assertFalse(any(ev.event_type == "CONVERSATIONAL_ANALYSIS_COMPLETED" for ev in session.timeline))

    def test_rejection_of_browser_supplied_privileged_options(self):
        """Server must strictly reject client attempts to supply executable path, arguments, or bypass flags."""
        runtime = AgentRuntime()
        adapter = WebApiAdapter(runtime)

        dangerous_payloads = [
            {"investigation_id": "inv_1", "cli_command": "/bin/sh -c evil"},
            {"investigation_id": "inv_1", "cli_args": ["--dangerously-skip-permissions"]},
            {"investigation_id": "inv_1", "executable": "/usr/bin/python3"},
            {"investigation_id": "inv_1", "allow_dangerous_permissions": True},
            {"investigation_id": "inv_1", "safe_working_dir": "/root"},
            {"investigation_id": "inv_1", "max_output_bytes": 99999999},
            {"investigation_id": "inv_1", "command": "rm -rf /"},
            {"investigation_id": "inv_1", "binary_path": "/bin/bash"},
            {"investigation_id": "inv_1", "shell": True},
        ]

        for payload in dangerous_payloads:
            res = adapter.analyze_investigation_chat(payload)
            self.assertFalse(res["success"], f"Payload {payload} should have been rejected")
            self.assertEqual(
                res["error"]["code"],
                "PRIVILEGED_CONFIG_FORBIDDEN",
                f"Expected PRIVILEGED_CONFIG_FORBIDDEN for {payload}",
            )

        # Invalid provider override rejection
        invalid_provider_res = adapter.analyze_investigation_chat({
            "investigation_id": "inv_1",
            "provider_override": "malicious_unrecognized_provider_123",
        })
        self.assertFalse(invalid_provider_res["success"])
        self.assertEqual(invalid_provider_res["error"]["code"], "INVALID_PARAM")

    def test_guard_against_self_termination(self):
        """_kill_process_group must never kill the runner's own process group or init."""
        curr_pgrp = os.getpgrp()

        class MockProc:
            pid = os.getpid()

        with patch("os.killpg") as mock_killpg:
            BaseCLIProvider._kill_process_group(MockProc())
            # Must NOT call killpg on current process group
            for call in mock_killpg.call_args_list:
                pgid_arg = call[0][0]
                self.assertNotEqual(pgid_arg, curr_pgrp)
                self.assertGreater(pgid_arg, 1)


if __name__ == "__main__":
    unittest.main()
