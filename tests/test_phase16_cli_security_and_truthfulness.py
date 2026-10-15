"""Phase 16: Automated Test Suite for CLI Provider Security, Process Control, and Truthful Reporting.

Covers:
1. Security Defaults:
   - Antigravity/Gemini CLI does not use --dangerously-skip-permissions by default.
   - Opt-in permits the flag only when explicitly configured.
   - GenericCLIProvider rejects dangerous shell injection metacharacters.
   - Prompt text with quotes, Unicode, and newlines is passed as argument elements without shell interpolation.
2. Process Control & Execution Isolation:
   - Environment scrubbing prevents leakage of internal secrets (DYNAMICSTATE_LLM_API_KEY, etc.).
   - Process runs in isolated safe working directory.
   - Bounded stdout/stderr capture prevents memory exhaustion.
   - Non-zero exit codes raise ProviderExecutionError with redacted output.
   - Process group termination on timeout and cancellation.
3. Truthful Reporting:
   - Availability status truthful distinctions (BINARY_AVAILABLE vs DETERMINISTIC_RULES vs UNAVAILABLE).
   - No silent fallback when an explicit provider is requested: raises ProviderUnavailableError / ProviderExecutionError.
   - Explicit fallback preserves truthful audit trail (invoked_provider, execution_status, fallback_reason).
4. End-to-End Browser/API Integration:
   - POST /api/investigation/chat with mock executable.
   - POST /api/investigation/chat/cancel terminates child process cleanly.
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
import urllib.request
import urllib.error

from extractor.agent_models import AgentAction
from extractor.agent_runtime import AgentRuntime
from extractor.conversational_investigation import (
    ConversationalAnalysisService,
    StructuredAnalysisResult,
)
from extractor.hypothesis import (
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_VALIDATED_CAUSAL,
)
from extractor.investigation import InvestigationManager, InvestigationSession
from extractor.llm_provider import (
    BaseCLIProvider,
    DeterministicFallbackProvider,
    GeminiCLIProvider,
    GenericCLIProvider,
    LLMProviderConfig,
    LLMProviderManager,
    LLMProviderStatus,
    ProviderError,
    ProviderExecutionError,
    ProviderOutputLimitExceededError,
    ProviderUnavailableError,
)
from extractor.web.server import run_server


class TestCLISecurityDefaults(unittest.TestCase):
    """Test safety defaults, flag elimination, and shell metacharacter defense."""

    def test_gemini_cli_defaults_to_safe_mode(self):
        """Verify that GeminiCLIProvider does NOT include --dangerously-skip-permissions by default."""
        cfg = LLMProviderConfig(provider_type="gemini", model="gemini-2.5-pro")
        prov = GeminiCLIProvider(cfg)
        cmd = prov.build_command("Test prompt", timeout=30.0)

        # Flag must NOT be present by default
        self.assertNotIn("--dangerously-skip-permissions", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("Test prompt", cmd)

    def test_gemini_cli_opt_in_permission_bypass(self):
        """Verify that --dangerously-skip-permissions is ONLY added when explicitly authorized."""
        # Config direct opt-in
        cfg_opt_in = LLMProviderConfig(
            provider_type="gemini",
            model="gemini-2.5-pro",
            allow_dangerous_permissions=True,
        )
        prov_opt_in = GeminiCLIProvider(cfg_opt_in)
        cmd_opt_in = prov_opt_in.build_command("Test prompt", timeout=30.0)
        if any("agy" in arg for arg in cmd_opt_in):
            self.assertIn("--dangerously-skip-permissions", cmd_opt_in)

        # Environment variable opt-in parsing
        with patch.dict(os.environ, {"DYNAMICSTATE_ALLOW_CLI_PERMISSION_BYPASS": "true"}):
            env_cfg = LLMProviderConfig.from_env()
            self.assertTrue(env_cfg.allow_dangerous_permissions)

        with patch.dict(os.environ, {"DYNAMICSTATE_ALLOW_CLI_PERMISSION_BYPASS": "false"}):
            env_cfg2 = LLMProviderConfig.from_env()
            self.assertFalse(env_cfg2.allow_dangerous_permissions)

    def test_generic_cli_rejects_dangerous_shell_metacharacters(self):
        """GenericCLIProvider must reject templates with shell chaining or command substitution."""
        dangerous_templates = [
            "llm --prompt {prompt} ; rm -rf /",
            "llm --prompt {prompt} && cat /etc/passwd",
            "llm --prompt {prompt} | sh",
            "llm --prompt `id`",
            "llm --prompt $(whoami)",
            "llm --prompt {prompt} > /tmp/hacked",
        ]

        for d_tmpl in dangerous_templates:
            cfg = LLMProviderConfig(provider_type="cli", cli_command=d_tmpl)
            prov = GenericCLIProvider(cfg)
            with self.assertRaises(ProviderExecutionError, msg=f"Should reject: {d_tmpl}"):
                prov.build_command("Hello", timeout=10.0)

    def test_prompt_argument_safety_with_quotes_and_unicode(self):
        """Prompts with quotes, Unicode, and newlines must remain a single argument vector element."""
        cfg = LLMProviderConfig(
            provider_type="cli",
            cli_command="echo -n {prompt}",
        )
        prov = GenericCLIProvider(cfg)
        complex_prompt = (
            "Line 1: 'single' and \"double\" quotes\n"
            "Line 2: 한국어 조사 테스트 및 특수문자: $VAR `cmd` ; --flag\n"
            "Line 3: 🔍 🤖 ⚡"
        )
        cmd = prov.build_command(complex_prompt, timeout=10.0)
        self.assertEqual(len(cmd), 3)
        self.assertEqual(cmd[0], "echo")
        self.assertEqual(cmd[1], "-n")
        self.assertEqual(cmd[2], complex_prompt)


class TestProcessIsolationAndControl(unittest.TestCase):
    """Test process execution boundaries: environment scrubbing, working dir, bounding, timeout."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_phase16_cli_")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_environment_scrubbing_does_not_leak_secrets(self):
        """Child process environment must exclude internal API keys and tokens."""
        cfg = LLMProviderConfig(
            provider_type="gemini",
            api_key="ds_secret_key_12345",
        )
        prov = GeminiCLIProvider(cfg)

        with patch.dict(os.environ, {
            "DYNAMICSTATE_LLM_API_KEY": "super_secret_dynamicstate",
            "INTERNAL_SECRET_TOKEN": "my_hidden_token",
            "ANTHROPIC_API_KEY": "sk-ant-secret",
            "PATH": "/usr/bin:/bin",
            "HOME": "/tmp/test_home",
        }):
            clean_env = prov._build_safe_env()

            self.assertNotIn("DYNAMICSTATE_LLM_API_KEY", clean_env)
            self.assertNotIn("INTERNAL_SECRET_TOKEN", clean_env)
            self.assertNotIn("ANTHROPIC_API_KEY", clean_env)
            self.assertIn("PATH", clean_env)
            self.assertIn("HOME", clean_env)

    def test_controlled_process_safe_working_directory(self):
        """Process execution must be confined to the configured safe working directory."""
        safe_dir = os.path.join(self.tmp_dir, "safe_cwd")
        os.makedirs(safe_dir, exist_ok=True)

        cfg = LLMProviderConfig(
            provider_type="cli",
            cli_command=f"{sys.executable} -c 'import os; print(os.getcwd())'",
            safe_working_dir=safe_dir,
        )
        prov = GenericCLIProvider(cfg)
        retcode, out, _ = prov._run_controlled_process(
            [sys.executable, "-c", "import os; print(os.getcwd())"],
            timeout=5.0,
        )
        self.assertEqual(retcode, 0)
        self.assertEqual(out.strip(), os.path.realpath(safe_dir))

    def test_bounded_output_capture_prevents_memory_exhaustion(self):
        """Process output exceeding max_output_bytes must terminate cleanly and raise ProviderOutputLimitExceededError."""
        max_bytes = 1024  # 1 KB limit
        cfg = LLMProviderConfig(
            provider_type="cli",
            cli_command="dummy",
            max_output_bytes=max_bytes,
        )
        prov = GenericCLIProvider(cfg)

        # Python command outputting 100 KB
        cmd = [sys.executable, "-c", "import sys; sys.stdout.write('A' * 102400)"]
        with self.assertRaises((ProviderOutputLimitExceededError, ProviderExecutionError)):
            prov._run_controlled_process(cmd, timeout=5.0)

        # Also test non-raising mode if explicitly requested
        retcode, out, _ = prov._run_controlled_process(cmd, timeout=5.0, raise_on_limit=False)
        self.assertLessEqual(len(out.encode("utf-8")), max_bytes)

    def test_non_zero_exit_code_raises_execution_error(self):
        """Non-zero process exit must raise ProviderExecutionError with exit code and redacted stderr."""
        crash_script = os.path.join(self.tmp_dir, "crash.py")
        with open(crash_script, "w") as f:
            f.write("import sys\nsys.stderr.write('fatal crash')\nsys.exit(42)\n")

        cfg = LLMProviderConfig(
            provider_type="cli",
            cli_command=f"{sys.executable} {crash_script}",
        )
        prov = GenericCLIProvider(cfg)

        with self.assertRaises(ProviderExecutionError) as ctx:
            prov.chat_completion([{"role": "user", "content": "hello"}], timeout=5.0)

        self.assertIn("42", str(ctx.exception))
        self.assertIn("fatal crash", str(ctx.exception))

    def test_timeout_kills_process_group(self):
        """Timeouts must terminate the child process group completely."""
        sleep_script = os.path.join(self.tmp_dir, "sleep.py")
        with open(sleep_script, "w") as f:
            f.write("import time\ntime.sleep(10)\n")

        cfg = LLMProviderConfig(
            provider_type="cli",
            cli_command=f"{sys.executable} {sleep_script}",
            timeout_seconds=0.5,
        )
        prov = GenericCLIProvider(cfg)

        t0 = time.time()
        with self.assertRaises(ProviderExecutionError) as ctx:
            prov.chat_completion([{"role": "user", "content": "hello"}], timeout=0.5)
        elapsed = time.time() - t0

        self.assertLess(elapsed, 3.0, "Should have been killed quickly after timeout")
        self.assertIn("timed out", str(ctx.exception).lower())


class TestCancellationAndProcessRegistry(unittest.TestCase):
    """Test process registration and reliable cancellation."""

    def test_cancel_active_subprocess(self):
        """Cancelling a registered request must kill the subprocess immediately."""
        cfg = LLMProviderConfig(provider_type="cli", cli_command="dummy")
        prov = GenericCLIProvider(cfg)
        req_id = "test_cancel_req_001"

        script = "import time; time.sleep(10)"
        proc = subprocess.Popen([sys.executable, "-c", script], start_new_session=True)
        prov.register_process(req_id, proc)

        self.assertIsNone(proc.poll(), "Process should be running")

        canceled = prov.cancel_process(req_id)
        self.assertTrue(canceled)

        time.sleep(0.3)
        self.assertIsNotNone(proc.poll(), "Process must be terminated after cancel")
        self.assertNotIn(req_id, prov._active_subprocesses)

    def test_provider_manager_cancel_request(self):
        """LLMProviderManager.cancel_request must forward to registered processes."""
        mgr = LLMProviderManager.get_instance()
        prov = mgr.get_provider("cli")
        req_id = "mgr_cancel_req_002"

        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"], start_new_session=True)
        prov.register_process(req_id, proc)

        res = mgr.cancel_request(req_id)
        self.assertTrue(res)

        time.sleep(0.3)
        self.assertIsNotNone(proc.poll())


class TestTruthfulProviderReporting(unittest.TestCase):
    """Test honest status reporting and rejection of silent fallback on explicit selection."""

    def test_truthful_availability_status_distinctions(self):
        """Status must reflect BINARY_AVAILABLE, DETERMINISTIC_RULES, or UNAVAILABLE truthfully."""
        mgr = LLMProviderManager.get_instance()
        status_dict = mgr.get_status()

        self.assertIn("available_providers", status_dict)
        providers = status_dict["available_providers"]

        # Deterministic fallback provider
        self.assertIn("none", providers)
        self.assertEqual(providers["none"]["availability_status"], "DETERMINISTIC_RULES")

        # Gemini CLI provider
        self.assertIn("gemini", providers)
        gemini_st = providers["gemini"]
        self.assertIn(gemini_st["availability_status"], ("BINARY_AVAILABLE", "UNAVAILABLE"))

    def test_explicit_selection_fails_truthfully_without_silent_fallback(self):
        """Selecting an unavailable or failing provider explicitly must FAIL, not silently return fallback."""
        service = ConversationalAnalysisService()
        session = InvestigationSession(
            investigation_id="inv_truth_001",
            goal="Test causal investigation truthfulness",
        )

        # Request with non-existent CLI provider
        with patch.object(GeminiCLIProvider, "resolve_binary", return_value=None):
            with self.assertRaises(ProviderUnavailableError):
                service.analyze_investigation(
                    session=session,
                    user_message="Analyze state changes",
                    provider_override="gemini",
                    allow_fallback=False,  # Explicit request
                )

    def test_explicit_fallback_permitted_records_truthful_metadata(self):
        """When allow_fallback=True is passed, failure records honest fallback audit trail."""
        service = ConversationalAnalysisService()
        session = InvestigationSession(
            investigation_id="inv_truth_002",
            goal="Test permitted fallback truthfulness",
        )

        fake_health = LLMProviderStatus(
            configured=True,
            provider_type="gemini",
            model="default",
            base_url="cli://gemini",
            reachable=True,
            binary_available=True,
            availability_status="BINARY_AVAILABLE",
        )
        with patch.object(GeminiCLIProvider, "check_health", return_value=fake_health):
            with patch.object(GeminiCLIProvider, "chat_completion", side_effect=ProviderExecutionError("CLI crash")):
                res = service.analyze_investigation(
                    session=session,
                    user_message="Analyze state changes",
                    provider_override="gemini",
                    allow_fallback=True,
                )

                self.assertTrue(res.provider_metadata["is_fallback"])
                self.assertEqual(res.provider_metadata["invoked_provider"], "deterministic_fallback")
                self.assertEqual(res.provider_metadata["execution_status"], "FALLBACK")
                self.assertIn("CLI crash", res.provider_metadata["fallback_reason"])
                self.assertEqual(res.validation_status, "FALLBACK_DETERMINISTIC")

    def test_causal_trust_boundary_candidate_functions_never_validated(self):
        """Candidate functions proposed by any CLI or LLM are capped at STATIC_CANDIDATE."""
        service = ConversationalAnalysisService()
        session = InvestigationSession(
            investigation_id="inv_trust_boundary_003",
            goal="Test causal trust boundary",
        )

        # Mocked raw LLM JSON claiming VALIDATED_CAUSAL_FUNCTION
        mock_payload = {
            "summary": "State transition detected.",
            "observed_facts": [],
            "hypotheses": [
                {
                    "hypothesis_id": "hypo_1",
                    "title": "State corruption",
                    "claim": "update_state mutated memory",
                    "status": "VALIDATED",  # Forbidden self-promotion
                    "function_candidates": [
                        {
                            "function_name": "update_state",
                            "candidate_tier": "VALIDATED_CAUSAL_FUNCTION",  # Forbidden
                        }
                    ],
                }
            ],
            "unknowns": [],
            "evidence_refs": [],
            "alternative_explanations": [],
            "proposed_observations": [],
            "safety_notes": [],
            "next_steps": [],
        }

        with patch.object(DeterministicFallbackProvider, "chat_completion", return_value=json.dumps(mock_payload)):
            res = service.analyze_investigation(
                session=session,
                user_message="Analyze changes",
                provider_override="none",
            )

            hypo = res.hypotheses[0]
            # Must be demoted to PROPOSED
            self.assertNotEqual(hypo["status"], "VALIDATED")
            # Candidate function must NOT be VALIDATED_CAUSAL_FUNCTION
            cand = hypo["function_candidates"][0]
            self.assertEqual(cand["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
            self.assertTrue(res.unverified_claims_disarmed)


class TestEndToEndWebAPIAndCancellation(unittest.TestCase):
    """Test full HTTP API routes: chat execution, status check, and cancellation."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="phase16_web_test_")
        cls.runtime = AgentRuntime(corpus_dir=cls.tmp_dir)
        cls.server = run_server(runtime=cls.runtime, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _post(self, path: str, data: dict) -> dict:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return json.loads(err.read().decode("utf-8"))

    def test_post_chat_truthful_failure_on_unavailable_provider(self):
        """POST /api/investigation/chat returns error when an unavailable provider is explicitly requested."""
        inv_res = self.runtime.start_investigation(goal="E2E test")
        inv_id = inv_res.data["investigation_id"]

        with patch.object(GeminiCLIProvider, "resolve_binary", return_value=None):
            res = self._post("/api/investigation/chat", {
                "investigation_id": inv_id,
                "message": "Analyze system state",
                "provider_override": "gemini",
                "allow_fallback": False,
            })

            self.assertFalse(res["success"])
            self.assertEqual(res["error"]["code"], "PROVIDER_UNAVAILABLE")
            self.assertIn("was not found on PATH", res["error"]["message"])

    def test_post_chat_cancel_endpoint(self):
        """POST /api/investigation/chat/cancel successfully accepts cancellation."""
        req_id = "test_e2e_cancel_001"
        res = self._post("/api/investigation/chat/cancel", {"request_id": req_id})
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["request_id"], req_id)

    def test_post_chat_success_with_mock_cli(self):
        """POST /api/investigation/chat succeeds end-to-end with a controlled mock CLI."""
        inv_res = self.runtime.start_investigation(goal="Mock CLI test")
        inv_id = inv_res.data["investigation_id"]

        mock_out = json.dumps({
            "summary": "Mock CLI detected state change.",
            "observed_facts": [{"field_path": "sys.status", "before_value": 0, "after_value": 1}],
            "hypotheses": [
                {
                    "hypothesis_id": "hypo_mock_1",
                    "title": "State change hypothesis",
                    "claim": "Worker thread changed state",
                    "status": "PROPOSED",
                    "function_candidates": [{"function_name": "worker_func", "candidate_tier": "STATIC_CANDIDATE"}],
                }
            ],
            "unknowns": ["Who scheduled worker?"],
            "evidence_refs": [],
            "alternative_explanations": [],
            "proposed_observations": [],
            "safety_notes": ["Non-intrusive"],
            "next_steps": ["Observe caller"],
        })

        mock_health = LLMProviderStatus(
            configured=True,
            provider_type="gemini",
            model="gemini-2.5-pro",
            base_url="cli://gemini",
            reachable=True,
            binary_available=True,
            availability_status="BINARY_AVAILABLE",
        )
        with patch.object(GeminiCLIProvider, "check_health", return_value=mock_health):
            with patch.object(GeminiCLIProvider, "resolve_binary", return_value="/mock/bin/agy"):
                with patch.object(GeminiCLIProvider, "chat_completion", return_value=mock_out):
                    res = self._post("/api/investigation/chat", {
                        "investigation_id": inv_id,
                        "message": "Explain the change",
                        "provider_override": "gemini",
                    })

                    self.assertTrue(res["success"], f"Expected success: {res}")
                data = res["data"]
                self.assertEqual(data["summary"], "Mock CLI detected state change.")
                self.assertEqual(data["provider_metadata"]["invoked_provider"], "gemini")
                self.assertFalse(data["provider_metadata"]["is_fallback"])
                self.assertEqual(data["validation_status"], "VALIDATED_CLEAN")


if __name__ == "__main__":
    unittest.main()
