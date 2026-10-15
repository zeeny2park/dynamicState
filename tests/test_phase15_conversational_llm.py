"""Phase 15: Automated Test Suite for Conversational LLM Integration and Investigation UX.

Covers:
1. Provider configuration & strict secret redaction (API keys never exposed).
2. Provider adapters (OpenAI-compatible, Ollama, deterministic fallback).
3. Evidence-grounded context construction & privacy minimization (no raw memory blobs).
4. Schema validation, JSON extraction, and defensive claim disarming:
   - Strips fabricated evidence IDs not in the ledger.
   - Demotes claimed VALIDATED status to PROPOSED.
   - Caps candidate functions to STATIC_CANDIDATE (never VALIDATED_CAUSAL_FUNCTION).
5. Audit timeline recording (CONVERSATIONAL_ANALYSIS_COMPLETED) and chat history persistence.
6. REST API routes: GET /api/llm/status, GET /api/investigation/llm-status, POST /api/investigation/chat.
7. AgentRuntime protocol dispatch for ANALYZE_INVESTIGATION_CHAT and GET_LLM_STATUS.
"""

from io import BytesIO
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
import urllib.request

from extractor.agent_models import AgentAction
from extractor.agent_runtime import AgentRuntime
from extractor.conversational_investigation import (
    ConversationalAnalysisService,
    StructuredAnalysisResult,
)
from extractor.hypothesis import (
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_VALIDATED,
)
from extractor.investigation import InvestigationManager, InvestigationSession
from extractor.llm_provider import (
    BaseCLIProvider,
    BaseLLMProvider,
    ClineCLIProvider,
    DeterministicFallbackProvider,
    GeminiACPProvider,
    GeminiCLIProvider,
    GenericCLIProvider,
    LLMProviderConfig,
    LLMProviderManager,
    LLMProviderStatus,
    OpenAICompatibleProvider,
)
from extractor.snapshot_consistency import STOPPED
from extractor.web.server import run_server


class TestLLMProviderConfigAndSecrets(unittest.TestCase):
    """Test LLM provider configuration and strict secret redaction guarantees."""

    def test_config_secret_redaction_in_repr_and_dict(self):
        secret_key = "sk-super-confidential-secret-key-123456"
        config = LLMProviderConfig(
            provider_type="openai",
            base_url="https://api.openai.com/v1",
            api_key=secret_key,
            model="gpt-4o",
            timeout_seconds=15.0,
        )

        # 1. repr() must redact api_key
        rep = repr(config)
        self.assertNotIn(secret_key, rep)
        self.assertIn("[REDACTED]", rep)

        # 2. to_safe_dict() must never contain api_key
        safe = config.to_safe_dict()
        self.assertNotIn("api_key", safe)
        self.assertTrue(safe.get("has_api_key"))
        self.assertEqual(safe.get("model"), "gpt-4o")
        self.assertEqual(safe.get("provider_type"), "openai")

    def test_config_from_env_loading_and_override(self):
        secret_key = "sk-test-env-key-999"
        with patch.dict(os.environ, {
            "DYNAMICSTATE_LLM_PROVIDER": "openai",
            "DYNAMICSTATE_LLM_BASE_URL": "http://test-server:9000/v1",
            "DYNAMICSTATE_LLM_API_KEY": secret_key,
            "DYNAMICSTATE_LLM_MODEL": "custom-model-x",
            "DYNAMICSTATE_LLM_TIMEOUT": "22.5",
        }):
            cfg = LLMProviderConfig.from_env()
            self.assertEqual(cfg.provider_type, "openai")
            self.assertEqual(cfg.base_url, "http://test-server:9000/v1")
            self.assertEqual(cfg.api_key, secret_key)
            self.assertEqual(cfg.model, "custom-model-x")
            self.assertEqual(cfg.timeout_seconds, 22.5)

            safe = cfg.to_safe_dict()
            self.assertNotIn(secret_key, json.dumps(safe))
            self.assertTrue(safe["has_api_key"])

    def test_provider_health_check_redacts_credentials_on_error(self):
        secret = "sk-secret-error-probe-444"
        cfg = LLMProviderConfig(
            provider_type="openai",
            base_url="http://127.0.0.1:54321/v1",
            api_key=secret,
            model="test-model",
            timeout_seconds=0.5,
        )
        provider = OpenAICompatibleProvider(cfg)
        status = provider.check_health()
        self.assertFalse(status.reachable)
        if status.error:
            self.assertNotIn(secret, status.error)

    def test_deterministic_fallback_provider_honesty(self):
        provider = DeterministicFallbackProvider()
        health = provider.check_health()
        self.assertTrue(health.is_fallback)
        self.assertFalse(health.configured)
        self.assertEqual(health.model, "deterministic-engine")

        messages = [{"role": "user", "content": "analyze"}]
        raw = provider.chat_completion(messages, json_mode=True)
        data = json.loads(raw)
        self.assertIn("Deterministic analysis executed", data["summary"])
        self.assertIn("No external LLM was configured", data["summary"])

    def test_live_local_llm_if_available(self):
        try:
            req = urllib.request.Request("http://127.0.0.1:8000/v1/models")
            with urllib.request.urlopen(req, timeout=0.8) as resp:
                if resp.status != 200:
                    self.skipTest("Local LLM not responding 200")
        except Exception:
            self.skipTest("Local LLM not reachable on 127.0.0.1:8000")

        cfg = LLMProviderConfig(
            provider_type="openai",
            base_url="http://127.0.0.1:8000/v1",
            model="/models/gemma-3n-e2b-it-q4_k_m.gguf",
            timeout_seconds=5.0,
        )
        provider = OpenAICompatibleProvider(cfg)
        status = provider.check_health()
        self.assertTrue(status.reachable)

        # Quick completion test
        messages = [
            {"role": "system", "content": "You are a debugger. Return valid JSON only with {\"summary\": \"ok\"}"},
            {"role": "user", "content": "hello"}
        ]
        res = provider.chat_completion(messages, json_mode=True)
        self.assertTrue(len(res) > 0)


class TestEvidenceGroundedContextAndSchemaDisarming(unittest.TestCase):
    """Test compact context generation, schema validation, and defensive claim disarming."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="phase15_ctx_test_")
        self.session = InvestigationSession(
            investigation_id="inv_test_ctx_01",
            goal="Analyze worker state corruption",
            corpus_dir=self.tmp_dir,
        )
        # Register a valid evidence record in the ledger
        self.ev_valid = self.session.ledger.record(
            evidence_type="OBJECT_STATE",
            nature="observation",
            source="semantic_interpretation",
            observation="Worker status changed from 1 to 2",
            details={"field": "status", "old": 1, "new": 2},
        )
        self.service = ConversationalAnalysisService()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_build_compact_context_minimization_and_fingerprint(self):
        ctx = self.service.build_compact_context(
            session=self.session,
            user_message="Why did worker status change?",
        )
        # Verify required keys present
        self.assertIn("investigation_id", ctx)
        self.assertIn("goal", ctx)
        self.assertIn("target_identity", ctx)
        self.assertIn("capture_quality", ctx)
        self.assertIn("evidence_ledger_ids", ctx)
        self.assertIn("context_fingerprint", ctx)

        # Context minimization: no raw memory bytes
        serialized = json.dumps(ctx)
        self.assertNotIn("raw_memory", serialized)
        self.assertNotIn("hex_dump", serialized)
        self.assertIn(self.ev_valid.evidence_id, ctx["evidence_ledger_ids"])

        # Deterministic fingerprint
        self.assertEqual(len(ctx["context_fingerprint"]), 64)

    def test_parse_and_validate_strips_fabricated_evidence_refs(self):
        valid_ids = [self.ev_valid.evidence_id]
        raw_llm_json = json.dumps({
            "summary": "State transition observed",
            "observed_facts": [{"fact": "Worker status changed"}],
            "hypotheses": [{"title": "Data Race", "claim": "Worker thread overwrite", "status": "PROPOSED"}],
            "unknowns": ["Thread scheduling order"],
            "evidence_refs": [self.ev_valid.evidence_id, "ev_FABRICATED_9999", "ev_HALLUCINATED_8888"],
            "proposed_observations": [],
        })

        data, disarmed = self.service.parse_and_validate_response(
            raw_response=raw_llm_json,
            valid_evidence_ids=valid_ids,
            ledger=self.session.ledger,
        )

        # Fabricated refs stripped
        self.assertEqual(data["evidence_refs"], [self.ev_valid.evidence_id])
        self.assertEqual(len(disarmed), 2)
        self.assertIn("Stripped fabricated evidence reference 'ev_FABRICATED_9999'", disarmed[0])

    def test_parse_and_validate_disarms_hallucinated_validated_status(self):
        valid_ids = [self.ev_valid.evidence_id]
        raw_llm_json = json.dumps({
            "summary": "Root cause definitively discovered",
            "hypotheses": [
                {
                    "title": "Confirmed Root Cause",
                    "claim": "worker_mutate() overwrote memory",
                    "status": "VALIDATED",  # Forbidden for LLM to claim
                    "candidate_function": "worker_mutate",
                }
            ],
        })

        data, disarmed = self.service.parse_and_validate_response(
            raw_response=raw_llm_json,
            valid_evidence_ids=valid_ids,
            ledger=self.session.ledger,
        )

        hypo = data["hypotheses"][0]
        # Status MUST be disarmed to PROPOSED
        self.assertEqual(hypo["status"], HYPOTHESIS_STATUS_PROPOSED)
        # Function tier MUST be capped to STATIC_CANDIDATE
        self.assertEqual(hypo["function_candidates"][0]["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(hypo["function_candidates"][0]["confirmed_root_cause"])
        self.assertTrue(any("Demoted claimed status VALIDATED to PROPOSED" in d for d in disarmed))

    def test_parse_and_validate_handles_markdown_and_broken_json(self):
        valid_ids = []
        raw_markdown = (
            "Here is my diagnostic analysis:\n"
            "```json\n"
            "{\n"
            '  "summary": "Extracted from markdown block",\n'
            '  "unknowns": ["Need more context"]\n'
            "}\n"
            "```\n"
            "Hope this helps!"
        )

        data, _ = self.service.parse_and_validate_response(
            raw_response=raw_markdown,
            valid_evidence_ids=valid_ids,
        )
        self.assertEqual(data["summary"], "Extracted from markdown block")
        self.assertEqual(data["unknowns"], ["Need more context"])

        # Completely broken JSON fails gracefully
        data_err, _ = self.service.parse_and_validate_response(
            raw_response="This is not JSON at all {broken",
            valid_evidence_ids=valid_ids,
        )
        self.assertIn("Investigation conversational analysis complete", data_err["summary"])


class TestConversationalAnalysisServiceEndToEnd(unittest.TestCase):
    """Test end-to-end service execution, session mutation, and audit timeline recording."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="phase15_e2e_test_")
        self.session = InvestigationSession(
            investigation_id="inv_test_e2e_02",
            goal="Test conversational pipeline",
            corpus_dir=self.tmp_dir,
        )
        self.service = ConversationalAnalysisService()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_analyze_investigation_with_fallback_records_audit_timeline(self):
        # Force fallback by testing with deterministic provider
        result = self.service.analyze_investigation(
            session=self.session,
            user_message="Analyze state changes",
            provider_override="none",
        )

        self.assertIsInstance(result, StructuredAnalysisResult)
        self.assertTrue(result.provider_metadata.get("is_fallback"))
        self.assertEqual(result.provider_metadata.get("provider"), "deterministic_fallback")

        # 1. Timeline event recorded
        timeline_events = [e for e in self.session.timeline if e.get("event_type") == "CONVERSATIONAL_ANALYSIS_COMPLETED"]
        self.assertEqual(len(timeline_events), 1)
        evt = timeline_events[0]
        self.assertIn("context_fingerprint", evt.get("details", {}))
        self.assertEqual(evt["details"]["provider"], "deterministic_fallback")

        # 2. Chat history updated
        self.assertGreaterEqual(len(self.session.chat_history), 2)
        self.assertEqual(self.session.chat_history[0]["role"], "user")
        self.assertEqual(self.session.chat_history[1]["role"], "assistant")

    def test_analyze_investigation_with_mocked_llm_response(self):
        mock_provider = MagicMock(spec=BaseLLMProvider)
        mock_provider.check_health.return_value = LLMProviderStatus(
            configured=True,
            provider_type="openai",
            model="mock-gpt4",
            base_url="http://mock-api:8000/v1",
            reachable=True,
            latency_ms=12.5,
            is_fallback=False,
        )
        mock_llm_payload = {
            "summary": "Mock LLM identified potential race condition in worker loop.",
            "observed_facts": [{"fact": "Worker status transitioned unexpectedly"}],
            "hypotheses": [
                {
                    "title": "Race Condition in update_worker()",
                    "claim": "update_worker() modifies state without holding lock",
                    "candidate_function": "update_worker",
                    "status": "PROPOSED",
                }
            ],
            "unknowns": ["Mutex acquisition order"],
            "evidence_refs": [],
            "alternative_explanations": ["Spurious wakeup"],
            "proposed_observations": [
                {
                    "question": "Inspect worker mutex ownership?",
                    "target_kind": "FIELD",
                    "target_field": "worker.mutex_state",
                }
            ],
            "safety_notes": ["Read-only inspection"],
            "next_steps": ["Execute observation on mutex_state"],
        }
        mock_provider.chat_completion.return_value = json.dumps(mock_llm_payload)

        with patch.object(self.service.provider_manager, "get_provider", return_value=mock_provider):
            result = self.service.analyze_investigation(
                session=self.session,
                user_message="Explain state discrepancy",
            )

            self.assertFalse(result.provider_metadata.get("is_fallback"))
            self.assertEqual(result.provider_metadata.get("model"), "mock-gpt4")
            self.assertIn("Mock LLM identified potential race condition", result.summary)

            # Hypothesis attached to session
            self.assertTrue(any(h.title == "Race Condition in update_worker()" for h in self.session.hypotheses))
            # Follow-up observation attached to session
            self.assertTrue(any("worker.mutex_state" in str(o.target_ref) for o in self.session.follow_up_observations))


class TestWebAPIAndRuntimeDispatch(unittest.TestCase):
    """Test HTTP routes: GET /api/llm/status, POST /api/investigation/chat, and ARP action dispatch."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="phase15_web_test_")
        cls.runtime = AgentRuntime(corpus_dir=cls.tmp_dir)
        cls.server = run_server(runtime=cls.runtime, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _get_json(self, path: str):
        req = urllib.request.Request(f"{self.base_url}{path}")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    def _post_json(self, path: str, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    def test_get_llm_status_endpoint(self):
        # 1. Primary route: /api/llm/status
        status, data = self._get_json("/api/llm/status")
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        status_data = data.get("data", {})
        self.assertIn("provider_type", status_data)
        self.assertIn("model", status_data)
        self.assertIn("is_fallback", status_data)
        self.assertIn("config", status_data)
        # Verify secret redaction: raw key must never be exposed
        self.assertNotIn("api_key", status_data["config"])

        # 2. Alias route: /api/investigation/llm-status
        status_alias, data_alias = self._get_json("/api/investigation/llm-status")
        self.assertEqual(status_alias, 200)
        self.assertTrue(data_alias.get("success"))

    def test_post_investigation_chat_workflow(self):
        # 1. Start an investigation session
        status, start_resp = self._post_json("/api/investigation/start", {
            "goal": "Verify worker transition",
        })
        self.assertEqual(status, 200)
        self.assertTrue(start_resp.get("success"))
        inv_id = start_resp["data"]["investigation_id"]

        # 2. Call conversational chat endpoint
        chat_payload = {
            "investigation_id": inv_id,
            "message": "Why is the worker in this state?",
            "provider_override": "none",  # Honest deterministic fallback test
        }
        status, chat_resp = self._post_json("/api/investigation/chat", chat_payload)
        self.assertEqual(status, 200)
        self.assertTrue(chat_resp.get("success"))
        res_data = chat_resp.get("data", {})
        self.assertIn("summary", res_data)
        self.assertIn("hypotheses", res_data)
        self.assertIn("provider_metadata", res_data)
        self.assertEqual(res_data["provider_metadata"]["provider"], "deterministic_fallback")

    def test_post_investigation_chat_error_on_missing_id(self):
        status, err_resp = self._post_json("/api/investigation/chat", {
            "message": "Missing ID",
        })
        self.assertEqual(status, 200)
        self.assertFalse(err_resp.get("success"))
        self.assertEqual(err_resp.get("error", {}).get("code"), "INVALID_PARAM")

    def test_agent_runtime_protocol_action_dispatch(self):
        # 1. Start session
        start_res = self.runtime.start_investigation(goal="ARP Chat Test")
        self.assertTrue(start_res.success)
        inv_id = start_res.data["investigation_id"]

        # 2. Dispatch ANALYZE_INVESTIGATION_CHAT
        action = AgentAction(
            action="ANALYZE_INVESTIGATION_CHAT",
            investigation_id=inv_id,
            message="Test ARP dispatch",
            provider_override="none",
        )
        action_res = self.runtime.dispatch_action(action)
        self.assertTrue(action_res.success)
        self.assertEqual(action_res.action, "ANALYZE_INVESTIGATION_CHAT")
        self.assertIn("summary", action_res.data)

        # 3. Dispatch GET_LLM_STATUS
        status_action = AgentAction(action="GET_LLM_STATUS")
        status_res = self.runtime.dispatch_action(status_action)
        self.assertTrue(status_res.success)
        self.assertEqual(status_res.action, "GET_LLM_STATUS")
        self.assertIn("provider_type", status_res.data)


class TestCLILLMProviders(unittest.TestCase):
    """Test suite for local CLI-based LLM adapters (Gemini, Gemini ACP, Cline, and generic CLI)."""

    def test_gemini_cli_provider_resolution_and_command_builder(self):
        cfg = LLMProviderConfig(provider_type="gemini", model="gemini-2.5-pro")
        prov = GeminiCLIProvider(cfg)
        bin_path = prov.resolve_binary()
        self.assertIsNotNone(bin_path, "Gemini or agy binary should resolve")
        self.assertTrue(os.path.exists(bin_path))

        cmd = prov.build_command("Test prompt", timeout=30.0)
        self.assertEqual(cmd[0], bin_path)
        self.assertIn("-p", cmd)
        self.assertIn("Test prompt", cmd)
        if "agy" in os.path.basename(bin_path).lower():
            self.assertIn("--output-format", cmd)
            self.assertIn("text", cmd)
            self.assertIn("--disable-slash-commands", cmd)
            self.assertIn("--dangerously-skip-permissions", cmd)

    def test_gemini_acp_provider_resolution_and_handshake(self):
        cfg = LLMProviderConfig(provider_type="acp")
        prov = GeminiACPProvider(cfg)
        bin_path = prov.resolve_binary()
        self.assertIsNotNone(bin_path, "agy-acp binary should resolve at ~/.gemini/antigravity/agy-acp/dist/")
        self.assertTrue(os.path.exists(bin_path))

        status = prov.check_health()
        self.assertTrue(status.configured)
        self.assertTrue(status.reachable)
        self.assertTrue(status.is_cli)
        self.assertIn("acp://", status.base_url)
        self.assertIsNotNone(status.latency_ms)

    def test_cline_cli_provider_resolution_and_command_builder(self):
        cfg = LLMProviderConfig(provider_type="cline")
        prov = ClineCLIProvider(cfg)
        bin_path = prov.resolve_binary()
        self.assertIsNotNone(bin_path, "Cline or paseo binary should resolve")
        self.assertTrue(os.path.exists(bin_path))

        cmd = prov.build_command("Inspect state", timeout=25.0)
        self.assertEqual(cmd[0], bin_path)
        if "paseo" in os.path.basename(bin_path).lower():
            self.assertIn("run", cmd)
            self.assertIn("Inspect state", cmd)
            self.assertIn("--provider", cmd)
            self.assertIn("--json", cmd)

    def test_generic_cli_provider_template_substitution_and_secrets(self):
        secret = "sk-super-secret-token-777"
        cfg = LLMProviderConfig(
            provider_type="cli",
            cli_command="echo 'Echoed: {prompt}'",
            api_key=secret,
        )
        prov = GenericCLIProvider(cfg)
        cmd = prov.build_command("Hello world", timeout=10.0)
        self.assertEqual(cmd, ["echo", "Echoed: Hello world"])

        # Test secret redaction on error
        err_msg = prov._redact_secrets(f"Failed with token {secret} and AIzaSyD1234567890abcdefghijklmnopqrst")
        self.assertNotIn(secret, err_msg)
        self.assertIn("[REDACTED]", err_msg)
        self.assertIn("[REDACTED_GEMINI_KEY]", err_msg)

    def test_cli_provider_missing_binary_fails_safely(self):
        cfg = LLMProviderConfig(
            provider_type="cli",
            cli_command="/usr/bin/nonexistent_llm_cli_99999",
        )
        prov = GenericCLIProvider(cfg)
        self.assertIsNone(prov.resolve_binary())

        status = prov.check_health()
        self.assertTrue(status.configured)
        self.assertFalse(status.reachable)
        self.assertTrue(status.is_cli)
        self.assertIn("not found", status.error)

        cfg_empty = LLMProviderConfig(provider_type="cli", cli_command="")
        prov_empty = GenericCLIProvider(cfg_empty)
        with self.assertRaises(RuntimeError):
            prov_empty.chat_completion([{"role": "user", "content": "hi"}])

    def test_conversational_analysis_with_gemini_cli_provider(self):
        session = InvestigationSession(
            investigation_id="inv_gemini_cli_test",
            goal="CLI Investigation Test",
        )

        mock_gemini_output = json.dumps({
            "summary": "State analysis produced by Gemini CLI adapter.",
            "observed_facts": [{"fact": "Worker status changed"}],
            "hypotheses": [
                {
                    "title": "Worker Mutator",
                    "claim": "update_worker mutated state",
                    "status": "VALIDATED",
                }
            ],
            "unknowns": ["No trace evidence available."],
            "evidence_refs": ["fabricated_ev_999"],
            "alternative_explanations": [],
            "proposed_observations": [
                {
                    "question": "Run read-only observation?",
                    "target_kind": "FIELD",
                }
            ],
            "safety_notes": ["Safe read only."],
            "next_steps": ["Observe next state."]
        })

        prov_mgr = LLMProviderManager.get_instance()
        with patch.object(GeminiCLIProvider, "chat_completion", return_value=mock_gemini_output):
            service = ConversationalAnalysisService(provider_manager=prov_mgr)
            result = service.analyze_investigation(
                session=session,
                user_message="Analyze state with Gemini CLI",
                provider_override="gemini",
            )

            self.assertEqual(result.summary, "State analysis produced by Gemini CLI adapter.")
            self.assertTrue(result.provider_metadata.get("is_cli"))
            self.assertEqual(result.provider_metadata.get("provider"), "gemini")

            # Defensive disarming checks
            self.assertNotIn("fabricated_ev_999", result.evidence_refs)
            for h in result.hypotheses:
                self.assertNotEqual(h.get("status"), "VALIDATED")
                self.assertEqual(h.get("status"), "PROPOSED")

            events = [e for e in session.timeline if e.get("event_type") == "CONVERSATIONAL_ANALYSIS_COMPLETED"]
            self.assertEqual(len(events), 1)
            self.assertTrue(events[0]["details"].get("is_cli"))
            self.assertEqual(events[0]["details"].get("provider"), "gemini")

    def test_llm_provider_manager_override_cli_types(self):
        cfg = LLMProviderConfig(provider_type="none")
        mgr = LLMProviderManager(config=cfg)

        p_gemini = mgr.get_provider("gemini")
        self.assertIsInstance(p_gemini, GeminiCLIProvider)

        p_acp = mgr.get_provider("acp")
        self.assertIsInstance(p_acp, GeminiACPProvider)

        p_cline = mgr.get_provider("cline")
        self.assertIsInstance(p_cline, ClineCLIProvider)

        p_cli = mgr.get_provider("cli")
        self.assertIsInstance(p_cli, GenericCLIProvider)

        p_fallback = mgr.get_provider("none")
        self.assertIsInstance(p_fallback, DeterministicFallbackProvider)


if __name__ == "__main__":
    unittest.main()
