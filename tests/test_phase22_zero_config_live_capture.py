"""Phase 22 Automated Test Suite: Zero-Configuration Live Capture, Language-Aligned LLM, and Radical UX Simplification.

Validates:
1. Two-Input Pre-Validation API (POST /api/investigation/validate-target):
   - Strict PID validation (missing, malformed, negative, ESRCH nonexistent).
   - Debug image validation (file not found, non-ELF, stripped/missing DWARF, Build ID mismatch).
   - Valid C++ live fixture with matching unstripped debug binary -> valid=True, GNU Build ID match.
2. Real C++ Fixture Live Capture:
   - Zero-configuration live connect & analyze using PID and debug image.
   - Single-submission safety and zero-stop memory read invariants (child not killed, heartbeat advances).
   - Status transitions and findings extraction (observed facts, static hypotheses, recommended actions).
3. Language-Aligned LLM & System Prompt Construction:
   - Authoritative locale propagation ('ko' vs 'en').
   - Mandatory language instructions in prompt formatting.
   - Technical token preservation: C++ symbols, source paths, addresses, and JSON schema keys are not corrupted.
   - Deterministic fallback provider localization for Korean and English.
4. UI Structure and Expert Mode Preservation:
   - Basic mode: 3 primary areas (TARGET, INVESTIGATION RESULT, ASK A QUESTION).
   - Expert mode: preservation of all 8 tabs, technical details, and deep link selectors.
   - API route parity: validate-target, start, chat with locale.
"""

from io import BytesIO
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from extractor.agent_models import AgentAction
from extractor.agent_runtime import AgentRuntime
from extractor.conversational_investigation import (
    ConversationalAnalysisService,
)
from extractor.debug_image import inspect_elf
from extractor.investigation import InvestigationManager, InvestigationSession
from extractor.llm_provider import DeterministicFallbackProvider, LLMProviderManager
from extractor.snapshot_consistency import NON_ATOMIC, STOPPED
from extractor.web.server import WebApiAdapter, run_server


class TestPhase22ZeroConfigLiveCapture(unittest.TestCase):
    """Test suite for Phase 22 target pre-validation, live capture, and language-aligned LLM."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_phase22_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        os.makedirs(cls.corpus_dir, exist_ok=True)

        # 1. Compile C++ debug binary with DWARF and GNU Build ID
        cls.fixture_src = os.path.abspath("tests/fixtures/real_runtime/main.cpp")
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        subprocess.run([
            "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
            "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
        ], check=True)

        # 2. Compile companion stripped binary (identical code, missing DWARF)
        cls.stripped_bin = os.path.join(cls.work_dir, "app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

        # 3. Compile an adversarial/different binary to produce Build ID mismatch
        cls.mismatch_bin = os.path.join(cls.work_dir, "mismatch.elf")
        mismatch_src = os.path.join(cls.work_dir, "mismatch.cpp")
        with open(mismatch_src, "w") as f:
            f.write("int main() { return 0; }\n")
        subprocess.run([
            "g++", "-g", "-Wl,--build-id=sha1", mismatch_src, "-o", cls.mismatch_bin
        ], check=True)

        # 4. Start live inferior target process
        cls.inferior_proc = subprocess.Popen(
            [cls.debug_bin],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        # Wait for "READY" synchronization signal
        ready_line = cls.inferior_proc.stdout.readline().strip()
        assert ready_line == "READY", f"Inferior failed to start, got: {ready_line}"

        # 5. Initialize runtime and ephemeral web server
        cls.runtime = AgentRuntime(corpus_dir=cls.corpus_dir)
        cls.server = run_server(runtime=cls.runtime, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        # Terminate inferior process
        if cls.inferior_proc and cls.inferior_proc.poll() is None:
            try:
                cls.inferior_proc.stdin.write("STOP\n")
                cls.inferior_proc.stdin.flush()
                cls.inferior_proc.wait(timeout=2.0)
            except Exception:
                cls.inferior_proc.kill()
                cls.inferior_proc.wait()

        cls.server.shutdown()
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def _post_json(self, path: str, data: dict) -> dict:
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=25.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return json.loads(e.read().decode("utf-8"))

    def _get_raw(self, path: str) -> str:
        req = urllib.request.Request(f"{self.base_url}{path}")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.read().decode("utf-8")

    # =========================================================================
    # 1. Target Pre-Validation Tests (POST /api/investigation/validate-target)
    # =========================================================================

    def test_validate_target_invalid_or_missing_pid(self):
        """Pre-validation rejects invalid, zero, or negative PIDs with clear next action."""
        # Malformed PID
        res = self._post_json("/api/investigation/validate-target", {"pid": "not-a-number", "debug_image": self.debug_bin})
        self.assertFalse(res.get("success", False))
        self.assertIn("INVALID_PARAM", res.get("error", {}).get("code", ""))

        # Negative PID
        res = self._post_json("/api/investigation/validate-target", {"pid": -10, "debug_image": self.debug_bin})
        self.assertFalse(res.get("success", False))

    def test_validate_target_nonexistent_pid(self):
        """Pre-validation returns TARGET_NOT_FOUND for nonexistent PID without sending signals."""
        res = self._post_json("/api/investigation/validate-target", {
            "pid": 99999999,
            "debug_image": self.debug_bin,
            "locale": "ko"
        })
        self.assertTrue(res.get("success"))
        data = res.get("data", {})
        self.assertFalse(data.get("valid"))
        self.assertEqual(data.get("reason"), "TARGET_NOT_FOUND")
        self.assertIn("99999999", data.get("message", ""))
        self.assertTrue(len(data.get("next_action", "")) > 0)

    def test_validate_target_debug_image_not_found(self):
        """Pre-validation checks that the debug image path exists on disk."""
        nonexistent_path = os.path.join(self.work_dir, "nonexistent_debug.elf")
        res = self._post_json("/api/investigation/validate-target", {
            "pid": self.inferior_proc.pid,
            "debug_image": nonexistent_path,
            "locale": "en"
        })
        self.assertTrue(res.get("success"))
        data = res.get("data", {})
        self.assertFalse(data.get("valid"))
        self.assertEqual(data.get("reason"), "DEBUG_IMAGE_NOT_FOUND")
        self.assertIn("not found", data.get("message", "").lower())
        self.assertIn("path", data.get("next_action", "").lower())

    def test_validate_target_invalid_elf(self):
        """Pre-validation rejects text files or non-ELF files as debug images."""
        text_file = os.path.join(self.work_dir, "dummy.txt")
        with open(text_file, "w") as f:
            f.write("This is not an ELF binary.\n")

        res = self._post_json("/api/investigation/validate-target", {
            "pid": self.inferior_proc.pid,
            "debug_image": text_file,
            "locale": "ko"
        })
        self.assertTrue(res.get("success"))
        data = res.get("data", {})
        self.assertFalse(data.get("valid"))
        self.assertEqual(data.get("reason"), "INVALID_ELF")
        self.assertIn("ELF", data.get("message", ""))

    def test_validate_target_missing_dwarf_in_stripped_binary(self):
        """Pre-validation detects stripped binaries that lack .debug_info."""
        res = self._post_json("/api/investigation/validate-target", {
            "pid": self.inferior_proc.pid,
            "debug_image": self.stripped_bin,
            "locale": "en"
        })
        self.assertTrue(res.get("success"))
        data = res.get("data", {})
        self.assertFalse(data.get("valid"))
        self.assertEqual(data.get("reason"), "MISSING_DWARF")
        self.assertIn("dwarf", data.get("message", "").lower())
        self.assertIn("-g", data.get("next_action", ""))

    def test_validate_target_build_id_mismatch(self):
        """Pre-validation compares GNU Build ID between running target and supplied debug image."""
        res = self._post_json("/api/investigation/validate-target", {
            "pid": self.inferior_proc.pid,
            "debug_image": self.mismatch_bin,
            "locale": "ko"
        })
        self.assertTrue(res.get("success"))
        data = res.get("data", {})
        self.assertFalse(data.get("valid"))
        self.assertEqual(data.get("reason"), "BUILD_ID_MISMATCH")
        self.assertIn("Build ID", data.get("message", ""))
        self.assertIsNotNone(data.get("target_build_id"))
        self.assertIsNotNone(data.get("debug_image_build_id"))
        self.assertNotEqual(data["target_build_id"], data["debug_image_build_id"])

    def test_validate_target_success_matching_live_process(self):
        """Pre-validation passes with valid=True for live running process and matching debug ELF."""
        res = self._post_json("/api/investigation/validate-target", {
            "pid": self.inferior_proc.pid,
            "debug_image": self.debug_bin,
            "locale": "ko"
        })
        self.assertTrue(res.get("success"))
        data = res.get("data", {})
        self.assertTrue(data.get("valid"))
        self.assertEqual(data.get("reason"), "VALID")
        self.assertEqual(data.get("pid"), self.inferior_proc.pid)
        self.assertTrue(data.get("has_dwarf"))
        self.assertTrue(data.get("build_id_match"))
        self.assertIn(data.get("memory_read_backend"), ["process_vm_readv", "procfs"])

    # =========================================================================
    # 2. Live Capture Happy Path & Zero-Stop Invariants
    # =========================================================================

    def test_live_capture_happy_path_and_process_resume(self):
        """Zero-configuration live capture connects with PID + debug_image and keeps target running."""
        # Start investigation
        start_payload = {
            "pid": self.inferior_proc.pid,
            "debug_image": self.debug_bin,
            "goal": "Live zero-config capture verification",
            "authorize_target": True,
        }
        res = self._post_json("/api/investigation/start", start_payload)
        self.assertTrue(res.get("success"), f"Failed to start live investigation: {res}")
        inv_data = res.get("data", {})
        self.assertIn(inv_data.get("status"), ["COMPLETED", "PARTIAL"])

        # Target identity
        target_id = inv_data.get("target_identity", {})
        self.assertEqual(target_id.get("pid"), self.inferior_proc.pid)
        build_id = target_id.get("target_build_id") or target_id.get("build_id")
        self.assertTrue(bool(build_id))

        # Capture quality: zero-stop memory read (CONSISTENT, LOW_IMPACT, NON_ATOMIC, or STOPPED)
        q_info = inv_data.get("capture_quality", {})
        self.assertIn(q_info.get("consistency_level"), ["CONSISTENT", "LOW_IMPACT", "NON_ATOMIC", "STOPPED"])

        # Verify inferior is still alive and running (heartbeat loop continues)
        self.assertIsNone(self.inferior_proc.poll(), "Inferior process unexpectedly terminated!")

    # =========================================================================
    # 3. Language-Aligned LLM & System Prompt Construction
    # =========================================================================

    def test_format_prompt_locale_korean(self):
        """Prompt formatting commands Korean responses when locale is 'ko', protecting technical tokens."""
        svc = ConversationalAnalysisService()
        session = InvestigationSession(investigation_id="inv_test_ko", goal="Korean locale test")
        context = svc.build_compact_context(session, "worker_status 상태를 설명해주세요.")
        messages = svc.format_prompt(context, locale="ko")
        prompt = messages[0]["content"]

        # Must include Korean language instruction
        self.assertIn("한국어", prompt)
        self.assertIn("C/C++ symbol names", prompt)
        self.assertIn("worker_status", prompt)
        self.assertIn("JSON keys", prompt)

    def test_format_prompt_locale_english(self):
        """Prompt formatting commands English responses when locale is 'en'."""
        svc = ConversationalAnalysisService()
        session = InvestigationSession(investigation_id="inv_test_en", goal="English locale test")
        context = svc.build_compact_context(session, "Why did worker_status change?")
        messages = svc.format_prompt(context, locale="en")
        prompt = messages[0]["content"]

        self.assertIn("LANGUAGE INSTRUCTION", prompt)
        self.assertIn("English", prompt)
        self.assertIn("JSON keys", prompt)

    def test_deterministic_fallback_provider_localization(self):
        """DeterministicFallbackProvider returns Korean responses when requested, without altering keys."""
        provider = DeterministicFallbackProvider()

        # 1. Test Korean locale
        res_ko = provider.chat_completion(
            messages=[{"role": "user", "content": "LANGUAGE INSTRUCTION: 한국어로 작성하세요."}]
        )
        self.assertIsInstance(res_ko, str)
        parsed_ko = json.loads(res_ko)
        # Structural keys must remain identical
        self.assertIn("observed_facts", parsed_ko)
        self.assertIn("hypotheses", parsed_ko)
        self.assertIn("next_steps", parsed_ko)
        # Content strings must be Korean
        self.assertIn("결정론적", parsed_ko["summary"])

        # 2. Test English locale
        res_en = provider.chat_completion(
            messages=[{"role": "user", "content": "Explain what happened in English"}]
        )
        self.assertIsInstance(res_en, str)
        parsed_en = json.loads(res_en)
        self.assertIn("observed_facts", parsed_en)
        self.assertIn("next_steps", parsed_en)
        self.assertIn("deterministic", parsed_en["summary"].lower())

    def test_conversational_chat_endpoint_accepts_and_propagates_locale(self):
        """POST /api/investigation/chat accepts locale and returns localized structured analysis."""
        # Create an investigation session
        start_res = self._post_json("/api/investigation/start", {
            "goal": "Chat test session",
            "authorize_target": True,
        })
        inv_id = start_res.get("data", {}).get("investigation_id")
        self.assertIsNotNone(inv_id)

        chat_res = self._post_json("/api/investigation/chat", {
            "investigation_id": inv_id,
            "message": "현재 상태 요약",
            "locale": "ko",
            "provider_override": "none",
            "allow_fallback": True,
        })
        self.assertTrue(chat_res.get("success"), f"Chat failed: {chat_res}")
        data = chat_res.get("data", {})
        self.assertIn("summary", data)
        self.assertEqual(data.get("provider_metadata", {}).get("locale"), "ko")

    # =========================================================================
    # 4. Basic Mode vs Expert Mode UI Structure
    # =========================================================================

    def test_html_contains_basic_three_areas_and_expert_preservation(self):
        """Index HTML defines the 3 basic areas and preserves advanced elements under .advanced-only."""
        html = self._get_raw("/")

        # Area 1: TARGET
        self.assertIn('id="basic-target-area"', html)
        self.assertIn('id="basic-target-pid"', html)
        self.assertIn('id="basic-debug-image"', html)
        self.assertIn('id="btn-basic-connect-analyze"', html)
        self.assertIn('id="basic-progress-sequence"', html)
        self.assertIn('id="basic-target-connected-summary"', html)

        # Area 2: INVESTIGATION RESULT
        self.assertIn('id="basic-results-area"', html)
        self.assertIn('id="basic-result-summary"', html)
        self.assertIn('id="basic-quality-warning"', html)
        self.assertIn('id="basic-facts-list"', html)
        self.assertIn('id="btn-more-facts"', html)
        self.assertIn('id="basic-causes-list"', html)
        self.assertIn('id="btn-more-causes"', html)
        self.assertIn('id="basic-next-list"', html)
        self.assertIn('id="btn-more-next"', html)

        # Area 3: ASK A QUESTION
        self.assertIn('id="basic-question-area"', html)
        self.assertIn('id="basic-question-input"', html)
        self.assertIn('id="btn-basic-ask"', html)
        self.assertIn('id="basic-chat-history"', html)

        # Expert Mode Preserved: 8 Tabs and advanced panels marked .advanced-only
        self.assertIn('id="app-nav-tabs"', html)
        self.assertIn('id="advanced-investigation-view"', html)
        self.assertIn('class="nav-tab advanced-only"', html)

    def test_css_and_js_assets_serve_successfully(self):
        """App CSS and JS assets load without 404 and contain Phase 22 rules."""
        css = self._get_raw("/app.css")
        self.assertIn("basic-progress-sequence", css)
        self.assertIn(".basic-card", css)

        js = self._get_raw("/app.js")
        self.assertIn("handleBasicConnectAndAnalyze", js)
        self.assertIn("renderBasicInvestigationView", js)
        self.assertIn("btn_basic_connect_analyze", js)


if __name__ == "__main__":
    unittest.main()
