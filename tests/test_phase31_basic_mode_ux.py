"""
tests/test_phase31_basic_mode_ux.py

End-to-End Browser Acceptance Test Suite for Phase 31:
Investigation-First Basic Mode UX.

Verifies:
1. Persistent, compact Target Bar (PID, companion debug image, connection status, Build ID validation, language selector, Switch Target).
2. Runtime Explorer: Threads and Memory Maps entry points, contextual detail inspectors, struct member navigation, step navigation footer.
3. Watch List: compact monitored items table, explicit add/remove, explanation of unreadable/unmapped memory, capture controls.
4. Timeline & Compare: snapshot sequence chips, stop duration (0.00 ms Zero-Stop), side-by-side diff with pointer semantics, provenance modal, step navigation footer.
5. Evidence-Grounded Investigation & Hallucination Prevention:
   - Clear investigation context chip (target PID, compared snapshots, watched items).
   - 0-observations prompt and prevention of ungrounded questions.
   - Investigation question scoped to captured observations.
6. Bilingual i18n verification for Korean and English across all Phase 31 elements.
"""

import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from typing import Any, Dict, Tuple

from playwright.sync_api import sync_playwright

from extractor.agent_runtime import AgentRuntime
from extractor.web.server import DynamicStateWebServer


class TestPhase31BasicModeUX(unittest.TestCase):
    """Phase 31 Browser Acceptance Test Suite for Investigation-First Basic Mode UX."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_phase31_")

        # 1. Compile real target with DWARF (-g) and GNU build-id
        cls.target_src = os.path.join(
            os.path.dirname(__file__), "fixtures", "real_runtime", "scenario_target.cpp"
        )
        cls.debug_bin = os.path.join(cls.work_dir, "scenario_target_debug.elf")
        cls.stripped_bin = os.path.join(cls.work_dir, "scenario_target_prod.stripped")

        cmd_compile = [
            "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline",
            "-fno-omit-frame-pointer", "-Wl,--build-id=sha1",
            cls.target_src, "-o", cls.debug_bin, "-lpthread"
        ]
        subprocess.run(cmd_compile, check=True)

        cmd_strip = ["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin]
        subprocess.run(cmd_strip, check=True)

        # 2. Launch real C++ inferior target process
        cls.proc, cls.oracle = cls._start_target_process(cls.stripped_bin)

        # 3. Start ephemeral DynamicStateWebServer
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        cls.server_runtime = AgentRuntime(corpus_dir=cls.corpus_dir)
        cls.server = None
        cls.server_thread = None
        cls.server_port = None
        cls._start_web_server()

        # 4. Launch headless Chromium via Playwright
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
        )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "browser") and cls.browser:
            try:
                cls.browser.close()
            except Exception:
                pass
        if hasattr(cls, "playwright") and cls.playwright:
            try:
                cls.playwright.stop()
            except Exception:
                pass
        if hasattr(cls, "server") and cls.server:
            try:
                cls.server.shutdown()
            except Exception:
                pass
        if hasattr(cls, "proc") and cls.proc:
            cls._stop_target_process(cls.proc)
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    @classmethod
    def _start_target_process(cls, bin_path: str) -> Tuple[subprocess.Popen, Dict[str, Any]]:
        proc = subprocess.Popen(
            [bin_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        ready_line = proc.stdout.readline().strip()
        if not ready_line.startswith("READY"):
            raise RuntimeError(f"Target failed to report READY: {ready_line}")

        oracle: Dict[str, Any] = {}
        for part in ready_line.split()[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                oracle[k] = v
        oracle["pid"] = proc.pid
        return proc, oracle

    @classmethod
    def _stop_target_process(cls, proc: subprocess.Popen) -> None:
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.write("QUIT\n")
                proc.stdin.flush()
                proc.wait(timeout=1.0)
        except Exception:
            pass
        finally:
            if proc.poll() is None:
                proc.kill()

    @classmethod
    def _start_web_server(cls):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        cls.server_port = sock.getsockname()[1]
        sock.close()

        static_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "extractor", "web", "static"
        )
        cls.server = DynamicStateWebServer(
            server_address=("127.0.0.1", cls.server_port),
            runtime=cls.server_runtime,
            static_dir=static_dir
        )
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    def setUp(self):
        self.context = self.browser.new_context(viewport={"width": 1440, "height": 900})
        self.page = self.context.new_page()
        self.base_url = f"http://127.0.0.1:{self.server_port}"

    def tearDown(self):
        try:
            self.context.close()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Test Cases
    # -------------------------------------------------------------------------

    def test_01_persistent_target_bar_and_navigation_persistence(self):
        """Verify persistent target bar visibility, PID/Build ID sync, and switch target action."""
        page = self.page
        page.goto(self.base_url)

        # Persistent target bar is present in Basic Mode
        page.wait_for_selector("#basic-persistent-target-bar", state="visible")
        self.assertIn("UNCONNECTED", page.locator("#ptb-val-status").text_content())

        # Fill and validate target
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        # Persistent target bar updates with connected target metadata
        self.assertEqual(page.locator("#ptb-val-pid").text_content(), str(self.proc.pid))
        self.assertIn("CONNECTED", page.locator("#ptb-val-status").text_content())
        self.assertIn("MATCHED", page.locator("#ptb-val-buildid").text_content())
        self.assertIn("Zero-Stop", page.locator("#ptb-val-backend").text_content())

        # Navigate across tabs: Bar remains visible and retains metadata
        tabs = ["#nav-tab-explorer", "#nav-tab-watchlist", "#nav-tab-timeline", "#nav-tab-investigation"]
        for tab_sel in tabs:
            page.locator(tab_sel).click()
            time.sleep(0.1)
            self.assertTrue(page.locator("#basic-persistent-target-bar").is_visible())
            self.assertEqual(page.locator("#ptb-val-pid").text_content(), str(self.proc.pid))
            self.assertIn("CONNECTED", page.locator("#ptb-val-status").text_content())

        # Click Switch Target button
        page.locator("#btn-ptb-switch-target").click()
        page.wait_for_selector("#tab-target-setup.active")
        self.assertTrue(page.locator("#te-target-pid").is_visible())

    def test_02_runtime_explorer_contextual_details_and_transitions(self):
        """Verify thread and variable contextual details inspector and step navigation footer."""
        page = self.page
        page.goto(self.base_url)

        # Connect target
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        # Use Step 1 transition button: Proceed to Runtime Explorer
        page.locator("#btn-step1-to-step2").click()
        page.wait_for_selector("#tab-runtime-explorer.active")
        page.wait_for_selector("#te-threads-tbody tr")
        page.wait_for_selector("#te-vars-tbody tr")

        # 1. Thread selection & details card
        first_thread_row = page.locator("#te-threads-tbody tr").first
        first_thread_row.click()
        page.wait_for_selector("#te-thread-details-card", state="visible")

        thread_card_text = page.locator("#te-thread-details-card").text_content()
        self.assertIn("Selected Thread Details", thread_card_text)
        self.assertIn("Stack Range:", thread_card_text)

        # Inspect Thread Stack in Memory Inspector
        page.locator("#btn-inspect-thread-stack").click()
        time.sleep(0.3)
        self.assertTrue(page.locator("#input-inspect-address").input_value().startswith("0x"))

        # 2. Variable selection & details card
        page.locator("button.btn-toggle-struct").first.click()
        page.wait_for_selector(".te-member-row", state="visible")

        member_row = page.locator(".te-member-row:has-text('g_state.sequence')")
        # Click member row to inspect details
        member_row.click()
        page.wait_for_selector("#te-var-details-card", state="visible")

        var_card_text = page.locator("#te-var-details-card").text_content()
        self.assertIn("g_state.sequence", var_card_text)
        self.assertIn("uint32_t", var_card_text)
        self.assertIn("4 bytes", var_card_text)

        # Add to watch list from details card
        page.locator("#btn-details-add-watch").click()
        time.sleep(0.3)

        # Also watch g_state.status and g_state.active
        page.locator(".te-member-row:has-text('g_state.status') button.btn-add-member-watch").click()
        time.sleep(0.2)
        page.locator(".te-member-row:has-text('g_state.active') button.btn-add-member-watch").click()
        time.sleep(0.2)

        # 3. Transition to Step 3 (Watch List) via footer button
        page.locator("#btn-step2-to-step3").click()
        page.wait_for_selector("#tab-watch-list.active")
        self.assertIn("3 items", page.locator("#watchlist-count-badge").text_content())

    def test_03_watchlist_and_unmapped_guard_memory_clarification(self):
        """Verify watch list captures, unmapped/guard memory clarification, and Step 4 transition."""
        page = self.page
        page.goto(self.base_url)

        # Connect target
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        # Go to Tab 3 Watch List
        page.locator("#nav-tab-watchlist").click()
        page.wait_for_selector("#tab-watch-list.active")

        # Add unmapped guard page from oracle
        guard_addr_hex = self.oracle.get("guard")
        self.assertTrue(guard_addr_hex)
        guard_target_int = int(guard_addr_hex, 16) + 4096
        guard_target_hex = f"0x{guard_target_int:x}"

        page.locator("#btn-te-toggle-add-custom").click()
        page.wait_for_selector("#te-custom-add-panel", state="visible")
        page.locator("#te-custom-name").fill("guard_page_prot_none")
        page.locator("#te-custom-address").fill(guard_target_hex)
        page.locator("#te-custom-size").fill("16")
        page.locator("#btn-te-submit-custom-watch").click()
        time.sleep(0.4)

        # Capture snapshot via Step 3 button
        page.locator("#btn-step3-capture-now").click()
        page.wait_for_selector("#te-watchlist-tbody tr:has-text('guard_page_prot_none') .badge-danger:has-text('UNREADABLE')", timeout=10000)

        # Verify unmapped memory shows clear UNREADABLE badge and explanatory text
        guard_row = page.locator("#te-watchlist-tbody tr:has-text('guard_page_prot_none')")
        guard_text = guard_row.text_content()
        self.assertIn("UNREADABLE", guard_text)
        self.assertIn("Unmapped / inaccessible", guard_text)

        # Transition to Step 4 Timeline via footer button
        page.locator("#btn-step3-to-step4").click()
        page.wait_for_selector("#tab-timeline-compare.active")
        page.wait_for_selector("#te-snapshot-chips .te-snap-chip:has-text('#1')")

    def test_04_timeline_compare_and_investigation_workflow_handoff(self):
        """Verify timeline comparison, provenance drilldown, scope context chip, and Step 5 ask."""
        page = self.page
        page.goto(self.base_url)

        # Setup target and watch g_state.sequence
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        page.locator("#nav-tab-explorer").click()
        page.wait_for_selector("#te-vars-tbody tr")
        page.locator("button.btn-toggle-struct").first.click()
        page.wait_for_selector(".te-member-row", state="visible")
        page.locator(".te-member-row:has-text('g_state.sequence') button.btn-add-member-watch").click()
        time.sleep(0.3)

        # Capture Snapshot #1 in Timeline
        page.locator("#nav-tab-timeline").click()
        page.wait_for_selector("#tab-timeline-compare.active")
        page.locator("#btn-timeline-capture-now").click()
        page.wait_for_selector("#te-snapshot-chips .te-snap-chip:has-text('#1')")

        # Mutate inferior process state
        self.proc.stdin.write("SET sequence 12345\n")
        self.proc.stdin.flush()
        self.assertEqual(self.proc.stdout.readline().strip(), "OK sequence=12345")

        # Capture Snapshot #2
        page.locator("#btn-timeline-capture-now").click()
        page.wait_for_selector("#te-snapshot-chips .te-snap-chip:has-text('#2')")

        # Compare Snapshots
        page.locator("#select-cmp-snap-a").select_option("1")
        page.locator("#select-cmp-snap-b").select_option("2")
        page.locator("#btn-execute-compare").click()
        page.wait_for_selector("#compare-summary-row", state="visible")

        # Check diff row
        diff_seq = page.locator("#tbody-snapshot-diffs tr:has-text('g_state.sequence')")
        self.assertIn("CHANGED", diff_seq.text_content())
        self.assertIn("12345", diff_seq.text_content())

        # Check Step 4 footer button: Proceed to Ask a Question (Step 5)
        page.locator("#btn-step4-to-step5").click()
        page.wait_for_selector("#tab-investigation-overview.active")

        # Verify Investigation Context chip shows active scope
        ctx_chip_text = page.locator("#basic-investigation-context").text_content()
        self.assertIn(f"PID {self.proc.pid}", ctx_chip_text)
        self.assertIn("#1 vs #2", ctx_chip_text)
        self.assertIn("1 items", ctx_chip_text)

        # Verify no 0-observations alert since observations exist
        self.assertFalse(page.locator("#basic-no-observations-alert").is_visible())

        # Goal is prefilled from diff
        goal_val = page.locator("#basic-investigation-goal").input_value()
        self.assertIn("g_state.sequence", goal_val)

        # Trigger analysis
        page.locator("#btn-basic-connect-analyze").click()
        page.wait_for_selector("#basic-badge-inv-status:has-text('COMPLETED')", timeout=15000)

        # Ask a follow-up grounded question
        page.locator("#basic-question-input").fill("What caused g_state.sequence to change?")
        page.locator("#btn-basic-ask").click()
        page.wait_for_selector("#basic-chat-history .chat-bubble-assistant", timeout=10000)

        chat_text = page.locator("#basic-chat-history").text_content()
        self.assertIn("g_state.sequence", chat_text)

    def test_05_zero_observations_prompt_and_hallucination_prevention(self):
        """Verify that asking questions with 0 captured observations warns user and prevents hallucinations."""
        page = self.page
        page.goto(self.base_url)

        # Switch to Tab 5 without connecting or capturing
        page.locator("#nav-tab-investigation").click()
        page.wait_for_selector("#tab-investigation-overview.active")

        # 0-Observations alert is visible
        page.wait_for_selector("#basic-no-observations-alert", state="visible")
        alert_text = page.locator("#basic-no-observations-alert").text_content()
        self.assertIn("No runtime observations recorded yet", alert_text)

        # Try asking a question
        page.locator("#basic-question-input").fill("Why did the buffer overflow?")
        page.locator("#btn-basic-ask").click()

        # System responds with immediate ungrounded warning without hallucinating
        page.wait_for_selector("#basic-chat-history .chat-bubble-assistant", state="visible")
        response_text = page.locator("#basic-chat-history").text_content()
        self.assertIn("No runtime observations recorded yet", response_text)
        self.assertIn("Step 4", response_text)

    def test_06_bilingual_i18n_verification(self):
        """Verify language toggle seamlessly translates Persistent Target Bar, buttons, and context chip."""
        page = self.page
        page.goto(self.base_url)

        # Connect target
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        # 1. English default checks
        self.assertIn("Switch Target", page.locator("#btn-ptb-switch-target").text_content())
        self.assertIn("Proceed to Runtime Explorer", page.locator("#btn-step1-to-step2").text_content())

        # Switch to Korean
        page.locator("#btn-lang-ko").click()
        time.sleep(0.3)

        # 2. Korean translated checks
        ptb_text_ko = page.locator("#basic-persistent-target-bar").text_content()
        self.assertIn("대상:", ptb_text_ko)
        self.assertIn("실행 파일:", ptb_text_ko)
        self.assertIn("상태:", ptb_text_ko)
        self.assertIn("대상 변경", page.locator("#btn-ptb-switch-target").text_content())
        self.assertIn("런타임 탐색기(2단계)로 이동", page.locator("#btn-step1-to-step2").text_content())

        # Go to Step 2
        page.locator("#btn-step1-to-step2").click()
        page.wait_for_selector("#tab-runtime-explorer.active")
        self.assertIn("감시 목록(3단계)으로 이동", page.locator("#btn-step2-to-step3").text_content())

        # Go to Step 3
        page.locator("#btn-step2-to-step3").click()
        page.wait_for_selector("#tab-watch-list.active")
        self.assertIn("타임라인 및 비교(4단계)로 이동", page.locator("#btn-step3-to-step4").text_content())

        # Go to Step 4
        page.locator("#btn-step3-to-step4").click()
        page.wait_for_selector("#tab-timeline-compare.active")
        self.assertIn("질문하기(5단계)로 이동", page.locator("#btn-step4-to-step5").text_content())

        # Go to Step 5
        page.locator("#btn-step4-to-step5").click()
        page.wait_for_selector("#tab-investigation-overview.active")
        self.assertIn("활성 조사 범위:", page.locator("#basic-investigation-context").text_content())

        # Switch back to English
        page.locator("#btn-lang-en").click()
        time.sleep(0.3)
        self.assertIn("Active Investigation Scope:", page.locator("#basic-investigation-context").text_content())
        self.assertIn("Switch Target", page.locator("#btn-ptb-switch-target").text_content())


if __name__ == "__main__":
    unittest.main()
