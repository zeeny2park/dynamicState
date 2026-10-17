"""
tests/test_phase29_browser_e2e.py

End-to-End Real Browser Acceptance Test Suite for Phase 29:
Complete and Validate the Browser-Based Runtime Investigation Workflow.

Executes real browser automation with Chromium headless via Playwright against
a live running C++ process (tests/fixtures/real_runtime/scenario_target.cpp)
and ephemeral DynamicStateWebServer.
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


class TestPhase29BrowserE2E(unittest.TestCase):
    """Real Browser E2E Acceptance Test Suite for Phase 29 Workflow."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_phase29_")

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

    def test_01_target_setup_i18n_persistence_and_validation(self):
        """Step A: Verify target PID/companion ELF inputs, form persistence, i18n, and target validation."""
        page = self.page
        page.goto(self.base_url)
        page.wait_for_selector("#nav-tab-target")

        # 1. Test Korean / English language toggling and DOM re-rendering
        btn_ko = page.locator("#btn-lang-ko")
        btn_en = page.locator("#btn-lang-en")
        btn_ko.click()

        # Check that navigation tabs updated to Korean
        tab_target = page.locator("#nav-tab-target")
        self.assertIn("대상 설정", tab_target.text_content())
        tab_explorer = page.locator("#nav-tab-explorer")
        self.assertIn("런타임 탐색기", tab_explorer.text_content())
        tab_watchlist = page.locator("#nav-tab-watchlist")
        self.assertIn("감시 목록", tab_watchlist.text_content())

        # Switch back to English
        btn_en.click()
        self.assertIn("Target", tab_target.text_content())
        self.assertIn("Runtime Explorer", tab_explorer.text_content())
        self.assertIn("Watch List", tab_watchlist.text_content())

        # 2. Enter target PID and companion debug ELF path
        pid_input = page.locator("#te-target-pid")
        elf_input = page.locator("#te-companion-elf")
        pid_input.fill(str(self.proc.pid))
        elf_input.fill(self.debug_bin)

        # 3. Test Form Persistence across tab navigation
        page.locator("#nav-tab-explorer").click()
        page.wait_for_selector("#tab-runtime-explorer.active")

        # Switch back to Tab 1
        page.locator("#nav-tab-target").click()
        page.wait_for_selector("#tab-target-setup.active")

        # Assert values remain populated
        self.assertEqual(pid_input.input_value(), str(self.proc.pid))
        self.assertEqual(elf_input.input_value(), self.debug_bin)

        # 4. Trigger target validation
        page.locator("#btn-validate-target").click()

        # Wait for validation diagnostics card to appear
        page.wait_for_selector("#target-validation-results", state="visible")
        conn_badge = page.locator("#target-conn-badge")
        self.assertIn("CONNECTED", conn_badge.text_content())

        # Verify diagnostic report details
        exe_text = page.locator("#diag-val-executable").text_content()
        self.assertTrue(len(exe_text) > 0)
        dwarf_badge = page.locator("#diag-val-dwarf")
        self.assertIn("VERIFIED", dwarf_badge.text_content())
        backend_el = page.locator("#diag-val-backend")
        self.assertIn("process_vm_readv", backend_el.text_content())

        # Verify feedback banner
        banner = page.locator("#diag-feedback-banner")
        self.assertTrue(banner.is_visible())
        self.assertIn("Validation Passed", banner.text_content())

    def test_02_runtime_explorer_threads_maps_and_struct_members(self):
        """Step B: Explore real threads, memory maps, and struct member expansion with individual watch."""
        page = self.page
        page.goto(self.base_url)

        # Setup and validate target
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        # Click Inspect Runtime Structure (navigates to Tab 2)
        page.locator("#btn-inspect-runtime").click()
        page.wait_for_selector("#tab-runtime-explorer.active")

        # 1. Assert threads table is populated
        page.wait_for_selector("#te-threads-tbody tr")
        threads_rows = page.locator("#te-threads-tbody tr")
        self.assertGreater(threads_rows.count(), 0)

        # 2. Assert memory maps table is populated
        page.wait_for_selector("#te-mappings-tbody tr")
        map_rows = page.locator("#te-mappings-tbody tr")
        self.assertGreater(map_rows.count(), 0)

        # 3. Assert DWARF discoverable variables table is populated
        page.wait_for_selector("#te-vars-tbody tr")
        vars_text = page.locator("#te-vars-tbody").text_content()
        self.assertIn("g_state", vars_text)

        # 4. Expand struct g_state to inspect nested members
        toggle_btn = page.locator("button.btn-toggle-struct").first
        self.assertTrue(toggle_btn.is_visible())
        toggle_btn.click()

        # Wait for struct member rows
        page.wait_for_selector(".te-member-row", state="visible")
        member_rows = page.locator(".te-member-row")
        self.assertGreaterEqual(member_rows.count(), 3)

        # Check member names (sequence, status, buffer, active)
        members_text = page.locator("#te-vars-tbody").text_content()
        self.assertIn("g_state.sequence", members_text)
        self.assertIn("g_state.status", members_text)

        # 5. Click Watch on g_state.sequence
        watch_btn_seq = page.locator(".te-member-row:has-text('g_state.sequence') button.btn-add-member-watch")
        self.assertTrue(watch_btn_seq.is_visible())
        watch_btn_seq.click()

        # Assert badge changes to Watching
        page.wait_for_selector(".te-member-row:has-text('g_state.sequence') .badge:has-text('Watching')")

        # 6. Click Watch on g_state.status
        watch_btn_stat = page.locator(".te-member-row:has-text('g_state.status') button.btn-add-member-watch")
        if watch_btn_stat.is_visible():
            watch_btn_stat.click()
            page.wait_for_selector(".te-member-row:has-text('g_state.status') .badge:has-text('Watching')")

    def test_03_watchlist_management_and_removal(self):
        """Step C: Verify user-selected watch items display, source provenance, and removal."""
        page = self.page
        page.goto(self.base_url)

        # Setup target
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        # Navigate to Tab 2 and watch g_state.sequence
        page.locator("#nav-tab-explorer").click()
        page.wait_for_selector("#te-vars-tbody tr")
        page.locator("button.btn-toggle-struct").first.click()
        page.wait_for_selector(".te-member-row", state="visible")
        page.locator(".te-member-row:has-text('g_state.sequence') button.btn-add-member-watch").click()

        # Navigate to Tab 3: Watch List
        page.locator("#nav-tab-watchlist").click()
        page.wait_for_selector("#tab-watch-list.active")

        # Assert watch item is listed
        page.wait_for_selector("#te-watchlist-tbody tr")
        wl_text = page.locator("#te-watchlist-tbody").text_content()
        self.assertIn("g_state.sequence", wl_text)
        self.assertIn("struct_member", wl_text)

        # Test Add Custom Range
        page.locator("#btn-te-toggle-add-custom").click()
        page.wait_for_selector("#te-custom-add-panel", state="visible")
        page.locator("#te-custom-name").fill("manual_range")
        page.locator("#te-custom-address").fill(self.oracle.get("g_state", "0x1000"))
        page.locator("#te-custom-size").fill("8")
        page.locator("#btn-te-submit-custom-watch").click()

        # Verify custom range added
        time.sleep(0.5)
        wl_text_updated = page.locator("#te-watchlist-tbody").text_content()
        self.assertIn("manual_range", wl_text_updated)

        # Test Remove item
        remove_btn = page.locator("#te-watchlist-tbody tr:has-text('manual_range') button:has-text('Remove')")
        remove_btn.click()
        time.sleep(0.5)
        wl_text_after_remove = page.locator("#te-watchlist-tbody").text_content()
        self.assertNotIn("manual_range", wl_text_after_remove)

    def test_04_repeated_captures_mutation_timeline_diffs_and_provenance(self):
        """Step D: Repeated captures across inferior state mutation, timeline replay, diffing, and provenance."""
        page = self.page
        page.goto(self.base_url)

        # 1. Target setup
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        # 2. Add g_state.sequence to watch list
        page.locator("#nav-tab-explorer").click()
        page.wait_for_selector("#te-vars-tbody tr")
        page.locator("button.btn-toggle-struct").first.click()
        page.wait_for_selector(".te-member-row", state="visible")
        page.locator(".te-member-row:has-text('g_state.sequence') button.btn-add-member-watch").click()
        page.wait_for_selector(".te-member-row:has-text('g_state.sequence') .badge:has-text('Watching')")

        # 3. Capture baseline snapshot #1
        page.locator("#nav-tab-watchlist").click()
        btn_capture = page.locator("#btn-manual-capture-now")
        btn_capture.click()
        time.sleep(1.0)

        # 4. Navigate to Tab 4: Timeline
        page.locator("#nav-tab-timeline").click()
        page.wait_for_selector("#tab-timeline-compare.active")

        # Verify Snapshot #1 chip is rendered
        page.wait_for_selector("#te-snapshot-chips .te-snap-chip")
        chips = page.locator("#te-snapshot-chips .te-snap-chip")
        self.assertGreaterEqual(chips.count(), 1)
        self.assertIn("#1", chips.first.text_content())

        # Verify initial sequence value is 42
        table_text = page.locator("#te-temporal-tbody").text_content()
        self.assertIn("g_state.sequence", table_text)
        self.assertIn("42", table_text)

        # 5. Mutate inferior process state via stdin
        self.proc.stdin.write("SET sequence 9999\n")
        self.proc.stdin.flush()
        out_line = self.proc.stdout.readline().strip()
        self.assertEqual(out_line, "OK sequence=9999")

        # 6. Capture snapshot #2
        page.locator("#btn-timeline-capture-now").click()
        time.sleep(1.0)

        # Verify Snapshot #2 chip exists
        page.wait_for_selector("#te-snapshot-chips .te-snap-chip:has-text('#2')")

        # Verify slider is updated
        slider = page.locator("#te-replay-slider")
        self.assertFalse(slider.is_disabled())

        # 7. Execute Side-by-Side Snapshot Comparison
        sel_a = page.locator("#select-cmp-snap-a")
        sel_b = page.locator("#select-cmp-snap-b")
        sel_a.select_option("1")
        sel_b.select_option("2")

        btn_compare = page.locator("#btn-execute-compare")
        btn_compare.click()

        # Wait for comparison results
        page.wait_for_selector("#compare-summary-row", state="visible")
        badge_changed = page.locator("#cmp-badge-changed")
        self.assertIn("1", badge_changed.text_content())

        # Assert diff row in table
        page.wait_for_selector("#tbody-snapshot-diffs tr:has-text('g_state.sequence')")
        diff_row = page.locator("#tbody-snapshot-diffs tr:has-text('g_state.sequence')")
        diff_row_text = diff_row.text_content()
        self.assertIn("CHANGED", diff_row_text)
        self.assertIn("42", diff_row_text)
        self.assertIn("9999", diff_row_text)

        # 8. Test Provenance Inspection Modal
        btn_prov = diff_row.locator("button.btn-diff-provenance")
        self.assertTrue(btn_prov.is_visible())
        btn_prov.click()

        # Assert provenance modal is open
        page.wait_for_selector("#modal-provenance-drilldown", state="visible")
        modal_text = page.locator("#provenance-modal-content").text_content()
        self.assertIn("process_vm_readv", modal_text)
        self.assertIn("Zero-Stop", modal_text)
        self.assertIn("42", modal_text)
        self.assertIn("9999", modal_text)

        # Close provenance modal
        page.locator("#btn-close-modal-provenance").click()
        time.sleep(0.3)
        self.assertFalse(page.locator("#modal-provenance-drilldown").is_visible())

    def test_05_investigation_integration_handoff(self):
        """Step E: Hand off diff evidence directly into Tab 5 Investigation Goal."""
        page = self.page
        page.goto(self.base_url)

        # Setup target
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        # Watch variable
        page.locator("#nav-tab-explorer").click()
        page.wait_for_selector("#te-vars-tbody tr")
        page.locator("button.btn-toggle-struct").first.click()
        page.wait_for_selector(".te-member-row", state="visible")
        page.locator(".te-member-row:has-text('g_state.sequence') button.btn-add-member-watch").click()

        # Switch to Tab 3: Watch List
        page.locator("#nav-tab-watchlist").click()
        page.wait_for_selector("#tab-watch-list.active")

        # Take 2 captures
        page.locator("#btn-manual-capture-now").click()
        time.sleep(0.5)

        self.proc.stdin.write("SET sequence 12345\n")
        self.proc.stdin.flush()
        self.proc.stdout.readline()

        page.locator("#btn-manual-capture-now").click()
        time.sleep(0.5)

        # Compare
        page.locator("#nav-tab-timeline").click()
        page.locator("#select-cmp-snap-a").select_option("1")
        page.locator("#select-cmp-snap-b").select_option("2")
        page.locator("#btn-execute-compare").click()
        page.wait_for_selector("#btn-send-diff-to-inv", state="visible")

        # Click Investigate this Difference in Tab 5
        page.locator("#btn-send-diff-to-inv").click()

        # Verify transition to Tab 5
        page.wait_for_selector("#tab-investigation-overview.active")
        goal_input = page.locator("#basic-investigation-goal")
        goal_val = goal_input.input_value()

        self.assertIn("Investigate state mutation", goal_val)
        self.assertIn("g_state.sequence", goal_val)

        # Verify radio source is switched to watch session
        radio_watch = page.locator("#radio-source-watch")
        self.assertTrue(radio_watch.is_checked())


if __name__ == "__main__":
    unittest.main()
