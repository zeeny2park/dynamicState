"""
tests/test_phase30_real_capture_e2e.py

End-to-End Real-Capture Integrity, UX Hardening, and Browser Acceptance Suite
for Phase 30: Runtime Investigation UX Hardening, Real-Capture Integrity, and Browser Acceptance.

Verifies:
1. Linear primary journey: Target -> Explore -> Select variables -> Capture -> Compare -> Ask.
2. Exact pointer semantics: POINTER_ADDRESS_CHANGED vs REFERENCED_MEMORY_CHANGED.
3. Guard page and unmapped memory truthfulness (UNAVAILABLE/UNREADABLE, never fabricated zeroes).
4. Provenance completeness: verified PID, verified Build ID, backend, timestamps, hex, status.
5. Ungrounded LLM hallucination prevention on sessions with 0 observations.
6. Negative cases: invalid PID, target process exit, Build ID mismatch, missing DWARF.
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


class TestPhase30RealCaptureE2E(unittest.TestCase):
    """Phase 30 Browser Acceptance & Real-Capture Integrity Test Suite."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_phase30_")

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

        # Separate companion binary with DWARF and distinct GNU build-id
        cls.mismatch_bin = os.path.join(cls.work_dir, "mismatch_debug.elf")
        subprocess.run(
            ["g++", "-g", "-Wl,--build-id=sha1", "-x", "c++", "-", "-o", cls.mismatch_bin],
            input="int main() { return 0; }\n",
            text=True,
            check=True
        )

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

    def test_01_primary_journey_complete_linear_workflow(self):
        """Primary linear journey: Target -> Explore -> Select variables -> Capture -> Compare -> Ask."""
        page = self.page
        page.goto(self.base_url)

        # 1. Target Connection
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        # Verify verified DWARF and Build ID
        self.assertIn("CONNECTED", page.locator("#target-conn-badge").text_content())
        self.assertIn("VERIFIED", page.locator("#diag-val-dwarf").text_content())

        # 2. Explore: Click 'Inspect Runtime Structure (Tab 2)'
        page.locator("#btn-inspect-runtime").click()
        page.wait_for_selector("#tab-runtime-explorer.active")
        page.wait_for_selector("#te-vars-tbody tr")

        # Expand struct g_state
        page.locator("button.btn-toggle-struct").first.click()
        page.wait_for_selector(".te-member-row", state="visible")

        # 3. Select variables to watch
        # Watch g_state.sequence
        page.locator(".te-member-row:has-text('g_state.sequence') button.btn-add-member-watch").click()
        page.wait_for_selector(".te-member-row:has-text('g_state.sequence') .badge:has-text('Watching')")

        # Watch g_state.status
        page.locator(".te-member-row:has-text('g_state.status') button.btn-add-member-watch").click()
        page.wait_for_selector(".te-member-row:has-text('g_state.status') .badge:has-text('Watching')")

        # Watch g_state.active (pointer)
        page.locator(".te-member-row:has-text('g_state.active') button.btn-add-member-watch").click()
        page.wait_for_selector(".te-member-row:has-text('g_state.active') .badge:has-text('Watching')")

        # 4. Capture Baseline Snapshot #1 in Tab 4
        page.locator("#nav-tab-timeline").click()
        page.wait_for_selector("#tab-timeline-compare.active")
        page.locator("#btn-timeline-capture-now").click()
        page.wait_for_selector("#te-snapshot-chips .te-snap-chip:has-text('#1')")

        # Verify initial values rendered
        re_text = page.locator("#te-temporal-tbody").text_content()
        self.assertIn("g_state.sequence", re_text)
        self.assertIn("42", re_text)

        # Mutate inferior process state
        self.proc.stdin.write("SET sequence 9000\n")
        self.proc.stdin.flush()
        self.assertEqual(self.proc.stdout.readline().strip(), "OK sequence=9000")

        self.proc.stdin.write("SET status 77\n")
        self.proc.stdin.flush()
        self.assertEqual(self.proc.stdout.readline().strip(), "OK status=77")

        self.proc.stdin.write("SET active null\n")
        self.proc.stdin.flush()
        self.assertTrue(self.proc.stdout.readline().strip().startswith("OK active="))

        # Capture Snapshot #2
        page.locator("#btn-timeline-capture-now").click()
        page.wait_for_selector("#te-snapshot-chips .te-snap-chip:has-text('#2')")

        # 5. Compare Snapshots #1 & #2
        page.locator("#select-cmp-snap-a").select_option("1")
        page.locator("#select-cmp-snap-b").select_option("2")
        page.locator("#btn-execute-compare").click()

        page.wait_for_selector("#compare-summary-row", state="visible")
        self.assertIn("3", page.locator("#cmp-badge-changed").text_content())

        # Verify diff rows: sequence
        diff_seq = page.locator("#tbody-snapshot-diffs tr:has-text('g_state.sequence')")
        self.assertIn("42", diff_seq.text_content())
        self.assertIn("9000", diff_seq.text_content())

        # Verify diff rows: status
        diff_stat = page.locator("#tbody-snapshot-diffs tr:has-text('g_state.status')")
        self.assertIn("1", diff_stat.text_content())
        self.assertIn("77", diff_stat.text_content())

        # Verify diff rows: active (pointer reassigned)
        diff_act = page.locator("#tbody-snapshot-diffs tr:has-text('g_state.active')")
        self.assertIn("Pointer Target Reassigned", diff_act.text_content())

        # Verify Provenance Inspection Modal
        diff_act.locator("button.btn-diff-provenance").click()
        page.wait_for_selector("#modal-provenance-drilldown", state="visible")

        prov_content = page.locator("#provenance-modal-content").text_content()
        self.assertIn("Verified PID:", prov_content)
        self.assertIn(str(self.proc.pid), prov_content)
        self.assertIn("Verified Build ID:", prov_content)
        self.assertIn("process_vm_readv", prov_content)
        self.assertIn("OBSERVED", prov_content)
        self.assertIn("POINTER_ADDRESS_CHANGED", prov_content)

        # Close Provenance Modal
        page.locator("#btn-close-modal-provenance").click()
        time.sleep(0.3)

        # 6. Ask about changes: handoff into Tab 5 Investigation
        page.locator("#btn-send-diff-to-inv").click()
        page.wait_for_selector("#tab-investigation-overview.active")

        # Goal is prefilled with mutated variables
        goal_val = page.locator("#basic-investigation-goal").input_value()
        self.assertIn("Investigate state mutation", goal_val)
        self.assertIn("g_state.sequence", goal_val)

        # Trigger investigation analysis
        page.locator("#btn-basic-connect-analyze").click()
        page.wait_for_selector("#basic-badge-inv-status:has-text('COMPLETED')", timeout=15000)

        results_text = page.locator("#basic-results-area").text_content()
        self.assertIn("g_state.sequence", results_text)

    def test_02_pointer_reassignment_vs_referenced_memory_mutation(self):
        """Strict verification: pointer address reassignment vs pointed-to memory mutation."""
        page = self.page
        page.goto(self.base_url)

        # Reset inferior active pointer to buffer
        self.proc.stdin.write("SET active self\n")
        self.proc.stdin.flush()
        self.proc.stdout.readline()

        self.proc.stdin.write("SET buffer.used 10\n")
        self.proc.stdin.flush()
        self.proc.stdout.readline()

        # Connect target
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        # Add g_state.active to watch list
        page.locator("#nav-tab-explorer").click()
        page.wait_for_selector("#te-vars-tbody tr")
        page.locator("button.btn-toggle-struct").first.click()
        page.wait_for_selector(".te-member-row", state="visible")
        page.locator(".te-member-row:has-text('g_state.active') button.btn-add-member-watch").click()

        # Take Baseline Snapshot #1
        page.locator("#nav-tab-timeline").click()
        page.wait_for_selector("#tab-timeline-compare.active")
        page.locator("#btn-timeline-capture-now").click()
        page.wait_for_selector("#te-snapshot-chips .te-snap-chip:has-text('#1')")

        # Mutate ONLY referenced buffer memory (pointer address itself remains completely stable)
        self.proc.stdin.write("SET buffer.used 888\n")
        self.proc.stdin.flush()
        self.assertEqual(self.proc.stdout.readline().strip(), "OK buffer.used=888")

        # Take Snapshot #2
        page.locator("#btn-timeline-capture-now").click()
        page.wait_for_selector("#te-snapshot-chips .te-snap-chip:has-text('#2')")

        # Compare #1 and #2: MUST report REFERENCED_MEMORY_CHANGED
        page.locator("#select-cmp-snap-a").select_option("1")
        page.locator("#select-cmp-snap-b").select_option("2")
        page.locator("#btn-execute-compare").click()
        page.wait_for_selector("#tbody-snapshot-diffs tr:has-text('Referenced Memory Mutated')")

        diff_row_12 = page.locator("#tbody-snapshot-diffs tr:has-text('g_state.active')")
        diff_text_12 = diff_row_12.text_content()
        self.assertIn("CHANGED", diff_text_12)
        self.assertIn("Referenced Memory Mutated", diff_text_12)
        self.assertNotIn("Pointer Target Reassigned", diff_text_12)

        # Inspect Provenance for referenced memory mutation
        diff_row_12.locator("button.btn-diff-provenance").click()
        page.wait_for_selector("#modal-provenance-drilldown", state="visible")

        prov_modal_12 = page.locator("#provenance-modal-content").text_content()
        self.assertIn("REFERENCED_MEMORY_CHANGED", prov_modal_12)
        self.assertIn("Pointer Target & Referenced Memory Inspection", prov_modal_12)
        page.locator("#btn-close-modal-provenance").click()
        time.sleep(0.3)

        # Now reassign the pointer target to null
        self.proc.stdin.write("SET active null\n")
        self.proc.stdin.flush()
        self.proc.stdout.readline()

        # Take Snapshot #3
        page.locator("#btn-timeline-capture-now").click()
        page.wait_for_selector("#te-snapshot-chips .te-snap-chip:has-text('#3')")

        # Compare #2 and #3: MUST report POINTER_ADDRESS_CHANGED
        page.locator("#select-cmp-snap-a").select_option("2")
        page.locator("#select-cmp-snap-b").select_option("3")
        page.locator("#btn-execute-compare").click()
        page.wait_for_selector("#tbody-snapshot-diffs tr:has-text('Pointer Target Reassigned')")

        diff_row_23 = page.locator("#tbody-snapshot-diffs tr:has-text('g_state.active')")
        diff_text_23 = diff_row_23.text_content()
        self.assertIn("CHANGED", diff_text_23)
        self.assertIn("Pointer Target Reassigned", diff_text_23)
        self.assertNotIn("Referenced Memory Mutated", diff_text_23)

    def test_03_unmapped_guard_memory_truthfulness(self):
        """Unmapped or PROT_NONE guard page must be reported truthfully as UNREADABLE/UNAVAILABLE, not 0x00."""
        page = self.page
        page.goto(self.base_url)

        # Target setup
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-validation-results", state="visible")

        # Guard address from oracle (page 2 of mmap has PROT_NONE)
        guard_addr_hex = self.oracle.get("guard")
        self.assertTrue(guard_addr_hex and guard_addr_hex.startswith("0x"))

        # Add guard page address as custom watch range
        page.locator("#nav-tab-watchlist").click()
        page.wait_for_selector("#tab-watch-list.active")
        page.locator("#btn-te-toggle-add-custom").click()
        page.wait_for_selector("#te-custom-add-panel", state="visible")

        # Guard page starts at guard_base + 4096
        guard_int = int(guard_addr_hex, 16) + 4096
        guard_target_hex = f"0x{guard_int:x}"

        page.locator("#te-custom-name").fill("guard_page_prot_none")
        page.locator("#te-custom-address").fill(guard_target_hex)
        page.locator("#te-custom-size").fill("16")
        page.locator("#btn-te-submit-custom-watch").click()

        time.sleep(0.5)
        page.wait_for_selector("#te-watchlist-tbody tr:has-text('guard_page_prot_none')")

        # Take Snapshot #1
        page.locator("#btn-manual-capture-now").click()
        time.sleep(0.5)

        # Mutate sequence and take Snapshot #2
        self.proc.stdin.write("SET sequence 4444\n")
        self.proc.stdin.flush()
        self.proc.stdout.readline()

        page.locator("#btn-manual-capture-now").click()
        time.sleep(0.5)

        # Compare Snapshots #1 & #2 in Tab 4
        page.locator("#nav-tab-timeline").click()
        page.locator("#select-cmp-snap-a").select_option("1")
        page.locator("#select-cmp-snap-b").select_option("2")
        page.locator("#btn-execute-compare").click()
        page.wait_for_selector("#compare-summary-row", state="visible")

        # Verify summary row shows unreadable count >= 1
        unr_badge = page.locator("#cmp-badge-unreadable")
        self.assertIn("1", unr_badge.text_content())

        # Verify diff row
        diff_guard = page.locator("#tbody-snapshot-diffs tr:has-text('guard_page_prot_none')")
        diff_guard_text = diff_guard.text_content()
        self.assertIn("UNREADABLE", diff_guard_text)

        # Open provenance drilldown
        diff_guard.locator("button.btn-diff-provenance").click()
        page.wait_for_selector("#modal-provenance-drilldown", state="visible")

        modal_text = page.locator("#provenance-modal-content").text_content()
        self.assertIn("UNAVAILABLE", modal_text)
        self.assertIn("None", modal_text)  # Value is None, not 0 or fabricated zeros
        page.locator("#btn-close-modal-provenance").click()

    def test_04_negative_cases_and_error_handling(self):
        """Negative cases: invalid PID, target process exit, Build ID mismatch, missing DWARF, 0 observations."""
        page = self.page
        page.goto(self.base_url)

        # Case A: Invalid PID
        page.locator("#te-target-pid").fill("999999")
        page.locator("#te-companion-elf").fill(self.debug_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#target-conn-badge:has-text('VALIDATION FAILED')")
        self.assertEqual(page.locator("#target-conn-badge").text_content(), "VALIDATION FAILED")

        # Case B: Build ID mismatch (validate against companion binary with different build-id)
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.mismatch_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#diag-feedback-banner:has-text('BUILD_ID_MISMATCH')")
        self.assertIn("BUILD_ID_MISMATCH", page.locator("#diag-feedback-banner").text_content())

        # Case C: Companion binary without DWARF (stripped)
        page.locator("#te-target-pid").fill(str(self.proc.pid))
        page.locator("#te-companion-elf").fill(self.stripped_bin)
        page.locator("#btn-validate-target").click()
        page.wait_for_selector("#diag-feedback-banner:has-text('MISSING_DWARF')")
        self.assertIn("MISSING_DWARF", page.locator("#diag-feedback-banner").text_content())

        # Case D: Target process termination mid-session
        temp_proc = subprocess.Popen(
            [self.stripped_bin],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )
        temp_proc.stdout.readline()
        temp_pid = temp_proc.pid

        temp_session = self.server_runtime.watch_session_manager.create_session(
            pid=temp_pid,
            companion_elf_path=self.debug_bin,
            capture_mode="MANUAL"
        )
        # Capture baseline
        self.server_runtime.watch_session_manager.capture_once(temp_session.session_id)

        # Terminate process
        temp_proc.kill()
        temp_proc.wait()

        # Capture after termination must raise/fail gracefully
        with self.assertRaises(RuntimeError) as ctx:
            self.server_runtime.watch_session_manager.capture_once(temp_session.session_id)
        self.assertIn("not accessible", str(ctx.exception))

        # Case E: Asking investigation question with 0 observations
        # Direct backend verification of temporal investigation 0-observation safety
        from extractor.temporal_investigation import TemporalInvestigationService
        from extractor.investigation import InvestigationSession

        svc = TemporalInvestigationService(watch_manager=self.server_runtime.watch_session_manager)
        dummy_session = self.server_runtime.watch_session_manager.create_session(
            pid=self.proc.pid,
            companion_elf_path=self.debug_bin,
            capture_mode="MANUAL"
        )
        inv_session = InvestigationSession(
            investigation_id="inv_test_0_obs",
            goal="Identify memory boundary approach"
        )

        analysis = svc.analyze_temporal_session(
            investigation_session=inv_session,
            watch_session=dummy_session,
            watch_manager=self.server_runtime.watch_session_manager,
            goal="Identify memory boundary approach"
        )

        self.assertEqual(analysis["status"], "PARTIAL")
        self.assertIn("No Observations Recorded in Watch Session", [f["title"] for f in analysis.get("findings", [])])
        self.assertIn("Zero observations", analysis["summary"].get("error", ""))


if __name__ == "__main__":
    unittest.main()
