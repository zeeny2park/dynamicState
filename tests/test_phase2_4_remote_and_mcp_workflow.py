"""Phase 2.4: Remote Embedded Target Adapter & MCP Protocol E2E Workflow.

Validates:
1. Remote SSH Target Adapter (SIMULATED):
   - Zero-Python on target: pure POSIX shell, /proc, dd, base64
   - Simulated network interruption & timeout recovery
   - Identity matching (start_time, boot_id) across reconnections
   - Detection of target termination or replacement while disconnected
2. End-to-End MCP Protocol Expert Workflow:
   - runtime_target_connect
   - runtime_symbol_search
   - runtime_run_diagnostic_recipe
   - runtime_start_investigation (vague query)
   - runtime_execute_investigation_step
   - runtime_get_investigation_conclusion
   - runtime_export_incident_report (markdown, json, html)
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from typing import List, Tuple

from extractor.target_adapter import (
    PIDReusedError,
    RemoteSshTargetAdapter,
)
from scripts.mcp_server import (
    runtime_target_connect,
    runtime_symbol_search,
    runtime_run_diagnostic_recipe,
    runtime_start_investigation,
    runtime_execute_investigation_step,
    runtime_get_investigation_conclusion,
    runtime_export_incident_report,
)


MCP_WORKFLOW_TARGET_CPP = """
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>

int g_healthy_counter = 42;
int g_buffer_len = 10;
int g_buffer_cap = 100;
std::atomic<bool> g_running{true};

int main() {
    std::cout << "MCP_TARGET_READY" << std::endl;
    std::cout.flush();

    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        g_healthy_counter++;
    }
    return 0;
}
"""


class TestPhase24RemoteAndMcpWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="phase2_4_mcp_")
        cls.src_path = os.path.join(cls.tmpdir, "mcp_target.cpp")
        cls.bin_path = os.path.join(cls.tmpdir, "mcp_target")
        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(MCP_WORKFLOW_TARGET_CPP)

        subprocess.check_call(["g++", "-O0", "-g", cls.src_path, "-o", cls.bin_path])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_01_remote_ssh_adapter_simulated_network_drop_and_recovery(self):
        """Verify RemoteSshTargetAdapter behaves correctly during simulated SSH drops and reconnects."""
        call_count = 0
        should_fail_network = False

        def mock_command_runner(cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
            nonlocal call_count, should_fail_network
            call_count += 1
            cmd_str = " ".join(cmd_args)

            if should_fail_network:
                return -1, "", "ssh: connect to host 192.168.1.100 port 22: Connection timed out"

            # Mock responses for POSIX commands executed by RemoteSshTargetAdapter
            if "kill -0" in cmd_str:
                return 0, "ALIVE\n", ""
            if "boot_id" in cmd_str:
                return 0, "simulated-boot-uuid-1234\n", ""
            if "/stat" in cmd_str:
                # Mock /proc/<pid>/stat output with start_time = 54321
                return 0, "100 (test_target) S 1 100 100 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 1 0 54321 1000 100\n", ""
            if "readlink" in cmd_str:
                return 0, "/usr/bin/embedded_service\n", ""
            if "dd" in cmd_str and "base64" in cmd_str:
                import base64
                dummy_bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08"
                return 0, base64.b64encode(dummy_bytes).decode("ascii") + "\n", ""

            return 0, "", ""

        adapter = RemoteSshTargetAdapter(
            host="192.168.1.100",
            user="root",
            command_runner=mock_command_runner,
        )
        self.assertTrue(adapter.is_remote())
        self.assertEqual(adapter.target_host(), "root@192.168.1.100")

        # 1. Normal liveness and identity check
        alive, reason = adapter.check_liveness(100)
        self.assertTrue(alive)
        ident = adapter.get_process_identity(100)
        self.assertEqual(ident["pid"], 100)
        self.assertEqual(ident["boot_id"], "simulated-boot-uuid-1234")
        self.assertEqual(ident["start_time"], "54321")

        # Pin identity
        pinned = adapter.pin_target_identity(100)
        self.assertIsNotNone(pinned)

        # 2. Simulate network interruption / dropped connection
        should_fail_network = True
        alive_fail, fail_reason = adapter.check_liveness(100)
        self.assertFalse(alive_fail)
        self.assertIn("Connection timed out", fail_reason)

        # 3. Simulate network recovery
        should_fail_network = False
        alive_recov, _ = adapter.check_liveness(100)
        self.assertTrue(alive_recov)

        # Verified pinned identity holds across recovery
        ok_pin, _ = adapter.verify_pinned_identity(100)
        self.assertTrue(ok_pin)

    def test_02_remote_ssh_adapter_detects_pid_reuse_on_target_reboot(self):
        """Verify RemoteSshTargetAdapter detects PID reuse when target reboot changes boot_id."""
        current_boot_id = "initial-boot-id"

        def mock_command_runner(cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
            cmd_str = " ".join(cmd_args)
            if "boot_id" in cmd_str:
                return 0, f"{current_boot_id}\n", ""
            if "/stat" in cmd_str:
                return 0, "200 (worker) S 1 200 200 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 77777 0 0\n", ""
            if "readlink" in cmd_str:
                return 0, "/bin/worker\n", ""
            return 0, "", ""

        adapter = RemoteSshTargetAdapter(
            host="192.168.1.101",
            command_runner=mock_command_runner,
        )
        adapter.pin_target_identity(200)

        # Verify identity matches initially
        ok_pin, _ = adapter.verify_pinned_identity(200)
        self.assertTrue(ok_pin)

        # Target embedded board reboots (boot_id changes)
        current_boot_id = "rebooted-new-boot-id"
        ok_after_reboot, mismatch_reason = adapter.verify_pinned_identity(200)
        self.assertFalse(ok_after_reboot)
        self.assertIn("boot_id", mismatch_reason)

    def test_03_mcp_protocol_expert_workflow_end_to_end(self):
        """Execute complete MCP expert workflow via runtime_* MCP entrypoints:
        1. runtime_target_connect -> binds live process
        2. runtime_symbol_search -> discovers DWARF symbols
        3. runtime_run_diagnostic_recipe -> executes deterministic recipe
        4. runtime_start_investigation -> starts adaptive investigation session
        5. runtime_execute_investigation_step -> advances session
        6. runtime_get_investigation_conclusion -> extracts verdict
        7. runtime_export_incident_report -> generates markdown, json, html reports
        """
        proc = subprocess.Popen([self.bin_path], stdout=subprocess.PIPE, text=True)
        try:
            line = proc.stdout.readline()
            self.assertIn("MCP_TARGET_READY", line)
            pid = proc.pid

            # 1. Connect target
            conn_res_raw = runtime_target_connect(pid=pid, companion_elf=self.bin_path)
            conn_res = json.loads(conn_res_raw)
            self.assertTrue(conn_res.get("success", False))
            self.assertEqual(conn_res.get("pid"), pid)

            # 2. Search symbols
            sym_res_raw = runtime_symbol_search(query="g_healthy_counter", companion_elf=self.bin_path)
            sym_res = json.loads(sym_res_raw)
            self.assertTrue(sym_res.get("success", False))
            self.assertGreater(sym_res.get("returned_count", 0), 0)

            # 3. Run recipe
            recipe_res_raw = runtime_run_diagnostic_recipe(
                recipe="RECIPE_INCONSISTENT_RELATED_VARIABLES",
                pid=pid,
                companion_elf=self.bin_path,
                expressions=["g_buffer_cap", "g_buffer_len"],
            )
            recipe_res = json.loads(recipe_res_raw)
            self.assertTrue(recipe_res.get("success", False))
            # IMP-001: a run whose only check is INCONCLUSIVE now ends INCONCLUSIVE instead of being
            # sealed as a confirmed-clean COMPLETED session.
            self.assertIn(recipe_res.get("outcome"), ("COMPLETED", "INCONCLUSIVE"))
            self.assertIn(recipe_res.get("status"), ("COMPLETED", "INCONCLUSIVE", "PASS"))

            # 4. Start investigation with vague goal
            inv_start_raw = runtime_start_investigation(
                goal="Check whether this process has a memory corruption or variable inconsistency problem",
                pid=pid,
                companion_elf=self.bin_path,
            )
            inv_start = json.loads(inv_start_raw)
            self.assertTrue(inv_start.get("success", False))
            investigation_id = inv_start.get("data", {}).get("investigation_id") or inv_start.get("investigation_id")
            self.assertIsNotNone(investigation_id)

            # 5. Execute investigation steps
            step_res_raw = runtime_execute_investigation_step(
                investigation_id=investigation_id,
            )
            step_res = json.loads(step_res_raw)
            self.assertTrue(step_res.get("success", False))

            # 6. Get investigation conclusion
            conclusion_raw = runtime_get_investigation_conclusion(investigation_id=investigation_id)
            conclusion = json.loads(conclusion_raw)
            self.assertTrue(conclusion.get("success", False))
            self.assertIn("conclusion", conclusion)
            self.assertIn(conclusion["conclusion"].get("status"), ("COMPLETED", "INCONCLUSIVE", "DEFECT_CONFIRMED", "HEALTHY"))

            # 7. Export incident reports across all 3 formats
            rep_md_raw = runtime_export_incident_report(investigation_id=investigation_id, format="markdown")
            rep_md_obj = json.loads(rep_md_raw) if rep_md_raw.strip().startswith("{") else {"report": rep_md_raw}
            report_text = rep_md_obj.get("report") or rep_md_raw
            self.assertIn("dynamicstate", report_text.lower())
            self.assertIn(investigation_id, report_text)

            rep_json_raw = runtime_export_incident_report(investigation_id=investigation_id, format="json")
            rep_json = json.loads(rep_json_raw)
            self.assertTrue(rep_json.get("success", False))
            self.assertEqual(rep_json.get("investigation_id"), investigation_id)

            rep_html_raw = runtime_export_incident_report(investigation_id=investigation_id, format="html")
            rep_html_obj = json.loads(rep_html_raw) if rep_html_raw.strip().startswith("{") else {"html": rep_html_raw}
            html_text = rep_html_obj.get("report") or rep_html_obj.get("html") or rep_html_raw
            self.assertIn("<html", html_text.lower())
            self.assertIn(investigation_id, html_text)

        finally:
            proc.terminate()
            proc.wait()


if __name__ == "__main__":
    unittest.main()
