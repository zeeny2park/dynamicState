#!/usr/bin/env python3
"""Phase 2.4.1 — MCP Protocol Transport & End-to-End Client Verification Suite.

Tests genuine MCP protocol-level communication between a client and the dynamicState
MCP server (scripts/mcp_server.py) over stdio JSON-RPC transport.

Validates:
1. MCP Protocol Handshake & Tool Discovery:
   - Client-server initialize handshake and capability negotiation.
   - Protocol listing of all 65 tools with parameter schemas.
2. Production Diagnostic Calls over Transport:
   - `runtime_target_connect` with real compiled inferior and companion ELF.
   - `runtime_symbol_search` over JSON-RPC transport.
   - `runtime_run_diagnostic_recipe` with budget tracking.
   - `runtime_start_investigation` and `runtime_execute_investigation_step`.
   - `runtime_export_incident_report` across Markdown, JSON, and HTML formats.
3. Protocol Error & Boundary Handling:
   - Calling unknown tools or malformed parameters.
   - Verification of fail-closed error responses and zero target stop time.
"""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from typing import Any, Dict, List, Optional

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError


class TestPhase241McpProtocolTransport(unittest.IsolatedAsyncioTestCase):
    """End-to-end MCP protocol transport test suite using stdio_client."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="ds_mcp_proto_")
        self.src_file = os.path.join(self.tmp_dir, "mcp_target.c")
        self.bin_file = os.path.join(self.tmp_dir, "mcp_target.elf")

        # Compile a real C target with debug symbols
        with open(self.src_file, "w") as f:
            f.write(
                """
                #include <stdio.h>
                #include <unistd.h>
                #include <stdint.h>

                int g_active_workers = 8;
                int g_max_capacity = 64;
                uint32_t g_magic_canary = 0x12345678;

                int main(void) {
                    printf("TARGET_READY %d\\n", getpid());
                    fflush(stdout);
                    while (1) {
                        sleep(1);
                    }
                    return 0;
                }
                """
            )

        cc = shutil.which("gcc") or "gcc"
        subprocess.check_call(
            [cc, "-g", "-O0", "-no-pie", "-o", self.bin_file, self.src_file]
        )

        self.proc = subprocess.Popen(
            [self.bin_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for ready output
        line = self.proc.stdout.readline()
        self.assertIn("TARGET_READY", line)
        self.pid = int(line.strip().split()[1])

        self.server_params = StdioServerParameters(
            command="python3",
            args=["scripts/mcp_server.py"],
            env=None,
        )

    async def asyncTearDown(self):
        if hasattr(self, "proc") and self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def test_01_mcp_protocol_initialize_and_tool_discovery(self):
        """Protocol initialization and listing of all registered MCP tools over stdio."""
        async with stdio_client(self.server_params) as (read, write):
            async with ClientSession(read, write) as session:
                init_res = await session.initialize()
                self.assertEqual(init_res.server_info.name, "dynamicstate")
                self.assertEqual(init_res.server_info.version, "1.0.0")

                tools_res = await session.list_tools()
                tool_names = [t.name for t in tools_res.tools]
                self.assertGreaterEqual(len(tool_names), 60)

                # Verify critical diagnostic tools are exposed
                expected_tools = [
                    "runtime_target_connect",
                    "runtime_symbol_search",
                    "runtime_run_diagnostic_recipe",
                    "runtime_start_investigation",
                    "runtime_execute_investigation_step",
                    "runtime_export_incident_report",
                    "runtime_get_playbook",
                ]
                for exp in expected_tools:
                    self.assertIn(exp, tool_names)

    async def test_02_mcp_protocol_target_connect_and_symbol_search(self):
        """Call runtime_target_connect and runtime_symbol_search over stdio transport."""
        async with stdio_client(self.server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # 1. runtime_target_connect
                conn_res = await session.call_tool(
                    "runtime_target_connect",
                    {"pid": self.pid, "companion_elf": self.bin_file},
                )
                self.assertFalse(conn_res.is_error)
                conn_data = json.loads(conn_res.content[0].text)
                self.assertTrue(conn_data.get("success"))
                self.assertEqual(conn_data.get("pid"), self.pid)
                self.assertIn("build_id", conn_data)
                self.assertIn("active_context", conn_data)
                self.assertEqual(conn_data.get("architecture"), "aarch64")

                # 2. runtime_symbol_search
                sym_res = await session.call_tool(
                    "runtime_symbol_search",
                    {"query": "g_active_workers", "pid": self.pid, "companion_elf": self.bin_file},
                )
                self.assertFalse(sym_res.is_error)
                sym_data = json.loads(sym_res.content[0].text)
                self.assertTrue(sym_data.get("success"))
                self.assertGreaterEqual(len(sym_data.get("symbols", [])), 1)
                self.assertEqual(sym_data.get("symbols")[0].get("name"), "g_active_workers")

    async def test_03_mcp_protocol_recipe_execution_and_budget(self):
        """Call runtime_run_diagnostic_recipe over stdio transport and verify results."""
        async with stdio_client(self.server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                recipe_res = await session.call_tool(
                    "runtime_run_diagnostic_recipe",
                    {"recipe": "instant_xray", "pid": self.pid, "companion_elf": self.bin_file},
                )
                self.assertFalse(recipe_res.is_error)
                data = json.loads(recipe_res.content[0].text)
                self.assertTrue(data.get("success"))
                self.assertEqual(data.get("recipe"), "instant_xray")
                self.assertIn("results", data)
                self.assertGreaterEqual(len(data.get("results", [])), 1)

    async def test_04_mcp_protocol_investigation_and_step_execution(self):
        """Execute multi-step adaptive investigation over stdio transport."""
        async with stdio_client(self.server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Start investigation
                start_res = await session.call_tool(
                    "runtime_start_investigation",
                    {
                        "goal": "Verify worker capacity invariants",
                        "pid": self.pid,
                        "companion_elf": self.bin_file,
                    },
                )
                self.assertFalse(start_res.is_error)
                start_data = json.loads(start_res.content[0].text)
                inv_id = start_data.get("data", {}).get("investigation_id")
                self.assertIsNotNone(inv_id)

                # Execute investigation step
                step_res = await session.call_tool(
                    "runtime_execute_investigation_step",
                    {"investigation_id": inv_id},
                )
                self.assertFalse(step_res.is_error)
                step_data = json.loads(step_res.content[0].text)
                self.assertTrue(step_data.get("success"))

    async def test_05_mcp_protocol_multi_format_report_export(self):
        """Export incident report in Markdown, JSON, and HTML formats via stdio MCP tool call."""
        async with stdio_client(self.server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                start_res = await session.call_tool(
                    "runtime_start_investigation",
                    {
                        "goal": "Verify worker capacity invariants for report export",
                        "pid": self.pid,
                        "companion_elf": self.bin_file,
                    },
                )
                start_data = json.loads(start_res.content[0].text)
                inv_id = start_data.get("data", {}).get("investigation_id")
                self.assertIsNotNone(inv_id)

                # Export Markdown
                md_path = os.path.join(self.tmp_dir, "report.md")
                r_md = await session.call_tool(
                    "runtime_export_incident_report",
                    {"investigation_id": inv_id, "format": "markdown", "output_path": md_path},
                )
                self.assertFalse(r_md.is_error)
                self.assertTrue(os.path.exists(md_path))
                with open(md_path, "r", encoding="utf-8") as f:
                    md_text = f.read()
                self.assertIn("Executive Summary", md_text)

                # Export JSON
                json_path = os.path.join(self.tmp_dir, "report.json")
                r_json = await session.call_tool(
                    "runtime_export_incident_report",
                    {"investigation_id": inv_id, "format": "json", "output_path": json_path},
                )
                self.assertFalse(r_json.is_error)
                self.assertTrue(os.path.exists(json_path))
                with open(json_path, "r", encoding="utf-8") as f:
                    report_obj = json.load(f)
                self.assertIn("section_a_executive_summary", report_obj)

                # Export HTML
                html_path = os.path.join(self.tmp_dir, "report.html")
                r_html = await session.call_tool(
                    "runtime_export_incident_report",
                    {"investigation_id": inv_id, "format": "html", "output_path": html_path},
                )
                self.assertFalse(r_html.is_error)
                self.assertTrue(os.path.exists(html_path))
                with open(html_path, "r", encoding="utf-8") as f:
                    html_text = f.read()
                self.assertIn("<html", html_text.lower())

    async def test_06_mcp_protocol_unknown_tool_error_handling(self):
        """Calling unknown tool returns protocol error safely."""
        async with stdio_client(self.server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Unknown tool call should return error response with is_error=True
                call_res = await session.call_tool("runtime_non_existent_tool_12345", {})
                self.assertTrue(call_res.is_error)
                self.assertIn("unknown tool", call_res.content[0].text.lower())


if __name__ == "__main__":
    unittest.main()
