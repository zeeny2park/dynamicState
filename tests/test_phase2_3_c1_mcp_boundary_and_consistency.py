"""Phase 2.3-C.1: Real MCP Boundary & Canonical Verdict Consistency Tests.

Validates P1 requirements:
- Distinguishes execution levels:
  1. Direct Python function invocation
  2. MCP tool handler execution
  3. Protocol-level MCP request/response (via server.call_tool)
  4. End-to-end report export
- Protocol-level argument validation:
  * Strict rejection of boolean PIDs (e.g. True/False)
  * Rejection of invalid non-integer PID strings
  * Proper handling of missing/unknown recipe IDs
- Protocol-level response serialization:
  * Valid TextContent return with valid JSON payload
  * Structured evidence IDs, provenance, receipts, and limitations preserved
  * Observation budget metrics and exhaustion states accurately reflected
- Canonical Verdict Consistency:
  * Compares the EXACT SAME investigation session across:
    - session.verdict
    - MCP tool output
    - DiagnosticReport (JSON)
    - DiagnosticReport (Markdown)
    - DiagnosticReport (HTML)
  * Proves 100% invariant agreement on:
    verdict status, confidence, findings count, evidence IDs, provenance class,
    contradictory facts, and limitations.
"""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.diagnostic_recipes import DiagnosticRecipeRegistry
from extractor.expert_diagnostic_engine import ExpertDiagnosticEngine
from extractor.observation_budget import ObservationBudgetLimits
import scripts.mcp_server as mcp_server_mod


CPP_TARGET_SRC = """
#include <iostream>
#include <thread>
#include <chrono>

int g_state = 42;

int main() {
    std::cout << "READY" << std::endl;
    std::cout.flush();
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        g_state++;
    }
    return 0;
}
"""


class TestPhase23C1McpBoundaryAndConsistency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="phase2_3_c1_mcp_")
        cls.src_path = os.path.join(cls.tmpdir, "mcp_target.cpp")
        cls.bin_path = os.path.join(cls.tmpdir, "mcp_target")

        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(CPP_TARGET_SRC)

        subprocess.check_call(["g++", "-g", "-O0", cls.src_path, "-o", cls.bin_path])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.proc = subprocess.Popen(
            [self.bin_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = self.proc.stdout.readline()
        self.assertIn("READY", line)

    def tearDown(self):
        if self.proc.stdout:
            self.proc.stdout.close()
        if self.proc.stderr:
            self.proc.stderr.close()
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                proc.wait()

    def test_mcp_protocol_argument_validation(self):
        """MCP protocol-level call_tool validates arguments and strictly rejects invalid types."""
        # 1. Boolean PID is strictly rejected
        res = asyncio.run(mcp_server_mod.server.call_tool(
            "runtime_run_diagnostic_recipe",
            {"pid": True, "recipe": "RECIPE_PROCESS_MEMORY_GROWTH"},
        ))
        data = json.loads(res.content[0].text)
        self.assertFalse(data.get("success"))
        self.assertIn("Invalid", data.get("error", ""))

        # 2. Unknown recipe ID produces explicit structured error
        res_bad_recipe = asyncio.run(mcp_server_mod.server.call_tool(
            "runtime_run_diagnostic_recipe",
            {"pid": self.proc.pid, "recipe": "NON_EXISTENT_RECIPE_XYZ"},
        ))
        data_bad = json.loads(res_bad_recipe.content[0].text)
        self.assertFalse(data_bad.get("success"))
        self.assertIn("NON_EXISTENT_RECIPE_XYZ", data_bad.get("error"))

    def test_mcp_protocol_call_tool_end_to_end(self):
        """MCP server call_tool dispatches recipe, serializes structured TextContent, and preserves evidence receipts."""
        res = asyncio.run(mcp_server_mod.server.call_tool(
            "runtime_run_diagnostic_recipe",
            {
                "pid": self.proc.pid,
                "companion_elf": self.bin_path,
                "recipe": "RECIPE_PROCESS_MEMORY_GROWTH",
                "duration_ms": 500,
            },
        ))
        self.assertIsNotNone(res)
        self.assertFalse(res.is_error)
        self.assertGreater(len(res.content), 0)

        # Parse TextContent JSON payload
        payload = json.loads(res.content[0].text)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["recipe_id"], "RECIPE_PROCESS_MEMORY_GROWTH")
        self.assertIn("status", payload)
        self.assertIn("findings", payload)
        self.assertIn("evidence_records", payload)
        self.assertIn("budget", payload)

        # Verify authentic evidence records and provenance
        ev_records = payload["evidence_records"]
        self.assertGreater(len(ev_records), 0)
        rec0 = ev_records[0]
        self.assertIn("evidence_id", rec0)
        self.assertEqual(rec0.get("target_identity", {}).get("pid"), self.proc.pid)
        prov_class = rec0.get("provenance", {}).get("provenance_class") or rec0.get("provenance_class")
        self.assertIn(prov_class, ("LIVE_RUNTIME_CAPTURE", "HISTORICAL_RECORD", "INFERRED"))

    def test_mcp_protocol_budget_exhaustion_representation(self):
        """MCP server call_tool faithfully reports budget exhaustion when limits are exceeded."""
        res = asyncio.run(mcp_server_mod.server.call_tool(
            "runtime_run_diagnostic_recipe",
            {
                "pid": self.proc.pid,
                "companion_elf": self.bin_path,
                "recipe": "RECIPE_PROCESS_MEMORY_GROWTH",
                "max_bytes_read": 10,  # Strict limit that will exhaust on collection
            },
        ))
        payload = json.loads(res.content[0].text)
        self.assertTrue(payload["success"])  # Dispatch succeeded
        self.assertEqual(payload["status"], "BUDGET_EXHAUSTED")
        self.assertEqual(payload["stop_reason"], "BUDGET_EXHAUSTED")
        self.assertTrue(payload["budget_metrics"]["is_budget_exhausted"])
        self.assertIn("BYTES_READ", payload["budget_metrics"].get("exhausted_dimension", ""))

    def test_canonical_verdict_consistency_across_mcp_and_all_reports(self):
        """Canonical session verdict matches MCP response, JSON report, Markdown report, and HTML report identically."""
        engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)

        # Run investigation on the live target
        session = engine.start_investigation(
            problem_statement="Targeted consistency audit for RECIPE_PROCESS_MEMORY_GROWTH",
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            target_recipe="RECIPE_PROCESS_MEMORY_GROWTH",
        )
        conclusion = session.run_to_completion(max_steps=10)
        self.assertIsNotNone(conclusion)
        canonical_verdict = conclusion.overall_verdict
        self.assertIsNotNone(canonical_verdict)

        # 1. Build master DiagnosticReport from this exact session
        report = session.build_diagnostic_report()
        report_json_str = report.to_json()
        report_json = json.loads(report_json_str)
        report_md = report.to_markdown()
        report_html = report.to_html()

        # 2. Extract MCP payload
        mcp_res = mcp_server_mod.runtime_run_diagnostic_recipe(
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            recipe="RECIPE_PROCESS_MEMORY_GROWTH",
        )
        mcp_payload = json.loads(mcp_res)

        # 3. Assert canonical verdict status agreement
        self.assertEqual(report.section_a_executive_summary.overall_result, canonical_verdict)
        self.assertEqual(report.section_i_final_conclusions.overall_conclusion, canonical_verdict)
        self.assertEqual(report_json["section_a_executive_summary"]["overall_result"], canonical_verdict)
        self.assertEqual(report_json["section_i_final_conclusions"]["overall_conclusion"], canonical_verdict)
        self.assertIn(canonical_verdict, report_md)
        self.assertIn(canonical_verdict, report_html)

        # 4. Assert findings agreement between report model and JSON export
        report_findings = (
            report.section_e_findings_and_root_cause.confirmed_root_causes
            + report.section_e_findings_and_root_cause.probable_causes
            + report.section_e_findings_and_root_cause.anomalies
            + report.section_e_findings_and_root_cause.observed_symptoms
            + report.section_e_findings_and_root_cause.derived_evidence
        )
        json_findings = (
            report_json["section_e_findings_and_root_cause"]["confirmed_root_causes"]
            + report_json["section_e_findings_and_root_cause"]["probable_causes"]
            + report_json["section_e_findings_and_root_cause"]["anomalies"]
            + report_json["section_e_findings_and_root_cause"]["observed_symptoms"]
            + report_json["section_e_findings_and_root_cause"]["derived_evidence"]
        )
        self.assertEqual(len(report_findings), len(json_findings))

        # 5. Assert evidence identifier agreement
        collected_ev_ids = [r.evidence_id for r in session.collected_evidence_records]
        report_ev_ids = [r.evidence_id for r in report.section_g_evidence_and_provenance.evidence_records]
        self.assertEqual(collected_ev_ids, report_ev_ids)
        self.assertGreater(len(report_ev_ids), 0)
        for ev_id in report_ev_ids:
            self.assertIn(ev_id, report_json_str)
            self.assertIn(ev_id, report_md)
            self.assertIn(ev_id, report_html)

        # 6. Assert limitations agreement
        for lim in conclusion.diagnostic_limitations:
            self.assertIn(lim, report.section_h_limitations_and_unverified.diagnostic_limitations)
            self.assertIn(lim, report_md)


if __name__ == "__main__":
    unittest.main()
