"""Phase 2.1 — MCP Tools & Web UI REST API Integration Tests.

Verifies:
1. All 9 clean MCP diagnostic tools:
   - `runtime_start_investigation`
   - `runtime_inspect_investigation`
   - `runtime_get_investigation_plan`
   - `runtime_execute_investigation_step`
   - `runtime_get_hypothesis_evidence`
   - `runtime_verify_hypothesis`
   - `runtime_compare_hypotheses`
   - `runtime_get_investigation_conclusion`
   - `runtime_export_incident_report`
2. Web UI REST endpoints for expert investigations:
   - `POST /api/investigations`
   - `GET /api/investigations/:id`
   - `GET /api/investigations/:id/plan`
   - `POST /api/investigations/:id/step`
   - `POST /api/investigations/:id/verify`
   - `GET /api/investigations/:id/conclusion`
   - `GET /api/investigations/:id/export`
   - `POST /api/investigations/:id/pause`
   - `POST /api/investigations/:id/resume`
"""

import json
import os
import subprocess
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.web.server import WebApiAdapter
import scripts.mcp_server as mcp_srv


class TestPhase21McpAndUiIntegration(unittest.TestCase):
    """Test suite for MCP tools and Web REST API integration."""

    def setUp(self):
        self.runtime = AgentRuntime(corpus_dir="/tmp/phase2_1_mcp_corpus")
        self.web_adapter = WebApiAdapter(self.runtime)
        self.companion_elf = "/tmp/expert_diagnostic_debug.elf"
        self.proc = subprocess.Popen([self.companion_elf, "healthy"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.15)
        self.pid = self.proc.pid

    def tearDown(self):
        try:
            if self.proc.stdout:
                self.proc.stdout.close()
            if self.proc.stderr:
                self.proc.stderr.close()
            self.proc.terminate()
            self.proc.wait(timeout=1.0)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass

    def test_mcp_all_9_tools_lifecycle_flow(self):
        """Verifies end-to-end execution across the 9 MCP expert diagnostic tools."""
        # 1. runtime_start_investigation
        raw_start = mcp_srv.runtime_start_investigation(
            problem_statement="Investigate deadlock in worker threads",
            pid=self.pid,
            companion_elf=self.companion_elf,
        )
        res_start = json.loads(raw_start)
        self.assertTrue(res_start["success"])
        inv_id = res_start["data"]["investigation_id"]
        self.assertTrue(inv_id.startswith("inv_"))
        self.assertIn("plan", res_start["data"])

        # 2. runtime_inspect_investigation
        raw_inspect = mcp_srv.runtime_inspect_investigation(investigation_id=inv_id)
        res_inspect = json.loads(raw_inspect)
        self.assertTrue(res_inspect["success"])
        self.assertEqual(res_inspect["investigation_id"], inv_id)
        self.assertIn("progress_percentage", res_inspect)
        self.assertIn("next_recommended_action", res_inspect)

        # 3. runtime_get_investigation_plan
        raw_plan = mcp_srv.runtime_get_investigation_plan(investigation_id=inv_id)
        res_plan = json.loads(raw_plan)
        self.assertTrue(res_plan["success"])
        self.assertGreater(len(res_plan["plan"]["steps"]), 0)
        first_step_id = res_plan["plan"]["steps"][0]["step_id"]

        # 4. runtime_execute_investigation_step
        raw_step = mcp_srv.runtime_execute_investigation_step(
            investigation_id=inv_id,
            step_id=first_step_id,
        )
        res_step = json.loads(raw_step)
        self.assertTrue(res_step["success"])
        self.assertEqual(res_step["investigation_id"], inv_id)

        # 5. runtime_verify_hypothesis
        raw_verify = mcp_srv.runtime_verify_hypothesis(
            investigation_id=inv_id,
            hypothesis_id="HYP_01",
        )
        res_verify = json.loads(raw_verify)
        self.assertTrue(res_verify["success"])
        self.assertEqual(res_verify["investigation_id"], inv_id)

        # 6. runtime_get_hypothesis_evidence
        raw_ev = mcp_srv.runtime_get_hypothesis_evidence(
            investigation_id=inv_id,
            hypothesis_id="HYP_01",
        )
        res_ev = json.loads(raw_ev)
        self.assertTrue(res_ev["success"])
        self.assertEqual(res_ev["hypothesis_id"], "HYP_01")

        # 7. runtime_compare_hypotheses
        raw_cmp = mcp_srv.runtime_compare_hypotheses(
            investigation_id=inv_id,
            hypothesis_ids=["HYP_01"],
        )
        res_cmp = json.loads(raw_cmp)
        self.assertTrue(res_cmp["success"])
        self.assertEqual(res_cmp["compared_count"], 1)

        # 8. runtime_get_investigation_conclusion
        raw_concl = mcp_srv.runtime_get_investigation_conclusion(investigation_id=inv_id)
        res_concl = json.loads(raw_concl)
        self.assertTrue(res_concl["success"])
        self.assertIsNotNone(res_concl["conclusion"])
        self.assertIn("primary_finding", res_concl["conclusion"])

        # 9. runtime_export_incident_report (Markdown)
        out_md_path = "/tmp/phase2_1_incident_report.md"
        raw_exp = mcp_srv.runtime_export_incident_report(
            investigation_id=inv_id,
            format="markdown",
            output_path=out_md_path,
        )
        res_exp = json.loads(raw_exp)
        self.assertTrue(res_exp["success"])
        self.assertTrue(os.path.exists(out_md_path))
        with open(out_md_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("dynamicState Expert Diagnostic Incident Report", content)
            self.assertIn(inv_id, content)

    def test_web_api_rest_endpoints(self):
        """Verifies WebApiAdapter REST methods for expert investigation."""
        # Start investigation
        start_res = self.web_adapter.start_expert_investigation({
            "problem_statement": "Worker heap allocation growth and memory leak",
            "pid": self.pid,
            "companion_elf": self.companion_elf,
        })
        self.assertTrue(start_res["success"])
        inv_id = start_res["investigation_id"]

        # Get investigation
        get_res = self.web_adapter.get_expert_investigation(inv_id)
        self.assertTrue(get_res["success"])
        self.assertEqual(get_res["investigation_id"], inv_id)

        # Get plan
        plan_res = self.web_adapter.get_expert_investigation_plan(inv_id)
        self.assertTrue(plan_res["success"])
        self.assertGreater(plan_res["plan"]["total_steps"], 0)

        # Step
        step_res = self.web_adapter.execute_expert_investigation_step(inv_id)
        self.assertTrue(step_res["success"])

        # Pause and resume
        pause_res = self.web_adapter.pause_expert_investigation(inv_id)
        self.assertTrue(pause_res["success"])
        self.assertTrue(pause_res["is_paused"])

        resume_res = self.web_adapter.resume_expert_investigation(inv_id)
        self.assertTrue(resume_res["success"])
        self.assertFalse(resume_res["is_paused"])

        # Conclusion & Export
        concl_res = self.web_adapter.get_expert_investigation_conclusion(inv_id)
        self.assertTrue(concl_res["success"])

        exp_res = self.web_adapter.export_expert_investigation(inv_id, format="json")
        self.assertTrue(exp_res["success"])
        self.assertIn("investigation_id", exp_res["report"])


if __name__ == "__main__":
    unittest.main()
