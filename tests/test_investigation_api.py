"""Automated tests for Investigation API and Safety Boundaries.

Tests acceptance criteria 6 and 8:
6. Investigation API using existing functionality and offline snapshots.
8. Read-only defaults and explicit authorization boundaries.
"""

import os
import shutil
import tempfile
import unittest

from extractor.agent_models import AgentAction
from extractor.agent_runtime import AgentRuntime
from extractor.investigation import InvestigationManager
from extractor.snapshot_consistency import STOPPED


class TestInvestigationAPIAndSafety(unittest.TestCase):
    """Test investigation workflow API, ARP action dispatch, and safety boundaries."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="dynstate_api_test_")
        self.mgr = InvestigationManager(corpus_dir=self.temp_dir)
        self.runtime = AgentRuntime(corpus_dir=self.temp_dir)

        # Seed sample snapshot in corpus
        self.sample_snapshot = {
            "snapshot_id": "snap_api_001",
            "timestamp": "2026-10-11T02:00:00Z",
            "process": {"pid": 1234, "binary": "/opt/app/bin"},
            "executable_build_id": "abcdef123456",
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_ctx",
                        "type": "AppContext",
                        "address": 0x5000,
                        "fields": [
                            {"name": "is_active", "type": "bool", "value": True},
                            {"name": "worker_ref", "type": "Worker*", "value": "0x6000", "reference": "obj_worker"},
                        ],
                    },
                    {
                        "object_id": "obj_worker",
                        "type": "Worker",
                        "address": 0x6000,
                        "fields": [
                            {"name": "task_id", "type": "int", "value": 42},
                            {"name": "healthy", "type": "bool", "value": False},
                        ],
                    },
                ]
            },
            "execution": {"threads": [{"thread_id": 1234, "state": "SLEEPING"}]},
            "consistency": {"level": STOPPED},
        }
        self.mgr.corpus.add(self.sample_snapshot)
        self.runtime.investigation_manager.corpus.add(self.sample_snapshot)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_investigation_manager_lifecycle(self):
        """Test full manager lifecycle: start, status, evidence, follow, next_steps, report."""
        # 1. Start investigation
        start_res = self.mgr.start_investigation(
            goal="Investigate worker health degradation",
            snapshot_id="snap_api_001",
            budgets={"max_objects": 50, "timeout_ms": 3000},
        )
        inv_id = start_res["investigation_id"]
        self.assertIn(start_res["status"], ["PARTIAL", "COMPLETED"])

        # Verify read-only default safety
        self.assertTrue(start_res["safety"]["read_only"])
        self.assertFalse(start_res["safety"]["target_authorized"])
        self.assertFalse(start_res["safety"]["allow_mutation"])

        # 2. Get Status
        status_res = self.mgr.get_investigation_status(inv_id)
        self.assertEqual(status_res["investigation_id"], inv_id)
        self.assertIn("stages", status_res)
        self.assertEqual(status_res["stages"]["report_synthesis"]["status"], "COMPLETED")
        self.assertGreater(status_res["evidence_count"], 0)
        self.assertGreater(status_res["findings_count"], 0)

        # 3. Get Evidence
        evidence_dict = self.mgr.get_evidence(inv_id)
        self.assertIsInstance(evidence_dict, dict)
        evidence_list = evidence_dict.get("records", [])
        self.assertGreater(len(evidence_list), 0)

        first_ev_id = evidence_list[0]["evidence_id"]
        single_ev = self.mgr.get_evidence(inv_id, evidence_id=first_ev_id)
        self.assertEqual(single_ev["evidence"]["evidence_id"], first_ev_id)


        # 4. Follow Evidence
        follow_res = self.mgr.follow_evidence(inv_id, evidence_id=first_ev_id)
        self.assertEqual(follow_res["evidence_id"], first_ev_id)
        self.assertIn("related_objects", follow_res)
        self.assertIn("related_fields", follow_res)

        # 5. Get Next Steps
        steps = self.mgr.get_next_steps(inv_id)
        self.assertIsInstance(steps, list)
        self.assertGreater(len(steps), 0)
        for s in steps:
            self.assertTrue(s["is_suggestion"])
            self.assertFalse(s["executed"])
            self.assertEqual(s["risk_level"], "READ_ONLY")

        # 6. Generate Report
        report = self.mgr.generate_report(inv_id)
        self.assertEqual(report["investigation_id"], inv_id)
        self.assertEqual(report["goal"], "Investigate worker health degradation")
        self.assertIn("findings", report)
        self.assertIn("observed_facts", report["findings"])
        self.assertIn("hypotheses", report["findings"])
        self.assertIn("unknowns", report["findings"])
        self.assertIn("recommended_next_steps", report)
        self.assertIn("evidence_ledger", report)


    def test_arp_agent_action_dispatch(self):
        """Test investigation workflow via existing Agent Runtime Protocol (ARP)."""
        # Verify capabilities advertised to agents
        caps = self.runtime.capabilities()
        self.assertTrue(caps.success)
        self.assertIn("investigation", caps.data)
        inv_caps = caps.data["investigation"]
        self.assertEqual(inv_caps["capability"], "SUPPORTED")
        self.assertTrue(inv_caps["evidence_ledger"])
        self.assertTrue(inv_caps["offline_investigation"])
        self.assertTrue(inv_caps["observation_comparison"])
        self.assertTrue(inv_caps["read_only_default"])

        # 1. Action: START_INVESTIGATION
        action_start = AgentAction(
            action="START_INVESTIGATION",
            goal="ARP automated investigation test",
            snapshot_id="snap_api_001",
        )
        res_start = self.runtime.dispatch_action(action_start)
        self.assertTrue(res_start.success)
        inv_id = res_start.data["investigation_id"]

        # 2. Action: GET_INVESTIGATION_STATUS
        action_status = AgentAction(
            action="GET_INVESTIGATION_STATUS",
            investigation_id=inv_id,
        )
        res_status = self.runtime.dispatch_action(action_status)
        self.assertTrue(res_status.success)
        self.assertIn(res_status.data["status"], ["PARTIAL", "COMPLETED"])


        # 3. Action: GET_EVIDENCE
        action_ev = AgentAction(
            action="GET_EVIDENCE",
            investigation_id=inv_id,
        )
        res_ev = self.runtime.dispatch_action(action_ev)
        self.assertTrue(res_ev.success)
        ev_items = res_ev.data.get("records") or res_ev.data.get("evidence", [])
        self.assertGreater(len(ev_items), 0)
        target_ev_id = ev_items[0]["evidence_id"]


        # 4. Action: FOLLOW_EVIDENCE
        action_follow = AgentAction(
            action="FOLLOW_EVIDENCE",
            investigation_id=inv_id,
            evidence_id=target_ev_id,
        )
        res_follow = self.runtime.dispatch_action(action_follow)
        self.assertTrue(res_follow.success)

        # 5. Action: GET_NEXT_STEPS
        action_steps = AgentAction(
            action="GET_NEXT_STEPS",
            investigation_id=inv_id,
        )
        res_steps = self.runtime.dispatch_action(action_steps)
        self.assertTrue(res_steps.success)
        self.assertGreater(len(res_steps.data["next_steps"]), 0)

        # 6. Action: GET_INVESTIGATION_REPORT
        action_report = AgentAction(
            action="GET_INVESTIGATION_REPORT",
            investigation_id=inv_id,
        )
        res_report = self.runtime.dispatch_action(action_report)
        self.assertTrue(res_report.success)
        self.assertIn("observed_facts", res_report.data["findings"])



    def test_explicit_authorization_boundary(self):
        """Test strict authorization boundaries when specifying target processes."""
        # Unset authorization: target_authorized is False
        res_unauth = self.mgr.start_investigation(
            goal="Safety test",
            snapshot_id="snap_api_001",
            authorize_target=False,
        )
        self.assertFalse(res_unauth["safety"]["target_authorized"])
        self.assertTrue(res_unauth["safety"]["read_only"])
        self.assertFalse(res_unauth["safety"]["allow_mutation"])

        # Explicit authorization: target_authorized is True, but read_only remains True
        res_auth = self.mgr.start_investigation(
            goal="Safety test authorized",
            snapshot_id="snap_api_001",
            authorize_target=True,
        )
        self.assertTrue(res_auth["safety"]["target_authorized"])
        self.assertTrue(res_auth["safety"]["read_only"])
        self.assertFalse(res_auth["safety"]["allow_mutation"])

    def test_error_handling_for_nonexistent_session(self):
        """Test clean error reporting when accessing nonexistent investigation IDs."""
        status = self.mgr.get_investigation_status("inv_does_not_exist")
        self.assertIn("error", status)

        evidence = self.mgr.get_evidence("inv_does_not_exist")
        self.assertIsInstance(evidence, dict)
        self.assertIn("error", evidence)

        report = self.mgr.generate_report("inv_does_not_exist")
        self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main()
