"""Investigation workflow through the web adapter (WebApiAdapter): successful, partial, empty and failed investigations.

The HTTP routes and the page that used these functions (the removed legacy UI) are gone; the functions are called directly.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.investigation import InvestigationManager
from extractor.snapshot_consistency import NON_ATOMIC, STOPPED
from extractor.web.server import WebApiAdapter
from tests.support.fixture_process import fixture_popen


class TestInvestigationUI(unittest.TestCase):
    """Investigation functions of the web adapter."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="dynstate_ui_test_")
        cls.corpus_dir = os.path.join(cls.tmp_dir, "corpus")
        cls.runtime = AgentRuntime(corpus_dir=cls.corpus_dir)

        # Seed two distinct snapshots for comparison and investigation
        cls.snap_alpha = {
            "snapshot_id": "snap_alpha_ui",
            "timestamp": "2026-10-11T03:00:00Z",
            "process": {"pid": 2048, "binary": "/bin/worker_app"},
            "executable_build_id": "112233445566",
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_channel",
                        "type": "DataChannel",
                        "address": 0x8000,
                        "fields": [
                            {"name": "buffer_capacity", "type": "int", "value": 1024},
                            {"name": "state", "type": "int", "value": 1},
                        ],
                    }
                ]
            },
            "execution": {"threads": []},
            "consistency": {"level": STOPPED},
        }

        cls.snap_beta = {
            "snapshot_id": "snap_beta_ui",
            "timestamp": "2026-10-11T03:05:00Z",
            "process": {"pid": 2048, "binary": "/bin/worker_app"},
            "executable_build_id": "112233445566",
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_channel",
                        "type": "DataChannel",
                        "address": 0x8000,
                        "fields": [
                            {"name": "buffer_capacity", "type": "int", "value": 1024},
                            {"name": "state", "type": "int", "value": 2},  # Changed value
                        ],
                    }
                ]
            },
            "execution": {"threads": []},
            "consistency": {"level": NON_ATOMIC},  # Generates uncertainty notice
        }

        cls.runtime.corpus.add(cls.snap_alpha)
        cls.runtime.corpus.add(cls.snap_beta)
        cls.runtime.investigation_manager.corpus.add(cls.snap_alpha)
        cls.runtime.investigation_manager.corpus.add(cls.snap_beta)

        # The investigation functions the removed legacy UI reached over HTTP, called directly.
        cls.adapter = WebApiAdapter(cls.runtime)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_successful_investigation_workflow_api(self):
        """Test full investigation workflow from start to report through the web adapter."""
        # 1. Start investigation
        resp = self.adapter.start_investigation({
            "goal": "Verify data channel state transition",
            "snapshot_id": "snap_alpha_ui",
            "budgets": {"max_objects": 20, "timeout_ms": 2000},
        })
        self.assertTrue(resp.get("success"))
        data = resp["data"]
        inv_id = data["investigation_id"]
        self.assertIn("inv_", inv_id)
        self.assertIn(data["status"], ["PARTIAL", "COMPLETED"])

        # 2. Get Status
        resp = self.adapter.get_investigation_status(inv_id)
        self.assertTrue(resp.get("success"))
        status_data = resp["data"]
        self.assertEqual(status_data["investigation_id"], inv_id)
        self.assertIn("stages", status_data)
        self.assertEqual(status_data["stages"]["report_synthesis"]["status"], "COMPLETED")
        self.assertGreater(status_data["evidence_count"], 0)

        # 3. Get Evidence
        resp = self.adapter.get_evidence(inv_id)
        self.assertTrue(resp.get("success"))
        ev_data = resp["data"]
        self.assertIn("records", ev_data)
        self.assertGreater(len(ev_data["records"]), 0)
        first_ev_id = ev_data["records"][0]["evidence_id"]

        # Follow Evidence
        resp = self.adapter.follow_evidence(inv_id, first_ev_id)
        self.assertTrue(resp.get("success"))
        self.assertEqual(resp["data"]["evidence_id"], first_ev_id)

        # 4. Compare Observations
        resp = self.adapter.compare_observations({
            "investigation_id": inv_id,
            "snapshot_a": "snap_alpha_ui",
            "snapshot_b": "snap_beta_ui",
        })
        self.assertTrue(resp.get("success"))
        cmp_data = resp["data"]
        self.assertEqual(cmp_data["summary"]["value_changes"], 1)
        self.assertIsNotNone(cmp_data["uncertainty"])  # snap_beta_ui is NON_ATOMIC

        # 5. Get Next Steps
        resp = self.adapter.get_next_steps(inv_id)
        self.assertTrue(resp.get("success"))
        steps_list = resp["data"].get("next_steps", resp["data"]) if isinstance(resp["data"], dict) else resp["data"]
        self.assertIsInstance(steps_list, list)
        self.assertGreater(len(steps_list), 0)


        # 6. Get Report
        resp = self.adapter.get_investigation_report(inv_id)
        self.assertTrue(resp.get("success"))
        rep = resp["data"]
        self.assertEqual(rep["investigation_id"], inv_id)
        self.assertIn("findings", rep)
        self.assertIn("observed_facts", rep["findings"])
        self.assertIn("recommended_next_steps", rep)
        self.assertIn("evidence_ledger", rep)

        # 7. List all investigations
        resp = self.adapter.list_investigations()
        self.assertTrue(resp.get("success"))
        self.assertIsInstance(resp["data"], list)
        self.assertIn(inv_id, [i["investigation_id"] for i in resp["data"]])

    def test_partial_and_empty_investigation_handling(self):
        """Test honest reporting of partial and empty investigation targets."""
        # Start investigation on nonexistent snapshot -> Empty/Partial handling
        resp = self.adapter.start_investigation({
            "goal": "Empty target investigation",
            "snapshot_id": "snap_nonexistent_999",
        })
        self.assertTrue(resp.get("success"))
        data = resp["data"]
        inv_id = data["investigation_id"]
        # Semantic interpretation should be partial with 0 facts claimed
        self.assertEqual(data["stages"]["semantic_interpretation"]["status"], "PARTIAL")
        self.assertEqual(data["findings_count"], 0)

        # Report synthesis accurately reflects empty findings
        resp = self.adapter.get_investigation_report(inv_id)
        self.assertTrue(resp.get("success"))
        rep = resp["data"]
        self.assertEqual(len(rep["findings"]["observed_facts"]), 0)
        self.assertEqual(rep["findings_summary"]["total"], 0)

    def test_failed_and_invalid_requests(self):
        """Test clean error handling for invalid investigation requests."""
        # 1. Nonexistent investigation ID
        resp = self.adapter.get_investigation_status("inv_does_not_exist")
        self.assertFalse(resp.get("success"))
        self.assertEqual(resp["error"]["code"], "NOT_FOUND")

        # 2. Missing investigation_id in compare
        resp = self.adapter.compare_observations({
            "snapshot_a": "snap_alpha_ui",
            "snapshot_b": "snap_beta_ui",
        })
        self.assertFalse(resp.get("success"))
        self.assertEqual(resp["error"]["code"], "INVALID_PARAM")

        # 3. Missing investigation_id in get status
        resp = self.adapter.get_investigation_status(None)
        self.assertFalse(resp.get("success"))
        self.assertEqual(resp["error"]["code"], "INVALID_PARAM")

    def test_follow_evidence_returns_provenance_lineage(self):
        """Verify follow_evidence returns provenance_chain for evidence records."""
        # 1. Start investigation
        resp = self.adapter.start_investigation({
            "goal": "Verify provenance lineage trace",
            "snapshot_id": "snap_alpha_ui",
        })
        inv_id = resp["data"]["investigation_id"]

        # 2. Get evidence list
        resp = self.adapter.get_evidence(inv_id)
        records = resp["data"]["records"]
        self.assertGreater(len(records), 0)
        first_eid = records[0]["evidence_id"]

        # 3. Follow evidence
        resp = self.adapter.follow_evidence(inv_id, first_eid)
        data = resp["data"]
        self.assertEqual(data["evidence_id"], first_eid)
        self.assertIn("provenance_chain", data)
        self.assertIsInstance(data["provenance_chain"], list)

    def test_compare_observations_returns_diff_changes(self):
        """Verify compare_observations returns structured diff changes list."""
        resp = self.adapter.start_investigation({
            "goal": "Test compare diff changes",
            "snapshot_id": "snap_alpha_ui",
        })
        inv_id = resp["data"]["investigation_id"]

        resp = self.adapter.compare_observations({
            "investigation_id": inv_id,
            "snapshot_a": "snap_alpha_ui",
            "snapshot_b": "snap_beta_ui",
        })
        data = resp["data"]
        self.assertIn("changes", data)
        self.assertIsInstance(data["changes"], list)
        self.assertGreater(len(data["changes"]), 0)
        # Verify first change has field path, kind, before, after
        chg = data["changes"][0]
        self.assertIn("path", chg)
        self.assertIn("kind", chg)


    def test_live_target_pid_propagation_and_validation(self):
        """Regression test for P1: Live target PID transmission, range checking, authorization, and capture."""
        # Spawn an isolated target child process for live capture testing
        child_proc = fixture_popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            target_pid = child_proc.pid

            # 1. Valid live PID with explicit authorization -> Live capture executed
            resp = self.adapter.start_investigation({
                "goal": "Live process capture test",
                "pid": target_pid,
                "authorize_target": True,
            })
            self.assertTrue(resp.get("success"))
            data = resp["data"]
            self.assertIn("inv_", data["investigation_id"])
            self.assertEqual(data["target_ref"]["pid"], target_pid)
            self.assertTrue(data["target_ref"].get("live_capture"))
            self.assertEqual(data["target_ref"].get("capture_source"), "LIVE_PROCESS")
            self.assertEqual(data["persistence"], "EPHEMERAL_PROCESS_LOCAL")

            # 2. Live PID without authorization -> BLOCKED
            resp = self.adapter.start_investigation({
                "goal": "Unauthorized live capture attempt",
                "pid": target_pid,
                "authorize_target": False,
            })
            self.assertTrue(resp.get("success"))
            data = resp["data"]
            self.assertEqual(data["status"], "BLOCKED")
            self.assertEqual(data["stages"]["target_identity"]["status"], "BLOCKED")
            self.assertIn("authorize_target=True", data["stages"]["target_identity"]["details"]["error"])
            auth_fnd = next((f for f in data["findings"] if "Authorization" in f["title"]), None)
            self.assertIsNotNone(auth_fnd)

            # 3. Invalid PID format -> INVALID_PARAM
            resp = self.adapter.start_investigation({
                "goal": "Invalid PID format test",
                "pid": "invalid_pid_string",
                "authorize_target": True,
            })
            self.assertFalse(resp.get("success"))
            self.assertEqual(resp["error"]["code"], "INVALID_PARAM")
            self.assertIn("Invalid PID format", resp["error"]["message"])

            # 4. Out-of-range negative PID -> INVALID_PARAM
            resp = self.adapter.start_investigation({
                "goal": "Negative PID test",
                "pid": -42,
                "authorize_target": True,
            })
            self.assertFalse(resp.get("success"))
            self.assertEqual(resp["error"]["code"], "INVALID_PARAM")
            self.assertIn("out of valid range", resp["error"]["message"])

            # 5. Conflicting live PID and offline snapshot -> INVALID_PARAM
            resp = self.adapter.start_investigation({
                "goal": "Ambiguous target parameters test",
                "pid": target_pid,
                "snapshot_id": "snap_alpha_ui",
                "authorize_target": True,
            })
            self.assertFalse(resp.get("success"))
            self.assertEqual(resp["error"]["code"], "INVALID_PARAM")
            self.assertIn("Conflicting target parameters", resp["error"]["message"])

            # 6. Non-existent PID with authorization -> TARGET_NOT_FOUND (ESRCH)
            resp = self.adapter.start_investigation({
                "goal": "Non-existent PID test",
                "pid": 999999999,
                "authorize_target": True,
            })
            self.assertFalse(resp.get("success"))
            self.assertEqual(resp["error"]["code"], "TARGET_NOT_FOUND")
            self.assertIn("ESRCH", resp["error"]["message"])
        finally:
            child_proc.kill()
            child_proc.wait()

    def test_scoped_zero_findings_messaging(self):
        """Regression test for P1: Honest zero-findings reporting and explicit analysis scope bounds."""
        # Start investigation on empty/non-existent snapshot
        resp = self.adapter.start_investigation({
            "goal": "Zero-findings scope verification",
            "snapshot_id": "snap_nonexistent_empty",
        })
        self.assertTrue(resp.get("success"))
        data = resp["data"]
        inv_id = data["investigation_id"]

        # Status response contains scope measurements and honest notice
        status_resp = self.adapter.get_investigation_status(inv_id)
        summary = status_resp["data"]["summary"]
        self.assertIn("scope", summary)
        self.assertIn("unresolved_checks", summary["scope"])
        self.assertGreater(len(summary["scope"]["unresolved_checks"]), 0)

        # Incomplete / partial investigation with 0 findings does NOT claim clean validation
        self.assertIn("zero_findings_notice", summary)
        self.assertIn("incomplete or restricted", summary["zero_findings_notice"])

        # Report response contains scoped findings_summary
        rep_resp = self.adapter.get_investigation_report(inv_id)
        findings_summary = rep_resp["data"]["findings_summary"]
        self.assertEqual(findings_summary["total"], 0)
        self.assertIn("scope", findings_summary)
        self.assertIn("zero_findings_notice", findings_summary)

    def test_investigation_session_loading_and_selection_preservation(self):
        """Verify session loading API, non-latest selection preservation, and ephemeral reporting."""
        # 1. Start session Alpha
        resp_a = self.adapter.start_investigation({
            "goal": "Session Alpha for selection test",
            "snapshot_id": "snap_alpha_ui",
        })
        inv_a = resp_a["data"]["investigation_id"]

        # 2. Start session Beta
        resp_b = self.adapter.start_investigation({
            "goal": "Session Beta for selection test",
            "snapshot_id": "snap_beta_ui",
        })
        inv_b = resp_b["data"]["investigation_id"]

        # 3. List sessions: both must be present in order
        resp_list = self.adapter.list_investigations()
        sessions = resp_list["data"]
        ids = [s["investigation_id"] for s in sessions]
        self.assertIn(inv_a, ids)
        self.assertIn(inv_b, ids)

        # 4. User selects Alpha (not latest): report returns Alpha specifically
        rep_a = self.adapter.get_investigation_report(inv_a)
        self.assertEqual(rep_a["data"]["investigation_id"], inv_a)
        self.assertEqual(rep_a["data"]["goal"], "Session Alpha for selection test")

        # 5. Stale / nonexistent session ID handling
        rep_stale = self.adapter.get_investigation_report("inv_stale_99999")
        self.assertIn("error", rep_stale)

    def test_clean_completed_zero_findings_scope_distinction(self):
        """Verify distinction between COMPLETED with 0 findings vs PARTIAL with 0 findings."""
        # 1. Start investigation on valid snapshot with 0 anomalies (clean state)
        resp = self.adapter.start_investigation({
            "goal": "Clean verification test",
            "snapshot_id": "snap_alpha_ui",
        })
        data = resp["data"]
        self.assertIn(data["status"], ["COMPLETED", "PARTIAL"])
        scope = data["summary"]["scope"]
        self.assertIn("objects_examined", scope)
        self.assertIn("roots_examined", scope)
        self.assertIn("unresolved_checks", scope)

        # 2. Start investigation on nonexistent snapshot (partial state with 0 findings)
        resp_partial = self.adapter.start_investigation({
            "goal": "Partial verification test",
            "snapshot_id": "snap_missing_artifact",
        })
        partial_data = resp_partial["data"]
        self.assertEqual(partial_data["status"], "PARTIAL")
        self.assertEqual(partial_data["findings_count"], 0)
        notice = partial_data["summary"].get("zero_findings_notice")
        self.assertIsNotNone(notice)
        self.assertIn("incomplete or restricted", notice)


if __name__ == "__main__":
    unittest.main()

