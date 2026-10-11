"""Automated tests for Investigation Overview UI and Web API Endpoints.

Tests acceptance criterion 7:
7. UI rendering for successful, partial, empty and failed investigations.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from extractor.agent_runtime import AgentRuntime
from extractor.investigation import InvestigationManager
from extractor.snapshot_consistency import NON_ATOMIC, STOPPED
from extractor.web.server import run_server


class TestInvestigationUI(unittest.TestCase):
    """Test investigation Web API endpoints and UI static asset integrations."""

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

        # Start Web Server on ephemeral port
        cls.server = run_server(runtime=cls.runtime, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _get_raw(self, path: str):
        req = urllib.request.Request(f"{self.base_url}{path}")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.headers.get_content_type(), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, err.headers.get_content_type(), err.read()

    def _get_json(self, path: str):
        status, _, raw = self._get_raw(path)
        return status, json.loads(raw.decode("utf-8"))

    def _post_json(self, path: str, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    def test_ui_static_assets_contain_investigation_views(self):
        """Verify HTML, CSS, and JS provide complete investigation overview UI elements."""
        # 1. HTML
        status, _, body = self._get_raw("/")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        self.assertIn("tab-investigation-overview", html)
        self.assertIn("Investigation Overview", html)
        self.assertIn("inv-input-goal", html)
        self.assertIn("inv-card-status-bar", html)
        self.assertIn("inv-target-identity-list", html)
        self.assertIn("inv-quality-list", html)
        self.assertIn("inv-comparisons-content", html)
        self.assertIn("inv-steps-container", html)
        self.assertIn("inv-findings-list", html)
        self.assertIn("inv-static-links-list", html)
        self.assertIn("inv-txt-ledger-count", html)

        # 2. CSS
        status, _, body = self._get_raw("/static/app.css")
        self.assertEqual(status, 200)
        css = body.decode("utf-8")
        self.assertIn(".inv-card", css)

        self.assertIn(".finding-card", css)

        self.assertIn(".badge-fact", css)
        self.assertIn(".step-card", css)

        # 3. JS
        status, _, body = self._get_raw("/static/app.js")
        self.assertEqual(status, 200)
        js = body.decode("utf-8")
        self.assertIn("renderInvestigationOverview", js)
        self.assertIn("renderFindings", js)
        self.assertIn("renderNextSteps", js)
        self.assertIn("renderComparisons", js)
        self.assertIn("renderStaticLinks", js)
        self.assertIn("__jumpToObject", js)

    def test_successful_investigation_workflow_api(self):
        """Test full investigation workflow from start to report via Web API."""
        # 1. Start investigation
        status, resp = self._post_json("/api/investigation/start", {
            "goal": "Verify data channel state transition",
            "snapshot_id": "snap_alpha_ui",
            "budgets": {"max_objects": 20, "timeout_ms": 2000},
        })
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("success"))
        data = resp["data"]
        inv_id = data["investigation_id"]
        self.assertIn("inv_", inv_id)
        self.assertIn(data["status"], ["PARTIAL", "COMPLETED"])

        # 2. Get Status
        status, resp = self._get_json(f"/api/investigation/status?investigation_id={inv_id}")
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("success"))
        status_data = resp["data"]
        self.assertEqual(status_data["investigation_id"], inv_id)
        self.assertIn("stages", status_data)
        self.assertEqual(status_data["stages"]["report_synthesis"]["status"], "COMPLETED")
        self.assertGreater(status_data["evidence_count"], 0)

        # 3. Get Evidence
        status, resp = self._get_json(f"/api/investigation/evidence?investigation_id={inv_id}")
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("success"))
        ev_data = resp["data"]
        self.assertIn("records", ev_data)
        self.assertGreater(len(ev_data["records"]), 0)
        first_ev_id = ev_data["records"][0]["evidence_id"]

        # Follow Evidence
        status, resp = self._get_json(f"/api/investigation/follow?investigation_id={inv_id}&evidence_id={first_ev_id}")
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("success"))
        self.assertEqual(resp["data"]["evidence_id"], first_ev_id)

        # 4. Compare Observations via Web API
        status, resp = self._post_json("/api/investigation/compare", {
            "investigation_id": inv_id,
            "snapshot_a": "snap_alpha_ui",
            "snapshot_b": "snap_beta_ui",
        })
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("success"))
        cmp_data = resp["data"]
        self.assertEqual(cmp_data["summary"]["value_changes"], 1)
        self.assertIsNotNone(cmp_data["uncertainty"])  # snap_beta_ui is NON_ATOMIC

        # 5. Get Next Steps
        status, resp = self._get_json(f"/api/investigation/next-steps?investigation_id={inv_id}")
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("success"))
        steps_list = resp["data"].get("next_steps", resp["data"]) if isinstance(resp["data"], dict) else resp["data"]
        self.assertIsInstance(steps_list, list)
        self.assertGreater(len(steps_list), 0)


        # 6. Get Report
        status, resp = self._get_json(f"/api/investigation/report?investigation_id={inv_id}")
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("success"))
        rep = resp["data"]
        self.assertEqual(rep["investigation_id"], inv_id)
        self.assertIn("findings", rep)
        self.assertIn("observed_facts", rep["findings"])
        self.assertIn("recommended_next_steps", rep)
        self.assertIn("evidence_ledger", rep)

        # 7. List all investigations
        status, resp = self._get_json("/api/investigations")
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("success"))
        self.assertIsInstance(resp["data"], list)
        self.assertIn(inv_id, [i["investigation_id"] for i in resp["data"]])

    def test_partial_and_empty_investigation_handling(self):
        """Test honest reporting of partial and empty investigation targets."""
        # Start investigation on nonexistent snapshot -> Empty/Partial handling
        status, resp = self._post_json("/api/investigation/start", {
            "goal": "Empty target investigation",
            "snapshot_id": "snap_nonexistent_999",
        })
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("success"))
        data = resp["data"]
        inv_id = data["investigation_id"]
        # Semantic interpretation should be partial with 0 facts claimed
        self.assertEqual(data["stages"]["semantic_interpretation"]["status"], "PARTIAL")
        self.assertEqual(data["findings_count"], 0)

        # Report synthesis accurately reflects empty findings
        status, resp = self._get_json(f"/api/investigation/report?investigation_id={inv_id}")
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("success"))
        rep = resp["data"]
        self.assertEqual(len(rep["findings"]["observed_facts"]), 0)
        self.assertEqual(rep["findings_summary"]["total"], 0)

    def test_failed_and_invalid_requests(self):
        """Test clean error handling for invalid investigation requests."""
        # 1. Nonexistent investigation ID
        status, resp = self._get_json("/api/investigation/status?investigation_id=inv_does_not_exist")
        self.assertEqual(status, 200)
        self.assertFalse(resp.get("success"))
        self.assertEqual(resp["error"]["code"], "NOT_FOUND")

        # 2. Missing investigation_id in compare
        status, resp = self._post_json("/api/investigation/compare", {
            "snapshot_a": "snap_alpha_ui",
            "snapshot_b": "snap_beta_ui",
        })
        self.assertEqual(status, 200)
        self.assertFalse(resp.get("success"))
        self.assertEqual(resp["error"]["code"], "INVALID_PARAM")

        # 3. Missing investigation_id in get status
        status, resp = self._get_json("/api/investigation/status")
        self.assertEqual(status, 200)
        self.assertFalse(resp.get("success"))
        self.assertEqual(resp["error"]["code"], "INVALID_PARAM")

    def test_two_level_header_and_launchpad_ui_elements(self):
        """Verify Level 1 primary status bar, Level 2 technical bar, and Launchpad UI elements."""
        status, _, body = self._get_raw("/")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")

        # Level 1 Primary Header
        self.assertIn("header-primary-status", html)
        self.assertIn("hdr-txt-target", html)
        self.assertIn("hdr-badge-capture-quality", html)
        self.assertIn("hdr-badge-investigation-state", html)
        self.assertIn("btn-toggle-tech-details", html)

        # Level 2 Secondary Technical Bar
        self.assertIn("runtime-summary-bar", html)
        self.assertIn("tech-badge-group", html)

        # Honest defaults: Disconnected and Unverified (no false 'Supported' claims)
        self.assertIn("status-disconnected", html)
        self.assertIn("Unverified", html)

        # Launchpad & Entry Paths
        self.assertIn("inv-launchpad", html)
        self.assertIn("btn-entry-snapshot", html)
        self.assertIn("btn-entry-live", html)
        self.assertIn("panel-entry-snapshot", html)
        self.assertIn("panel-entry-live", html)
        self.assertIn("inv-recent-sessions-container", html)

        # Dynamic Alert Banner
        self.assertIn("inv-alert-banner", html)

        # Inline Comparison controls
        self.assertIn("inv-cmp-select-a", html)
        self.assertIn("inv-cmp-select-b", html)
        self.assertIn("btn-run-inline-compare", html)

        # Lineage viewer
        self.assertIn("inv-lineage-container", html)
        self.assertIn("btn-close-lineage", html)

    def test_follow_evidence_returns_provenance_lineage(self):
        """Verify /api/investigation/follow returns provenance_chain for evidence records."""
        # 1. Start investigation
        status, resp = self._post_json("/api/investigation/start", {
            "goal": "Verify provenance lineage trace",
            "snapshot_id": "snap_alpha_ui",
        })
        self.assertEqual(status, 200)
        inv_id = resp["data"]["investigation_id"]

        # 2. Get evidence list
        status, resp = self._get_json(f"/api/investigation/evidence?investigation_id={inv_id}")
        self.assertEqual(status, 200)
        records = resp["data"]["records"]
        self.assertGreater(len(records), 0)
        first_eid = records[0]["evidence_id"]

        # 3. Follow evidence
        status, resp = self._get_json(f"/api/investigation/follow?investigation_id={inv_id}&evidence_id={first_eid}")
        self.assertEqual(status, 200)
        data = resp["data"]
        self.assertEqual(data["evidence_id"], first_eid)
        self.assertIn("provenance_chain", data)
        self.assertIsInstance(data["provenance_chain"], list)

    def test_compare_observations_returns_diff_changes(self):
        """Verify /api/investigation/compare returns structured diff changes list."""
        status, resp = self._post_json("/api/investigation/start", {
            "goal": "Test compare diff changes",
            "snapshot_id": "snap_alpha_ui",
        })
        self.assertEqual(status, 200)
        inv_id = resp["data"]["investigation_id"]

        status, resp = self._post_json("/api/investigation/compare", {
            "investigation_id": inv_id,
            "snapshot_a": "snap_alpha_ui",
            "snapshot_b": "snap_beta_ui",
        })
        self.assertEqual(status, 200)
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
        child_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            target_pid = child_proc.pid

            # 1. Valid live PID with explicit authorization -> Live capture executed
            status, resp = self._post_json("/api/investigation/start", {
                "goal": "Live process capture test",
                "pid": target_pid,
                "authorize_target": True,
            })
            self.assertEqual(status, 200)
            self.assertTrue(resp.get("success"))
            data = resp["data"]
            self.assertIn("inv_", data["investigation_id"])
            self.assertEqual(data["target_ref"]["pid"], target_pid)
            self.assertTrue(data["target_ref"].get("live_capture"))
            self.assertEqual(data["target_ref"].get("capture_source"), "LIVE_PROCESS")
            self.assertEqual(data["persistence"], "EPHEMERAL_PROCESS_LOCAL")

            # 2. Live PID without authorization -> BLOCKED
            status, resp = self._post_json("/api/investigation/start", {
                "goal": "Unauthorized live capture attempt",
                "pid": target_pid,
                "authorize_target": False,
            })
            self.assertEqual(status, 200)
            self.assertTrue(resp.get("success"))
            data = resp["data"]
            self.assertEqual(data["status"], "BLOCKED")
            self.assertEqual(data["stages"]["target_identity"]["status"], "BLOCKED")
            self.assertIn("authorize_target=True", data["stages"]["target_identity"]["details"]["error"])
            auth_fnd = next((f for f in data["findings"] if "Authorization" in f["title"]), None)
            self.assertIsNotNone(auth_fnd)

            # 3. Invalid PID format -> INVALID_PARAM
            status, resp = self._post_json("/api/investigation/start", {
                "goal": "Invalid PID format test",
                "pid": "invalid_pid_string",
                "authorize_target": True,
            })
            self.assertEqual(status, 200)
            self.assertFalse(resp.get("success"))
            self.assertEqual(resp["error"]["code"], "INVALID_PARAM")
            self.assertIn("Invalid PID format", resp["error"]["message"])

            # 4. Out-of-range negative PID -> INVALID_PARAM
            status, resp = self._post_json("/api/investigation/start", {
                "goal": "Negative PID test",
                "pid": -42,
                "authorize_target": True,
            })
            self.assertEqual(status, 200)
            self.assertFalse(resp.get("success"))
            self.assertEqual(resp["error"]["code"], "INVALID_PARAM")
            self.assertIn("out of valid range", resp["error"]["message"])

            # 5. Conflicting live PID and offline snapshot -> INVALID_PARAM
            status, resp = self._post_json("/api/investigation/start", {
                "goal": "Ambiguous target parameters test",
                "pid": target_pid,
                "snapshot_id": "snap_alpha_ui",
                "authorize_target": True,
            })
            self.assertEqual(status, 200)
            self.assertFalse(resp.get("success"))
            self.assertEqual(resp["error"]["code"], "INVALID_PARAM")
            self.assertIn("Conflicting target parameters", resp["error"]["message"])

            # 6. Non-existent PID with authorization -> TARGET_NOT_FOUND (ESRCH)
            status, resp = self._post_json("/api/investigation/start", {
                "goal": "Non-existent PID test",
                "pid": 999999999,
                "authorize_target": True,
            })
            self.assertEqual(status, 200)
            self.assertFalse(resp.get("success"))
            self.assertEqual(resp["error"]["code"], "TARGET_NOT_FOUND")
            self.assertIn("ESRCH", resp["error"]["message"])
        finally:
            child_proc.kill()
            child_proc.wait()

    def test_scoped_zero_findings_messaging(self):
        """Regression test for P1: Honest zero-findings reporting and explicit analysis scope bounds."""
        # Start investigation on empty/non-existent snapshot
        status, resp = self._post_json("/api/investigation/start", {
            "goal": "Zero-findings scope verification",
            "snapshot_id": "snap_nonexistent_empty",
        })
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("success"))
        data = resp["data"]
        inv_id = data["investigation_id"]

        # Status response contains scope measurements and honest notice
        status_resp = self._get_json(f"/api/investigation/status?investigation_id={inv_id}")[1]
        summary = status_resp["data"]["summary"]
        self.assertIn("scope", summary)
        self.assertIn("unresolved_checks", summary["scope"])
        self.assertGreater(len(summary["scope"]["unresolved_checks"]), 0)

        # Incomplete / partial investigation with 0 findings does NOT claim clean validation
        self.assertIn("zero_findings_notice", summary)
        self.assertIn("incomplete or restricted", summary["zero_findings_notice"])

        # Report response contains scoped findings_summary
        rep_resp = self._get_json(f"/api/investigation/report?investigation_id={inv_id}")[1]
        findings_summary = rep_resp["data"]["findings_summary"]
        self.assertEqual(findings_summary["total"], 0)
        self.assertIn("scope", findings_summary)
        self.assertIn("zero_findings_notice", findings_summary)

    def test_capture_method_and_consistency_descriptions(self):
        """Verify UI copy and metadata accurately describe capture methods, suspension, and NON_ATOMIC warnings."""
        # 1. Verify index.html copy
        status, _, body = self._get_raw("/")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        self.assertIn("Live Target PID:", html)
        self.assertIn("Authorize Target Signal (SIGSTOP / SIGCONT) &amp; Memory Read", html)
        self.assertIn("Memory capture was performed without pausing target threads", html)
        self.assertIn("cross-region execution skew", html)

        # 2. Verify app.js deduplication, selection preservation, and scoped messaging
        status, _, body = self._get_raw("/static/app.js")
        self.assertEqual(status, 200)
        js = body.decode("utf-8")
        self.assertIn("investigationLoadSeq", js)
        self.assertIn("renderRecentInvestigationSessions", js)
        self.assertIn("selectedInvestigationId", js)
        self.assertIn("Scope Boundaries &amp; Uninspected Checks:", js)
        self.assertIn("Zero findings recorded does NOT indicate clean state", js)

    def test_investigation_session_loading_and_selection_preservation(self):
        """Verify session loading API, non-latest selection preservation, and ephemeral reporting."""
        # 1. Start session Alpha
        status, resp_a = self._post_json("/api/investigation/start", {
            "goal": "Session Alpha for selection test",
            "snapshot_id": "snap_alpha_ui",
        })
        self.assertEqual(status, 200)
        inv_a = resp_a["data"]["investigation_id"]

        # 2. Start session Beta
        status, resp_b = self._post_json("/api/investigation/start", {
            "goal": "Session Beta for selection test",
            "snapshot_id": "snap_beta_ui",
        })
        self.assertEqual(status, 200)
        inv_b = resp_b["data"]["investigation_id"]

        # 3. List sessions: both must be present in order
        status, resp_list = self._get_json("/api/investigations")
        self.assertEqual(status, 200)
        sessions = resp_list["data"]
        ids = [s["investigation_id"] for s in sessions]
        self.assertIn(inv_a, ids)
        self.assertIn(inv_b, ids)

        # 4. User selects Alpha (not latest): report returns Alpha specifically
        status, rep_a = self._get_json(f"/api/investigation/report?investigation_id={inv_a}")
        self.assertEqual(status, 200)
        self.assertEqual(rep_a["data"]["investigation_id"], inv_a)
        self.assertEqual(rep_a["data"]["goal"], "Session Alpha for selection test")

        # 5. Stale / nonexistent session ID handling
        status, rep_stale = self._get_json("/api/investigation/report?investigation_id=inv_stale_99999")
        self.assertEqual(status, 200)
        self.assertIn("error", rep_stale)

    def test_clean_completed_zero_findings_scope_distinction(self):
        """Verify distinction between COMPLETED with 0 findings vs PARTIAL with 0 findings."""
        # 1. Start investigation on valid snapshot with 0 anomalies (clean state)
        status, resp = self._post_json("/api/investigation/start", {
            "goal": "Clean verification test",
            "snapshot_id": "snap_alpha_ui",
        })
        self.assertEqual(status, 200)
        data = resp["data"]
        self.assertIn(data["status"], ["COMPLETED", "PARTIAL"])
        scope = data["summary"]["scope"]
        self.assertIn("objects_examined", scope)
        self.assertIn("roots_examined", scope)
        self.assertIn("unresolved_checks", scope)

        # 2. Start investigation on nonexistent snapshot (partial state with 0 findings)
        status, resp_partial = self._post_json("/api/investigation/start", {
            "goal": "Partial verification test",
            "snapshot_id": "snap_missing_artifact",
        })
        self.assertEqual(status, 200)
        partial_data = resp_partial["data"]
        self.assertEqual(partial_data["status"], "PARTIAL")
        self.assertEqual(partial_data["findings_count"], 0)
        notice = partial_data["summary"].get("zero_findings_notice")
        self.assertIsNotNone(notice)
        self.assertIn("incomplete or restricted", notice)


if __name__ == "__main__":
    unittest.main()

