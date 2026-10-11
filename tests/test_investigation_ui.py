"""Automated tests for Investigation Overview UI and Web API Endpoints.

Tests acceptance criterion 7:
7. UI rendering for successful, partial, empty and failed investigations.
"""

import json
import os
import shutil
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


if __name__ == "__main__":
    unittest.main()
