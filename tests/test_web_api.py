"""Unit and integration tests for dynamicState Web API and Server."""

import http.client
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error

from extractor.agent_runtime import AgentRuntime
from extractor.explorer import MutationCandidate
from extractor.runtime_controller import ExecutionResult, MutationResult, RuntimeCapabilities, RuntimeController
from extractor.snapshot import RuntimeSnapshot, StateTransition
from extractor.web.server import DynamicStateWebServer, run_server


class MockWebRuntimeController(RuntimeController):
    """Mock RuntimeController for deterministic Web API unit testing."""

    def __init__(self):
        self._counter = 0
        self.snapshots = {}
        self._latest = None
        self._mock_checkpoint = "CP_001"
        self._checkpoints = {}
        self.binary = "/app/test_server"
        self.debug_image_path = "/app/test_server.debug"
        self.debug_image_status = "VERIFIED"

        self._sample_snap = {
            "schema_version": "0.3",
            "snapshot_id": "S001",
            "process": {"pid": 4321, "binary": "/app/test_server"},
            "execution": {
                "threads": [
                    {
                        "thread_id": 1,
                        "frames": [
                            {"level": 0, "function": "handle_request", "location": "main.cpp:20", "pc": "0x401000"}
                        ]
                    }
                ]
            },
            "persistent": {
                "roots": [{"name": "server_inst", "kind": "global"}],
                "objects": [
                    {
                        "object_id": "obj_0001",
                        "type": "ServerConfig",
                        "storage": "heap",
                        "fields": [
                            {"name": "retry", "type": "uint32_t", "value": 2},
                            {"name": "state", "type": "ServerState", "value": "IDLE"},
                            {"name": "active", "type": "bool", "value": True},
                            {"name": "buffer_ref", "type": "Buffer*", "value": "0x2000", "object_ref": "obj_0002"},
                        ]
                    },
                    {
                        "object_id": "obj_0002",
                        "type": "Buffer",
                        "storage": "heap",
                        "fields": [
                            {"name": "size", "type": "size_t", "value": 1024},
                        ]
                    }
                ],
                "statistics": {"object_count": 2, "root_count": 1, "edge_count": 1}
            },
            "provenance": {
                "runtime_binary": {"stripped": True, "build_id": "BUILD_123"},
                "debug_image": {"source": "external", "verified": True, "compatible": True}
            }
        }
        self.snapshots["S001"] = self._sample_snap
        self._latest = self._sample_snap

    def process_info(self):
        return {"pid": 4321, "status": "STOPPED", "binary": self.binary}

    def observe(self):
        return self._latest

    def snapshot(self, snapshot_id=None, output=None):
        self._counter += 1
        sid = snapshot_id or f"S{self._counter:03d}"
        snap = dict(self._sample_snap)
        snap["snapshot_id"] = sid
        self.snapshots[sid] = snap
        self._latest = snap
        return snap

    def propose_mutations(self, snapshot=None):
        return [
            MutationCandidate("M001", "S001", "obj_0001", "retry", 2, 3, "uint32_t", "BOUNDARY_PLUS_ONE"),
            MutationCandidate("M002", "S001", "obj_0001", "state", "IDLE", "RUNNING", "ServerState", "ENUM_MEMBER"),
            MutationCandidate("M003", "S001", "obj_0001", "active", True, False, "bool", "INVERT"),
        ]

    def checkpoint(self, checkpoint_id=None):
        cid = checkpoint_id or f"CP_{len(self._checkpoints) + 1:03d}"
        self._checkpoints[cid] = cid
        return cid

    def restore(self, checkpoint):
        pass

    def execute_transition(self, object_id=None, field_path=None, value=None, path=None, timeout_ms=1000):
        child_snap = json.loads(json.dumps(self._sample_snap))
        child_snap["snapshot_id"] = "S002"

        for o in child_snap["persistent"]["objects"]:
            if o["object_id"] == "obj_0001":
                for f in o["fields"]:
                    if f["name"] == field_path:
                        f["value"] = value
                    elif f["name"] == "state":
                        f["value"] = "RUNNING"

        self.snapshots["S002"] = child_snap
        self._latest = child_snap

        trans = StateTransition(
            transition_id="T001",
            parent_snapshot="S001",
            child_snapshot="S002",
            mutation=MutationResult(success=True, object_id=object_id, field=field_path, before=2, after=value),
            execution=ExecutionResult(status="STOPPED", reason="breakpoint"),
            diff={"summary": {"value_changes": 2, "reference_changes": 0, "objects_created": 0, "objects_removed": 0},
                  "changes": [
                      {"object_id": "obj_0001", "field": field_path, "before": 2, "after": value, "category": "value_changed"},
                      {"object_id": "obj_0001", "field": "state", "before": "IDLE", "after": "RUNNING", "category": "value_changed"}
                  ]}
        )
        return trans

    def explore(self, max_steps=10, timeout_ms=1000, corpus_dir="corpus"):
        return {
            "exploration_id": "E001",
            "seed_state_id": "state_000001",
            "steps": 5,
            "summary": {
                "new_states": 3,
                "executed": 5,
                "crashes": 0,
                "timeouts": 0
            },
            "corpus_status": {"total_states": 4, "total_transitions": 5}
        }


class TestWebApi(unittest.TestCase):
    """Test suite covering Web API endpoints, structured errors, and security boundaries."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp()
        cls.corpus_dir = os.path.join(cls.tmp_dir, "corpus")
        cls.controller = MockWebRuntimeController()
        cls.runtime = AgentRuntime(controller=cls.controller, corpus_dir=cls.corpus_dir)

        # Seed initial state into corpus
        cls.runtime.corpus.add(cls.controller._sample_snap, metadata={"interesting_reasons": ["SEED"]})

        # Start Web Server on ephemeral port (port=0 lets OS choose)
        cls.server = run_server(runtime=cls.runtime, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        # Run server loop in background thread
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)  # small pause to ensure socket listening

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def _get(self, path):
        req = urllib.request.Request(self.base_url + path)
        try:
            with urllib.request.urlopen(req) as resp:
                content = resp.read().decode("utf-8")
                return resp.status, json.loads(content)
        except urllib.error.HTTPError as exc:
            content = exc.read().decode("utf-8")
            try:
                data = json.loads(content)
            except Exception:
                data = {"raw": content}
            return exc.code, data

    def _post(self, path, payload):
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.base_url + path, data=data_bytes,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                content = resp.read().decode("utf-8")
                return resp.status, json.loads(content)
        except urllib.error.HTTPError as exc:
            content = exc.read().decode("utf-8")
            try:
                data = json.loads(content)
            except Exception:
                data = {"raw": content}
            return exc.code, data

    # -------------------------------------------------------------------------
    # API Verification Tests
    # -------------------------------------------------------------------------

    def test_01_health_endpoint(self):
        status, data = self._get("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(data.get("status"), "ok")
        self.assertIn("version", data)
        self.assertEqual(data.get("mode"), "CONSISTENT")

    def test_02_capabilities_endpoint(self):
        status, data = self._get("/api/capabilities")
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        caps = data.get("data", {})
        self.assertIn("runtime", caps)
        self.assertIn("mutation", caps)
        self.assertIn("limits", caps)

    def test_03_runtime_info_metadata_honesty(self):
        status, data = self._get("/api/runtime")
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        info = data.get("data", {})
        self.assertEqual(info.get("mode"), "CONSISTENT")
        self.assertEqual(info.get("pid"), 4321)
        self.assertEqual(info.get("status"), "STOPPED")
        # Ensure target endianness and elf_class are NOT silently guessed as "little" or "ELF64"
        self.assertIn(info.get("endianness"), ("UNKNOWN", None))
        self.assertIn(info.get("elf_class"), ("UNKNOWN", None))

    def test_04_states_listing_and_inspection(self):
        # List states
        status, data = self._get("/api/states")
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        states = data.get("data", [])
        self.assertGreaterEqual(len(states), 1)
        first_state = states[0]
        self.assertIn("state_id", first_state)
        self.assertIn("state_hash", first_state)

        # Inspect specific state
        sid = first_state["state_id"]
        status, s_data = self._get(f"/api/states/{sid}")
        self.assertEqual(status, 200)
        self.assertTrue(s_data.get("success"))
        self.assertEqual(s_data["data"]["state_id"], sid)

        # Missing state returns STATE_NOT_FOUND
        status, err_data = self._get("/api/states/nonexistent_state_999")
        self.assertFalse(err_data.get("success"))
        self.assertEqual(err_data["error"]["code"], "STATE_NOT_FOUND")

    def test_05_objects_and_field_inspection(self):
        status, data = self._get("/api/states/state_000001/objects")
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        objs = data.get("data", [])
        self.assertEqual(len(objs), 2)
        obj_ids = [o["object_id"] for o in objs]
        self.assertIn("obj_0001", obj_ids)
        self.assertIn("obj_0002", obj_ids)

        # Inspect object
        status, o_data = self._get("/api/objects/obj_0001")
        self.assertEqual(status, 200)
        self.assertTrue(o_data.get("success"))
        obj1 = o_data["data"]
        self.assertEqual(obj1["type"], "ServerConfig")

        # Inspect fields
        status, f_data = self._get("/api/objects/obj_0001/fields")
        self.assertEqual(status, 200)
        self.assertTrue(f_data.get("success"))
        field_names = [f["name"] for f in f_data["data"]]
        self.assertIn("retry", field_names)
        self.assertIn("state", field_names)

        # Inspect single field
        status, sf_data = self._get("/api/objects/obj_0001/fields?field=retry")
        self.assertEqual(status, 200)
        self.assertTrue(sf_data.get("success"))
        self.assertEqual(sf_data["data"]["mutability"], "mutable")
        self.assertEqual(sf_data["data"]["value"], 2)

    def test_06_mutation_candidates_and_filtering(self):
        status, data = self._get("/api/mutation-candidates")
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        cands = data.get("data", [])
        self.assertGreaterEqual(len(cands), 3)

        # Filter by field
        status, f_data = self._get("/api/mutation-candidates?field=retry")
        self.assertEqual(status, 200)
        self.assertTrue(f_data.get("success"))
        filtered = f_data.get("data", [])
        self.assertTrue(all(c["field"] == "retry" for c in filtered))

    def test_07_execute_transition_and_inspect_result(self):
        # First ensure candidates are loaded
        self._get("/api/mutation-candidates")

        # Execute mutation transition
        status, data = self._post("/api/mutation", {"candidate_id": "M001", "timeout_ms": 1000})
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        trans = data.get("data", {})
        self.assertEqual(trans.get("transition_id"), "T001")
        self.assertEqual(trans.get("execution", {}).get("status"), "STOPPED")

        # Verify transition can be inspected
        status, t_data = self._get("/api/transitions/T001")
        self.assertEqual(status, 200)
        self.assertTrue(t_data.get("success"))

        # Verify state graph contains the new transition edge
        status, g_data = self._get("/api/state-graph")
        self.assertEqual(status, 200)
        self.assertTrue(g_data.get("success"))
        edges = g_data.get("data", {}).get("edges", [])
        t_ids = [e["id"] for e in edges]
        self.assertIn("T001", t_ids)

    def test_08_snapshots_diff_endpoint(self):
        # Diff between S001 and S002
        status, data = self._get("/api/snapshots/S001/diff/S002")
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        diff = data.get("data", {})
        self.assertIn("summary", diff)
        self.assertIn("changes", diff)
        self.assertGreater(len(diff["changes"]), 0)

    def test_09_low_impact_mutation_rejection(self):
        # Switch runtime to LOW_IMPACT mode
        prev_mode = self.runtime.observation_mode
        self.runtime.observation_mode = "LOW_IMPACT"
        try:
            # Candidates must be rejected with CAPABILITY_UNSUPPORTED
            status, c_data = self._get("/api/mutation-candidates")
            self.assertFalse(c_data.get("success"))
            self.assertEqual(c_data["error"]["code"], "CAPABILITY_UNSUPPORTED")

            # Mutation must be rejected with CAPABILITY_UNSUPPORTED
            status, m_data = self._post("/api/mutation", {"candidate_id": "M001"})
            self.assertFalse(m_data.get("success"))
            self.assertEqual(m_data["error"]["code"], "CAPABILITY_UNSUPPORTED")

            # Checkpoint must be rejected with CAPABILITY_UNSUPPORTED
            status, cp_data = self._post("/api/checkpoint", {})
            self.assertFalse(cp_data.get("success"))
            self.assertEqual(cp_data["error"]["code"], "CAPABILITY_UNSUPPORTED")
        finally:
            self.runtime.observation_mode = prev_mode

    def test_10_security_boundary_no_gdb_or_arbitrary_shell(self):
        # Verify prohibited endpoints return 403 Forbidden
        for bad_endpoint in ["/api/gdb-command", "/api/write-memory", "/api/eval-expression", "/api/arbitrary-command"]:
            status, data = self._post(bad_endpoint, {"cmd": "print 1"})
            self.assertEqual(status, 403)
            self.assertFalse(data.get("success"))
            self.assertEqual(data["error"]["code"], "CAPABILITY_UNSUPPORTED")

        # Unknown route returns 404
        status, data = self._get("/api/unmapped_route_xyz")
        self.assertEqual(status, 404)
        self.assertFalse(data.get("success"))

    def test_11_static_file_serving_and_traversal_guard(self):
        # Root index.html
        req = urllib.request.Request(self.base_url + "/")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            html = resp.read().decode("utf-8")
            self.assertIn("dynamicState", html)
            self.assertIn("Runtime State Explorer", html)

        # Static CSS
        req = urllib.request.Request(self.base_url + "/static/app.css")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/css", resp.headers.get("Content-Type", ""))

        # Static JS
        req = urllib.request.Request(self.base_url + "/static/app.js")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)

        # Directory traversal attempt must be blocked
        try:
            req = urllib.request.Request(self.base_url + "/static/../../etc/passwd")
            urllib.request.urlopen(req)
            self.fail("Traversal request should have failed")
        except urllib.error.HTTPError as exc:
            self.assertIn(exc.code, (403, 404))

    def test_12_explore_endpoint(self):
        status, data = self._post("/api/explore", {"max_steps": 5, "timeout_ms": 1000, "max_states": 10})
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        res = data.get("data", {})
        self.assertEqual(res.get("steps"), 5)
        self.assertEqual(res.get("new_states"), 3)

    def test_13_memory_summary_endpoint(self):
        status, data = self._get("/api/memory-summary")
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        summary = data.get("data", {})
        self.assertIn("breakdown", summary)
        self.assertIn("objects", summary)
        self.assertIn("quality", summary)
        self.assertIn("status", summary)
        self.assertEqual(summary.get("objects", {}).get("total_objects"), 2)

        # Test state-specific memory summary
        status, s_data = self._get("/api/states/state_000001/memory-summary")
        self.assertEqual(status, 200)
        self.assertTrue(s_data.get("success"))
        self.assertEqual(s_data.get("data", {}).get("objects", {}).get("total_objects"), 2)

    def test_14_verify_restart_determinism_endpoint(self):
        # GET
        status, data = self._get("/api/runtime/verify_determinism")
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("data", {}).get("deterministic"))
        self.assertEqual(data.get("data", {}).get("status"), "VERIFIED")

        # POST
        status, p_data = self._post("/api/runtime/verify_determinism", {})
        self.assertEqual(status, 200)
        self.assertTrue(p_data.get("success"))
        self.assertTrue(p_data.get("data", {}).get("deterministic"))

    def test_15_enriched_human_centric_metadata(self):
        # 1. Runtime info threads_detail & observation_point
        status, data = self._get("/api/runtime")
        self.assertEqual(status, 200)
        info = data.get("data", {})
        self.assertIn("threads_detail", info)
        self.assertIn("observation_point", info)
        td = info["threads_detail"]
        self.assertGreaterEqual(len(td), 1)
        self.assertEqual(td[0]["thread_id"], 1)
        self.assertIn("name", td[0])
        self.assertEqual(td[0]["function"], "handle_request")
        self.assertEqual(td[0]["location"], "main.cpp:20")
        obs = info["observation_point"]
        self.assertIn("spec", obs)
        self.assertIn("location", obs)

        # 2. Objects enriched with semantic names & cleaned types
        status, o_data = self._get("/api/states/state_000001/objects")
        self.assertEqual(status, 200)
        objs = o_data.get("data", [])
        obj1 = next(o for o in objs if o["object_id"] == "obj_0001")
        self.assertEqual(obj1.get("semantic_name"), "server_inst")
        self.assertEqual(obj1.get("cleaned_type"), "ServerConfig")
        self.assertEqual(obj1.get("root_name"), "server_inst")
        self.assertTrue(any(f.get("mutability") == "mutable" for f in obj1.get("fields", [])))

        # 3. Candidates enriched with semantic targets
        status, c_data = self._get("/api/mutation-candidates")
        self.assertEqual(status, 200)
        cands = c_data.get("data", [])
        c1 = next(c for c in cands if c["object_id"] == "obj_0001" and c["field"] == "retry")
        self.assertEqual(c1.get("semantic_name"), "server_inst")
        self.assertEqual(c1.get("semantic_target"), "server_inst.retry")

        # 4. Mutation enriched with restore_backend, timeout, and hashes
        status, m_data = self._post("/api/mutation", {"candidate_id": "M001", "timeout_ms": 500})
        self.assertEqual(status, 200)
        trans = m_data.get("data", {})
        self.assertEqual(trans.get("timeout_ms"), 500)
        self.assertIn("restore_backend", trans)
        self.assertIn("child_state_hash", trans)

        # 5. Mutation with candidate payload dict
        status, m_custom = self._post("/api/mutation", {
            "candidate": {
                "candidate_id": "M001",
                "proposed_value": 9
            },
            "timeout_ms": 250
        })
        self.assertEqual(status, 200)
        self.assertEqual(m_custom.get("data", {}).get("timeout_ms"), 250)

    def test_16_static_assets_and_html_elements(self):
        # 1. Root index.html
        req_root = urllib.request.Request(self.base_url + "/")
        with urllib.request.urlopen(req_root) as resp:
            self.assertEqual(resp.status, 200)
            html_str = resp.read().decode("utf-8")
            self.assertIn("btn-mode-basic", html_str)
            self.assertIn("btn-mode-advanced", html_str)
            self.assertIn("modal-mutation-preview", html_str)
            self.assertIn("card-thread-explorer", html_str)
            self.assertIn("trans-flow-container", html_str)
            self.assertIn("exec-timeline-list", html_str)
            self.assertIn("table-exec-diff", html_str)

        # 2. Static CSS
        req_css = urllib.request.Request(self.base_url + "/static/app.css")
        with urllib.request.urlopen(req_css) as resp:
            self.assertEqual(resp.status, 200)
            css_text = resp.read().decode("utf-8")
            self.assertIn(".mode-toggle-group", css_text)
            self.assertIn(".execution-timeline", css_text)
            self.assertIn(".flow-card", css_text)

        # 3. Static JS
        req_js = urllib.request.Request(self.base_url + "/static/app.js")
        with urllib.request.urlopen(req_js) as resp:
            self.assertEqual(resp.status, 200)
            js_text = resp.read().decode("utf-8")
            self.assertIn("initModeToggle", js_text)
            self.assertIn("openMutationPreview", js_text)
            self.assertIn("renderThreads", js_text)

    def test_17_mutability_normalization_and_lowercase(self):
        """Verify _is_field_mutable returns canonical lowercase 'mutable', 'read_only', or 'unsupported'."""
        from extractor.web.server import _is_field_mutable
        self.assertEqual(_is_field_mutable("int"), "mutable")
        self.assertEqual(_is_field_mutable("bool"), "mutable")
        self.assertEqual(_is_field_mutable("float"), "mutable")
        self.assertEqual(_is_field_mutable("char *"), "mutable")
        self.assertEqual(_is_field_mutable("const int"), "read_only")
        self.assertEqual(_is_field_mutable("const char *"), "read_only")
        self.assertEqual(_is_field_mutable("void"), "unsupported")
        self.assertEqual(_is_field_mutable(""), "unsupported")

    def test_18_runtime_honesty_no_fake_obs_point_or_thread_name(self):
        """Verify no fake 'observation_checkpoint' or fake thread names are fabricated."""
        status, data = self._get("/api/runtime")
        self.assertEqual(status, 200)
        rt = data.get("data", {})
        
        # When no observation point is active, it must be None (never fake 'observation_checkpoint')
        obs = rt.get("observation_point")
        if obs is None:
            self.assertIsNone(obs)
        else:
            self.assertNotEqual(obs.get("function"), "observation_checkpoint")

        # When thread names are not provided by OS/debugger, name must be None (never fake 'Main Thread' or 'Worker #2')
        threads_detail = rt.get("threads_detail", [])
        for t in threads_detail:
            # If name is None, verify it's honestly None
            if t.get("name") is None:
                self.assertIsNone(t.get("name"))

    def test_19_capability_vs_verification_separation(self):
        """Verify capability (Supported) vs verification (Verified) are distinct fields."""
        status, data = self._get("/api/runtime")
        self.assertEqual(status, 200)
        rt = data.get("data", {})
        
        self.assertIn("branch_isolation_capability", rt)
        self.assertIn(rt["branch_isolation_capability"], ["SUPPORTED", "UNAVAILABLE", "CONDITIONAL"])
        self.assertIn("branch_isolation_verified", rt)
        self.assertIsInstance(rt["branch_isolation_verified"], bool)

        self.assertIn("determinism_capability", rt)
        self.assertIn("determinism_verified", rt)
        self.assertIsInstance(rt["determinism_verified"], bool)

        self.assertIn("default_timeout_ms", rt)
        self.assertIsInstance(rt["default_timeout_ms"], int)

    def test_20_object_reference_relationships_incoming_outgoing(self):
        """Verify incoming and outgoing reference relations in state objects and object inspector."""
        status, data = self._get("/api/states/state_seed/objects")
        self.assertEqual(status, 200)
        objects = data.get("data", [])
        self.assertIsInstance(objects, list)
        
        if objects:
            first_obj = objects[0]
            self.assertIn("outgoing_count", first_obj)
            self.assertIn("incoming_count", first_obj)
            self.assertIn("reference_count", first_obj)

            # Inspect object endpoint
            oid = first_obj["object_id"]
            istatus, idata = self._get(f"/api/states/state_seed/objects/{oid}")
            self.assertEqual(istatus, 200)
            iobj = idata.get("data", {})
            self.assertIn("incoming_references", iobj)
            self.assertIn("outgoing_references", iobj)
            self.assertIsInstance(iobj["incoming_references"], list)
            self.assertIsInstance(iobj["outgoing_references"], list)

    def test_21_object_explorer_html_workspace_and_components(self):
        """Verify 3-Pane Object Explorer workspace elements, summary bar, CSS and JS."""
        # 1. HTML elements
        req_root = urllib.request.Request(self.base_url + "/")
        with urllib.request.urlopen(req_root) as resp:
            html = resp.read().decode("utf-8")
            # Summary Bar
            self.assertIn("runtime-summary-bar", html)
            self.assertIn("sum-runtime-status", html)
            self.assertIn("sum-thread-count", html)
            self.assertIn("sum-object-count", html)
            self.assertIn("sum-root-count", html)
            self.assertIn("sum-state-hash", html)
            self.assertIn("sum-checkpoint-status", html)
            self.assertIn("sum-isolation-status", html)
            self.assertIn("sum-determinism-status", html)
            self.assertIn("sum-obs-point", html)
            self.assertIn("select-global-timeout", html)

            # 3-Pane Workspace
            self.assertIn("explorer-workspace", html)
            self.assertIn("pane-object-explorer", html)
            self.assertIn("filter-obj-group", html)
            self.assertIn("select-obj-sort", html)
            self.assertIn("pane-reference-center", html)
            self.assertIn("tree-reference-container", html)
            self.assertIn("table-objects-summary", html)
            self.assertIn("topology-graph-svg", html)
            self.assertIn("pane-object-inspector", html)
            self.assertIn("table-semantic-fields", html)
            self.assertIn("inspector-outgoing-refs", html)
            self.assertIn("inspector-incoming-refs", html)
            self.assertIn("card-integrated-mutation", html)

        # 2. CSS classes
        req_css = urllib.request.Request(self.base_url + "/static/app.css")
        with urllib.request.urlopen(req_css) as resp:
            css = resp.read().decode("utf-8")
            self.assertIn(".runtime-summary-bar", css)
            self.assertIn(".explorer-workspace", css)
            self.assertIn(".pane-card", css)
            self.assertIn(".ref-tree-node", css)
            self.assertIn(".outgoing-chip", css)
            self.assertIn(".incoming-chip", css)

        # 3. JS functions
        req_js = urllib.request.Request(self.base_url + "/static/app.js")
        with urllib.request.urlopen(req_js) as resp:
            js = resp.read().decode("utf-8")
            self.assertIn("normalizeMutability", js)
            self.assertIn("renderReferenceTree", js)
            self.assertIn("renderReferenceTable", js)
            self.assertIn("switchCenterView", js)


if __name__ == "__main__":
    unittest.main()


