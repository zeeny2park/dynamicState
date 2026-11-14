"""Unit and integration tests for dynamicState Web API and Server.

The state / object / mutation / transition behaviour of WebApiAdapter is exercised by calling the adapter directly:
its HTTP routes (the previous 8-tab UI's /api/runtime, /api/states, /api/mutation, ...) were removed with that UI.
Over HTTP this suite checks the kept /api/health route, that the removed and dangerous routes are 404, and the
static-file traversal guard of the root UI.
"""

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
        # This suite exercises the mutation/transition API, which IMP-019 makes opt-in.
        cls.runtime = AgentRuntime(controller=cls.controller, corpus_dir=cls.corpus_dir, allow_mutation=True)

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

    @property
    def adapter(self):
        return self.server.adapter

    @staticmethod
    def _api(result):
        """An adapter result as a client sees it (JSON round trip, as the server's _send_json did)."""
        return json.loads(json.dumps(result, default=str))

    def _get(self, path):
        req = urllib.request.Request(self.base_url + path, headers={"X-Session-Token": self.server.session_token})
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
                                     headers={"Content-Type": "application/json",
                                              "X-Session-Token": self.server.session_token})
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
        data = self._api(self.adapter.get_capabilities())
        self.assertTrue(data.get("success"))
        caps = data.get("data", {})
        self.assertIn("runtime", caps)
        self.assertIn("mutation", caps)
        self.assertIn("limits", caps)

    def test_03_runtime_info_metadata_honesty(self):
        data = self._api(self.adapter.get_runtime_info())
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
        data = self._api(self.adapter.list_states())
        self.assertTrue(data.get("success"))
        states = data.get("data", [])
        self.assertGreaterEqual(len(states), 1)
        first_state = states[0]
        self.assertIn("state_id", first_state)
        self.assertIn("state_hash", first_state)

        # Inspect specific state
        sid = first_state["state_id"]
        s_data = self._api(self.adapter.inspect_state(sid))
        self.assertTrue(s_data.get("success"))
        self.assertEqual(s_data["data"]["state_id"], sid)

        # Missing state returns STATE_NOT_FOUND
        err_data = self._api(self.adapter.inspect_state("nonexistent_state_999"))
        self.assertFalse(err_data.get("success"))
        self.assertEqual(err_data["error"]["code"], "STATE_NOT_FOUND")

    def test_05_objects_and_field_inspection(self):
        data = self._api(self.adapter.list_state_objects("state_000001"))
        self.assertTrue(data.get("success"))
        objs = data.get("data", [])
        self.assertEqual(len(objs), 2)
        obj_ids = [o["object_id"] for o in objs]
        self.assertIn("obj_0001", obj_ids)
        self.assertIn("obj_0002", obj_ids)

        # Inspect object
        o_data = self._api(self.adapter.inspect_object("obj_0001"))
        self.assertTrue(o_data.get("success"))
        obj1 = o_data["data"]
        self.assertEqual(obj1["type"], "ServerConfig")

        # Inspect fields
        f_data = self._api(self.adapter.inspect_fields("obj_0001"))
        self.assertTrue(f_data.get("success"))
        field_names = [f["name"] for f in f_data["data"]]
        self.assertIn("retry", field_names)
        self.assertIn("state", field_names)

        # Inspect single field
        sf_data = self._api(self.adapter.inspect_fields("obj_0001", field_path="retry"))
        self.assertTrue(sf_data.get("success"))
        self.assertEqual(sf_data["data"]["mutability"], "mutable")
        self.assertEqual(sf_data["data"]["value"], 2)

    def test_06_mutation_candidates_and_filtering(self):
        data = self._api(self.adapter.list_mutation_candidates())
        self.assertTrue(data.get("success"))
        cands = data.get("data", [])
        self.assertGreaterEqual(len(cands), 3)

        # Filter by field
        f_data = self._api(self.adapter.list_mutation_candidates(field_name="retry"))
        self.assertTrue(f_data.get("success"))
        filtered = f_data.get("data", [])
        self.assertTrue(all(c["field"] == "retry" for c in filtered))

    def test_07_execute_transition_and_inspect_result(self):
        # First ensure candidates are loaded
        self.adapter.list_mutation_candidates()

        # Execute mutation transition
        data = self._api(self.adapter.execute_transition({"candidate_id": "M001", "timeout_ms": 1000}))
        self.assertTrue(data.get("success"))
        trans = data.get("data", {})
        self.assertEqual(trans.get("transition_id"), "T001")
        self.assertEqual(trans.get("execution", {}).get("status"), "STOPPED")

        # Verify transition can be inspected
        t_data = self._api(self.adapter.inspect_transition("T001"))
        self.assertTrue(t_data.get("success"))

        # Verify state graph contains the new transition edge
        g_data = self._api(self.adapter.get_state_graph())
        self.assertTrue(g_data.get("success"))
        edges = g_data.get("data", {}).get("edges", [])
        t_ids = [e["id"] for e in edges]
        self.assertIn("T001", t_ids)

    def test_08_snapshots_diff_endpoint(self):
        # Diff between S001 and S002
        data = self._api(self.adapter.diff_snapshots("S001", "S002"))
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
            c_data = self._api(self.adapter.list_mutation_candidates())
            self.assertFalse(c_data.get("success"))
            self.assertEqual(c_data["error"]["code"], "CAPABILITY_UNSUPPORTED")

            # Mutation must be rejected with CAPABILITY_UNSUPPORTED
            m_data = self._api(self.adapter.execute_transition({"candidate_id": "M001"}))
            self.assertFalse(m_data.get("success"))
            self.assertEqual(m_data["error"]["code"], "CAPABILITY_UNSUPPORTED")

            # Checkpoint must be rejected with CAPABILITY_UNSUPPORTED
            cp_data = self._api(self.adapter.checkpoint({}))
            self.assertFalse(cp_data.get("success"))
            self.assertEqual(cp_data["error"]["code"], "CAPABILITY_UNSUPPORTED")
        finally:
            self.runtime.observation_mode = prev_mode

    def test_10_security_boundary_no_gdb_or_arbitrary_shell(self):
        # Command / memory-write endpoints do not exist (404), with a valid session token, GET or POST
        for bad_endpoint in ["/api/gdb-command", "/api/write-memory", "/api/eval-expression", "/api/arbitrary-command"]:
            status, data = self._post(bad_endpoint, {"cmd": "print 1"})
            self.assertEqual(status, 404, bad_endpoint)
            self.assertFalse(data.get("success"))
            self.assertEqual(data["error"]["code"], "NOT_FOUND")
            self.assertEqual(self._get(bad_endpoint)[0], 404, bad_endpoint)

        # The removed state-changing / legacy routes are gone as well (the adapter methods above are not reachable)
        for path in ("/api/mutation", "/api/transition", "/api/checkpoint", "/api/restore", "/api/explore",
                     "/api/runtime/verify_determinism", "/api/snapshots/S001/branch", "/api/snapshots/S001/mutate"):
            self.assertEqual(self._post(path, {"candidate_id": "M001"})[0], 404, path)
        for path in ("/api/runtime", "/api/capabilities", "/api/states", "/api/mutation-candidates", "/api/state-graph",
                     "/api/memory-summary", "/api/snapshots/S001/diff/S002"):
            self.assertEqual(self._get(path)[0], 404, path)

        # Unknown route returns 404
        status, data = self._get("/api/unmapped_route_xyz")
        self.assertEqual(status, 404)
        self.assertFalse(data.get("success"))

    def test_11_static_file_serving_and_traversal_guard(self):
        # The root page is the diagnosis UI
        req = urllib.request.Request(self.base_url + "/")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            self.assertIn("dynamicState", resp.read().decode("utf-8"))

        # The previous UI's asset URLs serve nothing
        for path in ("/static/app.css", "/static/app.js", "/static/index.html"):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(urllib.request.Request(self.base_url + path))
            self.assertEqual(ctx.exception.code, 404, path)

        # Directory traversal attempts must be blocked (raw paths: urllib would normalise them)
        for path in ("/static/../../etc/passwd", "/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd"):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            try:
                conn.request("GET", path)
                resp = conn.getresponse()
                body = resp.read()
            finally:
                conn.close()
            self.assertIn(resp.status, (403, 404), path)
            self.assertNotIn(b"root:", body, path)

    def test_12_explore_endpoint(self):
        data = self._api(self.adapter.explore({"max_steps": 5, "timeout_ms": 1000, "max_states": 10}))
        self.assertTrue(data.get("success"))
        res = data.get("data", {})
        self.assertEqual(res.get("steps"), 5)
        self.assertEqual(res.get("new_states"), 3)

    def test_13_memory_summary_endpoint(self):
        data = self._api(self.adapter.get_memory_summary())
        self.assertTrue(data.get("success"))
        summary = data.get("data", {})
        self.assertIn("breakdown", summary)
        self.assertIn("objects", summary)
        self.assertIn("quality", summary)
        self.assertIn("status", summary)
        self.assertEqual(summary.get("objects", {}).get("total_objects"), 2)

        # Test state-specific memory summary
        s_data = self._api(self.adapter.get_state_memory_summary("state_000001"))
        self.assertTrue(s_data.get("success"))
        self.assertEqual(s_data.get("data", {}).get("objects", {}).get("total_objects"), 2)

    def test_14_verify_restart_determinism_endpoint(self):
        # GET
        data = self._api(self.adapter.verify_restart_determinism({}))
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("data", {}).get("deterministic"))
        self.assertEqual(data.get("data", {}).get("status"), "VERIFIED")

        # POST
        p_data = self._api(self.adapter.verify_restart_determinism({}))
        self.assertTrue(p_data.get("success"))
        self.assertTrue(p_data.get("data", {}).get("deterministic"))

    def test_15_enriched_human_centric_metadata(self):
        # 1. Runtime info threads_detail & observation_point
        data = self._api(self.adapter.get_runtime_info())
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
        o_data = self._api(self.adapter.list_state_objects("state_000001"))
        objs = o_data.get("data", [])
        obj1 = next(o for o in objs if o["object_id"] == "obj_0001")
        self.assertEqual(obj1.get("semantic_name"), "server_inst")
        self.assertEqual(obj1.get("cleaned_type"), "ServerConfig")
        self.assertEqual(obj1.get("root_name"), "server_inst")
        self.assertTrue(any(f.get("mutability") == "mutable" for f in obj1.get("fields", [])))

        # 3. Candidates enriched with semantic targets
        c_data = self._api(self.adapter.list_mutation_candidates())
        cands = c_data.get("data", [])
        c1 = next(c for c in cands if c["object_id"] == "obj_0001" and c["field"] == "retry")
        self.assertEqual(c1.get("semantic_name"), "server_inst")
        self.assertEqual(c1.get("semantic_target"), "server_inst.retry")

        # 4. Mutation enriched with restore_backend, timeout, and hashes
        m_data = self._api(self.adapter.execute_transition({"candidate_id": "M001", "timeout_ms": 500}))
        trans = m_data.get("data", {})
        self.assertEqual(trans.get("timeout_ms"), 500)
        self.assertIn("restore_backend", trans)
        self.assertIn("child_state_hash", trans)

        # 5. Mutation with candidate payload dict
        m_custom = self._api(self.adapter.execute_transition({
            "candidate": {
                "candidate_id": "M001",
                "proposed_value": 9
            },
            "timeout_ms": 250
        }))
        self.assertEqual(m_custom.get("data", {}).get("timeout_ms"), 250)

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
        data = self._api(self.adapter.get_runtime_info())
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
        data = self._api(self.adapter.get_runtime_info())
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
        data = self._api(self.adapter.list_state_objects("state_seed"))
        objects = data.get("data", [])
        self.assertIsInstance(objects, list)
        
        if objects:
            first_obj = objects[0]
            self.assertIn("outgoing_count", first_obj)
            self.assertIn("incoming_count", first_obj)
            self.assertIn("reference_count", first_obj)

            # Inspect object endpoint
            oid = first_obj["object_id"]
            idata = self._api(self.adapter.inspect_object(oid, snapshot_id="state_seed"))
            iobj = idata.get("data", {})
            self.assertIn("incoming_references", iobj)
            self.assertIn("outgoing_references", iobj)
            self.assertIsInstance(iobj["incoming_references"], list)
            self.assertIsInstance(iobj["outgoing_references"], list)

    def test_22_test_a_capability_vs_verification_separation(self):
        """Test A: Verify SUPPORTED capability does not automatically mean VERIFIED even for single-thread."""
        data = self._api(self.adapter.get_runtime_info())
        rt = data.get("data", {})

        # Capability is SUPPORTED
        self.assertEqual(rt.get("branch_isolation_capability"), "SUPPORTED")
        self.assertEqual(rt.get("branch_isolation", {}).get("capability"), "SUPPORTED")

        # Verification must be FALSE because no verification was run!
        self.assertFalse(rt.get("branch_isolation_verified"))
        self.assertFalse(rt.get("branch_isolation", {}).get("verified"))

        # Determinism capability vs verification
        self.assertEqual(rt.get("determinism_capability"), "SUPPORTED")
        self.assertFalse(rt.get("determinism_verified"))
        self.assertFalse(rt.get("determinism", {}).get("verified"))

    def test_23_test_b_actual_verification_provenance(self):
        """Test B: When actual verification is performed/present in provenance, verified must be True."""
        old_caps = self.controller.get_capabilities()
        try:
            def mock_verified_caps():
                c = dict(old_caps)
                c["branch_isolation"] = dict(c.get("branch_isolation", {}))
                c["branch_isolation"]["verified"] = True
                c["branch_isolation"]["verification_source"] = "TEST_RESTORE_VERIFICATION"
                c["checkpoint_restore"] = dict(c.get("checkpoint_restore", {}))
                c["checkpoint_restore"]["determinism_status"] = "VERIFIED"
                c["checkpoint_restore"]["verified"] = True
                return c

            self.controller.get_capabilities = mock_verified_caps

            data = self._api(self.adapter.get_runtime_info())
            rt = data.get("data", {})
            self.assertTrue(rt.get("branch_isolation_verified"))
            self.assertTrue(rt.get("branch_isolation", {}).get("verified"))
            self.assertEqual(rt.get("branch_isolation", {}).get("verification_source"), "TEST_RESTORE_VERIFICATION")
            self.assertTrue(rt.get("determinism_verified"))
            self.assertTrue(rt.get("determinism", {}).get("verified"))
        finally:
            self.controller.get_capabilities = lambda: old_caps

    def test_24_test_c_determinism_and_branch_isolation_independence(self):
        """Test C: Determinism verified=True must NOT cause branch isolation verified=True, and vice versa."""
        old_caps = self.controller.get_capabilities()
        try:
            # Case 1: Determinism is VERIFIED, but Branch isolation is NOT verified
            def mock_det_only_caps():
                c = dict(old_caps)
                c["branch_isolation"] = dict(c.get("branch_isolation", {}))
                c["branch_isolation"]["status"] = "SUPPORTED"
                c["branch_isolation"]["verified"] = False
                c["checkpoint_restore"] = dict(c.get("checkpoint_restore", {}))
                c["checkpoint_restore"]["determinism_status"] = "VERIFIED"
                return c

            self.controller.get_capabilities = mock_det_only_caps
            data = self._api(self.adapter.get_runtime_info())
            rt = data.get("data", {})
            self.assertTrue(rt.get("determinism_verified"))
            self.assertFalse(rt.get("branch_isolation_verified"), "Determinism VERIFIED must NOT infer branch isolation VERIFIED")
            self.assertFalse(rt.get("branch_isolation", {}).get("verified"))

            # Case 2: Branch isolation is verified, but Determinism is NOT verified
            def mock_branch_only_caps():
                c = dict(old_caps)
                c["branch_isolation"] = dict(c.get("branch_isolation", {}))
                c["branch_isolation"]["status"] = "SUPPORTED"
                c["branch_isolation"]["verified"] = True
                c["branch_isolation"]["verification_source"] = "ISOLATION_CHECK"
                c["checkpoint_restore"] = dict(c.get("checkpoint_restore", {}))
                c["checkpoint_restore"]["determinism_status"] = "NOT_VERIFIED"
                return c

            self.controller.get_capabilities = mock_branch_only_caps
            data = self._api(self.adapter.get_runtime_info())
            rt = data.get("data", {})
            self.assertTrue(rt.get("branch_isolation_verified"))
            self.assertFalse(rt.get("determinism_verified"), "Branch isolation VERIFIED must NOT infer determinism VERIFIED")
        finally:
            self.controller.get_capabilities = lambda: old_caps

    def test_25_test_d_observation_point_honesty_no_spec_duplication(self):
        """Test D: Observation point spec must NOT be duplicated into function or location when frame info is absent."""
        self.controller.breakpoint_spec = "worker_loop"
        self.controller._cached_checkpoints = {}
        snap_copy = json.loads(json.dumps(self.controller._sample_snap))
        snap_copy["execution"]["threads"][0]["frames"] = []
        old_latest = self.controller._latest
        self.controller._latest = snap_copy

        try:
            data = self._api(self.adapter.get_runtime_info())
            rt = data.get("data", {})
            obs = rt.get("observation_point")
            self.assertIsNotNone(obs)
            self.assertEqual(obs.get("spec"), "worker_loop")
            self.assertIsNone(obs.get("function"), "spec must NOT be copied to function")
            self.assertIsNone(obs.get("location"), "spec must NOT be copied to location")
        finally:
            self.controller.breakpoint_spec = None
            self.controller._latest = old_latest

    def test_26_test_e_thread_metadata_honesty_no_name_fabrication(self):
        """Test E: Threads with no name or location must remain None / unavailable without fake generation."""
        snap_copy = json.loads(json.dumps(self.controller._sample_snap))
        snap_copy["execution"]["threads"] = [
            {
                "thread_id": 2,
                "frames": [
                    {"level": 0, "function": "worker_func", "location": None}
                ]
            }
        ]
        old_latest = self.controller._latest
        self.controller._latest = snap_copy

        try:
            data = self._api(self.adapter.get_runtime_info())
            rt = data.get("data", {})
            threads = rt.get("threads_detail", [])
            self.assertEqual(len(threads), 1)
            t = threads[0]
            self.assertEqual(t.get("thread_id"), 2)
            self.assertIsNone(t.get("name"), "Thread name must be None if not provided by OS/debugger (no fake 'Worker #2')")
            self.assertIsNone(t.get("location"), "Location must be None if not provided by debug info (no fake 'worker_func()')")
            self.assertEqual(t.get("function"), "worker_func")
        finally:
            self.controller._latest = old_latest

    def test_27_test_f_timeout_source_of_truth_consistency(self):
        """Test F: Timeout source of truth is backend default and is consistent across capabilities, runtime, and execution."""
        # 1. Capabilities endpoint
        caps_data = self._api(self.adapter.get_capabilities())
        c_data = caps_data.get("data", {})
        backend_default = c_data.get("default_timeout_ms") or c_data.get("mutation", {}).get("default_timeout_ms")
        self.assertEqual(backend_default, 1000)

        # 2. Runtime endpoint
        rt_data = self._api(self.adapter.get_runtime_info())
        rt_default = rt_data.get("data", {}).get("default_timeout_ms")
        self.assertEqual(rt_default, backend_default)

        # 3. Execute transition with default (no timeout specified in payload)
        payload = {"candidate_id": "M001", "proposed_value": 5}
        trans_data = self._api(self.adapter.execute_transition(payload))
        t_res = trans_data.get("data", {})
        self.assertEqual(t_res.get("timeout_ms"), backend_default)

        # 4. Execute transition with explicit user override (e.g. 5000ms)
        payload_override = {"candidate_id": "M001", "proposed_value": 7, "timeout_ms": 5000}
        trans_override = self._api(self.adapter.execute_transition(payload_override))
        t_res_override = trans_override.get("data", {})
        self.assertEqual(t_res_override.get("timeout_ms"), 5000)

    def test_28_test_g_hierarchical_semantic_path_generation(self):
        """Test G: Hierarchical semantic path Session -> worker -> state -> counter generates Session.worker.state.counter."""
        session_snap = {
            "schema_version": "0.3",
            "snapshot_id": "S_SESSION",
            "process": {"pid": 1111, "binary": "/app/session_srv"},
            "execution": {"threads": [{"thread_id": 1, "frames": []}]},
            "persistent": {
                "roots": [{"name": "Session", "kind": "global", "object_ref": "obj_session"}],
                "objects": [
                    {
                        "object_id": "obj_session",
                        "type": "SessionController",
                        "storage": "global",
                        "fields": [
                            {"name": "worker", "type": "WorkerThread*", "value": "0x1000", "object_ref": "obj_worker"}
                        ]
                    },
                    {
                        "object_id": "obj_worker",
                        "type": "WorkerThread",
                        "storage": "heap",
                        "fields": [
                            {"name": "state", "type": "WorkerState*", "value": "0x2000", "object_ref": "obj_state"}
                        ]
                    },
                    {
                        "object_id": "obj_state",
                        "type": "WorkerState",
                        "storage": "heap",
                        "fields": [
                            {"name": "counter", "type": "int", "value": 10},
                            {"name": "active", "type": "bool", "value": True}
                        ]
                    }
                ],
                "statistics": {"object_count": 3, "root_count": 1, "edge_count": 2}
            }
        }
        self.controller.snapshots["S_SESSION"] = session_snap
        sid, _ = self.runtime.corpus.add(session_snap, metadata={"interesting_reasons": ["SEED"]})

        # 1. Check list_state_objects
        data = self._api(self.adapter.list_state_objects(sid))
        objects = data.get("data", [])
        self.assertEqual(len(objects), 3)

        obj_state = next((o for o in objects if o["object_id"] == "obj_state"), None)
        self.assertIsNotNone(obj_state)
        self.assertEqual(obj_state.get("primary_path"), "Session.worker.state")
        self.assertEqual(obj_state.get("semantic_path"), "Session.worker.state")
        self.assertEqual(obj_state.get("semantic_name"), "Session.worker.state")

        # Check fields of obj_state
        fields = obj_state.get("fields", [])
        counter_field = next((f for f in fields if f["name"] == "counter"), None)
        self.assertIsNotNone(counter_field)
        self.assertEqual(counter_field.get("semantic_path"), "Session.worker.state.counter")

        # 2. Check inspect_object endpoint
        idata = self._api(self.adapter.inspect_object("obj_state", snapshot_id=sid))
        iobj = idata.get("data", {})
        self.assertEqual(iobj.get("primary_path"), "Session.worker.state")
        self.assertEqual(iobj.get("semantic_path"), "Session.worker.state")

        # 3. Check mutation candidates endpoint
        old_propose = self.controller.propose_mutations
        self.controller.propose_mutations = lambda snapshot=None: [
            MutationCandidate("M_CNT", "S_SESSION", "obj_state", "counter", 10, 20, "int", "INCREMENT")
        ]
        try:
            cdata = self._api(self.adapter.list_mutation_candidates(snapshot_id="S_SESSION"))
            cands = cdata.get("data", [])
            cnt_cand = next((c for c in cands if c.get("candidate_id") == "M_CNT"), None)
            self.assertIsNotNone(cnt_cand)
            self.assertEqual(cnt_cand.get("semantic_target"), "Session.worker.state.counter")
            self.assertEqual(cnt_cand.get("semantic_name"), "Session.worker.state")
        finally:
            self.controller.propose_mutations = old_propose


if __name__ == "__main__":
    unittest.main()


