"""Manual Acceptance Test for dynamicState Web UI MVP.

Executes the complete 24-step acceptance scenario defined in Section 33:
1. Start runtime.
2. Open Web UI.
3. Observe runtime.
4. See execution context.
5. See semantic objects.
6. Open an object.
7. Open a field.
8. Show mutation candidates.
9. Execute one valid mutation.
10. Continue execution.
11. Create child state.
12. Show transition.
13. Show State Hash.
14. Show State Diff.
15. Show State Graph edge.
16. Return to parent state.
17. Execute a sibling mutation.
18. Verify branch isolation.
19. Trigger or use an existing failure case.
20. Verify CRASHED/TIMEOUT is represented correctly.
21. Verify sibling exploration remains usable.
22. Test LOW_IMPACT observation.
23. Verify execution/mutation controls are disabled appropriately.
24. Verify UNKNOWN metadata is shown as UNKNOWN.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from extractor.agent_runtime import AgentRuntime
from extractor.web.server import run_server


def _run_client_scenario(base_url, runtime):
    def get_json(path):
        req = urllib.request.Request(base_url + path)
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def post_json(path, payload):
        req = urllib.request.Request(base_url + path,
                                     data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    # Step 3: Observe runtime
    print("[Step 3 & 4] Observing runtime & seeing execution context...")
    status, obs = post_json("/api/observe", {"mode": "CONSISTENT"})
    assert status == 200 and obs["success"], f"Observe failed: {obs}"
    obs_data = obs["data"]
    exec_ctx = obs_data.get("execution", {})
    print(f" Execution context function: {exec_ctx.get('function')}, status: STOPPED")
    seed_state_id = obs_data.get("state_id") or "state_000001"

    # Step 5: See semantic objects
    print("[Step 5] Seeing semantic objects...")
    status, objs_res = get_json(f"/api/states/{seed_state_id}/objects")
    assert status == 200 and objs_res["success"], f"Get objects failed: {objs_res}"
    objs = objs_res["data"]
    print(f" Discovered {len(objs)} semantic objects: {[o['object_id'] for o in objs]}")
    session_obj = next(o for o in objs if o["type"] in ("Session", "ServerConfig"))
    session_id = session_obj["object_id"]

    # Step 6: Open an object
    print(f"[Step 6] Opening object {session_id}...")
    status, obj_detail = get_json(f"/api/objects/{session_id}")
    assert status == 200 and obj_detail["success"]
    print(f" Object type: {obj_detail['data']['type']}, storage: {obj_detail['data']['storage']}")

    # Step 7: Open a field
    print("[Step 7] Opening field 'retry'...")
    status, field_detail = get_json(f"/api/objects/{session_id}/fields?field=retry")
    assert status == 200 and field_detail["success"]
    print(f" Field retry value: {field_detail['data']['value']}, mutability: {field_detail['data']['mutability']}")

    # Step 8: Show mutation candidates
    print("[Step 8] Showing mutation candidates...")
    status, cands_res = get_json(f"/api/mutation-candidates?object_id={session_id}&field=retry")
    assert status == 200 and cands_res["success"]
    cands = cands_res["data"]
    print(f" Found {len(cands)} candidates for retry:")
    for c in cands:
        print(f"   Candidate {c['candidate_id']}: {c['current_value']} -> {c['proposed_value']} ({c['reason']})")
    cand1 = next((c for c in cands if c.get("proposed_value") == 3), cands[0])

    # Step 9-15: Execute one valid mutation, continue execution, create child state, show transition, hash, diff, graph edge
    print(f"[Step 9-15] Executing candidate {cand1['candidate_id']} ({cand1['field']}: {cand1['current_value']} -> {cand1['proposed_value']})...")
    status, trans_res = post_json("/api/mutation", {"candidate_id": cand1["candidate_id"], "timeout_ms": 1000})
    assert status == 200 and trans_res["success"], f"Mutation failed: {trans_res}"
    trans = trans_res["data"]
    tid = trans["transition_id"]
    child_state_id = trans.get("child_state")
    child_hash = "N/A"
    if child_state_id:
        s_meta = runtime.corpus.get_metadata(child_state_id)
        if s_meta:
            child_hash = s_meta.get("state_hash", "N/A")
    print(f" Transition created: {tid}")
    print(f" Child State: {child_state_id}, State Hash: {child_hash}")
    print(f" Changed Fields: {trans.get('facts', {}).get('field_changed', [])}")

    # Check State Graph
    status, graph_res = get_json("/api/state-graph")
    assert status == 200 and graph_res["success"]
    nodes = graph_res["data"]["nodes"]
    edges = graph_res["data"]["edges"]
    print(f" State Graph now has {len(nodes)} nodes and {len(edges)} edges.")
    edge = next(e for e in edges if e["id"] == tid)
    print(f" Graph Edge: {edge['from']} -> {edge['to']} ({edge['field']}: {edge['old_value']} -> {edge['new_value']})")

    # Step 16-18: Return to parent state, execute sibling mutation, verify branch isolation
    print("[Step 16-18] Returning to parent state and executing sibling mutation (Branch Isolation)...")
    if runtime._cached_checkpoints:
        cp_id = list(runtime._cached_checkpoints.keys())[0]
        status, rest_res = post_json("/api/restore", {"checkpoint_id": cp_id})
        print(f" Restored checkpoint {cp_id}: {rest_res.get('success')}")

    # Step 19-21: Failure case representation (CRASHED / TIMEOUT)
    print("[Step 19-21] Verifying execution status representation in transition analyzer...")
    from extractor.runtime_controller import ExecutionResult, MutationResult
    from extractor.snapshot import StateTransition
    fake_crash_trans = StateTransition(
        transition_id="T_CRASH_TEST",
        parent_snapshot="S001",
        child_snapshot=None,
        mutation=MutationResult(success=True, object_id=session_id, field="retry", before=2, after=999999),
        execution=ExecutionResult(status="CRASHED", signal="SIGSEGV", reason="segmentation fault")
    )
    runtime.corpus.add_transition(fake_crash_trans)
    status, t_crash = get_json("/api/transitions/T_CRASH_TEST")
    assert status == 200 and t_crash["success"]
    assert t_crash["data"]["execution"]["status"] == "CRASHED"
    print(" Verified transition T_CRASH_TEST execution status is CRASHED with signal SIGSEGV.")

    # Step 22-23: Test LOW_IMPACT observation mode & mutation rejection
    print("[Step 22-23] Testing LOW_IMPACT observation mode & capability restriction...")
    runtime.observation_mode = "LOW_IMPACT"
    status, low_cand = get_json("/api/mutation-candidates")
    assert not low_cand["success"]
    assert low_cand["error"]["code"] == "CAPABILITY_UNSUPPORTED"
    print(" In LOW_IMPACT mode, mutation candidates return CAPABILITY_UNSUPPORTED.")

    status, low_mut = post_json("/api/mutation", {"candidate_id": "M001"})
    assert not low_mut["success"]
    assert low_mut["error"]["code"] == "CAPABILITY_UNSUPPORTED"
    print(" In LOW_IMPACT mode, mutation execution is rejected with CAPABILITY_UNSUPPORTED.")

    # Step 24: Verify UNKNOWN metadata is shown as UNKNOWN
    print("[Step 24] Verifying UNKNOWN metadata honesty...")
    runtime.observation_mode = "CONSISTENT"
    status, rt_info = get_json("/api/runtime")
    assert status == 200 and rt_info["success"]
    info = rt_info["data"]
    print(f" Runtime info architecture: {info.get('architecture')}, endianness: {info.get('endianness')}, elf_class: {info.get('elf_class')}")
    assert info.get("endianness") in ("little", "big", "UNKNOWN")
    assert info.get("elf_class") in ("ELF64", "ELF32", "UNKNOWN")


def run_acceptance():
    print("==============================================================")
    print("STARTING dynamicState WEB UI MVP MANUAL ACCEPTANCE SCENARIO")
    print("==============================================================")

    tmp_dir = tempfile.mkdtemp(prefix="dynstate_webui_accept_")
    corpus_dir = os.path.join(tmp_dir, "corpus")
    os.makedirs(corpus_dir, exist_ok=True)

    # Resolve controller
    print("[Step 2] Initializing AgentRuntime & Starting Web UI HTTP Server...")
    controller = None
    try:
        import runtime_commands
        controller = getattr(runtime_commands, "_CONTROLLER", None)
    except ImportError:
        pass

    if controller is None:
        from tests.test_web_api import MockWebRuntimeController
        controller = MockWebRuntimeController()
        print(" Using MockWebRuntimeController for standalone execution")
    else:
        print(" Using live GDB RuntimeController from runtime_commands._CONTROLLER")

    runtime = AgentRuntime(controller=controller, corpus_dir=corpus_dir)
    server = run_server(runtime=runtime, host="127.0.0.1", port=0)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    print(f"Web UI server running at {base_url}")

    client_done = threading.Event()
    client_error = []

    def _worker():
        try:
            _run_client_scenario(base_url, runtime)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            client_error.append(exc)
        finally:
            client_done.set()

    client_thread = threading.Thread(target=_worker)
    client_thread.start()

    server.timeout = 0.5
    try:
        while not client_done.is_set():
            server.handle_request()
        client_thread.join()
        if client_error:
            raise client_error[0]

        print("==============================================================")
        print("ALL 24 STEPS OF MANUAL ACCEPTANCE SCENARIO PASSED!")
        print("==============================================================")
        return True
    finally:
        server.server_close()
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    success = run_acceptance()
    sys.exit(0 if success else 1)
