"""GDB Python Scenario for Real-World Workload Validation.

Executed inside GDB batch session:
gdb -q -nx -batch -ex "file sample_prod_stripped" -ex "source gdb/extract_state.py" \
    -ex "load-debug-image sample_prod.debug" -ex "break runtime_state_checkpoint" \
    -ex "run 10" -ex "python -m tests.real_world_gdb_scenario"
"""

import json
import os
import sys
import threading
import time
import urllib.request
import urllib.error

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

import runtime_commands
from extractor.agent_runtime import AgentRuntime
from extractor.web.server import run_server


def run_gdb_validation_scenario(results_output_path):
    print("\n=== Validating CONSISTENT Observation Mode under Live GDB ===")
    controller = runtime_commands._CONTROLLER
    assert controller is not None, "Failed to obtain live GDB controller"

    tmp_dir = os.path.join(os.path.dirname(results_output_path), "gdb_corpus")
    os.makedirs(tmp_dir, exist_ok=True)

    runtime = AgentRuntime(controller=controller, corpus_dir=tmp_dir)
    server = run_server(runtime=runtime, host="127.0.0.1", port=0)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    print(f"[GDB LIVE] Web UI server listening on {base_url}")

    results = {}
    client_done = threading.Event()
    client_error = []

    def _worker():
        try:
            def get_json(path):
                req = urllib.request.Request(base_url + path)
                with urllib.request.urlopen(req) as resp:
                    return resp.status, json.loads(resp.read().decode("utf-8"))

            def post_json(path, payload):
                req = urllib.request.Request(
                    base_url + path,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                try:
                    with urllib.request.urlopen(req) as resp:
                        return resp.status, json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as err:
                    return err.code, json.loads(err.read().decode("utf-8"))

            # Step 1: Runtime Info
            print("[Step 1] Querying /api/runtime...")
            status, rt_res = get_json("/api/runtime")
            assert status == 200 and rt_res["success"], f"Runtime info failed: {rt_res}"
            rt_data = rt_res["data"]
            print(f"[GDB LIVE] Target Arch: {rt_data.get('architecture')}, Endianness: {rt_data.get('endianness')}, Debug Image: {rt_data.get('debug_image')} ({rt_data.get('debug_image_status')})")
            results["runtime_info"] = rt_data

            # Step 2: Observe
            print("[Step 2] Observing runtime via /api/observe (CONSISTENT)...")
            status, obs_res = post_json("/api/observe", {"mode": "CONSISTENT"})
            assert status == 200 and obs_res["success"], f"Observe failed: {obs_res}"
            obs = obs_res["data"]
            seed_state_id = obs.get("state_id") or "state_000001"
            exec_ctx = obs.get("execution", {})
            print(f"[GDB LIVE] Seed State: {seed_state_id}, Execution Function: {exec_ctx.get('function')}, Status: STOPPED")
            results["observe"] = obs

            # Step 3: Semantic Objects
            print(f"[Step 3] Querying semantic objects for {seed_state_id}...")
            status, objs_res = get_json(f"/api/states/{seed_state_id}/objects")
            assert status == 200 and objs_res["success"]
            objs = objs_res["data"]
            print(f"[GDB LIVE] Discovered {len(objs)} objects: {[o['object_id'] + ' (' + o['type'] + ')' for o in objs]}")
            results["objects_summary"] = objs

            session_obj = next(o for o in objs if o["type"] == "Session")
            buffer_obj = next(o for o in objs if o["type"] == "Buffer")
            session_id = session_obj["object_id"]
            buffer_id = buffer_obj["object_id"]

            # Step 4: Inspect Object (Session)
            print(f"[Step 4] Inspecting Session object {session_id}...")
            status, s_detail = get_json(f"/api/objects/{session_id}")
            assert status == 200 and s_detail["success"]
            s_data = s_detail["data"]
            fields = {f["name"]: f for f in s_data.get("fields", [])}
            print(f"[GDB LIVE] Session fields: retry={fields['retry']['value']}, state={fields['state']['value']}, parent={fields['parent']['value']}")
            assert fields["retry"]["value"] == 2
            assert "CONNECTED" in str(fields["state"]["value"])
            # Circular reference check
            assert fields["parent"]["object_ref"] == session_id or fields["parent"]["value"] != "0x0"
            results["session_object"] = s_data

            # Step 5: Inspect Object (Buffer)
            print(f"[Step 5] Inspecting Buffer object {buffer_id}...")
            status, b_detail = get_json(f"/api/objects/{buffer_id}")
            assert status == 200 and b_detail["success"]
            b_data = b_detail["data"]
            b_fields = {f["name"]: f for f in b_data.get("fields", [])}
            print(f"[GDB LIVE] Buffer fields: length={b_fields['length']['value']}, capacity={b_fields['capacity']['value']}")
            assert b_fields["length"]["value"] == 64
            assert b_fields["capacity"]["value"] == 256
            results["buffer_object"] = b_data

            # Step 6: Field detail
            print(f"[Step 6] Inspecting retry field...")
            status, f_detail = get_json(f"/api/objects/{session_id}/fields?field=retry")
            assert status == 200 and f_detail["success"]
            print(f"[GDB LIVE] retry field: value={f_detail['data']['value']}, mutability={f_detail['data']['mutability']}")
            results["retry_field"] = f_detail["data"]

            # Step 7: Mutation Candidates
            print(f"[Step 7] Querying mutation candidates for retry...")
            status, cands_res = get_json(f"/api/mutation-candidates?object_id={session_id}&field=retry")
            assert status == 200 and cands_res["success"]
            cands = cands_res["data"]
            print(f"[GDB LIVE] Found {len(cands)} candidates for retry:")
            for c in cands:
                print(f"   Candidate {c['candidate_id']}: {c['current_value']} -> {c['proposed_value']} ({c['reason']})")
            results["candidates"] = cands

            cand_retry_3 = next(c for c in cands if c.get("proposed_value") == 3)
            cand_retry_0 = next(c for c in cands if c.get("proposed_value") == 0)

            # Step 8: Capture Checkpoint for Branch Isolation
            print("[Step 8] Creating checkpoint C_SEED via /api/checkpoint...")
            status, cp_res = post_json("/api/checkpoint", {"checkpoint_id": "C_SEED"})
            assert status == 200 and cp_res["success"], f"Checkpoint failed: {cp_res}"
            print("[GDB LIVE] Checkpoint C_SEED captured successfully.")

            # Step 9: Execute Branch 1 (retry = 2 -> 3)
            print(f"[Step 9] Executing Branch 1: Candidate {cand_retry_3['candidate_id']} (retry = 2 -> 3)...")
            status, mut1_res = post_json("/api/mutation", {"candidate_id": cand_retry_3["candidate_id"], "timeout_ms": 1000})
            assert status == 200 and mut1_res["success"], f"Branch 1 mutation failed: {mut1_res}"
            t1 = mut1_res["data"]
            t1_id = t1["transition_id"]
            child1_state_id = t1.get("child_state")
            child1_meta = runtime.corpus.get_metadata(child1_state_id)
            child1_hash = child1_meta.get("state_hash")
            t1_facts = t1.get("facts", {})
            print(f"[GDB LIVE] Branch 1 Transition {t1_id} -> Child State: {child1_state_id}, Hash: {child1_hash}")
            print(f"[GDB LIVE] Branch 1 Facts: branch_changed={t1_facts.get('branch_changed')}, field_changed={t1_facts.get('field_changed')}")
            assert t1_facts.get("branch_changed") is True
            assert any("Session.retry" in f for f in t1_facts.get("field_changed", []))
            assert any("Session.state" in f for f in t1_facts.get("field_changed", []))
            assert any("Session.flagged" in f for f in t1_facts.get("field_changed", []))
            results["branch_1"] = {
                "transition_id": t1_id,
                "child_state_id": child1_state_id,
                "state_hash": child1_hash,
                "facts": t1_facts,
                "evidence": t1.get("evidence", [])
            }

            # Verify child state values
            status, c1_detail = get_json(f"/api/states/{child1_state_id}")
            assert status == 200 and c1_detail["success"]

            # Step 10: Restore Checkpoint C_SEED and Verify Isolation
            print("[Step 10] Restoring checkpoint C_SEED via /api/restore (Branch Isolation)...")
            status, rest_res = post_json("/api/restore", {"checkpoint_id": "C_SEED"})
            assert status == 200 and rest_res["success"], f"Restore failed: {rest_res}"
            print("[GDB LIVE] Restored C_SEED successfully.")

            # Verify runtime restored to retry == 2
            status, r_detail = get_json(f"/api/objects/{session_id}/fields?field=retry")
            assert status == 200 and r_detail["success"]
            print(f"[GDB LIVE] Verified restored parent retry value: {r_detail['data']['value']}")
            assert r_detail["data"]["value"] == 2

            # Step 11: Execute Branch 2 (retry = 2 -> 0)
            print(f"[Step 11] Executing Branch 2: Candidate {cand_retry_0['candidate_id']} (retry = 2 -> 0)...")
            status, mut2_res = post_json("/api/mutation", {"candidate_id": cand_retry_0["candidate_id"], "timeout_ms": 1000})
            assert status == 200 and mut2_res["success"], f"Branch 2 mutation failed: {mut2_res}"
            t2 = mut2_res["data"]
            t2_id = t2["transition_id"]
            child2_state_id = t2.get("child_state")
            child2_meta = runtime.corpus.get_metadata(child2_state_id)
            child2_hash = child2_meta.get("state_hash")
            t2_facts = t2.get("facts", {})
            print(f"[GDB LIVE] Branch 2 Transition {t2_id} -> Child State: {child2_state_id}, Hash: {child2_hash}")
            print(f"[GDB LIVE] Branch 2 Facts: branch_changed={t2_facts.get('branch_changed')}, field_changed={t2_facts.get('field_changed')}")
            assert t2_facts.get("branch_changed") is True
            assert any("Session.retry" in f for f in t2_facts.get("field_changed", []))
            assert any("Session.state" in f for f in t2_facts.get("field_changed", []))
            results["branch_2"] = {
                "transition_id": t2_id,
                "child_state_id": child2_state_id,
                "state_hash": child2_hash,
                "facts": t2_facts,
                "evidence": t2.get("evidence", [])
            }

            # Step 12: State Hash Invariance & Sensitivity Verification
            seed_meta = runtime.corpus.get_metadata(seed_state_id)
            seed_hash = seed_meta.get("state_hash")
            print(f"[GDB LIVE] State Hashes: Seed={seed_hash}, Branch1(retry=3)={child1_hash}, Branch2(retry=0)={child2_hash}")
            assert seed_hash != child1_hash, "State Hash failed sensitivity check (seed vs branch 1)"
            assert seed_hash != child2_hash, "State Hash failed sensitivity check (seed vs branch 2)"
            assert child1_hash != child2_hash, "State Hash failed sensitivity check (branch 1 vs branch 2)"
            results["state_hashes"] = {
                "seed": seed_hash,
                "branch_1_error": child1_hash,
                "branch_2_disconnected": child2_hash
            }

            # Step 13: Failure Case Representation
            print("[Step 13] Verifying failure case representation (CRASHED / SIGSEGV)...")
            from extractor.runtime_controller import ExecutionResult, MutationResult
            from extractor.snapshot import StateTransition
            crash_trans = StateTransition(
                transition_id="T_VAL_CRASH",
                parent_snapshot=obs.get("snapshot_id", "S001"),
                child_snapshot=None,
                mutation=MutationResult(success=True, object_id=session_id, field="priority", before=7, after=139),
                execution=ExecutionResult(status="CRASHED", signal="SIGSEGV", reason="Address not mapped to object")
            )
            runtime.corpus.add_transition(crash_trans)
            status, t_crash = get_json("/api/transitions/T_VAL_CRASH")
            assert status == 200 and t_crash["success"]
            assert t_crash["data"]["execution"]["status"] == "CRASHED"
            assert t_crash["data"]["execution"]["signal"] == "SIGSEGV"
            print("[GDB LIVE] Failure case successfully recorded and verified.")
            results["failure_case"] = t_crash["data"]

            # Step 14: State Graph Visualization
            print("[Step 14] Querying State Graph via /api/state-graph...")
            status, g_res = get_json("/api/state-graph")
            assert status == 200 and g_res["success"]
            graph_data = g_res["data"]
            nodes = graph_data["nodes"]
            edges = graph_data["edges"]
            print(f"[GDB LIVE] State Graph: {len(nodes)} nodes, {len(edges)} edges:")
            for e in edges:
                print(f"   Edge {e['id']}: {e['from']} -> {e['to']} ({e['field']}: {e['old_value']} -> {e['new_value']}) [status={e['status']}]")
            assert len(nodes) >= 3
            assert len(edges) >= 2
            results["state_graph"] = graph_data

            print("\nALL LIVE GDB ACCEPTANCE SCENARIOS PASSED CLEANLY!")
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

        with open(results_output_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[GDB LIVE] Results saved to {results_output_path}")
        return True
    finally:
        server.server_close()


if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/real_world_gdb_results.json"
    success = run_gdb_validation_scenario(out_path)
    sys.exit(0 if success else 1)
