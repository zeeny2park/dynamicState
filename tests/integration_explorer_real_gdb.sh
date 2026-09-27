#!/usr/bin/env bash
set -euo pipefail

# Integration test for Phase 4.1: Autonomous StateExplorer.run() with Real GDB.
# Verifies that StateExplorer.run() orchestrates checkpoint capture, candidate
# execution, parent restoration, state hashing, and corpus indexing autonomously.
# Core Invariant: Every sibling branch must start from exactly the same parent state (before == 2).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TMP_DIR="$(mktemp -d /tmp/dynstate_explorer_gdb_XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

CORPUS_DIR="${TMP_DIR}/corpus"
mkdir -p "${CORPUS_DIR}"

# 1. Compile test target with DWARF debug symbols
g++ -g -O0 -o "${TMP_DIR}/sample" "${ROOT_DIR}/examples/sample.cpp"

# 2. Run Autonomous StateExplorer via GDB Python
gdb -q -batch \
  -ex "file ${TMP_DIR}/sample" \
  -ex "set args 10" \
  -ex "source ${ROOT_DIR}/gdb/extract_state.py" \
  -ex "break runtime_state_checkpoint" \
  -ex "run" \
  -ex "python
import json, sys
import runtime_commands
from extractor.state_corpus import StateCorpus
from extractor.explorer import StateExplorer, MutationCandidate

controller = runtime_commands._CONTROLLER
corpus = StateCorpus('${CORPUS_DIR}')
explorer = StateExplorer(controller, corpus, '${CORPUS_DIR}')

# 1. Seed initial observation
seed_state_id = explorer.seed()
print('[E2E TEST] Seeded initial state:', seed_state_id)

# 2. Define specific sibling candidates (retry = 3, 1, 0)
seed_snap_id = explorer.seed_snapshot.snapshot_id
candidates = [
    MutationCandidate('M_RETRY_3', seed_snap_id, 'obj_0001', 'retry', 2, 3, 'uint32_t', 'BOUNDARY_PLUS_ONE'),
    MutationCandidate('M_RETRY_1', seed_snap_id, 'obj_0001', 'retry', 2, 1, 'uint32_t', 'BOUNDARY_MINUS_ONE'),
    MutationCandidate('M_RETRY_0', seed_snap_id, 'obj_0001', 'retry', 2, 0, 'uint32_t', 'ZERO_BOUNDARY'),
]

# 3. Autonomous run through StateExplorer.run()
result = explorer.run(max_steps=3, timeout_ms=1000, candidates=candidates)
print('[E2E TEST] Autonomous exploration complete:', result['exploration_id'])
print('[E2E TEST] Executed count:', result['executed_count'])
"

# 3. Validate exploration results and invariants
python3 - <<PY
import glob, json, os, sys

corpus_dir = "${CORPUS_DIR}"

# 1. Verify exploration artifact
exp_files = glob.glob(os.path.join(corpus_dir, "explorations", "E*.json"))
assert len(exp_files) == 1, f"Expected 1 exploration artifact, found {len(exp_files)}"
with open(exp_files[0]) as f:
    exp_artifact = json.load(f)

assert exp_artifact["executed_count"] == 3, f"Expected 3 executed steps, got {exp_artifact['executed_count']}"
assert exp_artifact["seed_state_id"] == "state_000001"

# Verify detailed performance metrics in step_metrics
step_metrics = exp_artifact["performance"]["step_metrics"]
assert len(step_metrics) == 3, f"Expected 3 step metrics, got {len(step_metrics)}"
for i, sm in enumerate(step_metrics):
    assert sm["status"] == "STOPPED", f"Step {i} status expected STOPPED, got {sm['status']}"
    assert sm["restore_ms"] >= 0.0, f"Step {i} restore_ms missing or invalid: {sm['restore_ms']}"
    assert sm["mutation_ms"] >= 0.0, f"Step {i} mutation_ms missing or invalid: {sm['mutation_ms']}"
    assert sm["continue_ms"] >= 0.0, f"Step {i} continue_ms missing or invalid: {sm['continue_ms']}"
    assert sm["snapshot_ms"] >= 0.0, f"Step {i} snapshot_ms missing or invalid: {sm['snapshot_ms']}"
    assert sm["diff_ms"] >= 0.0, f"Step {i} diff_ms missing or invalid: {sm['diff_ms']}"
    assert sm["hash_ms"] >= 0.0, f"Step {i} hash_ms missing or invalid: {sm['hash_ms']}"
    assert sm["step_ms"] >= 0.0, f"Step {i} step_ms missing or invalid: {sm['step_ms']}"
    assert sm["state_hash"] is not None, f"Step {i} child state_hash missing"

# 2. Verify all transitions from corpus/transitions/
trans_files = sorted(glob.glob(os.path.join(corpus_dir, "transitions", "T*.json")))
assert len(trans_files) == 3, f"Expected 3 transition files, found {len(trans_files)}"

t_records = []
for tf in trans_files:
    with open(tf) as f:
        t_records.append(json.load(f))

# Strict Invariant: Every candidate mutation MUST have before == 2 (parent state)
for i, tr in enumerate(t_records):
    t_obj = tr.get("transition", tr)
    mut = t_obj["mutation"]
    assert mut["before"] == 2, f"Transition {i+1} parent retry was {mut['before']}, expected 2"

# Verify candidate values
assert t_records[0].get("transition", t_records[0])["mutation"]["after"] == 3
assert t_records[1].get("transition", t_records[1])["mutation"]["after"] == 1
assert t_records[2].get("transition", t_records[2])["mutation"]["after"] == 0

# Verify semantic diff in child states:
# T1 (retry=3) -> state == ERROR
t1 = t_records[0].get("transition", t_records[0])
t1_state_change = next(c for c in t1["diff"]["changes"] if c.get("field") == "state")
assert "ERROR" in t1_state_change["after"], f"T1 state expected ERROR, got {t1_state_change['after']}"

# T3 (retry=0) -> state == DISCONNECTED
t3 = t_records[2].get("transition", t_records[2])
t3_state_change = next(c for c in t3["diff"]["changes"] if c.get("field") == "state")
assert "DISCONNECTED" in t3_state_change["after"], f"T3 state expected DISCONNECTED, got {t3_state_change['after']}"

print("[VERIFIED] StateExplorer.run() executed 3 branches autonomously.")
print("[VERIFIED] All 3 branches started strictly from parent retry == 2.")
print("[VERIFIED] All performance instrumentation metrics recorded.")
PY

echo "Explorer Real GDB integration test passed"
