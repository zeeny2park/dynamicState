#!/usr/bin/env bash
set -euo pipefail

# Integration test for Phase 4.1: Failure and Crash Isolation in StateExplorer.run().
# Verifies that severe failures in candidate branches (SIGSEGV crash, timeout)
# do NOT corrupt the parent checkpoint or prevent subsequent sibling branches
# from executing cleanly from the pristine parent state.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TMP_DIR="$(mktemp -d /tmp/dynstate_failure_iso_XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

CORPUS_DIR="${TMP_DIR}/corpus"
mkdir -p "${CORPUS_DIR}"

# 1. Compile test target with DWARF debug symbols
g++ -g -O0 -o "${TMP_DIR}/sample" "${ROOT_DIR}/examples/sample.cpp"

# 2. Run Autonomous StateExplorer with Crash, Timeout, and Normal candidates
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
print('[FAILURE ISO TEST] Seeded initial state:', seed_state_id)

seed_snap_id = explorer.seed_snapshot.snapshot_id
candidates = [
    # Candidate 1: triggers SIGSEGV via null pointer dereference
    MutationCandidate('M_CRASH', seed_snap_id, 'obj_0001', 'priority', 7, 139, 'uint8_t', 'TRIGGER_SIGSEGV'),
    # Candidate 2: triggers infinite loop interrupted by 200ms timeout
    MutationCandidate('M_TIMEOUT', seed_snap_id, 'obj_0001', 'priority', 7, 255, 'uint8_t', 'TRIGGER_TIMEOUT'),
    # Candidate 3: normal execution (retry = 1)
    MutationCandidate('M_NORMAL', seed_snap_id, 'obj_0001', 'retry', 2, 1, 'uint32_t', 'NORMAL_EXECUTION'),
]

# 2. Run exploration loop with failure isolation
result = explorer.run(max_steps=3, timeout_ms=200, candidates=candidates)
print('[FAILURE ISO TEST] Exploration complete:', result['exploration_id'])
print('[FAILURE ISO TEST] Executed count:', result['executed_count'])
print('[FAILURE ISO TEST] Crashes:', result['crash_count'])
print('[FAILURE ISO TEST] Timeouts:', result['timeout_count'])
"

# 3. Validate isolation invariants
python3 - <<PY
import glob, json, os, sys

corpus_dir = "${CORPUS_DIR}"

# 1. Verify exploration artifact
exp_files = glob.glob(os.path.join(corpus_dir, "explorations", "E*.json"))
assert len(exp_files) == 1, f"Expected 1 exploration artifact, found {len(exp_files)}"
with open(exp_files[0]) as f:
    exp_artifact = json.load(f)

assert exp_artifact["executed_count"] == 3, f"Expected 3 executed steps, got {exp_artifact['executed_count']}"
assert exp_artifact["crash_count"] == 1, f"Expected 1 crash, got {exp_artifact['crash_count']}"
assert exp_artifact["timeout_count"] == 1, f"Expected 1 timeout, got {exp_artifact['timeout_count']}"

step_metrics = exp_artifact["performance"]["step_metrics"]
assert len(step_metrics) == 3, f"Expected 3 step metrics, got {len(step_metrics)}"

# Step 0: CRASHED
assert step_metrics[0]["status"] == "CRASHED", f"Step 0 expected CRASHED, got {step_metrics[0]['status']}"
assert step_metrics[0]["candidate_id"] == "M_CRASH"
assert step_metrics[0]["child_state_id"] is None

# Step 1: TIMEOUT
assert step_metrics[1]["status"] == "TIMEOUT", f"Step 1 expected TIMEOUT, got {step_metrics[1]['status']}"
assert step_metrics[1]["candidate_id"] == "M_TIMEOUT"
assert step_metrics[1]["child_state_id"] is None

# Step 2: STOPPED (Normal execution recovered from parent!)
assert step_metrics[2]["status"] == "STOPPED", f"Step 2 expected STOPPED, got {step_metrics[2]['status']}"
assert step_metrics[2]["candidate_id"] == "M_NORMAL"
assert step_metrics[2]["child_state_id"] is not None
assert step_metrics[2]["state_hash"] is not None

# 2. Verify all transitions from corpus/transitions/
trans_files = sorted(glob.glob(os.path.join(corpus_dir, "transitions", "T*.json")))
assert len(trans_files) == 3, f"Expected 3 transition files, found {len(trans_files)}"

t_records = []
for tf in trans_files:
    with open(tf) as f:
        t_records.append(json.load(f))

# Transition 1: Crash
t1 = t_records[0].get("transition", t_records[0])
assert t1["execution"]["status"] == "CRASHED"
assert t1["execution"]["signal"] == "SIGSEGV"
assert t1["child_snapshot"] is None
assert t1["diff"] is None

# Transition 2: Timeout
t2 = t_records[1].get("transition", t_records[1])
assert t2["execution"]["status"] == "TIMEOUT"
assert t2["child_snapshot"] is None
assert t2["diff"] is None

# Transition 3: Normal Sibling
t3 = t_records[2].get("transition", t_records[2])
assert t3["execution"]["status"] == "STOPPED"
assert t3["child_snapshot"] is not None
assert t3["diff"] is not None
# Strict Invariant: despite prior crash and timeout, parent retry was preserved at 2!
assert t3["mutation"]["before"] == 2, f"Expected parent before == 2, got {t3['mutation']['before']}"
assert t3["mutation"]["after"] == 1, f"Expected parent after == 1, got {t3['mutation']['after']}"

print("[VERIFIED] Crash (SIGSEGV) and Timeout (SIGINT) isolated successfully.")
print("[VERIFIED] Subsequent candidate executed cleanly from restored parent state (before == 2).")
PY

echo "Explorer Failure Isolation integration test passed"
