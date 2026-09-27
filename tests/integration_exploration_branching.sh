#!/usr/bin/env bash
set -euo pipefail

# Integration test for Phase 4 Branch-safe Runtime State Exploration.
# Verifies that multiple mutation candidates (retry=3, retry=1, retry=0)
# execute independently from the exact same parent runtime state (retry=2).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TMP_DIR="${ROOT_DIR}/tmp_branching_test"
rm -rf "${TMP_DIR}"
mkdir -p "${TMP_DIR}/snapshots" "${TMP_DIR}/transitions" "${TMP_DIR}/corpus"

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

# 1. Compile test target
g++ -g -O0 -o sample examples/sample.cpp

# 2. Run GDB branching exploration
gdb -q -batch \
  -ex "file ./sample" \
  -ex "set args 10" \
  -ex "source gdb/extract_state.py" \
  -ex "break runtime_state_checkpoint" \
  -ex "run" \
  -ex "python
import json, os, sys
import runtime_commands
from extractor.state_corpus import StateCorpus
from extractor.explorer import StateExplorer, MutationCandidate

controller = runtime_commands._CONTROLLER
corpus = StateCorpus('${TMP_DIR}/corpus')
explorer = StateExplorer(controller, corpus, '${TMP_DIR}/corpus')

# 1. Seed snapshot
seed_state_id = explorer.seed()
seed_snap = explorer.seed_snapshot
print('[TEST] Seed snapshot captured:', seed_snap.snapshot_id)

# 2. Capture Parent Runtime Checkpoint
parent_cp = controller.checkpoint('C_PARENT')
print('[TEST] Parent Checkpoint captured:', parent_cp.checkpoint_id)

# 3. Branch 1: retry = 3
controller.restore(parent_cp)
t1 = controller.execute_transition(
    path='Session.retry',
    value=3,
    transition_id='T001',
    output='${TMP_DIR}/transitions/T001.json',
    snapshots_dir='${TMP_DIR}/snapshots'
)
print('[TEST] Branch 1 executed: before =', t1.mutation.before, '-> after =', t1.mutation.after)

# 4. Branch 2: retry = 1
controller.restore(parent_cp)
t2 = controller.execute_transition(
    path='Session.retry',
    value=1,
    transition_id='T002',
    output='${TMP_DIR}/transitions/T002.json',
    snapshots_dir='${TMP_DIR}/snapshots'
)
print('[TEST] Branch 2 executed: before =', t2.mutation.before, '-> after =', t2.mutation.after)

# 5. Branch 3: retry = 0
controller.restore(parent_cp)
t3 = controller.execute_transition(
    path='Session.retry',
    value=0,
    transition_id='T003',
    output='${TMP_DIR}/transitions/T003.json',
    snapshots_dir='${TMP_DIR}/snapshots'
)
print('[TEST] Branch 3 executed: before =', t3.mutation.before, '-> after =', t3.mutation.after)

controller.release_checkpoint(parent_cp)
print('[TEST] Checkpoint released successfully.')
"

# 3. Validate branching invariants on transition JSON files
python3 - <<EOF
import json, sys

with open("${TMP_DIR}/transitions/T001.json") as f:
    t1 = json.load(f)
with open("${TMP_DIR}/transitions/T002.json") as f:
    t2 = json.load(f)
with open("${TMP_DIR}/transitions/T003.json") as f:
    t3 = json.load(f)

# Invariant: Every candidate mutation MUST have before == 2 (the parent state)
assert t1["mutation"]["before"] == 2, f"T001 expected before==2, got {t1['mutation']['before']}"
assert t1["mutation"]["after"] == 3, f"T001 expected after==3, got {t1['mutation']['after']}"

assert t2["mutation"]["before"] == 2, f"T002 expected before==2 (isolated parent), got {t2['mutation']['before']}"
assert t2["mutation"]["after"] == 1, f"T002 expected after==1, got {t2['mutation']['after']}"

assert t3["mutation"]["before"] == 2, f"T003 expected before==2 (isolated parent), got {t3['mutation']['before']}"
assert t3["mutation"]["after"] == 0, f"T003 expected after==0, got {t3['mutation']['after']}"

# Verify resulting states in children
# In T001: retry=3 caused state -> ERROR
t1_state_change = next(c for c in t1["diff"]["changes"] if c.get("field") == "state")
assert "ERROR" in t1_state_change["after"], f"T001 state expected ERROR, got {t1_state_change['after']}"

# In T003: retry=0 caused state -> DISCONNECTED
t3_state_change = next(c for c in t3["diff"]["changes"] if c.get("field") == "state")
assert "DISCONNECTED" in t3_state_change["after"], f"T003 state expected DISCONNECTED, got {t3_state_change['after']}"

print("[VERIFIED] All 3 candidates branched independently from parent retry == 2.")
EOF

echo "Exploration Branching integration test passed"
