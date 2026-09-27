#!/usr/bin/env bash
set -euo pipefail

# Integration test for State Transition and State Exploration on Stripped Binaries
# with External Debug Images.
# Verifies:
# 1. Stripped production binary + external debug image execution.
# 2. StateTransition (Snapshot A -> Mutate Session.retry=3 -> Continue -> Snapshot B -> Semantic Diff).
# 3. Deterministic verification: Session.state CONNECTED -> ERROR, Session.flagged false -> true.
# 4. Provenance tracking throughout transition and exploration states.
# 5. StateExplorer systematic exploration on stripped binary yielding valid StateCorpus.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TMP_DIR="$(mktemp -d /tmp/dynstate_stripped_trans_XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/snapshots" "${TMP_DIR}/transitions" "${TMP_DIR}/corpus"

# 1. Compile matching sample binary and extract debug image
g++ -g -O0 -o "${TMP_DIR}/sample" "${ROOT_DIR}/examples/sample.cpp"
objcopy --only-keep-debug "${TMP_DIR}/sample" "${TMP_DIR}/sample.debug"
strip -s -o "${TMP_DIR}/sample_stripped" "${TMP_DIR}/sample"

# 2. Run GDB State Transition and Exploration on stripped binary
gdb -q -nx -batch \
  -ex "set confirm off" \
  -ex "file ${TMP_DIR}/sample_stripped" \
  -ex "source ${ROOT_DIR}/gdb/extract_state.py" \
  -ex "load-debug-image ${TMP_DIR}/sample.debug" \
  -ex "set args 10" \
  -ex "break runtime_state_checkpoint" \
  -ex "run" \
  -ex "transition-state --path Session.retry --value 3 --id T001 --parent A --child B --output ${TMP_DIR}/transitions/T001.json --snapshots-dir ${TMP_DIR}/snapshots" \
  -ex "explore-state --steps 3 --corpus-dir ${TMP_DIR}/corpus" > "${TMP_DIR}/transcript.txt"

# 3. Deterministic verification of State Transition Artifact, Snapshots, Provenance, and Corpus
python3 - "${TMP_DIR}/transitions/T001.json" "${TMP_DIR}/snapshots/A.json" "${TMP_DIR}/snapshots/B.json" "${TMP_DIR}/corpus" <<'PY'
import json, os, sys
from extractor.state_corpus import StateCorpus

trans_path = sys.argv[1]
snap_a_path = sys.argv[2]
snap_b_path = sys.argv[3]
corpus_dir = sys.argv[4]

assert os.path.exists(trans_path), "Transition artifact not found"
assert os.path.exists(snap_a_path), "Snapshot A not found"
assert os.path.exists(snap_b_path), "Snapshot B not found"

trans_data = json.load(open(trans_path))
snap_a = json.load(open(snap_a_path))
snap_b = json.load(open(snap_b_path))

# 1. StateTransition Artifact Structure & Metadata
assert trans_data.get("schema_version") == "0.3"
trans = trans_data.get("transition", trans_data)

assert trans["transition_id"] == "T001"
assert trans["parent_snapshot"] == "A"
assert trans["child_snapshot"] == "B"

# 2. Mutation Result
mutation = trans["mutation"]
assert mutation["success"] is True, f"Mutation failed: {mutation}"
assert mutation["field"] == "retry"
assert mutation["before"] == 2
assert mutation["after"] == 3

# 3. Execution Result
execution = trans["execution"]
assert execution["status"] == "STOPPED"
assert "breakpoint" in execution.get("reason", "")

# 4. Semantic Diff
diff = trans["diff"]
assert diff is not None
changes = {(c.get("path"), c.get("before"), c.get("after")) for c in diff["changes"] if c["kind"] == "value_change"}

# Session.retry: 2 -> 3
assert ("Session.retry", 2, 3) in changes, f"Missing Session.retry in {changes}"

# Session.state: CONNECTED -> ERROR
assert any(p == "Session.state" and "CONNECTED" in str(b) and "ERROR" in str(a) for p, b, a in changes), \
    f"Missing state change CONNECTED -> ERROR in {changes}"

# Session.flagged: false -> true
assert any(p == "Session.flagged" and not b and a for p, b, a in changes), \
    f"Missing flagged change false -> true in {changes}"

# 5. Provenance in Snapshots A and B
for name, snap in [("A", snap_a), ("B", snap_b)]:
    prov = snap.get("provenance")
    assert prov is not None, f"Snapshot {name} missing provenance"
    rb = prov["runtime_binary"]
    di = prov["debug_image"]
    assert rb["stripped"] is True, f"Snapshot {name} runtime binary should be stripped"
    assert di["source"] == "external", f"Snapshot {name} debug image source should be external"
    assert di["verified"] is True
    assert di["compatible"] is True
    assert di["build_id"] == rb["build_id"]

# 6. Performance Metrics
perf = trans.get("performance")
assert perf is not None
for metric in ("snapshot_before_ms", "mutation_ms", "continue_ms", "snapshot_after_ms", "diff_ms", "total_ms"):
    assert metric in perf, f"Missing performance metric {metric}"

# 7. Corpus Verification from explore-state on stripped binary
corpus = StateCorpus(corpus_dir)
index_path = os.path.join(corpus_dir, "index.json")
assert os.path.isfile(index_path), "corpus index.json missing"
index = json.load(open(index_path))

assert index.get("schema_version") == "0.4"
assert len(index["states"]) >= 1, f"Expected at least 1 corpus state, got {len(index['states'])}"
for state_id, meta in index["states"].items():
    s_snap = corpus.get(state_id)
    assert s_snap is not None
    prov = s_snap.get("provenance")
    assert prov is not None, f"Corpus state {state_id} missing provenance"
    assert prov["runtime_binary"]["stripped"] is True
    assert prov["debug_image"]["compatible"] is True

print("[VERIFIED] State Transition executed deterministically on stripped binary with external debug image.")
print("[VERIFIED] Semantic Diff (retry=3, state=ERROR, flagged=true) accurately captured.")
print("[VERIFIED] State Corpus successfully created on stripped binary.")
PY

echo "Stripped Transition integration test passed"
