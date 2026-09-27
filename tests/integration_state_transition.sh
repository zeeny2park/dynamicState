#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT

mkdir -p "$build_dir/snapshots" "$build_dir/transitions"

# 1. Build product binary with DWARF debug symbols
g++ -g -O0 -o "$build_dir/sample" "$root_dir/examples/sample.cpp"

# 2. Run GDB State Transition workflow: Snapshot A -> Mutate -> Continue -> Snapshot B -> Diff -> Transition Artifact
gdb -q -nx -batch "$build_dir/sample" \
  -ex "source $root_dir/gdb/extract_state.py" \
  -ex 'break runtime_state_checkpoint' \
  -ex run \
  -ex "transition-state --object obj_0001 --field retry --value 3 --id T001 --parent A --child B --output $build_dir/transitions/T001.json --snapshots-dir $build_dir/snapshots" \
  -ex 'continue-state' > "$build_dir/transcript.txt"

# 3. Deterministic verification of State Transition Artifact, Snapshots, and Semantic Diff
python3 - "$build_dir/transitions/T001.json" "$build_dir/snapshots/A.json" "$build_dir/snapshots/B.json" <<'PY'
import json, sys

trans_data = json.load(open(sys.argv[1]))
snap_a = json.load(open(sys.argv[2]))
snap_b = json.load(open(sys.argv[3]))

# 1. StateTransition Artifact Structure & Metadata
assert trans_data.get("schema_version") == "0.3"
trans = trans_data.get("transition", trans_data)

assert trans["transition_id"] == "T001", f"Expected transition_id T001, got {trans.get('transition_id')}"
assert trans["parent_snapshot"] == "A", f"Expected parent_snapshot A, got {trans.get('parent_snapshot')}"
assert trans["child_snapshot"] == "B", f"Expected child_snapshot B, got {trans.get('child_snapshot')}"

# 2. Mutation Result in Transition
mutation = trans["mutation"]
assert mutation["success"] is True
assert mutation["object_id"] == "obj_0001"
assert mutation["field"] == "retry"
assert mutation["before"] == 2
assert mutation["after"] == 3

# 3. Execution Result in Transition
execution = trans["execution"]
assert execution["status"] == "STOPPED"
assert "breakpoint" in execution.get("reason", "")

# 4. Semantic Diff in Transition
diff = trans["diff"]
assert diff is not None
assert diff["summary"]["value_changes"] >= 3

changes = {(c.get("path"), c.get("before"), c.get("after")) for c in diff["changes"] if c["kind"] == "value_change"}

# Session.retry: 2 -> 3
assert ("Session.retry", 2, 3) in changes, f"Missing Session.retry in {changes}"

# Session.state: CONNECTED -> ERROR
assert any(p == "Session.state" and "CONNECTED" in str(b) and "ERROR" in str(a) for p, b, a in changes), "Missing state change CONNECTED -> ERROR"

# Session.flagged: false/0 -> true/1
assert any(p == "Session.flagged" and not b and a for p, b, a in changes), "Missing flagged change false -> true"

# 5. Snapshots A and B verification
def get_session(snapshot):
    return next(o for o in snapshot["persistent"]["objects"] if o["type"] == "Session")

obj_a = get_session(snap_a)
obj_b = get_session(snap_b)

fields_a = {f["name"]: f for f in obj_a["fields"]}
fields_b = {f["name"]: f for f in obj_b["fields"]}

# Initial conditions
assert fields_a["retry"]["value"] == 2
assert "CONNECTED" in str(fields_a["state"]["value"])
assert fields_a["flagged"]["value"] in (0, False)

# Post-transition conditions
assert fields_b["retry"]["value"] == 3
assert "ERROR" in str(fields_b["state"]["value"])
assert fields_b["flagged"]["value"] in (1, True)

# 6. Object Identity Verification: snapshot-scoped observation identity
assert "identity" in obj_a
assert obj_a["identity"]["strategy"] == "address_type"
assert obj_a["identity"]["scope"] == "snapshot"
assert obj_b["identity"]["strategy"] == "address_type"
assert obj_b["identity"]["scope"] == "snapshot"

# 7. Performance metrics
perf = trans.get("performance")
assert perf is not None
for metric in ("snapshot_before_ms", "mutation_ms", "continue_ms", "snapshot_after_ms", "diff_ms", "total_ms"):
    assert metric in perf, f"Missing performance metric {metric}"

print("State Transition integration test passed")
PY
