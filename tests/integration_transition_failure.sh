#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT

mkdir -p "$build_dir/transitions"

# 1. Build sample binary with DWARF debug symbols
g++ -g -O0 -o "$build_dir/sample" "$root_dir/examples/sample.cpp"

# 2. Run Crash Transition (priority = 139 triggers SIGSEGV)
gdb -q -nx -batch "$build_dir/sample" \
  -ex "source $root_dir/gdb/extract_state.py" \
  -ex 'break runtime_state_checkpoint' \
  -ex run \
  -ex "transition-state --object obj_0001 --field priority --value 139 --id T_CRASH --output $build_dir/transitions/T_CRASH.json" > /dev/null

# 3. Run Timeout Transition (priority = 255 triggers infinite loop with 200ms timeout)
gdb -q -nx -batch "$build_dir/sample" \
  -ex "source $root_dir/gdb/extract_state.py" \
  -ex 'break runtime_state_checkpoint' \
  -ex run \
  -ex "transition-state --object obj_0001 --field priority --value 255 --id T_TIMEOUT --timeout-ms 200 --output $build_dir/transitions/T_TIMEOUT.json" > /dev/null

# 4. Verify Crash and Timeout transition artifacts
python3 - "$build_dir/transitions/T_CRASH.json" "$build_dir/transitions/T_TIMEOUT.json" <<'PY'
import json, sys

crash_data = json.load(open(sys.argv[1]))
timeout_data = json.load(open(sys.argv[2]))

# Verify Crash Transition
assert crash_data.get("schema_version") == "0.3"
trans_c = crash_data.get("transition", crash_data)
assert trans_c["transition_id"] == "T_CRASH"
assert trans_c["mutation"]["success"] is True
assert trans_c["mutation"]["field"] == "priority"
assert trans_c["mutation"]["after"] == 139

assert trans_c["execution"]["status"] == "CRASHED"
assert trans_c["execution"]["signal"] == "SIGSEGV"
assert trans_c["child_snapshot"] is None
assert trans_c["diff"] is None
assert trans_c["performance"]["continue_ms"] > 0

# Verify Timeout Transition
assert timeout_data.get("schema_version") == "0.3"
trans_t = timeout_data.get("transition", timeout_data)
assert trans_t["transition_id"] == "T_TIMEOUT"
assert trans_t["mutation"]["success"] is True
assert trans_t["mutation"]["field"] == "priority"
assert trans_t["mutation"]["after"] == 255

assert trans_t["execution"]["status"] == "TIMEOUT"
assert trans_t["child_snapshot"] is None
assert trans_t["diff"] is None
assert trans_t["performance"]["continue_ms"] >= 150

print("Transition failure integration test passed")
PY
