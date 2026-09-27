#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT

# Build sample binary
g++ -g -O0 -o "$build_dir/sample" "$root_dir/examples/sample.cpp"

# Execute all 10 mutation validations in real GDB
gdb -q -nx -batch "$build_dir/sample" \
  -ex "source $root_dir/gdb/extract_state.py" \
  -ex 'break runtime_state_checkpoint' \
  -ex run \
  -ex 'snapshot-state S001' \
  -ex 'mutate-state --object obj_0001 --field retry --value 5' \
  -ex 'mutate-state --object obj_0001 --field state --value SessionState::ERROR' \
  -ex 'mutate-state --object obj_0001 --field flagged --value true' \
  -ex 'mutate-state --object obj_0001 --field ratio --value 3.14159' \
  -ex 'mutate-state --object obj_0001 --field buffer --value null' \
  -ex 'mutate-state --object obj_0001 --field retry --value hello' \
  -ex 'mutate-state --object obj_0001 --field priority --value 999' \
  -ex 'mutate-state --object obj_0001 --field nonexistent_field --value 1' \
  -ex 'mutate-state --path Buffer.length --value 10' \
  -ex 'mutate-state --object obj_0001 --field buffer.length --value 10' \
  -ex 'continue-state' > "$build_dir/transcript.txt"

# Verify all 10 mutation cases in Python
python3 - "$build_dir/transcript.txt" <<'PY'
import json, sys

lines = [line.strip() for line in open(sys.argv[1]) if line.strip().startswith('{') and '"success"' in line]
assert len(lines) == 10, f"Expected 10 mutation responses, got {len(lines)}: {lines}"

results = [json.loads(line) for line in lines]

# 1. uint32 정상 mutation
res1 = results[0]
assert res1["success"] is True, f"Case 1 failed: {res1}"
assert res1["field"] == "retry"
assert res1["before"] == 2
assert res1["after"] == 5

# 2. enum 정상 mutation
res2 = results[1]
assert res2["success"] is True, f"Case 2 failed: {res2}"
assert res2["field"] == "state"
assert "ERROR" in str(res2["after"])

# 3. bool 정상 mutation
res3 = results[2]
assert res3["success"] is True, f"Case 3 failed: {res3}"
assert res3["field"] == "flagged"
assert res3["after"] in (1, True), f"Expected bool 1 or True, got {res3['after']}"

# 4. float/double 정상 mutation
res4 = results[3]
assert res4["success"] is True, f"Case 4 failed: {res4}"
assert res4["field"] == "ratio"
assert abs(float(res4["after"]) - 3.14159) < 1e-4

# 5. NULL pointer mutation
res5 = results[4]
assert res5["success"] is True, f"Case 5 failed: {res5}"
assert res5["field"] == "buffer"
assert res5["after"] in ("0x0", "0x00000000", "0x0000000000000000")

# 6. invalid type -> TYPE_CONVERSION_ERROR
res6 = results[5]
assert res6["success"] is False, f"Case 6 should fail: {res6}"
assert res6["error"]["code"] == "TYPE_CONVERSION_ERROR"

# 7. out of range -> RANGE_ERROR
res7 = results[6]
assert res7["success"] is False, f"Case 7 should fail: {res7}"
assert res7["error"]["code"] == "RANGE_ERROR"

# 8. nonexistent field -> FIELD_NOT_FOUND
res8 = results[7]
assert res8["success"] is False, f"Case 8 should fail: {res8}"
assert res8["error"]["code"] == "FIELD_NOT_FOUND"

# 9. ambiguous object -> AMBIGUOUS_OBJECT
res9 = results[8]
assert res9["success"] is False, f"Case 9 should fail: {res9}"
assert res9["error"]["code"] == "AMBIGUOUS_OBJECT"

# 10. unsupported mutation -> UNSUPPORTED_TYPE
res10 = results[9]
assert res10["success"] is False, f"Case 10 should fail: {res10}"
assert res10["error"]["code"] == "UNSUPPORTED_TYPE"

print("Mutation Validation integration test passed")
PY
