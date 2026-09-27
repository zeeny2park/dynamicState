#!/usr/bin/env bash
set -euo pipefail

# Integration test for External Debug Image Support with Stripped Production Binaries.
# Verifies:
# 1. Negative test: Mismatched Build ID rejection.
# 2. Negative test: Nonexistent debug image rejection.
# 3. Positive test: Stripped runtime binary + matching external debug image.
# 4. Provenance tracking: runtime_binary (stripped), debug_image (external, verified, build_id).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TMP_DIR="$(mktemp -d /tmp/dynstate_stripped_debug_XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/snapshots"

# 1. Compile matching sample binary and extract debug image
g++ -g -O0 -o "${TMP_DIR}/sample" "${ROOT_DIR}/examples/sample.cpp"
objcopy --only-keep-debug "${TMP_DIR}/sample" "${TMP_DIR}/sample.debug"
strip -s -o "${TMP_DIR}/sample_stripped" "${TMP_DIR}/sample"

# 2. Compile an intentionally mismatched binary to generate mismatched debug image
cat <<'EOF' > "${TMP_DIR}/other.cpp"
#include <iostream>
int main() { return 42; }
EOF
g++ -g -O0 -o "${TMP_DIR}/other" "${TMP_DIR}/other.cpp"
objcopy --only-keep-debug "${TMP_DIR}/other" "${TMP_DIR}/other.debug"

# 3. Negative Test 1: Mismatched Build ID rejection in GDB
set +e
gdb_mismatch_output=$(gdb -q -batch \
  -ex "file ${TMP_DIR}/sample_stripped" \
  -ex "source ${ROOT_DIR}/gdb/extract_state.py" \
  -ex "load-debug-image ${TMP_DIR}/other.debug" 2>&1)
set -e

if echo "${gdb_mismatch_output}" | grep -q "BUILD_ID_MISMATCH"; then
    echo "[TEST PASS] Mismatched debug image rejected correctly with BUILD_ID_MISMATCH"
else
    echo "[TEST FAIL] Expected BUILD_ID_MISMATCH rejection, got:"
    echo "${gdb_mismatch_output}"
    exit 1
fi

# 4. Negative Test 2: Nonexistent debug image rejection
set +e
gdb_notfound_output=$(gdb -q -batch \
  -ex "file ${TMP_DIR}/sample_stripped" \
  -ex "source ${ROOT_DIR}/gdb/extract_state.py" \
  -ex "load-debug-image ${TMP_DIR}/nonexistent.debug" 2>&1)
set -e

if echo "${gdb_notfound_output}" | grep -q "Binary file not found"; then
    echo "[TEST PASS] Nonexistent debug image rejected correctly"
else
    echo "[TEST FAIL] Expected file not found error, got:"
    echo "${gdb_notfound_output}"
    exit 1
fi

# 5. Positive Test: Stripped binary + Matching external debug image
gdb -q -batch \
  -ex "set confirm off" \
  -ex "file ${TMP_DIR}/sample_stripped" \
  -ex "symbol-file ${TMP_DIR}/sample.debug" \
  -ex "set args 10" \
  -ex "source ${ROOT_DIR}/gdb/extract_state.py" \
  -ex "break runtime_state_checkpoint" \
  -ex "run" \
  -ex "runtime-info --json" \
  -ex "extract-state --output ${TMP_DIR}/snapshots/stripped_state.json"

# 6. Validate snapshot artifact and provenance
python3 - <<PY
import json, os, sys

snap_file = "${TMP_DIR}/snapshots/stripped_state.json"
assert os.path.exists(snap_file), "Snapshot file was not created"

with open(snap_file) as f:
    data = json.load(f)

# Verify process and semantic objects
assert data["schema_version"] == "0.2"
objects = data["persistent"]["objects"]
roots = data["persistent"]["roots"]
assert len(objects) >= 3, f"Expected at least 3 semantic objects, got {len(objects)}"
assert len(roots) >= 1, f"Expected semantic roots, got {len(roots)}"

# Verify Session object was extracted with accurate runtime values
session_obj = next(o for o in objects if o["type"] == "Session")
retry_field = next(f for f in session_obj["fields"] if f["name"] == "retry")
assert retry_field["value"] == 2, f"Expected Session.retry == 2, got {retry_field['value']}"

# Verify Provenance metadata
provenance = data.get("provenance")
assert provenance is not None, "Snapshot missing provenance metadata"

rb = provenance["runtime_binary"]
assert rb["stripped"] is True, f"Expected runtime_binary.stripped == True, got {rb['stripped']}"
assert rb["build_id"] is not None, "Missing runtime_binary build_id"

di = provenance["debug_image"]
assert di["source"] in ("external", "embedded")
assert di["verified"] is True
assert di["compatible"] is True
assert di["build_id"] == rb["build_id"], f"Build ID mismatch in provenance: {di['build_id']} != {rb['build_id']}"

# Verify performance instrumentation
perf = data["persistent"]["statistics"]["performance"]
assert "debug_image_load_ms" in perf
assert "binary_identity_check_ms" in perf
assert "debug_image_verification_ms" in perf

print("[VERIFIED] Semantic state extracted from stripped binary using external debug image.")
print("[VERIFIED] Provenance and build identity correctly recorded.")
PY

echo "Stripped Debug Image integration test passed"
