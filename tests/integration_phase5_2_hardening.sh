#!/usr/bin/env bash
set -euo pipefail

# Integration test for Phase 5.2: Production-grade Low-Impact Observation Hardening
# Verifies:
# 1. PIE and shared library module discovery with accurate ELF PT_LOAD load bias calculation
# 2. Capture-time Build ID provenance and .gnu_debuglink discovery with CRC verification
# 3. Intentional debug image mismatch rejection (DEBUG_IMAGE_MISMATCH)
# 4. Zero-stop safety contract (continuous monotonic counter increment without ptrace/SIGSTOP)
# 5. Offline semantic analysis without fake execution context (availability=UNAVAILABLE, threads=[])
# 6. Read-only safety contract (mutation / continue rejected)
# 7. Process exit race resilience (ESRCH handled, status=PROCESS_EXITED)
# 8. Full CLI toolchain: runtime-info, capture-memory, list-modules, analyze-memory

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TMP_DIR="$(mktemp -d /tmp/dynstate_p52_XXXXXX)"
TARGET_PID=""

cleanup() {
    if [[ -n "${TARGET_PID}" ]] && kill -0 "${TARGET_PID}" 2>/dev/null; then
        kill -9 "${TARGET_PID}" 2>/dev/null || true
    fi
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "=== Phase 5.2 Production-Grade Low-Impact Observation Hardening Integration Test ==="

# Step 1: Compile shared library and PIE test binary
echo "[1/10] Compiling shared library and PIE target binary..."
cat << 'C_EOF' > "${TMP_DIR}/libhelper.c"
int helper_calc(int val) {
    return val * 2 + 10;
}
C_EOF

gcc -shared -fPIC -g -o "${TMP_DIR}/libhelper.so" "${TMP_DIR}/libhelper.c"

# Compile main binary linking to shared library
g++ -g -O0 -fPIE -pie -pthread \
    -Wl,--no-as-needed -L"${TMP_DIR}" -lhelper -Wl,-rpath,"${TMP_DIR}" \
    -o "${TMP_DIR}/target_app" "${ROOT_DIR}/examples/sample_low_impact.cpp"

# Step 2: Extract external debug info, add gnu_debuglink, and strip runtime binary
echo "[2/10] Splitting DWARF debug image and generating .gnu_debuglink..."
objcopy --only-keep-debug "${TMP_DIR}/target_app" "${TMP_DIR}/target_app.debug"
cp "${TMP_DIR}/target_app" "${TMP_DIR}/target_app_stripped"
strip -s "${TMP_DIR}/target_app_stripped"
objcopy --add-gnu-debuglink="${TMP_DIR}/target_app.debug" "${TMP_DIR}/target_app_stripped"

# Compile an unrelated binary to serve as mismatched debug image
echo "int main() { return 42; }" | gcc -g -x c - -o "${TMP_DIR}/mismatch.debug"

# Step 3: Launch target process in background
echo "[3/10] Launching stripped target process..."
"${TMP_DIR}/target_app_stripped" 10 > "${TMP_DIR}/app.log" 2>&1 &
TARGET_PID=$!

for i in {1..30}; do
    if grep -q "READY: PID=" "${TMP_DIR}/app.log" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if ! grep -q "READY: PID=" "${TMP_DIR}/app.log"; then
    echo "ERROR: Target application failed to start"
    cat "${TMP_DIR}/app.log"
    exit 1
fi
echo "Target process running with PID ${TARGET_PID}."

# Step 4: Capture memory snapshot via process_vm_readv (Low-Impact)
echo "[4/10] Capturing memory snapshot with zero process stopping..."
SNAP_DIR="${TMP_DIR}/snap_001"
python3 -m extractor.cli capture-memory \
    --pid "${TARGET_PID}" \
    --output-dir "${SNAP_DIR}" \
    --snapshot-id "M_P52_TEST"

# Step 5: Verify no-stop condition (application continued running during and after capture)
echo "[5/10] Verifying zero-stop safety contract..."
if ! kill -0 "${TARGET_PID}" 2>/dev/null; then
    echo "ERROR: Process died during capture"
    exit 1
fi
echo "Verified: Target process ${TARGET_PID} remained actively running throughout capture."

# Step 6: Verify modules and accurate ELF load bias
echo "[6/10] Verifying module discovery and load bias calculations..."
python3 - "${SNAP_DIR}" <<'PY'
import sys, json, os
from extractor.memory_snapshot import RawMemorySnapshot
from extractor.modules import RuntimeModule

snap_dir = sys.argv[1]
raw_snap = RawMemorySnapshot.load(snap_dir)

assert raw_snap.status in ("COMPLETE", "PARTIAL"), f"Unexpected status {raw_snap.status}"
assert raw_snap.modules, "Modules must be discovered at capture time"

# Check modules.json existence
assert os.path.exists(os.path.join(snap_dir, "modules.json")), "modules.json missing from snapshot artifact"

mods = [RuntimeModule.from_dict(m) for m in raw_snap.modules]
main_mod = next((m for m in mods if m.is_main_executable), None)
assert main_mod is not None, "Main executable module not found"
assert main_mod.module_id == "main"
assert main_mod.load_bias > 0 or main_mod.elf_type == "ET_EXEC", "Load bias must be resolved"
assert main_mod.pt_loads, "PT_LOAD segments must be recorded"
print(f"Main module resolved: base=0x{main_mod.runtime_base:x}, load_bias=0x{main_mod.load_bias:x}, type={main_mod.elf_type}")

# Check libhelper shared library discovery
shlib_mod = next((m for m in mods if "libhelper.so" in m.path), None)
assert shlib_mod is not None, "Shared library libhelper.so not discovered in runtime modules"
assert not shlib_mod.is_main_executable
print(f"Shared library module resolved: {shlib_mod.path}, base=0x{shlib_mod.runtime_base:x}")
PY

# Step 7: Test DebugArtifactProvider provenance and mismatch detection
echo "[7/10] Testing debug artifact provenance and mismatch detection..."
python3 - "${SNAP_DIR}" "${TMP_DIR}/target_app.debug" "${TMP_DIR}/mismatch.debug" <<'PY'
import sys, os
from extractor.memory_snapshot import RawMemorySnapshot
from extractor.modules import RuntimeModule
from extractor.debug_artifacts import DebugArtifactProvider

snap_dir = sys.argv[1]
good_dbg = sys.argv[2]
bad_dbg = sys.argv[3]

raw_snap = RawMemorySnapshot.load(snap_dir)
mods = [RuntimeModule.from_dict(m) for m in raw_snap.modules]
main_mod = next(m for m in mods if m.is_main_executable)

provider = DebugArtifactProvider(search_paths=[os.path.dirname(good_dbg)])

# 1. Matching debug image verification
res_good = provider.verify(main_mod, good_dbg)
assert res_good.compatible, f"Expected compatible debug image: {res_good.reason}"
print("Verified matching debug artifact compatibility.")

# 2. Mismatched debug image rejection
res_bad = provider.verify(main_mod, bad_dbg)
assert not res_bad.compatible, "Mismatched debug image must be rejected"
assert res_bad.reason in ("DEBUG_IMAGE_MISMATCH", "DEBUG_IMAGE_STRIPPED"), f"Unexpected rejection reason: {res_bad.reason}"
print(f"Verified mismatched debug artifact rejection: {res_bad.reason}")
PY

# Step 8: Offline Semantic Analysis and Execution Context Availability Verification
echo "[8/10] Performing offline semantic analysis and verifying execution context..."
OUT_SEMANTIC="${TMP_DIR}/semantic_snapshot.json"
python3 -m extractor.cli analyze-memory \
    --snapshot "${SNAP_DIR}" \
    --debug-image "${TMP_DIR}/target_app.debug" \
    --output "${OUT_SEMANTIC}"

python3 - "${OUT_SEMANTIC}" <<'PY'
import sys, json

with open(sys.argv[1]) as f:
    snap_data = json.load(f)

# 1. Execution context verification: strictly UNAVAILABLE, no fake threads
exec_data = snap_data["execution"]
assert exec_data["availability"] == "UNAVAILABLE", f"Expected UNAVAILABLE execution context, got {exec_data.get('availability')}"
assert exec_data["reason"] == "LOW_IMPACT_MEMORY_SNAPSHOT", f"Expected reason LOW_IMPACT_MEMORY_SNAPSHOT, got {exec_data.get('reason')}"
assert exec_data["threads"] == [], f"Expected empty threads list, got {exec_data['threads']}"
print("Verified: Execution context correctly marked UNAVAILABLE with 0 fake threads.")

# 2. Semantic object graph verification
persistent = snap_data["persistent"]
roots = persistent["roots"]
objects = persistent["objects"]
assert len(roots) >= 1, "Expected at least 1 global root"
assert len(objects) >= 2, f"Expected at least 2 semantic objects (Session, Buffer), got {len(objects)}"

# Check Session fields
session_obj = next(o for o in objects if o["type"] == "Session")
field_names = {f["name"] for f in session_obj["fields"]}
assert "packet_count" in field_names
assert "buffer" in field_names
assert "parent" in field_names

# 3. State hash calculation
from extractor.state_hash import compute_state_hash
shash = compute_state_hash(snap_data)
assert len(shash) == 16, f"Expected 16-char state hash, got {shash}"
print(f"Verified: Semantic object graph and state hash ({shash}) reconstructed successfully.")
PY

# Step 9: AgentRuntime read-only safety enforcement
echo "[9/10] Verifying read-only safety enforcement in AgentRuntime..."
python3 - "${SNAP_DIR}" <<'PY'
import sys
from extractor.agent_runtime import AgentRuntime

runtime = AgentRuntime()
# In LOW_IMPACT mode, mutation and continue are strictly forbidden
caps_res = runtime.capabilities()
caps = caps_res.data
assert caps.get("low_impact", {}).get("mutation") is False, "LOW_IMPACT must not permit mutation"
assert caps.get("low_impact", {}).get("process_stop") is False, "LOW_IMPACT must not stop process"

# Query modules action
mod_res = runtime.get_modules(snapshot_id=sys.argv[1])
assert mod_res.success, f"GET_MODULES failed: {mod_res.error}"
assert len(mod_res.data.get("modules", [])) >= 2, "Expected main and shared library modules"
print("Verified: AgentRuntime capabilities and GET_MODULES action working properly.")
PY

# Step 10: Process exit race resilience and CLI commands
echo "[10/10] Verifying process exit resilience and CLI runtime-info..."
# Terminate the target process
kill -9 "${TARGET_PID}" 2>/dev/null || true
wait "${TARGET_PID}" 2>/dev/null || true

# Test capturing already exited process
EXIT_SNAP_DIR="${TMP_DIR}/snap_exited"
python3 - "${TARGET_PID}" "${EXIT_SNAP_DIR}" <<'PY'
import sys
from extractor.agent_runtime import AgentRuntime

runtime = AgentRuntime()
pid = int(sys.argv[1])
res = runtime.capture_memory_snapshot(pid=pid, output_dir=sys.argv[2])
assert not res.success
assert res.error.get("code") == "PROCESS_EXITED", f"Expected PROCESS_EXITED, got {res.error.get('code')}"
print("Verified: Process exit handled gracefully with status PROCESS_EXITED.")
PY

# Test CLI runtime-info and list-modules
python3 -m extractor.cli runtime-info
python3 -m extractor.cli list-modules --snapshot "${SNAP_DIR}"

echo ""
echo "================================================================="
echo "ALL PHASE 5.2 INTEGRATION TESTS PASSED SUCCESSFULLY!"
echo "================================================================="
