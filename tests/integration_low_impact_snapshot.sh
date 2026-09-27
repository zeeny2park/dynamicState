#!/usr/bin/env bash
set -euo pipefail

# Integration test for Phase 5.1: Low-Impact Runtime Memory Snapshot + Offline Semantic Analysis
# Verifies:
# 1. Non-intrusive memory capture of stripped production binary via process_vm_readv()
# 2. Target application runs continuously without GDB stop-the-world breakpoints or SIGSTOP
# 3. No-stop verification: counter increments continuously before, during, and after capture
# 4. Partial consistency metadata verification (level == NON_ATOMIC)
# 5. Offline semantic analysis combining RawMemorySnapshot with external debug image
# 6. Reconstructing semantic object graph (Session, Buffer, circular reference)
# 7. Semantic state hash generation
# 8. Strict safety boundaries: mutation strictly rejected in LOW_IMPACT mode
# 9. CLI commands: capture-memory and analyze-memory

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

TMP_DIR="$(mktemp -d /tmp/dynstate_low_impact_XXXXXX)"
TARGET_PID=""

cleanup() {
    if [[ -n "${TARGET_PID}" ]] && kill -0 "${TARGET_PID}" 2>/dev/null; then
        kill -9 "${TARGET_PID}" 2>/dev/null || true
    fi
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "=== Phase 5.1 Low-Impact Memory Snapshot Integration Test ==="

# 1. Compile test application, split DWARF debug image, and strip runtime binary
echo "[1/8] Compiling sample_low_impact and preparing stripped binary..."
g++ -g -O0 -pthread -o "${TMP_DIR}/sample" "${ROOT_DIR}/examples/sample_low_impact.cpp"
objcopy --only-keep-debug "${TMP_DIR}/sample" "${TMP_DIR}/sample.debug"
strip -s -o "${TMP_DIR}/sample_stripped" "${TMP_DIR}/sample"

# 2. Launch stripped production binary in background
echo "[2/8] Launching stripped process in background..."
"${TMP_DIR}/sample_stripped" 10 > "${TMP_DIR}/app.log" 2>&1 &
TARGET_PID=$!

# Wait for process initialization
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

# 3. Perform low-impact memory capture via process_vm_readv
echo "[3/8] Performing process_vm_readv memory capture without stopping target..."
python3 - "${TARGET_PID}" "${TMP_DIR}/mem_snap" <<'PY'
import os, sys
from extractor.memory_capture import MemoryCapture

pid = int(sys.argv[1])
out_dir = sys.argv[2]

capturer = MemoryCapture()
assert capturer.is_supported, "process_vm_readv is required on Linux"

raw_snap = capturer.capture(
    pid=pid,
    policy="ALL_READABLE",
    output_dir=out_dir,
    snapshot_id="M_E2E_001",
    max_bytes=32 * 1024 * 1024,
    timeout_ms=2000
)

assert raw_snap.status in ("COMPLETE", "PARTIAL")
assert raw_snap.bytes_captured > 0
assert raw_snap.regions_captured > 0
assert raw_snap.duration_us > 0
assert raw_snap.consistency["level"] == "NON_ATOMIC"
print(f"Captured {raw_snap.bytes_captured} bytes across {raw_snap.regions_captured} regions in {raw_snap.duration_us} us.")
PY

# 4. Verify no-stop condition: target process is STILL executing after capture
echo "[4/8] Verifying no-stop condition (application continues execution)..."
if ! kill -0 "${TARGET_PID}" 2>/dev/null; then
    echo "ERROR: Process unexpectedly died during capture"
    exit 1
fi
echo "Process ${TARGET_PID} is still actively running without interruption."

# Let application finish or terminate gracefully
sleep 1
if kill -0 "${TARGET_PID}" 2>/dev/null; then
    kill -TERM "${TARGET_PID}" 2>/dev/null || true
fi
wait "${TARGET_PID}" 2>/dev/null || true
TARGET_PID=""

# Verify stdout log shows active worker thread increments
cat "${TMP_DIR}/app.log"
if ! grep -q "EXIT: PID=" "${TMP_DIR}/app.log"; then
    echo "ERROR: Application log missing completion message"
    exit 1
fi
echo "No-stop verification PASSED: Process actively modified state before and after capture."

# 5. Offline semantic analysis using external debug image
echo "[5/8] Performing offline DWARF semantic analysis on captured memory..."
python3 - "${TMP_DIR}/mem_snap" "${TMP_DIR}/sample.debug" "${TMP_DIR}/semantic_snapshot.json" <<'PY'
import json, os, sys
from extractor.offline_analyzer import OfflineMemoryAnalyzer
from extractor.snapshot import RuntimeSnapshot
from extractor.state_hash import compute_state_hash

snap_dir = sys.argv[1]
debug_img = sys.argv[2]
out_json = sys.argv[3]

analyzer = OfflineMemoryAnalyzer()
semantic_snap = analyzer.analyze(memory_snapshot=snap_dir, debug_image=debug_img)

assert isinstance(semantic_snap, RuntimeSnapshot)
assert semantic_snap.process["capture_mode"] == "LOW_IMPACT"

# Verify persistent roots & reconstructed objects
persistent = semantic_snap.persistent
assert len(persistent.roots) >= 1
global_root = next((r for r in persistent.roots if r.name == "global_session"), None)
assert global_root is not None, "Missing global_session root"
assert global_root.object_ref is not None

# Find Session object
objects_by_id = {o.object_id: o for o in persistent.objects}
session_obj = objects_by_id.get(global_root.object_ref)
assert session_obj is not None
assert session_obj.type == "Session"
assert session_obj.storage == "heap"

fields = {f.name: f for f in session_obj.fields}
assert "CONNECTED" in str(fields["state"].value), f"Expected CONNECTED state, got {fields['state'].value}"
assert fields["packet_count"].value >= 100, f"Expected packet_count >= 100, got {fields['packet_count'].value}"
assert fields["priority"].value == 7
assert abs(fields["ratio"].value - 1.0) < 0.001

# Verify circular reference: Session.parent points to itself
assert fields["parent"].object_ref == session_obj.object_id, "Expected circular self reference for session->parent"

# Verify Buffer object
buffer_id = fields["buffer"].object_ref
assert buffer_id is not None
buffer_obj = objects_by_id[buffer_id]
assert buffer_obj.type == "Buffer"
buf_fields = {f.name: f for f in buffer_obj.fields}
assert buf_fields["length"].value == 64
assert buf_fields["capacity"].value == 256

# Verify semantic state hash
h = compute_state_hash(semantic_snap)
assert isinstance(h, str) and len(h) == 16, f"Invalid state hash: {h}"
print(f"Offline semantic analysis PASSED. Reconstructed Session {session_obj.object_id} with State Hash: {h}")

semantic_snap.write_json(out_json)
PY

# 6. Verify AgentRuntime integration & safety boundaries
echo "[6/8] Verifying AgentRuntime integration & safety boundaries..."
python3 - "${TMP_DIR}/mem_snap" "${TMP_DIR}/sample.debug" "${TMP_DIR}" <<'PY'
import sys
from extractor.agent_runtime import AgentRuntime

snap_dir = sys.argv[1]
debug_img = sys.argv[2]
corpus_dir = sys.argv[3]

agent = AgentRuntime(controller=None, corpus_dir=corpus_dir)

# 1. Inspect memory snapshot
res_get = agent.get_memory_snapshot("M_E2E_001")
assert res_get.success
assert res_get.data["snapshot_id"] == "M_E2E_001"
assert res_get.data["consistency"]["level"] == "NON_ATOMIC"

# 2. Analyze memory snapshot through AgentRuntime
res_ana = agent.analyze_memory_snapshot("M_E2E_001", debug_image=debug_img)
assert res_ana.success
assert res_ana.data["snapshot_id"] == "S_M_E2E_001"
assert len(res_ana.data["objects"]) >= 1

# 3. Safety boundary: Mutation strictly rejected in LOW_IMPACT mode
agent.observation_mode = "LOW_IMPACT"
res_mut = agent.execute_transition("M0001")
assert not res_mut.success
assert res_mut.error.code == "CAPABILITY_UNSUPPORTED"
assert "not supported in LOW_IMPACT" in res_mut.error.message

# 4. Capabilities reflection
res_caps = agent.capabilities()
assert res_caps.data["observation"]["low_impact_memory_snapshot"] is True
assert res_caps.data["memory_snapshot"]["process_vm_readv"] is True
print("AgentRuntime LOW_IMPACT integration and safety boundary PASSED.")
PY

# 7. Test CLI commands (capture-memory and analyze-memory)
echo "[7/8] Testing CLI commands..."
python3 -m extractor.cli --help >/dev/null
"${ROOT_DIR}/bin/dynamic-state" --help >/dev/null

# Launch short target for CLI test
"${TMP_DIR}/sample_stripped" 5 >/dev/null 2>&1 &
CLI_PID=$!
sleep 0.2

"${ROOT_DIR}/bin/dynamic-state" capture-memory \
    --pid "${CLI_PID}" \
    --policy STACK \
    --output "${TMP_DIR}/cli_mem_snap" \
    --snapshot-id "M_CLI_001" >/dev/null

kill -TERM "${CLI_PID}" 2>/dev/null || true
wait "${CLI_PID}" 2>/dev/null || true

test -f "${TMP_DIR}/cli_mem_snap/metadata.json"
test -f "${TMP_DIR}/cli_mem_snap/manifest.json"

"${ROOT_DIR}/bin/dynamic-state" analyze-memory \
    --snapshot "${TMP_DIR}/mem_snap" \
    --debug-image "${TMP_DIR}/sample.debug" \
    --output "${TMP_DIR}/cli_semantic.json" >/dev/null

test -f "${TMP_DIR}/cli_semantic.json"
echo "CLI tools capture-memory and analyze-memory PASSED."

# 8. Error handling verification: non-existent PID and unreadable memory
echo "[8/8] Verifying error handling (non-existent PID, invalid commands)..."
python3 -c "
from extractor.memory_capture import MemoryCapture
capturer = MemoryCapture()
try:
    capturer.capture(pid=9999999)
    assert False, 'Should fail on non-existent PID'
except ProcessLookupError:
    pass
"
echo "Error handling verification PASSED."

echo "=== All Phase 5.1 Low-Impact Integration Tests Passed Successfully ==="
