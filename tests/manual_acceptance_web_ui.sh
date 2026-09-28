#!/usr/bin/env bash
set -euo pipefail

# Manual Acceptance Test runner for dynamicState Web UI MVP
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "=== 1. Standalone Acceptance Scenario ==="
python3 tests/manual_acceptance_web_ui.py

echo ""
echo "=== 2. Real GDB Backend Acceptance Scenario ==="
TMP_DIR="$(mktemp -d /tmp/dynstate_live_gdb_web_XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

g++ -g -O0 -o "${TMP_DIR}/sample" "${ROOT_DIR}/examples/sample.cpp"
objcopy --only-keep-debug "${TMP_DIR}/sample" "${TMP_DIR}/sample.debug"
strip -s -o "${TMP_DIR}/sample_stripped" "${TMP_DIR}/sample"

gdb -q -nx -batch \
  -ex "set confirm off" \
  -ex "set python print-stack full" \
  -ex "file ${TMP_DIR}/sample_stripped" \
  -ex "source ${ROOT_DIR}/gdb/extract_state.py" \
  -ex "load-debug-image ${TMP_DIR}/sample.debug" \
  -ex "set args 10" \
  -ex "break runtime_state_checkpoint" \
  -ex "run" \
  -ex "python
import sys
sys.path.insert(0, '${ROOT_DIR}')
from tests.manual_acceptance_web_ui import run_acceptance
assert run_acceptance(), 'Live GDB Acceptance failed'
"

echo "dynamicState Web UI MVP Acceptance Scenario: PASS (Both Standalone and Real GDB)"
