#!/usr/bin/env bash
# ==============================================================================
# dynamicState — All Tests Runner
# Executes unit tests, integration tests, multithread determinism tests,
# and optionally GDB 9.2 container compatibility tests.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "================================================================================"
echo " dynamicState: Comprehensive Test Suite"
echo "================================================================================"

PASSED=0
FAILED=0

run_step() {
    local name="$1"
    shift
    echo ""
    echo "[TEST] Running: ${name}..."
    if "$@"; then
        echo "[PASS] ${name}"
        PASSED=$((PASSED + 1))
    else
        echo "[FAIL] ${name}"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# 1. Build C Target Collector (if gcc/make available)
if command -v make >/dev/null 2>&1 && [ -d "target/collector" ]; then
    run_step "Build Target Collector (C)" make -C target/collector || true
fi

# 2. Compile multithread sample targets and real runtime C++ fixture
if command -v g++ >/dev/null 2>&1; then
    run_step "Compile Deterministic Multithread Sample" \
        g++ -g -O0 -pthread examples/sample_multithread.cpp -o /tmp/sample_multithread
    run_step "Compile Nondeterministic Multithread Sample" \
        g++ -g -O0 -pthread examples/sample_multithread_nondet.cpp -o /tmp/sample_multithread_nondet
    if [ -f "tests/fixtures/real_runtime/main.cpp" ]; then
        run_step "Compile Real Runtime C++ Fixture (Debug ELF with build-id)" \
            g++ -fPIE -pie -g -O0 -fno-inline -fno-omit-frame-pointer -Wl,--build-id=sha1 tests/fixtures/real_runtime/main.cpp -o /tmp/real_runtime_app_debug.elf -lpthread
        if command -v strip >/dev/null 2>&1; then
            run_step "Create Stripped Companion for Real Runtime Fixture" \
                strip -s -o /tmp/real_runtime_app_prod.stripped /tmp/real_runtime_app_debug.elf
        fi
    fi
fi

# 3. Dedicated Capture Safety, Process Identity, and Diff Accuracy Suite
run_step "Capture Safety and Snapshot Diff Accuracy Suite" \
    python3 -m unittest tests/test_capture_safety_and_diff_accuracy.py

# 4. Process Target Lifecycle, Pinned Identity, and Seam Invariants Suite
run_step "Process Target Lifecycle, Pinned Identity & Seam Invariants Suite" \
    python3 -m unittest tests/test_capture_lifecycle_seam.py

# 5. Live Process Real Runtime Validation Suite
run_step "Live Process Real Runtime Validation Suite" \
    python3 -m unittest tests/test_real_runtime_validation.py

# 6. End-to-End C++ Investigation Pipeline Suite (Scenarios A-E)
run_step "End-to-End C++ Investigation Pipeline Suite (Scenarios A-E)" \
    python3 -m unittest tests/test_cpp_e2e_investigation.py

# 7. Discover and run all remaining unit and integration tests
run_step "Python Unit & Integration Test Suite (Full Discovery)" \
    python3 -m unittest discover tests

# 8. Multithread determinism & branch isolation specific tests
run_step "Multithread Restart Determinism & Branch Isolation Suite" \
    python3 -m unittest tests/test_multithread_exploration.py

# 9. Web API & UI Lifecycle Suite
run_step "Web API & Server Lifecycle Tests" \
    python3 -m unittest tests/test_web_api.py tests/test_web_server_lifecycle.py

# 10. CI Workflow Parity & Discoverability Suite
run_step "CI Workflow Parity & Discoverability Suite" \
    python3 -m unittest tests/test_ci_workflow_parity.py

# 11. Performance Benchmark Smoke Test
run_step "Capture Performance Benchmark Smoke Test" \
    python3 -m benchmarks.capture_benchmark --smoke

# 6. GDB 9.2 Compatibility Test (Docker if available)
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo ""
    echo "[TEST] Running GDB 9.2 Docker Container Test..."
    if python3 tests/integration_gdb92.py; then
        echo "[PASS] GDB 9.2 Container Test"
        PASSED=$((PASSED + 1))
    else
        echo "[FAIL] GDB 9.2 Container Test"
        FAILED=$((FAILED + 1))
    fi
else
    echo ""
    echo "[INFO] Docker not accessible or running; skipping GDB 9.2 Docker test."
    echo "       (Run 'python3 tests/integration_gdb92.py' manually in a Docker-enabled environment)"
fi

echo ""
echo "================================================================================"
echo " Summary: ${PASSED} steps passed, ${FAILED} steps failed."
echo "================================================================================"

if [ "${FAILED}" -gt 0 ]; then
    exit 1
fi
exit 0
