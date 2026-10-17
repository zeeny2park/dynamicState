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

# 7. Causal Validation & Evidence Authenticity Suite
run_step "Causal Validation & Evidence Authenticity Suite" \
    python3 -m unittest tests/test_causal_validation_hardening.py

# 8. Phase 10 Independent Security Gates Suite
run_step "Phase 10 Security Gates & Independent Trust Verification Suite" \
    python3 -m unittest tests/test_phase10_ci_security_gates.py

# 9. Phase 11 Real-Target Validation & Release Readiness Suite
run_step "Phase 11 Real-Target Validation & Release Readiness Suite" \
    python3 -m unittest tests/test_phase11_real_target_release_readiness.py

# 10. Phase 12 Evidence-Driven Investigation Loop & Conversational Validation Suite
run_step "Phase 12 Evidence-Driven Investigation Loop & Conversational Validation Suite" \
    python3 -m unittest tests/test_phase12_investigation_loop.py

# 11. Phase 13 End-to-End Operational Acceptance Suite
run_step "Phase 13 End-to-End Operational Acceptance Suite" \
    python3 -m unittest tests/test_phase13_operational_acceptance.py

# 12. Phase 13 Operational Acceptance Demonstration Script
run_step "Phase 13 Operational Acceptance Demonstration Script" \
    python3 scripts/run_e2e_operational_acceptance.py

# 13. Phase 14 Production Pilot & Release Qualification Suite
run_step "Phase 14 Production Pilot & Release Qualification Suite" \
    python3 -m unittest tests/test_phase14_production_pilot.py

# 14. Phase 14 Production Pilot Demonstration Script
run_step "Phase 14 Production Pilot Demonstration Script" \
    python3 scripts/run_production_pilot.py --smoke

# 15. Phase 15 Conversational LLM & Simplified Investigation UX Suite
run_step "Phase 15 Conversational LLM & Simplified Investigation UX Suite" \
    python3 -m unittest tests/test_phase15_conversational_llm.py

# 16. Phase 16 CLI Provider Security, Process Control & Truthfulness Suite
run_step "Phase 16 CLI Provider Security, Process Control & Truthfulness Suite" \
    python3 -m unittest tests/test_phase16_cli_security_and_truthfulness.py

# 17. Phase 17 CLI Process Isolation Hardening & Regression Suite
run_step "Phase 17 CLI Process Isolation Hardening & Regression Suite" \
    python3 -m unittest tests/test_phase17_process_isolation_regression.py

# 18. Phase 20 Benchmark Execution Integrity and Trustworthy Results Suite
run_step "Phase 20 Benchmark Execution Integrity and Trustworthy Results Suite" \
    python3 -m unittest tests/test_investigation_quality_benchmark.py

# 19. Phase 20 Benchmark Demonstration Script
run_step "Phase 20 Benchmark Demonstration Script" \
    python3 benchmarks/investigation_quality/run_benchmark.py --smoke

# 20. Phase 21 Watch Session & Temporal Memory Explorer Foundation Suite
run_step "Phase 21 Watch Session & Temporal Memory Explorer Foundation Suite" \
    python3 -m unittest tests/test_phase21_watch_session.py

# 21. Phase 22 Zero-Configuration Live Capture & UX Simplification Suite
run_step "Phase 22 Zero-Configuration Live Capture & UX Simplification Suite" \
    python3 -m unittest tests/test_phase22_zero_config_live_capture.py

# 22. Phase 23 Remote Watch Sessions and MCP Integration Suite
run_step "Phase 23 Remote Watch Sessions and MCP Integration Suite" \
    python3 -m unittest tests/test_phase23_remote_watch_session.py

# 23. Phase 24 Evidence-First Temporal Investigation Workflow Suite
run_step "Phase 24 Evidence-First Temporal Investigation Workflow Suite" \
    python3 -m unittest tests/test_phase24_temporal_investigation.py

# 24. Phase 25 Evidence-Grounded LLM Investigation and End-to-End Quality Validation Suite
run_step "Phase 25 Evidence-Grounded LLM Investigation and End-to-End Quality Validation Suite" \
    python3 -m unittest tests/test_phase25_grounded_investigation.py

# 25. Phase 26 Real-Execution Quality Verification and Agent-First UX Suite
run_step "Phase 26 Real-Execution Quality Verification and Agent-First UX Suite" \
    python3 -m unittest tests/test_phase26_real_execution_quality.py

# 26. Phase 28 Runtime Memory Explorer and State Inspection UX Suite
run_step "Phase 28 Runtime Memory Explorer and State Inspection UX Suite" \
    python3 -m unittest tests/test_phase28_memory_explorer_ux.py

# 27. Phase 29 Browser-Based Runtime Investigation Workflow Suite (Playwright E2E)
if python3 -c "import playwright" >/dev/null 2>&1; then
    run_step "Phase 29 Browser-Based Runtime Investigation Workflow Suite" \
        python3 -m unittest tests/test_phase29_browser_e2e.py
fi

# 28. Discover and run all remaining unit and integration tests
run_step "Python Unit & Integration Test Suite (Full Discovery)" \
    python3 -m unittest discover tests

# 16. Multithread determinism & branch isolation specific tests
run_step "Multithread Restart Determinism & Branch Isolation Suite" \
    python3 -m unittest tests/test_multithread_exploration.py

# 17. Web API & UI Lifecycle Suite
run_step "Web API & Server Lifecycle Tests" \
    python3 -m unittest tests/test_web_api.py tests/test_web_server_lifecycle.py

# 18. CI Workflow Parity & Discoverability Suite
run_step "CI Workflow Parity & Discoverability Suite" \
    python3 -m unittest tests/test_ci_workflow_parity.py

# 19. Performance Benchmark Integrity & Unit Suite
run_step "Capture Benchmark Integrity & Schema Suite" \
    python3 -m unittest tests/test_capture_benchmark.py

# 20. Performance Benchmark Smoke Test
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
