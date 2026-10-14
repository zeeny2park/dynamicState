# CI Workflows for dynamicState

This directory contains the automated CI workflows for dynamicState.

### Workflows

1. **`ci/workflows/test.yml`**:
   - Runs on Ubuntu 22.04.
   - Installs system dependencies (`gdb`, `gcc`, `g++`, `make`).
   - Compiles the native C99 target collector (`target/collector`) and real runtime C++ fixtures.
   - Executes the full test suite (634+ unit and integration tests across all modules, including Phase 10-14 security gates, operational acceptance, and production pilot).

2. **`ci/workflows/gdb92.yml`**:
   - Runs on Ubuntu 22.04 with Docker.
   - Builds the containerized legacy GDB 9.2 environment (`docker/gdb92/Dockerfile`).
   - Runs `tests/integration_gdb92.py` verifying GDB 9.2 compatibility for multithread inferior inspection, low-impact observation, and process lifecycle handling.

### Activating in GitHub Actions & Drift Prevention

The canonical workflow definitions are maintained under `ci/workflows/test.yml` and `ci/workflows/gdb92.yml`.
To activate these workflows directly on GitHub Actions or synchronize drift:
```bash
./scripts/sync_workflows.sh
git add .github/workflows
git commit -m "ci: enable GitHub Actions workflows"
git push
```
*(Requires a GitHub personal access token with the `workflow` scope. GitHub OAuth tokens lacking the `workflow` scope will be rejected by GitHub's pre-receive hook).*

To prevent drift between `ci/workflows/` and `.github/workflows/`, all changes to workflow specifications must be authored in `ci/workflows/` and synced via `./scripts/sync_workflows.sh`.

### Local Test Matrix & Verification Commands

Because remote workflow pushes require the `workflow` OAuth token scope which is currently absent, the complete regression, operational acceptance, and production pilot suite can be executed locally with identical coverage:

```bash
# 1. Benchmark harness and acceptance gates (12 tests)
python3 -m unittest tests/test_capture_benchmark.py -v

# 2. Capture lifecycle, PID reuse races, and byte accounting seams (54 tests)
python3 -m unittest tests/test_capture_lifecycle_seam.py -v

# 3. Real runtime C++ process live capture & memory mutation (20 tests)
python3 -m unittest tests/test_real_runtime_validation.py -v

# 4. End-to-end C++ investigation pipeline scenarios A-E (5 tests)
python3 -m unittest tests/test_cpp_e2e_investigation.py -v

# 5. Phase 10 CI Security Gates & Trust Boundaries (16 tests)
python3 -m unittest tests/test_phase10_ci_security_gates.py -v

# 6. Phase 11 Real-Target Release Readiness (17 tests)
python3 -m unittest tests/test_phase11_real_target_release_readiness.py -v

# 7. Phase 12 Conversational Investigation Loop (11 tests)
python3 -m unittest tests/test_phase12_investigation_loop.py -v

# 8. Phase 13 End-to-End Operational Acceptance (16 tests)
python3 -m unittest tests/test_phase13_operational_acceptance.py -v
python3 scripts/run_e2e_operational_acceptance.py

# 9. Phase 14 Embedded Linux Production Pilot & Security Gates (13 tests)
python3 -m unittest tests/test_phase14_production_pilot.py -v
python3 scripts/run_production_pilot.py --smoke

# 10. Capture benchmark smoke run (schema, byte accounting, SLA checks)
python3 -m benchmarks.capture_benchmark --smoke

# 11. Capture benchmark 20-iteration acceptance run
python3 -m benchmarks.capture_benchmark --iterations 20 --acceptance --output benchmarks/latest_results.json

# 12. Full test discovery suite (634+ tests)
python3 -m unittest discover -s tests -v
```

