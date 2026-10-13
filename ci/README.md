# CI Workflows for dynamicState

This directory contains the automated CI workflows for dynamicState.

### Workflows

1. **`ci/workflows/test.yml`**:
   - Runs on Ubuntu 22.04.
   - Installs system dependencies (`gdb`, `gcc`, `g++`, `make`).
   - Compiles the native C99 target collector (`target/collector`) and real runtime C++ fixtures.
   - Executes the full test suite (430 unit and integration tests including multithread exploration, memory snapshot, and lifecycle tests, plus end-to-end C++ investigation pipeline scenarios A-E).

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

Because remote workflow pushes require the `workflow` OAuth token scope which is currently absent, the complete regression and benchmark suite can be executed locally with identical coverage:

```bash
# 1. Benchmark harness and acceptance gates (12 tests)
python3 -m unittest tests/test_capture_benchmark.py -v

# 2. Capture lifecycle, PID reuse races, and byte accounting seams (54 tests)
python3 -m unittest tests/test_capture_lifecycle_seam.py -v

# 3. Real runtime C++ process live capture & memory mutation (20 tests)
python3 -m unittest tests/test_real_runtime_validation.py -v

# 4. End-to-end C++ investigation pipeline scenarios A-E (5 tests)
python3 -m unittest tests/test_cpp_e2e_investigation.py -v

# 5. Capture benchmark smoke run (schema, byte accounting, SLA checks)
python3 -m benchmarks.capture_benchmark --smoke

# 6. Capture benchmark 20-iteration acceptance run
python3 -m benchmarks.capture_benchmark --iterations 20 --acceptance --output benchmarks/latest_results.json

# 7. Full test discovery suite (464 tests)
python3 -m unittest discover -s tests -v
```

