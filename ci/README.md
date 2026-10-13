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
