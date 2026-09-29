# CI Workflows for dynamicState

This directory contains the automated CI workflows for dynamicState.

### Workflows

1. **`ci/workflows/test.yml`**:
   - Runs on Ubuntu 22.04.
   - Installs system dependencies (`gdb`, `gcc`, `g++`, `make`).
   - Compiles the native C99 target collector (`target/collector`).
   - Executes the full test suite (229 unit and integration tests including multithread exploration, memory snapshot, and lifecycle tests).

2. **`ci/workflows/gdb92.yml`**:
   - Runs on Ubuntu 22.04 with Docker.
   - Builds the containerized legacy GDB 9.2 environment (`docker/gdb92/Dockerfile`).
   - Runs `tests/integration_gdb92.py` verifying GDB 9.2 compatibility for multithread inferior inspection, low-impact observation, and process lifecycle handling.

### Activating in GitHub Actions

To activate these workflows directly on GitHub Actions:
```bash
mkdir -p .github/workflows
cp ci/workflows/*.yml .github/workflows/
git add .github/workflows
git commit -m "ci: enable GitHub Actions workflows"
git push
```
*(Requires a GitHub personal access token with the `workflow` scope).*
