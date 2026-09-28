#!/usr/bin/env bash
set -euo pipefail

# Manual Acceptance Test runner for dynamicState Web UI MVP
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

python3 tests/manual_acceptance_web_ui.py

echo "dynamicState Web UI MVP Acceptance Scenario: PASS"
