#!/bin/bash
set -e

echo "=== GDB 9.2 Verification Environment ==="
gdb --version | head -n 1
python3 --version

echo "=== Running dynamicState GDB 9.2 Integration Tests ==="
python3 tests/integration_gdb92.py --direct

echo "=== GDB 9.2 Integration Tests Passed ==="
