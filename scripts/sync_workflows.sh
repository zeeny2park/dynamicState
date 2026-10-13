#!/usr/bin/env bash
# ==============================================================================
# dynamicState — CI Workflow Synchronization & Drift Prevention Script
#
# Copies canonical workflow definitions from ci/workflows/ to .github/workflows/
# and validates exact parity.
#
# NOTE ON GITHUB ACTIONS PERMISSIONS / OAUTH TOKENS:
# GitHub pre-receive hooks enforce that any push creating or updating files under
# .github/workflows/ requires a token with the 'workflow' scope.
# When running with a scoped OAuth token lacking 'workflow', git push will fail with:
#   "refusing to allow an OAuth App to create or update workflow .github/workflows/...
#    without workflow scope"
#
# This script ensures that local canonical definitions in ci/workflows/ can be synced
# deterministically whenever a token with 'workflow' scope is available.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SOURCE_DIR="${SYNC_SOURCE_DIR:-${REPO_ROOT}/ci/workflows}"
TARGET_DIR="${SYNC_TARGET_DIR:-${REPO_ROOT}/.github/workflows}"

echo "=== Syncing CI workflows from ${SOURCE_DIR} to ${TARGET_DIR} ==="

if [ ! -d "${SOURCE_DIR}" ]; then
    echo "ERROR: Source directory ${SOURCE_DIR} not found!" >&2
    exit 1
fi

mkdir -p "${TARGET_DIR}"

# 1. Clean up stale workflows in .github/workflows/ that do not exist in ci/workflows/
STALE_COUNT=0
for dst_file in "${TARGET_DIR}"/*.yml "${TARGET_DIR}"/*.yaml; do
    [ -e "${dst_file}" ] || continue
    fname="$(basename "${dst_file}")"
    src_file="${SOURCE_DIR}/${fname}"
    if [ ! -f "${src_file}" ]; then
        echo "  [STALE] Removing stale workflow: .github/workflows/${fname}"
        rm -f "${dst_file}"
        STALE_COUNT=$((STALE_COUNT + 1))
    fi
done

# 2. Copy canonical workflows from ci/workflows/ to .github/workflows/
SYNCED_COUNT=0
for src_file in "${SOURCE_DIR}"/*.yml "${SOURCE_DIR}"/*.yaml; do
    [ -e "${src_file}" ] || continue
    fname="$(basename "${src_file}")"
    dst_file="${TARGET_DIR}/${fname}"
    cp -p "${src_file}" "${dst_file}"
    echo "  Synced: ci/workflows/${fname} -> .github/workflows/${fname}"
    SYNCED_COUNT=$((SYNCED_COUNT + 1))
done

echo ""
echo "Validating workflow parity..."
MISMATCH_COUNT=0
for src_file in "${SOURCE_DIR}"/*.yml "${SOURCE_DIR}"/*.yaml; do
    [ -e "${src_file}" ] || continue
    fname="$(basename "${src_file}")"
    dst_file="${TARGET_DIR}/${fname}"
    if [ ! -f "${dst_file}" ]; then
        echo "  [MISSING] ${fname} missing from .github/workflows/!" >&2
        MISMATCH_COUNT=$((MISMATCH_COUNT + 1))
    elif ! cmp -s "${src_file}" "${dst_file}"; then
        echo "  [MISMATCH] ${fname} differs between source and target!" >&2
        MISMATCH_COUNT=$((MISMATCH_COUNT + 1))
    fi
done

for dst_file in "${TARGET_DIR}"/*.yml "${TARGET_DIR}"/*.yaml; do
    [ -e "${dst_file}" ] || continue
    fname="$(basename "${dst_file}")"
    src_file="${SOURCE_DIR}/${fname}"
    if [ ! -f "${src_file}" ]; then
        echo "  [EXTRA] ${fname} exists in .github/workflows/ but not in ci/workflows/!" >&2
        MISMATCH_COUNT=$((MISMATCH_COUNT + 1))
    fi
done

if [ "${MISMATCH_COUNT}" -eq 0 ]; then
    echo "SUCCESS: All ${SYNCED_COUNT} workflows synchronized with 100% parity (stale cleaned: ${STALE_COUNT})."
else
    echo "ERROR: ${MISMATCH_COUNT} workflow parity issues detected!" >&2
    exit 1
fi
