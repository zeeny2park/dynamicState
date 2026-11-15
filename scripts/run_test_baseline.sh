#!/usr/bin/env bash
# ==============================================================================
# dynamicState — test baseline recorder (IMP-005)
#
# Runs every tests/test_*.py in its own interpreter with a per-file timeout and
# writes a machine-readable, self-describing summary so "how many tests pass" is
# a recorded fact rather than a claim.
#
# Usage: scripts/run_test_baseline.sh [output_dir]   (default: docs/test_baseline)
# Env:   BASELINE_JOBS (default 2, never above available CPUs),
#        BASELINE_TIMEOUT seconds per file (default 600),
#        BASELINE_RECORD_ONLY (1 to record artifact without non-zero exit gate)
# Exit:  0 when every file passes (or when RECORD_ONLY=1), 1 if failures occur.
# ==============================================================================
set -euo pipefail

REPO_ROOT="${BASELINE_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "${REPO_ROOT}"
OUT="${1:-docs/test_baseline}"
CPU_COUNT="$(python3 -c 'import os; print(max(1, len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else (os.cpu_count() or 1)))')"
DEFAULT_JOBS=2
if (( CPU_COUNT < DEFAULT_JOBS )); then DEFAULT_JOBS="${CPU_COUNT}"; fi
JOBS="${BASELINE_JOBS:-${DEFAULT_JOBS}}"
TMO="${BASELINE_TIMEOUT:-600}"

if ! [[ "${JOBS}" =~ ^[1-9][0-9]*$ ]]; then
    echo "BASELINE_JOBS must be a positive integer (got: ${JOBS})" >&2
    exit 2
fi
if (( JOBS > CPU_COUNT )); then
    echo "BASELINE_JOBS=${JOBS} exceeds ${CPU_COUNT} available CPU(s); lower BASELINE_JOBS before running." >&2
    exit 2
fi
if ! [[ "${TMO}" =~ ^[1-9][0-9]*$ ]]; then
    echo "BASELINE_TIMEOUT must be a positive integer number of seconds (got: ${TMO})" >&2
    exit 2
fi

LOGS="$(mktemp -d)"
trap 'rm -rf "${LOGS}"' EXIT

# Clean and initialize output directory
mkdir -p "${OUT}"
rm -f "${OUT}"/failed_*.log "${OUT}/summary.tsv" "${OUT}/totals.txt" "${OUT}/summary.tsv.totals"

# Build products the suite expects (same as run_all_tests.sh / ci/workflows/test.yml).
if [ -d "${REPO_ROOT}/target/collector" ]; then
    make -C "${REPO_ROOT}/target/collector" >/dev/null
fi
if [ -f "${REPO_ROOT}/tests/fixtures/real_runtime/main.cpp" ]; then
    g++ -fPIE -pie -g -O0 -fno-inline -fno-omit-frame-pointer -Wl,--build-id=sha1 \
        "${REPO_ROOT}/tests/fixtures/real_runtime/main.cpp" -o /tmp/real_runtime_app_debug.elf -lpthread
    strip -s -o /tmp/real_runtime_app_prod.stripped /tmp/real_runtime_app_debug.elf
fi

# Deterministic enumeration of all test files
mapfile -t ALL_TEST_FILES < <(find tests -maxdepth 1 -name 'test_*.py' | LC_ALL=C sort)

if [ "${#ALL_TEST_FILES[@]}" -eq 0 ]; then
    echo "Error: No test files found matching tests/test_*.py" >&2
    exit 2
fi

run_one() {
    local f="$1" n rc status tests_ran last_line
    n="$(basename "$f" .py)"
    set +e
    timeout -k 10 "${TMO}" python3 scripts/run_unittest.py "$f" >"${LOGS}/${n}.log" 2>&1
    rc=$?
    set -e

    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        status="INFRA_FAILURE"
    elif [ "$rc" -eq 0 ]; then
        status="PASSED"
    else
        status="FAILED"
    fi

    tests_ran="$(grep -E '^Ran [0-9]+ tests?' "${LOGS}/${n}.log" | tail -1 | awk '{print $2}')"
    if [ -z "${tests_ran}" ]; then
        tests_ran=0
    fi
    last_line="$(tail -1 "${LOGS}/${n}.log" 2>/dev/null | tr -d '\n\r\t' || echo "")"

    printf '%s\t%s\t%s\t%s\t%s\n' "$n" "$status" "$rc" "$tests_ran" "$last_line" >>"${LOGS}/_rows.tsv"
    [ "$rc" -eq 0 ] || cp "${LOGS}/${n}.log" "${OUT}/failed_${n}.log"
}
export -f run_one; export LOGS TMO OUT

touch "${LOGS}/_rows.tsv"
PARALLEL_EXEC=()
SERIAL_EXEC=()

for f in "${ALL_TEST_FILES[@]}"; do
    n="$(basename "$f" .py)"
    skip_line="$(grep -m 1 -E "(BASELINE_SKIP|CI_FLAKY)" "$f" || true)"
    if [ -n "${skip_line}" ]; then
        reason="$(echo "${skip_line}" | sed -E 's/^# *(BASELINE_SKIP|CI_FLAKY):? *//')"
        if echo "${skip_line}" | grep -qiE "eBPF|root|capability|privilege|permission"; then
            status="SKIPPED_CAPABILITY"
        else
            status="SKIPPED_FLAKY"
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' "$n" "$status" "SKIPPED" "0" "$reason" >>"${LOGS}/_rows.tsv"
    else
        if grep -q "BASELINE_SERIAL" "$f"; then
            SERIAL_EXEC+=("$f")
        else
            PARALLEL_EXEC+=("$f")
        fi
    fi
done

# Run parallel batch
if [ "${#PARALLEL_EXEC[@]}" -gt 0 ]; then
    printf '%s\n' "${PARALLEL_EXEC[@]}" | xargs -P "${JOBS}" -I{} bash -c 'run_one "$1"' _ {}
fi

# Run serial batch alone
for f in "${SERIAL_EXEC[@]}"; do
    run_one "$f"
done

SUMMARY="${OUT}/summary.tsv"
{
    echo "# commit=$(git rev-parse --short HEAD)$(git diff --quiet HEAD -- . ':!docs/test_baseline' || echo '+dirty') date=$(date -u +%Y-%m-%dT%H:%MZ) arch=$(uname -m) python=$(python3 -c 'import platform;print(platform.python_version())') kernel=$(uname -r)"
    printf 'file\tstatus\texit_code\ttests_ran\tdetail\n'
    LC_ALL=C sort "${LOGS}/_rows.tsv"
} >"${SUMMARY}"

TOTAL_FILES="${#ALL_TEST_FILES[@]}"
PASSED_FILES=$(awk -F'\t' 'NR>2 && $2=="PASSED"' "${SUMMARY}" | wc -l)
FAILED_FILES=$(awk -F'\t' 'NR>2 && $2=="FAILED"' "${SUMMARY}" | wc -l)
INFRA_FILES=$(awk -F'\t' 'NR>2 && $2=="INFRA_FAILURE"' "${SUMMARY}" | wc -l)
SKIP_CAP_FILES=$(awk -F'\t' 'NR>2 && $2=="SKIPPED_CAPABILITY"' "${SUMMARY}" | wc -l)
SKIP_FLAKY_FILES=$(awk -F'\t' 'NR>2 && $2=="SKIPPED_FLAKY"' "${SUMMARY}" | wc -l)
EXEC_FILES=$(( PASSED_FILES + FAILED_FILES + INFRA_FILES ))
TESTS_RAN=$(awk -F'\t' 'NR>2 {s+=$4} END{print s+0}' "${SUMMARY}")
BAD=$(( FAILED_FILES + INFRA_FILES ))

{
    echo "files_total=${TOTAL_FILES} files_executed=${EXEC_FILES} files_passed=${PASSED_FILES} files_failed=${FAILED_FILES} files_skipped_capability=${SKIP_CAP_FILES} files_skipped_flaky=${SKIP_FLAKY_FILES} files_infra_failure=${INFRA_FILES} tests_ran=${TESTS_RAN}"
    echo "files=${TOTAL_FILES} failing_files=${BAD} tests_ran=${TESTS_RAN}"
} >"${OUT}/totals.txt"

cat "${OUT}/totals.txt"

if [ "${BASELINE_RECORD_ONLY:-0}" = "1" ]; then
    echo "BASELINE_RECORD_ONLY=1: baseline recorded as informational artifact without gating (executed=${EXEC_FILES}, passed=${PASSED_FILES}, failing_files=${BAD}, skipped_flaky=${SKIP_FLAKY_FILES}, skipped_capability=${SKIP_CAP_FILES})"
    exit 0
fi

[ "${BAD}" -eq 0 ]
