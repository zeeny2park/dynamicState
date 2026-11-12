#!/usr/bin/env bash
# ==============================================================================
# dynamicState — test baseline recorder (IMP-005)
#
# Runs every tests/test_*.py in its own interpreter with a per-file timeout and
# writes a machine-readable summary, so "how many tests pass" is a recorded
# fact rather than a claim.
#
# Usage: scripts/run_test_baseline.sh [output_dir]   (default: docs/test_baseline)
# Env:   BASELINE_JOBS (default 3), BASELINE_TIMEOUT seconds per file (default 600)
# Exit:  0 when every file passes, 1 otherwise.
# ==============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"
OUT="${1:-docs/test_baseline}"
JOBS="${BASELINE_JOBS:-3}"
TMO="${BASELINE_TIMEOUT:-600}"
LOGS="$(mktemp -d)"
trap 'rm -rf "${LOGS}"' EXIT
mkdir -p "${OUT}"

# Build products the suite expects (same as run_all_tests.sh / ci/workflows/test.yml).
make -C target/collector >/dev/null
g++ -fPIE -pie -g -O0 -fno-inline -fno-omit-frame-pointer -Wl,--build-id=sha1 \
    tests/fixtures/real_runtime/main.cpp -o /tmp/real_runtime_app_debug.elf -lpthread
strip -s -o /tmp/real_runtime_app_prod.stripped /tmp/real_runtime_app_debug.elf

run_one() {
    local f="$1" n rc
    n="$(basename "$f" .py)"
    timeout -k 10 "${TMO}" python3 -m unittest "$f" >"${LOGS}/${n}.log" 2>&1
    rc=$?
    printf '%s\t%s\t%s\t%s\n' "$n" "$rc" \
        "$(grep -E '^Ran [0-9]+ tests?' "${LOGS}/${n}.log" | tail -1 | awk '{print $2}')" \
        "$(tail -1 "${LOGS}/${n}.log" | tr -d '\n\t')" >>"${LOGS}/_rows.tsv"
    [ "$rc" -eq 0 ] || cp "${LOGS}/${n}.log" "${OUT}/failed_${n}.log"
}
export -f run_one; export LOGS TMO OUT

rm -f "${OUT}"/failed_*.log
ls tests/test_*.py | xargs -P "${JOBS}" -I{} bash -c 'run_one "$1"' _ {}

SUMMARY="${OUT}/summary.tsv"
{
    echo "# commit=$(git rev-parse --short HEAD)$(git diff --quiet HEAD -- . ':!docs/test_baseline' || echo '+dirty') date=$(date -u +%Y-%m-%dT%H:%MZ) arch=$(uname -m) python=$(python3 -c 'import platform;print(platform.python_version())') kernel=$(uname -r)"
    printf 'file\texit_code\ttests_ran\tlast_line\n'
    sort "${LOGS}/_rows.tsv"
} >"${SUMMARY}"

FILES=$(grep -vc '^[#f]' "${SUMMARY}" || true)
BAD=$(awk -F'\t' 'NR>2 && $2!=0' "${SUMMARY}" | wc -l)
TESTS=$(awk -F'\t' 'NR>2 {s+=$3} END{print s+0}' "${SUMMARY}")
echo "files=${FILES} failing_files=${BAD} tests_ran=${TESTS}" | tee -a "${SUMMARY}.totals"
mv "${SUMMARY}.totals" "${OUT}/totals.txt"
[ "${BAD}" -eq 0 ]
