# Source from a shell script (needs ROOT_DIR = repository root):  . "${ROOT_DIR}/tests/support/fixture_process.sh"
#
#   start_fixture LOGFILE CMD [ARGS...]    # sets FIXTURE_PID (the fixture) and FIXTURE_RUNNER_PID (its guard)
#
# The fixture is started through tests/support/fixture_process.py (pdeathsig, watchdog, RSS ceiling, lifetime), so it
# cannot outlive this script however the script ends.  Never start a long-lived fixture with a bare `cmd &`.
start_fixture() {
    local log="$1"; shift
    local pidfile; pidfile="$(mktemp)"; rm -f "${pidfile}"
    ( cd "${ROOT_DIR}" && exec python3 -m tests.support.fixture_process --pidfile "${pidfile}" -- "$@" ) \
        > "${log}" 2>&1 &
    FIXTURE_RUNNER_PID=$!
    local _
    for _ in $(seq 1 200); do [ -s "${pidfile}" ] && break; sleep 0.05; done
    FIXTURE_PID="$(cat "${pidfile}" 2>/dev/null || true)"
    rm -f "${pidfile}"
}
stop_fixture_runner() {
    if [[ -n "${FIXTURE_RUNNER_PID:-}" ]]; then kill "${FIXTURE_RUNNER_PID}" 2>/dev/null || true; fi
}
