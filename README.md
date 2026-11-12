# dynamicState

[![Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)](#supported-targets-and-known-limits)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](#install)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

dynamicState lets an AI agent (or you) diagnose a **live Linux process** (memory leaks, buffer ownership, deadlocks,
misbehaving threads) by reading the process's memory and `/proc` **without stopping it**. It resolves what it reads
against DWARF debug info, so findings name the variable, thread, lock and source line. It runs locally or against an
embedded target over SSH, and is exposed as an MCP server, a CLI and a web UI.

## Quick start: diagnose PID N

```bash
python3 -m pip install .
gcc -g -O0 -pthread -o /tmp/deadlock_demo benchmarks/diagnosis_accuracy/targets/deadlock_pipeline.c
/tmp/deadlock_demo > /dev/null &
PID=$!
sleep 1
dynamic-state diagnose -p $PID
```

Output (abridged): `Verdict CONFIRMED_FAULT: found DEADLOCK_INDICATORS. ...` and a report path. Add `--json` for the full
result, `-d /path/to/debug.elf` when the process binary is stripped, `--symptom "..."` to describe the problem.

```bash
dynamic-state diagnose -p $PID --json
kill $PID
```

From an AI agent, the same thing is one MCP call, `runtime_diagnose_process(pid, debug_image?, symptom?)`. The web UI/API has the same one-call entry: the "Diagnose" button on `/workspace`, or `POST /api/diagnose` with `{"pid", "debug_image"?, "symptom"?, "time_limit_s"?}` (session token required; returns `{"success": true, "result": {...}}`).
Configure your agent (Claude Desktop, Cursor, ...) with:

```json
{
  "mcpServers": {
    "dynamicstate": { "command": "dynamic-state-mcp" }
  }
}
```

The server ships its operating instructions (the `diagnose-process` skill, [skills/diagnose-process/SKILL.md](skills/diagnose-process/SKILL.md))
so an agent asked to "diagnose PID N" calls `runtime_diagnose_process` once and reports what was and was not examined.
The same text is returned by `runtime_get_playbook`.

## Install

Requires Python 3.10+, Linux, and the `mcp` Python package (>= 2.0, installed automatically).

<!-- check: skip (the check script creates its own fresh venv) -->
```bash
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install .
```

Host tools used by the analysis (install the `binutils` package; `gcc`/`g++` only to build test programs):

| Tool | Used for | Required |
| :--- | :--- | :--- |
| `readelf` (binutils) | DWARF location lists, section checks | yes, for symbol-level diagnosis |
| `nm`, `objdump`, `addr2line`, `c++filt`, `objcopy`, `strip` (binutils) | symbol / address resolution, debug-image handling | recommended |
| `ssh`, `scp` (OpenSSH client) | remote (embedded) targets | only for remote |
| `gdb` | CONSISTENT (stop-and-checkpoint) mode only | optional |
| `bpftrace` | function tracing (`trace-function`) | optional |
| cross compilers (`aarch64-linux-gnu-gcc`, `x86_64-linux-gnu-gcc`) | building the collector for ARM64 / x86-64 targets | only to build it |

Reading another process's memory needs the same user and `kernel.yama.ptrace_scope` permitting it (or `CAP_SYS_PTRACE`).
Debug info: the target binary must be built with `-g`, or you must pass the unstripped build of the same program as
`debug_image` (the GNU build-id must match).

## What the diagnosis returns

`diagnose()` (CLI `diagnose`, MCP `runtime_diagnose_process`) returns one JSON object:

- `verdict`: `CONFIRMED_FAULT`, `PROBABLE_FAULT`, `FAULT`, `DEGRADED`, `HEALTHY`, `INCONCLUSIVE` or `ABORTED`, with `confidence` and `summary`.
- `findings[]`: `category`, `severity`, `subjects` (the concrete lock, thread, function, variable and `file:line` names), evidence ids.
- `checks_run[]` and `not_covered[]`: what was executed, and what could not be examined and why. An unreadable PID or a
  missing debug image gives `INCONCLUSIVE` with the cause in `not_covered`; it is never reported as healthy.
- `collection_impact`: capture mode, measured stop time (0 for the default mode), bytes read, budget use.
- `report_path`: a JSON report on disk.

Narrower tools for follow-up (MCP): `runtime_heap_owner_lookup` (address to owning variable), `runtime_heap_leak_candidates`
(in-use chunks no root reaches), `runtime_inspect_thread_callstack_and_locks`, `runtime_eval_memory_path`, and others.
Call `runtime_get_playbook` for how an agent should use them.

## Embedded and remote targets

The target needs no Python: a small static C collector captures memory on the board and the host does the analysis.

```bash
make -C target/collector dist
```

This builds `target/collector/dist/<arch>/dynamicstate-collector` for each installed cross compiler (aarch64 and
x86_64) and prints which architectures were skipped. Deploy and connect (needs SSH access to the target):

<!-- check: skip (needs a remote target; checked with --help) -->
```bash
dynamic-state connect --pid 1234 --debug-image ./app.debug --remote-host 192.0.2.10 --ssh-user root --auto-deploy-collector
```

The collector matching the target's `uname -m` is streamed over SSH (falls back to a writable directory if `/tmp` is
noexec). The target's ABI (architecture, libc, allocator) is detected and unsupported features are refused explicitly.
The one-call `diagnose` also works against a remote target (analysis on the host, collector on the board; the matching
**unstripped** ELF on the host is required because the board's own executable is usually stripped):

<!-- check: skip (needs a remote target; checked with --help) -->
```bash
dynamic-state diagnose --pid 1234 --debug-image ./app.debug --host 192.0.2.10 --user root --port 22 --identity ~/.ssh/id_ed25519 --auto-deploy-collector
```

The same fields exist on the MCP tool `runtime_diagnose_process` (`remote_host`, `ssh_user`, `ssh_port`, `ssh_key`,
`ssh_proxy_jump`, `auto_deploy_collector`) and on `POST /api/diagnose`; key files only, no passwords. An unreachable
host is `INCONCLUSIVE` with `target_unreachable`; a missing debug image is `INCONCLUSIVE` with `missing_debug_image`.
The default wall-clock budget of a remote diagnosis is 120 s (local 5 s; `--time-limit` overrides). Remote gaps are listed in `not_covered` (`remote_limitation`): thread-local storage / TCB discovery, stacks of threads that
were running at collection time, and symbols of libraries that could not be fetched. Heap walks (leak owner, heap
integrity) run remotely through the collector's zero-stop reads in 64 KiB slices; they are capped by the observation
budget, so a large heap over a slow link is reported as not checked rather than walked partially.

## Safety defaults

- **Read-only and zero-stop by default.** Reads use `process_vm_readv` and `/proc`; the process is never paused or written to.
  `collection_impact.measured_stop_ms` reports the measured stop time.
- **Needs explicit approval:** any stop-mode capture (`allow_stop`, CONSISTENT/GDB mode) and any state change
  (checkpoint, restore, transition, explore, replay). The runtime is read-only unless started with `--allow-mutation` (`dynamic-state server`).
- **Web UI/API:** the REST API requires a per-run session token (injected into the page the server itself serves) and binds to 127.0.0.1 by default.
- Observation budgets (bytes, wall clock, samples) bound every diagnosis.

Web UI (optional):

<!-- check: skip (blocking server; checked by starting it and fetching /workspace) -->
```bash
dynamic-state-workspace --host 127.0.0.1 --port 8765
```

Then open `http://127.0.0.1:8765/workspace`.

## Supported targets and known limits

- Linux, C/C++ programs with DWARF. Lock-owner decoding, heap walking and call-stack unwinding are implemented for
  **glibc on 64-bit x86_64 and aarch64 (little-endian)** (`extractor/target_abi.py`). On other ABIs (32-bit ARM, musl, MIPS, ...)
  `diagnose` lists the affected features in `not_covered` as `unsupported_on_target` and does not guess; raw capture with the
  collector still works there.
- Current accuracy is low and measured, not assumed. [benchmarks/diagnosis_accuracy](benchmarks/diagnosis_accuracy/README.md)
  runs `diagnose` on 13 defective and 8 healthy real processes (committed results in `benchmarks/diagnosis_accuracy/results/`;
  re-run on this version: 0 of 13 detected with the scenario symptom, 2 of 13 with the general health check).
  - Works today: **deadlocks** are confirmed with the lock names and thread names (and the lock call's source line, within a few lines).
  - Not yet: leaks, heap overflow, use-after-free, busy-wait and long stalls are usually `INCONCLUSIVE` from `diagnose`.
    For leaks and buffer ownership use `runtime_heap_leak_candidates` and `runtime_heap_owner_lookup` directly.
  - Healthy processes are not yet cleared: they come back `INCONCLUSIVE`, never `HEALTHY` and never a false fault.
    Treat `INCONCLUSIVE` as "could not tell".
  - The result depends on the symptom wording ("the service stopped responding" is `INCONCLUSIVE` on a real deadlock; the default general check finds it).
- Remote one-call diagnosis has the gaps listed above (`remote_limitation` in `not_covered`).

## Tests and CI

```bash
python3 -m pip install ".[test]"
python3 -m unittest tests/test_imp_006_diagnose.py
```

<!-- check: skip (full suite; run by its own CI steps) -->
```bash
python3 -m unittest discover tests
```

The per-file baseline of the full suite is in [docs/TEST_BASELINE.md](docs/TEST_BASELINE.md) (regenerate with
`scripts/run_test_baseline.sh`). CI ([ci/workflows/test.yml](ci/workflows/test.yml), mirrored in `.github/workflows/`) builds the
collector and fixtures, runs the suite, records the baseline, runs the diagnosis accuracy benchmark (reports, never gates on the score),
and installs the package into a fresh venv and runs the commands in this README (`scripts/check_readme_commands.sh`).

## Documentation

- [skills/diagnose-process/SKILL.md](skills/diagnose-process/SKILL.md): the agent workflow (single source for the MCP instructions and playbook)
- [docs/PRACTICAL_PLAYBOOK_KO.md](docs/PRACTICAL_PLAYBOOK_KO.md): practical playbook (Korean)
- [docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md](docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md), [docs/PROCESS_HEALTH_INVESTIGATION_KNOWLEDGE.md](docs/PROCESS_HEALTH_INVESTIGATION_KNOWLEDGE.md): investigation method and tool semantics
- [target/collector/README.md](target/collector/README.md): the target-side collector

## License

MIT, see [LICENSE](LICENSE).
