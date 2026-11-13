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

From an AI agent, the same thing is one MCP call, `runtime_diagnose_process(pid, debug_image?, symptom?)` (an agent without MCP uses the skill, see [Agents without MCP](#agents-without-mcp-the-skill)). The web UI/API has the same one-call entry: the diagnosis page at `/` (it starts `POST /api/diagnose/start` and shows each check as it finishes; events at `GET /api/diagnose/{job_id}/events`, same data as polling JSON at `.../status`, the report at `.../report?format=html|md|json&lang=ko|en`), or the synchronous `POST /api/diagnose` with `{"pid", "debug_image"?, "symptom"?, "time_limit_s"?}` (session token required; returns `{"success": true, "result": {...}}`).
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

## Agents without MCP: the skill

The `diagnose-process` skill ([skills/diagnose-process/SKILL.md](skills/diagnose-process/SKILL.md)) is the workflow an agent
follows: when to diagnose, what to ask the user, how to read the verdict, what `INCONCLUSIVE` and `HEALTHY` mean, which
narrower follow-up to run, and how to report honestly. It is one file for two ways of calling the tool. Every step has an
`[mcp]` line (a tool call) and a `[cli]` line (a shell command); a test (`tests/test_skill_transports.py`) fails when the
two diverge or when a named tool, command or option does not exist.

**MCP or skill?** Use MCP when your agent can connect MCP servers: the server sends the skill's `[mcp]` view as its
instructions, so nothing else is needed (configuration above). Use the skill when the agent cannot use MCP, or MCP
cannot be configured where it runs, but the agent has a shell: it runs `dynamic-state` commands and reads their JSON.
The skill also tells such an agent how to check that the tool is installed and what to do when it is not.

**1. Install the tool** (on the machine where the target process runs, or where you analyse a remote target from):
the commands in [Install](#install) (`python3 -m pip install .` from a checkout, in a venv if you like). The agent needs
`dynamic-state` on its `PATH`; `readelf` (binutils) is needed for symbol-level diagnosis. The agent's user must be able
to read the target (same user, or `CAP_SYS_PTRACE`, and `kernel.yama.ptrace_scope` permitting it); if not, the result is
`INCONCLUSIVE` with `target_unreadable` in `not_covered`, never "healthy".

**2. Install the skill.** The skill ships inside the installed package, so one command copies it:

<!-- check: skip (writes to your home directory; the check script runs it with --dir and --project) -->
```bash
dynamic-state skill install            # ~/.claude/skills/diagnose-process/   (all your projects)
dynamic-state skill install --project  # ./.claude/skills/diagnose-process/   (this project only)
dynamic-state skill install --dir DIR  # DIR/diagnose-process/                (any skills directory)
```

It refuses to overwrite an existing copy unless you add `--force`. From a checkout without installing, `cp -r
skills/diagnose-process ~/.claude/skills/` is the same thing. `dynamic-state skill path` prints where the shipped copy is.

- **Claude Code** loads skills from `~/.claude/skills/<name>/SKILL.md` (personal) and `.claude/skills/<name>/SKILL.md`
  (project), which is where the commands above write; restart or start a new session, then ask "diagnose PID 1234".
- **Other agents** (Codex CLI, Gemini CLI, Cursor, Copilot, a chat model with a shell tool, ...) have no skill directory in
  common. What works everywhere is to put the skill's text where the agent reads standing instructions, or paste it at the
  start of the conversation. `dynamic-state skill show` prints the command-line view without the frontmatter, ready for that:

<!-- check: skip (appends to a file of your choosing) -->
```bash
dynamic-state skill show >> AGENTS.md
```

`AGENTS.md` is read by Codex CLI and by other agents that follow that convention; Gemini CLI reads `GEMINI.md` and GitHub
Copilot reads `.github/copilot-instructions.md`; for any other agent use its own rules or system-prompt file (check its
documentation for the current name and location). The agent also needs permission to run shell commands.

**3. What the agent runs.** A real session against the deadlock demo from the quick start, as an agent would run it
(corpus and output files in a scratch directory):

```bash
mkdir -p /tmp/ds-example
/tmp/deadlock_demo > /dev/null &
PID=$!
sleep 1
dynamic-state find-process deadlock_demo
dynamic-state diagnose -p $PID --corpus /tmp/ds-example/corpus --json > /tmp/ds-example/result.json
python3 -c 'import json; d = json.load(open("/tmp/ds-example/result.json")); print(d["verdict"], d["confidence"]); print(d["findings"][0]["subjects"]); print(d["collection_impact"]["zero_stop"], d["collection_impact"]["measured_stop_ms"])'
dynamic-state export-report -p $PID -d /proc/$PID/exe --corpus /tmp/ds-example/corpus -o /tmp/ds-example/report.md --report-html /tmp/ds-example/report.html --report-json /tmp/ds-example/report.json > /dev/null
kill $PID
```

`find-process` prints (abridged) `{"success": true, "matches": [{"pid": 80135, "name": "deadlock_demo", "executable":
"/tmp/deadlock_demo", ...}]}`. `diagnose --json` writes the full result object (about 20 keys: `verdict`, `confidence`,
`summary`, `findings`, `checks_run`, `not_covered`, `collection_impact`, `healthy_scope`, `human_summary`, `report_path`, ...).
The Python line prints:

```text
CONFIRMED_FAULT 0.92
['80138', 'ingest', 'm_out', '80139', 'flush', 'm_in', '__GI___lll_lock_wait', 'pthread_mutex_lock', 'ingest', 'deadlock_pipeline.c:15', 'start_thread', 'thread_start', 'flush', 'deadlock_pipeline.c:27']
True 0.0
```

The agent then relays `human_summary` (what is wrong, why, what was not examined, the measured impact) and, for narrower
questions, runs the follow-ups in the skill. The commands and the MCP tool each one stands for:

| Step | MCP tool | Command |
| :--- | :--- | :--- |
| find the PID by name | `runtime_target_connect(process_name=...)` | `dynamic-state find-process NAME` |
| diagnose (symptom, structured symptom fields, remote, language) | `runtime_diagnose_process` | `dynamic-state diagnose -p PID [--symptom ...] [--symptom-kind ...] [--host ...] [--lang ko\|en] --json` |
| export the report (Markdown, HTML, JSON) | `runtime_export_incident_report` | `dynamic-state export-report -p PID -d ELF -o r.md --report-html r.html --report-json r.json` |
| thread call stacks, lock cycles | `runtime_inspect_thread_callstack_and_locks` | `dynamic-state callstacks -p PID -d ELF` |
| heap leak candidates | `runtime_heap_leak_candidates` | `dynamic-state heap-leaks -p PID -d ELF` |
| who owns this address | `runtime_heap_owner_lookup` | `dynamic-state heap-owner -p PID -d ELF -a 0xADDR,...` |
| evaluate a variable | `runtime_eval_memory_path` | `dynamic-state eval --pid PID --debug-image ELF --expr NAME` |
| find a symbol | `runtime_symbol_search` | no keyword search on the command line; `dynamic-state fuzzy-resolve -p PID -d ELF -q "words"` |

Limits are the ones in [Supported targets and known limits](#supported-targets-and-known-limits): zero-stop by default,
`HEALTHY` only within the stated scope, `INCONCLUSIVE` means "could not tell". Each command also takes the remote options:
`--host --user --port --identity` on `diagnose`, `find-process`, `heap-leaks`, `heap-owner` and `export-report`;
`--remote-host --ssh-user --ssh-port --ssh-key` on `callstacks` and `eval`.

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
  (checkpoint, restore, transition, explore, replay). The runtime is read-only unless constructed with `allow_mutation=True`.
- **Web UI/API:** read-only towards the target: no route writes memory, stops the process, runs a command or changes
  state (the route table is `API_ROUTES` in `extractor/web/server.py`). The REST API requires a per-run session token
  (injected into the page the server itself serves) and binds to 127.0.0.1 by default.
- Observation budgets (bytes, wall clock, samples) bound every diagnosis.

Web UI (optional):

<!-- check: skip (blocking server; checked by starting it and fetching /) -->
```bash
dynamic-state server --host 127.0.0.1 --port 8765
```

Then open `http://127.0.0.1:8765/` (the same as `python3 -m extractor.web --host 127.0.0.1 --port 8765`). `/` is the diagnosis page (`extractor/web/ui/`): enter a PID or a process name, optionally a symptom and a debug ELF, press **진단 / Diagnose**; the page fills in as the diagnosis runs and, when it ends, is the report, with a link to the full HTML report (also Markdown and JSON). Korean by default, English with the `KO/EN` button; light/dark follows the OS or the theme button. `/?replay=deadlock` (also `healthy`, `inconclusive`, `degraded`) replays a saved diagnosis without any target, for demos. The previous interfaces (the 8-tab explorer at `/legacy/` and the chat workspace at `/legacy/workspace`) were removed; their old URLs redirect to `/`. Behind a reverse proxy under a path prefix (for example `/dynamicstate/`), every URL the pages use is relative, so no server option is needed; if the proxy buffers the event stream the page falls back to polling by itself (the server also sends `X-Accel-Buffering: no` for nginx). The HTTP contract is `docs/ui-redesign/API_CONTRACT.md`.

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
  - Healthy processes are cleared as `HEALTHY` only when every baseline check ran to completion and found nothing;
    `healthy_scope` lists what was checked and what was not ([docs/HEALTHY_VERDICT.md](docs/HEALTHY_VERDICT.md)).
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

- [skills/diagnose-process/SKILL.md](skills/diagnose-process/SKILL.md): the agent workflow for MCP and for shell-only agents (single source for the MCP instructions and playbook; install: [Agents without MCP](#agents-without-mcp-the-skill))
- [docs/PRACTICAL_PLAYBOOK_KO.md](docs/PRACTICAL_PLAYBOOK_KO.md): practical playbook (Korean)
- [docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md](docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md), [docs/PROCESS_HEALTH_INVESTIGATION_KNOWLEDGE.md](docs/PROCESS_HEALTH_INVESTIGATION_KNOWLEDGE.md): investigation method and tool semantics
- [target/collector/README.md](target/collector/README.md): the target-side collector

## License

MIT, see [LICENSE](LICENSE).
