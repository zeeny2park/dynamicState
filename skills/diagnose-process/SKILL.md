---
name: diagnose-process
description: Use when the user asks you to diagnose, health-check or find what is wrong with a running Linux process ("diagnose PID 1234", "why is this process hung / leaking memory / slow", "is this process healthy") and the dynamicstate MCP tools (runtime_diagnose_process) or the dynamic-state command line are available. Runs one zero-stop diagnosis, reads the verdict, runs the narrower follow-up only when needed, and reports what was and was not examined. Works from MCP tool calls or from plain shell commands. Do not use for offline core dumps or for processes you cannot read.
---

# Diagnose a live process with dynamicState

dynamicState reads a running process's memory and /proc without stopping it and resolves what it finds against DWARF
debug info.
[mcp] One call, `runtime_diagnose_process`, runs the whole diagnosis. This skill says how to use it and how to report the result honestly.
[cli] One command, `dynamic-state diagnose`, runs the whole diagnosis. This skill says how to use it and how to report the result honestly.

<!-- begin:raw -->
One method, two ways to call it. Lines starting with `[mcp]` apply when you have the dynamicState MCP tools; lines
starting with `[cli]` apply when you only have a shell. Use one family and ignore the other's tagged lines. Everything
untagged applies to both. (`dynamic-state skill install` installs this file as is; the MCP server sends only the
`[mcp]` view.)
<!-- end:raw -->

<!-- begin:cli -->
## Before you start (command line only)
1. Is the tool installed? Run `dynamic-state --help`. If the command is not found, install it (Python 3.10+, Linux):
   `git clone https://github.com/zeeny2park/dynamicState.git && cd dynamicState && python3 -m pip install .`
   (a virtual environment is fine; the `dynamic-state` command must then be on PATH). Symbol-level diagnosis also needs
   `readelf` from the `binutils` package. Tell the user before you install anything.
2. Can you read the target? Reading another process needs the same user, or `CAP_SYS_PTRACE` (root), and
   `kernel.yama.ptrace_scope` (`cat /proc/sys/kernel/yama/ptrace_scope`) that permits it. When it does not, the command
   does not fail: the result is `INCONCLUSIVE` with a `target_unreadable` entry in `not_covered`, for example
   `process 1 memory is not readable by this user: [Errno 13] Permission denied: '/proc/1/mem'`, or
   `process 999999 does not exist`. Report that and ask the user to run you as the process's user or to allow ptrace;
   do not try `sudo`, `gdb` or `kill` on your own.
3. Always pass `--corpus DIR` with a scratch directory you can write (for example `--corpus /tmp/dynamicstate-corpus`).
   The default is `./corpus` in the current directory, where the report files are written.
4. Output: `dynamic-state diagnose` prints a Markdown report. Add `--json` for the full result object (the report is then
   under `human_summary`) and redirect it to a file, then read the fields named below.
<!-- end:cli -->

## When to use
- The user names a PID (or a process you can resolve to one) and asks what is wrong, or whether it is healthy.
- Symptoms: hang, deadlock, stuck threads, high CPU, memory growth or leak, a buffer that "belongs" to someone.
- Not for: crashed processes (no live PID), offline snapshots only, or targets the tool does not support (see Limits).

## Required inputs
1. PID of the target. If missing, ask: "Which process (PID, or the name I should look up)?" If the user gives a name:
[mcp] `runtime_target_connect(process_name=NAME, companion_elf=ELF)` resolves it; if several match, ask which one.
[cli] `dynamic-state find-process NAME [-d ELF]` lists matches as JSON (`matches[]`: `pid`, `name`, `executable`, `cmdline`, `build_id_match`); if several match, ask which one. It exits 1 when nothing matches.
2. Debug ELF: the binary built with debug info (DWARF) that matches the running build. Default is the process's own
   executable, which works only if it is not stripped. If the process is stripped or the user ships a separate
   debug file, ask: "Where is the unstripped / debug build of this program (same build as the running process)?"
   Never guess a path.
3. Optional symptom in the user's words (for example "the process hangs"). Pass it as the symptom only if the user
   gave one; do not invent one. Wording changes which checks run: a phrase such as "the service stopped
   responding" can yield INCONCLUSIVE on a real deadlock where the default general health check finds it.
   Structured fields are better than free text when the user's words make the kind clear:
[mcp] `symptom_kind` (memory_growth, hang_deadlock, cpu_spin, crash_corruption, use_after_free, double_free, stack_corruption, data_race, thread_growth, fd_leak, slow_contended, process_instability, variable_anomaly, state_transition, state_inconsistency, resource_exhaustion, health_check), `symptom_frequency` (constant, intermittent, once), `symptom_duration`, `affected_area` (memory, threads, cpu, locks, files, network, state, other), `related_objects` (names the user mentioned).
[cli] `--symptom-kind KIND` (the values are listed by `dynamic-state diagnose --help`), `--symptom-frequency constant|intermittent|once`, `--symptom-duration TEXT`, `--affected-area AREA`, `--related-object NAME` (repeatable).
4. Remote (embedded) target: if the process runs on a board / another host, ask: "Which host (name or IP), ssh user,
   port and key file should I use?" and never invent them. The PID is the PID on the target. For a remote target
   the debug ELF is REQUIRED (the board's own executable is usually stripped): ask for the unstripped build of the
   running program on this machine. It is the host that analyses; nothing is stopped on the board. Key file path only,
   never a password or key contents. If the user agrees to copy the small collector to the board, also enable collector deployment.
[mcp] Pass `remote_host`, `ssh_user`, `ssh_port`, `ssh_key`, optionally `ssh_proxy_jump` and `auto_deploy_collector=true` to the same `runtime_diagnose_process` call.
[cli] Add `--host HOST --user USER --port PORT --identity KEYFILE [--ssh-proxy-jump JUMP] [--auto-deploy-collector]` to `dynamic-state diagnose` (`find-process`, `heap-owner`, `heap-leaks` and `export-report` take the same options; `callstacks` and `eval` take only the long names `--remote-host --ssh-user --ssh-port --ssh-key`).

## Workflow
1. Run the diagnosis once; use language `ko` when the user writes Korean, otherwise `en`.
[mcp] Call `runtime_diagnose_process(pid, debug_image, symptom, language[, remote_host, ssh_user, ssh_port, ssh_key, auto_deploy_collector])` once.
[cli] Run `dynamic-state diagnose -p PID [-d ELF] [--symptom TEXT] --lang ko|en --corpus DIR --json > result.json`; the exit code is 0 even for INCONCLUSIVE, so read `verdict` in the JSON.
2. Read `human_summary` first (a ready-made plain-language report in the requested language), then `verdict`, `findings`, `not_covered`, `collection_impact` (see next section).
3. Follow up according to the verdict (see Follow-up). Do not re-run the diagnosis hoping for a different answer.
4. Relay `human_summary` to the user as written (do not re-summarize away its names, source locations, what was not examined or the measured impact), then add only what a follow-up contributed. If you must explain in your own words, use the user's language.
5. If the user wants a report to keep or share, export it (Markdown, HTML or JSON). This runs a fresh diagnosis of the same PID.
[mcp] `runtime_export_incident_report(pid, companion_elf, format="markdown"|"html"|"json", output_path=PATH, language)`.
[cli] `dynamic-state export-report -p PID -d ELF --corpus DIR --lang en -o report.md --report-html report.html --report-json report.json` (any subset of the three outputs). It prints a large JSON object; redirect it to a file and read `verdict`, `saved_path`, `saved_html_path`, `saved_json_path`. The JSON file is the full structured report (keys `section_a_...` to `section_j_...`); the summary fields are on stdout.

## Reading the result
- `verdict`: CONFIRMED_FAULT (a named problem, evidence in hand), PROBABLE_FAULT / FAULT (likely, not fully proven),
  DEGRADED, HEALTHY (every baseline check ran to completion and found nothing, within the scope in `healthy_scope`),
  INCONCLUSIVE (could not decide), ABORTED.
- `healthy_scope`: `checked` (what the baseline checks cleared), `not_checked` (scope limits of a HEALTHY verdict),
  `blocking` (why the run is not HEALTHY).
- `findings[]`: `category` (kind of problem, e.g. deadlock), `severity`, `status`, `description`, `subjects` (the concrete
  lock, thread, function, variable or `file:line` names), `evidence_ids`. A finding without subjects is not a diagnosis.
- `checks_run[]`: what was actually executed and its status.
- `not_covered[]`: what could not be examined and why (`kind`, `item`, `reason`): unreadable pid, missing debug image,
  unsupported target ABI or allocator, checks that failed or were inconclusive, checks the planner did not select,
  exhausted budget. This is part of the answer, not a footnote.
- `collection_impact`: `capture_mode`, `measured_stop_ms`, `zero_stop` (true means the process was never paused),
  `bytes_read`, `budget_exhausted`.
- `human_summary`: Markdown report with six numbered sections (conclusion, what is wrong, why, certainty and what was not examined, next steps, impact) and a glossary; identifiers are untouched.
- `report_path`: JSON report on disk; cite it so the user can open it.

## Follow-up by verdict
- CONFIRMED_FAULT: report it. Optionally add detail with the thread call-stack tool (deadlock) or the heap tools.
- PROBABLE_FAULT / FAULT / DEGRADED: say it is suspected, not proven. Narrow down with the tool for the finding's category:
  - deadlock / blocked threads: thread call stacks and locks.
[mcp]     `runtime_inspect_thread_callstack_and_locks(pid, companion_elf)`.
[cli]     `dynamic-state callstacks -p PID -d ELF --corpus DIR` (JSON: threads with frames, lock owners, wait-for cycles). Unstripped local program: `-d /proc/PID/exe`.
  - memory growth / leak: leak candidates, then owner lookup on example addresses to name the owning variable. Take two readings some time apart before calling growth a leak.
[mcp]     `runtime_heap_leak_candidates(pid, companion_elf)`, then `runtime_heap_owner_lookup(addresses, pid, companion_elf)`.
[cli]     `dynamic-state heap-leaks -p PID -d ELF --corpus DIR`, then `dynamic-state heap-owner -p PID -d ELF -a 0xADDR1,0xADDR2 --corpus DIR` (each prints JSON; `results[]` of `heap-owner` names the owning variable path).
  - who owns this buffer or address: owner lookup.
[mcp]     `runtime_heap_owner_lookup(addresses, pid, companion_elf)`.
[cli]     `dynamic-state heap-owner -p PID -d ELF -a 0xADDR --corpus DIR`.
  - a suspect variable: evaluate it with the names from `subjects`.
[mcp]     `runtime_eval_memory_path(pid, companion_elf, expressions)`.
[cli]     `dynamic-state eval --pid PID --debug-image ELF --expr "name1,name2" --corpus DIR`.
  - you need a variable name you do not have: find it in the debug info, do not guess.
[mcp]     `runtime_symbol_search(companion_elf, query, pid)`.
[cli]     There is no keyword symbol search on the command line; `dynamic-state fuzzy-resolve -p PID -d ELF -q "words describing it" --corpus DIR` resolves a described concept to DWARF symbols and live values.
- INCONCLUSIVE: read `not_covered` and act on the cause.
  - target_unreadable: ask the user to fix permissions (same user, or ptrace allowed) or confirm the PID.
  - missing_debug_image / no DWARF: ask for the debug ELF of the running build (remote: the matching unstripped ELF on this machine).
  - target_unreachable: SSH to the host failed (the reason is in `not_covered`); ask the user to check host, user, port, key and that the board is up. Do not retry with other credentials you were not given.
  - remote_limitation: things a remote diagnosis cannot examine (thread-local storage, stacks of threads that were running, symbols of libraries that could not be fetched). State them as not examined.
  - unsupported_on_target: say the feature is not supported there; do not substitute a guess.
  - no findings: if you passed a symptom, re-run the diagnosis once without `symptom` (general health check); then offer the narrower follow-ups above for the user's symptom.
- HEALTHY: say it is healthy within the checked scope, then name `healthy_scope.not_checked` (e.g. long waits whose expectedness was not judged, heap integrity above the walk cap, use-after-free). Nothing outside that scope is claimed.
- ABORTED: report why (`not_covered`, `summary`) and ask how to proceed.

## Explaining the result to the user
- Use the user's language. Start with the verdict in one sentence.
- Name the specifics from `subjects`: the variable, thread, lock and source line, and what they mean (for example "thread A holds lock X and waits for lock Y that thread B holds").
- State confidence honestly: confirmed, probable, or not decided.
- Always state what was NOT examined (from `not_covered`) and that the process was not stopped (or what stop was used).
- Offer the next step in one line.

## Hard rules
- Never say "no problem" / "healthy" when the verdict is INCONCLUSIVE or ABORTED. Say you could not tell, and why.
- Never present a finding without a named subject as confirmed.
- Zero-stop is the default and needs no approval. Anything that stops the process (stop-mode capture, `allow_stop`, CONSISTENT/GDB modes) and anything that changes the target (checkpoint, restore, transition, explore, replay, `--allow-mutation`, memory writes, signals) needs the user's explicit approval first. Ask, wait, then proceed.
- Do not guess on unsupported targets (non-glibc allocator, unsupported architecture, no debug info). Report the refusal.
- Do not invent symbols. Never assume a program has a particular global; take names from `subjects`, from the user, or from the debug info.
- Do not claim more than the evidence: the benchmark shows today's one-call diagnosis reliably names lock and thread for deadlocks; leaks, heap corruption, busy-wait and long stalls are usually INCONCLUSIVE and need the narrower follow-ups.

## Limits (state them when relevant)
- Linux, same-user (or ptrace-permitted) processes; x86_64 and aarch64 hosts.
- Heap tools support glibc ptmalloc only.
- The diagnosis also runs against a remote target over SSH (ARM64 / x86-64 glibc board, host-side analysis); every heap byte then crosses the link, so heap checks are capped and slower, and the remote gaps listed in `not_covered` apply. Key authentication only (no passwords).
