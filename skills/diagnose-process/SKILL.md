---
name: diagnose-process
description: Use when the user asks you to diagnose, health-check or find what is wrong with a running Linux process ("diagnose PID 1234", "why is this process hung / leaking memory / slow", "is this process healthy") and the dynamicstate MCP tools or the dynamic-state CLI are available. Calls runtime_diagnose_process once, reads the verdict, runs the narrower follow-up tool only when needed, and reports what was and was not examined. Do not use for offline core dumps or for processes you cannot read.
---

# Diagnose a live process with dynamicState

dynamicState reads a running process's memory and /proc without stopping it and resolves what it finds against DWARF
debug info. One call, `runtime_diagnose_process`, runs the whole diagnosis. This skill says how to use it and how to
report the result honestly.

## When to use
- The user names a PID (or a process you can resolve to one) and asks what is wrong, or whether it is healthy.
- Symptoms: hang, deadlock, stuck threads, high CPU, memory growth or leak, a buffer that "belongs" to someone.
- Not for: crashed processes (no live PID), offline snapshots only, or targets the tool does not support (see Limits).

## Required inputs
1. PID of the target. If missing, ask: "Which process (PID, or the name I should look up)?"
2. Debug ELF: the binary built with debug info (DWARF) that matches the running build. Default is the process's own
   executable, which works only if it is not stripped. If the process is stripped or the user ships a separate
   debug file, ask: "Where is the unstripped / debug build of this program (same build as the running process)?"
   Never guess a path.
3. Optional symptom in the user's words (for example "the process hangs"). Pass it as `symptom` only if the user
   gave one; do not invent one. Wording changes which checks run: a phrase such as "the service stopped
   responding" can yield INCONCLUSIVE on a real deadlock where the default general health check finds it.
4. Remote (embedded) target: if the process runs on a board / another host, ask: "Which host (name or IP), ssh user,
   port and key file should I use?" and never invent them. Then pass `remote_host`, `ssh_user`, `ssh_port`,
   `ssh_key` (a key FILE path on this machine; never a password or key contents) and, if the user agrees to copy the
   small collector to the board, `auto_deploy_collector=true` to the same `runtime_diagnose_process` call (CLI:
   `--host --user --port --identity [--auto-deploy-collector]`). The PID is the PID on the target. For a remote target
   the debug ELF is REQUIRED (the board's own executable is usually stripped): ask for the unstripped build of the
   running program on this machine. It is the host that analyses; nothing is stopped on the board.

## Workflow
1. Call `runtime_diagnose_process(pid, debug_image, symptom, language[, remote_host, ssh_user, ssh_port, ssh_key, auto_deploy_collector])` once; set `language` to `ko` when the user writes Korean, otherwise `en`. CLI equivalent: `dynamic-state diagnose -p PID [-d ELF] [--symptom TEXT] [--lang ko|en] --json`.
2. Read `human_summary` first (a ready-made plain-language report in the requested language), then `verdict`, `findings`, `not_covered`, `collection_impact` (see next section).
3. Follow up according to the verdict (see Follow-up). Do not re-run `diagnose` hoping for a different answer.
4. Relay `human_summary` to the user as written (do not re-summarize away its names, source locations, what was not examined or the measured impact), then add only what a follow-up tool contributed. If you must explain in your own words, use the user's language.

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
- CONFIRMED_FAULT: report it. Optionally run `runtime_inspect_thread_callstack_and_locks` (deadlock) or the heap tools to add detail.
- PROBABLE_FAULT / FAULT / DEGRADED: say it is suspected, not proven. Narrow down with the tool for the finding's category:
  - deadlock / blocked threads: `runtime_inspect_thread_callstack_and_locks`.
  - memory growth / leak: `runtime_heap_leak_candidates`, then `runtime_heap_owner_lookup` on example addresses to name the owning variable. Take two readings some time apart before calling growth a leak.
  - who owns this buffer or address: `runtime_heap_owner_lookup`.
  - a suspect variable: `runtime_eval_memory_path` with the names from `subjects`.
- INCONCLUSIVE: read `not_covered` and act on the cause.
  - target_unreadable: ask the user to fix permissions (same user, or ptrace allowed) or confirm the PID.
  - missing_debug_image / no DWARF: ask for the debug ELF of the running build (remote: the matching unstripped ELF on this machine).
  - target_unreachable: SSH to the host failed (the reason is in `not_covered`); ask the user to check host, user, port, key and that the board is up. Do not retry with other credentials you were not given.
  - remote_limitation: things a remote diagnosis cannot examine (thread-local storage, stacks of threads that were running, symbols of libraries that could not be fetched). State them as not examined.
  - unsupported_on_target: say the feature is not supported there; do not substitute a guess.
  - no findings: if you passed a symptom, re-run `diagnose` once without `symptom` (general health check); then offer the narrower tools above for the user's symptom.
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
- Do not invent symbols. Never assume a program has a particular global; take names from `subjects`, from the user, or from symbol search.
- Do not claim more than the evidence: the benchmark shows today's one-call diagnosis reliably names lock and thread for deadlocks; leaks, heap corruption, busy-wait and long stalls are usually INCONCLUSIVE and need the narrower tools.

## Limits (state them when relevant)
- Linux, same-user (or ptrace-permitted) processes; x86_64 and aarch64 hosts.
- Heap tools support glibc ptmalloc only.
- `diagnose` also runs against a remote target over SSH (ARM64 / x86-64 glibc board, host-side analysis); every heap byte then crosses the link, so heap checks are capped and slower, and the remote gaps listed in `not_covered` apply. Key authentication only (no passwords).
