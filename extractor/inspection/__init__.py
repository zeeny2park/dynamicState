"""Live-process inspection functions behind ``WatchSessionManager`` (moved out of extractor/watch_session.py).

Each module holds plain functions that take the manager first (``mgr``) and use its adapter / DWARF /
target-context helpers; ``extractor.watch_session.WatchSessionManager`` binds them as methods, so the MCP server,
the web server, the CLI, the evidence provider and the thread sampler keep calling ``manager.<method>(...)``.

    process_memory  zero-stop memory reads (process_vm_readv, /proc/<pid>/mem) and scalar decoding
    process_maps    memory maps, ELF load bias (main image, shared libraries), memory-map/thread overview
    threads         thread/lock inspection, CFI call stacks (IMP-011), exact source lines, frame locals
    tls             thread-pointer/TCB discovery, TLS variables, concurrent-read consistency
    expressions     symbol-path expressions: tokenize, coerce, resolve, typed decoding, self-repair hints
    baselines       capture-and-diff, golden baselines, scenario recipe runner
    pools           pool/array scanner, owner/thread lookup, x-ray blueprint, linked structures
    memory          memory integrity audit, code pointers, heap object scan
    ipc             shared memory / IPC pipelines, DPDK lcores and rings
    triage          auto-triage, symptom investigator, dependency graph, source correlation
    profiler        statistical hotspots, fuzzy symbol intent
    recorder        watch-until-condition, flight recorder, behavioural drift
    context         target-context binding and resolution
    batch           runtime questions, token budget, smart compact query, batch macro
    hypothesis      hypothesis assertions, incident report export

No module here generates a process verdict: scans that report one take it from diagnostic_verdict_aggregator
(IMP-017); the one diagnosis entry point is expert_diagnostic_engine.diagnose().
"""
