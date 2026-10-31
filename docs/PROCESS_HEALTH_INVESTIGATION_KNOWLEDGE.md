# dynamicState — Knowledge & MCP Interface Reference: Process Health Investigation

**Document Version:** 2.0.0  
**Phase:** 2.0 (Adaptive Investigation: Process Health Investigation)  
**Layer:** Knowledge (Tool Semantics, Preconditions, Outputs, Errors & Safety Limits) + MCP Capability Mapping  
**Companion Skill Spec:** `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md`  
**Target Repository:** `zeeny2park/dynamicState`

---

## 1. Overview

This document specifies the **Knowledge Layer** and **MCP Capability Mapping** used by the Process Health Investigation Skill (`docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md`). No new MCP tools or ARP actions are introduced; the investigation orchestrates existing read-only capabilities under strict budget and provenance invariants.

---

## 2. Reused Read-Only MCP Tools & Semantics

| MCP Tool Name | Domain | Preconditions | Measured Outputs | Error / Abstain Conditions | Safety & Budget Profile |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `runtime_target_connect` | `GENERIC` | Target `pid` or `process_name` reachable locally or via `xssh` | `pid`, `companion_elf_path`, `build_id`, `has_dwarf_info`, recommended root symbols | `ESRCH` (process not found), `SSH_ERROR` | `READ_ONLY`, `0.00ms` stop, est. `1024 B` |
| `runtime_watch_inspect_target` | `GENERIC` | Valid ELF path with DWARF debug info | Global variables, struct layouts, static root addresses | `NO_DWARF_INFO`, `FILE_NOT_FOUND` | `READ_ONLY`, offline ELF parse (`0 B` target read) |
| `runtime_inspect_thread_callstack_and_locks` | `CONCURRENCY` | `threads_available` (`/proc/<pid>/task` readable) | Thread list, states (`R`/`S`/`D`), unwound callstacks, contended mutexes, deadlock cycles | `RESTRICTED` (`EPERM`), `TARGET_TERMINATED` | `READ_ONLY`, `0.00ms` stop, est. `4096 B`, ceiling `64 KB` |
| `runtime_inspect_thread_locals_and_frame_vars` | `CONCURRENCY` | `threads_available` + `dwarf_symbols_available` | Decoded stack frame local variables and parameters per thread | `RESTRICTED`, `UNWIND_INCOMPLETE` | `READ_ONLY`, `0.00ms` stop, est. `2048 B`, ceiling `32 KB` |
| `runtime_eval_memory_path` | `GENERIC` / `FIELD` | `memory_read_available` + valid symbol expression | Per-expression `status` (`OBSERVED`, `READ_ERROR`, `RESTRICTED`, `NULL_POINTER`), decoded `value`, `runtime_address` | `SYMBOL_NOT_FOUND`, `READ_ERROR`, `PERMISSION_DENIED` | `READ_ONLY`, `0.00ms` stop, `64 B`–`4096 B` per batch |
| `runtime_capture_and_diff` | `TEMPORAL` | `memory_read_available` + explicit `expressions` | Two-sample temporal delta (`changed_fields`, `unchanged_fields`, `wait_ms`) | `READ_ERROR`, `TARGET_TERMINATED` | `READ_ONLY`, `0.00ms` stop, advances runtime epoch |
| `runtime_verify_concurrent_read_consistency` | `INTEGRITY` | `memory_read_available` + explicit `target_expression` | Seqlock double-read comparison (`is_consistent`, `skew_detected`, `read_a`, `read_b`) | `READ_ERROR`, `UNAVAILABLE` | `READ_ONLY`, `0.00ms` stop, est. `512 B`, ceiling `8 KB` |
| `runtime_scan_memory_pool` | `MEMORY` | `memory_read_available` + **discovered/explicit** `target_expression` | `total_slots`, `active_slots`, `leak_count`, `allocation_bitmap` | `PREREQUISITE_UNAVAILABLE` if no pool symbol exists | `READ_ONLY`, `0.00ms` stop, est. `8192 B`, ceiling `128 KB` |
| `runtime_find_symbol_owners` | `CONCURRENCY` | `memory_read_available` + `threads_available` + **explicit** `target_expression` | `matched_threads` referencing target slot/object address | `PREREQUISITE_UNAVAILABLE` if no target expression | `READ_ONLY`, `0.00ms` stop, est. `4096 B`, ceiling `64 KB` |
| `runtime_audit_memory_integrity` | `INTEGRITY` | `memory_read_available` + **discovered/explicit** `root_expression` | `corrupted_pointers`, vtable/enum/bool out-of-bounds anomalies | `PREREQUISITE_UNAVAILABLE` if no root expression | `READ_ONLY`, `0.00ms` stop, est. `4096 B`, ceiling `64 KB` |
| `runtime_trace_ipc_pipeline` | `IPC` | `memory_read_available` + **discovered/explicit** `pipeline_expression` | Producer/consumer indices, queue depth, stall detection | `PREREQUISITE_UNAVAILABLE` if no ring/queue symbol | `READ_ONLY`, `0.00ms` stop, est. `1024 B`, ceiling `16 KB` |
| `runtime_start_investigation` / `runtime_get_investigation_report` | `STATEFUL` | Snapshot or authorized live target | Full `InvestigationSession` report, `evidence_ledger`, `competing_hypotheses`, `report_html` | `BLOCKED` (if live capture unauthorized), `FAILED` | Enforces session budgets and provenance trust boundaries |

---

## 3. Observation Result Categories & Error Semantics

Every observation step executed by `AdaptiveInvestigationEngine` or `InvestigationManager` produces one of seven canonical result categories:

| Result Category | Meaning | Impact on Evidence Ledger | Impact on Hypotheses |
| :--- | :--- | :--- | :--- |
| `NEW_EVIDENCE` | Observation succeeded (`COLLECTED`) and produced novel semantic content | Appended to `EvidenceLedger` with `semantic_digest` | Evaluates supporting/contradicting outcomes |
| `DUPLICATE_EVIDENCE` | Observation succeeded, but `semantic_digest` matches an existing record in the same epoch | Not re-appended; references existing `evidence_id` | Zero change to evidence count or confidence |
| `NO_NEW_EVIDENCE` | Tool call succeeded (`success=True`), but returned empty/unchanged baseline state | Recorded as diagnostic trace; increments diminishing-returns counter | Does not promote defect hypotheses |
| `PARTIAL_EVIDENCE` | Partial read (`COLLECTION_STATUS_PARTIAL`); some fields/threads succeeded, others failed | Appended with `completeness="PARTIAL"` | Caps confidence at `MEDIUM` ($\le 0.55$) and blocks `CONFIRMED` |
| `OBSERVATION_FAILED` | Read error, timeout, or runtime exception (`READ_ERROR`, `TIMEOUT`) | Recorded with `collection_status="ABSTAIN"` | Never supports or refutes any hypothesis; `obs.executed` remains `False` |
| `OBSERVATION_UNAVAILABLE` | Missing symbol, stripped binary without DWARF, or permission restriction (`EPERM`) | Recorded with `collection_status="ABSTAIN"` and unavailability reason | Recorded under `uninspected_scope` and `unknowns`; never treated as a defect |
| `BUDGET_REJECTED` | Pre-execution conservative cost estimate exceeded remaining global or profile ceiling | Recorded in `ObservationBudgetTracker` rejection log | Prevents execution; triggers `BUDGET_EXHAUSTED` stop if no cheaper observation remains |

---

## 4. Provenance Classes & Trust Ceilings

| Provenance Class | Source Description | Maximum Allowed Diagnosis |
| :--- | :--- | :--- |
| `LIVE_RUNTIME_CAPTURE` | Direct read from a verified live process via `LocalTargetAdapter` or `RemoteSshTargetAdapter` | `CONFIRMED` / `NO_ISSUE_DETECTED_WITHIN_SCOPE` (when completeness and consistency gates pass) |
| `CONTROLLED_RUNTIME_REPRODUCTION` | Verified single-writer or deterministic reproduction run with authentic session receipt | `CONFIRMED` / `VALIDATED` |
| `SYNTHETIC_FIXTURE` | Deterministic test fixture or simulated state | Capped at `SUSPECTED` (for defects) or `INCONCLUSIVE` |
| `IMPORTED_UNVERIFIED` | External/offline snapshot or caller-submitted payload without live capture verification | Strictly capped at `SUSPECTED` or `INCONCLUSIVE`; never upgraded to `LIVE_RUNTIME_CAPTURE` |

---

## 5. Safety & Operational Limits

1. **No Target Mutation**: Inspection modules execute through `InspectionContext.enforce_read_only()`, which forbids memory writes, ptrace register writes, or state restoration during health triage.
2. **Protected Filesystem Paths**: Report exporters (`sanitize_report_output_path`) resolve symlinks via `os.path.realpath` and block writes to `/etc/`, `/proc/`, `/sys/`, `/dev/`, `/boot/`, `/bin/`, `/sbin/`, `/usr/`, `/lib/`, and `/lib64/`.
3. **Disaggregated Telemetry**: `target_stop_duration_ms` (process suspension time) is measured and reported separately from `observation_latency_us` (host-side DWARF decode and read latency).
