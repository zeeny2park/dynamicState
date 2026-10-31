# dynamicState — Skill Specification: Process Health Investigation

**Document Version:** 2.0.0  
**Phase:** 2.0 (Adaptive Investigation: Process Health Investigation)  
**Layer:** Skill (Procedural Workflow & Decision Policy)  
**Companion Knowledge Spec:** `docs/PROCESS_HEALTH_INVESTIGATION_KNOWLEDGE.md`  
**Target Repository:** `zeeny2park/dynamicState`

---

## 1. Purpose & Separation of Concerns

This document defines the **Process Health Investigation Skill**—the procedural workflow and deterministic decision policy for answering vague or open-ended process health inquiries such as:

> *"이 프로세스에 문제가 있는지 검사해주세요."*  
> *"Check whether this process has a problem."*

### Architectural Layer Separation
- **Skill (`docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md`)**: Defines *how* to conduct a bounded, evidence-grounded investigation—entry conditions, triage sequence, competing hypothesis generation, discriminating follow-up selection, budget enforcement, stopping rules, and verdict calibration.
- **Knowledge (`docs/PROCESS_HEALTH_INVESTIGATION_KNOWLEDGE.md`)**: Defines *tool semantics*—parameters, preconditions, output contracts, error codes, provenance classes, and safety limits.
- **MCP (`scripts/mcp_server.py`)**: Provides the *capability interface*—reusing existing registered read-only MCP tools without duplicating orchestration or inventing ad-hoc actions.

---

## 2. Entry Conditions & Required Target Inputs

### 2.1 Entry Triggers
- Vague or broad health check requests (`"이 프로세스에 문제가 있는지 검사해주세요"`, `"프로세스 상태가 정상인지 확인해줘"`, `"check process health"`).
- Symptom-oriented requests without predetermined root-cause symbols (`"응답이 느려요"`, `"메모리가 늘어나는 것 같아요"`, `"스레드가 멈춘 것 같아요"`).

### 2.2 Required Target Inputs
At least one of the following target references must be provided or resolved via active context:
1. **Live Local or Remote Process**: `pid` (or `process_name`) + optional `companion_elf_path` / `debug_image` (with optional SSH transport parameters `remote_host`, `ssh_user`, `ssh_port`).
2. **Offline Snapshot**: `snapshot_id` or `memory_snapshot_path` + optional `debug_image`.

### 2.3 Safety Preconditions
- **Strictly Read-Only**: Zero target memory writes, zero register modifications, zero signal injection, and zero arbitrary shell command execution.
- **Zero-Stop Default (`0.00ms`)**: Live observations must use non-intrusive reads (`process_vm_readv` or `/proc/<pid>/mem`) with `target_stop_duration_ms == 0.0` unless stopped capture is explicitly authorized.

---

## 3. Single Investigation State Machine

Every Process Health Investigation executes through a single persisted, auditable state machine (`InvestigationStateMachine`):

```text
CREATED
  │
  ▼
TARGET_VALIDATION
  │
  ▼
INITIAL_TRIAGE
  │
  ▼
HYPOTHESIS_FORMATION
  │
  ▼
FOLLOW_UP_PLANNING ◄──────────────┐
  │                               │
  ▼                               │
OBSERVATION                       │ (Additional discriminating
  │                               │  observation needed & within budget)
  ▼                               │
HYPOTHESIS_UPDATE ────────────────┘
  │
  ▼ (Stopping policy triggered)
FINALIZATION
  │
  ▼
COMPLETED | INCONCLUSIVE | BUDGET_EXHAUSTED | FAILED | CANCELED
```

### State Machine Invariants
1. Every transition records `from_state`, `to_state`, non-empty `reason`, and ISO-8601 `timestamp`.
2. Invalid transitions (e.g., `CREATED -> COMPLETED` or `INITIAL_TRIAGE -> OBSERVATION`) are rejected with `ValueError`.
3. A failed, unavailable, or budget-rejected observation sets `status = "failed"` and `executed = False`—it never becomes a successful observation.
4. Resume or replay restores `executed_observation_keys` (`observation_id` and `semantic_key`) so equivalent observations within the same runtime epoch are never silently duplicated.

---

## 4. Initial Process Health Triage Sequence

For a generic process-health request, **never assume or hardcode application-specific symbols** (such as `*gpMem`, `g_corrupt_record`, or `g_ipc_ring`).

### Step 1: Target & Build Identity (`TARGET_VALIDATION`)
- Verify process liveness (`check_liveness`) or snapshot integrity.
- Inspect ELF / DWARF availability (`inspect_elf`, GNU Build-ID, `has_dwarf_info`).
- Probe observation capabilities (`memory_maps_available`, `threads_available`, `dwarf_symbols_available`, `memory_read_available`, `watch_history_available`).
- If a capability is unavailable, record `UNKNOWN` / `UNAVAILABLE` with the exact reason. Never treat missing debug symbols or missing application globals as evidence of a defect.

### Step 2: Low-Impact Read-Only Triage (`INITIAL_TRIAGE`)
Execute only capabilities supported by the target, ordered by low impact and high coverage:
1. **Memory Maps & Module Inventory**: Inspect mapped segments (`[heap]`, `[stack]`, `.data`/`.bss`, shared memory) without blind byte scanning.
2. **Thread Inventory & Callstack/Lock Triage**: Enumerate thread states and callstacks (`runtime_inspect_thread_callstack_and_locks`) to detect blocked waiters, mutex contention, or circular waits.
3. **DWARF Global Root Discovery**: Discover actual globals present in the target ELF (`runtime_watch_inspect_target` / `runtime_symbol_search`) and sample a bounded set of top-level scalar/struct health indicators (`runtime_eval_memory_path`).
4. **Watch-Session History**: Check existing runtime watch sessions (`runtime_watch_session_list`) for prior observations or deltas.

Rank candidate anomaly areas (`suspicious_threads`, `memory_growth_candidates`, `pointer_anomalies`, `queue_backlogs`) strictly from observed triage evidence.

---

## 5. Competing Hypothesis Formation Guidance

Reuse `extractor/hypothesis.py` (`InvestigationHypothesis`, `DeterministicHypothesisGenerator`). Whenever initial triage identifies a candidate anomaly, formulate **at least two competing explanations** linked via `competing_hypothesis_ids`:

| Candidate Anomaly Area | Defect Hypothesis ($H_1$) | Competing Benign / Alternative Hypothesis ($H_2$) | Required Discriminating Evidence |
| :--- | :--- | :--- | :--- |
| **Suspicious / Blocked Thread** | Thread stalled due to lock contention, deadlock, or unreleasing mutex owner | Thread parked normally in idle condition wait / work-queue poll | Lock owner identity, owner thread state/progress, and stack frame locals |
| **Elevated Memory / Pool Usage** | Memory or slot leak (orphaned allocations not reclaimed after task completion) | Expected active workload buffering or single-snapshot steady cache | Multi-sample temporal diff ($\ge 2$ samples) AND thread/symbol ownership scan |
| **Invalid / Null Pointer or Struct Field** | Stale object lifetime (dangling pointer) or memory corruption | Concurrent unstopped read skew or benign uninitialized optional field | Optimistic Seqlock double-read consistency check and surrounding struct state |
| **Queue / Ring Backlog** | Consumer stall (consumer blocked or failing to advance read index) | Transient ingress burst (consumer actively draining items) | Temporal delta on consumer read index / processed counter and consumer thread state |

### Hypothesis Rules
- **Never fabricate facts**: An inference or hypothesis (`NATURE_INFERENCE`, `NATURE_HYPOTHESIS`) is never recorded as an `OBSERVED_FACT` (`NATURE_OBSERVATION`).
- **No self-support**: A hypothesis record is never counted as supporting evidence for itself.
- **Independence**: Correlated copies or repeated identical observations (`same semantic_digest`) count as a single piece of evidence.
- **Failure neutrality**: Failed, timed-out, restricted, or budget-rejected reads (`ABSTAIN`) never support or refute any hypothesis.
- **Contradiction preservation**: Both `supporting_evidence_ids` and `contradicting_evidence_ids` are retained on the hypothesis.

---

## 6. Discriminating Follow-Up Selection Rules

The `AdaptiveInvestigationPlanner` selects one follow-up observation per iteration using deterministic ranking:
1. **Eligibility Filter**: Must be `READ_ONLY` / `LOW_IMPACT`, unexecuted in the current runtime epoch, have all `prerequisites` satisfied, and pass `ObservationBudgetTracker.check_pre_execution(...)`.
2. **Deterministic Ranking Key**:
   - `can_materially_change_ranking` (descending): Prioritizes observations with opposite expected outcomes across competing hypotheses.
   - `discriminating_count` (descending): Number of unresolved competing hypotheses distinguished.
   - `estimated_bytes` (ascending): **Prefers the cheapest observation that can materially change the hypothesis ranking.**
   - `info_gain_score` (descending).
   - `estimated_latency_ms` (ascending).
   - `observation_id` (ascending lexicographical tie-breaker).
3. **Mandatory Plan Explanation**: Every selected observation records `tested_hypothesis_ids`, `why_needed`, `expected_outcomes_by_hypothesis`, `required_capture_quality`, `estimated_bytes`, `estimated_latency_ms`, `risk_level`, `prerequisites`, and `preference_rationale` (why it was chosen over alternatives).

---

## 7. Budget Policy

All triage and follow-up observations are governed by `ObservationBudgetTracker`:
- **Dimensions Enforced**:
  - Global `max_wall_clock_ms`, `max_bytes_read`, `max_samples`, `max_consecutive_read_failures`, `max_total_read_failures`, `min_poll_interval_ms`, `max_bytes_per_observation`, and optional `max_target_stop_ms`.
  - Per-profile `budget_ceiling` (`max_bytes_read`, `max_wall_clock_ms`, `max_samples`, `max_target_stop_ms`).
- **Pre-Execution Gate**: No operation starts if its conservative estimated cost exceeds the remaining global or profile budget (`RESULT_BUDGET_REJECTED`).
- **Honest Byte Accounting**: Unknown byte cost is never treated as zero (a conservative estimate is charged against budget ceilings), and `measured_bytes_read` is never silently fabricated with a default like `4096`.
- **Progress Categorization**: Every observation execution is classified into `NEW_EVIDENCE`, `DUPLICATE_EVIDENCE`, `NO_NEW_EVIDENCE`, `PARTIAL_EVIDENCE`, `OBSERVATION_FAILED`, `OBSERVATION_UNAVAILABLE`, or `BUDGET_REJECTED`.

---

## 8. Stopping Conditions & Verdict Integrity

### 8.1 Explicit Stopping Reasons
- `SUFFICIENT_EVIDENCE`: Primary hypothesis is supported and competing explanations are refuted within required provenance/temporal bounds (does not require an artificial 100% confidence score).
- `ALL_HYPOTHESES_REFUTED`: All candidate defect hypotheses are contradicted by direct evidence.
- `NO_USEFUL_SAFE_OBSERVATION_REMAINS`: Unresolved hypotheses remain, but no safe read-only discriminating observation is available.
- `DIMINISHING_INFORMATION_GAIN`: Consecutive observations yield `DUPLICATE_EVIDENCE` or `NO_NEW_EVIDENCE`.
- `BUDGET_EXHAUSTED`: Global or per-profile budget ceiling reached; partial findings are preserved.
- `REPEATED_OBSERVATION_FAILURE`: Consecutive read failures reach `max_consecutive_read_failures`.
- `CAPABILITY_UNAVAILABLE`: Required target capabilities or permissions are unavailable.
- `USER_CANCELED`: Explicit cancellation requested.

### 8.2 Verdict Semantics
- `NO_ISSUE_DETECTED_WITHIN_SCOPE`: Triage and follow-ups succeeded with trusted provenance and found no actionable anomaly **within the inspected scope** (never claims universal health across uninspected domains).
- `SUSPECTED`: Anomaly evidence exists, but competing explanations remain open, provenance is unverified/partial, attribution is call-stack-only, or memory growth has only a single temporal sample.
- `PARTIALLY_CONFIRMED`: Primary defect hypothesis is supported by multiple observations, with secondary questions or partial scope remaining.
- `CONFIRMED`: Defect hypothesis is supported by independent trusted evidence and competing benign explanations are refuted (and for memory leaks, $\ge 2$ temporal samples + orphan verification).
- `REFUTED`: Tested defect hypothesis is contradicted by direct observational evidence.
- `INCONCLUSIVE`: Required observations failed, were restricted (`EPERM`), or lacked sufficient evidence to support or refute.

---

## 9. Example Walkthroughs for Vague Requests

### Example A: Vague Request on a Healthy Process
- **User Prompt**: *"이 프로세스에 문제가 있는지 검사해주세요."*
- **Execution**:
  1. `TARGET_VALIDATION`: Confirms PID is alive, ELF Build-ID matches, DWARF available, `LIVE_RUNTIME_CAPTURE`.
  2. `INITIAL_TRIAGE`: Runs `insp_locks` and bounded DWARF root check. All threads are in normal event-loop wait or active with zero lock contention; discovered error/drop counters are `0`.
  3. `HYPOTHESIS_FORMATION`: Zero defect hypotheses triggered.
  4. `FINALIZATION -> COMPLETED`: Stops with `SUFFICIENT_EVIDENCE`.
- **Verdict**: `NO_ISSUE_DETECTED_WITHIN_SCOPE` (explicitly listing inspected threads/symbols and uninspected domains such as full heap scan).

### Example B: Vague Request on a Process with a Blocked Worker Thread
- **User Prompt**: *"이 프로세스에 문제가 있는지 검사해주세요."*
- **Execution**:
  1. `INITIAL_TRIAGE`: `insp_locks` observes Thread 104 blocked on mutex `0x7f0010` in `process_packet()`.
  2. `HYPOTHESIS_FORMATION`: Generates competing pair:
     - $H_1$: Thread 104 stalled on contended lock / unreleasing owner.
     - $H_2$: Thread 104 parked in normal idle wait.
  3. `FOLLOW_UP_PLANNING`: Selects `obs_disc_thread` (`insp_frame_locals`, est. 2048 B, 0.0ms stop) over heavier heap/pool scans.
  4. `OBSERVATION & HYPOTHESIS_UPDATE`: Frame locals show lock owner TID 102 is deadlocked waiting on `0x7f0020` with zero progress delta (`NEW_EVIDENCE`). $H_1 \to \text{SUPPORTED}$, $H_2 \to \text{CONTRADICTED}$.
  5. `FINALIZATION -> COMPLETED`: Stops with `SUFFICIENT_EVIDENCE`.
- **Verdict**: `CONFIRMED` (or `SUSPECTED` if owner state was only partially observable).

### Example C: Restricted Process / Read Failure
- **User Prompt**: *"이 프로세스에 문제가 있는지 검사해주세요."*
- **Execution**:
  1. `TARGET_VALIDATION`: Process is alive, but `/proc/<pid>/mem` and `process_vm_readv` return `EPERM` (`RESTRICTED`).
  2. `INITIAL_TRIAGE`: Observation returns `RESULT_OBSERVATION_UNAVAILABLE` (`COLLECTION_STATUS_ABSTAIN`).
  3. `FINALIZATION -> INCONCLUSIVE`: Stops with `CAPABILITY_UNAVAILABLE`.
- **Verdict**: `INCONCLUSIVE` (never `NO_ISSUE_DETECTED_WITHIN_SCOPE` or `PASS`), with recommended action to check `yama.ptrace_scope` or process user permissions.
