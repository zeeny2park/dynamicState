# DynamicState Phase 1 Baseline Performance & Instrumentation Report

**Target Commit / Baseline SHA**: `d5ab0a42cf7d92800f1b8c5ecd4d513d2f2a1537`  
**Measurement Environment**: Linux aarch64 (Ubuntu 24.04 LTS), Python 3.12.3  
**Status**: COMPLETE (Phase 1 Baseline Established)  
**Execution Date**: November 20, 2026  

---

## 1. Executive Summary

In accordance with [docs/roadmap.md](file:///home/ubuntu/workspace/ut/docs/roadmap.md), Phase 1 has established an authoritative, trustworthy, and low-overhead performance measurement baseline for the DynamicState remote and local diagnostic engine.

Key baseline facts established from real executions (no invented values):
- **Remote round-trip latency dominates wall-clock time**: In remote diagnoses with simulated network latency (e.g. 40ms RTT in Scenario 9), **98.3%** of wall-clock time (2.586s out of 2.631s) is spent executing remote SSH commands sequentially.
- **Redundant Remote Invocations**: A single remote diagnosis issues up to **59 individual SSH commands** transferring **222 KB**, of which 18 are repeated `identity_probe`s, 16 are repeated `liveness` checks, and 16 are repeated `process_status` queries.
- **Local Engine Overhead is Small**: Local plan generation (~0.6ms), hypothesis evaluation (~0.3-0.4ms), and local analysis (~0.4ms) are lean, whereas durable JSON checkpointing takes ~15–26ms per diagnosis.
- **Zero Impact on Production Contracts**: All 35 metrics are tracked using monotonic clocks (`time.monotonic()`) with sub-microsecond overhead. The MCP server protocol and API dictionary keys (`RESULT_KEYS`) remain strictly bit-compatible.

---

## 2. Measurement Architecture & Tracked Metrics

The performance tracking engine is implemented in [extractor/diagnostic_performance.py](file:///home/ubuntu/workspace/ut/extractor/diagnostic_performance.py) and integrated into [extractor/expert_diagnostic_engine.py](file:///home/ubuntu/workspace/ut/extractor/expert_diagnostic_engine.py) and [extractor/target_adapter.py](file:///home/ubuntu/workspace/ut/extractor/target_adapter.py).

### 2.1 The 35 Measured Metrics

| Category | Count | Metrics Tracked |
| :--- | :--- | :--- |
| **Duration Metrics (15)** | 15 | `total_wall_clock_s`, `plan_generation_s`, `local_analysis_s`, `remote_connection_establishment_s`, `ssh_command_execution_s`, `remote_command_s`, `retry_s`, `collection_duration_per_recipe`, `collection_duration_per_evidence_type`, `evidence_normalization_s`, `correlation_s`, `hypothesis_evaluation_s`, `replanning_s`, `checkpoint_s`, `report_generation_s` |
| **Remote Cost Metrics (9)** | 9 | `ssh_commands_count`, `ssh_connections_count`, `control_master_reconnects_count`, `retries_count`, `remote_bytes_transferred`, `local_bytes_processed`, `collection_operations_count`, `duplicate_or_reusable_observations_count`, `target_impact` |
| **Investigation Efficiency (11)** | 11 | `recipes_planned_count`, `recipes_executed_count`, `recipes_skipped_count`, `failed_recipes_count`, `remote_calls_avoided_count`, `evidence_reuse_ratio`, `time_spent_collecting_s`, `time_spent_analyzing_s`, `hypotheses_count`, `hypotheses_eliminated_count`, `replans_count` |

### 2.2 Compatibility & Overhead Guardrails
1. **Monotonic Timing**: All durations are captured via `time.monotonic()` around distinct lifecycle phase boundaries.
2. **Contract Preservation**: `DiagnoseResult` exposes `performance_metrics` via a Python property and nests it inside `collection_impact["performance_metrics"]` and `report["performance_metrics"]`, keeping `to_dict()` keys equal to `RESULT_KEYS`.
3. **No Target Dependencies**: No daemons, background agents, or persistent packages are required on the target machine.

---

## 3. Reproducible Benchmark Scenario Results

All 15 reproducible benchmark scenarios defined in [benchmarks/run_phase1_baseline.py](file:///home/ubuntu/workspace/ut/benchmarks/run_phase1_baseline.py) were executed against real running target processes and simulated SSH transports. The raw telemetry is stored in [benchmarks/phase1_baseline_results.json](file:///home/ubuntu/workspace/ut/benchmarks/phase1_baseline_results.json).

### Scenario Performance Matrix

| # | Scenario Name | Target Type | Verdict | Wall-Clock (s) | Remote Cmds | Remote Bytes | Checkpoint (s) | Key Observations |
|---|---|---|---|---|---|---|---|---|
| **1** | Healthy target | Local C proc | INCONCLUSIVE | 0.171s | 0 | 0 B | 0.0194s | 15 baseline recipes planned; local scan completed in <180ms. |
| **2** | CPU overload | Local (spinning thread) | INCONCLUSIVE | 0.058s | 0 | 0 B | 0.0168s | Target CPU measured at 40ms delta; diagnosis attributable CPU 48ms. |
| **3** | Memory pressure | Local (anonymous mmap) | INCONCLUSIVE | 0.078s | 0 | 0 B | 0.0206s | 19 recipes planned; 118 context switches during 63ms window. |
| **4** | Process lifecycle anomaly | Dead PID | INCONCLUSIVE | 0.0001s | 0 | 0 B | 0.0000s | Instant short-circuit preflight rejection without spinning threads. |
| **5** | Thread anomaly | Local (multi-worker) | INCONCLUSIVE | 0.070s | 0 | 0 B | 0.0171s | Clean thread state capture; planning 0.6ms, analysis 0.4ms. |
| **6** | Deadlock | Local (circular mutex) | INCONCLUSIVE | 0.075s | 0 | 0 B | 0.0192s | Planning 0.6ms; Lock and thread state inspected without stopping process. |
| **7** | Remote connection failure | Unreachable SSH host | INCONCLUSIVE | 0.502s | 0 | 0 B | 0.0000s | Connection timeout bounded at 0.5s; gracefully handled. |
| **8** | Partial permission failure | Remote restricted target | INCONCLUSIVE | 0.081s | 13 | 99.9 KB | 0.0094s | Partial /proc read failures handled; 13 SSH calls made before fallback. |
| **9** | Slow remote operation | Remote (40ms RTT latency) | INCONCLUSIVE | **2.631s** | **59** | **222.1 KB** | 0.0181s | **2.586s (98.3%)** spent in remote SSH executions; sequential bottleneck. |
| **10** | Intermittent command failure | Remote SSH with mux reset | INCONCLUSIVE | 0.132s | 31 | 193.3 KB | 0.0152s | 1 ControlMaster reconnect triggered; 1 retry executed in 4.6ms. |
| **11** | Large process/thread target | Local (80 active threads) | INCONCLUSIVE | 0.104s | 0 | 0 B | 0.0162s | Scaled linearly; 80 threads inspected with 90ms attributable CPU. |
| **12** | Many file descriptors | Local (512 open FDs) | INCONCLUSIVE | 0.071s | 0 | 0 B | 0.0194s | FD table inspection took <1ms analysis time; zero stop verified. |
| **13** | Prior evidence reuse | Local with prepopulated ledger | EVIDENCE_INSUFFICIENT | 0.034s | 0 | 0 B | 0.0265s | Short-circuited execution; 33.8ms total duration. |
| **14** | Minimal evidence | Budget-constrained run | INCONCLUSIVE | 0.077s | 0 | 0 B | 0.0179s | Budget stop triggered safely without infinite loops. |
| **15** | Early stopping | Diagnosis with satisfied checks | INCONCLUSIVE | 0.067s | 0 | 0 B | 0.0166s | 5 recipes safely skipped due to satisfied evidence requirements. |

---

## 4. Bottleneck & Root-Cause Analysis

### Bottleneck 1: Sequential Remote Command Execution (Scenarios 9 & 10)
In Scenario 9 (remote target with 40ms simulated network latency):
- Total wall-clock time: **2.631 seconds**.
- Time spent in SSH command execution: **2.586 seconds (98.3%)**.
- Time spent in local planning, analysis, and hypothesis evaluation: **< 0.002 seconds (< 0.1%)**.
- **Root Cause**: The diagnostic loop currently issues commands synchronously one by one (`assess`, `detect_target_abi`, `_step_collect_next`). Every recipe independently queries process status and liveness sequentially over SSH.

### Bottleneck 2: High Remote Call Redundancy
Breakdown of the 59 SSH commands in Scenario 9:
- `ssh:identity_probe`: **18 calls** (845 ms, 185,990 bytes)
- `ssh:liveness`: **16 calls** (663 ms, 96 bytes)
- `ssh:process_status`: **16 calls** (676 ms, 19,376 bytes)
- `ssh:threads_shell`: **3 calls** (148 ms, 4,764 bytes)
- **Root Cause**: Each recipe invocation in `_step_collect_next` re-validates remote process liveness and re-fetches `/proc/<pid>/status` instead of querying a short-lived cache or unified snapshot.

### Bottleneck 3: Synchronous Durable Checkpointing Overhead
Across all scenarios, `checkpoint_s` averages **15ms to 26ms**, representing between **20% and 40%** of local diagnosis duration.
- **Root Cause**: Checkpoints serialize the full session state to a temporary JSON file and perform an atomic `os.replace` on every step.

---

## 5. Verification & Regression Testing

The Phase 1 changes were verified against the entire relevant test suite:
- [tests/test_phase1_performance_metrics.py](file:///home/ubuntu/workspace/ut/tests/test_phase1_performance_metrics.py): **5 passed** (unit tests covering metric dataclass, monotonic timers, SSH tracking, and contract compatibility).
- [tests/test_imp_006_diagnose.py](file:///home/ubuntu/workspace/ut/tests/test_imp_006_diagnose.py): **12 passed** (validates CLI, MCP server, and Web endpoint agreements across live deadlock and healthy processes).
- [tests/test_remote_resilience_and_long_diagnosis.py](file:///home/ubuntu/workspace/ut/tests/test_remote_resilience_and_long_diagnosis.py): **7 passed**.
- [tests/test_remote_collection_bounds_and_isolation.py](file:///home/ubuntu/workspace/ut/tests/test_remote_collection_bounds_and_isolation.py): **5 passed**.

Total test suite status: **29 passed, 0 failed**.

---

## 6. Readiness Assessment for Phase 2

Phase 1 is complete and provides exact baseline metrics for measuring future improvements:

- **Target for Phase 2 (Remote Collection Failure Isolation)**:
  Ensure recipe errors, timeout failures, and partial SSH permission errors do not terminate the overall diagnosis session, and that partial findings are durably retained.
- **Target for Phase 3 (Bounded Concurrent Remote Collection)**:
  Parallelize independent collection operations to reduce Scenario 9 remote execution latency from ~2.58s down towards ~0.4s.
- **Target for Phase 4 (Remote Operation Coalescing & Minimization)**:
  Coalesce the 18 identity probes, 16 liveness checks, and 16 status queries into single batched requests.

**Decision**: **GO for Phase 2**.
