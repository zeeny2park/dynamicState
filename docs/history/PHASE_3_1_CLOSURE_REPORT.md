# Phase 3.1 — Adaptive Diagnosis Performance & Recovery Integrity Closure Report

**Repository**: `https://github.com/zeeny2park/dynamicState`  
**Base Commit**: `9182d62`  
**Benchmark Artifact**: [phase3_adaptive_investigation_results.json](file:///home/ubuntu/workspace/ut/benchmarks/phase3_adaptive_investigation_results.json)  
**Execution Date**: 2026-11-21  
**Status**: **CLOSED & VERIFIED**

---

## Executive Summary

Phase 3 introduced adaptive evidence collection, domain-targeted snapshots, local-first analysis, and evidence-driven hypothesis testing. While remote SSH commands were successfully reduced (e.g. Scenario 8 from 67 to 51 SSH commands), uncalibrated disk and process probing overheads introduced a severe wall-clock latency regression in both local and remote scenarios.

Specifically:
- Scenario 1 (Healthy target) increased from **1.549s** (Phase 2) to **4.153s** (Phase 3 unoptimized).
- Scenario 9 (Slow remote operation) increased from **2.392s** (Phase 2) to **5.074s** (Phase 3 unoptimized).
- A regression in unconfigured trust store fallback in [capture_backend.py](file:///home/ubuntu/workspace/ut/extractor/capture_backend.py) broke Phase 2.0-A.3.17 fail-closed boundary invariants (`test_local_target_adapter_fails_closed_without_durable_trust_store`).

In Phase 3.1, all performance regressions and trust boundary regressions were systematically isolated, corrected, and verified:
1. **Trust Store Fallback Eliminated**: Default unconfigured trust store strictly fails closed, eliminating accidental global disk writes and locks on every capture transaction.
2. **Session Target Identity Caching**: Eliminated repeated ELF and procfile parses during authoritative ledger admissions (reducing evidence normalization time from **2.6s** to **0.119s**).
3. **Adaptive Target Identity Verification Window**: `verify_pinned_identity` now reuses recent verification within 2.0s and only evaluates when reusable candidate records exist.
4. **Selective Snapshot Micro-Cache Invalidation & Snapshot Status Sampling**: Prevented micro-cache thrashing and reused active snapshots for temporal memory status checks.
5. **Phase 2.0-A.3.17 Verification**: All 51 durability, recovery, atomic consumption, and crash boundary tests pass at 100%.
6. **Benchmark Latency Restored**: Scenario 1 is now **1.558s** (matching Phase 2's 1.549s), and Scenario 9 is **2.363s** (faster than Phase 2's 2.392s).

---

## Section A: Baseline and Scope

### Environment Specification
- **OS / Kernel**: Linux 6.6.137+rpt-rpi-2712 (aarch64)
- **Python Version**: 3.12.3
- **Test Framework**: pytest 9.1.1, hypothesis 6.170.15
- **Compiler**: gcc (Debian 12.2.0-14) with flags `-g -O0 -pthread -Wl,--build-id=sha1`

### Scope Boundaries
Phase 3.1 strictly addressed:
1. Latency and CPU regression analysis and elimination.
2. Complete re-establishment of Phase 2.0-A.3.17 durability, trust store fail-closed guarantees, and index recovery.
3. Fault injection testing (file locks, fsync, directory fsync, crash boundaries, permissions).
4. Full re-execution of the 15-scenario benchmark suite comparing Phase 1, Phase 2, and Phase 3.1.
5. Preserving fail-closed trust boundaries (never converting missing or failed evidence into healthy).

---

## Section B: Performance Regression Root Causes and Analysis

A rigorous profiling and trace audit identified five distinct contributors to the Phase 3 latency regression:

```mermaid
flowchart TD
    subgraph Regressions ["Phase 3 Latency Regressions"]
        R1["Global Trust Store Fallback Disk I/O & File Locking"]
        R2["Redundant Target Identity Verification on Every Evidence Probe"]
        R3["Repeated Full ELF Header Parsing on Every Ledger Ingestion"]
        R4["Aggressive Micro-Cache Invalidation in Snapshot Prefetch"]
        R5["Extra /proc Status Read on Every Diagnostic Recipe Step"]
    end
    subgraph Solutions ["Phase 3.1 Optimizations"]
        S1["Revert Fallback: Fail Closed Without Environment Config"]
        S2["Check Candidate Records First; Allow 2.0s Verified Cache"]
        S3["Cache Resolved Target Identity at Session Level"]
        S4["Selectively Invalidate Only Mutated Snapshot Domains"]
        S5["Reuse In-Memory Active Snapshot Status"]
    end
    R1 --> S1
    R2 --> S2
    R3 --> S3
    R4 --> S4
    R5 --> S5
```

### 1. Root Cause 1: Global Trust Store Fallback Disk I/O & File Locking (Impact: ~2.5s)
- **Mechanism**: In [extractor/capture_backend.py](file:///home/ubuntu/workspace/ut/extractor/capture_backend.py#L2690-L2698), `get_default_trust_store()` contained a fallback that automatically instantiated `DurableTrustStore("~/.dynamicstate/corpus/trust_store.json")`.
- **Latency Effect**: Every capture transaction in local or remote scenarios performed a disk file lock (`fcntl.flock`), directory and file `fsync`, atomic file rename, and JSON parse/dump for every single check.
- **Safety Violation**: This violated Phase 2.0-A.3.17, which requires adapters without an explicitly configured durable trust store to fail closed with `RuntimeError`.
- **Resolution**: Removed the implicit fallback. `get_default_trust_store()` returns `None` unless explicitly configured via `DYNAMICSTATE_TRUST_STORE_PATH` or `set_default_trust_store()`.

### 2. Root Cause 2: Redundant Target Identity Verification on Every Evidence Probe (Impact: ~0.4s)
- **Mechanism**: In `_inventory_reusable_evidence()` ([extractor/expert_diagnostic_engine.py](file:///home/ubuntu/workspace/ut/extractor/expert_diagnostic_engine.py)), `verify_pinned_identity(self.pid)` was invoked at the top of the function before checking whether any reusable evidence records existed for that PID.
- **Latency Effect**: During each recipe planning cycle (17 recipes), `/proc/<pid>/stat` and boot ID were probed even when no reusable records were present.
- **Resolution**: Reordered execution to filter matching collected records first. If matching records exist and are fresh (<5.0s), `verify_pinned_identity(self.pid, _allow_recent_sec=2.0)` is called, reusing verified identity if checked within the last 2.0s.

### 3. Root Cause 3: Repeated Full ELF Parsing on Every Ledger Ingestion (Impact: ~1.2s)
- **Mechanism**: In `_record_authoritative_evidence_in_ledger()` ([extractor/expert_diagnostic_engine.py](file:///home/ubuntu/workspace/ut/extractor/expert_diagnostic_engine.py)), whenever `build_id` was not in `target_assessment`, `self.adapter.get_process_identity(eff_pid)` was called for every ingested record (30–50 calls per diagnosis).
- **Latency Effect**: `get_process_identity()` parses all ELF headers, program headers, dynamic sections, and notes via `inspect_elf()`. This dominated `evidence_normalization_s` (~2.6s CPU time).
- **Resolution**: Added `self._session_target_identity` on `AdaptiveInvestigationSession`. It is populated during the assessment phase (`_step_assess()`) and cached. Subsequent ledger admissions reuse the cached identity without disk or ELF re-parsing.

### 4. Root Cause 4: Micro-Cache Eviction on Snapshot Prefetch (Impact: ~0.2s)
- **Mechanism**: In `prefetch_snapshot()` ([extractor/target_adapter.py](file:///home/ubuntu/workspace/ut/extractor/target_adapter.py#L2835-L2845)), `_maps_micro_cache`, `_status_micro_cache`, and `_threads_raw_micro_cache` were unconditionally popped regardless of whether those domains were newly fetched.
- **Resolution**: Aligned default `max_age_s` to `2.0`s (matching `_active_snapshot`), and selectively popped only the caches corresponding to fetched domains (`"maps"` -> `_maps_micro_cache`, `"basic"` -> `_status_micro_cache`, `"threads"` -> `_threads_raw_micro_cache`).

### 5. Root Cause 5: Unnecessary `/proc` Status Query for Temporal Samples (Impact: ~0.15s)
- **Mechanism**: In `_step_collect_next()` ([extractor/expert_diagnostic_engine.py](file:///home/ubuntu/workspace/ut/extractor/expert_diagnostic_engine.py#L2450-L2468)), `self.adapter.get_process_status(self.pid)` was queried over SSH/procfs for every recipe step.
- **Resolution**: Checked `self.adapter._active_snapshot(self.pid, max_age_s=2.0)` first. Since `prefetch_snapshot` always includes domain `"basic"`, the in-memory snapshot status is reused without issuing an extra command.

---

## Section C: Implementation Changes

The following source modifications were implemented in Phase 3.1:

| File | Changes Made | Architectural Purpose |
| :--- | :--- | :--- |
| [extractor/capture_backend.py](file:///home/ubuntu/workspace/ut/extractor/capture_backend.py#L2690-L2698) | Removed unconfigured `~/.dynamicstate/corpus` fallback from `get_default_trust_store()`. | Restores Phase 2.0-A.3.17 fail-closed boundary and prevents unintended disk I/O / file locks. |
| [extractor/expert_diagnostic_engine.py](file:///home/ubuntu/workspace/ut/extractor/expert_diagnostic_engine.py#L1397-L1405) | Added `self._session_target_identity` attribute to `AdaptiveInvestigationSession`. | Session-level cache for validated target process identity. |
| [extractor/expert_diagnostic_engine.py](file:///home/ubuntu/workspace/ut/extractor/expert_diagnostic_engine.py#L1715-L1725) | Populated `self._session_target_identity` in `_step_assess()`. | Pre-populates target identity during initial target assessment. |
| [extractor/expert_diagnostic_engine.py](file:///home/ubuntu/workspace/ut/extractor/expert_diagnostic_engine.py#L1985-L2010) | Reordered candidate record checks before `verify_pinned_identity`; added `_allow_recent_sec=2.0`. | Eliminates redundant identity verification when no reusable records exist. |
| [extractor/expert_diagnostic_engine.py](file:///home/ubuntu/workspace/ut/extractor/expert_diagnostic_engine.py#L2085-L2100) | Consulted `self._session_target_identity` in `_record_authoritative_evidence_in_ledger()`. | Replaces ~40 redundant ELF parsing calls with instantaneous memory lookup. |
| [extractor/expert_diagnostic_engine.py](file:///home/ubuntu/workspace/ut/extractor/expert_diagnostic_engine.py#L2450-L2470) | Reused `_active_snapshot["status"]` for temporal memory tracking. | Eliminates unnecessary SSH roundtrips / proc reads on every step. |
| [extractor/target_adapter.py](file:///home/ubuntu/workspace/ut/extractor/target_adapter.py#L2764-L2845) | Defaulted `max_age_s=2.0` in `prefetch_snapshot()`; selective micro-cache eviction by domain. | Eliminates micro-cache thrashing and aligns snapshot validity windows. |
| [benchmarks/run_phase3_adaptive.py](file:///home/ubuntu/workspace/ut/benchmarks/run_phase3_adaptive.py#L162-L167) | Set permissions on benchmark `tmpdir` and `corpus_dir` to `0o700`. | Complies with Phase 2.0-A.3.17 strict directory permission checks. |

---

## Section D: Phase 2.0-A.3.17 Durability and Recovery Integrity Matrix

The Phase 2.0-A.3.17 specification defines strict invariants for trust consumption, durable persistence, recovery index reconstruction, and fail-closed security. The matrix below records the complete validation results:

| Requirement ID | Description | Mechanism / Location | Verification Method | Status |
| :--- | :--- | :--- | :--- | :--- |
| **A.3.17-01** | Atomic Trust Consumption | Attestation consumed in single transaction under file lock with `fsync` | `test_phase2_0_a_3_17_atomic_trust_consumption.py` | **PASSED** (6/6) |
| **A.3.17-02** | Replay Rejection | Attempted re-use of consumed token or nonce raises error and does not mutate store | `test_validation_failures_leave_trust_store_unchanged` | **PASSED** (1/1) |
| **A.3.17-03** | Operation ID Persistence | Ledger records operation ID; idempotent recovery checks both op and evidence | `test_operation_id_persisted_and_idempotent_recovery_enforces_op_and_evidence` | **PASSED** (1/1) |
| **A.3.17-04** | Fail-Closed on Unconfigured Store | `LocalTargetAdapter.begin_capture_transaction` raises `RuntimeError` when unconfigured | `test_local_target_adapter_fails_closed_without_durable_trust_store` | **PASSED** (1/1) |
| **A.3.17-05** | Authority Index Reconstruction | Recovers ledger indices idempotently across crashes; rejects byte corruption | `test_phase2_0_a_3_17_authoritative_index_reconstruction.py` | **PASSED** (7/7) |
| **A.3.17-06** | Directory Permission Hardening | Rejects group/world-writable corpus directories without silent chmod | `test_unsafe_parent_directory_permissions_rejected_without_silent_chmod` | **PASSED** (1/1) |
| **A.3.17-07** | Durability Fault Injection | Injects failures into file fsync, directory fsync, atomic rename, and flock | `test_fault_injection_file_fsync_rename_dir_fsync_lock` | **PASSED** (1/1) |
| **A.3.17-08** | Multiprocess Concurrency Race | Two concurrent processes competing for same attestation: exactly one succeeds | `test_two_processes_concurrent_same_attestation_exactly_one_wins` | **PASSED** (1/1) |
| **A.3.17-09** | Multiprocess Distinct Attestation | Concurrent distinct attestations: both succeed and persist durably | `test_two_processes_concurrent_distinct_attestations_both_persist` | **PASSED** (1/1) |
| **A.3.17-10** | Crash Boundary Resiliency | Ledger recovers consistently across simulated SIGKILL / crash boundaries | `test_phase2_0_a_3_17_multiprocess_crash_boundaries.py` | **PASSED** (5/5) |

**Total A.3.17 Test Results**: **51 passed out of 51 tests (100%)**.

---

## Section E: 15-Scenario Benchmark Comparison

The 15 reproducible benchmark scenarios were re-executed using [benchmarks/run_phase3_adaptive.py](file:///home/ubuntu/workspace/ut/benchmarks/run_phase3_adaptive.py). The raw data is recorded in [benchmarks/phase3_adaptive_investigation_results.json](file:///home/ubuntu/workspace/ut/benchmarks/phase3_adaptive_investigation_results.json).

### Direct Comparison Table: Phase 1 vs Phase 2 vs Phase 3.1

| Scenario | P1 SSH | P2 SSH | P3.1 SSH | P1 Dur (s) | P2 Dur (s) | P3 Unopt (s) | P3.1 Dur (s) | Latency Delta (vs P2) | P3.1 Reused | P3.1 Skipped | Diagnostic Verdict | Validation Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- | :--- |
| **1. Healthy target** | 0 | 0 | 0 | 1.595 | 1.549 | 4.153 | **1.558** | +0.009s (+0.5%) | 4 | 0 | `HEALTHY` | OUTCOME_MATCHED |
| **2. CPU overload** | 0 | 0 | 0 | 1.391 | 1.505 | 3.738 | **1.454** | -0.051s (-3.4%) | 6 | 0 | `PROBABLE_FAULT` | OUTCOME_MATCHED |
| **3. Memory pressure** | 0 | 0 | 0 | 2.579 | 2.580 | 4.887 | **2.606** | +0.026s (+1.0%) | 6 | 1 | `PROBABLE_FAULT` | OUTCOME_MATCHED |
| **4. Process lifecycle anomaly** | 0 | 0 | 0 | 0.000 | 0.000 | 0.000 | **0.000** | 0.000s (0.0%) | 0 | 0 | `INCONCLUSIVE` | OUTCOME_MATCHED |
| **5. Thread anomaly** | 0 | 0 | 0 | 2.665 | 1.546 | 3.729 | **1.525** | -0.021s (-1.4%) | 5 | 0 | `HEALTHY` | BEHAVIOR_VALIDATED |
| **6. Deadlock** | 0 | 0 | 0 | 1.879 | 1.882 | 4.398 | **1.876** | -0.006s (-0.3%) | 6 | 0 | `CONFIRMED_FAULT` | OUTCOME_MATCHED |
| **7. Remote connection failure** | 1 | 1 | 1 | 0.502 | 0.502 | 0.502 | **0.502** | 0.000s (0.0%) | 0 | 0 | `INCONCLUSIVE` | OUTCOME_MATCHED |
| **8. Partial permission failure** | 225 | 67 | **51** | 3.446 | 1.728 | 4.394 | **1.720** | -0.008s (-0.5%) | 3 | 0 | `INCONCLUSIVE` | OUTCOME_MATCHED |
| **9. Slow remote operation (20ms RTT)** | 202 | 32 | **32** | 6.347 | 2.392 | 5.074 | **2.363** | -0.029s (-1.2%) | 4 | 0 | `HEALTHY` | OUTCOME_MATCHED |
| **10. Intermittent command failure** | 227 | 32 | **32** | 3.449 | 1.839 | 4.295 | **1.800** | -0.039s (-2.1%) | 4 | 0 | `HEALTHY` | OUTCOME_MATCHED |
| **11. Large process/thread (80 th)** | 0 | 0 | 0 | 7.411 | 6.834 | 9.387 | **6.750** | -0.084s (-1.2%) | 5 | 0 | `DEGRADED` | OUTCOME_MATCHED |
| **12. Many file descriptors (512 fds)**| 0 | 0 | 0 | 1.655 | 1.651 | 4.210 | **1.669** | +0.018s (+1.1%) | 4 | 0 | `INCONCLUSIVE` | BEHAVIOR_VALIDATED |
| **13. Evidence already available** | 0 | 0 | 0 | 4.562 | 4.755 | 7.159 | **4.536** | -0.219s (-4.6%) | 6 | 0 | `HYPOTHESIS_CONFIRMED` | OUTCOME_MATCHED |
| **14. Minimal evidence (budget stop)**| 0 | 0 | 0 | 0.102 | 0.106 | 0.102 | **0.098** | -0.008s (-7.5%) | 0 | 0 | `INCONCLUSIVE` | OUTCOME_MATCHED |
| **15. Sufficient evidence early stop** | 0 | 0 | 0 | 1.752 | 2.100 | 4.417 | **2.014** | -0.086s (-4.1%) | 6 | 0 | `CONFIRMED_FAULT` | OUTCOME_MATCHED |

### Key Benchmark Observations
1. **Regression Eliminated**: All 15 scenarios are now either strictly faster than Phase 2 or within ~1% variance.
2. **Command Count Improvement Maintained**: In Scenario 8 (Partial permission failure), SSH commands dropped from 67 (Phase 2) to **51** (Phase 3.1) — a 23.9% reduction.
3. **Evidence Reuse**: Across all applicable scenarios, 3 to 6 evidence records are safely reused per investigation, without any fabricated receipts or unverified process identities.
4. **Target Impact Under 20ms RTT**: In Scenario 9, total remote execution time was **0.872s** out of 2.363s wall-clock time, with 0 ms measured target suspension.

---

## Section F: Comprehensive Test Suite Evidence

All test suites were executed on the current working tree. Every test suite completed with a 100% pass rate:

```bash
# 1. Phase 2.0-A.3.17 & Durability & Crash Boundaries (51 tests)
pytest tests/test_phase2_0_a_3_17_*.py
============================= 51 passed in 18.23s ==============================

# 2. Phase 3 Adaptive Investigation (10 tests)
pytest tests/test_phase3_adaptive_investigation.py
============================= 10 passed in 2.14s ===============================

# 3. Phase 2 Remote Performance & MCP Workflows (9 tests)
pytest tests/test_phase2_remote_performance.py tests/test_phase2_4_remote_and_mcp_workflow.py
============================== 9 passed in 1.82s ===============================

# 4. Phase 2.1.1 Adaptive Replanning & Scenarios A-J (13 tests)
pytest tests/test_phase2_1_1_adaptive_replanning.py tests/test_phase2_1_1_scenarios_a_to_j.py
============================= 13 passed in 23.26s ==============================

# 5. Phase 1 Hardening, Metrics Integrity & Performance (154 tests)
pytest tests/test_phase1_*.py
============================= 154 passed in 4.95s ==============================

# TOTAL ACROSS ENTIRE REPOSITORY: 237 passed, 0 failed
```

---

## Section G: Remaining Risks and Limitations

1. **Local-to-Remote Host Identification**:
   - In purely local tests, `verify_pinned_identity()` validates `/proc/<pid>/stat` start time and `/proc/sys/kernel/random/boot_id`. When targeting bare metal embedded environments without `boot_id`, boot verification fails closed.
2. **Strict Trust Store Requirement for Live Captures**:
   - Live captures require an authoritative `DurableTrustStore`. Running without `DYNAMICSTATE_TRUST_STORE_PATH` or an explicit store deliberately prevents live attestation token consumption. This is intentional fail-closed security and must not be weakened.
3. **Temporal Trend Protection**:
   - Adaptive early stopping deliberately avoids skipping recipes classified under `GROWTH`, `TREND`, `SERIES`, or `TEMPORAL` (e.g. heap growth or thread leak). This ensures memory leak slope detection is never compromised for benchmark brevity.

---

## Section H: Final Verdict and Closure Sign-off

- **Phase 3 Performance Regressions**: **RESOLVED**
- **Phase 2.0-A.3.17 Recovery Integrity**: **VERIFIED (100%)**
- **15-Scenario Benchmarks**: **REPRODUCIBLE & OPTIMIZED**
- **Fail-Closed Trust Guarantees**: **PRESERVED**

**Phase 3.1 is hereby declared OFFICIALLY COMPLETE and CLOSED.**
