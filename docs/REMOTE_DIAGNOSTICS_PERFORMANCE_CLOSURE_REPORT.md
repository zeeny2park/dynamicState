# DynamicState — Remote Diagnostics Performance Closure & Hardening Report

**Repository**: `https://github.com/zeeny2park/dynamicState`  
**Reviewed Commit**: `a004633e2318c34a31dce2c49584b1e999277164` *(local mirror baseline `6d1db06`)*  
**Assessment Date**: 2026-11-22  
**Final Verdict**: **`HARDENING COMPLETE (LOCAL VERIFIED; REMOTE CI NOT VERIFIED)`**

---

## 1. Executive Summary

This narrowly scoped hardening pass audited `extractor/remote_scheduler.py`, `extractor/target_adapter.py`, `extractor/diagnostic_performance.py`, `benchmarks/remote_diagnostics_benchmark.py`, and `tests/test_remote_diagnostics_performance.py` against strict deadline, task-timeout, cancellation, subprocess-termination, and single-target overhead contracts.

The audit uncovered **6 concrete defects**—including two **CRITICAL** bugs (`RemoteCollectionTask.timeout_s` was ignored; `with ThreadPoolExecutor` silently blocked callers past `overall_deadline_s` during shutdown) and one **CRITICAL** latent bug (`import signal` was missing in `extractor/target_adapter.py`, causing `os.killpg` to fall back to `proc.kill()` and leaving grandchildren holding stdout open). All 6 defects were fixed and verified with a new 20-case deterministic timeout/cancellation test matrix (`tests/test_remote_scheduler_deadline_and_cancellation.py`: **16/16 test methods PASS in 0.588s**) and **18/18 regression suites (201/201 tests PASS, 0 failures, 0 skips)**.

---

## 2. Exact Commit Reviewed & Findings (`SOURCE VERIFIED`)

| Finding | Severity | Source Location | Previous Behavior | Fixed Behavior | Verification |
|---|---|---|---|---|---|
| **F-01** | **CRITICAL** | `extractor/remote_scheduler.py` (`RemoteCollectionTask.timeout_s`, `_run_task`, `execute`) | `timeout_s` was never validated or enforced; tasks ran until `overall_deadline_s` | Strictly validates `timeout_s`; computes `eff_deadline = min(task_dl, overall_dl)`; enforces in `wait()` loop and propagates to worker context | `TEST VERIFIED` (`test_01`–`test_04`, `test_19`) |
| **F-02** | **CRITICAL** | `extractor/remote_scheduler.py` (`execute` executor shutdown) | `with ThreadPoolExecutor(...)` called `shutdown(wait=True)`, silently blocking callers past `overall_deadline_s` on hung workers | Explicit `pool.shutdown(wait=(not abandoned_workers), cancel_futures=True)` returns promptly within deadline tolerance | `TEST VERIFIED` (`test_03`, `test_05`, `test_13_15_17_18`) |
| **F-03** | **CRITICAL** | `extractor/target_adapter.py` (`_default_command_runner`) | Missing top-level `import signal` caused `os.killpg(proc.pid, signal.SIGKILL)` to raise `NameError` inside `except Exception`, falling back to `proc.kill()` and leaking grandchild processes | Added `import signal` and integrated scheduler `register_cancel_hook` so `os.killpg` terminates the entire POSIX process group on both timeout and `cancel()` | `TEST VERIFIED` (`test_02`, `test_07_and_16`) |
| **F-04** | **HIGH** | `extractor/remote_scheduler.py` (`_run_task` retry backoff) | `time.sleep(backoff)` ignored `cancel()` until full backoff elapsed | Replaced with `self._cancel_event.wait(timeout=min(backoff, remaining_budget))` for instant wake on cancel and strict budget compliance | `TEST VERIFIED` (`test_09`, `test_10`) |
| **F-05** | **HIGH** | `extractor/remote_scheduler.py` (`_run_task`, `execute`) | Tasks completing just after deadline could return `STATUS_COMPLETE`; finalized results dict was not snapshotted | Late completions after `effective_deadline` are classified `STATUS_TIMED_OUT`; finalized `results` are snapshotted into a fresh dict and never overwritten by late workers | `TEST VERIFIED` (`test_12`, `test_13_15_17_18`) |
| **F-06** | **MEDIUM** | `extractor/target_adapter.py` (`remaining_deadline_sec`) | Worker threads did not inherit scheduler `effective_deadline` | `remaining_deadline_sec()` now checks both `self._deadline_tls.deadline` and `get_active_execution_context()[0]`, taking `min(...)` | `TEST VERIFIED` (`test_02`) |

---

## 3. Deadline, Task Timeout & Cancellation Contract (`SOURCE VERIFIED` / `TEST VERIFIED`)

- **Monotonic Clock Only**: All deadlines (`overall_deadline`, `task_dl`, `eff_dl`, `remaining_deadline_sec`) use `time.monotonic()`.
- **No Budget Reset**: Child operations receive `min(local_deadline, scheduler_effective_deadline)`.
- **Immediate Process-Group Termination**: `AdaptiveRemoteCollectionScheduler.register_cancel_hook()` is bound into worker thread context (`_EXEC_CTX`) and registered by `RemoteSshTargetAdapter._default_command_runner()`; invoking `sched.cancel()` immediately calls `os.killpg(proc.pid, signal.SIGKILL)` on all active POSIX subprocess groups with zero polling threads.
- **Actual Caller Return-Time Verification (`MEASURED` / `TEST VERIFIED`)**:
  - `0.8s` blocking task under `overall_deadline_s=0.06`: caller returns in `< 0.30s` (`test_03`).
  - `sh -c "sleep 10 & wait"` real subprocess + grandchild under `timeout_s=0.10`: killed and returned in `< 0.50s` (`test_02`).
  - `sh -c "sleep 10 & wait"` cancelled at `0.05s`: killed via `os.killpg` and returned in `< 0.50s` (`test_07_and_16`).
  - `2.0s` retry backoff cancelled at `0.02s`: woke and returned in `< 0.35s` (`test_09`).

---

## 4. Single-Target Overhead Analysis (Phase 3 — `MEASURED`, 100 Iterations After Warm-Up)

Executed 100 post-warmup iterations to evaluate the prior 5-run Scenario B (1 target) `33.00ms` P95 spike:

| Workload (100 iterations, post-warmup) | P50 | P90 | P95 | P99 | Mean | Stddev | Max | Classification |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Direct call (0ms work) | 0.000ms | 0.000ms | 0.000ms | 0.000ms | 0.000ms | 0.000ms | 0.000ms | `MEASURED` |
| Scheduler 1-task (0ms work) | 0.126ms | 0.146ms | 0.178ms | 0.243ms | 0.133ms | 0.024ms | 0.244ms | `MEASURED` |
| Direct call (5ms work) | 5.071ms | 5.079ms | 5.085ms | 5.100ms | 5.074ms | 0.007ms | 5.122ms | `MEASURED` |
| Scheduler 1-task (5ms work) | 5.303ms | 5.382ms | 5.430ms | 5.882ms | 5.328ms | 0.091ms | 5.889ms | `MEASURED` |

**Conclusion**: True scheduler overhead for a single target is only **+0.13ms to +0.23ms** (`P95 = 0.178ms` for 0ms work, `P95 = 5.430ms` vs `5.085ms` for 5ms work). The earlier `33.00ms` P95 was cold-start OS scheduling jitter amplified by a 5-run sample size. A direct-execution bypass was intentionally **not** added so that single-task workloads retain full non-blocking timeout and cancellation guarantees.

---

## 5. Benchmark Methodology Corrections (`SOURCE VERIFIED`)

Updated `benchmarks/remote_diagnostics_benchmark.py`:
- Added `p99_s` and `tail_latency_reliable` (`runs >= 20`) to `_stats()`.
- Labeled baseline explicitly as `simulated_sequential_baseline` (`SIMULATED`) and network model as `synthetic_deterministic_rtt_except_scenario_F_real_subprocess`.
- Renamed Scenario G throughput metric to `local_parsing_throughput_mb_s` (`LOCAL_PARSING_WITH_SYNTHETIC_RTT_5MS`) so local parsing throughput is never misread as network transfer throughput.

---

## 6. Regression, Trust & Durability Verification (`TEST VERIFIED`)

Executed via `python3 scripts/run_unittest.py <file>` (**18/18 suites, 201/201 tests PASS, 0 failures, 0 skips**):
- `tests/test_remote_scheduler_deadline_and_cancellation.py`: **16/16 PASS** (all 20 Phase 4 matrix cases + per-target auth isolation)
- `tests/test_remote_diagnostics_performance.py`: **9/9 PASS**
- `tests/test_phase2_remote_performance.py`, `test_remote_collection_bounds_and_isolation.py`, `test_remote_resilience_and_long_diagnosis.py`: **18/18 PASS**
- `tests/test_finalization_review2_adversarial.py`, `test_final_product_stability_and_edge_cases.py`: **27/27 PASS**
- `tests/test_target_collector.py` + `test_crypto --selftest`: **59/59 PASS** + FIPS/RFC crypto PASS
- Phase 2.0-A.3.17 (all 7 suites, **51/51 PASS**), A.3.18 persistence failure closure (**7/7 PASS**), A.3.19 durable commit semantics (**6/6 PASS**)
- `tests/test_ci_workflow_parity.py`: **8/8 PASS** (YAML schema & exact byte parity)
- Static check (`python3 -m py_compile`): **PASS** (exit code 0)

---

## 7. Remaining Limitations & CI Status

- **Blocking Non-Subprocess Python Threads**: Python threads executing pure-Python blocking calls (e.g., `time.sleep()`) cannot be forcibly killed safely; the scheduler returns promptly via `shutdown(wait=False)` and guarantees late completions cannot mutate finalized results, while real SSH subprocesses ARE terminated via `os.killpg`.
- **GitHub Actions CI**: **`NOT VERIFIED`** from this offline sandbox (no outbound network access). Apply `dynamicstate-remote-perf-hardening.patch` and push to verify the newly gated `Run Remote Scheduler Deadline and Cancellation Matrix Tests` step on GitHub Actions.
