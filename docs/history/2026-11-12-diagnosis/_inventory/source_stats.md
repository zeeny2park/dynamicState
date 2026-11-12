# Source statistics

- Code lines: 191868 (source 91338, tests 100530, ratio 1.101)

## By language

| Language | Files | Code | Comment | Blank |
|---|---|---|---|---|
| Python | 368 | 178528 | 23711 | 26162 |
| JavaScript | 1 | 9161 | 359 | 1078 |
| C++ | 19 | 2133 | 148 | 328 |
| Shell | 19 | 1455 | 360 | 385 |
| C | 13 | 579 | 91 | 128 |
| Dockerfile | 1 | 12 | 0 | 4 |

## By top-level module

| Module | Files | Source LOC | Test LOC |
|---|---|---|---|
| `tests` | 308 | 0 | 100523 |
| `extractor` | 85 | 84267 | 0 |
| `scripts` | 6 | 3281 | 0 |
| `benchmarks` | 6 | 2503 | 0 |
| `examples` | 11 | 803 | 0 |
| `gdb` | 2 | 338 | 0 |
| `(root)` | 1 | 134 | 0 |
| `docker` | 2 | 12 | 7 |

## Largest source files

- `extractor/watch_session.py` (10133)
- `extractor/web/static/app.js` (9161)
- `extractor/capture_backend.py` (4858)
- `extractor/investigation.py` (4479)
- `extractor/web/server.py` (4425)
- `extractor/expert_diagnostic_engine.py` (3074)
- `extractor/hypothesis.py` (2857)
- `scripts/mcp_server.py` (2249)
- `extractor/adaptive_engine.py` (2156)
- `extractor/diagnostic_recipes.py` (2091)
- `extractor/ebpf_tracer.py` (2062)
- `extractor/evidence_ledger.py` (2042)
- `extractor/competing_hypotheses.py` (2031)
- `extractor/target_adapter.py` (1908)
- `extractor/agent_runtime.py` (1796)
- `extractor/cli.py` (1544)
- `extractor/cpp_decoder.py` (1518)
- `extractor/llm_provider.py` (1417)
- `extractor/dwarf_indexer.py` (1321)
- `extractor/workflow.py` (1142)
- `extractor/temporal_investigation.py` (1141)
- `extractor/runtime_evidence_provider.py` (1104)
- `extractor/evaluation.py` (1084)
- `extractor/dwarf_evaluator.py` (1039)
- `extractor/verdict_engine.py` (1036)

## Stub signals

- `extractor/debug_info.py:195`  raise NotImplementedError(
- `extractor/debug_info.py:200`  raise NotImplementedError()
- `extractor/debug_info.py:203`  raise NotImplementedError()
- `extractor/debug_info.py:206`  raise NotImplementedError()
- `extractor/execution.py:12`  raise NotImplementedError
- `extractor/inspection_module.py:94`  raise NotImplementedError
- `extractor/runtime_controller.py:79`  raise NotImplementedError
- `extractor/runtime_controller.py:82`  raise NotImplementedError
- `extractor/runtime_controller.py:85`  raise NotImplementedError
- `extractor/runtime_controller.py:88`  raise NotImplementedError
- `extractor/runtime_controller.py:91`  raise NotImplementedError
- `extractor/runtime_controller.py:94`  raise NotImplementedError
- `extractor/runtime_controller.py:101`  raise NotImplementedError
- `extractor/runtime_controller.py:182`  raise NotImplementedError
- `extractor/state_diff.py:24`  raise NotImplementedError
- `extractor/state_diff.py:27`  raise NotImplementedError
- `extractor/state_restorer.py:57`  raise NotImplementedError
- `extractor/state_restorer.py:60`  raise NotImplementedError

## Skipped / focused tests

- `tests/test_phase2_4_4_mcp_e2e.py:55`  @unittest.skipUnless(MCP_AVAILABLE, "mcp package not available")
- `tests/test_phase51_real_workspace_web_service.py:104`  @unittest.skipUnless(shutil.which("g++"), "g++ compiler required")

## Debt markers

- none

## Test files without detectable assertions

- `docker/gdb92/run_test.sh`
- `tests/fixtures/real_runtime/ebpf_stack_fixture.cpp`
- `tests/fixtures/real_runtime/expert_diagnostic_scenarios.cpp`
- `tests/fixtures/real_runtime/guard_pool_fixture.cpp`
- `tests/fixtures/real_runtime/main.cpp`
- `tests/fixtures/real_runtime/phase11_concurrency_fixture.cpp`
- `tests/fixtures/real_runtime/phase14_embedded_telemetry_fixture.cpp`
- `tests/fixtures/real_runtime/phase2_1_8_runtime_targets.cpp`
- `tests/fixtures/real_runtime/proc_accidental_tid_memory.c`
- `tests/fixtures/real_runtime/proc_mem_burst_and_drop.c`
- `tests/fixtures/real_runtime/proc_mem_vsz_mapping_only.c`
- `tests/fixtures/real_runtime/proc_raw_futex_no_mutex.c`
- `tests/fixtures/real_runtime/proc_scenario_a_healthy.c`
- `tests/fixtures/real_runtime/proc_scenario_b_growing_mem.c`
- `tests/fixtures/real_runtime/proc_scenario_c_thread_contention.c`
- `tests/fixtures/real_runtime/proc_scenario_d_stripped.c`
- `tests/fixtures/real_runtime/proc_thread_3way_deadlock.c`
- `tests/fixtures/real_runtime/proc_thread_circular_deadlock.c`
- `tests/fixtures/real_runtime/proc_thread_normal_cv.c`
- `tests/fixtures/real_runtime/proc_two_waiters_one_lock.c`
- `tests/fixtures/real_runtime/product_general_scenarios.cpp`
- `tests/fixtures/real_runtime/scenario_target.cpp`

## Source files not referenced by any test (6)

- `examples/deadlock_demo.cpp`
- `benchmarks/investigation_quality/fixture_target.cpp`
- `examples/pool_demo.cpp`
- `examples/real_multithread_example.py`
- `run_all_tests.sh`
- `scripts/target_capture.sh`
