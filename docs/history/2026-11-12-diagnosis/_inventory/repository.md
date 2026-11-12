# Repository inventory: dynamicState

- Path: `C:\task\dynamicState\dynamicState`
- Files (excluding vendored/generated): 469

## Categories

- build: 1
- ci: 4
- config: 12
- docs: 28
- other: 3
- source: 112
- test: 309

## Languages (file count)

- Python: 368
- C++: 19
- Shell: 19
- C: 13
- Dockerfile: 1
- JavaScript: 1

## Top-level layout

- `.gitignore` (1)
- `README.md` (1)
- `benchmarks/` (12)
- `ci/` (4)
- `docker/` (2)
- `docs/` (26)
- `examples/` (11)
- `extractor/` (88)
- `gdb/` (2)
- `protocol/` (5)
- `requirements.txt` (1)
- `run_all_tests.sh` (1)
- `scripts/` (6)
- `snapshots/` (1)
- `tests/` (308)

## Intent sources

- **readme**: `README.md`, `ci/README.md`, `protocol/README.md`
- **architecture**: `docs/EBPF_TRACING_ARCHITECTURE_PHASE1.md`, `docs/EMBEDDED_DEPLOYMENT_ARCHITECTURE.md`, `docs/PHASE_6_AGENT_API_DESIGN.md`
- **roadmap_plan**: `docs/EBPF_TRACING_ARCHITECTURE_PHASE1.md`, `docs/FUNCTIONAL_GAP_ANALYSIS_AND_DEVELOPMENT_ROADMAP.md`, `docs/PHASE_0_IMPLEMENTATION_INVENTORY_AND_INTEGRATION_AUDIT.md`, `docs/PHASE_2_2_2_3_FINAL_REPORT.md`, `docs/PHASE_2_2_C_1_FINAL_REPORT.md`, `docs/PHASE_2_2_C_FINAL_REPORT.md`, `docs/PHASE_2_3_C_1_FINAL_REPORT.md`, `docs/PHASE_2_3_C_FINAL_REPORT.md`, `docs/PHASE_2_4_1_FINAL_REPORT.md`, `docs/PHASE_2_4_2_FINAL_REPORT.md`, `docs/PHASE_2_4_3_FINAL_REPORT.md`, `docs/PHASE_2_4_4_FINAL_REPORT.md`, `docs/PHASE_2_4_FINAL_REPORT.md`, `docs/PHASE_6_AGENT_API_DESIGN.md`
- **api_spec**: `docs/PHASE_6_AGENT_API_DESIGN.md`

## Build systems

- Python (pip) (requirements.txt)

## CI

- custom ci/ directory: ci/README.md
- custom ci/ directory: ci/ci.yml
- custom ci/ directory: ci/workflows/gdb92.yml
- custom ci/ directory: ci/workflows/test.yml

## Deployment

- Docker: docker/gdb92/Dockerfile

## Entry points

- Python __main__: `benchmarks/capture_benchmark.py:950`
- CLI parser: `benchmarks/capture_benchmark.py:930`
- C/C++ main: `benchmarks/investigation_quality/fixture_target.cpp:127`
- Python __main__: `benchmarks/investigation_quality/run_benchmark.py:1174`
- CLI parser: `benchmarks/investigation_quality/run_benchmark.py:1141`
- C/C++ main: `examples/deadlock_demo.cpp:60`
- C/C++ main: `examples/pool_demo.cpp:23`
- Python __main__: `examples/real_multithread_example.py:243`
- C/C++ main: `examples/sample.cpp:65`
- C/C++ main: `examples/sample_dwarf_target.cpp:17`
- C/C++ main: `examples/sample_low_impact.cpp:65`
- C/C++ main: `examples/sample_multithread.cpp:77`
- C/C++ main: `examples/sample_multithread_nondet.cpp:52`
- C/C++ main: `examples/sample_pointer_cycle_target.cpp:25`
- C/C++ main: `examples/sample_prod.cpp:108`
- Python __main__: `extractor/__main__.py:5`
- Python __main__: `extractor/cli.py:1712`
- CLI parser: `extractor/cli.py:23`
- Python __main__: `extractor/evaluation.py:1244`
- Python __main__: `extractor/state_diff.py:404`
- CLI parser: `extractor/state_diff.py:411`
- Python __main__: `extractor/web/__main__.py:61`
- CLI parser: `extractor/web/__main__.py:17`
- Python __main__: `extractor/web/workspace.py:134`
- CLI parser: `extractor/web/workspace.py:23`
- Python __main__: `scripts/mcp_server.py:2895`
- Python __main__: `scripts/run_e2e_operational_acceptance.py:350`
- CLI parser: `scripts/run_e2e_operational_acceptance.py:79`
- Python __main__: `scripts/run_production_pilot.py:134`
- CLI parser: `scripts/run_production_pilot.py:30`
- Python __main__: `scripts/validate_real_target.py:652`
- CLI parser: `scripts/validate_real_target.py:626`

## SCM

- Branch: main  HEAD: f842448aec36  commits: 236
- First commit: b2dc8f2|2026-09-27|feat: complete Phase 3 Runtime State Transition Engine (Snapshot, Typed Mutation, Continue, Semantic Diff)
- Working tree dirty: False

### Recent commits

- f842448 2026-11-10 feat(phase-2.4.4): end-to-end adaptive investigation, counter source continuity, and evidence provenance validation
- 12b0547 2026-11-10 feat(phase-2.4.3): enforce temporal epoch integrity, missing metrics semantics, and production path validation
- 4c738c9 2026-11-10 feat(phase-2.4.2): temporal evidence integrity and lifecycle diagnostics closure
- b63c044 2026-11-10 feat(phase-2.4.1): validation integrity, evidence closure, and mcp transport e2e
- 635765d 2026-11-10 feat(phase-2.4): embedded linux and real-world diagnostic validation closure
- 3d4d47d 2026-11-09 feat(phase-2.3-c.1): measurement semantics and all-22-recipe diagnostic accuracy closure
- 52d4754 2026-11-09 feat(phase-2.3-c): production diagnostic pipeline closure and end-to-end audit verification
- c0375a0 2026-11-09 Phase 2.2-C.1: Runtime Interpretation Correctness & End-to-End Diagnostic Validation
- 0df718b 2026-11-09 feat(phase-2.2-c): unified C++ type decoder, allocator-aware pointer integrity, and temporal identity
- 69bb100 2026-11-09 feat(phase-2.2-2.3): functional correctness and diagnostic integration closure
- 9be2661 2026-11-09 docs: add functional gap analysis and development roadmap report
- 9a3b684 2026-11-09 feat(phase-1.2.4.1): final trust boundary and serialization closure
- 86b320a 2026-11-09 feat(security): close Phase 1.2.4 cryptographic conformance and legacy migration
- ddf73dd 2026-11-09 feat(security): close Phase 1.2.3 canonicalization compliance and trust compatibility
- e182796 2026-11-09 feat(trust): Phase 1.2.2 Cryptographic Canonicalization & Attestation Authority Closure

### Churn hot-spots

- `extractor/target_adapter.py` (49)
- `extractor/investigation.py` (44)
- `README.md` (44)
- `extractor/evidence_ledger.py` (41)
- `extractor/web/server.py` (37)
- `extractor/web/static/app.js` (36)
- `extractor/observation_budget.py` (34)
- `ci/workflows/test.yml` (31)
- `extractor/web/static/index.html` (30)
- `extractor/agent_runtime.py` (28)
- `extractor/adaptive_engine.py` (27)
- `extractor/watch_session.py` (27)
- `extractor/capture_backend.py` (27)
- `tests/test_ebpf_tracer.py` (26)
- `docs/EBPF_TRACING_ARCHITECTURE_PHASE1.md` (25)
