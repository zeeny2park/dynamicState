# Dependency inventory

## Manifests

- `requirements.txt`: 0 deps, pinning {}

## Lockfiles

- none

## Internal component graph (depth 2, 1172 file edges)

- `benchmarks` -> `extractor` (3)
- `benchmarks/investigation_quality` -> `extractor` (7)
- `examples` -> `extractor` (3)
- `extractor/web` -> `extractor` (7)
- `gdb` -> `extractor` (4)
- `scripts` -> `extractor` (10)
- `tests` -> `benchmarks` (1), `benchmarks/investigation_quality` (2), `extractor` (858), `extractor/web` (44), `scripts` (25)

Lazy (function-local/conditional) Python imports excluded from cycles: 153

## Component cycles

- none detected

## File-level cycles

- none detected

## Highest fan-in

- `extractor/target_adapter.py` (84)
- `extractor/evidence_ledger.py` (82)
- `extractor/capture_backend.py` (73)
- `extractor/agent_runtime.py` (61)
- `extractor/observation_budget.py` (60)
- `extractor/debug_image.py` (56)
- `extractor/investigation.py` (46)
- `extractor/web/server.py` (45)
- `extractor/watch_session.py` (40)
- `extractor/hypothesis.py` (31)
- `extractor/expert_diagnostic_engine.py` (30)
- `extractor/diagnostic_recipes.py` (26)
- `extractor/dwarf_indexer.py` (25)
- `scripts/mcp_server.py` (25)
- `extractor/adaptive_engine.py` (24)
