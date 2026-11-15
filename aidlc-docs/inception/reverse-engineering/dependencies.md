# 의존성 (Dependencies)

> 기준: `main` HEAD `9b327dd` (PR #1 머지 완료).

## 내부 의존성

```mermaid
flowchart TB
    CLI["cli.py"]
    MCP["scripts/mcp_server.py"]
    WEB["web/server.py"]
    EXP["process_explainer.py"]
    AGRT["agent_runtime.py"]
    ENG["expert_diagnostic_engine.py"]
    REC["diagnostic_recipes.py, recipe_plugins/*"]
    EVID["runtime_evidence_provider.py"]
    AGG["diagnostic_verdict_aggregator.py"]
    HV["healthy_verdict.py"]
    VIS["report_visuals.py, report_registry.py"]
    WS["watch_session.py"]
    ADP["target_adapter.py"]
    ABI["target_abi.py"]
    THR["thread_sampler.py"]
    CFI["cfi_unwinder.py"]
    DW["dwarf_indexer.py"]
    CPP["cpp_containers.py"]
    REL["object_relations.py"]
    HW["heap_walker.py"]
    RCH["reachability.py"]
    LEAK["leak_attribution.py"]
    MI["memory_integrity.py"]
    UAF["uaf_detection.py"]
    HR["human_report.py, incident_report.py"]
    INV["investigation.py"]
    BUD["observation_budget.py, check_budget.py"]
    CI["collection_impact.py"]
    LED["evidence_ledger.py, session_store.py"]
    COL["target/collector (C, SSH 선로 프로토콜)"]

    CLI --> ENG
    CLI --> AGRT
    CLI --> HR
    MCP --> AGRT
    MCP --> EXP
    MCP --> HR
    WEB --> AGRT
    WEB --> HR
    EXP --> ENG
    AGRT --> ENG
    AGRT --> WS
    AGRT --> INV
    ENG --> REC
    ENG --> EVID
    ENG --> AGG
    ENG --> HV
    ENG --> ADP
    ENG --> BUD
    ENG --> CI
    ENG --> LED
    ENG --> VIS
    EVID --> REC
    EVID --> THR
    EVID --> LEAK
    EVID --> MI
    EVID --> CPP
    EVID --> REL
    EVID --> WS
    WS --> ADP
    THR --> ADP
    HW --> ADP
    MI --> ADP
    ADP --> ABI
    ADP --> COL
    HR --> VIS
```

## 외부 런타임 의존성

- `mcp` (`>=2.0.0,<3`): MCP 서버 프로토콜
- `setuptools` (`>=61`): 파이썬 패키징
- `PyYAML` (`>=6.0`, 선택 의존성 `test`): CI 워크플로 정합성 검증
