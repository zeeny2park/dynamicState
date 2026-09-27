# Runtime State Explorer — Phase 3 State Transition Engine

GDB가 멈춘 순간의 execution context와 DWARF-aware C/C++ object graph를 관찰하고, typed field mutation·continue·snapshot·semantic diff를 제공합니다. Phase 3는 deterministic runtime engine이며 Agent, fuzzing, coverage, invariant inference는 Phase 4 대상입니다.

## Architecture

```text
    Coding Agent
          │
          ▼
    Runtime State API
          │
          ▼
    Runtime State Engine
          │
          ├── Execution Context
          ├── Object Graph
          ├── Snapshot
          ├── Mutation
          └── Semantic Diff
          │
          ▼
    GDB Backend
          │
          ▼
    Product Binary
```

### Important Architecture Principle

이 시스템은 전체 heap scanner가 아닙니다. 절대로 `/proc/<pid>/mem` 전체를 읽거나 무차별 scanning을 하지 않습니다.

```text
Typed Roots (Global / Static / Frame Locals / Arguments)
    ↓
DWARF Type Resolution
    ↓
Field Metadata
    ↓
Pointer Dereference
    ↓
Target Object Identification (address, canonical_type)
    ↓
Recursive Semantic Reachability Traversal
```

`/proc/<pid>/maps`는 typed root를 통해 이미 도달한 주소의 storage classification(heap, stack, global, unknown)에만 사용되며, 주소 공간 탐색 목적으로 사용되지 않습니다.

---

## Current Capability

### Phase 1: Execution Context
- Thread, Frame, Arguments, Locals 추출
- DWARF type resolution 및 scalar value serialization

### Phase 2: Persistent Object Graph
- Global / Frame root 탐색
- Pointer → object_ref semantic edge traversal
- Object identity `(address, canonical_type)` 기반 cycle detection 및 deduplication
- max-depth 제한 및 unreadable memory 방어
- storage classification (`heap`, `stack`, `global`, `unknown`)

### Phase 3: Runtime Snapshot + Typed Mutation + State Transition + Semantic Diff
- **RuntimeSnapshot (schema 0.3)**: Execution context + Persistent Object Graph + Snapshot Metadata + Transition record 원자적 캡처
- **Typed Mutation**: DWARF-aware typed memory write (signed/unsigned integers `uint8_t`~`uint64_t`, `bool`, `float`/`double`, `enum`, `null pointer`)
- **Execution Continue**: `continue-state` (breakpoint stop, signal, exit code, timeout interrupt 감지)
- **Semantic Diff Engine**: Pure Python, order-independent semantic diff with `ObjectMatcher` abstraction (value changes, object created/removed, reference changes, execution frame changes, availability changes)
- **State Transition Engine**: `StateTransition` 1급 결과물 생성 및 JSON artifact 영속화 (`transitions/T001.json`)

---

## State Transition & Object Identity

### State Transition Workflow

```text
    Snapshot A
        │
        │ Typed Mutation
        ▼
    Product Execution
        │
        ▼
    Snapshot B
        │
        ▼
    Semantic Diff
        │
        ▼
    StateTransition (Artifact: transitions/T001.json)
```

### Object Identity

```text
(address, canonical_type) is used as snapshot-scoped observation identity.
It is NOT a guaranteed cross-snapshot lifetime identity.
```

- **Observation Identity vs Lifetime Identity**: 스냅샷 A의 `(0x2000, Session)`과 스냅샷 B의 `(0x2000, Session)`은 동일 관측 주소와 정규화된 DWARF 타입을 공유하지만, 프로세스 실행 중 재할당(deallocation & reallocation) 여부까지 보장하는 process-lifetime identity는 아닙니다.
- **Pluggable ObjectMatcher**: `ObjectMatcher` 인터페이스를 통해 현재 기본 매처인 `AddressTypeObjectMatcher`가 적용되며, 향후 Phase 4에서 `AllocationAwareObjectMatcher`, `RootPathObjectMatcher` 등으로 손쉽게 확장할 수 있습니다.
- **Identity Metadata**: 각 객체 및 diff change 레코드에 `identity: {"strategy": "address_type", "scope": "snapshot", "confidence": "observation"}` 메타데이터가 명시됩니다.

### Transition Artifact Directory

```text
    snapshots/
        S001.json
        S002.json

    transitions/
        T001.json
```

---

## Example Workflow

```text
    Session.retry = 2
    Session.state = CONNECTED
    Session.flagged = false

          ↓

    mutate retry = 3

          ↓

    continue

          ↓

    Session.retry = 3
    Session.state = ERROR
    Session.flagged = true

          ↓

    StateTransition (T001)
```

---

## Usage

### 1. Build and Run Sample

```bash
g++ -g -O0 -o sample examples/sample.cpp
gdb -q ./sample
(gdb) source gdb/extract_state.py
(gdb) break runtime_state_checkpoint
(gdb) run
```

### 2. Phase 3 GDB Commands

#### High-level Transition Command:
```gdb
# Snapshot A -> Mutate -> Continue -> Snapshot B -> Diff -> Transition Artifact를 한 번에 실행
(gdb) transition-state --object obj_0001 --field retry --value 3 --id T001 --parent A --child B --output transitions/T001.json --snapshots-dir snapshots
```

#### Individual Step Commands:
```gdb
# 1. Snapshot A 생성
(gdb) snapshot-state A --output snapshots/A.json

# 2. Typed Mutation (object_id 또는 semantic path 지원)
(gdb) mutate-state --object obj_0001 --field retry --value 3
# 또는 positional:
(gdb) mutate-state obj_0001 retry 3
(gdb) mutate-state Session.retry 3

# 3. Execution Continue
(gdb) continue-state --timeout-ms 1000

# 4. Snapshot B 생성
(gdb) snapshot-state B --output snapshots/B.json

# 5. Semantic Diff 계산
(gdb) diff-state A B --output snapshots/diff.json
# 또는 파일 경로 지정:
(gdb) diff-state --before snapshots/A.json --after snapshots/B.json
```

### 3. Standalone CLI Diff (Outside GDB)

```bash
python3 -m extractor.state_diff --before snapshots/A.json --after snapshots/B.json --output snapshots/diff.json
```

---

## Supported Types & Mutations

### Supported Mutation Types
- **Integers**: `int8_t`, `int16_t`, `int32_t`, `int64_t`, `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t` (엄격한 range validation 적용)
- **Boolean**: `bool` (`true`/`false`, `1`/`0`)
- **Enum**: Qualified name (예: `SessionState::ERROR`), unqualified name (예: `ERROR`), 또는 underlying integer
- **Floating Point**: `float`, `double` (finite number 검증)
- **Pointer**: `null` / `nullptr` / `0` 으로의 초기화 지원 (임의 raw memory address mutation은 안전을 위해 차단)

### Error Codes
- `PROCESS_NOT_STOPPED`: Inferior가 running 상태일 때 mutation/snapshot 시도
- `OBJECT_NOT_FOUND`: 최신 snapshot에 해당 object가 없을 때
- `FIELD_NOT_FOUND`: DWARF metadata에 해당 field가 없을 때
- `AMBIGUOUS_OBJECT`: semantic path (예: `Session.retry`) 매칭 객체가 2개 이상일 때
- `TYPE_CONVERSION_ERROR`: 타입 변환 실패 (예: 문자열 "hello"를 int에 대입)
- `RANGE_ERROR`: 타입 범위를 벗어난 값 대입 (예: `uint8_t`에 999 또는 음수 대입)
- `UNSUPPORTED_TYPE`: struct/class 전체 write 또는 nested field mutation 시도

---

## Testing

```bash
# 1. Unit Tests (MemoryMaps, ObjectGraph, Serializer, Snapshot, TypeResolver, StateDiff, Mutation)
python3 -m unittest discover -s tests -v

# 2. Phase 1 & 2 GDB Integration Test
bash tests/integration_gdb.sh

# 3. State Transition Integration Test (End-to-End State Transition Workflow)
bash tests/integration_state_transition.sh

# 4. Mutation Validation Integration Test (10 Mutation Type & Error Validation Scenarios)
bash tests/integration_mutation_validation.sh

# 5. Phase 3 종합 Integration Test
bash tests/integration_phase3.sh
```

---

## Phase 4 Boundary & Candidates

Phase 3의 책임은 **결정론적 Runtime State Transition Engine** 구축이며, autonomous exploration은 Phase 4에서 진행합니다.

### Phase 4 Candidates
- Autonomous LLM Coding Agent integration (`observe`, `mutate`, `continue`, `diff`, `execute_transition`)
- Coverage-guided mutation strategy
- State corpus management and loop exploration
- Richer STL container and smart pointer traversals
- Portable TLS discovery
