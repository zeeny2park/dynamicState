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
- **Semantic Diff Engine**: Pure Python, order-independent semantic diff (value changes, object created/removed, reference changes, execution frame changes, availability changes)
- **State Transition Model**: `StateTransition` (parent_snapshot, child_snapshot, mutation, execution, diff) 데이터 구조 확립

---

## Example Workflow

```text
    Snapshot A
        Session
          retry = 2
          state = CONNECTED
            ↓
        mutate retry = 3
            ↓
        continue
            ↓
    Snapshot B
        Session
          retry = 3
          state = ERROR
            ↓
        Semantic Diff
        retry: 2 → 3
        state: CONNECTED → ERROR
        flagged: 0 → 1
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
# Unit Tests (MemoryMaps, ObjectGraph, Serializer, Snapshot, TypeResolver, StateDiff, Mutation)
python3 -m unittest discover -s tests -v

# Phase 1 & 2 GDB Integration Test
bash tests/integration_gdb.sh

# Phase 3 GDB Integration Test (Snapshot A -> Mutate -> Continue -> Snapshot B -> Diff -> Transition)
bash tests/integration_phase3.sh
```

---

## Phase 4 Candidates

- Autonomous LLM Coding Agent integration
- Coverage-guided mutation strategy
- State corpus management and loop exploration
- Richer STL container and smart pointer traversals
- Portable TLS discovery
