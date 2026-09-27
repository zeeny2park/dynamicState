# Runtime State Explorer — State Transition & Exploration Engine

GDB가 멈춘 순간의 execution context와 DWARF-aware C/C++ object graph를 관찰하고, typed field mutation·continue·snapshot·semantic diff를 통한 결정론적 상태 전이(State Transition)와 체계적인 런타임 상태 탐색(State Exploration) 및 코퍼스(State Corpus) 영속화를 제공합니다.

---

## Architecture

```text
               Coding Agent (Future Phase)
                     │
                     ▼
             Runtime State API
                     │
                     ▼
              State Explorer
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
      Snapshot    Mutation   Transition
          │          │          │
          └──────────┼──────────┘
                     ▼
                State Diff
                     │
                     ▼
              Interestingness
                     │
                     ▼
                State Corpus
                     │
                     ▼
              Next Exploration
                     │
                     ▼
                GDB Backend
                     │
                     ▼
               Product Binary
```

### Important Architecture Principle

이 시스템은 전체 heap scanner가 아닙니다. 절대로 `/proc/<pid>/mem` 전체를 읽거나 무차별 memory scanning을 하지 않습니다.

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

`/proc/<pid>/maps`는 typed root를 통해 이미 도달한 유효 주소의 storage classification(`heap`, `stack`, `global`, `unknown`)에만 사용되며, 주소 공간 탐색 목적으로 사용되지 않습니다.

---

## Current Capability

### Phase 1: Execution Context
- Thread, Frame, Arguments, Locals 추출
- DWARF type resolution 및 scalar value serialization
- call stack frame depth 및 symbol 정보 수집

### Phase 2: Persistent Object Graph
- Global / Frame root 탐색
- Pointer → `object_ref` semantic edge traversal
- Object identity `(address, canonical_type)` 기반 cycle detection 및 deduplication
- max-depth 제한 및 unreadable memory 방어
- storage classification (`heap`, `stack`, `global`, `unknown`)

### Phase 3: Deterministic State Transition Engine
- **RuntimeSnapshot (schema 0.3)**: Execution context + Persistent Object Graph + Snapshot Metadata + Transition reference 원자적 캡처
- **Typed Mutation**: DWARF-aware typed memory write (signed/unsigned integers `uint8_t`~`uint64_t`, `bool`, `float`/`double`, `enum`, `null pointer`)
- **Execution Continue**: `continue-state` (breakpoint stop, signal, exit code, timeout interrupt 감지)
- **Semantic Diff Engine**: Pure Python, order-independent semantic diff with `ObjectMatcher` abstraction (value changes, object created/removed, reference changes, execution frame changes, availability changes)
- **State Transition Engine**: `StateTransition` 1급 결과물 생성 및 JSON artifact 영속화 (`transitions/T001.json`)

### Phase 4: Runtime State Exploration & State Corpus Foundation
- **State Corpus (`extractor/state_corpus.py`)**: 흥미로운 runtime state 및 transition 아티팩트를 보존하고 관리하는 영속 저장소 (`corpus/states/`, `corpus/transitions/`, `corpus/index.json`)
- **Deterministic Semantic State Hash**: 타임스탬프, PID, 성능 지표 등 비의미론적 데이터를 배제하고 실행 컨텍스트와 도달 가능한 객체 그래프의 정규형을 기반으로 중복 상태를 감지하는 16-char SHA-256 해시
- **Interesting State Evaluation**: `NEW_STATE`, `NEW_OBJECT`, `OBJECT_REMOVED`, `REFERENCE_CHANGED`, `VALUE_CHANGE`, `CRASH`, `TIMEOUT`, `EXECUTION_CHANGE` 기준에 따른 자동 흥미도 판정
- **Exploration Engine (`extractor/explorer.py`)**: 시드 스냅샷으로부터 규칙 기반 변이 후보(`MutationCandidate`)를 생성하고, 안전하게 전이를 실행하여 흥미로운 상태를 코퍼스에 축적하는 체계적 탐색 루프
- **Failure Transitions**: 실제 타깃 프로세스에서의 결정론적 `CRASH` (`SIGSEGV`) 및 `TIMEOUT` 전이 아티팩트 지원

---

## State Transition & Object Identity

### State Transition Workflow

```text
    Snapshot A (Parent)
        │
        │ Typed Mutation
        ▼
    Product Execution (Continue with Timeout)
        │
        ▼
    Snapshot B (Child)
        │
        ▼
    Semantic Diff (DiffEngine with ObjectMatcher)
        │
        ▼
    StateTransition (Artifact: transitions/T001.json)
```

### Transition Artifact Schema

```json
{
  "transition_id": "T001",
  "parent_snapshot": "A",
  "child_snapshot": "B",
  "mutation": {
    "status": "SUCCESS",
    "target_object": "obj_0001",
    "field": "retry",
    "old_value": 2,
    "new_value": 3
  },
  "execution": {
    "status": "COMPLETED",
    "stop_reason": "breakpoint",
    "signal": null,
    "exit_code": null,
    "duration_ms": 12
  },
  "diff": {
    "summary": { "changed_fields": 2, "total_changes": 2 },
    "changes": [
      {
        "change_type": "value_changed",
        "object_id": "obj_0001",
        "field_name": "retry",
        "old_value": 2,
        "new_value": 3
      },
      {
        "change_type": "value_changed",
        "object_id": "obj_0001",
        "field_name": "state",
        "old_value": "CONNECTED",
        "new_value": "ERROR"
      }
    ]
  }
}
```

### Failure Transitions (Crash & Timeout)

전이 도중 타깃 프로세스가 크래시되거나 타임아웃이 발생한 경우에도 유효한 `StateTransition` 아티팩트가 생성됩니다:

- **Crash Transition (`SIGSEGV` 등)**:
  ```json
  {
    "transition_id": "T_CRASH",
    "parent_snapshot": "S_PRE_CRASH",
    "child_snapshot": null,
    "execution": {
      "status": "CRASHED",
      "signal": "SIGSEGV"
    },
    "diff": null
  }
  ```
- **Timeout Transition**:
  ```json
  {
    "transition_id": "T_TIMEOUT",
    "parent_snapshot": "S_PRE_TIMEOUT",
    "child_snapshot": null,
    "execution": {
      "status": "TIMEOUT",
      "duration_ms": 200
    },
    "diff": null
  }
  ```

### Object Identity: Observation vs Lifetime Identity

```text
(address, canonical_type) is used as snapshot-scoped observation identity.
It is NOT a guaranteed cross-snapshot lifetime identity.
```

- **Observation Identity**: 스냅샷 A의 `(0x2000, Session)`과 스냅샷 B의 `(0x2000, Session)`은 동일 관측 주소와 정규화된 DWARF 타입을 공유하지만, 프로세스 실행 중 메모리 해제 후 재할당(deallocation & reallocation) 여부까지 보장하는 process-lifetime identity는 아닙니다.
- **Pluggable ObjectMatcher**: `ObjectMatcher` 인터페이스를 통해 현재 기본 매처인 `AddressTypeObjectMatcher`가 적용되며, 메타데이터(`matcher.metadata()`)를 동적으로 제공합니다. 향후 `AllocationAwareObjectMatcher`, `FingerprintObjectMatcher` 등으로 손쉽게 확장할 수 있습니다.
- **Identity Metadata**:
  ```json
  {
    "strategy": "address_type",
    "scope": "snapshot",
    "confidence": "observation"
  }
  ```

---

## State Corpus & Exploration Loop

### State ID vs Snapshot ID

- **Snapshot ID (`A`, `B`, `S001`)**: 특정 실행 시점에 캡처된 원시 관측 스냅샷 파일 식별자
- **State ID (`state_000001`, `state_000002`)**: 의미론적 상태 해시(`state_hash`)를 기준으로 코퍼스에 등록된 고유 정규 상태 식별자
- **Transition ID (`trans_000001`, `T001`)**: 상태 간의 전이 결과(변이 + 실행 + 디프) 식별자

### Deterministic State Hash

`compute_state_hash(snapshot)`는 16자리 SHA-256 헥스 문자열을 생성합니다:
1. 최상위 호출 스택 프레임의 함수명 및 프레임 수
2. 도달 가능한 모든 객체의 정규화 타입 및 정렬된 주소
3. 각 객체의 정렬된 필드명, 스칼라 값, 객체 참조 관계

타임스탬프, PID, 스레드 ID, `/proc/maps` 경로 등 비의미론적(non-semantic) 데이터는 해시 계산에서 철저히 배제되어 완벽한 상태 중복 제거(deduplication)를 보장합니다.

### State Corpus Directory Structure

```text
corpus/
├── index.json
├── states/
│   ├── state_000001.json
│   └── state_000002.json
└── transitions/
    ├── trans_000001.json
    └── trans_000002.json
```

- `index.json`: 등록된 상태 해시 목록, 상태별 참조 카운트, 메타데이터 인덱스
- `states/`: 각 정규 상태의 전체 스냅샷 JSON
- `transitions/`: 각 전이의 전체 StateTransition JSON

### Interestingness Evaluation

상태 전이 후 다음 기준 중 하나 이상을 만족하면 해당 상태를 **흥미로운 상태(Interesting State)**로 평가하여 코퍼스에 저장합니다:
- `NEW_STATE`: 이전에 관측되지 않은 새로운 `state_hash` 발견
- `NEW_OBJECT`: 힙 등에 새로운 객체 동적 할당 관측
- `OBJECT_REMOVED`: 기존 객체의 메모리 해제 관측
- `REFERENCE_CHANGED`: 포인터 참조 관계 변경 관측
- `VALUE_CHANGE`: 구조체 내부 스칼라 필드값 변경 관측
- `EXECUTION_CHANGE`: 실행 함수나 호출 스택 변경 관측
- `CRASH`: 프로세스 비정상 종료 (SIGSEGV 등) 유발
- `TIMEOUT`: 실행 시간 초과 유발

---

## Usage

### 1. Build and Run Sample

```bash
# 디버그 심볼 포함 빌드
g++ -g -O0 -o sample examples/sample.cpp

# GDB 실행 및 브레이크포인트 설정
gdb -q ./sample
(gdb) source gdb/extract_state.py
(gdb) break runtime_state_checkpoint
(gdb) run
```

### 2. Phase 3 GDB Commands: State Transitions

#### High-level Transition Command:
```gdb
# Snapshot A -> Mutate -> Continue -> Snapshot B -> Diff -> Transition Artifact를 원자적으로 실행
(gdb) transition-state --object obj_0001 --field retry --value 3 --id T001 --parent A --child B --output transitions/T001.json --snapshots-dir snapshots
```

#### Individual Step Commands:
```gdb
# 1. Snapshot A 생성
(gdb) snapshot-state A --output snapshots/A.json

# 2. Typed Mutation (object_id 또는 semantic path 지원)
(gdb) mutate-state --object obj_0001 --field retry --value 3
# 또는 축약형:
(gdb) mutate-state obj_0001 retry 3
(gdb) mutate-state Session.retry 3

# 3. Execution Continue (timeout_ms 지정)
(gdb) continue-state --timeout-ms 1000

# 4. Snapshot B 생성
(gdb) snapshot-state B --output snapshots/B.json

# 5. Semantic Diff 계산
(gdb) diff-state A B --output snapshots/diff.json
# 또는 파일 경로 직접 지정:
(gdb) diff-state --before snapshots/A.json --after snapshots/B.json
```

### 3. Phase 4 GDB Commands: Exploration & State Corpus

#### Mutation Candidates Proposal:
```gdb
# 현재 스냅샷(또는 지정 스냅샷)에서 가능한 변이 후보군을 규칙 기반으로 추출
(gdb) propose-mutations
(gdb) propose-mutations A
```

#### Autonomous State Exploration:
```gdb
# 최대 N 스텝 탐색 루프 실행 (시드 등록 -> 변이 제안 -> 전이 실행 -> 흥미도 평가 -> 코퍼스 저장)
(gdb) explore-state --steps 5 --timeout-ms 1000 --corpus-dir corpus
```

#### Corpus Inspection:
```gdb
# 코퍼스에 저장된 모든 상태 목록 및 통계 확인
(gdb) corpus-list --corpus-dir corpus

# 특정 상태의 세부 스냅샷 정보 조회
(gdb) corpus-show state_000001 --corpus-dir corpus
```

### 4. Standalone CLI Diff (Outside GDB)

GDB 없이 독립된 CLI 환경에서 두 스냅샷 간의 의미론적 차이를 분석할 수 있습니다:

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

단위 테스트와 통합 테스트 스위트가 완비되어 있습니다.

```bash
# 1. Unit Tests (43 unit tests across all modules)
python3 -m unittest discover -s tests -v

# 2. Phase 1 & 2 GDB Integration Test
bash tests/integration_gdb.sh

# 3. State Transition Integration Test (End-to-End State Transition Workflow)
bash tests/integration_state_transition.sh

# 4. Mutation Validation Integration Test (10 Mutation Type & Error Validation Scenarios)
bash tests/integration_mutation_validation.sh

# 5. Transition Failure Integration Test (Real Crash [SIGSEGV] and Timeout Transitions)
bash tests/integration_transition_failure.sh

# 6. Exploration Integration Test (Seed -> Propose -> Transitions -> Corpus -> Deduplication)
bash tests/integration_exploration.sh

# 7. Phase 3 종합 Integration Test
bash tests/integration_phase3.sh
```

---

## Boundaries & Limitations (Not Yet Implemented)

본 시스템은 런타임 탐색 기반을 구축하는 단계이며, 다음 기능은 의도적으로 제외되어 있으며 향후 Phase 대상입니다:
- Autonomous LLM Coding Agent 의사결정 루프 (상위 에이전트 계층 연동)
- Edge / Branch Code Coverage 수집 및 피드백 루프
- Automatic Invariant Inference (불변식 자동 추론)
- Coverage-guided mutation prioritization
- Allocation-aware object lifetime identity (malloc/free hook)
- Frida / DynamoRIO 동적 바이너리 계측 백엔드
- 분산 타깃 탐색 및 임의 메모리 바이트 쓰기
- 자동 process restart loop (Safety 원칙에 따라 금지)
