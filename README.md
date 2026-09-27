# Runtime State Explorer — Branch-safe State Transition & Exploration Engine

GDB가 멈춘 순간의 execution context와 DWARF-aware C/C++ object graph를 관찰하고, typed field mutation·continue·snapshot·semantic diff를 통한 결정론적 상태 전이(State Transition)와 동일한 부모 상태(Parent State)로부터 여러 변이 후보를 독립적으로 탐색하는 Branch-safe 런타임 상태 탐색(State Exploration) 및 코퍼스(State Corpus) 영속화를 제공합니다.

---

## Architecture & Exploration Pipeline

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
      Checkpoint  Mutation  Transition
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
             State Restorer (GDB Fork Backend)
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

## Phase Distinction

- **Phase 3**: *"Can I execute and observe one deterministic state transition?"*  
  (단일 결정론적 상태 전이 실행 및 관측: Snapshot A -> Mutate -> Continue -> Snapshot B -> Diff -> StateTransition)
- **Phase 4**: *"Can the runtime engine systematically discover new states from a parent runtime state through independent mutations?"*  
  (단일 부모 상태에서 여러 변이 후보를 안전하게 복원하며 독립적인 상태 공간 가지(Branches)를 체계적으로 탐색)

---

## Branch-safe Exploration & Checkpoint Architecture

### 1. The Core Invariant

Mutation Candidate A, B, C는 **반드시 동일한 Parent State에서 독립적으로 실행**되어야 합니다.

#### ❌ 잘못된 구조 (Linear Transition Chain):
```text
S001
  │
  ├─ M1 → S002
  │         │
  │         └─ M2 → S003
  │                    │
  │                    └─ M3 → S004
```
이는 단순한 선형 전이 체인이며, M1의 결과나 부작용(또는 Crash)이 M2, M3에 누적되어 독립적인 상태 공간 탐색이 불가능합니다.

#### ✅ 올바른 구조 (Branch-safe Independent Exploration):
```text
                    S001 (Parent State)
                  /        |        \
                 /         |         \
               M1          M2         M3
               │           │          │
            restore     restore    restore
               │           │          │
              S002        S003       S004
```

각 변이 후보 실행 직전에 반드시 부모 런타임 체크포인트를 복원(`restore`)하여, 후보 A가 크래시(`SIGSEGV`)나 타임아웃(`TIMEOUT`)을 유발하더라도 다음 후보 B, C는 깨끗한 부모 상태에서 독립적으로 실행됩니다.

### 2. Semantic Snapshot vs Runtime Checkpoint

시스템은 의미론적 스냅샷과 런타임 체크포인트를 명확히 분리합니다:

| 개념 | 식별자 예시 | 역할 및 성격 |
| :--- | :--- | :--- |
| **Semantic Snapshot** | `S001`, `S002` | 특정 시점 프로세스의 관측된 실행 컨텍스트와 객체 그래프를 담은 읽기 전용 JSON 아티팩트 |
| **Runtime Checkpoint**| `C001`, `C002` | 프로세스 메모리와 레지스터를 해당 시점으로 정확히 되돌릴 수 있는 실행 런타임 복원 상태 |
| **State ID** | `state_000001` | 의미론적 상태 해시(`state_hash`)를 기준으로 코퍼스에 등록된 고유 정규 상태 |
| **Transition ID** | `T001`, `T002` | 부모 상태에서 자식 상태로의 전이 결과(변이 + 실행 + 디프) 아티팩트 |

> [!IMPORTANT]
> JSON 스냅샷 자체를 프로세스 메모리 복원 수단으로 사용하지 않습니다. 런타임 복원은 전용 `StateRestorer` 인터페이스를 통해 안전하게 수행됩니다.

### 3. Restore Backend (`extractor/state_restorer.py`)

GDB 환경에서 OS Copy-on-Write `fork()` 기반의 체크포인트 엔진(`GdbCheckpointRestorer`)을 구현했습니다:
- **Master Checkpoint**: 부모 상태 지점에서 GDB `checkpoint`로 생성되어 변경 없이 보존되는 기준 프로세스
- **Worker Clone**: 각 후보 변이 실행 직전에 Master로부터 순간적으로 포크되는 일회용 복제 프로세스
- 후보 실행 도중 `SIGSEGV` 크래시나 무한 루프(`TIMEOUT`)가 발생하더라도 Master Checkpoint는 무결하게 보존되며, 다음 후보 실행 시 새로운 Worker Clone으로 안전하게 복귀합니다.

---

## Deterministic Semantic State Hash (`extractor/state_hash.py`)

동일한 의미론적 상태는 프로세스 재시작이나 ASLR로 인해 메모리 주소가 달라져도 **동일한 16자리 SHA-256 해시**를 산출합니다.

### 배제되는 비의미론적(Non-semantic) 데이터
- 원시 힙, 스택, 전역 메모리 주소 (ASLR 독립성 보장)
- OS 스레드 ID (`thread_id`) 및 프로세스 PID
- 타임스탬프 및 성능 지표 (`*_ms`)
- `/proc/maps` 호스트 파일시스템 경로

### 정규화(Canonicalization) 원칙
1. **호출 스택**: 스레드 ID나 PC 대신 호출 스택의 함수명 시퀀스 정규화
2. **객체 그래프 위상 정렬**: 정렬된 루트(Root)들로부터의 도달 순서에 따라 위상 정규 ID(`C_0`, `C_1`, ...) 부여
3. **포인터 참조 정규화**: 메모리 주소 대신 상대적 정규 ID(`ref:C_1`), 자기 참조(`self`), 널 포인터(`null`)로 변환하여 **순환 참조(Cycle) 시의 무한 재귀를 원천 차단**

---

## Mutation Candidate Generation (`extractor/explorer.py`)

DWARF 타입 정보를 활용하여 정밀한 변이 후보군을 규칙 기반으로 생성합니다:

1. **정수형 (Type-width-aware boundaries)**:
   - `uint8_t`: `0` ~ `255` (`MAX = 255`)
   - `uint16_t`: `0` ~ `65535` (`MAX = 65535`)
   - `uint32_t`: `0` ~ `4294967295` (`MAX = 4294967295`)
   - `uint64_t`: `0` ~ `18446744073709551615`
   - 부호 있는 정수(`int8_t`~`int64_t`): 실제 비트 폭에 따른 `MIN` / `MAX`
   - 후보 생성 규칙: `val - 1`, `val + 1`, `0`, `1`, `MAX`, `MIN` (범위 내 값만 생성, 언더플로우 및 중복 제거)
2. **열거형 (Enum)**:
   - DWARF 메타데이터를 파싱하여 심볼릭 멤버 목록 추출
   - 현재 값 이외의 대체 심볼릭 멤버 후보 생성 (예: `CONNECTED` -> `DISCONNECTED`, `ERROR`)
3. **포인터 (Pointer)**:
   - 임의 주소 쓰기를 금지하고 안전한 `null` / `nullptr` 변이만 허용
4. **부울 (Boolean)**:
   - `true` <-> `false` 토글
5. **부동소수점 (Floating Point)**:
   - 유한수(finite) 경계값: `0.0`, `1.0`, `-1.0`, `val - 1.0`, `val + 1.0`

---

## State Corpus & Exploration Artifacts

### Directory Structure

```text
corpus/
├── index.json
├── states/
│   ├── state_000001/
│   │   ├── snapshot.json
│   │   └── metadata.json
│   └── state_000002/
├── transitions/
│   ├── T001.json
│   └── T002.json
└── explorations/
    └── E000001.json
```

### Exploration Artifact Schema (`corpus/explorations/E000001.json`)

```json
{
  "exploration_id": "E000001",
  "seed_state_id": "state_000001",
  "seed_snapshot_id": "S001",
  "parent_checkpoint_id": "C001",
  "steps": 3,
  "summary": {
    "candidates": 6,
    "executed": 3,
    "new_states": 2,
    "duplicate_states": 1,
    "crashes": 0,
    "timeouts": 0
  },
  "performance": {
    "checkpoint_creation_ms": 5.21,
    "candidate_generation_ms": 1.15,
    "total_time_ms": 48.32,
    "avg_step_ms": 16.1,
    "step_metrics": [
      {
        "candidate_id": "M0001",
        "transition_id": "T001",
        "restore_ms": 4.12,
        "step_ms": 15.3,
        "status": "STOPPED",
        "child_state_id": "state_000002",
        "interesting": true,
        "reasons": ["VALUE_CHANGE", "NEW_STATE"]
      }
    ]
  },
  "states": ["state_000001", "state_000002"],
  "transitions": ["T001", "T002", "T003"],
  "new_states": ["state_000002"],
  "crashes": [],
  "timeouts": []
}
```

---

## Usage

### 1. Build and Run Target

```bash
g++ -g -O0 -o sample examples/sample.cpp
gdb -q ./sample
(gdb) source gdb/extract_state.py
(gdb) break runtime_state_checkpoint
(gdb) set args 10
(gdb) run
```

### 2. GDB Commands

#### High-level Transition Command:
```gdb
# Snapshot A -> Mutate -> Continue -> Snapshot B -> Diff -> Transition Artifact를 실행
(gdb) transition-state --object obj_0001 --field retry --value 3 --id T001 --parent A --child B --output transitions/T001.json
```

#### Mutation Candidates Proposal:
```gdb
# 현재 스냅샷에서 가능한 변이 후보군을 규칙 기반으로 추출
(gdb) propose-mutations
```

#### Branch-safe State Exploration:
```gdb
# 부모 체크포인트를 안전하게 유지하며 최대 N 스텝 독립 변이 탐색 실행
(gdb) explore-state --steps 5 --timeout-ms 1000 --corpus-dir corpus
```

#### Corpus Inspection:
```gdb
(gdb) corpus-list --corpus-dir corpus
(gdb) corpus-show state_000001 --corpus-dir corpus
```

---

## Testing

```bash
# 1. 단위 테스트 (53 unit tests across all modules)
python3 -m unittest discover -s tests -v

# 2. Phase 1 & 2 GDB 기본 통합 테스트
bash tests/integration_gdb.sh

# 3. 상태 전이 E2E 통합 테스트
bash tests/integration_state_transition.sh

# 4. 타입 변이 및 유효성 검증 테스트
bash tests/integration_mutation_validation.sh

# 5. 크래시(SIGSEGV) 및 타임아웃 전이 테스트
bash tests/integration_transition_failure.sh

# 6. 코퍼스 저장 및 중복 제거 탐색 테스트
bash tests/integration_exploration.sh

# 7. Branch-safe 독립 후보 전이 통합 테스트 (신규)
bash tests/integration_exploration_branching.sh

# 8. Phase 3 종합 통합 테스트
bash tests/integration_phase3.sh
```

---

## Boundaries & Known Limitations

- **Multi-thread Nondeterminism**: 다중 스레드 레이스 컨디션에 따른 비결정론적 스케줄링은 현재 싱글 스레드/중단점 컨텍스트에 초점이 맞춰져 있습니다.
- **External I/O & Socket State**: 프로세스 외부 커널 소켓 연결이나 원격 RPC 상태는 OS fork만으로 완전 롤백되지 않습니다.
- **Optimized Binaries (-O2/-O3)**: 컴파일러 인라인화 및 레지스터 할당으로 DWARF 위치 표현식이 `<optimized out>`인 필드는 변이가 제한됩니다.
- **Automated Restart Loop**: 무제한 프로세스 재생성 루프는 안전성 원칙에 따라 방지되며, 최대 탐색 스텝(`max_steps`)과 타임아웃 제한이 적용됩니다.
