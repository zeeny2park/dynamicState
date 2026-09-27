# Runtime State Explorer — Branch-safe State Transition & Exploration Engine

> [!NOTE]
> **Status: `EXTERNAL_DEBUG_IMAGE_FOUNDATION_COMPLETE`** — External Debug Image Support for Stripped Production Binaries  
> Verified with 81 Unit Tests and 11 GDB E2E Integration Test Suites.

GDB가 멈춘 순간의 execution context와 DWARF-aware C/C++ object graph를 관찰하고, typed field mutation·continue·snapshot·semantic diff를 통한 결정론적 상태 전이(State Transition)와 동일한 부모 상태(Parent State)로부터 여러 변이 후보를 독립적으로 탐색하는 Branch-safe 런타임 상태 탐색(State Exploration) 및 코퍼스(State Corpus) 영속화를 제공합니다.

나아가 실제 CI/CD 및 프로덕션 환경에서 배포되는 **Stripped Production Binary**를 그대로 실행하면서, 동일 빌드의 **External Debug Image**(unstripped artifact / split DWARF)를 바인딩하여 안전하고 결정론적인 런타임 상태 추출·변이·탐색을 수행합니다.

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
          ┌──────────┴──────────┐
          ▼                     ▼
Stripped Production Binary  External Debug Image
(/proc/<pid>/mem, /proc/exe) (DWARF & Symbols only)
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

## Phase Distinction & Progress

- **Phase 3**: *"Can I execute and observe one deterministic state transition?"*  
  (단일 결정론적 상태 전이 실행 및 관측: Snapshot A -> Mutate -> Continue -> Snapshot B -> Diff -> StateTransition)
- **Phase 4**: *"Can the runtime engine systematically discover new states from a parent runtime state through independent mutations?"*  
  (단일 부모 상태에서 여러 변이 후보를 안전하게 복원하며 독립적인 상태 공간 가지(Branches)를 체계적으로 탐색)
- **Phase 4.1**: *"Validation & Hardening — Real GDB Checkpoints, Crash/Timeout Isolation, and Semantic Determinism"*  
  (GDB 체크포인트 에러 코드 명시화, 자율적 `StateExplorer.run()` 오케스트레이션, `SIGSEGV`/`TIMEOUT` 장애 격리, ASLR 및 Storage-Class 무관 상태 해시, Runtime Capabilities API 및 안전 한계 적용)
- **External Debug Image Foundation (Complete)**: *"Production-Grade Stripped Binary Execution with External Debug Images"*  
  (실제 프로덕션 환경의 stripped 바이너리를 변경 없이 실행하면서 동일 빌드의 외부 unstripped/debug 이미지를 바인딩하여 런타임 상태 추출, 변이, 전이, 탐색을 온전히 수행. GNU Build ID 검증, 아키텍처 호환성 검사, 런타임 프로세스 메모리 격리 보장, 스냅샷 출처(Provenance) 추적)

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

### 3. Restore Backend & GDB Checkpoint Hardening (`extractor/state_restorer.py`)

GDB 환경에서 OS Copy-on-Write `fork()` 기반의 체크포인트 엔진(`GdbCheckpointRestorer`)을 구현 및 강화했습니다:
- **Master Checkpoint**: 부모 상태 지점에서 GDB `checkpoint`로 생성되어 변경 없이 보존되는 기준 프로세스
- **Worker Clone**: 각 후보 변이 실행 직전에 Master로부터 순간적으로 포크되는 일회용 복제 프로세스
- **Crash & Timeout Isolation**: 후보 실행 도중 `SIGSEGV` 크래시나 무한 루프(`TIMEOUT`)가 발생하더라도 Master Checkpoint는 무결하게 보존됩니다.
- **Signal Leakage Prevention**: GDB `signal 0` 재개를 통해 이전 후보에서 발생한 `SIGSEGV`나 인터럽트 신호가 새로 복제된 Worker에 누출되어 즉시 비정상 종료되는 현상을 원천 차단했습니다.
- **Explicit Structured Error Codes**:
  - `CHECKPOINT_CREATE_FAILED`: GDB 체크포인트 포크 실패
  - `CHECKPOINT_NOT_FOUND`: 요청한 체크포인트 ID가 등록되지 않음
  - `CHECKPOINT_RESTORE_FAILED`: Master 체크포인트 재시작 또는 Worker 복제 실패
  - `CHECKPOINT_RELEASE_FAILED`: 체크포인트 프로세스 해제 실패
  - `CHECKPOINT_STATE_INVALID`: Inferior가 실행 중이거나 디스크립터가 유효하지 않음
  - `CHECKPOINT_LIMIT_REACHED`: 최대 체크포인트 제한(`max_checkpoints`) 초과
- **Safe Release Cycle**: GDB가 현재 활성 체크포인트 삭제를 거부하는 제약을 처리하기 위해, 삭제 전 Master 또는 루트 프로세스로 컨텍스트를 안전하게 전환 후 Worker와 Master를 순차 해제합니다.

---

## Deterministic Semantic State Hash (`extractor/state_hash.py`)

동일한 의미론적 상태는 프로세스 재시작이나 ASLR로 인해 메모리 주소나 물리적 저장 영역이 달라져도 **동일한 16자리 SHA-256 해시**를 산출합니다.

### 배제되는 비의미론적(Non-semantic) 데이터
- 원시 힙, 스택, 전역 메모리 주소 (ASLR 독립성 보장)
- 물리적 메모리 저장소 구분 (`storage`: `heap` vs `stack` 메모리 레이아웃 독립성 보장)
- 관측 단위 객체 레이블 (`object_id`: `obj_0001` 라벨 변경에 무관)
- OS 스레드 ID (`thread_id`) 및 프로세스 PID
- 타임스탬프 및 성능 지표 (`*_ms`)
- `/proc/maps` 호스트 파일시스템 경로

### 정규화(Canonicalization) 원칙
1. **호출 스택**: 스레드 ID나 PC 대신 호출 스택의 함수명 시퀀스 정규화 (스레드 목록 순서 독립적)
2. **필드 순서 정규화**: DWARF 선언 순서나 메모리 오프셋에 영향받지 않도록 필드명을 알파벳순 정렬
3. **객체 그래프 위상 정렬**: 정렬된 루트(Root)들로부터의 BFS 도달 순서에 따라 위상 정규 ID(`C_0`, `C_1`, ...) 부여
4. **포인터 참조 정규화**: 메모리 주소 대신 상대적 정규 ID(`ref:C_1`), 자기 참조(`self`), 널 포인터(`null`)로 변환하여 **순환 참조(Cycle) 시의 무한 재귀를 원천 차단**

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

## External Debug Image Architecture for Stripped Production Binaries

실제 CI/CD 및 프로덕션 환경에서는 보안 및 용량 최적화를 위해 바이너리가 완전히 `strip`되어 배포됩니다. dynamicState는 실행 중인 stripped 바이너리의 런타임 메모리를 변경 없이 관찰하면서, 동일 빌드의 unstripped 아티팩트(External Debug Image)로부터 심볼과 DWARF 구조체를 안전하게 바인딩합니다.

```text
    Runtime Binary
        │ 실제 실행 (/proc/<pid>/mem, /proc/<pid>/exe, registers)
        ▼
   Stripped Production Binary
        │
        ▼
       GDB Backend ───────────────┐ (Zero memory reads from debug image)
        ▲                         │
        │ DWARF / Types / Symbols │
        │ Strict GNU Build ID     ▼
   External Debug Image     Runtime State Engine
   (Unstripped / Split DWARF)  (Snapshot, Mutation, Transition, Exploration)
```

### Core Invariants & Safety Guarantees

1. **Process Memory as Single Source of Truth**:
   - 런타임 상태 값(Primitive, Pointer, Enum, String 등)은 **오직 실행 중인 프로세스 메모리 및 레지스터**에서만 읽습니다.
   - 외부 디버그 이미지 파일의 데이터 섹션이나 정적 메모리는 결코 상태 값의 소스로 사용되지 않습니다.

2. **Strict GNU Build ID & Architecture Verification**:
   - 런타임 바이너리와 외부 디버그 이미지는 ELF 헤더 및 `.note.gnu.build-id`를 대조하여 엄격히 검증됩니다.
   - 불일치 시 상태 추출을 즉시 거부하며 명확한 에러 코드를 반환합니다:
     - `BUILD_ID_MISMATCH`: 동일 아키텍처이나 빌드 해시가 불일치함
     - `ARCHITECTURE_MISMATCH`: ELF 클래스(32/64), 아키텍처(x86_64, aarch64 등), 엔디언 불일치
     - `BUILD_ID_NOT_AVAILABLE`: Build ID가 누락되고 `.gnu_debuglink`가 불일치함
     - `DEBUG_INFO_MISSING`: 디버그 이미지에 DWARF 정보(`.debug_*`) 및 심볼이 존재하지 않음

3. **Zero-Dependency ELF Inspector**:
   - `extractor/debug_image.py`는 `readelf`나 `pyelftools` 등 외부 패키지에 의존하지 않고, 순수 파이썬 struct 기반으로 ELF32/ELF64 헤더, PT_NOTE, `.note.gnu.build-id`, `.gnu_debuglink`, 섹션 헤더를 직접 파싱하여 < 1ms 내에 검증을 완료합니다.

4. **Snapshot Provenance Tracking**:
   - 모든 스냅샷과 상태 전이 아티팩트는 출처 메타데이터를 보존합니다:
     ```json
     "provenance": {
       "runtime_binary": {
         "path": "/opt/app/bin/server",
         "build_id": "d100266b036d9ecf7280e3e01eb5fd541d1cb348",
         "architecture": "aarch64",
         "elf_class": "ELF64",
         "stripped": true
       },
       "debug_image": {
         "path": "/opt/debug/server.debug",
         "build_id": "d100266b036d9ecf7280e3e01eb5fd541d1cb348",
         "source": "external",
         "verified": true,
         "compatible": true,
         "reason": "COMPATIBLE"
       },
       "performance": {
         "debug_image_load_ms": 0.35,
         "binary_identity_check_ms": 0.21,
         "debug_image_verification_ms": 0.58
       }
     }
     ```

5. **State Hash Invariance**:
   - 의미론적 상태 해시(`SemanticStateHash`)는 실행 바이너리의 파일 경로, stripped 여부, 디버그 이미지 경로, Build ID에 **완전히 독립적**입니다.
   - 동일한 논리적 런타임 상태는 unstripped 로컬 바이너리에서 추출하든 stripped 프로덕션 바이너리+외부 디버그 이미지에서 추출하든 100% 동일한 SHA-256 해시를 산출합니다.

---

## Usage

### 1. Build and Run Target with External Debug Image

CI/CD 파이프라인에서 분리된 디버그 이미지 생성 및 GDB 실행 예시:

```bash
# 1. 빌드 및 디버그 심볼 분리
g++ -g -O0 -o sample examples/sample.cpp
objcopy --only-keep-debug sample sample.debug
strip -s -o sample_stripped sample

# 2. GDB 실행 및 외부 디버그 이미지 로드
gdb -q ./sample_stripped
(gdb) source gdb/extract_state.py
(gdb) load-debug-image ./sample.debug
(gdb) break runtime_state_checkpoint
(gdb) set args 10
(gdb) run
```

### 2. GDB Commands

#### Binary Identity & Capabilities Inspection:
```gdb
# 런타임 바이너리와 디버그 이미지의 호환성 및 Build ID 검사
(gdb) runtime-info
(gdb) runtime-info --json
```

#### External Debug Image Binding:
```gdb
# 외부 디버그 이미지 로드 및 엄격 검증
(gdb) load-debug-image /path/to/sample.debug
```

#### State Extraction with Debug Image:
```gdb
(gdb) extract-state --output snapshot.json
# 또는 명시적 디버그 이미지 지정:
(gdb) extract-state --debug-image /path/to/sample.debug --output snapshot.json
```

#### High-level Transition Command:
```gdb
# Snapshot A -> Mutate -> Continue -> Snapshot B -> Diff -> Transition Artifact를 실행
(gdb) transition-state --object obj_0001 --field retry --value 3 --id T001 --parent A --child B --output transitions/T001.json
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

### 3. Programmatic Python API (Agent & Script Usage)

상위 계층(예: 자율 탐색 스크립트 또는 향후 연동될 Coding Agent)은 `StateExplorer` 및 `RuntimeController` API를 직접 호출하여 프로덕션 바이너리를 제어할 수 있습니다:

```python
import runtime_commands
from extractor.state_corpus import StateCorpus
from extractor.explorer import StateExplorer

# 1. 런타임 컨트롤러 초기화 및 외부 디버그 이미지 로드
controller = runtime_commands._CONTROLLER
controller.load_debug_image("/path/to/sample.debug")

# 2. 런타임 정보 및 출처 검증
info = controller.runtime_info()
assert info["debug_image"]["compatible"] is True

# 3. 코퍼스 및 탐색기 초기화
corpus = StateCorpus("corpus")
explorer = StateExplorer(controller, corpus, "corpus")

# 4. 초기 런타임 상태 관측 및 시드 상태 등록
seed_state_id = explorer.seed()

# 5. 브랜치 안전 자율 상태 공간 탐색 실행
result = explorer.run(max_steps=10, timeout_ms=1000)

print("Exploration ID:", result["exploration_id"])
print("New states found:", result["summary"]["new_states"])
print("Crashes detected:", result["summary"]["crashes"])
print("Timeouts detected:", result["summary"]["timeouts"])
```

---

## Runtime Capabilities & Safety Limits

### 1. Capabilities API (`extractor/runtime_controller.py`)

상위 에이전트 및 컨트롤러 계층이 현재 백엔드의 지원 기능을 프로그래밍 방식으로 질의할 수 있습니다:

```python
caps = controller.get_capabilities()
# RuntimeCapabilities(
#     checkpoint=True,
#     restore=True,
#     typed_mutation=True,
#     semantic_snapshot=True,
#     semantic_diff=True,
#     state_hash=True,
#     branch_exploration=True,
#     crash_recovery=True,
#     timeout_recovery=True,
#     external_debug_image=True,
#     multi_thread_determinism=False,
#     external_io_rollback=False,
#     exploration_mode="deterministic_single_thread_context",
#     backend="gdb_fork"
# )
```

### 2. Exploration Safety Limits

- **`max_steps`** (기본값: 10): 단일 탐색 세션 동안 실행할 최대 변이 스텝 수
- **`max_candidates`** (기본값: 50): 단일 상태에서 생성할 수 있는 최대 변이 후보 수
- **`max_corpus_states`** (기본값: 100): 코퍼스에 저장 가능한 최대 고유 상태 수
- **`max_checkpoints`** (기본값: 10): 동시에 유지 가능한 최대 런타임 체크포인트 수
- **`timeout_ms`** (기본값: 1000ms): 자식 브랜치 실행 지속 시간 상한 (무한 루프 방지)

---

## Testing

모든 단위 테스트와 11개의 GDB 종단간 통합 테스트 스크립트가 완전히 통과합니다:

```bash
# 1. 단위 테스트 (81 unit tests across all modules)
python3 -m unittest discover -s tests -v

# 2. Phase 1 & 2 GDB 기본 통합 테스트
bash tests/integration_gdb.sh

# 3. Phase 3 상태 전이 E2E 통합 테스트
bash tests/integration_state_transition.sh

# 4. Phase 3 타입 변이 및 유효성 검증 테스트
bash tests/integration_mutation_validation.sh

# 5. Phase 3 크래시(SIGSEGV) 및 타임아웃 전이 테스트
bash tests/integration_transition_failure.sh

# 6. Phase 3 종합 통합 테스트
bash tests/integration_phase3.sh

# 7. Phase 4 코퍼스 저장 및 중복 제거 탐색 테스트
bash tests/integration_exploration.sh

# 8. Phase 4 Branch-safe 독립 후보 전이 통합 테스트
bash tests/integration_exploration_branching.sh

# 9. Phase 4.1 StateExplorer.run() 자율 브랜칭 GDB 통합 테스트
bash tests/integration_explorer_real_gdb.sh

# 10. Phase 4.1 크래시/타임아웃 장애 격리 GDB 통합 테스트
bash tests/integration_explorer_failure_isolation.sh

# 11. External Debug Image 호환성/Build-ID 불일치 거부 및 상태 추출 통합 테스트 (신규)
bash tests/integration_stripped_debug_image.sh

# 12. Stripped 바이너리 상태 전이 및 상태 공간 탐색 통합 테스트 (신규)
bash tests/integration_stripped_transition.sh
```

---

## Boundaries & Known Limitations

- **Multi-thread Nondeterminism**: 다중 스레드 레이스 컨디션에 따른 비결정론적 스케줄링은 현재 싱글 스레드/중단점 컨텍스트에 초점이 맞춰져 있습니다.
- **External I/O & Socket State**: 프로세스 외부 커널 소켓 연결이나 원격 RPC 상태는 OS fork만으로 완전 롤백되지 않습니다.
- **Optimized Binaries (-O2/-O3)**: 컴파일러 인라인화 및 레지스터 할당으로 DWARF 위치 표현식이 `<optimized out>`인 필드는 변이가 제한됩니다.
- **Automated Restart Loop**: 무제한 프로세스 재생성 루프는 안전성 원칙에 따라 방지되며, 최대 탐색 스텝(`max_steps`)과 타임아웃 제한이 적용됩니다.

