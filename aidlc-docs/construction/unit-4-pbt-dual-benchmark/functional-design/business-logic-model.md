# Business Logic Model: PBT Invariants & Clean Benchmark Verification (Unit 4)

> **Unit ID**: `unit-4-pbt-dual-benchmark`  
> **Source Files**: [tests/test_trust_boundary_pbt.py](file:///home/ubuntu/workspace/ut/tests/test_trust_boundary_pbt.py), [benchmarks/diagnosis_accuracy/run_benchmark.py](file:///home/ubuntu/workspace/ut/benchmarks/diagnosis_accuracy/run_benchmark.py)  
> **Related Stories**: `US-BENCH-001`, `US-PROCESS-001`  
> **Related Requirements**: `NFR-PBT-001`, `FR-BENCH-001 & 002`, `NFR-PROCESS-001 & 002`  

---

## 1. PBT 핵심 불변식 검증 모델 (Core Invariants Model)

Hypothesis 기반 속성 검증(Property-Based Testing)을 통해 수천 개의 무작위 생성 입력에 대해 다음 5대 불변식을 검증합니다:

1. **식별자 결정론 및 멱등성 (Determinism & Idempotency)**:
   - 동일한 입력 튜플 `(op_id, kind, host, boot_id, pid, start_time, build_id, session_id, scope, params, schema)`에 대해 `build_canonical_replay_identity`는 항상 비트 단위로 동일한 RFC 8785 정규화 JSON 및 해시를 생성.
2. **화이트리스트 불변식 (Strict Character Whitelist)**:
   - `^[a-zA-Z0-9_.:-]{1,128}\Z`에 부합하지 않는 임의의 문자열(공백, 줄바꿈, 널 바이트, 특수문자, 유니코드)은 예외 없이 `InvalidOperationIdError`를 발생.
3. **메타데이터 단조성 및 충돌 격리 (Monotonicity & Conflict Isolation)**:
   - 이미 등록된 연산 ID에 대해 상이한 `build_id`, `pid`, `process_identity`를 주입할 경우 반드시 `IdentityConflictError`가 발생하고 기존 메타데이터는 오염되지 않음.
4. **생명주기 단방향 전이 및 불변 터미널성 (One-Way Transitions & Terminal COMMITTED)**:
   - `COMMITTED` 상태에 도달한 연산은 어떠한 상태(CREATED, VALIDATED, RESERVED, EXECUTING, FAILED, CANCELLED 등)로도 재전이될 수 없음.
5. **입도 완전 분리성 (Strict Admission Partitioning)**:
   - `EvidenceLedger` 내 임의의 레코드 집합에 대해 `get_eligible_evidence()`의 반환값 중 `admission_state != ACCEPTED`인 레코드가 존재할 확률은 수학적으로 0임.

---

## 2. Clean Benchmark 검증 모델

- **Git Clean Commit 보장**:
  - `git status --porcelain` 결과 dirty 상태가 없는 깨끗한 commit SHA를 기준으로 벤치마크 메타데이터를 봉인.
- **아키텍처 메타데이터 기록**:
  - `arch` (aarch64 / x86_64), `timestamp`, `commit_sha`, `sample_count`, `target_count`를 결과 JSON에 포함.
