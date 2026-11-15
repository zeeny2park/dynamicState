# Performance Validation Plan

> **Stage**: OPERATIONS - Performance Validation  
> **Target System**: dynamicState Diagnosis Engine  
> **Environment**: Linux aarch64 (Oracle Cloud), Python 3.12.3, GCC 13.3.0  
> **Related NFRs**: `NFR-PERF-001`, `NFR-RESILIENCY-001`, `FR-BENCH-001 ~ 003`  

---

## 1. 개요 (Overview)

본 계획은 dynamicState 진단 엔진의 성능 목표(NFR) 및 복원력 제약을 실제 런타임 환경에서 정량적으로 측정하고 검증하기 위한 부하 및 벤치마크 테스트 절차를 정의합니다.

---

## 2. 성능 검증 작업 체크리스트 (Performance Validation Checklist)

### 2.1 계획 및 질문 수립
- [x] 이전 NFR 요구사항(`NFR-PERF-001`, `NFR-RESILIENCY-001`) 및 벤치마크 인프라 분석
- [x] Performance Validation 계획 및 명확화 질문 작성 (`aidlc-docs/operations/plans/performance-validation-plan.md`)
- [ ] 사용자 답변 수집 및 모호성 해소

### 2.2 부하 테스트 설계 및 실행
- [ ] `aidlc-docs/operations/performance-validation/load-test-plan.md` 작성
- [ ] 마이크로 벤치마크 실행 (Operation ID 검증 100,000회 지연시간 분포 측정: p50, p90, p99)
- [ ] 동시성 부하 테스트 실행 (Multi-threaded lock contention & 5.0s timeout safety)
- [ ] 진단 정확도 벤치마크 실행 (`benchmarks/diagnosis_accuracy/run_benchmark.py` 타깃 실행시간 측정)

### 2.3 산출물 생성 및 판정
- [ ] `aidlc-docs/operations/performance-validation/test-results.md` (지연 시간, 처리량, 오류율, 병목 분석)
- [ ] `aidlc-docs/operations/performance-validation/nfr-validation-matrix.md` (NFR 목표 대비 실측 대조표)
- [ ] 완료 보고서 및 최종 승인 대기

---

## 3. 성능 검증 명확화 질문 (Clarification Questions)

성능 검증의 측정 범위와 판정 기준을 확정하기 위해 다음 3가지 질문에 답변해 주시기 바랍니다. 권장안(`Option A`)을 기본값으로 표기해 두었습니다.

### Question 1: 성능 검증 대상 워크로드 및 벤치마크 프로토콜
시스템의 성능과 복원력을 다각도로 검증하기 위해 어떤 워크로드 프로토콜을 채택하시겠습니까?

- **Option A (권장 / Recommended)**: 3단계 종합 부하 검증
  1. **초경량 마이크로 벤치마크**: `validate_operation_id` 및 in-memory Canonical Identity 비교 100,000회 반복 측정 (p50, p90, p99 실측치 대조, NFR-PERF-001 p99 < 50 µs 검증).
  2. **동시성 경합 부하 테스트**: 다중 스레드 동시 접근 환경에서 1,000회 트랜잭션 수행 시 Lock 경합 지연 및 5.0초 타임아웃 안전성 검증.
  3. **실제 진단 파이프라인 벤치마크**: `benchmarks/diagnosis_accuracy/run_benchmark.py` 대표 타깃 대상 진단 소요 시간 및 메모리 오버헤드 실측.
- **Option B**: 마이크로 벤치마크(Operation ID 100k)만 단독 수행.
- **Option C**: 실제 진단 벤치마크만 단독 수행.

[Answer]: A

---

### Question 2: 지연 시간 백분위(Latency Percentile) 합격 기준
성능 합격 판정을 위한 SLA 임계치로 어떤 기준을 적용하시겠습니까?

- **Option A (권장 / Recommended)**: 엄격한 SLA 적용
  - 격리된 Operation ID 검증: **p99 < 50 µs**
  - 다중 스레드 락 획득 평균 지연시간: **< 1.0 ms** (최대 타임아웃 5.0s 초과 0건)
  - 전체 192개 단위/통합 회귀 테스트 스위트 실행시간: **< 15.0 s**
- **Option B**: 완화된 기준 (Operation ID p99 < 100 µs, 전체 테스트 < 30 s).

[Answer]: A

---

### Question 3: 벤치마크 실행 환경 및 결과 봉인 정책
실측 결과를 어떤 수준으로 봉인하고 문서화하시겠습니까?

- **Option A (권장 / Recommended)**: 완전한 재현성 메타데이터 봉인
  - 현재 Linux aarch64 (Oracle Cloud 7.0 커널, GCC 13.3.0) 환경에서 실측을 수행하고, CPU 아키텍처, 커널 버전, Python 버전, 샘플 수, 백분위 분포를 `test-results.md` 및 `nfr-validation-matrix.md`에 투명하게 공식 봉인.
- **Option B**: 요약 수치(평균치)만 간략히 기록.

[Answer]: A
