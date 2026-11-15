# 부하 및 성능 검증 계획서 (Load & Performance Test Plan)

> **대상**: dynamicState Diagnosis Engine  
> **환경**: Linux aarch64 (Oracle Cloud), Python 3.12.3, GCC 13.3.0  
> **관련 NFR**: `NFR-PERF-001`, `NFR-RESILIENCY-001`, `FR-BENCH-001 ~ 003`  

---

## 1. 검증 시나리오 설계 (Test Scenarios)

### 시나리오 1: Operation ID 정밀 마이크로 벤치마크 (Micro-benchmark)
- **목적**: `validate_operation_id` 격리 실행 지연시간 측정 및 NFR-PERF-001 (p99 < 50 µs) 달성 검증.
- **표본 크기**: 100,000회 연속 호출 (다양한 길이 1~128자 및 화이트리스트 문자 조합).
- **측정 지표**: 최소값, 평균(Mean), p50, p90, p95, p99, p99.9, 최대값.

### 시나리오 2: 멀티스레드 동시성 락 경합 부하 테스트 (Concurrency Stress Test)
- **목적**: `DurableTrustStore._file_lock()`의 5.0초 타임아웃 안전성 및 상호 배제 무결성 검증.
- **부하 설정**: 10개 작업 스레드가 각 100회(총 1,000회 트랜잭션) 동시 파일 락 획득/해제 및 영속화 수행.
- **측정 지표**: 락 획득 지연시간, 타임아웃 발생 수(목표: 0건), 데이터 손상 여부.

### 시나리오 3: 대표 타깃 진단 파이프라인 벤치마크 (Diagnostic Pipeline Benchmark)
- **목적**: 실제 프로세스 진단 시 오버헤드 및 수집기 실행시간 측정.
- **대상 타깃**: `ok_idle_server`, `ok_busy_server`, `deadlock_circular`
- **측정 지표**: 타깃당 진단 소요 시간(s), 메모리 사용량, 판정 정확도.
