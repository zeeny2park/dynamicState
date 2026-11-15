# NFR Design Patterns: PBT Invariants & Clean Benchmark Verification (Unit 4)

> **Unit ID**: `unit-4-pbt-dual-benchmark`  

---

## 1. Property-Based Testing Pattern
- 사전 정의된 고정 테스트 케이스 대신, 유효/무효 입력 공간 전역에 걸친 생성 전략(`strategies`)을 통해 코너 케이스(경계값, 특수문자, 임의 순환 참조 등) 자동 탐색.

## 2. Reproducible Measurement Pattern
- 환경 메타데이터(CPU 아키텍처, 커스텀 빌드 ID, dirty 플래그, commit SHA)를 벤치마크 결과의 최상위에 박제하여 결과의 재현성과 신뢰성 입증.
