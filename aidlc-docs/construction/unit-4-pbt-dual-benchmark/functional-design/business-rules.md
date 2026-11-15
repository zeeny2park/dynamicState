# Business Rules: PBT Invariants & Clean Benchmark Verification (Unit 4)

> **Unit ID**: `unit-4-pbt-dual-benchmark`  

---

## 1. PBT 테스트 수행 규칙 (Rule BR-PBT-001)
- CI 및 PR 검증 시 `seed=42`를 사용한 결정론적 테스트를 수행한다.
- 핵심 보안 불변식에 대해 최소 100개 이상의 생성 예제를 실행한다.
- 반례 축소(Shrinking)를 활성화하여 실패 시 최소 반례를 기록한다.

## 2. 벤치마크 신뢰 규칙 (Rule BR-BNCH-001)
- 미커밋 변경 사항(dirty files)이 존재하는 상태에서 생성된 벤치마크 결과는 공식 베이스라인으로 인정하지 않는다.
- 동일한 데이터셋 및 동일한 평가 프로토콜을 양대 아키텍처(aarch64, x86_64)에 일관되게 적용한다.
