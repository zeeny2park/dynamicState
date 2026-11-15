# 속성 기반 테스트 (Property-Based Testing) — Opt-In

**확장 (Extension)**: Property-Based Testing

## Opt-In 질문 (Opt-In Prompt)

이 확장이 로드되면 다음 질문이 Requirements Analysis 의 확인 질문에 자동으로 포함된다:

```markdown
## Question: 속성 기반 테스트 확장 (Property-Based Testing Extension)
이 프로젝트에 속성 기반 테스트 (PBT) 규칙을 강제할까요?

A) 예 — 모든 PBT 규칙을 차단성 제약으로 강제 (비즈니스 로직, 데이터 변환, 직렬화, 상태를 가진 구성요소가 있는 프로젝트에 권장)

B) 부분 — 순수 함수와 직렬화 왕복 (round-trip) 에만 PBT 규칙 강제 (알고리즘 복잡도가 낮은 프로젝트에 적합)

C) 아니요 — 모든 PBT 규칙 건너뜀 (단순 CRUD 애플리케이션, UI 전용 프로젝트, 중요한 비즈니스 로직이 없는 얇은 통합 계층에 적합)

X) Other (please describe after [Answer]: tag below)

[Answer]: 
```
