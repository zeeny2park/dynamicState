# 기본 보안 (Security Baseline) — Opt-In

**확장 (Extension)**: Security Baseline

## Opt-In 질문 (Opt-In Prompt)

이 확장이 로드되면 다음 질문이 Requirements Analysis 의 확인 질문에 자동으로 포함된다:

```markdown
## Question: 보안 확장 (Security Extensions)
이 프로젝트에 보안 확장 규칙을 강제할까요?

A) 예 — 모든 SECURITY 규칙을 차단성 제약으로 강제 (운영 수준 애플리케이션에 권장)

B) 아니요 — 모든 SECURITY 규칙 건너뜀 (PoC, 프로토타입, 실험 프로젝트에 적합)

X) Other (please describe after [Answer]: tag below)

[Answer]: 
```
