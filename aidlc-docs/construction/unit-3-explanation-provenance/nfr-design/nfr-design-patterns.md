# NFR Design Patterns: Explanation Layer Immutability & Provenance (Unit 3)

> **Unit ID**: `unit-3-explanation-provenance`  

---

## 1. Defensive Copy Pattern
- 외부 입력 `report_dict` 또는 진단 상태에 대해 즉시 `copy.deepcopy()`를 적용하여 하류 분석 단계에서의 원본 객체 참조 변조를 원천 차단.

## 2. Circuit Breaker / Graceful Fallback Pattern
- LLM 계층의 장애나 비정상 출력이 감지될 경우, 기 수집된 확정적 증거(Thread, FDs, Modules, Verdict)에 기반한 정적 템플릿 엔진으로 자동 전환.
