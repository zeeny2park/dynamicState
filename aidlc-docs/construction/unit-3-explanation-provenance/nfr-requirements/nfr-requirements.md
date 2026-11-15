# NFR Requirements: Explanation Layer Immutability & Provenance (Unit 3)

> **Unit ID**: `unit-3-explanation-provenance`  

---

## 1. 보안 및 신뢰성 NFRs
- **NFR-SEC-U3-001 (Zero Mutation)**: 해설 생성 프로세스는 기존 진단 상태, 판정 결과, 증거 레코드에 어떠한 사이드 이펙트도 유발하지 않는다.
- **NFR-RES-U3-001 (Fail-Safe Graceful Fallback)**: LLM 또는 외부 서비스 장애 시 서비스 다운 없이 구조화된 템플릿 응답을 보장한다.
- **NFR-PERF-U3-001 (Overhead Control)**: 방어적 복사 및 템플릿 해설 생성 시간은 100ms 이내에 완료되어야 한다.
