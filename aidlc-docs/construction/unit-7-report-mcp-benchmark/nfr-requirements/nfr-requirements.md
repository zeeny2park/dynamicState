# NFR Requirements & Tech Stack: Report Equivalence, MCP Contracts & Clean Benchmark (Unit 7)

> **Unit ID**: `unit-7-report-mcp-benchmark`  

---

## 1. NFRs
- **NFR-REP-U7-001 (Equivalence)**: HTML 렌더러와 Markdown 렌더러의 판정 및 점수 일치도 100%.
- **NFR-MCP-U7-001 (Schema Strictness)**: MCP 프로토콜 요청 처리 시 잘못된 입력에 대해 5ms 이내 에러 응답 반환.
- **NFR-BENCH-U7-001 (Clean Environment)**: Git dirty 상태 배제 및 재현 가능한 결과 JSON 생성.

## 2. Tech Stack
- HTML 템플릿: 순수 Python 문자열 포매터 (외부 템플릿 엔진 종속성 없음)
- MCP 프로토콜: Model Context Protocol SDK (`mcp`)
- 벤치마크: Python 3 + GCC + POSIX 프로세스 제어
