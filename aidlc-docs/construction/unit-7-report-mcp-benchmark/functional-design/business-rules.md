# Business Rules: Report Equivalence, MCP Contracts & Clean Benchmark (Unit 7)

> **Unit ID**: `unit-7-report-mcp-benchmark`  

---

## 1. 리포트 일치성 규칙 (Rule BR-REP-001)
- HTML 리포트와 Markdown 리포트는 동일한 진단 결과에 대해 상이한 판정이나 모순된 결론을 내릴 수 없다.
- 모든 결함 주장 항목은 근거 증거 ID를 최소 1개 이상 명시해야 한다.

## 2. MCP 계약 규칙 (Rule BR-MCP-001)
- MCP 입력 파라미터가 유효하지 않은 경우, 표준 MCP 에러 포맷(`isError=True` 및 에러 메시지)을 반환해야 하며 파이썬 프로세스를 비정상 종료시켜서는 안 된다.

## 3. 벤치마크 평가 규칙 (Rule BR-BNCH-001)
- 벤치마크 결과는 검증된 ground-truth 결함 유형과의 일치율, 오탐률(False Positive), False Clear를 분리하여 보고한다.
