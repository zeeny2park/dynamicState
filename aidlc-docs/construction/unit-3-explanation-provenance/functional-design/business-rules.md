# Business Rules: Explanation Layer Immutability & Provenance (Unit 3)

> **Unit ID**: `unit-3-explanation-provenance`  

---

## 1. 불변성 규칙 (Rule BR-EXP-001)
- `explain_process_behavior(report_dict=...)`는 인자로 전달된 딕셔너리나 객체 내부의 어떠한 필드도 직접 수정하거나 삭제하지 않는다.
- 진입 즉시 방어적 전체 복사(`copy.deepcopy`)를 수행하여 격리된 컨텍스트에서 분석을 수행한다.

## 2. 증거 접지 및 환각 방지 규칙 (Rule BR-EXP-002)
- 해설에 포함되는 모든 증거 인용은 원본 리포트에 존재하는 유효한 `evidence_id`여야 한다.
- 환각된 증거 ID가 감지되면 해당 인용을 배제하고 경고를 기록한다.

## 3. 안정적 폴백 규칙 (Rule BR-EXP-003)
- 외부 LLM API 실패, 타임아웃, 예외 발생 시 fail-soft 결정론적 템플릿 리포트를 생성하여 반환하며 프로세스를 중단시키지 않는다.
