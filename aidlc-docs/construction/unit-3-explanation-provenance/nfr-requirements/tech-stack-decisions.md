# Technology Stack Decisions: Explanation Layer Immutability & Provenance (Unit 3)

> **Unit ID**: `unit-3-explanation-provenance`  

---

## 1. 표준 라이브러리 준수
- 방어적 복사: `copy.deepcopy`
- JSON 직렬화: Python 내장 `json` 및 `canonical_json`
- 정규식 및 텍스트 템플릿: `re`
