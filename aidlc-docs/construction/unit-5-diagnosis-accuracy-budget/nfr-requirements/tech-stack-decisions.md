# Technology Stack Decisions: Diagnosis Accuracy & Hypothesis Budgeting (Unit 5)

> **Unit ID**: `unit-5-diagnosis-accuracy-budget`  

---

## 1. DWARF 파싱 및 바이너리 검사 도구
- DWARF 디버그 정보 파싱: 표준 `readelf` / `addr2line` 서브프로세스 래퍼 및 파이썬 파서
- 소스 코드 텍스트 검사: 로컬 파일시스템 인덱서
