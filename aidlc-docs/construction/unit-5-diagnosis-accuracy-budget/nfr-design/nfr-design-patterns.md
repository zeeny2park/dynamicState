# NFR Design Patterns: Diagnosis Accuracy & Hypothesis Budgeting (Unit 5)

> **Unit ID**: `unit-5-diagnosis-accuracy-budget`  

---

## 1. Candidate Ranking Pattern
- DWARF 변수/함수 심볼과 소스 텍스트를 교차 분석하여 호출 지점의 관련성 가중치에 따라 결정론적으로 후보를 상위 3개까지 선정.

## 2. Budget Guard Pattern
- 진단 체크 실행 루프에 예산 가드를 배치하여 남은 시간이 부족한 경우 새 체크를 건너뛰고 기존 결과를 패키징.
