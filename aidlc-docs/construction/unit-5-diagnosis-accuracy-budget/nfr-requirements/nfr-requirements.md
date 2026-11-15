# NFR Requirements: Diagnosis Accuracy & Hypothesis Budgeting (Unit 5)

> **Unit ID**: `unit-5-diagnosis-accuracy-budget`  

---

## 1. 성능 및 복원력 NFRs
- **NFR-PERF-U5-001 (Time Budgeting Cap)**:
  - 정적 위치 후보 추출은 전체 호출당 최대 4.0초(`TIME_BUDGET_S`) 이내에 완료되어야 하며, 초과 시 안전하게 저하(degrade)되어 진단을 지연시키지 않는다.
- **NFR-RES-U5-001 (Partial Finding Retention)**:
  - 타임아웃이나 예산 소진 발생 시 기 탐지된 finding 데이터를 절대 유실하지 않는다.
