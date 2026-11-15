# Business Rules: Diagnosis Accuracy & Hypothesis Budgeting (Unit 5)

> **Unit ID**: `unit-5-diagnosis-accuracy-budget`  

---

## 1. 정적 위치 후보 정직성 규칙 (Rule BR-DIAG-001)
- 후보 위치는 절대 `subjects`에 주입되지 않는다.
- 후보는 최대 3개(`CANDIDATE_CAP=3`)로 제한되며, 선정 이유(`reason`)가 명시되어야 한다.
- 타깃 프로세스 메모리나 `/proc`을 직접 읽지 않고 로컬 DWARF 이미지 및 소스 코드만을 읽는다.

## 2. 가설 모델 불변식 (Rule BR-DIAG-002)
- 거부(`REJECTED`) 또는 격리(`QUARANTINED`)된 증거는 가설 점수 계산에서 완전히 배제된다.
- 모순 증거는 독립적인 카테고리로 집계된다.

## 3. 예산 통제 규칙 (Rule BR-DIAG-003)
- 예산이 초과되어 중단되더라도 기존 발견된 `findings`는 삭제되지 않고 최종 리포트에 유지된다.

## 4. 기권 일관성 규칙 (Rule BR-DIAG-004)
- 결함 부재는 건강의 충분조건이 아니며, 필수 정상 관측 항목이 결측된 경우 판정은 `INCONCLUSIVE`여야 한다.
