# 코드 품질 평가 (Code Quality Assessment)

> 기준: `main` HEAD `9b327dd` (PR #1 머지 완료).

## 테스트 커버리지 및 현황

- **전체**: 측정 안 됨. 전용 coverage 측정 도구가 저장소 기본 세팅에 포함되어 있지 않음.
- **단위/통합 테스트**: `tests/` 디렉터리에 436개 파일 존재.
- **진단 정확도 벤치마크(최신)**:
  - 채점 대상 결함 11개 전원 탐지 (11/11 scored defects detected).
  - 정상 대조군 8개 중 7개 `HEALTHY` 확정, 1개(`ok_sawtooth`)는 의도된 `INCONCLUSIVE`.
  - 오탐(False Positive) 0건, 결함 대상에 대한 정상 오판정(False Clear) 0건 유지.
  - Held-out 검증 스위트(21개 별도 결함 프로그램: C++, 멀티파일, 함수 포인터, 매크로, -O2 최적화 등)를 분리하여 과적합 없는 일반화 성능 검증 진행 (`c934aac-heldout`).
  - libstdc++ 컨테이너(vector, map 등) 런타임 디코딩 및 eBPF/uprobe 선택적 추적 모드를 통해 결함 위치 특정 정확도 대폭 향상.

## 코드 품질 지표

- **린팅 및 포매팅**: `.pre-commit-config.yaml` 연동을 통한 기본 검사 기반 마련.
- **코드 스타일**: 일관된 Python 타입 힌트와 docstring, 진단 항목별 이슈 추적 번호(`IMP-xxx`, `RECIPE-xxx`) 태깅 체계 유지.
- **문서화**: PRD, README, 진단 베이스라인, HEALTHY 판정 규칙, 임베디드 타깃 매트릭스가 체계적으로 유지됨.
- **CI 파이프라인**: GitHub Actions 3종(`.github/workflows/test.yml`, `gdb92.yml`, `embedded-matrix.yml`)을 통한 크로스 플랫폼 검증.

## 기술 부채 및 개선 상황

- **플러그인 기반 분리**: 기존 거대 모듈에서 진단 레시피를 `extractor/recipe_plugins/` 아래 독립 플러그인(double_free, mapping_growth, heap_retention, thread_leak, lock_contention 등)으로 분리하여 단일 모듈 집중도 완화.
- **시각화 엔진 모듈화**: 인시던트 리포트 렌더링 로직을 `extractor/report_visuals.py`, `extractor/report_registry.py`, `extractor/report_story.py` 등으로 분리하여 유지보수성 향상.
- **시간 예산 관리 도입**: `extractor/check_budget.py`를 통해 기본 점검 수행 시 호스트 부하에 따른 시간 초과를 통제.
