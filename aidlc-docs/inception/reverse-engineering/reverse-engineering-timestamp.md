# Reverse Engineering 메타데이터 (Reverse Engineering Metadata)

**분석 일시**: 2026-11-15T00:42:00Z
**분석 주체**: AI-DLC
**작업 공간**: /home/ubuntu/workspace/ut
**분석한 전체 파일 수**: 1082

## 파일 수 계산 방법

- 1082 = `git ls-files` 가 돌려주는 추적 파일 수(분석 시점 HEAD `9b327dd`). 추적되지 않는 파일과 `.agents/`, `aidlc-docs/`, `.aidlc-rule-details/`, `build/`, `dynamicstate.egg-info/`, 컴파일된 예제 바이너리는 세지 않았다.
- 구성: `tests/` 436, `docs/` 209, `extractor/` 175, `benchmarks/` 167, `scripts/` 23, `.claude/` 21, `examples/` 11, `target/` 10, 루트 파일 8(`.gitignore`, `LICENSE`, `README.md`, `pyproject.toml`, `requirements-test.txt`, `requirements.txt`, `run_all_tests.sh`, `.pre-commit-config.yaml`), `protocol/` 5, `ci/` 4, `.github/` 3, `skills/` 3, `bin/` 2, `docker/` 2, `gdb/` 2, `snapshots/` 1.
- 분석 방식: PR #1(`feat/visual-incident-report`) 머지 및 진단 엔진 확장(libstdc++ 컨테이너 디코딩, 레시피 플러그인 확장, 객체 연관 모델, 시간 예산 모델, 선택적 eBPF/uprobe 추적, 시각적 인시던트 리포트, 한/영 이중언어 보고서, 자연어 프로세스 해설기)을 포함한 변경 사항을 반영하여 재분석했다.
- 주요 소스(`extractor/expert_diagnostic_engine.py`, `extractor/report_visuals.py`, `extractor/recipe_plugins/`, `extractor/cpp_containers.py`, `extractor/object_relations.py`, `extractor/process_explainer.py`, `scripts/mcp_server.py`, `extractor/cli.py`, `extractor/web/`) 및 최신 벤치마크 결과 문서를 직접 확인했다.

## 생성한 산출물
- [x] business-overview.md
- [x] architecture.md
- [x] code-structure.md
- [x] api-documentation.md
- [x] component-inventory.md
- [x] technology-stack.md
- [x] dependencies.md
- [x] code-quality-assessment.md
- [x] reverse-engineering-timestamp.md
