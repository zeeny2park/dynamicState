# 테스트 기준선 (IMP-005)

이 문서는 전체 테스트를 실제로 실행한 기록이다. 수치의 원본은 `docs/test_baseline/summary.tsv`이고, `scripts/run_test_baseline.sh`로 다시 만들 수 있다.

## 실행 환경

- 날짜: 2026-11-12, 기준 커밋: `f842448` + 이 작업의 변경
- 호스트: Linux aarch64, Python 3.12.3, `kernel.yama.ptrace_scope=0`
- x86_64와 Python 3.10(CI 러너 구성)에서는 실행하지 못했다.

## 결과

| | 수정 전 (`f842448`) | 수정 후 |
|---|---|---|
| 테스트 파일 | 268 | 227 |
| 실패한 파일 | 59 | 0 |
| 실행된 테스트 | 2,138 | 2,096 |
| 오류 / 실패 | 73 / 13 | 0 / 0 |
| 예상된 실패(실제 결함 표시) | 0 | 14 |
| 건너뜀 | 2 | 2 |

수정 전의 "실행된 테스트" 수에는 import 단계에서 죽은 42개 파일의 테스트 약 1,100건이 빠져 있다(파일당 오류 1건으로만 집계됨).

두 가지 방식으로 확인했다.

- 파일별 실행(`scripts/run_test_baseline.sh`): 227개 파일 전부 종료 코드 0
- 단일 프로세스 실행(`python3 -m unittest discover tests`, CI와 같은 방식): 2,096건, `OK (skipped=2, expected failures=14)`

## 현재 상태 (2026-11-12, 로드맵 23개 항목 완료 시점)

수치의 원본은 `docs/test_baseline/summary.tsv`(이 호스트, aarch64)와 CI 아티팩트 `test-baseline`(x86_64)이다.

| | aarch64 (이 호스트) | x86_64 (CI 러너, 커밋 `2a9d442`) |
|---|---|---|
| 테스트 파일 | 245 | 246 |
| 실행된 테스트 | 2,350 | 2,324 |
| 실패한 파일 (파일별 실행) | 1 (로컬 LLM 시간 초과, 아래 참고) | 0 |
| 단일 프로세스 실행 | OK (skipped=1) | OK |
| 벤치마크 (`benchmarks/diagnosis_accuracy`) | 채점 대상 11개 중 9개 탐지, 원인 이름 완전 일치 6, 오탐 0/8 | 같음 |

남아 있는 실제 결함 표시(`expectedFailure`): 없음. 이전 6건은 수정 후 표시를 제거했다: clang 14 / binutils 2.38의 위치 목록(`extractor/dwarf_loclists_binary.py`가 섹션 바이트를 직접 읽음), x86_64 CFI 에필로그(`parse_cfi_table`), aarch64 TLS/TCB 탐색(`_discover_thread_pointers_aarch64`). x86_64 CI 러너에서의 실행은 아직 확인되지 않았다(오브젝트 파일 분석과 ubuntu:22.04 컨테이너 재현으로만 확인).

부하에 민감한 파일: `tests/test_phase15_conversational_llm.py`(이 호스트의 8000번 포트에 다른 서비스가 있어 실시간 LLM 검사가 시간 초과), `tests/test_imp_010_runnable_fraction.py`와 `tests/test_multithread_exploration.py`(`BASELINE_SERIAL` 표시, 기준선 스크립트가 단독 실행), `tests/test_phase2_0_a_3_12_real_cpp_e2e.py`, `tests/test_imp006_remote_diagnose.py`와 `tests/test_imp_012_human_report.py`의 누수 테스트(병렬 부하에서 간헐 실패, 단독 실행 시 통과). CI의 파일별 실행은 이 때문에 병렬도 2로 돈다.

## 실패 59개 파일의 분류

| 분류 | 파일 수 | 처리 |
|---|---|---|
| 폐기: 커밋 `533a0bb`가 삭제한 심볼을 import | 42 | 파일 삭제. 목록은 `docs/TEST_BASELINE_RETIRED.txt` |
| 낡은 테스트, 타이밍 의존, 실제 결함이 섞인 파일 | 17 | 테스트별로 아래와 같이 처리 |

17개 파일의 실패 테스트 45건:

| 분류 | 건수 | 처리 |
|---|---|---|
| 낡은 테스트(이후 커밋이 의도적으로 계약을 바꿈) | 26 | 현재 계약에 맞게 수정 |
| 타이밍 의존 | 1 | 결정적으로 수정 |
| 대상 기능이 삭제됨 | 4 | 테스트 메서드 삭제(`test_target_collector`의 `capture_snapshot_via_collector` 4건) |
| 실제 결함 | 14 | 단언은 그대로 두고 `expectedFailure`로 표시 |

추가로, 처음에는 통과했지만 부하나 실행 순서에 따라 실패하던 테스트 3건을 고쳤다: `test_real_target_runner`의 핸드셰이크 경합, `test_phase45`의 표본 타이밍, `test_phase2_1_6`의 전역 런타임 바인딩.

폐기한 42개 파일은 삭제된 트랜잭션·회계 원장과 캡처 영수증 코드의 테스트다. 그중 교착 검증에 쓰이던 음성 대조군은 `tests/test_deadlock_real_process_baseline.py`로 다시 만들었다.

## 교착 검증 (실제 프로세스)

`tests/test_deadlock_real_process_baseline.py`가 대상 프로그램을 컴파일해 띄우고 현재 진단 경로(`RuntimeEvidenceProvider.collect_for_recipe` → 교착 레시피)로 판정한다. 결론을 주입하지 않는다.

| 대상 | 기대 | 결과 |
|---|---|---|
| `proc_thread_circular_deadlock.c` | 교착, 락 `g_mutex_a`·`g_mutex_b` | 통과 |
| `proc_thread_3way_deadlock.c` | 교착, 락 3개 | 통과 |
| `proc_thread_normal_cv.c` (조건 변수 대기) | 교착 아님 | 통과 |
| `proc_scenario_c_thread_contention.c` (단순 경합) | 교착 아님 | 통과 |

## 실제 결함 14건

모두 테스트에 `# IMP-005 baseline: real defect —` 주석과 함께 표시되어 있다. 결함을 고치면 "예상 밖의 성공"으로 CI가 실패하므로, 그때 표시를 지운다.

| 테스트 | 관측 | 원인 위치 |
|---|---|---|
| `test_mcp_first_phase1` test_03 | `runtime_capture_and_diff` 결과에 `consistency` 없음 | `extractor/watch_session.py:3108` (`533a0bb` 회귀) |
| `test_mcp_first_phase1` test_07, test_11 | `runtime_batch_execute` 결과에 `success`, `error_code` 없음 | `extractor/watch_session.py:10992` (`533a0bb` 회귀) |
| `test_mcp_first_phase1` test_08 | 다른 대상의 PID가 앞서 묶인 대상의 디버그 ELF를 상속 | `extractor/watch_session.py:9998-9999` (`533a0bb` 회귀) |
| `test_phase14_production_pilot` 2건 | `run_pilot()`이 `evidence_id` 없이 호출해 예외 | `extractor/production_pilot.py:595` |
| `test_causal_validation_hardening` 평가 하니스 | 시나리오 H 픽스처가 원장에서 거부됨 | `extractor/causal_fixtures.py:726` |
| `test_target_collector` test_44 | 미검증 오프라인 스냅샷이 TRUSTED / CONFIRMED / LIVE_RUNTIME_CAPTURE로 보고됨 | `extractor/investigation.py:3431`, `:3565-3590` |
| `test_target_collector` test_63 | 보고서와 `target_ref`에 `provenance_class` 없음 | `extractor/investigation.py:1285-1292`, `:3520` |
| `test_phase41` test_01 | 프레임 지역 변수가 매 실행 다른 쓰레기 값 | `extractor/watch_session.py:6506`, `:6525` (x86_64 프레임 배치 가정) |
| `test_phase47` test_01 | 콜스택 최상위 프레임이 틀림 | `extractor/watch_session.py:5589`, `:6506` (x86 CALL 옵코드 탐침) |
| `test_phase46` test_01, test_03, `test_phase47` test_03 | TLS 변수와 TCB를 찾지 못함 | `extractor/watch_session.py:8881-8978` (x86_64 glibc TCB 가정) |

마지막 세 줄의 5건은 aarch64에서만 `expectedFailure`이고 x86_64에서는 일반 테스트로 실행된다. x86_64 전용 가정이 원인이라는 것은 코드에서 읽은 추론이며 x86_64에서 실행해 확인하지 않았다.

기준선 작업 중 확인된 것 하나: 순환 대기를 한 번만 관측해도 교착 레시피가 `PERSISTENT_DEADLOCK`, 신뢰도 0.98을 낸다(IMP-003).

## CI

- `ci/workflows/test.yml`에 테스트 의존성 설치(`requirements-test.txt`), `ptrace_scope` 설정, 교착 기준선 테스트, 파일별 결과 업로드 단계를 추가했다.
- `ci/ci.yml`은 폐기된 파일만 실행하던 미사용 워크플로우라 삭제했다.
- 워크플로우는 아직 GitHub에 올라가지 않았다. `.github/workflows/`를 올리려면 `workflow` 권한이 있는 토큰이 필요하다.

```bash
gh auth refresh -s workflow
./scripts/sync_workflows.sh
git add .github/workflows && git commit -m "ci: enable GitHub Actions workflows" && git push
```

## 확인하지 못한 것

- x86_64 Ubuntu 22.04, Python 3.10에서의 실행. 아키텍처 의존 단언(`test_phase2_4_real_world_targets`, `test_phase2_4_1_mcp_protocol_transport`, `test_dwarf_evaluator_correctness`, `test_ebpf_integration`)은 호스트 중립으로 고쳤지만 정적 검토만 했다.
- Python 3.10 문법은 `ast.parse(feature_version=(3,10))`로만 확인했다. `extractor/capture_backend.py:954` 등의 `datetime.fromisoformat`은 3.10에서 끝의 "Z"를 거부한다.
