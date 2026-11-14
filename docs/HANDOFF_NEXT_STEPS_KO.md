# 인수인계: 이어서 할 일

작성: 2026-11-14 07:25 UTC · 브랜치 `feat/visual-incident-report` · 원격 push 및 CI 검증 준비 완료

이 문서만 읽고 이어서 작업할 수 있게 썼습니다. 현황 표는 `docs/WORK_STATUS_KO.md`, 로드맵은
`docs/IMPROVEMENT_STRATEGY_AND_ROADMAP_KO.md`(6.1 결정, 8 진행 현황)에 있습니다. 작업이 진행되면 `WORK_STATUS_KO.md`를 고치고
갱신 기록에 한 줄을 남깁니다.

## 0. 먼저 알아야 할 것

### 0.1 저장소 상태

| 항목 | 값 |
|---|---|
| 작업 디렉터리 | `/home/ubuntu/workspace/ut` (브랜치 `feat/visual-incident-report`) |
| PR | https://github.com/zeeny2park/dynamicState/pull/1 (열림, 병합 전). CI는 `feat/visual-incident-report` 대상 push/PR에서 실행(x86-64) |
| 호스트 | AArch64, 4코어, RAM 24GB, 디스크 45GB(여유 약 9.3GB) |
| 지켜야 할 범위 | `.aidlc-rule-details/`, `.claude/`, `aidlc-docs/`, `*.patch`, `.claude.zip` (건드리지 않음), `/home/ubuntu/workspace/ut-webui` |
| 데모 프로세스 보존 | `deadlock_pipeline` (PID 419893), `ok_busy_server` (PID 419894) 상주 유지 |

### 0.2 에이전트 작업 및 검증 현황 (병합 및 안정화 완료)

- 에이전트 1(`worktree-agent-a014e64fe14f5206a`): 이름 추측 오탐 전체 점검, 락 타입 판별 병합 완료.
- 에이전트 2(`worktree-agent-a84d5a8a832de2b37`): 배타적 원인 표시, 4단계 나머지 병합 완료.
- PR 자동 리뷰 의견: 32비트/비-glibc 대상 `mapping_growth` ABI 가드 및 미지원 오탐 차단 조치 완료.
- `lock_hotspot`: 락 대기자 큐잉(`samples_queued > 0`) 발생 시 HEALTHY 오판 완전 차단 및 안정화 완료.
- 통합 베이스라인: 303개 파일, 3,042개 테스트 전체 통과 (0 failures).
- 통합 벤치마크 3종(`generic`, `ground_truth`, `heldout`) 21/21 검출, 90회 함정 오탐 0건, `--repeat 5` 100% 일치율 달성.

### 0.3 지켜야 할 규칙

- **시험 프로세스**: 모든 시험 프로그램 실행은 `tests/support/fixture_process.py`(`fixture_popen`, `fixture_process`)를 거칩니다.
  정책 테스트(`tests/test_fixture_process_policy.py`)가 강제합니다. 누수 시험 프로그램은 스스로 상한을 둡니다.
- **실행 중단**: 벤치마크나 테스트를 러너만 죽여서 멈추지 않습니다. 프로세스 그룹을 죽이고
  `ps -eo pid,ppid,etimes,rss,args | grep -E "/tmp/|diagacc|real_runtime"`로 남은 프로세스를 확인합니다.
- **임시 경로**: 테스트 출력은 `tests/support/tmpdirs.py`의 `temp_dir()`을 씁니다. `/tmp/` 고정 경로는
  `tests/test_tmp_path_policy.py`가 막습니다. 긴 실행 전에 `df -h /`를 확인합니다.
- **테스트 러너**: `python3 -m unittest tests/<file>.py` (pytest 형식 함수는 0개로 실행됨).
- **테스트를 약하게 만들지 않기, 벤치마크 대상·시험 프로그램 이름으로 분기하지 않기.**
- **판정 근거**: 보고서 문구를 검색해 판정하지 않습니다(`NoStringSearchInVerificationPathTest`). 변수 이름은 후보 순위에만 쓰고,
  증거는 DWARF 타입·배치·관측된 관계입니다.
- **독자용 출력**: 신뢰도 %나 건강 점수를 쓰지 않습니다. 상태 단어는 이상 발견 / 판단 불가 / 통과 / 실행 안 함.
  `human_report.REPORT_SECTION_ORDER`는 바꾸지 않습니다.
- **데모 서버**: nginx 기본 인증을 제거하지 않습니다(UI가 ubuntu 소유 프로세스 메모리를 읽을 수 있음).
  `~/dynamicstate-demo/bin/leak_registry`는 실행하지 않습니다.
- **결정된 범위(다시 묻지 않음)**: 추적 모드는 선택 기능, 기본 검사에 시간 예산 적용, DEGRADED는 벤치마크 채점 제외,
  대상은 x86-64·ARM64의 glibc, `long_stall` 결함은 채점 제외, `ok_sawtooth`는 판단 불가(범위 한계) 유지.

---

## 1. 진행 순서 (현재 단계)

### 1단계: 변경사항 커밋 및 push (HANDOFF 5절)

1. `docs/WORK_STATUS_KO.md`, `docs/HANDOFF_NEXT_STEPS_KO.md`, `docs/IMPROVEMENT_STRATEGY_AND_ROADMAP_KO.md` 8절 갱신.
2. 커밋 생성 (커밋 메시지 끝에 `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>` 포함).
3. `git push origin feat/visual-incident-report`.
4. PR #1의 CI 확인:
   ```bash
   gh run list --branch feat/visual-incident-report -L 5
   ```
   실패 시: `gh run view <id> --log-failed`.
5. PR 병합(`gh pr merge`)은 사용자가 명시적으로 요청할 때만 수행.

---

### 2단계: push 뒤 정리 및 배포 (HANDOFF 6절)

1. **샘플 보고서 재생성**:
   ```bash
   python3 scripts/make_sample_reports.py --out /tmp/sample_reports_new
   # 백업 및 배포
   sudo -n cp -r /var/www/dynamicstate-samples /var/www/dynamicstate-samples.bak.$(date +%Y%m%d%H%M)
   sudo -n cp -r /tmp/sample_reports_new/* /var/www/dynamicstate-samples/
   ```
2. **데모 웹 서버 재시작** (현재 pid 644852):
   ```bash
   kill 644852
   cd /home/ubuntu/workspace/ut
   setsid nohup python3 -m extractor.web --host 127.0.0.1 --port 8081 --corpus /home/ubuntu/dynamicstate-demo/corpus \
     >> /home/ubuntu/dynamicstate-demo/ui.log 2>&1 < /dev/null &
   ```
   확인: 직접 200 (`curl -I http://127.0.0.1:8081/`), nginx 경유 인증 확인.
3. **MCP 서버 안내**:
   떠 있는 MCP 서버 프로세스는 각 클라이언트 세션 소유이므로, 수정 반영을 위해 클라이언트에서 재연결해야 함을 사용자에게 안내.
4. **미사용 브랜치 정리**:
   이미 로컬에 통합된 `worktree-agent-*` 브랜치 정리 (`git branch -d`).

---

## 2. 미처리 항목 (담당 없음, 여유가 될 때)

| 순위 | 항목 | 할 일 | 상태 |
|---|---|---|---|
| 1 | PR 자동 리뷰 의견 | `extractor/recipe_plugins/mapping_growth.py` 32비트/비-glibc 대상 glibc 헤더 언팩 방지 및 오탐 차단 | **조치 완료** (PR 회신 완료) |
| 2 | `runtime_auto_triage_incident` | `examples/pool_demo`에서 응답의 `SUPPORTED` 항목이 무엇인지 확인 | 대기 |
| 3 | 위치 후보의 일반화 검증 | 지금 규칙을 보지 않은 새 결함 프로그램 세트(12개 이상)를 만들어 첫 실행 결과 검증 | 대기 |
| 4 | C++ `-O0`의 줄 표시 | `addr2line` 경로의 헤더 인라인 줄 표 해석 오차 교정 (`test_source_line_resolution.py`) | 대기 |
| 5 | 새 보고서 부분의 브라우저 확인 | HTML 보고서와 웹 UI에서 위치 후보, 검토한 다른 원인, 진행 순서 화면 확인 | 대기 |
| 6 | 미검증 범위 | 시간 예산(원격 대상, 스레드 50~250개), C++ 해독기(다른 libstdc++·clang·libc++ 거부) | 대기 |
| 7 | 보고서 JSON 크기 | 스레드 301개 대상에서 60MB(관측 반복 구조 압축 검토) | 대기 |
| 8 | `ok_sawtooth` | 범위 한계(판단 불가) 유지로 정책 확정 완료 | **확정 완료** |
| 9 | 웹 UI의 시간 예산 입력란 | 지금은 API 매개변수만 있음 | 대기 |

---

## 3. 사용자에게 전달해야 할 사항

- **베이스라인 회귀 결과**: 303개 테스트 파일, 3,042개 단위/통합 테스트 100% 통과 (0 fail).
- **`lock_hotspot` 안정화**: 부하 상황에서 락 경합 대기자가 존재할 경우 정상(HEALTHY)으로 판정되지 않도록 `healthy_verdict.py`에 가드를 두어 완전 해결.
- **반복 판정 일치율**: `--repeat 5` 벤치마크 결과 29개 채점 대상 100% 일치 (`mean 1.0, pooled 1.0`).
- **PR 자동 리뷰 의견 처리**: 32비트/비-glibc 환경에서 LP64 glibc 청크 헤더 해독을 건너뛰도록 `target_abi` 검사를 추가하고 PR #1 코멘트에 회신 완료.
- **임시 파일 정리**: `/tmp/phase2_1_1_scenarios_corpus` 삭제 완료 (디스크 여유 9.3GB).
