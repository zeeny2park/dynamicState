# dynamicState 실전 활용 플레이북 (Embedded Live Memory X-Ray Guide)

본 문서는 외부 서버(호스트)에 있는 `nostrip` (DWARF 포함) ELF 바이너리를 이용하여, **실행 중인 임베디드 리눅스 장비 내부 프로세스의 상세 메모리(전역 구조체, 메모리 풀, 싱글톤, 다단계 힙 포인터 체인, 스레드별 버퍼 점유 현황)를 프로세스 중단(0.00ms 정지) 없이 분석**하는 실전 가이드입니다.

---

## 1. 언제 `dynamicState`를 사용해야 하는가? (6대 핵심 시나리오)

| 장애/점검 상황 | 기존 디버깅 방식의 문제점 | `dynamicState` 해결 방식 |
| :--- | :--- | :--- |
| **1. 조용한 먹통 (Silent Hang / 상태 고착)**<br>프로세스는 살아있는데 특정 기능만 멈춤 | `gdbserver` 부착 시 하드웨어 Watchdog 리셋 또는 통신 타임아웃 발생 | **`instant_xray` 레시피 / `eval` 명령**:<br>전역 상태 구조체와 힙 포인터(`g_ctx->state`)를 0.00ms 무중단으로 즉시 해독하여 어느 상태 분기에 걸려 있는지 확인 |
| **2. 메모리 풀 / 버퍼 배열 할당 현황 시각화**<br>`*gpMem` 등 버퍼 풀의 슬롯별 사용 현황 파악 | `evaluate_symbol_paths`의 기본 배열 16개 제한 또는 수백 번의 수동 조회 필요 | **`runtime_scan_memory_pool` / `pool-map` 명령**:<br>`*gpMem` 또는 `gpMem->buffers` 전체 슬롯을 단일 무정지 배치 읽기로 스캔해 할당 비트맵(`allocation_bitmap`)과 시각적 맵 차트(`ascii_map_chart`) 즉시 생성 |
| **3. 특정 버퍼 인덱스를 점유 중인 스레드 역추적**<br>`gpMem` 9번 인덱스를 누가 잡고 안 놓는지 확인 | 구조체에 `tid`가 없거나 스레드 스택 지역 변수에만 포인터가 있으면 추적 불가 | **`runtime_find_symbol_owners` / `find-owner` 명령**:<br>① 구조체 내부 `tid`/`owner` 필드, ② 전역 워커 테이블, ③ 각 활성 스레드(`/proc/<pid>/task/<tid>`)의 스택 프레임 메모리를 무정지로 스캔해 해당 버퍼 주소를 보유한 스레드(TID·스레드명) 특정 |
| **4. 이벤트 전·후 상태 전이 검증**<br>명령/패킷 인가 시 내부 플래그·카운터가 정상 반영되는지 확인 | `printf` 디버그 로그를 넣으려면 펌웨어 재빌드 및 재배포 필요 | **`before_after_diff` 레시피 / `diff` 명령**:<br>시간차를 두고 2회 무중단 샘플링하여 변경된 필드(`changed`)와 고정된 필드(`unchanged`)만 자동 추출 |
| **5. 장시간 구동 후 카운터/풀 고착 및 누수 추적**<br>특정 워커 스레드나 큐/버퍼가 멈춰 있는지 확인 | 재현 중인 장비를 재시작하면 현상이 사라짐 | **`timeseries_watch` 레시피**:<br>연속 샘플링으로 활발히 변하는 변수(`active_variables`)와 완전히 멈춘 변수(`stuck_variables`)를 자동 분리 |
| **6. 정상 기준점(Golden Baseline) 대비 장애 비교**<br>정상일 때와 지금 무엇이 달라졌는지 모를 때 | 수백 개 구조체 필드의 정상값을 사람이 기억할 수 없음 | **Golden Baseline 저장 및 비교**:<br>정상 부팅/유휴 상태의 메모리 값을 저장해 두고, 이상 발생 시 원클릭으로 달라진 필드만 검출 |

---

## 2. CLI 1줄 명령어 치트시트

```bash
# 1) 원격 임베디드 장비 프로세스 자동 탐색 + Build ID 검증 + 추천 심볼 확인 (C99 컬렉터 자동 배포 포함)
./bin/dynamic-state connect \
  --remote-host 192.168.1.50 --ssh-user root \
  --process-name media_daemon \
  --debug-image /build/media_daemon.debug \
  --auto-deploy-collector

# 2) 메모리 풀(*gpMem) 전체 버퍼 할당 현황 맵 차트 조회 (Phase 8 신규)
./bin/dynamic-state pool-map \
  --pid 8842 --debug-image /build/media_daemon.debug \
  --expr "*gpMem"

# 3) 특정 버퍼 슬롯(gpMem 9번 인덱스)을 사용/참조 중인 스레드 역추적 (Phase 8 신규)
./bin/dynamic-state find-owner \
  --pid 8842 --debug-image /build/media_daemon.debug \
  --expr "gpMem->buffers[9]"

# 4) 다단계 구조체 및 힙 포인터 경로 즉시 해독 (0.00ms 무중단)
./bin/dynamic-state eval \
  --remote-host 192.168.1.50 --ssh-user root \
  --pid 8842 --debug-image /build/media_daemon.debug \
  --expr "g_session,g_session.worker.state.counter,g_heap_state->counter,g_node_a.next->value"

# 5) 1000ms 간격 전·후 상태 변화 비교 (Diff)
./bin/dynamic-state diff \
  --remote-host 192.168.1.50 --ssh-user root \
  --pid 8842 --debug-image /build/media_daemon.debug \
  --wait-ms 1000

# 6) 3대 진단 레시피 및 Golden Baseline 실행
./bin/dynamic-state recipe --name instant_xray --pid 8842 --debug-image /build/media_daemon.debug
./bin/dynamic-state recipe --name timeseries_watch --pid 8842 --debug-image /build/media_daemon.debug --duration-ms 2000
./bin/dynamic-state recipe --name save_baseline --pid 8842 --debug-image /build/media_daemon.debug --label "Normal_Idle"
./bin/dynamic-state recipe --name compare_baseline --pid 8842 --debug-image /build/media_daemon.debug --baseline-id golden_xxx
```

---

## 3. Web UI 3분 Quickstart

1. **Web UI 서버 실행 (호스트 서버)**:
   ```bash
   ./bin/dynamic-state-ui --host 0.0.0.0 --port 8080
   ```
   - 접속 주소: `http://<호스트>:8080/` 가 진단 화면입니다. PID 또는 프로세스 이름(원격이면 SSH 정보도)을 넣고
     **진단**을 누르면 검사가 끝나는 대로 화면이 채워지고, 끝나면 그 화면이 보고서입니다(HTML · Markdown · JSON 내려받기).
   - 이전 8탭 화면(`/legacy/`)과 채팅 워크스페이스(`/legacy/workspace`)는 제거되었고, 옛 주소는 `/` 로 옮겨 갑니다.
     레시피 · Golden Baseline · 시계열 비교는 CLI(위 2장의 `dynamic-state recipe`)와 MCP 도구로 씁니다.

---

## 4. Coding Agent (MCP) 실전 프롬프트 예시

MCP 서버(`scripts/mcp_server.py`)가 연결된 코딩 에이전트(Claude Code, Cursor, Gemini CLI 등)에게 다음과 같이 요청하세요:

> **프롬프트 예시 1 (메모리 풀 할당 맵 차트 & 특정 인덱스 점유 스레드 역추적)**:
> "현재 실행 중인 프로세스에 대해 `runtime_scan_memory_pool`로 `*gpMem` 메모리 풀의 버퍼 할당 현황을 맵 차트로 그려주고, `runtime_find_symbol_owners`로 `gpMem` 9번 인덱스를 사용 중인 스레드가 누구인지 찾아서 관련 소스 코드 위치까지 알려줘."

> **프롬프트 예시 2 (먹통/행 원인 분석)**:
> "현재 `192.168.1.50` 장비(root 계정)에서 실행 중인 `media_daemon` 프로세스가 응답이 없어. 호스트의 `/build/media_daemon.debug` 파일을 사용해서 `runtime_target_connect`와 `runtime_get_xray_blueprint`로 연결한 뒤, `runtime_run_diagnostic_recipe(recipe='instant_xray')`와 `timeseries_watch`를 실행해서 어떤 상태 구조체나 포인터 필드가 멈춰 있는지 소스코드와 대조해 원인을 찾아줘."

> **프롬프트 예시 3 (코드 수정 전후 라이브 메모리 검증)**:
> "방금 분석한 `g_session.worker.state`와 `g_heap_state->counter` 경로를 `runtime_eval_memory_path`로 읽어서 현재 메모리 값이 무엇인지 보여주고, 내가 이벤트를 발생시키는 동안 `runtime_capture_and_diff(wait_ms=2000)`로 상태 전이가 정상적으로 일어나는지 검증해 줘."

---

## 5. MCP를 쓸 수 없는 에이전트: 스킬 설치와 사용

`diagnose-process` 스킬([skills/diagnose-process/SKILL.md](../skills/diagnose-process/SKILL.md))은 에이전트가 따르는 진단 절차입니다(언제 진단하는지, 사용자에게 무엇을 물어야 하는지, 판정을 어떻게 읽는지, `INCONCLUSIVE`와 `HEALTHY`가 무슨 뜻인지, 어떤 후속 도구를 쓰는지, 어떻게 정직하게 보고하는지). 파일은 하나이고 호출 방식만 둘입니다. 각 단계에 `[mcp]` 줄(도구 호출)과 `[cli]` 줄(셸 명령)이 짝으로 들어 있고, `tests/test_skill_transports.py`가 둘이 어긋나거나 없는 도구·명령·옵션을 가리키면 실패합니다.

- **MCP를 쓸 수 있으면** MCP 서버를 연결하세요(위 4장). 서버가 스킬의 `[mcp]` 부분을 지침으로 보내 주므로 별도 설치가 필요 없습니다.
- **MCP를 쓸 수 없거나 설정할 수 없지만 셸이 있으면** 스킬을 설치하세요. 에이전트가 `dynamic-state` 명령을 실행하고 JSON 결과를 읽습니다. 스킬에는 도구가 설치되어 있는지 확인하는 방법과, 없을 때의 설치 방법도 들어 있습니다.

1. **도구 설치**: `README.md`의 Install 절(`python3 -m pip install .`). 에이전트의 `PATH`에 `dynamic-state`가 있어야 하고, 심볼 수준 진단에는 `readelf`(binutils)가 필요합니다. 대상 프로세스를 읽으려면 같은 사용자이거나 `CAP_SYS_PTRACE`가 있고 `kernel.yama.ptrace_scope`가 허용해야 합니다. 그렇지 않으면 결과는 `not_covered`에 `target_unreadable`이 있는 `INCONCLUSIVE`이며, "정상"이라고 하지 않습니다.
2. **스킬 설치**: 스킬은 설치된 패키지에 들어 있으므로 명령 하나로 복사됩니다.

   ```bash
   dynamic-state skill install            # ~/.claude/skills/diagnose-process/  (모든 프로젝트)
   dynamic-state skill install --project  # ./.claude/skills/diagnose-process/  (이 프로젝트만)
   dynamic-state skill install --dir DIR  # DIR/diagnose-process/               (임의의 스킬 디렉터리)
   ```

   이미 있으면 `--force` 없이는 덮어쓰지 않습니다. 설치 없이 체크아웃만 있으면 `cp -r skills/diagnose-process ~/.claude/skills/`도 같습니다.
   - **Claude Code**는 `~/.claude/skills/<이름>/SKILL.md`(개인)와 `.claude/skills/<이름>/SKILL.md`(프로젝트)에서 스킬을 읽습니다. 위 명령이 그 위치에 씁니다. 새 세션에서 "PID 1234 진단해줘"라고 요청하세요.
   - **그 밖의 에이전트**(Codex CLI, Gemini CLI, Cursor, Copilot, 셸 도구가 있는 채팅 모델 등)는 공통된 스킬 디렉터리가 없습니다. 공통으로 통하는 방법은 스킬 본문을 그 에이전트가 상시 지침으로 읽는 파일에 넣거나 대화 처음에 붙여 넣는 것입니다. `dynamic-state skill show`가 frontmatter 없이 명령줄용 본문을 출력합니다(`dynamic-state skill show >> AGENTS.md`). `AGENTS.md`는 Codex CLI 등이 읽고, Gemini CLI는 `GEMINI.md`, GitHub Copilot은 `.github/copilot-instructions.md`를 읽습니다. 그 외 에이전트는 해당 에이전트의 규칙/시스템 프롬프트 파일을 쓰세요(현재 파일 이름과 위치는 그 에이전트 문서로 확인). 에이전트에게 셸 명령 실행 권한이 있어야 합니다.
3. **에이전트가 실행하는 명령** (교착 데모 대상):

   ```bash
   dynamic-state find-process deadlock_demo
   dynamic-state diagnose -p $PID --corpus /tmp/ds-example/corpus --json > /tmp/ds-example/result.json
   dynamic-state export-report -p $PID -d /proc/$PID/exe --corpus /tmp/ds-example/corpus -o report.md --report-html report.html --report-json report.json
   ```

   `result.json`의 `verdict`가 `CONFIRMED_FAULT`이고 `findings[0].subjects`에 `ingest`, `m_out`, `flush`, `m_in`, `deadlock_pipeline.c:15` 같은 이름이 나오며, `collection_impact.zero_stop`은 `true`입니다. 단계별 MCP 도구와 명령의 대응표는 `README.md`의 "Agents without MCP: the skill" 절에 있습니다.
