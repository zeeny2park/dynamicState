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
2. **Step 1 (Target 연결 및 레시피 실행)**:
   - `Matching Companion Nostrip / Debug ELF`에 호스트의 디버그 바이너리 경로를 입력합니다.
   - 원격 임베디드 장비라면 `🌐 Remote Embedded Target (SSH)` 드로어를 열어 장비 IP, 계정, `Process Name`을 입력하고 `Find` → `🔍 Validate Target`을 클릭합니다.
   - 검증 완료 후 나타나는 **💡 Smart Recommended Symbols** 칩을 클릭하거나, **🩺 Quick Diagnostic Recipes**의 3가지 버튼(`Instant X-Ray`, `500ms State Diff`, `Auto-Watch`) 중 하나를 눌러 즉시 결과를 확인합니다.
3. **Tab 4 (Golden Baseline & 시계열 비교)**:
   - 정상 동작 중일 때 `📌 Save Golden Baseline`을 눌러 기준점을 저장하고, 문제 발생 시 `⚖️ Compare vs Golden`으로 변질된 구조체 필드를 즉시 찾아냅니다.

---

## 4. Coding Agent (MCP) 실전 프롬프트 예시

MCP 서버(`scripts/mcp_server.py`)가 연결된 코딩 에이전트(Claude Code, Cursor, Gemini CLI 등)에게 다음과 같이 요청하세요:

> **프롬프트 예시 1 (메모리 풀 할당 맵 차트 & 특정 인덱스 점유 스레드 역추적)**:
> "현재 실행 중인 프로세스에 대해 `runtime_scan_memory_pool`로 `*gpMem` 메모리 풀의 버퍼 할당 현황을 맵 차트로 그려주고, `runtime_find_symbol_owners`로 `gpMem` 9번 인덱스를 사용 중인 스레드가 누구인지 찾아서 관련 소스 코드 위치까지 알려줘."

> **프롬프트 예시 2 (먹통/행 원인 분석)**:
> "현재 `192.168.1.50` 장비(root 계정)에서 실행 중인 `media_daemon` 프로세스가 응답이 없어. 호스트의 `/build/media_daemon.debug` 파일을 사용해서 `runtime_target_connect`와 `runtime_get_xray_blueprint`로 연결한 뒤, `runtime_run_diagnostic_recipe(recipe='instant_xray')`와 `timeseries_watch`를 실행해서 어떤 상태 구조체나 포인터 필드가 멈춰 있는지 소스코드와 대조해 원인을 찾아줘."

> **프롬프트 예시 3 (코드 수정 전후 라이브 메모리 검증)**:
> "방금 분석한 `g_session.worker.state`와 `g_heap_state->counter` 경로를 `runtime_eval_memory_path`로 읽어서 현재 메모리 값이 무엇인지 보여주고, 내가 이벤트를 발생시키는 동안 `runtime_capture_and_diff(wait_ms=2000)`로 상태 전이가 정상적으로 일어나는지 검증해 줘."
