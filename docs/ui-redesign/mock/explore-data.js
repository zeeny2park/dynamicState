/* Canned data for the exploration mock. Names, tids, frames, lines and figures come from the benchmark targets
   (benchmarks/diagnosis_accuracy/targets/*.c), the saved results in tests/fixtures/ko_report and the real-UI screenshots
   in docs/ui-redesign/screens/impl. Two targets are illustrative and say so: slot_server (pool case) and svc_main
   (no debug info, remote). Text is [ko, en]. Values that change over time are functions of the sample index t. */
(function (G) {
  "use strict";

  // check names exactly as the live UI shows them (view.py / report), [ko, en, domain ko, domain en]
  var CK = {
    MEM_GROWTH: ["프로세스 메모리 증가", "Process memory growth", "메모리 증가", "Memory growth"],
    HEAP_GROWTH: ["힙 증가", "Heap growth", "메모리 증가", "Memory growth"],
    MAP_GROWTH: ["malloc 밖 메모리 증가", "Memory growth outside malloc", "메모리 증가", "Memory growth"],
    ALLOC_IMB: ["할당·해제 불균형", "Allocation/free imbalance", "메모리 증가", "Memory growth"],
    HEAP_META: ["힙 메타데이터 무결성", "Heap metadata integrity", "메모리 무결성", "Memory integrity"],
    DFREE: ["이중 해제", "Double free", "메모리 무결성", "Memory integrity"],
    FREED_USE: ["해제된 메모리 사용", "Freed memory use", "메모리 무결성", "Memory integrity"],
    UAF: ["해제 후 사용", "Use after free", "메모리 무결성", "Memory integrity"],
    INV_ACCESS: ["잘못된 메모리 접근", "Invalid memory access", "메모리 무결성", "Memory integrity"],
    INV_FREE: ["잘못된 해제", "Invalid free", "메모리 무결성", "Memory integrity"],
    SUSP_ALLOC: ["의심스러운 할당 패턴", "Suspicious allocation pattern", "메모리 무결성", "Memory integrity"],
    NULL_PTR: ["널·잘못된 포인터", "Null or invalid pointer", "메모리 무결성", "Memory integrity"],
    LIFETIME: ["객체 수명 이상", "Object lifetime anomaly", "메모리 증가", "Memory growth"],
    FD: ["파일 디스크립터 누수", "File descriptor leak", "프로그램 상태", "Program state"],
    THREAD_LEAK: ["스레드 누수", "Thread leak", "프로그램 상태", "Program state"],
    THREAD_STATE: ["스레드 상태 이상", "Thread state anomaly", "스레드와 락", "Threads and locks"],
    BLOCKED: ["오래 막힌 스레드", "Long-blocked thread", "스레드와 락", "Threads and locks"],
    DEADLOCK: ["교착 상태(대기 고리)", "Deadlock (wait cycle)", "스레드와 락", "Threads and locks"],
    LOCK_OWN: ["의심스러운 락 소유", "Suspicious lock ownership", "스레드와 락", "Threads and locks"],
    CONTENTION: ["락 경합", "Lock contention", "스레드와 락", "Threads and locks"],
    ORPHAN: ["주인 없는 락", "Orphan lock", "스레드와 락", "Threads and locks"],
    SELF_DL: ["자기 교착", "Self-deadlock", "스레드와 락", "Threads and locks"],
    VAR_CHG: ["예상 밖 변수 변화", "Unexpected variable change", "프로그램 상태", "Program state"],
    SHARED: ["공유 상태 불일치", "Shared state inconsistency", "스레드와 락", "Threads and locks"]
  };
  var NOREASON = ["검사가 이유를 기록하지 않음", "the check recorded no reason"];

  // a deterministic pseudo-random source so every load and every screenshot is the same
  function rng(seed) { var s = seed >>> 0; return function () { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; }; }

  var CASES = {};

  /* ------------------------------------------------------------------ healthy: ok_busy_server */
  CASES.healthy = {
    label: ["정상", "Healthy"],
    target: { name: "ok_busy_server", pid: 41177, arch: "aarch64", libc: "glibc", exe: "/opt/svc/bin/ok_busy_server",
      buildid: "7d02c4f1a8e93b6d0c51e2f74a90b3d841aa", debug: ["DWARF 있음 (대상 실행 파일)", "DWARF (target executable)"],
      transport: ["로컬", "local"], threads: 3 },
    verdict: { code: "HEALTHY", tone: "pass", word: ["점검한 범위 안에서 정상", "Healthy within the checked scope"],
      mean: ["점검한 범위 밖에 대해서는 판단하지 않습니다.", "Nothing is said about what was not checked."],
      sum: ["<code>ok_busy_server</code> (pid 41177)은(는) 점검한 범위 안에서 정상입니다. 기본 검사 14개가 모두 끝까지 실행되었고 아무것도 발견하지 못했습니다. 메모리는 3.4초 동안 그대로였고, 두 작업 스레드 <code>serve0</code>, <code>serve1</code>은 계속 일하고 있었습니다.",
            "<code>ok_busy_server</code> (pid 41177) is healthy within the checked scope. All 14 baseline checks ran to completion and found nothing. Memory stayed flat for 3.4 s and the two workers <code>serve0</code>, <code>serve1</code> kept working."],
      dur: ["3.4초", "3.4 s"], bytes: "61 KB", stop: "0 ms" },
    tiles: { ran: 17, fail: 0, inc: 2, pass: 15, skip: 13 },
    findings: [],
    checks: [
      ["INV_ACCESS", "INCONCLUSIVE", NOREASON, 29], ["MEM_GROWTH", "PASS", ["증가 추세 없음 (RSS +0 KB, 0.70초 동안 표본 6개): 힙 순회는 필요 없음", "no growth trend (RSS +0 KB over 0.70 s, 6 samples)"], 702],
      ["LOCK_OWN", "PASS", ["락 소유 관계에 이상이 없음을 확인", "lock ownership consistent"], 7], ["DEADLOCK", "PASS", ["대기 관계 그래프가 완전하며 고리가 없음", "wait-for graph complete, no cycle"], 7],
      ["THREAD_STATE", "PASS", ["모든 스레드가 정상 상태", "all threads in normal states"], 8], ["BLOCKED", "PASS", ["샘플링 구간에서 소유자가 진행하지 않는데 락을 기다리는 스레드는 없음", "no thread waits on a lock whose owner is not progressing"], 8],
      ["HEAP_META", "PASS", ["힙 메타데이터에 이상 없음: 청크 3개를 훑었고 top 청크, 해제 목록, bin 연결 일치", "heap metadata intact: 3 chunks walked"], 2],
      ["DFREE", "PASS", ["모든 해제 목록을 끝까지 따라갔고 두 번 올라 있는 블록은 없음", "no block listed twice"], 21],
      ["FD", "PASS", ["열린 fd 3 -> 3 -> 3, 0.8초 동안 (+0, 0.0/초), 한도 1048576", "open fds 3 -> 3 -> 3 over 0.8 s, limit 1048576"], 804],
      ["CONTENTION", "PASS", ["0.64초 동안 샘플 5회: 스레드 2개 이상이 기다린 샘플이 40%를 넘는 뮤텍스 없음", "no mutex with waiters in over 40% of 5 samples"], 3],
      ["ORPHAN", "PASS", ["뮤텍스 0개를 샘플 2회에서 검사: 잠긴 뮤텍스는 모두 살아 있는 스레드가 소유", "0 mutexes, every locked one has a live owner"], 162],
      ["SELF_DL", "PASS", ["뮤텍스 0개를 샘플 2회에서 검사: 자기가 소유한 뮤텍스를 기다리는 스레드 없음", "no thread waits for a mutex it owns"], 3],
      ["MAP_GROWTH", "PASS", ["malloc 밖에서 증가 없음: malloc 밖의 익명 메모리 +0 KB, 0.9초 동안", "no anonymous growth outside malloc over 0.9 s"], 905],
      ["THREAD_LEAK", "PASS", ["스레드 수 3 -> 3 -> 3 -> 3, 0.6초 동안 (+0, 0.0/초)", "threads 3 -> 3 -> 3 -> 3 over 0.6 s"], 4],
      ["FREED_USE", "PASS", ["해제된 청크를 가리키는 타입 있는 포인터도 쓰기가 일어난 해제 청크도 없음", "no typed pointer to a freed chunk"], 4],
      ["ALLOC_IMB", "INCONCLUSIVE", NOREASON, 3], ["HEAP_GROWTH", "PASS", ["힙 크기가 안정적임 (변화량 0바이트)", "heap stable (delta 0 bytes)"], 3]
    ],
    notseen: [[CK.INV_ACCESS, NOREASON], [CK.ALLOC_IMB, NOREASON],
      [["데이터 레이스, 프로그램 논리 오류", "data races, logic errors"], ["기본 검사가 찾지 않는 종류", "not what the baseline checks look for"]]],
    next: ["이 검사 결과로는 고칠 것이 없습니다. 증상이 계속되면 더 구체적으로 알려 다시 실행하고, '확인하지 못한 것'에 적힌 항목도 함께 고려하세요.",
      "Nothing to fix from these checks. If the symptom persists, describe it more specifically and run again; also weigh the items under 'Not examined'."],
    profile: {
      window: ["관측 구간 3.4초, 표본 42회", "window 3.4 s, 42 samples"],
      sum: { threads: "3", rss: "1.7 MB", heap: "132 KiB", fds: "3" },
      threads: [
        { tid: 41177, name: "ok_busy_server", st: "S S S S S", cpu: "0%", top: ["pause", "ok_busy_server.c:39"],
          frames: [["pause", "libc.so.6", ""], ["main", "", "ok_busy_server.c:39"], ["__libc_start_call_main", "libc.so.6", ""], ["__libc_start_main", "libc.so.6", ""], ["_start", "ok_busy_server", ""]],
          locals: { 1: [["t", "pthread_t[2]", "{281473448235232, 281473439781088}"]] }, holds: [], waits: null },
        { tid: 41178, name: "serve0", st: "R S S R S", cpu: "38%", top: ["clock_nanosleep", "ok_busy_server.c:25"],
          frames: [["clock_nanosleep", "libc.so.6", ""], ["usleep", "libc.so.6", ""], ["serve_loop", "", "ok_busy_server.c:25"], ["start_thread", "libc.so.6", ""], ["thread_start", "libc.so.6", ""]],
          locals: { 2: [["arg", "void *", "0x0"], ["me", "int", "0"]] }, holds: [], waits: null },
        { tid: 41179, name: "serve1", st: "S R S S R", cpu: "37%", top: ["clock_nanosleep", "ok_busy_server.c:25"],
          frames: [["clock_nanosleep", "libc.so.6", ""], ["usleep", "libc.so.6", ""], ["serve_loop", "", "ok_busy_server.c:25"], ["start_thread", "libc.so.6", ""], ["thread_start", "libc.so.6", ""]],
          locals: { 2: [["arg", "void *", "0x1"], ["me", "int", "1"]] }, holds: [], waits: null }
      ],
      threadsLine: ["3개 · 실행 2 · 대기 1 · 막힌 스레드 없음", "3 · 2 running · 1 waiting · none blocked"],
      memory: { line: ["RSS 1.7 MB, 3.4초 동안 +0 KB · 매핑 19개 · 힙 청크 3개", "RSS 1.7 MB, +0 KB over 3.4 s · 19 mappings · 3 heap chunks"],
        cats: [[["공유 라이브러리", "Shared libraries"], 1280, 1], [["기타 익명", "Other anonymous"], 380, 4], [["스레드 스택", "Thread stacks"], 56, 3], [["힙", "Heap"], 12, 2], [["실행 파일", "Executable"], 8, 5]],
        maps: [
          ["aaaad5f20000", "aaaad5f21000", "r-xp", "4 KiB", 5, "/opt/svc/bin/ok_busy_server"],
          ["aaaad5f30000", "aaaad5f31000", "r--p", "4 KiB", 5, "/opt/svc/bin/ok_busy_server"],
          ["aaaad5f31000", "aaaad5f32000", "rw-p", "4 KiB", 5, "/opt/svc/bin/ok_busy_server  .data .bss"],
          ["aaab0c4e5000", "aaab0c506000", "rw-p", "132 KiB", 2, "[heap]"],
          ["ffff7ce00000", "ffff7d600000", "rw-p", "8 MiB", 3, ["[serve0 스택]", "[serve0 stack]"]],
          ["ffff7d610000", "ffff7de10000", "rw-p", "8 MiB", 3, ["[serve1 스택]", "[serve1 stack]"]],
          ["ffff7de20000", "ffff7dfa8000", "r-xp", "1.5 MiB", 1, "/usr/lib/aarch64-linux-gnu/libc.so.6"],
          ["ffff7dfbb000", "ffff7dfbd000", "rw-p", "8 KiB", 1, "/usr/lib/aarch64-linux-gnu/libc.so.6"],
          ["ffff7dfd0000", "ffff7dffb000", "r-xp", "172 KiB", 1, "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"],
          ["ffffd8a10000", "ffffd8a31000", "rw-p", "132 KiB", 3, "[stack]"]
        ], more: 9 },
      locks: { line: ["기다린 락 없음 (표본 5회) · 관측된 뮤텍스 0개", "no lock waited on (5 samples) · 0 mutexes seen"], list: [] },
      files: { line: ["3개 · 0.8초 동안 3 → 3 → 3", "3 · 3 → 3 → 3 over 0.8 s"],
        list: [["0", "tty", "/dev/pts/3"], ["1", "pipe", "pipe:[811233]"], ["2", "tty", "/dev/pts/3"]] },
      modules: { line: ["4개 · 디버그 정보: 실행 파일만 (DWARF)", "4 · debug info: executable only (DWARF)"],
        list: [["ok_busy_server", "aaaad5f20000", ["DWARF 있음", "DWARF"]], ["libc.so.6", "ffff7de20000", ["심볼만 (.dynsym)", "symbols only (.dynsym)"]],
          ["ld-linux-aarch64.so.1", "ffff7dfd0000", ["심볼만", "symbols only"]], ["linux-vdso.so.1", "ffff7e010000", ["심볼만", "symbols only"]]] },
      vars: { line: ["전역·정적 2개 (DWARF) · 검색해서 값 보기", "2 globals/statics (DWARF) · search to read a value"], query: "handled",
        list: [
          { name: "handled", type: "volatile uint64_t[2]", size: "16 B", sect: ".bss", decl: "ok_busy_server.c:7", addr: "aaaad5f31010", kind: "array",
            elems: [["handled[0]", "uint64_t"], ["handled[1]", "uint64_t"]] },
          { name: "digest", type: "volatile uint32_t[2]", size: "8 B", sect: ".bss", decl: "ok_busy_server.c:8", addr: "aaaad5f31020", kind: "array",
            elems: [["digest[0]", "uint32_t"], ["digest[1]", "uint32_t"]] }
        ] }
    },
    series: {
      "handled[0]": function (t) { return 1612 + t * 471 + ((t * 7) % 5); },
      "handled[1]": function (t) { return 1598 + t * 466 + ((t * 3) % 4); },
      "digest[0]": function (t) { return hex32(Math.imul(0x9e3779b1, t + 11) >>> 0); },
      "digest[1]": function (t) { return hex32(Math.imul(0x85ebca6b, t + 5) >>> 0); }
    },
    stages: [
      { key: "result", label: ["결과", "Result"], cap: ["진단이 끝난 화면. 대상 아래에 새 '프로세스 프로필' 카드가 있고, 줄마다 어떻게 관측했는지가 적혀 있다.", "The finished screen. A new Process profile card sits under Target; every row says how it was observed."] },
      { key: "threads", label: ["스레드", "Threads"], cap: ["'스레드' 줄을 펼치고 serve0을 눌러 호출 스택과 선택한 프레임의 지역 변수를 본다. 아래 카드는 밀려 내려갈 뿐 위는 움직이지 않는다.", "Open Threads, then serve0: its call stack and the locals of the selected frame. Content below is pushed down; nothing above moves."],
        open: ["pf:threads", "th:41178"], frame: { 41178: 2 } },
      { key: "memory", label: ["메모리", "Memory"], cap: ["'메모리' 줄: 주소 공간 구성 → 매핑 목록. 매핑을 고르면 그 범위를 읽는다.", "Memory: address-space breakdown, then the mapping list. Choosing a mapping reads that range."],
        open: ["pf:memory", "maps"] },
      { key: "vars", label: ["변수", "Variables"], cap: ["'변수' 줄의 검색 상자: handled → 결과 → 값 보기 → 추적에 추가.", "The search box in Variables: handled, results, Show value, Add to watch."],
        open: ["pf:vars", "var:handled"], track: ["handled", "digest"], ticks: 0 },
      { key: "watch", label: ["관찰", "Watch"], cap: ["'관찰' 카드가 다음에 할 일 아래에 생기고, 값이 1초마다 갱신된다. 헤더 칩은 '관찰 중'.", "The Watch card appears under Next steps; values refresh every second. The header chip says watching."],
        open: [], track: ["handled", "digest"], ticks: 24, focus: "observe" },
      { key: "compare", label: ["비교", "Compare"], cap: ["'지금 값 고정' 뒤에 바뀐 항목만 이전 → 지금으로 나온다.", "After Freeze now only the items that changed are listed, before → after."],
        open: [], track: ["handled", "digest"], ticks: 30, freezeAt: 24, openTrack: ["handled"], focus: "observe" },
      { key: "report", label: ["보고서", "Report"], cap: ["'보고서에 추가' 뒤의 보고서 보기: 같은 카드 + '추가 관찰' 절.", "Report view after Add to report: the same cards plus an Additional observation section."],
        open: [], track: ["handled", "digest"], ticks: 30, freezeAt: 24, inReport: true, view: "report", focus: "obs-report" }
    ]
  };

  /* ------------------------------------------------------------------ deadlock: deadlock_pipeline */
  CASES.deadlock = {
    label: ["교착", "Deadlock"],
    target: { name: "deadlock_pipeli", pid: 4098732, arch: "aarch64", libc: "glibc", exe: "/opt/pipeline/bin/deadlock_pipeline",
      buildid: "a17d964ec7bc8b15a4ac05ff43b0d2e19c2e", debug: ["/proc/4098732/exe", "/proc/4098732/exe"], transport: ["로컬", "local"], threads: 3 },
    verdict: { code: "CONFIRMED_FAULT", tone: "fail", word: ["확인된 결함", "Confirmed fault"],
      mean: ["확보한 증거가 문제를 입증합니다.", "The evidence proves a problem."],
      sum: ["<code>deadlock_pipeli</code> (pid 4098732)에서 확인된 문제가 있습니다: 교착 상태. <code>ingest</code> (tid 4098733)이(가) 락 <code>m_out</code> 을(를) 기다림; <code>flush</code> (tid 4098734)이(가) 락 <code>m_in</code> 을(를) 기다림.",
            "<code>deadlock_pipeli</code> (pid 4098732) has a confirmed problem: deadlock. <code>ingest</code> (tid 4098733) waits for lock <code>m_out</code>; <code>flush</code> (tid 4098734) waits for lock <code>m_in</code>."],
      dur: ["4.7초", "4.7 s"], bytes: "188 KB", stop: "0 ms" },
    tiles: { ran: 14, fail: 3, inc: 1, pass: 10, skip: 16 },
    findings: [{ n: 1, title: ["교착 상태(deadlock)", "Deadlock"], cat: "DEADLOCK_INDICATORS", status: ["확정된 근본 원인", "Confirmed root cause"], sev: ["치명적", "critical"],
      steps: [
        [["<code>ingest</code> : 락 <code>m_in</code> 획득", "<code>ingest</code> : takes lock <code>m_in</code>"], "rec"],
        [["<code>flush</code> : 락 <code>m_out</code> 획득", "<code>flush</code> : takes lock <code>m_out</code>"], "rec"],
        [["<code>ingest</code> : <code>flush</code> 이(가) 잡고 있는 락 <code>m_out</code> 을(를) 요청하고 대기 · <code>deadlock_pipeline.c:15</code>", "<code>ingest</code> : waits for <code>m_out</code>, held by <code>flush</code> · <code>deadlock_pipeline.c:15</code>"], "obs"],
        [["<code>flush</code> : <code>ingest</code> 이(가) 잡고 있는 락 <code>m_in</code> 을(를) 요청하고 대기 · <code>deadlock_pipeline.c:27</code>", "<code>flush</code> : waits for <code>m_in</code>, held by <code>ingest</code> · <code>deadlock_pipeline.c:27</code>"], "obs"],
        [["고리가 닫힘: 0.63초 동안 5회 샘플, CPU 0%, 같은 고리가 서로 다른 2번의 관측에서 확인됨", "The cycle is closed: 5 samples over 0.63 s, CPU 0%, the same cycle in 2 separate observations"], "obs"]
      ],
      subjects: [["thread", "4098733"], ["thread_name", "deadlock_pipeli"], ["lock", "m_out"], ["thread", "4098734"], ["lock", "m_in"],
        ["function", "__GI___lll_lock_wait"], ["function", "pthread_mutex_lock"], ["source_location", "deadlock_pipeline.c:15"], ["source_location", "deadlock_pipeline.c:27"]] }],
    refuted: ["MEMORY_LEAK", "MEMORY_CORRUPTION", "INVALID_DOUBLE_FREE", "FD_LEAK", "LOCK_CONTENTION", "ORPHAN_LOCK"],
    checks: [
      ["THREAD_STATE", "INCONCLUSIVE", NOREASON, 787], ["LOCK_OWN", "FAIL", ["의심스럽거나 고리를 이루는 뮤텍스 소유 관계를 발견", "suspicious or circular mutex ownership"], 74],
      ["DEADLOCK", "FAIL", ["스레드 사이의 대기 고리가 계속 유지됨을 확인", "a wait cycle between threads persists"], 73],
      ["BLOCKED", "FAIL", ["멈춘 스레드 2개; 스레드 'deadlock_pipeli' (tid 4098732)이(가) 0.63초 구간 내내 ppoll", "2 blocked threads"], 115],
      ["MEM_GROWTH", "PASS", ["증가 추세 없음 (RSS +0 KB, 1.10초 동안 샘플 6개)", "no growth trend (RSS +0 KB over 1.10 s)"], 4],
      ["HEAP_META", "PASS", ["힙 메타데이터에 이상 없음: 청크 4개를 훑었고 top 청크, 해제 목록, bin 연결 일치", "heap metadata intact: 4 chunks"], 30],
      ["DFREE", "PASS", ["모든 해제 목록을 끝까지 따라갔고 두 번 올라 있는 블록은 없음", "no block listed twice"], 4],
      ["FD", "PASS", ["열린 fd 3 -> 3 -> 3, 0.8초 동안 (+0, 0.0/초), 한도 1048576", "open fds 3 -> 3 -> 3 over 0.8 s"], 805],
      ["CONTENTION", "PASS", ["0.63초 동안 샘플 5회: 스레드 2개 이상이 기다린 샘플이 40%를 넘는 뮤텍스 없음", "no contended mutex"], 5],
      ["ORPHAN", "PASS", ["뮤텍스 2개를 샘플 2회에서 검사: 잠긴 뮤텍스는 모두 살아 있는 스레드가 소유", "2 mutexes, live owners"], 166],
      ["SELF_DL", "PASS", ["뮤텍스 2개를 샘플 2회에서 검사: 자기가 소유한 뮤텍스를 기다리는 스레드 없음", "no self-wait"], 3],
      ["MAP_GROWTH", "PASS", ["malloc 밖에서 증가 없음: 익명 메모리 +0 KB, 0.9초 동안", "no growth outside malloc"], 905],
      ["THREAD_LEAK", "PASS", ["스레드 수 3 -> 3 -> 3 -> 3, 0.6초 동안 (+0, 0.0/초)", "threads 3 -> 3 -> 3"], 5],
      ["FREED_USE", "PASS", ["해제된 청크를 가리키는 타입 있는 포인터도 쓰기가 일어난 해제 청크도 없음", "no freed-memory use"], 5]
    ],
    notseen: [[CK.THREAD_STATE, NOREASON]],
    next: ["두 락 <code>m_out</code> 와 <code>m_in</code> 가 서로 반대 순서로 잡히고 있습니다. <code>ingest</code> (<code>deadlock_pipeline.c:15</code>)와 <code>flush</code> (<code>deadlock_pipeline.c:27</code>)가 각각 하나를 잡은 채 다른 하나를 기다립니다. 두 위치에서 락을 잡는 순서를 하나로 맞추세요.",
      "<code>m_out</code> and <code>m_in</code> are taken in opposite orders by <code>ingest</code> (<code>deadlock_pipeline.c:15</code>) and <code>flush</code> (<code>deadlock_pipeline.c:27</code>). Make both take them in one order."],
    profile: {
      window: ["관측 구간 0.63초, 표본 5회 (스레드) · 1.1초, 6회 (메모리)", "window 0.63 s, 5 samples (threads) · 1.1 s, 6 (memory)"],
      sum: { threads: "3", rss: "1.5 MB", heap: "132 KiB", fds: "3" },
      threads: [
        { tid: 4098732, name: "deadlock_pipeli", st: "S S S S S", cpu: "0%", top: ["ppoll", "deadlock_pipeline.c:42"],
          frames: [["ppoll", "libc.so.6", ""], ["pause", "libc.so.6", ""], ["main", "", "deadlock_pipeline.c:42"], ["__libc_start_call_main", "libc.so.6", ""], ["_start", "deadlock_pipeline", ""]],
          locals: { 2: [["a", "pthread_t", "281473602437344"], ["b", "pthread_t", "281473594044640"]] }, holds: [], waits: null },
        { tid: 4098733, name: "ingest", st: "S S S S S", cpu: "0%", top: ["__GI___lll_lock_wait", "deadlock_pipeline.c:15"], hot: true,
          frames: [["__GI___lll_lock_wait", "libc.so.6", ""], ["pthread_mutex_lock", "libc.so.6", ""], ["ingest", "", "deadlock_pipeline.c:15"], ["start_thread", "libc.so.6", ""], ["thread_start", "libc.so.6", ""]],
          locals: { 2: [["arg", "void *", "0x0"]] }, holds: ["m_in"], waits: "m_out" },
        { tid: 4098734, name: "flush", st: "S S S S S", cpu: "0%", top: ["__GI___lll_lock_wait", "deadlock_pipeline.c:27"], hot: true,
          frames: [["__GI___lll_lock_wait", "libc.so.6", ""], ["pthread_mutex_lock", "libc.so.6", ""], ["flush", "", "deadlock_pipeline.c:27"], ["start_thread", "libc.so.6", ""], ["thread_start", "libc.so.6", ""]],
          locals: { 2: [["arg", "void *", "0x0"]] }, holds: ["m_out"], waits: "m_in" }
      ],
      threadsLine: ["3개 · 락 대기 2 (고리) · 대기 1", "3 · 2 waiting on locks (cycle) · 1 idle"],
      memory: { line: ["RSS 1.5 MB, 1.1초 동안 +0 KB · 매핑 21개 · 힙 청크 4개", "RSS 1.5 MB, +0 KB over 1.1 s · 21 mappings · 4 heap chunks"],
        cats: [[["공유 라이브러리", "Shared libraries"], 1268, 1], [["기타 익명", "Other anonymous"], 212, 4], [["스레드 스택", "Thread stacks"], 40, 3], [["힙", "Heap"], 8, 2], [["실행 파일", "Executable"], 8, 5]],
        maps: [
          ["aaaab0e10000", "aaaab0e11000", "r-xp", "4 KiB", 5, "/opt/pipeline/bin/deadlock_pipeline"],
          ["aaaab0e21000", "aaaab0e22000", "rw-p", "4 KiB", 5, "/opt/pipeline/bin/deadlock_pipeline  .data .bss"],
          ["aaaacf2b1000", "aaaacf2d2000", "rw-p", "132 KiB", 2, "[heap]"],
          ["ffffa0400000", "ffffa0c00000", "rw-p", "8 MiB", 3, ["[ingest 스택]", "[ingest stack]"]],
          ["ffffa0c10000", "ffffa1410000", "rw-p", "8 MiB", 3, ["[flush 스택]", "[flush stack]"]],
          ["ffffa1420000", "ffffa15a8000", "r-xp", "1.5 MiB", 1, "/usr/lib/aarch64-linux-gnu/libc.so.6"],
          ["ffffa15d0000", "ffffa15fb000", "r-xp", "172 KiB", 1, "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"],
          ["ffffe7c20000", "ffffe7c41000", "rw-p", "132 KiB", 3, "[stack]"]
        ], more: 13 },
      locks: { line: ["뮤텍스 2개 · 둘 다 소유됨, 서로를 기다림", "2 mutexes · both owned, each waits for the other"],
        list: [
          { name: "m_out", type: "pthread_mutex_t", addr: "aaaab0e21040", owner: 4098734, waiters: [4098733], decl: "deadlock_pipeline.c:5", lockw: "2" },
          { name: "m_in", type: "pthread_mutex_t", addr: "aaaab0e21010", owner: 4098733, waiters: [4098734], decl: "deadlock_pipeline.c:4", lockw: "2" }
        ] },
      files: { line: ["3개 · 0.8초 동안 3 → 3 → 3", "3 · 3 → 3 → 3 over 0.8 s"], list: [["0", "tty", "/dev/pts/1"], ["1", "pipe", "pipe:[9823411]"], ["2", "tty", "/dev/pts/1"]] },
      modules: { line: ["4개 · 디버그 정보: 실행 파일만 (DWARF)", "4 · debug info: executable only (DWARF)"],
        list: [["deadlock_pipeline", "aaaab0e10000", ["DWARF 있음", "DWARF"]], ["libc.so.6", "ffffa1420000", ["심볼만 (.dynsym)", "symbols only (.dynsym)"]],
          ["ld-linux-aarch64.so.1", "ffffa15d0000", ["심볼만", "symbols only"]], ["linux-vdso.so.1", "ffffa1610000", ["심볼만", "symbols only"]]] },
      vars: { line: ["전역·정적 3개 (DWARF) · 검색해서 값 보기", "3 globals/statics (DWARF) · search to read a value"], query: "m_",
        list: [
          { name: "m_out", type: "pthread_mutex_t", size: "48 B", sect: ".data", decl: "deadlock_pipeline.c:5", addr: "aaaab0e21040", kind: "struct",
            fields: [["__data.__lock", "int", "2"], ["__data.__count", "unsigned int", "0"], ["__data.__owner", "int", "4098734"], ["__data.__nusers", "unsigned int", "1"], ["__data.__kind", "int", "0"]] },
          { name: "m_in", type: "pthread_mutex_t", size: "48 B", sect: ".data", decl: "deadlock_pipeline.c:4", addr: "aaaab0e21010", kind: "struct",
            fields: [["__data.__lock", "int", "2"], ["__data.__count", "unsigned int", "0"], ["__data.__owner", "int", "4098733"], ["__data.__nusers", "unsigned int", "1"], ["__data.__kind", "int", "0"]] },
          { name: "bar", type: "pthread_barrier_t", size: "32 B", sect: ".bss", decl: "deadlock_pipeline.c:6", addr: "aaaab0e21070", kind: "opaque", value: "{__size = \"\\002\", '\\000' <repeats 30 times>}" }
        ] }
    },
    series: {
      "m_out.__data.__owner": function () { return 4098734; }, "m_out.__data.__lock": function () { return 2; },
      "m_in.__data.__owner": function () { return 4098733; }, "m_in.__data.__lock": function () { return 2; },
      "m_out.__data.__count": function () { return 0; }, "m_out.__data.__nusers": function () { return 1; }, "m_out.__data.__kind": function () { return 0; },
      "m_in.__data.__count": function () { return 0; }, "m_in.__data.__nusers": function () { return 1; }, "m_in.__data.__kind": function () { return 0; }
    },
    stages: [
      { key: "result", label: ["결과", "Result"], cap: ["발견 카드 아래 '관련 정보' 칩: 발견이 이름을 댄 스레드와 락에서 만들어진다. 프로필은 닫혀 있다.", "Related chips under the finding are built from the threads and locks it names. The profile is closed."] },
      { key: "thread", label: ["칩 → 스레드", "Chip → thread"], cap: ["[스레드 ingest] 칩: 프로필의 같은 자리(스레드 → ingest)로 스크롤해 펼친다. 프레임 #2 ingest를 골라 지역 변수, 잡은 락·기다리는 락을 본다.", "The ingest chip scrolls to the same place in the profile and opens it; frame #2 shows its locals and the locks held and awaited."],
        open: ["pf:threads", "th:4098733"], frame: { 4098733: 2 }, from: "finding-1", focus: "th:4098733" },
      { key: "lock", label: ["락", "Lock"], cap: ["[락 m_out] 칩: 소유자 flush와 대기자 ingest를 각자의 맨 위 프레임과 함께.", "The m_out chip: owner flush and waiter ingest with their top frames."],
        open: ["pf:locks", "lk:m_out"], from: "finding-1", focus: "lk:m_out" },
      { key: "watch", label: ["관찰", "Watch"], cap: ["락의 '소유자 추적': m_out, m_in을 관찰에 넣으면 24번의 표본 동안 값이 한 번도 바뀌지 않는다(고리가 풀리지 않음).", "Watching both mutexes: 24 samples, no value ever changes (the cycle never resolves)."],
        open: [], track: ["m_out", "m_in"], ticks: 24, openTrack: ["m_out"], focus: "observe" }
    ]
  };

  /* ------------------------------------------------------------------ overflow: overflow_ring */
  var OVF_BASE = 0xabf89a76d290;
  CASES.overflow = {
    label: ["버퍼 넘침", "Overflow"],
    target: { name: "overflow_ring", pid: 3732883, arch: "aarch64", libc: "glibc", exe: "/opt/ring/bin/overflow_ring",
      buildid: "3c9e51d07a4b2f68e1d0c7a95b3e4f21d6a8", debug: ["/proc/3732883/exe", "/proc/3732883/exe"], transport: ["로컬", "local"], threads: 1 },
    verdict: { code: "CONFIRMED_FAULT", tone: "fail", word: ["확인된 결함", "Confirmed fault"],
      mean: ["확보한 증거가 문제를 입증합니다.", "The evidence proves a problem."],
      sum: ["<code>overflow_ring</code> (pid 3732883)에서 확인된 문제가 있습니다: 힙 메모리 손상. 버퍼 <code>rb.buf</code> (사용 가능 72 B)에 쓴 내용이 끝을 24 B 넘어, 다음 블록 <code>aux</code> 의 청크 헤더를 덮었습니다.",
            "<code>overflow_ring</code> (pid 3732883) has a confirmed problem: heap corruption. A write into <code>rb.buf</code> (72 usable bytes) ran 24 bytes past its end and overwrote the chunk header of the next block, <code>aux</code>."],
      dur: ["3.8초", "3.8 s"], bytes: "535 KB", stop: "0 ms" },
    tiles: { ran: 20, fail: 1, inc: 6, pass: 13, skip: 11 },
    findings: [{ n: 1, title: ["힙 메모리 손상 (버퍼 넘침)", "Heap corruption (buffer overflow)"], cat: "MEMORY_CORRUPTION", status: ["확정된 근본 원인", "Confirmed root cause"], sev: ["치명적", "critical"],
      mem: true,
      steps: [
        [["버퍼 <code>rb.buf</code> = 힙 블록 <code>0xabf89a76d2a0</code>, 사용 가능 72 B", "<code>rb.buf</code> = heap block <code>0xabf89a76d2a0</code>, 72 usable bytes"], "rec"],
        [["쓰기가 끝을 24 B 넘음: 같은 바이트 <code>0x6d</code> 가 버퍼 끝과 그 뒤를 채움", "The write ran 24 bytes past the end: byte <code>0x6d</code> fills the buffer's end and beyond"], "obs"],
        [["다음 청크 헤더 <code>0xabf89a76d2e0</code> 의 크기가 <code>0x6d6d6d6d6d6d6d68</code> 로 손상, 재읽기 2회에서 같음", "The next chunk header at <code>0xabf89a76d2e0</code> has size <code>0x6d6d6d6d6d6d6d68</code>, same on 2 re-reads"], "obs"],
        [["손상된 블록의 주인은 <code>aux</code>", "The damaged block belongs to <code>aux</code>"], "obs"]
      ],
      subjects: [["variable", "rb"], ["variable", "rb.buf"], ["variable", "aux"], ["address", "0xabf89a76d2e0"]] }],
    refuted: ["DEADLOCK_INDICATORS", "MEMORY_LEAK", "FD_LEAK", "INVALID_DOUBLE_FREE"],
    checks: [
      ["INV_ACCESS", "INCONCLUSIVE", NOREASON, 61], ["INV_FREE", "INCONCLUSIVE", NOREASON, 12], ["UAF", "INCONCLUSIVE", ["추적 모드가 필요함 (DYNAMIC_EVENT_TRACING)", "needs tracing (DYNAMIC_EVENT_TRACING)"], 2],
      ["HEAP_META", "FAIL", ["청크 헤더 손상 0xabf89a76d2e0 (크기 0x6d6d6d6d6d6d6d68), 재읽기 2회 같음; 넘친 버퍼 rb.buf", "chunk header damaged at 0xabf89a76d2e0; overflowing buffer rb.buf"], 140],
      ["SUSP_ALLOC", "INCONCLUSIVE", NOREASON, 9], ["NULL_PTR", "INCONCLUSIVE", NOREASON, 21], ["DFREE", "PASS", ["모든 해제 목록을 끝까지 따라갔고 두 번 올라 있는 블록은 없음", "no block listed twice"], 6],
      ["LIFETIME", "INCONCLUSIVE", NOREASON, 4], ["THREAD_STATE", "PASS", ["모든 스레드가 정상 상태", "all threads normal"], 7], ["BLOCKED", "PASS", ["락을 기다리는 스레드 없음", "no thread waits on a lock"], 9],
      ["LOCK_OWN", "PASS", ["락 소유 관계에 이상 없음", "lock ownership consistent"], 6], ["DEADLOCK", "PASS", ["고리 없음", "no cycle"], 6],
      ["MEM_GROWTH", "PASS", ["증가 추세 없음 (RSS +0 KB, 1.0초 동안 표본 6개)", "no growth trend (RSS +0 KB over 1.0 s)"], 1004],
      ["FD", "PASS", ["열린 fd 3 -> 3 -> 3, 0.8초 동안", "open fds 3 -> 3 -> 3"], 801], ["CONTENTION", "PASS", ["경합한 뮤텍스 없음", "no contended mutex"], 4],
      ["ORPHAN", "PASS", ["뮤텍스 0개", "0 mutexes"], 120], ["SELF_DL", "PASS", ["자기 교착 없음", "no self-wait"], 3],
      ["MAP_GROWTH", "PASS", ["malloc 밖에서 증가 없음", "no growth outside malloc"], 902], ["THREAD_LEAK", "PASS", ["스레드 수 1 -> 1 -> 1", "threads 1 -> 1 -> 1"], 4],
      ["FREED_USE", "PASS", ["해제된 청크를 가리키는 포인터 없음", "no pointer to a freed chunk"], 5]
    ],
    notseen: [[CK.INV_ACCESS, NOREASON], [CK.INV_FREE, NOREASON], [CK.UAF, ["추적 모드가 꺼져 있음", "tracing is off"]], [CK.SUSP_ALLOC, NOREASON], [CK.NULL_PTR, NOREASON], [CK.LIFETIME, NOREASON]],
    next: ["<code>rb_put</code> 이 길이를 확인하지 않고 <code>memcpy(r->buf + r->head, src, len)</code> (<code>overflow_ring.c:24</code>)로 96 B를 64 B 버퍼에 씁니다. 남은 공간까지만 복사하거나 둘로 나눠 감아 쓰세요. 이미 손상된 힙은 다음 <code>free</code>·<code>malloc</code> 에서 중단될 수 있으니 재시작이 필요합니다.",
      "<code>rb_put</code> copies 96 bytes into a 64-byte buffer with no length check (<code>overflow_ring.c:24</code>). Copy only what fits, or wrap in two parts. The damaged heap may abort on the next free/malloc; restart the process."],
    profile: {
      window: ["관측 구간 1.0초, 표본 42회", "window 1.0 s, 42 samples"],
      sum: { threads: "1", rss: "1.4 MB", heap: "132 KiB", fds: "3" },
      threads: [{ tid: 3732883, name: "overflow_ring", st: "S S S S S", cpu: "0%", top: ["pause", "overflow_ring.c:39"],
        frames: [["pause", "libc.so.6", ""], ["main", "", "overflow_ring.c:39"], ["__libc_start_call_main", "libc.so.6", ""], ["__libc_start_main", "libc.so.6", ""], ["_start", "overflow_ring", ""]],
        locals: { 1: [["msg", "unsigned char[96]", "'m' <repeats 96 times>"]] }, holds: [], waits: null }],
      threadsLine: ["1개 · 대기 1", "1 · 1 idle"],
      memory: { line: ["RSS 1.4 MB, 1.0초 동안 +0 KB · 매핑 17개 · 힙 청크 4개 (1개 손상)", "RSS 1.4 MB, +0 KB over 1.0 s · 17 mappings · 4 heap chunks (1 damaged)"],
        cats: [[["공유 라이브러리", "Shared libraries"], 1240, 1], [["기타 익명", "Other anonymous"], 160, 4], [["스택", "Stack"], 16, 3], [["힙", "Heap"], 8, 2], [["실행 파일", "Executable"], 8, 5]],
        maps: [
          ["aaaab8c40000", "aaaab8c41000", "r-xp", "4 KiB", 5, "/opt/ring/bin/overflow_ring"],
          ["aaaab8c51000", "aaaab8c52000", "rw-p", "4 KiB", 5, "/opt/ring/bin/overflow_ring  .data .bss"],
          ["abf89a76d000", "abf89a78e000", "rw-p", "132 KiB", 2, "[heap]", "abf89a76d290"],
          ["ffff8f5d0000", "ffff8f758000", "r-xp", "1.5 MiB", 1, "/usr/lib/aarch64-linux-gnu/libc.so.6"],
          ["ffff8f780000", "ffff8f7ab000", "r-xp", "172 KiB", 1, "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"],
          ["fffff2a10000", "fffff2a31000", "rw-p", "132 KiB", 3, "[stack]"]
        ], more: 11 },
      locks: { line: ["관측된 뮤텍스 0개 (단일 스레드)", "0 mutexes seen (single thread)"], list: [] },
      files: { line: ["3개 · 0.8초 동안 3 → 3 → 3", "3 · 3 → 3 → 3 over 0.8 s"], list: [["0", "tty", "/dev/pts/2"], ["1", "pipe", "pipe:[9811762]"], ["2", "tty", "/dev/pts/2"]] },
      modules: { line: ["4개 · 디버그 정보: 실행 파일만 (DWARF)", "4 · debug info: executable only (DWARF)"],
        list: [["overflow_ring", "aaaab8c40000", ["DWARF 있음", "DWARF"]], ["libc.so.6", "ffff8f5d0000", ["심볼만 (.dynsym)", "symbols only (.dynsym)"]],
          ["ld-linux-aarch64.so.1", "ffff8f780000", ["심볼만", "symbols only"]], ["linux-vdso.so.1", "ffff8f7c0000", ["심볼만", "symbols only"]]] },
      vars: { line: ["전역·정적 2개 (DWARF) · 검색해서 값 보기", "2 globals/statics (DWARF) · search to read a value"], query: "rb",
        list: [
          { name: "rb", type: "struct ring", size: "32 B", sect: ".bss", decl: "overflow_ring.c:12", addr: "aaaab8c51010", kind: "struct",
            fields: [["buf", "unsigned char *", "0xabf89a76d2a0", "rb.buf"], ["cap", "size_t", "64"], ["head", "size_t", "32"], ["tail", "size_t", "0"]] },
          { name: "rb.buf", type: "unsigned char *", size: "8 B", sect: ["(rb 의 필드)", "(field of rb)"], decl: "overflow_ring.c:8", addr: "aaaab8c51010", kind: "ptr", value: "0xabf89a76d2a0",
            pointee: "abf89a76d2a0", block: ["힙 블록, 사용 가능 72 B", "heap block, 72 usable bytes"], hidden: true },
          { name: "aux", type: "unsigned char *", size: "8 B", sect: ".bss", decl: "overflow_ring.c:13", addr: "aaaab8c51030", kind: "ptr", value: "0xabf89a76d2f0",
            pointee: "abf89a76d2f0", block: ["힙 블록, 청크 헤더 손상", "heap block, chunk header damaged"] }
        ] },
      range: { base: OVF_BASE, len: 160, bytes: (function () {
        var b = [], i;
        b.push(0, 0, 0, 0, 0, 0, 0, 0); b.push(0x51, 0, 0, 0, 0, 0, 0, 0);       // rb.buf chunk: prev_size, size 0x51
        for (i = 0; i < 96; i++) b.push(0x6d);                                    // 72 usable + 24 past the end
        for (i = 0; i < 48; i++) b.push(0);                                        // the rest of aux (memset 0)
        return b; })(),
        marks: [[0, 16, "b-hdr", ["rb.buf 청크 헤더", "rb.buf chunk header"]], [16, 88, "b-buf", ["rb.buf (72 B)", "rb.buf (72 B)"]],
          [88, 112, "b-over", ["넘친 24 B: aux 크기 필드 + aux 앞 16 B", "24 bytes over: aux size field + first 16 bytes of aux"]], [112, 160, "", ["aux 나머지", "rest of aux"]]],
        decode: [
          ["0xabf89a76d290", "malloc_chunk (rb.buf)", ["size = 0x51 → 80 B, PREV_INUSE", "size = 0x51 → 80 B, PREV_INUSE"], ""],
          ["0xabf89a76d2a0", "unsigned char[72]  rb.buf", ["\"mmmm…m\" (72 B 모두 0x6d)", "\"mmmm…m\" (all 72 bytes 0x6d)"], ""],
          ["0xabf89a76d2e0", "malloc_chunk (aux)", ["size = 0x6d6d6d6d6d6d6d6d → 잘못된 크기 (힙 범위 132 KiB 초과)", "size = 0x6d6d6d6d6d6d6d6d → invalid (exceeds the 132 KiB heap)"], "bad"],
          ["0xabf89a76d2f0", "unsigned char[64]  *aux", ["앞 16 B = 0x6d, 나머지 48 B = 0", "first 16 bytes 0x6d, remaining 48 = 0"], "bad"]
        ] }
    },
    series: {
      "rb.buf": function () { return "0xabf89a76d2a0"; }, "rb.cap": function () { return 64; }, "rb.head": function () { return 32; }, "rb.tail": function () { return 0; },
      "*rb.buf@72": function () { return "6d6d6d6d…6d (72 B)"; }, "aux": function () { return "0xabf89a76d2f0"; },
      "chunk(aux).size": function () { return "0x6d6d6d6d6d6d6d6d"; }
    },
    stages: [
      { key: "result", label: ["결과", "Result"], cap: ["발견 카드의 관련 정보: 발견이 이름을 댄 변수 rb.buf, aux와 손상 주소에서 만든 칩.", "Related chips from the variables (rb.buf, aux) and the address the finding names."] },
      { key: "range", label: ["칩 → 메모리", "Chip → memory"], cap: ["[버퍼 주변 메모리] 칩: 프로필 '메모리' 아래에 범위 보기(160 B, 한 번 읽기)가 열린다. 버퍼·넘친 부분·다음 청크가 색으로 구분되고, 형식을 아는 곳은 해석이 붙는다.", "The memory chip opens a 160-byte range view under Memory: buffer, overflow and next chunk coloured; typed decode where the type is known."],
        open: ["pf:memory", "range"], from: "finding-1", focus: "range" },
      { key: "value", label: ["값 보기", "Value"], cap: ["[rb 값] 칩: struct ring 해석. buf는 포인터라 '따라가기'로 같은 범위 보기를 연다.", "The rb chip: struct ring decoded; buf is a pointer with Follow."],
        open: ["pf:vars", "var:rb"], from: "finding-1", focus: "var:rb" },
      { key: "watch", label: ["추적", "Watch"], cap: ["[rb.buf 추적] 칩: 관찰 카드에 rb와 aux 청크 크기가 들어간다. 대상이 pause()에 있어 값은 그대로다.", "Watch rb.buf: rb and aux's chunk size are tracked. The target sits in pause(), so nothing changes."],
        open: [], track: ["rb", "chunk(aux).size"], ticks: 18, openTrack: ["rb"], focus: "observe" },
      { key: "report", label: ["보고서", "Report"], cap: ["'보고서에 추가' 후 보고서 보기: 끝에 '추가 관찰' 절.", "Report view after Add to report: an Additional observation section."],
        open: [], track: ["rb", "chunk(aux).size"], ticks: 18, inReport: true, view: "report", focus: "obs-report" }
    ]
  };

  /* ------------------------------------------------------------------ threads300: request_threads */
  var REQ = [];
  (function () { var r = rng(7); for (var i = 0; i < 300; i++) REQ.push({ tid: 3735614 + i + Math.floor(i / 37), st: r() < 0.03 ? "S S R S S" : "S S S S S" }); })();
  CASES.threads300 = {
    label: ["스레드 300", "300 threads"],
    target: { name: "request_threads", pid: 3735613, arch: "aarch64", libc: "glibc", exe: "/opt/req/bin/request_threads",
      buildid: "5e0a8c13f9d27b46e8a1c05d93f7b2e6a410", debug: ["/proc/3735613/exe", "/proc/3735613/exe"], transport: ["로컬", "local"], threads: 301 },
    verdict: { code: "INCONCLUSIVE", tone: "warn", word: ["판단 불가", "Could not judge"],
      mean: ["확보한 증거로는 결론을 내리지 못했습니다.", "The evidence does not support a conclusion."],
      sum: ["<code>request_threads</code> (pid 3735613)에 대해 결론을 내리지 못했습니다. 시간 예산 20초를 다 써서 메모리 증가 검사 2개와 해제 후 사용 검사가 끝나지 못했습니다. 스레드 301개를 읽는 데 시간이 대부분 들었습니다.",
            "No conclusion for <code>request_threads</code> (pid 3735613). The 20 s budget ran out before two memory-growth checks and the use-after-free check finished; reading 301 threads took most of it."],
      dur: ["30.9초", "30.9 s"], bytes: "2.4 MB", stop: "0 ms" },
    tiles: { ran: 11, fail: 0, inc: 3, pass: 8, skip: 26 },
    findings: [],
    checks: [
      ["THREAD_STATE", "PASS", ["모든 스레드가 정상 상태 (301개)", "all 301 threads normal"], 2210], ["HEAP_GROWTH", "INCONCLUSIVE", ["시간 예산 소진 (20 s)", "budget exhausted (20 s)"], 0],
      ["BLOCKED", "PASS", ["락을 기다리는 스레드 없음 (301개, 표본 5회)", "no thread waits on a lock (301 threads)"], 6120], ["HEAP_META", "PASS", ["힙 메타데이터에 이상 없음: 청크 303개", "heap metadata intact: 303 chunks"], 41],
      ["DEADLOCK", "PASS", ["고리 없음", "no cycle"], 512], ["MEM_GROWTH", "INCONCLUSIVE", ["시간 예산 소진 (20 s)", "budget exhausted (20 s)"], 0],
      ["LOCK_OWN", "PASS", ["락 소유 관계에 이상 없음", "lock ownership consistent"], 498], ["UAF", "INCONCLUSIVE", ["시간 예산 소진 (20 s)", "budget exhausted (20 s)"], 0],
      ["DFREE", "PASS", ["두 번 올라 있는 블록 없음", "no block listed twice"], 30], ["FD", "PASS", ["열린 fd 3 -> 3 -> 3", "open fds 3 -> 3 -> 3"], 806],
      ["CONTENTION", "PASS", ["경합한 뮤텍스 없음", "no contended mutex"], 702]
    ],
    notseen: [[CK.MEM_GROWTH, ["시간 예산 20초 소진", "20 s budget exhausted"]], [CK.HEAP_GROWTH, ["시간 예산 20초 소진", "20 s budget exhausted"]], [CK.UAF, ["시간 예산 20초 소진", "20 s budget exhausted"]]],
    next: ["스레드 수가 관측 중에도 289 → 301로 늘었습니다. 고급 옵션에서 시간 예산을 60초로 늘려 다시 진단하면 남은 검사 3개가 끝납니다.",
      "The thread count grew 289 → 301 while observed. Run again with a 60 s budget (Advanced) so the three remaining checks finish."],
    profile: {
      window: ["관측 구간 6.1초, 표본 5회 (스레드 301개 × 5)", "window 6.1 s, 5 samples (301 threads × 5)"],
      sum: { threads: "301", rss: "4.9 MB", heap: "132 KiB", fds: "3" },
      groups: [
        { name: "req_handler", n: 300, top: ["clock_nanosleep", "request_threads.c:12"], st: ["대기 300 (실행 표본 9개)", "300 waiting (9 running samples)"],
          frames: [["clock_nanosleep", "libc.so.6", ""], ["__sleep", "libc.so.6", ""], ["handle_request", "", "request_threads.c:12"], ["start_thread", "libc.so.6", ""], ["thread_start", "libc.so.6", ""]],
          locals: { 2: [["arg", "void *", "0x0"]] }, members: REQ },
        { name: "request_threads", n: 1, top: ["pause", "request_threads.c:39"], st: ["대기 1", "1 waiting"],
          frames: [["pause", "libc.so.6", ""], ["main", "", "request_threads.c:39"], ["__libc_start_call_main", "libc.so.6", ""], ["_start", "request_threads", ""]],
          locals: { 1: [["n", "int", "300"]] }, members: [{ tid: 3735613, st: "S S S S S" }] }
      ],
      threadsLine: ["301개 · 이름 2종류 · 위치 2곳 · 관측 중 289 → 301", "301 · 2 names · 2 places · grew 289 → 301 while observed"],
      memory: { line: ["RSS 4.9 MB · 가상 2.4 GiB (스레드 스택 300 × 8 MiB) · 매핑 619개", "RSS 4.9 MB · virtual 2.4 GiB (300 stacks × 8 MiB) · 619 mappings"],
        cats: [[["스레드 스택", "Thread stacks"], 3600, 3], [["공유 라이브러리", "Shared libraries"], 1240, 1], [["기타 익명", "Other anonymous"], 140, 4], [["힙", "Heap"], 12, 2], [["실행 파일", "Executable"], 8, 5]],
        maps: [
          ["aaaac2a00000", "aaaac2a01000", "r-xp", "4 KiB", 5, "/opt/req/bin/request_threads"],
          ["aaaaf1c3e000", "aaaaf1c5f000", "rw-p", "132 KiB", 2, "[heap]"],
          ["fffef0000000", "fffef0800000", "rw-p", "8 MiB", 3, ["[req_handler 3735614 스택]", "[req_handler 3735614 stack]"]],
          ["fffef0810000", "fffef1010000", "rw-p", "8 MiB", 3, ["[req_handler 3735615 스택]", "[req_handler 3735615 stack]"]],
          ["ffff8a420000", "ffff8a5a8000", "r-xp", "1.5 MiB", 1, "/usr/lib/aarch64-linux-gnu/libc.so.6"]
        ], more: 614 },
      locks: { line: ["기다린 락 없음 (301개 × 표본 5회)", "no lock waited on (301 × 5 samples)"], list: [] },
      files: { line: ["3개 · 0.8초 동안 3 → 3 → 3", "3 · 3 → 3 → 3 over 0.8 s"], list: [["0", "tty", "/dev/pts/4"], ["1", "pipe", "pipe:[9850127]"], ["2", "tty", "/dev/pts/4"]] },
      modules: { line: ["4개 · 디버그 정보: 실행 파일만 (DWARF)", "4 · debug info: executable only (DWARF)"],
        list: [["request_threads", "aaaac2a00000", ["DWARF 있음", "DWARF"]], ["libc.so.6", "ffff8a420000", ["심볼만 (.dynsym)", "symbols only (.dynsym)"]],
          ["ld-linux-aarch64.so.1", "ffff8a5d0000", ["심볼만", "symbols only"]], ["linux-vdso.so.1", "ffff8a610000", ["심볼만", "symbols only"]]] },
      vars: { line: ["전역·정적 0개 (DWARF) · 이 실행 파일에는 전역 변수가 없음", "0 globals/statics (DWARF) · this executable has none"], query: "", list: [] }
    },
    series: {},
    stages: [
      { key: "result", label: ["결과", "Result"], cap: ["판단 불가 결과. 프로필의 스레드 줄이 301개를 이름과 위치로 묶어 한 줄로 요약한다.", "Could not judge. The Threads row sums up 301 threads by name and place."] },
      { key: "groups", label: ["묶음", "Groups"], cap: ["스레드 줄을 펼치면 (이름, 맨 위 위치)로 묶인 2줄: req_handler × 300, request_threads × 1. 같은 묶음은 스택이 같으므로 스택을 한 번만 보여준다.", "Opened: two groups by (name, top frame). One stack per group, since members share it."],
        open: ["pf:threads", "grp:req_handler"], frame: { "grp:req_handler": 2 } },
      { key: "members", label: ["구성원", "Members"], cap: ["묶음의 구성원은 20개씩: '280개 더' 를 누르면 50개씩 더 나온다. tid로 거르기도 된다.", "Members 20 at a time; '280 more' adds 50 each; filter by tid."],
        open: ["pf:threads", "grp:req_handler", "mem:req_handler"], frame: { "grp:req_handler": 2 }, focus: "mem:req_handler" },
      { key: "one", label: ["한 스레드", "One thread"], cap: ["구성원 하나(tid 3735674)를 누르면 그 스레드만 다시 읽어 스택을 연다.", "One member (tid 3735674) re-read on demand."],
        open: ["pf:threads", "grp:req_handler", "mem:req_handler", "th:3735674"], frame: { 3735674: 2 }, focus: "th:3735674" }
    ]
  };

  /* ------------------------------------------------------------------ pool: slot_server (illustrative target) */
  var POOL_N = 4096, POOL_FRAMES = 64, POOL_STATES = [
    { v: 0, name: "SLOT_FREE", cls: 0 }, { v: 1, name: "SLOT_ACCEPTING", cls: 1 }, { v: 2, name: "SLOT_READING", cls: 3 },
    { v: 3, name: "SLOT_WRITING", cls: 2 }, { v: 4, name: "SLOT_CLOSING", cls: 5 }];
  // Every slot runs the cycle FREE x5, ACCEPTING, READING x2, WRITING, CLOSING; phases are a permutation, so the
  // counts per state stay level and only one thing moves: three slots per sample stop in SLOT_CLOSING for good.
  var CYCLE = [0, 0, 0, 0, 0, 1, 2, 2, 3, 4];
  function poolFrames() {
    var r = rng(4096), fr = [], ph = new Uint8Array(POOL_N), stuckAt = new Int32Array(POOL_N).fill(-1), i, k, perm = [];
    for (i = 0; i < POOL_N; i++) perm.push(i);
    for (i = POOL_N - 1; i > 0; i--) { k = Math.floor(r() * (i + 1)); var x = perm[i]; perm[i] = perm[k]; perm[k] = x; }
    for (i = 0; i < POOL_N; i++) ph[perm[i]] = i % CYCLE.length;
    for (i = 0; i < 40; i++) stuckAt[Math.floor(r() * POOL_N)] = 0;          // already stuck when watching starts
    for (var t = 0; t < POOL_FRAMES; t++) {
      for (k = 0; k < 3; k++) { var j; do { j = Math.floor(r() * POOL_N); } while (stuckAt[j] >= 0 || CYCLE[(t + ph[j]) % CYCLE.length] !== 4); stuckAt[j] = t; }
      if (t === 9) stuckAt[1337] = 9;
      var f = new Uint8Array(POOL_N);
      for (i = 0; i < POOL_N; i++) f[i] = stuckAt[i] >= 0 && stuckAt[i] <= t ? 4 : CYCLE[(t + ph[i]) % CYCLE.length];
      fr.push(f);
    }
    return fr;
  }
  CASES.pool = {
    label: ["풀", "Pool"],
    illustrative: ["설명용 대상: 벤치마크에 연결 슬롯 풀을 가진 대상이 없어 만든 예 (slot_server).", "Illustrative target: no benchmark target has a connection-slot pool (slot_server)."],
    target: { name: "slot_server", pid: 52740, arch: "x86_64", libc: "glibc", exe: "/opt/slot/bin/slot_server",
      buildid: "c81f0a2e7d5b39461ae0f8c2d4b7a95e3016", debug: ["DWARF 있음 (대상 실행 파일)", "DWARF (target executable)"], transport: ["로컬", "local"], threads: 5 },
    verdict: { code: "HEALTHY", tone: "pass", word: ["점검한 범위 안에서 정상", "Healthy within the checked scope"],
      mean: ["점검한 범위 밖에 대해서는 판단하지 않습니다.", "Nothing is said about what was not checked."],
      sum: ["<code>slot_server</code> (pid 52740)은(는) 점검한 범위 안에서 정상입니다. 기본 검사 14개가 끝까지 실행되었고 아무것도 발견하지 못했습니다. 프로그램 고유의 상태(연결 슬롯이 어떤 상태에 머무는지)는 기본 검사가 보지 않습니다.",
            "<code>slot_server</code> (pid 52740) is healthy within the checked scope. Program-specific state (which state connection slots stay in) is not what the baseline checks look at."],
      dur: ["4.1초", "4.1 s"], bytes: "402 KB", stop: "0 ms" },
    tiles: { ran: 17, fail: 0, inc: 1, pass: 16, skip: 13 },
    findings: [],
    checks: [
      ["MEM_GROWTH", "PASS", ["증가 추세 없음 (RSS +4 KB, 1.0초 동안 표본 6개)", "no growth trend (RSS +4 KB over 1.0 s)"], 1003], ["HEAP_GROWTH", "PASS", ["힙 크기가 안정적임", "heap stable"], 3],
      ["HEAP_META", "PASS", ["힙 메타데이터에 이상 없음: 청크 1,212개", "heap metadata intact: 1,212 chunks"], 61], ["DFREE", "PASS", ["두 번 올라 있는 블록 없음", "no block listed twice"], 22],
      ["FD", "PASS", ["열린 fd 1,861 -> 1,858 -> 1,866, 0.8초 동안 (+5), 한도 65536", "open fds 1,861 -> 1,858 -> 1,866 over 0.8 s, limit 65536"], 811],
      ["THREAD_STATE", "PASS", ["모든 스레드가 정상 상태", "all threads normal"], 8], ["BLOCKED", "PASS", ["락을 기다리는 스레드 없음", "no thread waits on a lock"], 9],
      ["DEADLOCK", "PASS", ["고리 없음", "no cycle"], 7], ["LOCK_OWN", "PASS", ["락 소유 관계에 이상 없음", "lock ownership consistent"], 7],
      ["CONTENTION", "PASS", ["5회 중 1회만 g_slot_mu 대기자 1명", "g_slot_mu had one waiter in 1 of 5 samples"], 4], ["ORPHAN", "PASS", ["뮤텍스 1개, 소유자 살아 있음", "1 mutex, live owner"], 140],
      ["SELF_DL", "PASS", ["자기 교착 없음", "no self-wait"], 3], ["MAP_GROWTH", "PASS", ["malloc 밖에서 증가 없음", "no growth outside malloc"], 901],
      ["THREAD_LEAK", "PASS", ["스레드 수 5 -> 5 -> 5", "threads 5 -> 5 -> 5"], 4], ["FREED_USE", "PASS", ["해제된 청크를 가리키는 포인터 없음", "no pointer to a freed chunk"], 6],
      ["ALLOC_IMB", "INCONCLUSIVE", NOREASON, 3], ["INV_ACCESS", "PASS", ["잘못된 접근 흔적 없음", "no invalid access"], 31]
    ],
    notseen: [[CK.ALLOC_IMB, NOREASON], [["프로그램 고유 상태", "program-specific state"], ["기본 검사가 보지 않음: 아래 '관찰'로 직접 볼 수 있음", "not what the baseline looks at: see Watch"]]],
    next: ["이 검사 결과로는 고칠 것이 없습니다. 슬롯이 특정 상태에 머무는지 보려면 변수 g_slots를 풀로 관찰하세요.",
      "Nothing to fix from these checks. To see whether slots stay in one state, watch g_slots as a pool."],
    profile: {
      window: ["관측 구간 4.1초, 표본 42회", "window 4.1 s, 42 samples"],
      sum: { threads: "5", rss: "9.8 MB", heap: "2.1 MiB", fds: "1,866" },
      threads: [
        { tid: 52740, name: "slot_server", st: "S S S S S", cpu: "0%", top: ["epoll_wait", "slot_server.c:212"], frames: [["epoll_wait", "libc.so.6", ""], ["accept_loop", "", "slot_server.c:212"], ["main", "", "slot_server.c:260"]], locals: { 1: [["ep", "int", "4"], ["nev", "int", "0"]] }, holds: [], waits: null },
        { tid: 52741, name: "slot_io0", st: "R S R S S", cpu: "21%", top: ["recv", "slot_server.c:148"], frames: [["recv", "libc.so.6", ""], ["slot_read", "", "slot_server.c:148"], ["io_loop", "", "slot_server.c:181"], ["start_thread", "libc.so.6", ""]], locals: { 1: [["s", "struct slot *", "0x5581c3a61e40 (g_slots[1337])"], ["n", "ssize_t", "512"]] }, holds: [], waits: null },
        { tid: 52742, name: "slot_io1", st: "S R S R S", cpu: "19%", top: ["send", "slot_server.c:163"], frames: [["send", "libc.so.6", ""], ["slot_write", "", "slot_server.c:163"], ["io_loop", "", "slot_server.c:183"], ["start_thread", "libc.so.6", ""]], locals: { 1: [["s", "struct slot *", "0x5581c3a5a2c0"]] }, holds: [], waits: null },
        { tid: 52743, name: "slot_io2", st: "S S R S R", cpu: "18%", top: ["epoll_wait", "slot_server.c:176"], frames: [["epoll_wait", "libc.so.6", ""], ["io_loop", "", "slot_server.c:176"], ["start_thread", "libc.so.6", ""]], locals: { 1: [["ep", "int", "6"]] }, holds: [], waits: null },
        { tid: 52744, name: "slot_io3", st: "R S S S R", cpu: "20%", top: ["epoll_wait", "slot_server.c:176"], frames: [["epoll_wait", "libc.so.6", ""], ["io_loop", "", "slot_server.c:176"], ["start_thread", "libc.so.6", ""]], locals: { 1: [["ep", "int", "7"]] }, holds: [], waits: null }
      ],
      threadsLine: ["5개 · 실행 4 · 대기 1", "5 · 4 running · 1 waiting"],
      memory: { line: ["RSS 9.8 MB, 1.0초 동안 +4 KB · 매핑 31개 · 힙 청크 1,212개", "RSS 9.8 MB, +4 KB over 1.0 s · 31 mappings · 1,212 heap chunks"],
        cats: [[["힙", "Heap"], 2150, 2], [["공유 라이브러리", "Shared libraries"], 1920, 1], [["실행 파일 (.bss: g_slots 192 KiB)", "Executable (.bss: g_slots 192 KiB)"], 212, 5], [["스레드 스택", "Thread stacks"], 96, 3], [["기타 익명", "Other anonymous"], 5650, 4]],
        maps: [["5581c3a20000", "5581c3a2a000", "r-xp", "40 KiB", 5, "/opt/slot/bin/slot_server"], ["5581c3a3a000", "5581c3a6e000", "rw-p", "208 KiB", 5, "/opt/slot/bin/slot_server  .data .bss"],
          ["5581c4e10000", "5581c5032000", "rw-p", "2.1 MiB", 2, "[heap]"], ["7f3a1c000000", "7f3a1c5a6000", "rw-p", "5.6 MiB", 4, ["[익명: 수신 버퍼]", "[anon: rx buffers]"]],
          ["7f3a1e400000", "7f3a1e5d8000", "r-xp", "1.8 MiB", 1, "/usr/lib/x86_64-linux-gnu/libc.so.6"]], more: 26 },
      locks: { line: ["뮤텍스 1개 g_slot_mu · 대기 표본 1/5", "1 mutex g_slot_mu · waited in 1/5 samples"],
        list: [{ name: "g_slot_mu", type: "pthread_mutex_t", addr: "5581c3a3a040", owner: 0, waiters: [], decl: "slot_server.c:41", lockw: "0" }] },
      files: { line: ["1,866개 · 소켓 1,861 · 0.8초 동안 +5 · 한도 65536", "1,866 · 1,861 sockets · +5 over 0.8 s · limit 65536"],
        list: [["0", "tty", "/dev/null"], ["3", "socket", "TCP *:7001 (LISTEN)"], ["4", "anon", "[eventpoll]"], ["5..1865", "socket", ["TCP 연결 1,861개", "1,861 TCP connections"]]] },
      modules: { line: ["5개 · 디버그 정보: 실행 파일만 (DWARF)", "5 · debug info: executable only (DWARF)"],
        list: [["slot_server", "5581c3a20000", ["DWARF 있음", "DWARF"]], ["libc.so.6", "7f3a1e400000", ["심볼만 (.dynsym)", "symbols only (.dynsym)"]]] },
      vars: { line: ["전역·정적 6개 (DWARF) · 검색해서 값 보기", "6 globals/statics (DWARF) · search to read a value"], query: "slot",
        list: [
          { name: "g_slots", type: "struct slot[4096]", size: "196,608 B", sect: ".bss", decl: "slot_server.c:38", addr: "5581c3a42040", kind: "pool",
            elemType: "struct slot (48 B)", enumField: "state", fieldsOf: ["state", "fd", "peer", "rx", "tx", "last_ms"] },
          { name: "g_slot_mu", type: "pthread_mutex_t", size: "40 B", sect: ".bss", decl: "slot_server.c:41", addr: "5581c3a3a040", kind: "opaque", value: "{__lock = 0, __owner = 0, __nusers = 0, …}" },
          { name: "g_slots_used", type: "int", size: "4 B", sect: ".bss", decl: "slot_server.c:39", addr: "5581c3a3a030", kind: "num" }
        ] }
    },
    pool: { n: POOL_N, frames: null, build: poolFrames, states: POOL_STATES, expr: "g_slots", field: "state", elem: 48, base: 0x5581c3a42040 },
    series: { "g_slots_used": function (t) { return 1840 + Math.round(25 * Math.sin(t / 3)) + t; } },
    stages: [
      { key: "result", label: ["결과", "Result"], cap: ["정상 결과. 다음에 할 일이 '변수 g_slots를 풀로 관찰'을 권한다.", "Healthy. Next steps suggest watching g_slots as a pool."] },
      { key: "vars", label: ["변수 검색", "Search"], cap: ["변수 줄에서 'slot' 검색 → g_slots는 struct slot[4096]이고 열거형 필드 state가 있어 '풀로 보기'가 붙는다.", "Search 'slot': g_slots is struct slot[4096] with an enum field, so it gets View as pool."],
        open: ["pf:vars"], },
      { key: "pool", label: ["풀 보기", "Pool"], cap: ["풀 보기: 식·개수·상태 필드가 형식에서 미리 채워짐. 4,096칸, 상태별 색과 개수. 1초마다 갱신되고 바뀐 칸은 테두리로 표시.", "Pool view: inputs prefilled from the type. 4,096 cells by status with counts; refreshes each second, changed cells outlined."],
        open: [], pool: true, ticks: 12, focus: "observe" },
      { key: "cell", label: ["칸 선택", "Cell"], cap: ["범례에서 SLOT_CLOSING만 보이게 하고 칸 #1337을 고르면 그 원소의 필드가 격자 옆에 나온다. CLOSING 칸이 표본마다 늘어난다.", "Show only SLOT_CLOSING and pick cell #1337: its fields appear beside the grid. CLOSING keeps growing."],
        open: [], pool: true, ticks: 24, poolSel: 1337, poolOnly: 5, focus: "observe" },
      { key: "compare", label: ["비교", "Compare"], cap: ["'지금 값 고정' 뒤 바뀐 것만: 상태별 개수와 추적 중인 원소.", "Freeze now, then only what changed: counts per status and the tracked element."],
        open: [], pool: true, ticks: 36, poolSel: 1337, freezeAt: 24, track: ["g_slots[1337]", "g_slots_used"], openTrack: ["g_slots[1337]"], focus: "observe" }
    ]
  };

  /* ------------------------------------------------------------------ nodebug: svc_main on board-7 (illustrative, remote, stripped) */
  CASES.nodebug = {
    label: ["디버그 정보 없음", "No debug info"],
    illustrative: ["설명용 대상: 디버그 정보 없이 SSH로 연결한 원격 보드의 서비스 (svc_main).", "Illustrative target: a stripped service on a remote board over SSH (svc_main)."],
    target: { name: "svc_main", pid: 812, arch: "x86_64", libc: "glibc", exe: "/usr/sbin/svc_main", host: "board-7 · 192.168.1.50",
      buildid: "e44b07c19d2a6f83b5c0e7a1d93f2b64c805", debug: ["없음 (stripped, 디버그 ELF 미지정)", "none (stripped, no debug ELF given)"], transport: ["SSH · board-7 192.168.1.50", "SSH · board-7 192.168.1.50"], threads: 6 },
    verdict: { code: "INCONCLUSIVE", tone: "warn", word: ["판단 불가", "Could not judge"],
      mean: ["확보한 증거로는 결론을 내리지 못했습니다.", "The evidence does not support a conclusion."],
      sum: ["<code>svc_main</code> (pid 812, board-7)에 대해 결론을 내리지 못했습니다. 디버그 이미지가 없어 변수 형식이 필요한 검사 8개가 판단하지 못했습니다. 스레드·메모리·파일 수준의 검사 9개는 통과했습니다.",
            "No conclusion for <code>svc_main</code> (pid 812, board-7): without a debug image, 8 checks that need variable types could not judge. 9 thread/memory/file-level checks passed."],
      dur: ["9.7초", "9.7 s"], bytes: "214 KB", stop: "0 ms" },
    tiles: { ran: 17, fail: 0, inc: 8, pass: 9, skip: 13 },
    findings: [],
    checks: [
      ["MEM_GROWTH", "PASS", ["증가 추세 없음 (RSS +0 KB, 1.2초 동안 표본 6개)", "no growth trend"], 1204], ["FD", "PASS", ["열린 fd 14 -> 14 -> 14", "open fds 14 -> 14 -> 14"], 830],
      ["THREAD_STATE", "PASS", ["모든 스레드가 정상 상태", "all threads normal"], 31], ["BLOCKED", "PASS", ["락을 기다리는 스레드 없음 (심볼로 판단)", "no thread waits on a lock (by symbol)"], 44],
      ["THREAD_LEAK", "PASS", ["스레드 수 6 -> 6 -> 6", "threads 6 -> 6 -> 6"], 9], ["MAP_GROWTH", "PASS", ["malloc 밖에서 증가 없음", "no growth outside malloc"], 911],
      ["HEAP_META", "PASS", ["힙 메타데이터에 이상 없음: 청크 88개 (glibc 배치로 판단)", "heap metadata intact: 88 chunks (by glibc layout)"], 77], ["DFREE", "PASS", ["두 번 올라 있는 블록 없음", "no block listed twice"], 18],
      ["DEADLOCK", "PASS", ["고리 없음 (스레드 상태로 판단)", "no cycle (from thread states)"], 12],
      ["LOCK_OWN", "INCONCLUSIVE", ["디버그 정보 없음: 뮤텍스 위치를 알 수 없음", "no debug info: mutex locations unknown"], 3], ["ORPHAN", "INCONCLUSIVE", ["디버그 정보 없음", "no debug info"], 2],
      ["SELF_DL", "INCONCLUSIVE", ["디버그 정보 없음", "no debug info"], 2], ["CONTENTION", "INCONCLUSIVE", ["디버그 정보 없음", "no debug info"], 2],
      ["FREED_USE", "INCONCLUSIVE", ["디버그 정보 없음: 타입 있는 포인터를 찾을 수 없음", "no debug info: no typed pointers"], 2], ["VAR_CHG", "INCONCLUSIVE", ["디버그 정보 없음", "no debug info"], 1],
      ["SHARED", "INCONCLUSIVE", ["디버그 정보 없음", "no debug info"], 1], ["NULL_PTR", "INCONCLUSIVE", ["디버그 정보 없음", "no debug info"], 1]
    ],
    notseen: [[["변수 형식이 필요한 검사 8개", "8 checks that need variable types"], ["디버그 이미지 없음 (stripped)", "no debug image (stripped)"]]],
    next: ["빌드 산출물의 디버그 ELF(같은 Build ID <code>e44b07c1…c805</code>)를 '디버그 ELF 경로'에 지정해 다시 진단하세요. 대상에는 아무것도 설치하지 않습니다.",
      "Run again with the build's debug ELF (same Build ID <code>e44b07c1…c805</code>) as Debug ELF path. Nothing is installed on the target."],
    profile: {
      window: ["관측 구간 1.2초, 표본 30회 (SSH)", "window 1.2 s, 30 samples (SSH)"],
      sum: { threads: "6", rss: "6.2 MB", heap: "1.1 MiB", fds: "14" },
      nodebug: true,
      threads: [
        { tid: 812, name: "svc_main", st: "S S S S S", cpu: "0%", top: ["epoll_wait", "svc_main+0x2a3c"], frames: [["epoll_wait", "libc.so.6", ""], ["svc_main+0x2a3c", "svc_main", ""], ["svc_main+0x19f0", "svc_main", ""], ["__libc_start_main", "libc.so.6", ""]], holds: [], waits: null },
        { tid: 815, name: "svc_rx", st: "S R S S S", cpu: "6%", top: ["recvmsg", "svc_main+0x4c10"], frames: [["recvmsg", "libc.so.6", ""], ["svc_main+0x4c10", "svc_main", ""], ["start_thread", "libc.so.6", ""], ["clone3", "libc.so.6", ""]], holds: [], waits: null },
        { tid: 816, name: "svc_tx", st: "S S S R S", cpu: "4%", top: ["sendmsg", "svc_main+0x5288"], frames: [["sendmsg", "libc.so.6", ""], ["svc_main+0x5288", "svc_main", ""], ["start_thread", "libc.so.6", ""], ["clone3", "libc.so.6", ""]], holds: [], waits: null },
        { tid: 817, name: "svc_timer", st: "S S S S S", cpu: "0%", top: ["clock_nanosleep", "svc_main+0x6104"], frames: [["clock_nanosleep", "libc.so.6", ""], ["svc_main+0x6104", "svc_main", ""], ["start_thread", "libc.so.6", ""]], holds: [], waits: null },
        { tid: 818, name: "svc_log", st: "S S S S S", cpu: "0%", top: ["write", "svc_main+0x7a2c"], frames: [["write", "libc.so.6", ""], ["svc_main+0x7a2c", "svc_main", ""], ["start_thread", "libc.so.6", ""]], holds: [], waits: null },
        { tid: 819, name: "svc_log", st: "S S S S S", cpu: "0%", top: ["futex_wait", "svc_main+0x7b80"], frames: [["futex_wait", "libc.so.6", ""], ["svc_main+0x7b80", "svc_main", ""], ["start_thread", "libc.so.6", ""]], holds: [], waits: null }
      ],
      threadsLine: ["6개 · 실행 2 · 대기 4 · 함수 이름은 libc만", "6 · 2 running · 4 waiting · function names for libc only"],
      memory: { line: ["RSS 6.2 MB, 1.2초 동안 +0 KB · 매핑 27개 · 힙 청크 88개", "RSS 6.2 MB, +0 KB over 1.2 s · 27 mappings · 88 heap chunks"],
        cats: [[["공유 라이브러리", "Shared libraries"], 2480, 1], [["기타 익명", "Other anonymous"], 2380, 4], [["힙", "Heap"], 1120, 2], [["실행 파일", "Executable"], 180, 5], [["스레드 스택", "Thread stacks"], 120, 3]],
        maps: [["55d0e3a00000", "55d0e3a2c000", "r-xp", "176 KiB", 5, "/usr/sbin/svc_main"], ["55d0e3a3c000", "55d0e3a3e000", "rw-p", "8 KiB", 5, "/usr/sbin/svc_main  .data .bss", "55d0e3a3c040"],
          ["55d0e4c1a000", "55d0e4d3b000", "rw-p", "1.1 MiB", 2, "[heap]"], ["7f61b8200000", "7f61b83d8000", "r-xp", "1.8 MiB", 1, "/usr/lib/x86_64-linux-gnu/libc.so.6"]], more: 23 },
      locks: { line: ["알 수 없음: 디버그 정보가 없어 뮤텍스 위치를 모름 (futex 대기 1개는 보임)", "unknown: no debug info, mutex locations unknown (1 futex wait seen)"], list: [], unknown: true },
      files: { line: ["14개 · 1.2초 동안 14 → 14 → 14", "14 · 14 → 14 → 14 over 1.2 s"], list: [["0", "tty", "/dev/null"], ["3", "socket", "UDP *:5683"], ["4", "anon", "[eventpoll]"], ["5", "file", "/var/log/svc/svc.log"], ["6..13", "socket", ["UNIX 소켓 8개", "8 UNIX sockets"]]] },
      modules: { line: ["5개 · 디버그 정보 없음 (모든 모듈 심볼만, 실행 파일은 그것도 없음)", "5 · no debug info (symbols only; the executable has none)"],
        list: [["svc_main", "55d0e3a00000", ["없음 (stripped)", "none (stripped)"]], ["libc.so.6", "7f61b8200000", ["심볼만 (.dynsym)", "symbols only (.dynsym)"]]] },
      vars: { disabled: true, line: ["검색할 수 없음: 디버그 정보 없음", "cannot search: no debug info"], query: "", list: [] },
      range: { base: 0x55d0e3a3c040, len: 64, raw: true, bytes: (function () {
        var b = [0x2a, 0x91, 0x03, 0, 0, 0, 0, 0, 0x10, 0x27, 0, 0, 0x01, 0, 0, 0, 0x73, 0x76, 0x63, 0x2d, 0x37, 0, 0, 0, 0x40, 0xc0, 0xa3, 0xe3, 0xd0, 0x55, 0, 0];
        for (var i = 0; i < 32; i++) b.push(i < 4 ? [0xe8, 0x03, 0, 0][i] : 0); return b; })(),
        marks: [[0, 64, "", [".data (형식 모름)", ".data (type unknown)"]]],
        decode: [["0x55d0e3a3c040", "u64 (LE)", ["233770", "233770"], ""], ["0x55d0e3a3c048", "u32, u32", ["10000, 1", "10000, 1"], ""], ["0x55d0e3a3c050", "ascii", ["\"svc-7\"", "\"svc-7\""], ""], ["0x55d0e3a3c058", ["포인터처럼 보임", "looks like a pointer"], ["0x55d0e3a3c040 (.data 안)", "0x55d0e3a3c040 (inside .data)"], ""]] }
    },
    series: { "0x55d0e3a3c040 (u64)": function (t) { return t >= 14 ? 233770 + 13 * 31 : 233770 + 31 * t; } },
    exitAt: 14,
    stages: [
      { key: "result", label: ["결과", "Result"], cap: ["판단 불가 (디버그 정보 없음). 프로필은 그래도 채워지지만 '변수' 줄은 비활성이고 이유와 해결 방법을 적는다.", "Could not judge (no debug info). The profile still fills in; the Variables row is disabled with the reason and the fix."] },
      { key: "threads", label: ["스레드", "Threads"], cap: ["스레드 스택: libc 함수 이름만 있고 실행 파일 프레임은 모듈+오프셋. 지역 변수는 없다고 말한다.", "Stacks: libc names only, executable frames as module+offset; locals unavailable, said so."],
        open: ["pf:threads", "th:815"], frame: { 815: 1 } },
      { key: "vars", label: ["변수 (불가)", "Variables (n/a)"], cap: ["변수 줄을 펼치면 검색 상자는 비활성, 왜 안 되는지와 무엇을 하면 되는지.", "Variables: search disabled, why, and what to do."],
        open: ["pf:vars"] },
      { key: "range", label: ["주소 읽기", "Read address"], cap: ["형식이 없어도 주소로 읽기는 된다: .data의 64 B, 원시 해석(u64·u32·ascii·포인터 후보)만.", "Reading by address still works: 64 bytes of .data, raw decode only."],
        open: ["pf:memory", "range"], focus: "range" },
      { key: "watch", label: ["주소 추적", "Watch address"], cap: ["그 주소의 u64를 추적: SSH라 표본마다 왕복 1회, 비용 줄에 그 값이 나온다.", "Watching the u64 at that address over SSH; the cost line shows the round trip."],
        open: [], track: ["0x55d0e3a3c040 (u64)"], ticks: 10, focus: "observe" },
      { key: "exited", label: ["대상 종료", "Target exited"], cap: ["대상이 끝나면 읽기가 실패: 관찰이 멈추고 마지막 값이 남는다. 헤더 칩은 '대상 종료'. 범위 보기의 '다시 읽기'도 같은 이유로 실패를 그 자리에 말한다.", "The target exits: reads fail, watching stops with the last values kept; the header says exited. Re-reading the range fails in place."],
        open: ["pf:memory", "range"], track: ["0x55d0e3a3c040 (u64)"], ticks: 16, rangeErr: true, focus: "observe" }
    ]
  };

  function hex32(n) { return "0x" + ("00000000" + n.toString(16)).slice(-8); }

  G.EXPLORE_DATA = { CK: CK, CASES: CASES, ORDER: ["healthy", "deadlock", "overflow", "threads300", "pool", "nodebug"] };
})(typeof window !== "undefined" ? window : globalThis);
