/* dynamicState web UI.
 *
 * One column that only grows downward while a diagnosis runs and ends as the report.
 *   state = reduce(events)          pure: the list of server events received so far (any order, duplicates allowed)
 *   html  = render(state, ui)       pure: a string; the shell morphs it into the page, so nodes already on screen stay
 * Words, labels and pictures of the diagnosis come from the server (event payloads and the verdict's `view`); the
 * only words here are the UI's own (STR).  No framework, no build step, no external URL.  Event shapes:
 * docs/ui-redesign/API_CONTRACT.md.
 */
(function (root) {
  "use strict";

  /* ------------------------------------------------------------------ strings (the one table, ko / en) */
  var STR = {
    ko: {
      title: "dynamicState · 진단", brand_sub: "진단", skip: "본문으로 건너뛰기",
      new: "새 진단", new_title: "다른 프로세스 진단", theme: "밝게 / 어둡게 전환", lang_btn: "KO",
      lang_aria: "언어 전환: 지금 한국어, 누르면 English", tools: "도구",
      legacy_ui: "기존 UI (레거시)", legacy_ws: "기존 워크스페이스 (레거시)",
      hero_h: "실행 중인 프로세스를 멈추지 않고 진단합니다",
      hero_p: "PID 하나면 됩니다. 결과는 이 화면에 진행되는 대로 쌓이고, 끝나면 그대로 보고서가 됩니다.",
      mode_label: "대상 위치", local: "로컬", ssh: "SSH", target_label: "대상 프로세스",
      target_ph: "PID 또는 프로세스 이름  (예: 3351223, deadlock_pipeline)", go: "진단", starting: "시작하는 중…",
      symptom_label: "증상", symptom_ph: "증상 (선택)  예: 서비스가 응답하지 않음, 메모리가 계속 늘어남",
      elf_label: "디버그 ELF", elf_ph: "디버그 ELF 경로 (선택 · 기본 /proc/PID/exe)",
      host_ph: "호스트 (예: 192.168.1.50)", user_ph: "사용자 (선택)", port_ph: "포트 (22)",
      key_ph: "SSH 키 파일 경로 (선택)",
      opt_line: "읽기 전용 · 대상 정지 없음 · 기본 시간 예산 20초", advanced: "고급 옵션", budget_label: "시간 예산 (초)",
      need_target: "PID 또는 프로세스 이름을 입력하세요.", need_host: "SSH 호스트를 입력하세요.",
      recent_h: "최근 진단", examples_h: "예시 진단 (저장된 결과 재생)", recent_none: "아직 진단한 기록이 없습니다.",
      recent_unreachable: "서버에 연결할 수 없어 최근 진단을 불러오지 못했습니다.",
      replay_tag: "재생", running: "진단 중", aborted: "중단됨",
      phases: ["대상 확인", "증상 분류", "계획", "수집", "분석·검증", "판정"],
      checks_progress: "검사 {done}/{total}",
      cls_sym_cat: "증상 “{sym}” → <b>{cat}</b> 쪽 검사 {n}개를 먼저 봅니다.",
      cls_sym: "증상 “{sym}”에 맞춰 검사 {n}개를 계획합니다.", cls_nosym: "증상 없이 기본 검사를 실행합니다.",
      so_far_susp: "지금까지: <b>{label} 의심</b> — 검증 중…",
      so_far_ver: "지금까지: <b>{label}</b> 검증됨 — 판정을 정리하는 중…",
      so_far_clean: "검사를 마쳤습니다. 판정을 정리하는 중…",
      verdict_prefix: "판정", verdict_detail: "판정 근거 상세 기록",
      tile_checks: "검사", tile_stop: "대상 정지 시간", tile_bytes: "읽은 데이터", tile_time: "소요 시간",
      after_plan: "계획 후 표시", never_stopped: "한 번도 멈추지 않음", budget: "예산 {s}초",
      target_h: "대상", target_desc: "연결됨 · 읽기 전용",
      profile_h: "프로세스 프로필", profile_pending: "판정이 나오면 채워집니다.", profile_pending_t: "지금까지 확인한 스레드 {n}개.",
      profile_none: "이 진단에는 프로세스를 설명할 데이터가 남지 않았습니다.",
      k_proc: "프로세스", k_arch: "아키텍처", k_exe: "실행 파일", k_build: "Build ID", k_debug: "디버그 정보",
      k_transport: "전송", match: "일치", mismatch: "불일치", debug_none: "없음 (심볼만 사용)",
      transport_local: "로컬", transport_ssh: "SSH (원격 수집기)",
      findings_h: "발견된 문제", findings_none_yet: "아직 없음. 검사에서 이상이 나오면 여기에 나타납니다.",
      findings_none: "이번 진단에서 발견된 문제가 없습니다.", finding_n: "발견 {n}: {label}",
      b_suspect: "의심 · 검증 중", b_verified: "검증됨", sev: "심각도 {s}",
      f_pending: "그림과 근거는 검증이 끝나면 이 자리에 나타납니다.", f_by: "이 문제를 가리킨 검사",
      f_detail: "이 발견의 상세 기록 (보고서)",
      checks_h: "검사", checks_desc: "{done}/{total} 완료", checks_hint: "행을 누르면 그 검사의 결과만 펼쳐집니다",
      st_FAIL: "이상 발견", st_INCONCLUSIVE: "판단 불가", st_PASS: "통과", st_SKIPPED: "실행 안 함",
      st_RUNNING: "실행 중…", st_PENDING: "대기",
      not_run_n: "실행 안 함 {n}", not_run_hint: "정상이라는 근거가 아님",
      not_planned_h: "이번 증상에 선택되지 않음", not_in_mode_h: "무정지 진단으로는 답할 수 없어 점검하지 않음",
      needs: "필요한 것: {cap}", not_executed: "계획했지만 진단이 끝날 때까지 실행되지 않음",
      ck_wait_detail: "판정이 끝나면 이 검사가 확인한 것과 읽은 값을 여기에서 볼 수 있습니다.",
      ck_detail: "이 검사의 상세 기록 (보고서)", ck_id: "검사 ID", scope_detail: "검사 범위 상세 기록",
      notseen_h: "확인하지 못한 것", notseen_right: "정상이라는 근거가 아님",
      notseen_none: "없음. 실행한 검사는 모두 답을 냈습니다.",
      next_h: "다음에 할 일", next_none: "보고서에 따로 제안한 조치가 없습니다.",
      report_h: "보고서", report_desc: "이 화면과 같은 내용 + 부분별 상세 기록",
      open_html: "HTML 보고서 열기", md: "Markdown", json: "JSON (<span class=\"mono\">diagnose</span> 결과)",
      copy: "요약 복사", copied: "요약을 복사했습니다.", again: "같은 대상 다시 진단",
      impact: "수집이 대상에 준 영향: 정지 {stop} · 읽기 {bytes} · {time} · 쓰기 없음", method_detail: "수집 방법 상세 기록",
      no_report: "보고서 파일이 없습니다.",
      err_TARGET_NOT_FOUND: "프로세스를 찾을 수 없습니다: {target}. PID나 프로세스 이름을 확인하세요.",
      err_AMBIGUOUS_TARGET: "‘{target}’에 맞는 프로세스가 여럿입니다 ({message}). PID로 지정하세요.",
      err_PERMISSION_DENIED: "이 프로세스를 읽을 권한이 없습니다. 대상과 같은 사용자로 서버를 실행하거나 ptrace 권한(CAP_SYS_PTRACE, ptrace_scope)을 확인하세요.",
      err_TARGET_EXITED: "진단 중에 대상 프로세스가 종료되었습니다. 그때까지 읽은 결과만 남습니다.",
      err_BUSY: "이미 다른 진단이 실행 중입니다. 끝난 뒤 다시 시도하세요.",
      err_INVALID_PARAM: "입력을 확인하세요: {message}", err_UNREACHABLE: "서버에 연결할 수 없습니다. 서버가 실행 중인지 확인하세요.",
      err_JOB_NOT_FOUND: "이 진단 기록을 서버에서 찾을 수 없습니다 (서버가 다시 시작되었을 수 있습니다).",
      err_REPLAY: "재생 파일을 불러오지 못했습니다: {message}",
      err_generic: "진단을 끝내지 못했습니다: {message}",
      conn_retry: "연결이 끊겨 다시 연결하는 중… (받은 이벤트 {seq}개까지 유지)",
      conn_poll: "실시간 스트림이 오지 않아 상태를 주기적으로 가져오는 중",
      conn_lost: "서버와 연결이 끊겼습니다. 진단은 서버에서 계속되고 있을 수 있습니다.", reconnect: "다시 연결",
      replay_label: "재생", replay_again: "다시 재생", replay_note: "저장된 진단 결과를 재생 중 (실제 프로세스가 아님)",
      ago_now: "방금", ago_min: "{n}분 전", ago_hour: "{n}시간 전", ago_day: "어제", ago_days: "{n}일 전",
      live_phase: "{phase} 단계", live_finding: "발견 {n}: {label} 의심", live_verdict: "판정: {word}",
      refuted: "반박된 경쟁 가설:", err_TOO_MANY_JOBS: "동시에 실행할 수 있는 진단 수(4)를 넘었습니다. 하나가 끝난 뒤 다시 시도하세요.",
      err_TARGET_UNREADABLE: "대상 프로세스를 읽을 수 없습니다: {message}"
    },
    en: {
      title: "dynamicState · Diagnose", brand_sub: "diagnose", skip: "Skip to content",
      new: "New diagnosis", new_title: "Diagnose another process", theme: "Toggle light / dark", lang_btn: "EN",
      lang_aria: "Switch language: now English, press for 한국어", tools: "Tools",
      legacy_ui: "Previous UI (legacy)", legacy_ws: "Previous workspace (legacy)",
      hero_h: "Diagnose a running process without stopping it",
      hero_p: "A PID is all it takes. Results build up on this page as they arrive; when it ends, the page is the report.",
      mode_label: "Target location", local: "Local", ssh: "SSH", target_label: "Target process",
      target_ph: "PID or process name  (e.g. 3351223, deadlock_pipeline)", go: "Diagnose", starting: "Starting…",
      symptom_label: "Symptom", symptom_ph: "Symptom (optional)  e.g. service stopped responding, memory keeps growing",
      elf_label: "Debug ELF", elf_ph: "Debug ELF path (optional · default /proc/PID/exe)",
      host_ph: "Host (e.g. 192.168.1.50)", user_ph: "User (optional)", port_ph: "Port (22)",
      key_ph: "SSH key file path (optional)",
      opt_line: "Read-only · never stops the target · default time budget 20 s", advanced: "Advanced",
      budget_label: "Time budget (s)",
      need_target: "Enter a PID or a process name.", need_host: "Enter the SSH host.",
      recent_h: "Recent diagnoses", examples_h: "Examples (replays of saved results)", recent_none: "No diagnoses yet.",
      recent_unreachable: "Could not reach the server, so recent diagnoses are not shown.",
      replay_tag: "replay", running: "Diagnosing", aborted: "Stopped",
      phases: ["Target", "Symptom", "Plan", "Collect", "Analyse · verify", "Verdict"],
      checks_progress: "check {done}/{total}",
      cls_sym_cat: "Symptom “{sym}” → looking at <b>{cat}</b> first ({n} checks).",
      cls_sym: "Planned {n} checks for the symptom “{sym}”.", cls_nosym: "No symptom given: running the baseline checks.",
      so_far_susp: "So far: <b>{label} suspected</b> — verifying…",
      so_far_ver: "So far: <b>{label}</b> verified — writing the verdict…",
      so_far_clean: "All checks done. Writing the verdict…",
      verdict_prefix: "Verdict", verdict_detail: "Detailed records behind the verdict",
      tile_checks: "Checks", tile_stop: "Target stop time", tile_bytes: "Data read", tile_time: "Time taken",
      after_plan: "shown once planned", never_stopped: "never paused", budget: "budget {s} s",
      target_h: "Target", target_desc: "attached · read-only",
      profile_h: "Process profile", profile_pending: "Filled in when the verdict arrives.", profile_pending_t: "{n} threads seen so far.",
      profile_none: "The diagnosis left no data to profile this process.",
      k_proc: "Process", k_arch: "Architecture", k_exe: "Executable", k_build: "Build ID", k_debug: "Debug info",
      k_transport: "Transport", match: "match", mismatch: "MISMATCH", debug_none: "none (symbols only)",
      transport_local: "local", transport_ssh: "SSH (remote collector)",
      findings_h: "Problems found", findings_none_yet: "None yet. A problem a check finds appears here.",
      findings_none: "This diagnosis found no problem.", finding_n: "Finding {n}: {label}",
      b_suspect: "suspected · verifying", b_verified: "verified", sev: "severity {s}",
      f_pending: "The picture and the evidence appear here once verification ends.", f_by: "Checks that pointed to it",
      f_detail: "Detailed records of this finding (report)",
      checks_h: "Checks", checks_desc: "{done}/{total} done", checks_hint: "Press a row to see that check's result",
      st_FAIL: "Found a problem", st_INCONCLUSIVE: "Could not judge", st_PASS: "Passed", st_SKIPPED: "Not run",
      st_RUNNING: "running…", st_PENDING: "waiting",
      not_run_n: "Not run {n}", not_run_hint: "not evidence that the process is fine",
      not_planned_h: "Not selected for this symptom",
      not_in_mode_h: "Not examined: a zero-stop diagnosis cannot answer these",
      needs: "Needs: {cap}", not_executed: "planned but not executed before the diagnosis ended",
      ck_wait_detail: "Once the verdict is in, what this check looked at and the values it read appear here.",
      ck_detail: "Detailed records of this check (report)", ck_id: "Check ID", scope_detail: "Detailed records of the scope",
      notseen_h: "Not established", notseen_right: "not evidence that the process is fine",
      notseen_none: "Nothing: every check that ran reached an answer.",
      next_h: "What to do next", next_none: "The report suggests no specific action.",
      report_h: "Report", report_desc: "The same content as this page, plus detailed records per part",
      open_html: "Open HTML report", md: "Markdown", json: "JSON (<span class=\"mono\">diagnose</span> result)",
      copy: "Copy summary", copied: "Summary copied.", again: "Diagnose the same target again",
      impact: "Impact of the collection on the target: stopped {stop} · read {bytes} · {time} · no writes",
      method_detail: "Detailed records of the method", no_report: "No report file.",
      err_TARGET_NOT_FOUND: "No such process: {target}. Check the PID or the process name.",
      err_AMBIGUOUS_TARGET: "Several processes match ‘{target}’ ({message}). Give a PID.",
      err_PERMISSION_DENIED: "Not allowed to read this process. Run the server as the target's user, or check the ptrace permission (CAP_SYS_PTRACE, ptrace_scope).",
      err_TARGET_EXITED: "The target process exited during the diagnosis. Only what was read until then remains.",
      err_BUSY: "Another diagnosis is already running. Try again when it ends.",
      err_INVALID_PARAM: "Check the input: {message}", err_UNREACHABLE: "Cannot reach the server. Check that it is running.",
      err_JOB_NOT_FOUND: "The server has no record of this diagnosis (it may have restarted).",
      err_REPLAY: "Could not load the replay file: {message}",
      err_generic: "The diagnosis did not finish: {message}",
      conn_retry: "Connection lost, reconnecting… (keeping the {seq} events received)",
      conn_poll: "The live stream does not arrive: polling the status instead",
      conn_lost: "Lost the connection to the server. The diagnosis may still be running there.", reconnect: "Reconnect",
      replay_label: "Replay", replay_again: "Play again", replay_note: "Replaying a saved diagnosis (not a live process)",
      ago_now: "just now", ago_min: "{n} min ago", ago_hour: "{n} h ago", ago_day: "yesterday", ago_days: "{n} days ago",
      live_phase: "{phase}", live_finding: "Finding {n}: {label} suspected", live_verdict: "Verdict: {word}",
      refuted: "Competing hypotheses refuted:", err_TOO_MANY_JOBS: "Too many diagnoses at once (limit 4). Try again when one ends.",
      err_TARGET_UNREADABLE: "Cannot read the target process: {message}"
    }
  };
  var ICON = { FAIL: "✖", INCONCLUSIVE: "?", PASS: "✔", SKIPPED: "–", RUNNING: "", PENDING: "" };
  var TONE = { FAIL: "fail", INCONCLUSIVE: "warn", PASS: "pass", SKIPPED: "skip" };
  var DONE = { FAIL: 1, INCONCLUSIVE: 1, PASS: 1, SKIPPED: 1 };
  var PHASES = ["target", "classify", "plan", "collect", "verify", "verdict"];

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function fill(s, vars) {
    return String(s).replace(/\{(\w+)\}/g, function (m, k) { return vars && vars[k] != null ? vars[k] : m; });
  }
  function tr(lang, key, vars) {
    var table = STR[lang] || STR.ko, s = table[key];
    if (s == null) s = STR.ko[key] != null ? STR.ko[key] : key;
    return vars ? fill(s, vars) : s;
  }
  /* label objects from the server are {ko, en}; a plain string is used as is */
  function L(x, lang) {
    if (x == null) return "";
    if (typeof x === "string") return x;
    return x[lang] != null ? x[lang] : (x.ko != null ? x.ko : (x.en != null ? x.en : ""));
  }
  function stripTags(h) { return String(h || "").replace(/<[^>]+>/g, "").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&#x?27;|&#39;/g, "'").replace(/&amp;/g, "&"); }

  /* the four outcomes of a check (= human_report.check_group: what is not PASS/FAIL/not-run could not judge) */
  function groupOf(status) {
    var s = String(status || "").toUpperCase();
    if (s === "PASS" || s === "FAIL") return s;
    if (s === "" || s === "SKIPPED" || s === "NOT_EXECUTED" || s === "NOT_RUN" || s === "NOT_PLANNED") return "SKIPPED";
    return "INCONCLUSIVE";
  }
  function fmtMs(ms, lang) {
    var v = Number(ms);
    if (!isFinite(v)) return "—";
    if (v < 1000) return Math.round(v) + " ms";
    var x = (v / 1000).toFixed(1);
    return lang === "en" ? x + " s" : x + "초";
  }
  function fmtBytes(n) {
    var v = Number(n);
    if (!isFinite(v)) return "—";
    if (v < 1024) return Math.round(v) + " B";
    if (v < 1048576) return Math.round(v / 1024) + " KB";
    return (v / 1048576).toFixed(1) + " MB";
  }

  /* ------------------------------------------------------------------ reducer */
  function sortEvents(events) {
    var seen = {}, out = [];
    (events || []).forEach(function (e, i) {
      if (!e || typeof e !== "object" || !e.type) return;
      if (e.seq != null) { if (seen[e.seq]) return; seen[e.seq] = 1; }
      out.push({ e: e, i: i });
    });
    out.sort(function (a, b) {
      var sa = a.e.seq, sb = b.e.seq;
      if (sa != null && sb != null && sa !== sb) return sa - sb;
      return a.i - b.i;
    });
    return out.map(function (x) { return x.e; });
  }

  /* one event, whatever its wire shape: the server's envelope {seq, ts, type, data:{...}} (API_CONTRACT.md 3) or a flat
     object (replay files); field names of the contract are mapped onto the names the renderer uses */
  function norm(e) {
    var d = e.data && typeof e.data === "object" && !Array.isArray(e.data) ? e.data : null;
    var x = {}, k;
    if (d) for (k in d) x[k] = d[k];
    for (k in e) if (k !== "data" || !d) x[k] = e[k];
    if (x.recipe_id && !x.rid) x.rid = x.recipe_id;
    switch (x.type) {
      case "target":
        var abi = x.abi || x.target_abi || {};
        x.architecture = x.architecture || abi.architecture || x.arch || null;
        x.libc = x.libc || abi.libc || null;
        x.libc_version = x.libc_version || abi.libc_version || null;
        if (x.threads == null) x.threads = x.thread_count;
        x.debug_image = x.debug_image || x.companion_elf_path || null;
        if (x.debug_info == null && x.dwarf_available != null) x.debug_info = x.dwarf_available;
        if (x.remote_host == null && x.transport === "ssh") x.remote_host = x.target_host;
        break;
      case "classified":
        x.symptom = x.symptom || x.problem_statement || null;
        if (x.hypotheses == null) x.hypotheses = x.competing_hypotheses_count;
        break;
      case "plan":
        if (!x.checks && x.steps) x.checks = x.steps.map(function (st) {
          return { rid: st.recipe_id, name: st.label || st.name, domain: st.domain, domain_label: st.domain_label };
        });
        break;
      case "check_done":
        if (x.line == null && x.summary != null) x.line = x.summary;
        break;
      case "verdict":
        if (!x.report_url && x.report_urls && x.report_urls.html) x.report_url = x.report_urls.html + "&lang={lang}";
        if (!x.human_summary && x.result && x.result.human_summary) x.human_summary = x.result.human_summary;
        break;
      default: break;
    }
    return x;
  }

  function reduce(events, request) {
    var s = { request: request || null, target: null, classified: null, plan: null, order: [], checks: {},
      skipped: { not_planned: [], not_in_mode: [] }, findings: [], refuted: [], verified: false, verdict: null, error: null,
      lastSeq: 0, t: 0, ts0: null, bytes: null, count: 0 };
    var keys = [];                                   // provisional findings without a number: numbered by first sight
    function check(rid) {
      if (!s.checks[rid]) { s.checks[rid] = { rid: rid, status: "PENDING" }; s.order.push(rid); }
      return s.checks[rid];
    }
    function finding(n) {
      for (var i = 0; i < s.findings.length; i++) if (s.findings[i].n === n) return s.findings[i];
      var f = { n: n, verified: false };
      s.findings.push(f);
      s.findings.sort(function (a, b) { return a.n - b.n; });
      return f;
    }
    sortEvents(events).forEach(function (raw) {
      var e = norm(raw);
      s.count++;
      if (e.seq != null && e.seq > s.lastSeq) s.lastSeq = e.seq;
      var tt = typeof e.t === "number" ? e.t : null;
      if (tt == null && e.ts) { var ms = Date.parse(e.ts); if (isFinite(ms)) { if (s.ts0 == null) s.ts0 = ms; tt = ms - s.ts0; } }
      if (tt != null && tt > s.t) s.t = tt;
      if (typeof e.bytes_read === "number") s.bytes = Math.max(s.bytes || 0, e.bytes_read);
      switch (e.type) {
        case "target": s.target = e; break;
        case "classified": s.classified = e; break;
        case "plan":
          s.plan = e;
          var before = s.order.slice();      // checks heard of before the plan keep their place after the plan's
          s.order = [];
          (e.checks || []).forEach(function (c) {
            if (!c.rid || s.order.indexOf(c.rid) >= 0) return;
            var k = s.checks[c.rid] || (s.checks[c.rid] = { rid: c.rid, status: "PENDING" });
            k.name = c.name; k.domain_label = c.domain_label; k.domain = c.domain;
            s.order.push(c.rid);
          });
          before.forEach(function (rid) { if (s.order.indexOf(rid) < 0) s.order.push(rid); });
          var withRid = function (c) { return c.rid ? c : Object.assign({ rid: c.recipe_id }, c); };
          s.skipped = { not_planned: (e.not_planned || []).map(withRid), not_in_mode: (e.not_in_mode || []).map(withRid) };
          break;
        case "check_start": {
          if (!e.rid) break;
          var c1 = check(e.rid);
          if (c1.status === "PENDING") c1.status = "RUNNING";
          if (!c1.name && e.name) c1.name = e.name;
          break;
        }
        case "check_done": {
          if (!e.rid) break;
          var c2 = check(e.rid);
          c2.status = groupOf(e.status); c2.raw = e.status;
          if (e.duration_ms != null) c2.ms = e.duration_ms;
          if (e.line != null) c2.line = e.line;
          if (!c2.name && e.name) c2.name = e.name;
          break;
        }
        case "finding_provisional": {
          var key = e.n != null ? "n" + e.n : String(e.key || e.category || "");
          if (keys.indexOf(key) < 0) keys.push(key);
          var f = finding(e.n != null ? e.n : keys.indexOf(key) + 1);
          f.category = e.category; f.label = e.label || e.category_label; f.severity = e.severity;
          f.recipe_ids = e.recipe_ids || (e.recipe_id ? [e.recipe_id] : []);
          break;
        }
        case "verified":
          s.verified = true;
          (e.findings || []).forEach(function (x) { var g = finding(x.n); g.verified = true; g.status = x.status; });
          (e.hypotheses || []).forEach(function (h) {
            s.findings.forEach(function (g) {
              if (g.category === h.category) { g.verified = true; g.status = h.status === "CONFIRMED" ? "CONFIRMED_ROOT_CAUSE" : "PROBABLE_CAUSE"; }
            });
          });
          s.refuted = (e.rejected || []).map(function (h) { return h.category; }).filter(Boolean);
          break;
        case "verdict": s.verdict = e; break;
        case "error": s.error = e; break;
        default: break;
      }
    });
    /* the verdict is authoritative for every check's outcome and for the findings */
    var V = s.verdict, R = V && V.result;
    if (R && R.checks_run) {
      R.checks_run.forEach(function (c) {
        if (!c.recipe_id) return;
        var k = check(c.recipe_id);
        k.status = groupOf(c.status); k.raw = c.status;
        if (k.ms == null && c.duration_s != null) k.ms = Math.round(c.duration_s * 1000);
        if (!k.name && c.name) k.name = c.name;
      });
    }
    var views = V && V.view;
    var anyView = views && (views.ko || views.en);
    if (anyView) {
      (anyView.checks || []).forEach(function (c) {
        if (c.kind === "not_executed" && s.checks[c.rid]) s.checks[c.rid].status = "SKIPPED";
      });
    } else if (R && R.not_covered && !s.skipped.not_planned.length && !s.skipped.not_in_mode.length) {
      R.not_covered.forEach(function (n) {                   // no view: the not-run groups straight from not_covered
        var ids = String(n.item || "").split(",").map(function (x) { return x.trim(); }).filter(Boolean);
        if (n.kind === "recipes_not_planned") ids.forEach(function (r) { if (!s.checks[r]) s.skipped.not_planned.push({ rid: r }); });
        if (n.kind === "unsupported_in_mode") ids.forEach(function (r) { if (!s.checks[r]) s.skipped.not_in_mode.push({ rid: r, capability: n.capability }); });
      });
    }
    if (R && Array.isArray(R.findings)) {
      var prov = s.findings;
      s.findings = R.findings.map(function (rf, i) {
        var p = prov.filter(function (x) { return x.category === rf.category; })[0] || {};
        return { n: i + 1, category: rf.category, status: rf.status, severity: rf.severity, verified: true, label: p.label,
          recipe_ids: rf.recipe_ids || p.recipe_ids || [], description: rf.description, observed: rf.observed || [] };
      });
    }
    s.phase = phaseOf(s);
    return s;
  }

  function phaseOf(s) {
    if (s.verdict) return "verdict";
    if (s.verified) return "verify";
    if (s.plan) {
      var all = s.order.length > 0 && s.order.every(function (r) { return DONE[s.checks[r].status]; });
      return all ? "verify" : "collect";
    }
    if (s.classified) return "plan";
    if (s.target) return "classify";
    return "target";
  }

  function counts(s) {
    var n = { FAIL: 0, INCONCLUSIVE: 0, PASS: 0, SKIPPED: 0, done: 0, total: s.order.length };
    s.order.forEach(function (rid) {
      var st = s.checks[rid].status;
      if (DONE[st]) { n.done++; n[st]++; }
    });
    var gone = function (c) { return !s.checks[c.rid]; };
    n.notrun = n.SKIPPED + s.skipped.not_planned.filter(gone).length + s.skipped.not_in_mode.filter(gone).length;
    return n;
  }

  function viewOf(s, lang) {
    var vs = s.verdict && s.verdict.view;
    if (!vs) return null;
    return vs[lang] || vs.ko || vs.en || null;
  }

  /* ------------------------------------------------------------------ render (pure) */
  function statusIcon(st, lang) {
    return '<span class="status-icon ' + st + (TONE[st] ? " tone-" + TONE[st] : "") + '" aria-hidden="true">' +
      (ICON[st] || "") + '</span><span class="sr-only">' + esc(tr(lang, "st_" + st)) + "</span>";
  }
  function reportHref(s, ui, anchor) {
    var base = ui.reportUrl || "";
    if (!base) return "";
    return base.replace("{lang}", ui.lang) + (anchor ? "#" + anchor : "");
  }
  function link(href, text) {
    return href ? '<a class="detail-link" href="' + esc(href) + '" target="_blank" rel="noopener">' + esc(text) + " ↗</a>" : "";
  }
  function findingLabel(s, f, lang) {
    var V = viewOf(s, lang);
    var vf = V && (V.findings || []).filter(function (x) { return x.n === f.n; })[0];
    if (vf) return stripTags(vf.heading_html).replace(/^[^:]*:\s*/, "").replace(/\s*\([A-Z_]+\)\s*$/, "");
    return L(f.label, lang) || f.category || "";
  }

  var VTONE = { CONFIRMED_FAULT: "fail", FAULT: "fail", PROBABLE_FAULT: "warn", DEGRADED: "warn", HEALTHY: "pass" };
  /* the verdict in words comes from the server (view.verdict_word, jobs[].verdict_word); without it, the code */
  function verdictWord(code, lang, words) {
    return L(words, lang) || String(code || "");
  }
  function mdInline(t) {
    return esc(t).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>");
  }
  /* without a view: the conclusion sentence of the human summary (Markdown: verdict line, blank, conclusion) */
  function conclusionFromSummary(v) {
    var md = typeof v.human_summary === "string" ? v.human_summary : "";
    var lines = md.split("\n"), i = 0;
    while (i < lines.length && !/^\*\*/.test(lines[i])) i++;
    for (i++; i < lines.length; i++) if (lines[i].trim()) return /^#/.test(lines[i]) ? "" : mdInline(lines[i].trim());
    return "";
  }
  /* the four tiles' final values: the view's, else computed from the result */
  function tilesOf(s, lang) {
    var V = viewOf(s, lang);
    if (V) return V.tiles;
    var R = s.verdict && s.verdict.result;
    if (!R) return {};
    var ci = R.collection_impact || {}, out = {};
    if (typeof ci.measured_stop_ms === "number") out.stop = { value: fmtMs(ci.measured_stop_ms, lang), note: ci.measured_stop_ms === 0 && ci.zero_stop ? tr(lang, "never_stopped") : "" };
    if (typeof ci.bytes_read === "number") out.bytes = { value: fmtBytes(ci.bytes_read), note: ci.impact_transport || "" };
    if (typeof R.duration_s === "number") out.duration = { value: fmtMs(R.duration_s * 1000, lang) };
    return out;
  }

  function renderBanner(s, ui) {
    var lang = ui.lang, V = viewOf(s, lang), v = s.verdict, idx = PHASES.indexOf(s.phase), n = counts(s);
    var html, tone;
    if (v) {
      var code = v.result && v.result.verdict || (V && V.verdict) || "";
      tone = V ? V.tone : VTONE[code] || "skip";
      var T0 = tilesOf(s, lang);
      html = '<div class="line1"><span class="badge badge-tone badge-lg">' + esc(tr(lang, "verdict_prefix")) + ": " +
        esc(V ? V.verdict_word : verdictWord(code, lang)) + "</span>" + '<span class="phase"><code>' + esc(code) + "</code>" +
        (V ? " · " + esc(V.verdict_meaning) : "") + "</span>" +
        '<span class="elapsed">' + esc(T0.duration ? T0.duration.value : fmtMs(ui.elapsed, lang)) + "</span></div>" +
        '<p class="sum">' + (V ? V.conclusion_html : conclusionFromSummary(v) || esc(v.result && v.result.summary || "")) + "</p>" +
        (V && V.symptom_html.length ? V.symptom_html.map(function (x) { return '<p class="note">' + x + "</p>"; }).join("") : "") +
        link(reportHref(s, ui, "verdict-detail"), tr(lang, "verdict_detail"));
    } else {
      var stopped = !!s.error;
      tone = stopped ? "skip" : "info";
      var phaseTxt = tr(lang, "phases")[Math.max(idx, 0)] +
        (s.phase === "collect" ? " · " + tr(lang, "checks_progress", { done: n.done, total: n.total }) : "");
      var sum = "";
      var first = s.findings[0];
      if (first && (s.verified || first.verified)) sum = '<p class="sum">' + tr(lang, "so_far_ver", { label: esc(findingLabel(s, first, lang)) }) + "</p>";
      else if (first) sum = '<p class="sum">' + tr(lang, "so_far_susp", { label: esc(findingLabel(s, first, lang)) }) + "</p>";
      else if (s.phase === "verify") sum = '<p class="sum text-muted">' + esc(tr(lang, "so_far_clean")) + "</p>";
      else if (s.classified) {
        var c = s.classified, sym = c.symptom || (s.request && s.request.symptom);
        var nchk = s.plan ? n.total : c.hypotheses;
        sum = '<p class="sum text-muted">' + (sym ? (c.category_label ? tr(lang, "cls_sym_cat", { sym: esc(sym), cat: esc(L(c.category_label, lang)), n: nchk })
          : tr(lang, "cls_sym", { sym: esc(sym), n: nchk })) : esc(tr(lang, "cls_nosym"))) + "</p>";
      }
      if (!sum) sum = '<p class="sum text-muted" aria-hidden="true">&nbsp;</p>';      // the line is there from the start
      if (ui.conn === "retry") phaseTxt += " · " + tr(lang, "conn_retry", { seq: s.lastSeq });
      if (ui.conn === "poll") phaseTxt += " · " + tr(lang, "conn_poll");
      var pct = s.plan ? 40 + Math.round(45 * n.done / Math.max(n.total, 1)) + (s.verified ? 10 : 0)
        : s.classified ? 28 : s.target ? 14 : 4;
      html = '<div class="line1"><span class="badge badge-tone badge-lg">' +
        (stopped ? "" : '<span class="spinner" aria-hidden="true"></span>') +
        esc(tr(lang, stopped ? "aborted" : "running")) + '</span><span class="phase">' + esc(phaseTxt) + "</span>" +
        '<span class="elapsed">' + esc(fmtMs(ui.elapsed, lang)) + "</span></div>" + sum +
        (stopped ? "" : '<div class="progress" style="margin-top:12px" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' +
          pct + '"><i style="width:' + pct + '%"></i></div>') +
        '<ol class="phases">' + tr(lang, "phases").map(function (p, i) {
          var cls = stopped && i === idx ? "stop" : i < idx ? "done" : i === idx && !stopped ? "now" : "";
          return '<li class="' + cls + '"' + (i === idx && !stopped ? ' aria-current="step"' : "") + ">" + esc(p) + "</li>";
        }).join("") + "</ol>";
    }
    if (s.error) html += '<div class="alert alert-tone tone-fail" role="alert">' + esc(errorText(s.error, lang, s.request)) + "</div>";
    else if (v && v.notice && v.notice.code) {       // the verdict stands; the target itself prevented more (it exited ...)
      html += '<div class="alert alert-tone tone-warn" role="status">' + esc(errorText(v.notice, lang, s.request)) + "</div>";
    }
    if (ui.conn === "lost" && !v) {
      html += '<div class="alert alert-tone tone-fail" role="alert"><span>' + esc(tr(lang, "conn_lost")) +
        '</span><button type="button" class="btn btn-outline btn-sm" data-act="reconnect" style="margin-left:auto">' + esc(tr(lang, "reconnect")) + "</button></div>";
    }
    return '<section class="card card-tone banner tone-' + tone + '" id="banner" aria-label="' + esc(tr(lang, "verdict_prefix")) + '"><div class="card-content">' + html + "</div></section>";
  }

  function errorText(err, lang, req) {
    var code = err.code || "";
    var key = "err_" + code;
    var target = (req && (req.target || req.pid || req.process_name)) || "";
    if (STR.ko[key] == null) return tr(lang, "err_generic", { message: err.message || code });
    return tr(lang, key, { message: err.message || "", target: target });
  }

  function tile(k, v, sub, extra, pend) {
    return '<div class="card tile"><div class="k">' + esc(k) + '</div><div class="v' + (pend ? " pend" : "") + '">' + esc(v) +
      "</div>" + (extra || "") + '<div class="s">' + sub + "</div></div>";
  }
  function renderTiles(s, ui) {
    var lang = ui.lang, n = counts(s), T = tilesOf(s, lang);
    if (!T.checks) T = { checks: null, stop: T.stop, bytes: T.bytes, duration: T.duration };
    var ran = T.checks ? T.checks.value : (s.plan || s.verdict) ? n.total : null;
    var cnt = T.checks ? { FAIL: T.checks.counts.found, INCONCLUSIVE: T.checks.counts.undecided, PASS: T.checks.counts.clean,
      notrun: T.checks.counts.not_run } : n;
    var denom = Math.max(1, (T.checks ? T.checks.counts.run : n.total - n.SKIPPED));
    if (!T.checks && s.verdict) ran = n.total - n.SKIPPED;
    var bar = ran != null ? '<div class="progress-stack" aria-hidden="true">' + ["FAIL", "INCONCLUSIVE", "PASS"].map(function (st) {
      return '<i class="s-' + st + '" style="width:' + (100 * cnt[st] / denom).toFixed(1) + '%"></i>';
    }).join("") + "</div>" : '<div class="progress-stack" aria-hidden="true"></div>';
    var sub1 = ran != null ? '<span title="' + esc(tr(lang, "st_FAIL")) + '">✖ ' + cnt.FAIL + '</span> · <span title="' + esc(tr(lang, "st_INCONCLUSIVE")) + '">? ' + cnt.INCONCLUSIVE +
      '</span> · <span title="' + esc(tr(lang, "st_PASS")) + '">✔ ' + cnt.PASS + '</span> · <span title="' + esc(tr(lang, "st_SKIPPED")) + '">– ' + cnt.notrun + "</span>"
      : esc(tr(lang, "after_plan"));
    var tg = s.target;
    var stopV = T.stop ? T.stop.value : tg && typeof tg.stop_ms === "number" ? fmtMs(tg.stop_ms, lang) : tg && tg.zero_stop ? "0 ms" : "—";
    var stopS = T.stop ? T.stop.note : tg && (tg.zero_stop || tg.stop_ms === 0) ? tr(lang, "never_stopped") : "";
    var bytesV = T.bytes ? T.bytes.value : s.bytes != null ? fmtBytes(s.bytes) : "—";
    var tp = tg && tg.transport ? (tg.transport === "ssh" ? tr(lang, "transport_ssh") : tg.transport === "local" ? tr(lang, "transport_local") : tg.transport) : "";
    var timeV = T.duration ? T.duration.value : (s.count || ui.started) ? fmtMs(ui.elapsed, lang) : "—";
    var budget = s.plan && s.plan.budget_s ? tr(lang, "budget", { s: s.plan.budget_s }) : "";
    return '<div class="tiles" id="tiles">' +
      tile(tr(lang, "tile_checks"), ran == null ? "—" : ran, sub1, bar, ran == null) +
      tile(tr(lang, "tile_stop"), stopV, esc(stopS), "", stopV === "—") +
      tile(tr(lang, "tile_bytes"), bytesV, esc(tp), "", bytesV === "—") +
      tile(tr(lang, "tile_time"), timeV, esc(budget), "", timeV === "—") + "</div>";
  }

  function kv(k, v) {
    return "<div><dt>" + esc(k) + "</dt>" + (v ? '<dd title="' + esc(v) + '">' + esc(v) + "</dd>" : '<dd class="pend">—</dd>') + "</div>";
  }
  function renderTarget(s, ui) {
    var g = s.target, lang = ui.lang;
    if (!g) return "";
    var proc = [g.process_name, g.pid != null ? "pid " + g.pid : "", g.threads ? "threads " + g.threads : ""].filter(Boolean).join(" · ");
    var arch = [g.architecture, [g.libc, g.libc_version].filter(Boolean).join(" ")].filter(Boolean).join(" · ");
    var build = g.build_id ? g.build_id + (g.build_id_match === true ? " (" + tr(lang, "match") + ")" : g.build_id_match === false ? " (" + tr(lang, "mismatch") + ")" : "") : "";
    var dbg = g.debug_image || (g.debug_info === false ? tr(lang, "debug_none") : "");
    var tp = g.transport === "ssh" ? tr(lang, "transport_ssh") + (g.remote_host ? " · " + g.remote_host : "") : g.transport === "local" ? tr(lang, "transport_local") : (g.transport || "");
    return '<section class="card" id="target" aria-labelledby="h-target"><div class="card-header"><h2 class="card-title" id="h-target">' +
      esc(tr(lang, "target_h")) + '</h2><span class="card-description">' + esc(tr(lang, "target_desc")) + "</span></div>" +
      '<div class="card-content"><dl class="kv">' + kv(tr(lang, "k_proc"), proc) + kv(tr(lang, "k_arch"), arch) +
      kv(tr(lang, "k_exe"), g.exe || "") + kv(tr(lang, "k_build"), build) + kv(tr(lang, "k_debug"), dbg) +
      kv(tr(lang, "k_transport"), tp) + "</dl></div></section>";
  }

  /* the process profile: the place is reserved from the plan stage; the content is the server's (view.profile) */
  function renderProfile(s, ui) {
    if (!s.plan && !s.verdict) return "";
    var lang = ui.lang, V = viewOf(s, lang), P = V && V.profile, body, desc = "";
    if (P && P.available) {
      body = '<div class="pbody dsv" lang="' + lang + '">' + P.html + "</div>";
    } else if (P) {
      body = '<p class="empty">' + esc(tr(lang, "profile_none")) + "</p>";
    } else {
      var n = s.target && s.target.threads;
      body = '<p class="empty">' + esc(tr(lang, "profile_pending")) + (n ? " " + esc(tr(lang, "profile_pending_t", { n: n })) : "") + "</p>";
    }
    return '<section class="card" id="profile" aria-labelledby="h-profile"><div class="card-header"><h2 class="card-title" id="h-profile">' +
      esc((P && P.title) || tr(lang, "profile_h")) + "</h2>" + desc + '</div><div class="card-content">' + body + "</div></section>";
  }

  function checkName(s, rid, lang) {
    var V = viewOf(s, lang);
    var vc = V && (V.checks || []).filter(function (c) { return c.rid === rid; })[0];
    if (vc && vc.name) return vc.name;
    var c = s.checks[rid];
    return (c && L(c.name, lang)) || rid;
  }

  function renderFindings(s, ui) {
    if (!s.plan && !s.findings.length && !s.verdict) return "";
    var lang = ui.lang, V = viewOf(s, lang), body = "";
    var list = s.findings;
    if (!list.length) body = '<p class="fnone">' + esc(tr(lang, s.verdict ? "findings_none" : "findings_none_yet")) + "</p>";
    list.forEach(function (f) {
      var vf = V && (V.findings || []).filter(function (x) { return x.n === f.n; })[0];
      var badge;
      if (vf) badge = '<span class="badge badge-tone tone-' + vf.tone + '">' + esc(vf.status_word) + "</span>";
      else if (f.verified) badge = '<span class="badge badge-tone tone-' + (f.status === "CONFIRMED_ROOT_CAUSE" ? "fail" : "warn") + '">' + esc(tr(lang, "b_verified")) + "</span>";
      else badge = '<span class="badge badge-tone tone-warn">' + esc(tr(lang, "b_suspect")) + "</span>";
      var sev = vf ? vf.severity_word : (f.severity || "");
      var head = vf ? vf.heading_html : esc(tr(lang, "finding_n", { n: f.n, label: L(f.label, lang) || f.category }));
      var inner;
      if (vf) {
        inner = '<div class="fbody dsv" lang="' + lang + '" data-static="f' + f.n + "-" + lang + '">' + vf.body_html + "</div>" +
          link(reportHref(s, ui, vf.anchor), tr(lang, "f_detail"));
      } else if (s.verdict) {          // no view from the server: the result's own words (engine English)
        inner = '<div class="prose" lang="en">' + (f.description ? "<p>" + esc(f.description) + "</p>" : "") +
          (f.observed.length ? '<ul>' + f.observed.slice(0, 4).map(function (o) { return "<li>" + esc(o) + "</li>"; }).join("") + "</ul>" : "") + "</div>" +
          link(reportHref(s, ui, "finding-" + f.n + "-detail"), tr(lang, "f_detail"));
      } else {
        var by = (f.recipe_ids || []).filter(function (r) { return s.checks[r] && s.checks[r].status === "FAIL"; });
        inner = '<div class="fpend"><div class="skeleton" aria-hidden="true"></div><div><p>' + esc(tr(lang, "f_pending")) + "</p>" +
          (by.length ? '<p style="margin-top:8px">' + esc(tr(lang, "f_by")) + '</p><ul class="ul">' + by.map(function (r) {
            return "<li>" + esc(checkName(s, r, lang)) + ' <span class="why mono">' + esc(r) + "</span></li>";
          }).join("") + "</ul>" : "") + "</div></div>";
      }
      body += '<article class="finding" id="finding-' + f.n + '"><div class="fhead"><h3>' + head + "</h3>" + badge +
        (sev ? '<span class="badge badge-outline">' + esc(tr(lang, "sev", { s: sev })) + "</span>" : "") +
        (f.category && !vf ? '<span class="badge badge-outline mono">' + esc(f.category) + "</span>" : "") + "</div>" + inner + "</article>";
    });
    if (s.refuted.length && list.length) {
      body += '<p class="text-xs text-muted" style="margin:10px 0 0">' + esc(tr(lang, "refuted")) + " " + s.refuted.map(function (c) {
        return '<span class="badge badge-outline mono">' + esc(c) + "</span>";
      }).join(" ") + "</p>";
    }
    return '<section class="card" id="findings" aria-labelledby="h-findings"><div class="card-header"><h2 class="card-title" id="h-findings">' +
      esc(tr(lang, "findings_h")) + '</h2><span class="card-description">' + (list.length || (s.verdict ? "0" : "—")) + "</span></div>" +
      '<div class="card-content">' + body + "</div></section>";
  }

  function renderChecks(s, ui) {
    if (!s.plan && !s.order.length) return "";
    var lang = ui.lang, V = viewOf(s, lang), n = counts(s);
    var vmap = {};
    if (V) (V.checks || []).forEach(function (c) { vmap[c.rid] = c; });
    var rows = s.order.map(function (rid) {
      var c = s.checks[rid], st = c.status, vc = vmap[rid], open = !!(ui.expanded && ui.expanded[rid]);
      var line = st === "PENDING" ? tr(lang, "st_PENDING") : st === "RUNNING" ? tr(lang, "st_RUNNING")
        : vc ? vc.line : L(c.line, lang) || (st === "SKIPPED" ? tr(lang, "not_executed") : "");
      var ms = DONE[st] && st !== "SKIPPED" && c.ms != null ? Math.round(c.ms) + " ms" : "";
      var domain = vc && vc.domain || L(c.domain_label, lang);
      var dt = "";
      if (open) {
        if (vc && vc.detail_html) {
          dt = '<div class="ckdetail dsv" lang="' + lang + '">' + vc.detail_html + "</div>" + link(reportHref(s, ui, vc.anchor), tr(lang, "ck_detail"));
        } else {
          dt = (DONE[st] && line ? "<p>" + esc(line) + "</p>" : "") + '<p class="text-muted">' + esc(tr(lang, "ck_wait_detail")) + "</p>" +
            '<p class="rid">' + esc(tr(lang, "ck_id")) + " <code>" + esc(rid) + "</code></p>";
        }
      }
      return '<li id="ck-' + esc(rid) + '" class="' + (st === "PENDING" ? "pend" : "") + '"><button type="button" class="ck-row" data-act="ck" data-rid="' +
        esc(rid) + '" aria-expanded="' + open + '" aria-controls="ckd-' + esc(rid) + '">' + statusIcon(st, lang) +
        '<span class="nm">' + esc(checkName(s, rid, lang)) + '</span><span class="cat">' + esc(domain) + "</span>" +
        '<span class="ln">' + esc(line) + '</span><span class="ms">' + ms + '</span><span class="chev" aria-hidden="true">' + (open ? "▾" : "▸") + "</span></button>" +
        '<div class="dt" id="ckd-' + esc(rid) + '"' + (open ? "" : " hidden") + ">" + dt + "</div></li>";
    }).join("");
    var notRow = function (c) { return !s.checks[c.rid]; };     // a left-out check the engine ran after all is a row
    var np = s.skipped.not_planned.filter(notRow), nm = s.skipped.not_in_mode.filter(notRow);
    function staticRow(c, why) {
      var vc = vmap[c.rid];
      return '<li><div class="ck-static">' + statusIcon("SKIPPED", lang) + '<span class="nm">' + esc(vc && vc.name || L(c.name, lang) || c.rid) +
        '</span><span class="why">' + esc(why || (vc && vc.domain) || L(c.domain_label, lang)) + '</span><span class="rid mono">' + esc(c.rid) + "</span></div></li>";
    }
    var skip = "";
    if (np.length || nm.length) {
      var caps = {};
      nm.forEach(function (c) { var k = c.capability || ""; (caps[k] = caps[k] || { label: c.capability_label, items: [] }).items.push(c); });
      skip = '<details class="collapsible collapsible-plain skipgroup" id="skipped"><summary><b>' + esc(tr(lang, "not_run_n", { n: np.length + nm.length })) +
        "</b> " + esc(tr(lang, "not_run_hint")) + "</summary>" +
        (np.length ? "<h4>" + esc(tr(lang, "not_planned_h")) + " (" + np.length + ')</h4><ul class="ck">' + np.map(function (c) { return staticRow(c); }).join("") + "</ul>" : "") +
        (nm.length ? "<h4>" + esc(tr(lang, "not_in_mode_h")) + " (" + nm.length + ")</h4>" + Object.keys(caps).map(function (k) {
          return '<p class="cap">' + esc(tr(lang, "needs", { cap: L(caps[k].label, lang) || k })) + '</p><ul class="ck">' +
            caps[k].items.map(function (c) { return staticRow(c); }).join("") + "</ul>";
        }).join("") : "") + "</details>";
    }
    return '<section class="card" id="checks" aria-labelledby="h-checks"><div class="card-header"><h2 class="card-title" id="h-checks">' +
      esc(tr(lang, "checks_h")) + '</h2><span class="card-description">' + esc(tr(lang, "checks_desc", { done: n.done, total: n.total })) +
      '</span><span class="right">' + esc(tr(lang, "checks_hint")) + "</span></div>" +
      '<div class="card-content"><ul class="ck">' + rows + "</ul>" + skip +
      (s.verdict ? link(reportHref(s, ui, "scope-detail"), tr(lang, "scope_detail")) : "") + "</div></section>";
  }

  function renderTail(s, ui) {
    var v = s.verdict;
    if (!v) return "";
    var lang = ui.lang, V = viewOf(s, lang);
    var und = s.order.filter(function (r) { return s.checks[r].status === "INCONCLUSIVE"; });
    var vmap = {};
    if (V) (V.checks || []).forEach(function (c) { vmap[c.rid] = c; });
    var ns = (und.length ? '<ul class="ul">' + und.map(function (r) {
      var line = vmap[r] ? vmap[r].line : L(s.checks[r].line, lang);
      return "<li>" + esc(checkName(s, r, lang)) + (line ? ' <span class="why">— ' + esc(line) + "</span>" : "") + "</li>";
    }).join("") + "</ul>" : "");
    var other = V ? V.not_examined_html || "" : "";
    if (!V && v.result && v.result.not_covered) {        // no view: the result's not_covered entries that are not about one check
      var rest = v.result.not_covered.filter(function (n) {
        var k = String(n.kind || "");
        return k.indexOf("check_") !== 0 && k !== "recipes_not_planned" && k !== "unsupported_in_mode";
      });
      if (rest.length) other = '<ul lang="en">' + rest.map(function (n) { return "<li><code>" + esc(n.kind) + "</code> " + esc(n.reason || n.item || "") + "</li>"; }).join("") + "</ul>";
    }
    if (other) ns += '<div class="prose">' + other + "</div>";
    var nsCount = und.length + (other.match(/<li>/g) || []).length;
    var out = '<section class="card" id="notseen" aria-labelledby="h-notseen"><div class="card-header"><h2 class="card-title" id="h-notseen">' +
      esc(tr(lang, "notseen_h")) + '</h2><span class="card-description">' + nsCount + '</span><span class="right">' + esc(tr(lang, "notseen_right")) +
      '</span></div><div class="card-content">' + (ns || '<p class="empty">' + esc(tr(lang, "notseen_none")) + "</p>") + "</div></section>";
    out += '<section class="card" id="next" aria-labelledby="h-next"><div class="card-header"><h2 class="card-title" id="h-next">' + esc(tr(lang, "next_h")) +
      '</h2></div><div class="card-content">' + (V && V.next_html ? '<div class="prose">' + V.next_html + "</div>" : '<p class="empty">' + esc(tr(lang, "next_none")) + "</p>") + "</div></section>";
    var T = tilesOf(s, lang), href = reportHref(s, ui, "");
    var urls = v.report_urls || {};
    var mdHref = urls.md ? urls.md + "&lang=" + lang : "", jsHref = urls.json || "";
    var md = mdHref || (v.human_summary && L(v.human_summary, lang)), js = jsHref || !!v.result;
    out += '<section class="card" id="report" aria-labelledby="h-report"><div class="card-header"><h2 class="card-title" id="h-report">' + esc(tr(lang, "report_h")) +
      '</h2><span class="card-description">' + esc(tr(lang, "report_desc")) + '</span></div><div class="card-footer" style="padding-top:12px">' +
      (href ? '<a class="btn" href="' + esc(href) + '" target="_blank" rel="noopener" style="text-decoration:none">' + esc(tr(lang, "open_html")) + "</a>"
        : '<button type="button" class="btn" disabled>' + esc(tr(lang, "open_html")) + "</button>") +
      (mdHref ? '<a class="btn btn-outline" href="' + esc(mdHref) + '" target="_blank" rel="noopener" style="text-decoration:none">' + esc(tr(lang, "md")) + "</a>"
        : md ? '<button type="button" class="btn btn-outline" data-act="md">' + esc(tr(lang, "md")) + "</button>" : "") +
      (jsHref ? '<a class="btn btn-outline" href="' + esc(jsHref) + '" target="_blank" rel="noopener" style="text-decoration:none">' + tr(lang, "json") + "</a>"
        : js ? '<button type="button" class="btn btn-outline" data-act="json">' + tr(lang, "json") + "</button>" : "") +
      '<button type="button" class="btn btn-outline" data-act="copy">' + esc(tr(lang, "copy")) + "</button>" +
      (s.request ? '<button type="button" class="btn btn-ghost" data-act="again">' + esc(tr(lang, "again")) + "</button>" : "") +
      '</div><div class="card-content" style="padding-top:0"><p class="impact">' +
      esc(tr(lang, "impact", { stop: T && T.stop ? T.stop.value : "—", bytes: T && T.bytes ? T.bytes.value : "—", time: T && T.duration ? T.duration.value : "—" })) +
      (href ? " · " + link(reportHref(s, ui, "method-detail"), tr(lang, "method_detail")).replace('class="detail-link" ', "") : "") +
      (ui.copied ? ' <span role="status">· ' + esc(tr(lang, "copied")) + "</span>" : "") + "</p></div></section>";
    return out;
  }

  /* the running/finished diagnosis: the cards in the report's order, each present once its data exists */
  function render(s, ui) {
    var started = s.count > 0 || ui.started;
    if (!started) return "";
    return renderBanner(s, ui) + renderTiles(s, ui) + renderTarget(s, ui) + renderProfile(s, ui) + renderFindings(s, ui) + renderChecks(s, ui) + renderTail(s, ui) +
      (ui.replay ? '<div class="replaybar no-print" role="region" aria-label="' + esc(tr(ui.lang, "replay_label")) + '"><span>' +
        esc(tr(ui.lang, "replay_label")) + ": <b>" + esc(ui.replay) + '</b> · <span class="text-muted">' + esc(tr(ui.lang, "replay_note")) +
        '</span></span><button type="button" class="btn btn-outline btn-sm" data-act="replay-again">' + esc(tr(ui.lang, "replay_again")) + "</button></div>" : "");
  }

  function renderChip(s, ui) {
    var g = s.target;
    if (!g) return "";
    var live = !s.verdict && !s.error;
    return "<b>" + esc(g.process_name || "?") + '</b><span class="sep">·</span><span>pid ' + esc(g.pid) + "</span>" +
      (g.architecture ? '<span class="sep opt-hide">·</span><span class="opt-hide">' + esc(g.architecture) + "</span>" : "") +
      (live ? '<span class="sep">·</span><span class="live"><i aria-hidden="true"></i>' + esc(tr(ui.lang, "running")) + "</span>" : "");
  }

  function ago(iso, lang, now) {
    var t = Date.parse(iso);
    if (!isFinite(t)) return "";
    var m = Math.max(0, Math.round(((now || Date.now()) - t) / 60000));
    if (m < 1) return tr(lang, "ago_now");
    if (m < 60) return tr(lang, "ago_min", { n: m });
    var h = Math.round(m / 60);
    if (h < 24) return tr(lang, "ago_hour", { n: h });
    var d = Math.round(h / 24);
    return d <= 1 ? tr(lang, "ago_day") : tr(lang, "ago_days", { n: d });
  }
  /* idle: the title line, the form, the recent diagnoses (or the examples when there is no server) */
  function renderIdle(ui) {
    var lang = ui.lang, f = ui.form || {}, ssh = f.mode === "ssh";
    function inp(name, cls, ph, label, type) {
      return '<input class="input ' + cls + '" name="' + name + '" type="' + (type || "text") + '" placeholder="' + esc(ph) + '" aria-label="' + esc(label) +
        '" value="' + esc(f[name] || "") + '" autocomplete="off" spellcheck="false">';
    }
    var recent = "";
    var jobs = ui.jobs || [];
    if (jobs.length) {
      recent = "<h3>" + esc(tr(lang, "recent_h")) + "</h3>" + jobs.map(function (j) {
        var tg = j.target || { pid: j.pid, process_name: j.target_name, remote_host: j.remote_host };
        var word = L(j.verdict_word, lang) || (j.state === "running" ? tr(lang, "running") : j.verdict ? verdictWord(j.verdict, lang)
          : j.state === "error" ? tr(lang, "aborted") : j.state || "");
        var tone = j.state === "running" ? "info" : VTONE[j.verdict] || "skip";
        return '<a class="card it" href="?job=' + encodeURIComponent(j.job_id) + '" data-act="open-job" data-job="' + esc(j.job_id) + '">' +
          '<span class="badge badge-tone tone-' + tone + '">' + esc(word) + '</span><span class="n">' + esc(tg.process_name || tg.pid || "?") +
          '</span><span class="d">' + esc([L(j.headline, lang), tg.pid != null ? "pid " + tg.pid : "", tg.remote_host || ""].filter(Boolean).join(" · ")) +
          '</span><span class="t">' + esc(ago(j.started_at, lang, ui.now)) + "</span></a>";
      }).join("");
    } else if (ui.jobsState === "empty") {
      recent = "<h3>" + esc(tr(lang, "recent_h")) + '</h3><p class="note">' + esc(tr(lang, "recent_none")) + "</p>";
    } else if (ui.jobsState === "unreachable") {
      recent = '<p class="note">' + esc(tr(lang, "recent_unreachable")) + "</p>";
    }
    if ((ui.examples || []).length && (ui.jobsState === "unreachable" || ui.jobsState === "empty" || ui.showExamples)) {
      recent += "<h3" + (recent ? ' style="margin-top:18px"' : "") + ">" + esc(tr(lang, "examples_h")) + "</h3>" + ui.examples.map(function (x) {
        return '<a class="card it" href="?replay=' + encodeURIComponent(x.name) + '" data-act="open-replay" data-replay="' + esc(x.name) + '">' +
          '<span class="badge badge-tone tone-' + (VTONE[x.verdict] || "skip") + '">' + esc(L(x.verdict_word, lang) || x.verdict) + "</span>" +
          '<span class="n">' + esc(x.process_name || x.name) + '</span><span class="d">' + esc(L(x.headline, lang) || ("pid " + x.pid)) +
          '</span><span class="t">' + esc(tr(lang, "replay_tag")) + "</span></a>";
      }).join("");
    }
    return '<div class="hero"><h1>' + esc(tr(lang, "hero_h")) + "</h1><p>" + esc(tr(lang, "hero_p")) + "</p>" +
      '<form class="card form" id="form" novalidate autocomplete="off">' +
      '<div class="row"><div class="toggle-group toggle-group-lg" role="group" aria-label="' + esc(tr(lang, "mode_label")) + '">' +
      '<button type="button" data-act="mode" data-mode="local" aria-pressed="' + !ssh + '">' + esc(tr(lang, "local")) + "</button>" +
      '<button type="button" data-act="mode" data-mode="ssh" aria-pressed="' + ssh + '">' + esc(tr(lang, "ssh")) + "</button></div>" +
      inp("target", "input-lg mono", tr(lang, "target_ph"), tr(lang, "target_label")) +
      '<button type="submit" class="btn btn-lg" id="go"' + (ui.starting ? " disabled" : "") + ">" + esc(tr(lang, ui.starting ? "starting" : "go")) + "</button></div>" +
      (ssh ? '<div class="row">' + inp("remote_host", "mono", tr(lang, "host_ph"), tr(lang, "host_ph")) + inp("ssh_user", "mono", tr(lang, "user_ph"), tr(lang, "user_ph")) +
        inp("ssh_port", "mono", tr(lang, "port_ph"), tr(lang, "port_ph"), "text").replace('class="input mono"', 'class="input mono" style="flex:.4"') +
        inp("ssh_key", "mono", tr(lang, "key_ph"), tr(lang, "key_ph")) + "</div>" : "") +
      '<div class="row">' + inp("symptom", "", tr(lang, "symptom_ph"), tr(lang, "symptom_label")) +
      inp("debug_image", "mono elf", tr(lang, "elf_ph"), tr(lang, "elf_label")) + "</div>" +
      '<div class="opt"><span>' + esc(tr(lang, "opt_line")) + "</span>" +
      '<details id="adv"><summary>' + esc(tr(lang, "advanced")) + '</summary><label class="adv">' + esc(tr(lang, "budget_label")) +
      ' <input class="input mono" name="time_limit_s" type="number" min="1" max="120" step="1" placeholder="20" value="' + esc(f.time_limit_s || "") + '"></label></details></div>' +
      (ui.formError ? '<div class="alert alert-tone tone-fail" role="alert">' + esc(ui.formError) + "</div>" : "") +
      "</form></div>" + '<div class="recent" id="recent">' + recent + "</div>";
  }

  /* what the live region says: changes only when the phase, a finding or the outcome changes */
  function announce(s, lang) {
    if (s.error) return errorText(s.error, lang, s.request);
    if (s.verdict) { var V = viewOf(s, lang); return tr(lang, "live_verdict", { word: V ? V.verdict_word : (s.verdict.result || {}).verdict }); }
    var f = s.findings[0];
    var ph = tr(lang, "live_phase", { phase: tr(lang, "phases")[PHASES.indexOf(s.phase)] });
    return f ? ph + ". " + tr(lang, "live_finding", { n: f.n, label: findingLabel(s, f, lang) }) : ph;
  }

  /* the replay's stop points (?stage=), as in the mock: 1 target, 2 plan, 3 collecting, 4 verified, 5 verdict */
  function stageIndex(events, stage) {
    var ev = sortEvents(events), at = function (type) { for (var i = 0; i < ev.length; i++) if (ev[i].type === type) return i + 1; return ev.length; };
    switch (Number(stage)) {
      case 0: return 0;
      case 1: return at("classified");
      case 2: return at("plan");
      case 3: {
        var fp = at("finding_provisional");
        if (fp >= ev.length) { var p = at("plan"); return p + Math.floor((ev.length - p) / 2); }
        for (var i = fp; i < ev.length; i++) if (ev[i].type === "check_start") return i + 1;
        return fp;
      }
      case 4: return at("verified");
      default: return ev.length;
    }
  }

  var api = { STR: STR, reduce: reduce, render: render, renderIdle: renderIdle, renderChip: renderChip, announce: announce,
    sortEvents: sortEvents, groupOf: groupOf, counts: counts, fmtMs: fmtMs, fmtBytes: fmtBytes, stageIndex: stageIndex,
    PHASES: PHASES, viewOf: viewOf };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.DSUI = api;
  if (typeof document === "undefined") return;

  /* ================================================================== browser shell (side effects only) */
  var Q = new URLSearchParams(location.search);
  var LS = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage blocked */ } }
  };
  var ui = { lang: (Q.get("lang") || LS.get("ds-lang") || "ko") === "en" ? "en" : "ko", expanded: {}, form: { mode: "local" },
    elapsed: 0, conn: "ok", jobs: null, jobsState: "", examples: [], now: Date.now() };
  var events = [], request = null, job = null, replayTimers = [], es = null, pollTimer = null, watchdog = null,
    retries = 0, t0 = 0, tick = null, frozenElapsed = null, lastSpoken = "", gen = 0;
  var main = document.getElementById("main"), chip = document.getElementById("tchip"), live = document.getElementById("live");

  /* morph: bring the live node `a` to the new node `b` in place, so what is on screen keeps its node (focus, the
     picture's step radios, a <details> the reader opened); new children are inserted where they belong */
  function keyOf(n) { return n.nodeType === 1 ? (n.id || n.getAttribute("data-k") || "") : ""; }
  function morph(a, b, childrenOnly) {
    if (a.nodeType === 3 || a.nodeType === 8) { if (a.nodeValue !== b.nodeValue) a.nodeValue = b.nodeValue; return; }
    var st = b.getAttribute && b.getAttribute("data-static");
    if (st && a.getAttribute("data-static") === st) return;
    var i, at;
    if (!childrenOnly) for (i = a.attributes.length - 1; i >= 0; i--) {
      at = a.attributes[i].name;
      if (!b.hasAttribute(at) && !(a.nodeName === "DETAILS" && at === "open")) a.removeAttribute(at);
    }
    if (!childrenOnly) for (i = 0; i < b.attributes.length; i++) {
      at = b.attributes[i];
      if (a.nodeName === "DETAILS" && at.name === "open") continue;
      if (a.getAttribute(at.name) !== at.value) a.setAttribute(at.name, at.value);
    }
    if (a.nodeName === "INPUT" || a.nodeName === "TEXTAREA") return;      // the user's typing is not re-rendered
    var ac = a.firstChild, bc = b.firstChild, next;
    while (bc) {
      next = bc.nextSibling;
      if (!ac) { a.appendChild(bc); bc = next; continue; }
      if (ac.nodeType === bc.nodeType && ac.nodeName === bc.nodeName && keyOf(ac) === keyOf(bc)) { morph(ac, bc); ac = ac.nextSibling; bc = next; continue; }
      var k = keyOf(bc), later = null;
      if (k) for (var x = ac.nextSibling; x; x = x.nextSibling) if (keyOf(x) === k) { later = x; break; }
      if (later) { while (ac !== later) { var gone = ac; ac = ac.nextSibling; a.removeChild(gone); } morph(ac, bc); ac = ac.nextSibling; }
      else a.insertBefore(bc, ac);
      bc = next;
    }
    while (ac) { var rm = ac; ac = ac.nextSibling; a.removeChild(rm); }
  }
  function patch(node, html) {
    var tpl = document.createElement(node.nodeName === "MAIN" ? "main" : "div");
    tpl.innerHTML = html;
    morph(node, tpl, true);
  }

  function state() { return reduce(events, request); }
  var pending = false;
  function draw() {
    if (pending) return;
    pending = true;
    (window.requestAnimationFrame || setTimeout)(function () { pending = false; drawNow(); });
  }
  function drawNow() {
    applyStatic();
    ui.now = Date.now();
    var s = state();
    if (!request && !events.length && !ui.started) {
      patch(main, renderIdle(ui));
      chip.hidden = true;
      return;
    }
    ui.elapsed = frozenElapsed != null ? frozenElapsed : ui.replayClock != null ? ui.replayClock : (t0 ? Date.now() - t0 : s.t);
    if (s.verdict || s.error) {
      stopTick();
      var vt = s.verdict && s.verdict.result && s.verdict.result.duration_s;
      if (frozenElapsed == null) frozenElapsed = vt ? vt * 1000 : ui.elapsed;
      ui.elapsed = frozenElapsed;
    }
    ui.reportUrl = s.verdict && s.verdict.report_url ? s.verdict.report_url
      : job ? "api/diagnose/" + encodeURIComponent(job) + "/report?lang={lang}" : "";
    /* what the reader is looking at stays where it is: when a card above it grows (a finding arrives, its picture
       comes in with the verdict), the page scrolls by the same amount */
    var anchor = null, before = 0;
    if (window.scrollY > 0) {
      for (var c0 = main.firstElementChild; c0; c0 = c0.nextElementSibling) {
        var r0 = c0.getBoundingClientRect();
        if (r0.bottom > window.innerHeight / 3) { anchor = c0; before = r0.top; break; }   // the card at the reading line
      }
    }
    patch(main, render(s, ui));
    if (anchor && anchor.isConnected) {
      var delta = anchor.getBoundingClientRect().top - before;
      if (delta) window.scrollBy(0, delta);
    }
    var c = renderChip(s, ui);
    chip.hidden = !c;
    patch(chip, c);
    var say = announce(s, ui.lang);
    if (say !== lastSpoken) { lastSpoken = say; live.textContent = say; }
    document.title = (s.target ? (s.target.process_name || s.target.pid) + " · " : "") + tr(ui.lang, "title");
  }
  function applyStatic() {
    var lang = ui.lang;
    document.documentElement.lang = lang;
    document.querySelectorAll("[data-s]").forEach(function (n) { n.textContent = tr(lang, n.getAttribute("data-s")); });
    document.querySelectorAll("[data-s-aria]").forEach(function (n) {
      var t = tr(lang, n.getAttribute("data-s-aria")); n.setAttribute("aria-label", t); n.title = t;
    });
    var nb = document.querySelector('[data-act="new"]'); nb.title = tr(lang, "new_title");
    var lb = document.getElementById("btn-lang"); lb.textContent = tr(lang, "lang_btn"); lb.setAttribute("aria-label", tr(lang, "lang_aria"));
  }
  function startTick() { stopTick(); tick = setInterval(draw, 200); }
  function stopTick() { if (tick) { clearInterval(tick); tick = null; } }

  function push(e) {
    if (!e || typeof e !== "object") return;
    events.push(e);
    if (!t0) t0 = Date.now() - (typeof e.t === "number" ? e.t : 0);
    draw();
    if (e.type === "verdict" || e.type === "error") closeStream();
  }

  /* ---- server: start, SSE, polling fallback, reconnect from the last seq ---- */
  function jobState(b) { return (b.job && b.job.state) || b.state || ""; }
  function getJSON(url, opt) {
    return fetch(url, opt).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (b) { b.__status = r.status; return b; });
    });
  }
  function closeStream() {
    if (es) { es.close(); es = null; }
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    if (watchdog) { clearTimeout(watchdog); watchdog = null; }
  }
  var TYPES = ["target", "classified", "plan", "check_start", "check_done", "finding_provisional", "verified", "verdict", "error"];
  function connect() {
    closeStream();
    var my = gen, s0 = state();
    if (s0.verdict || s0.error || !window.EventSource) { if (!s0.verdict && !s0.error) poll(); return; }
    var got = false;
    es = new EventSource("api/diagnose/" + encodeURIComponent(job) + "/events?after=" + s0.lastSeq);
    var on = function (m) {
      if (my !== gen) return;
      got = true; retries = 0;
      if (ui.conn !== "ok") { ui.conn = "ok"; }
      try { push(JSON.parse(m.data)); } catch (err) { /* a malformed frame is skipped */ }
    };
    es.onmessage = on;
    TYPES.forEach(function (t) { es.addEventListener(t, on); });
    es.onerror = function () {
      if (my !== gen) return;
      var s = state();
      if (s.verdict || s.error) { closeStream(); return; }
      closeStream();
      retries++;
      ui.conn = retries > 3 ? "poll" : "retry";
      draw();
      if (retries > 3) poll(); else setTimeout(function () { if (my === gen) connect(); }, 500 * retries);
    };
    /* a proxy that buffers the stream delivers nothing: fall back to polling the status */
    watchdog = setTimeout(function () { if (my === gen && !got) { closeStream(); ui.conn = "poll"; draw(); poll(); } }, 4000);
  }
  function poll() {
    var my = gen, failures = 0;
    (function once() {
      if (my !== gen) return;
      getJSON("api/diagnose/" + encodeURIComponent(job) + "/status?after=" + state().lastSeq).then(function (b) {
        if (my !== gen) return;
        if (b.__status === 404) { push({ type: "error", code: "JOB_NOT_FOUND", seq: 1e9 }); return; }
        failures = 0;
        (b.events || []).forEach(push);
        var s = state();
        if (ui.conn === "lost") ui.conn = "poll";
        if (!s.verdict && !s.error && jobState(b) !== "done" && jobState(b) !== "error") pollTimer = setTimeout(once, 1000);
        else draw();
      }).catch(function () {
        if (my !== gen) return;
        failures++;
        if (failures > 5) { ui.conn = "lost"; draw(); return; }
        pollTimer = setTimeout(once, 1000 * failures);
      });
    })();
  }
  function reset() {
    gen++;
    closeStream();
    replayTimers.forEach(clearTimeout); replayTimers = [];
    events = []; request = null; job = null; t0 = 0; frozenElapsed = null; retries = 0;
    ui.expanded = {}; ui.conn = "ok"; ui.started = false; ui.replay = null; ui.replayClock = null; ui.copied = false;
    stopTick();
  }
  function openJob(id, req) {
    reset();
    job = id; request = req || { target: "" }; ui.started = true;
    startTick();
    connect();
    draw();
  }
  function start(req) {
    ui.formError = ""; ui.starting = true; draw();
    var body = { language: ui.lang, symptom: req.symptom || undefined, debug_image: req.debug_image || undefined,
      time_limit_s: req.time_limit_s ? Number(req.time_limit_s) : undefined };
    if (req.mode === "ssh") {
      body.remote_host = req.remote_host; body.ssh_user = req.ssh_user || undefined;
      body.ssh_port = req.ssh_port ? Number(req.ssh_port) : undefined; body.ssh_key = req.ssh_key || undefined;
    }
    var fail = function (code, message) { ui.starting = false; ui.formError = errorText({ code: code, message: message }, ui.lang, req); draw(); };
    resolvePid(req).then(function (pid) {
      body.pid = pid;
      return getJSON("api/diagnose/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    }).then(function (b) {
        if (!b) return;
        ui.starting = false;
        if (b.success === false || !b.job_id) {
          var err = b.error || { code: "INTERNAL", message: "HTTP " + b.__status };
          ui.formError = errorText(err, ui.lang, req);
          draw();
          return;
        }
        history.pushState(null, "", "?job=" + encodeURIComponent(b.job_id));
        openJob(b.job_id, req);
      })
      .catch(function (err) {
        if (err && err.code) fail(err.code, err.message);
        else fail("UNREACHABLE", "");
      });
  }
  /* a process name becomes a pid through the process listing (API_CONTRACT.md 1: start takes a pid only) */
  function resolvePid(req) {
    if (/^\d+$/.test(req.target)) return Promise.resolve(Number(req.target));
    var q = "process_name=" + encodeURIComponent(req.target);
    if (req.mode === "ssh") ["remote_host", "ssh_user", "ssh_port", "ssh_key"].forEach(function (k) { if (req[k]) q += "&" + k + "=" + encodeURIComponent(req[k]); });
    return getJSON("api/target/processes?" + q).then(function (b) {
      if (b.success === false) throw { code: (b.error || {}).code || "FIND_PROCESSES_ERROR", message: (b.error || {}).message || "" };
      var all = ((b.data || {}).processes || []);
      var exact = all.filter(function (p) { return p.exact_name_match; });
      var pick = exact.length ? exact : all;
      if (!pick.length) throw { code: "TARGET_NOT_FOUND" };
      if (pick.length > 1) throw { code: "AMBIGUOUS_TARGET", message: pick.slice(0, 5).map(function (p) { return p.name + " " + p.pid; }).join(", ") };
      return pick[0].pid;
    });
  }

  /* ---- replay: a recorded event sequence played at ?speed=, stopped at ?stage= ---- */
  function replay(name) {
    reset();
    ui.replay = name; ui.started = true;
    var my = gen;
    getJSON("replay/" + encodeURIComponent(name) + ".json").then(function (doc) {
      if (my !== gen) return;
      if (!doc.events) throw new Error("HTTP " + doc.__status);
      request = doc.request || {};
      var evs = sortEvents(doc.events), report = doc.report && doc.report.html;
      if (report) evs = evs.map(function (e) { return e.type === "verdict" && !e.report_url ? Object.assign({}, e, { report_url: report }) : e; });
      var stage = Q.get("stage"), speed = Math.max(0.1, Number(Q.get("speed")) || 1);
      if (stage != null && stage !== "") {
        var upto = stageIndex(evs, stage);
        evs.slice(0, upto).forEach(function (e) { events.push(e); });
        ui.replayClock = upto ? evs[upto - 1].t || 0 : 0;
        if (Number(stage) === 3) {                 // show the next check as running, as the mock does
          var s = reduce(events, request), nextRid = s.order.filter(function (r) { return s.checks[r].status === "PENDING"; })[0];
          var busy = s.order.some(function (r) { return s.checks[r].status === "RUNNING"; });
          if (nextRid && !busy) events.push({ type: "check_start", rid: nextRid, seq: (s.lastSeq || 0) + 0.5, t: ui.replayClock });
        }
        draw();
        return;
      }
      var begin = Date.now();
      ui.replayClock = 0;
      tick = setInterval(function () { ui.replayClock = (Date.now() - begin) * speed; draw(); }, 200);
      evs.forEach(function (e) {
        replayTimers.push(setTimeout(function () { if (my === gen) push(e); }, (e.t || 0) / speed));
      });
      draw();
    }).catch(function (err) {
      if (my !== gen) return;
      push({ type: "error", code: "REPLAY", message: String(err && err.message || err), seq: 1 });
    });
  }

  /* ---- idle data ---- */
  function loadIdle() {
    getJSON("api/diagnose/jobs").then(function (b) {
      if (b.__status >= 400 || !Array.isArray(b.jobs)) throw new Error("jobs");
      ui.jobs = b.jobs; ui.jobsState = b.jobs.length ? "ok" : "empty"; draw();
    }).catch(function () { ui.jobs = []; ui.jobsState = "unreachable"; draw(); });
    getJSON("replay/index.json").then(function (b) { if (Array.isArray(b)) { ui.examples = b; draw(); } }).catch(function () { /* none */ });
  }

  function route() {
    var q = new URLSearchParams(location.search);
    Q = q;
    if (q.get("replay")) replay(q.get("replay"));
    else if (q.get("job")) openJob(q.get("job"));
    else { reset(); loadIdle(); draw(); }
  }

  /* ---- input ---- */
  function readForm() {
    var fm = document.getElementById("form");
    if (!fm) return ui.form;
    Array.prototype.forEach.call(fm.querySelectorAll("input[name]"), function (n) { ui.form[n.name] = n.value.trim(); });
    return ui.form;
  }
  function download(name, text, type) {
    var a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: type }));
    a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }
  function copyText(text) {
    var done = function () { ui.copied = true; draw(); setTimeout(function () { ui.copied = false; draw(); }, 2500); };
    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(text).then(done, fallback); } else fallback();
    function fallback() {
      var ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch (e) { /* nothing to do */ }
      ta.remove();
    }
  }
  function setTheme(dark) {
    var r = document.documentElement;
    r.classList.toggle("dark", dark); r.classList.toggle("light", !dark);
    LS.set("ds-theme", dark ? "dark" : "light");
  }
  function toggleMenu(open) {
    var b = document.getElementById("btn-tools"), m = document.getElementById("tools-menu");
    open = open == null ? m.hidden : open;
    m.hidden = !open; b.setAttribute("aria-expanded", String(open));
    if (open) m.querySelector("a").focus();
  }

  document.addEventListener("click", function (ev) {
    var el = ev.target.closest("[data-act]");
    if (!el) {
      if (!ev.target.closest(".menu")) toggleMenu(false);
      return;
    }
    var act = el.getAttribute("data-act"), s;
    switch (act) {
      case "ck": {
        var rid = el.getAttribute("data-rid");
        ui.expanded[rid] = !ui.expanded[rid];
        drawNow();
        break;
      }
      case "mode": readForm(); ui.form.mode = el.getAttribute("data-mode"); ui.formError = ""; drawNow(); break;
      case "new": case "home":
        ev.preventDefault(); toggleMenu(false); history.pushState(null, "", location.pathname); reset(); loadIdle(); drawNow();
        var tgt = document.querySelector('#form input[name="target"]'); if (tgt) tgt.focus();
        break;
      case "theme": {
        var r = document.documentElement;
        setTheme(!(r.classList.contains("dark") || (!r.classList.contains("light") && matchMedia("(prefers-color-scheme: dark)").matches)));
        break;
      }
      case "lang": readForm(); ui.lang = ui.lang === "ko" ? "en" : "ko"; LS.set("ds-lang", ui.lang); drawNow(); break;
      case "tools": toggleMenu(); break;
      case "open-job": ev.preventDefault(); history.pushState(null, "", "?job=" + encodeURIComponent(el.getAttribute("data-job"))); route(); break;
      case "open-replay": ev.preventDefault(); history.pushState(null, "", "?replay=" + encodeURIComponent(el.getAttribute("data-replay"))); route(); break;
      case "replay-again": history.replaceState(null, "", "?replay=" + encodeURIComponent(ui.replay)); route(); break;
      case "reconnect": ui.conn = "retry"; retries = 0; connect(); draw(); break;
      case "again":
        if (ui.replay) { history.replaceState(null, "", "?replay=" + encodeURIComponent(ui.replay)); route(); }
        else if (request) { var rq = request; reset(); history.pushState(null, "", location.pathname); start(rq); }
        break;
      case "md": s = state(); download(((s.target || {}).process_name || "diagnosis") + "." + ui.lang + ".md", L(s.verdict.human_summary, ui.lang), "text/markdown"); break;
      case "json": s = state(); download(((s.target || {}).process_name || "diagnosis") + ".json", JSON.stringify(s.verdict.result, null, 2), "application/json"); break;
      case "copy": {
        s = state();
        var V = viewOf(s, ui.lang);
        copyText(V ? tr(ui.lang, "verdict_prefix") + ": " + V.verdict_word + "\n" + stripTags(V.conclusion_html) : (s.verdict.result || {}).summary || "");
        break;
      }
      default: break;
    }
  });
  document.addEventListener("submit", function (ev) {
    if (ev.target.id !== "form") return;
    ev.preventDefault();
    var f = readForm();
    if (!f.target) { ui.formError = tr(ui.lang, "need_target"); drawNow(); document.querySelector('#form input[name="target"]').focus(); return; }
    if (f.mode === "ssh" && !f.remote_host) { ui.formError = tr(ui.lang, "need_host"); drawNow(); return; }
    start(Object.assign({}, f));
  });
  document.addEventListener("input", function (ev) { if (ev.target.name && ev.target.closest("#form")) ui.form[ev.target.name] = ev.target.value; });
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") { var m = document.getElementById("tools-menu"); if (!m.hidden) { toggleMenu(false); document.getElementById("btn-tools").focus(); } }
    if ((ev.key === "ArrowDown" || ev.key === "ArrowUp") && ev.target.closest("#tools-menu")) {
      var items = Array.prototype.slice.call(document.querySelectorAll("#tools-menu a")), i = items.indexOf(ev.target);
      items[(i + (ev.key === "ArrowDown" ? 1 : items.length - 1)) % items.length].focus(); ev.preventDefault();
    }
  });
  window.addEventListener("popstate", route);
  route();
})(typeof window !== "undefined" ? window : globalThis);
