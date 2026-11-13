/* Exploration mock: renders the finished diagnosis screen of the live UI plus the proposed Process profile card,
   related-information chips and the Watch card, from canned data (explore-data.js). One column; rows open their
   detail in place; nothing above an opened row moves. Mock only: no network, no server. */
(function () {
  "use strict";
  var D = window.EXPLORE_DATA, CK = D.CK, CASES = D.CASES;
  var Q = new URLSearchParams(location.search);
  var ICON = { PASS: "✔", FAIL: "✖", INCONCLUSIVE: "?", SKIPPED: "–" };
  var TONE = { PASS: "pass", FAIL: "fail", INCONCLUSIVE: "warn", SKIPPED: "skip" };
  var ROW_SRC = {
    threads: ["스레드 표본", "thread samples"], memory: ["/proc/pid/smaps · maps", "/proc/pid/smaps · maps"], locks: ["뮤텍스 값 + 스레드 표본", "mutex values + thread samples"],
    files: ["/proc/pid/fd", "/proc/pid/fd"], modules: ["/proc/pid/maps · ELF", "/proc/pid/maps · ELF"], vars: ["DWARF .debug_info", "DWARF .debug_info"]
  };

  var ui, C, timer = null, playing = [];

  /* ------------------------------------------------------------------ helpers */
  function L(x) { return Array.isArray(x) ? (ui.lang === "en" ? x[1] : x[0]) : (x == null ? "" : x); }
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function fmtN(n) { return typeof n === "number" ? n.toLocaleString("en-US") : String(n); }
  function $(s) { return document.querySelector(s); }
  function clock(t) {
    var s = 14 * 3600 + 2 * 60 + 10 + Math.round(t * ui.obs.interval), p = function (n) { return ("0" + n).slice(-2); };
    return p(Math.floor(s / 3600)) + ":" + p(Math.floor(s / 60) % 60) + ":" + p(s % 60);
  }
  function hexa(n) { return "0x" + n.toString(16); }
  function statusIcon(st) { return '<span class="status-icon ' + st + " tone-" + TONE[st] + '" aria-hidden="true">' + ICON[st] + '</span><span class="sr-only">' + L(WORD[st]) + "</span>"; }
  var WORD = { PASS: ["통과", "Passed"], FAIL: ["이상 발견", "Found a problem"], INCONCLUSIVE: ["판단 불가", "Could not judge"], SKIPPED: ["실행 안 함", "Not run"] };
  function threadByTid(tid) {
    var P = C.profile, i, g;
    if (P.threads) for (i = 0; i < P.threads.length; i++) if (P.threads[i].tid === +tid) return P.threads[i];
    if (P.groups) for (i = 0; i < P.groups.length; i++) { g = P.groups[i];
      for (var j = 0; j < g.members.length; j++) if (g.members[j].tid === +tid) return { tid: +tid, name: g.name, st: g.members[j].st, cpu: "0%", top: g.top, frames: g.frames, locals: g.locals, holds: [], waits: null }; }
    return null;
  }
  function findVar(name) { var l = C.profile.vars.list || []; for (var i = 0; i < l.length; i++) if (l[i].name === name) return l[i]; return null; }
  function isOpen(k) { return ui.open.has(k); }
  function chev(open) { return '<span class="chev" aria-hidden="true">' + (open ? "▾" : "▸") + "</span>"; }

  /* ------------------------------------------------------------------ state */
  function freshState(caseId) {
    return { case: caseId, stage: 0, lang: ui ? ui.lang : (Q.get("lang") === "en" ? "en" : "ko"), view: "app", open: new Set(), frame: {}, from: null,
      q: null, memCount: {}, ckOpen: new Set(), chipsMore: new Set(), rangeErr: false, rangeLen: 160, still: Q.get("still") === "1",
      added: null, obs: { track: [], running: true, interval: 1, tick: 0, frozen: null, inReport: null, pool: null, gone: false, openTrack: new Set(), poolForm: false } };
  }
  function applyStage(caseId, k, live) {
    var keepLang = ui ? ui.lang : null, keepView = Q.get("view") === "report" ? "report" : "app", st;
    if (!live) { ui = freshState(caseId); if (keepLang) ui.lang = keepLang; }
    C = CASES[caseId]; ui.case = caseId;
    k = Math.max(0, Math.min(k, C.stages.length - 1)); ui.stage = k; st = C.stages[k];
    ui.open = new Set(st.open || []); ui.frame = Object.assign({}, st.frame || {}); ui.from = st.from || null;
    ui.view = st.view || (live ? "app" : keepView);
    ui.rangeErr = !!st.rangeErr;
    if (st.focus === "mem:req_handler" || ui.open.has("mem:req_handler")) ui.memCount.req_handler = 70;
    var O = ui.obs;
    if (!live) O.tick = st.ticks || 0;
    (st.track || []).forEach(function (n) { if (!O.track.some(function (x) { return x.name === n; })) O.track.push({ name: n, at: live ? O.tick : 0 }); });
    if (st.pool && !O.pool) O.pool = { at: live ? O.tick : 0, sel: null, only: null, cur: 0 };
    if (O.pool && st.poolSel != null) O.pool.sel = st.poolSel;
    if (O.pool && st.poolOnly != null) O.pool.only = st.poolOnly;
    if (st.freezeAt != null && !O.frozen) O.frozen = { t: live ? O.tick : st.freezeAt };
    (st.openTrack || []).forEach(function (n) { O.openTrack.add(n); });
    if (st.inReport) O.inReport = { t: O.tick };
    if (C.exitAt != null && O.tick >= C.exitAt) { O.gone = true; O.running = false; }
    if (st.key === "vars" && C.profile.vars.query) ui.q = C.profile.vars.query;
    if (caseId === "healthy" && st.key === "vars") ui.open.add("var:handled");
    if (caseId === "overflow" && st.key === "value") ui.q = "rb";
    if (caseId === "pool" && st.key === "vars") ui.q = "slot";
  }

  /* ------------------------------------------------------------------ cards: the live UI's finished screen */
  function header() {
    var g = C.target, O = ui.obs, live = obsActive();
    $("#tchip").hidden = false;
    $("#tchip").innerHTML = "<b>" + esc(g.name) + '</b><span class="sep">·</span><span>pid ' + g.pid + "</span>" +
      '<span class="sep opt-hide">·</span><span class="opt-hide">' + esc(g.host || g.arch) + "</span>" +
      (O.gone ? '<span class="sep">·</span><span class="gone">' + L(["대상 종료", "target exited"]) + "</span>"
        : live ? '<span class="sep">·</span><span class="watch"><i aria-hidden="true"></i>' + L(O.running ? ["관찰 중", "watching"] : ["관찰 멈춤", "watch paused"]) + "</span>" : "");
    $("#btn-lang").textContent = ui.lang === "en" ? "EN" : "KO";
    document.documentElement.lang = ui.lang;
    document.body.classList.toggle("report", ui.view === "report");
  }
  function masthead() {
    var g = C.target;
    return '<section class="card masthead" id="masthead"><h1>' + L(["dynamicState 무정지 런타임 인시던트 보고서", "dynamicState zero-stop runtime incident report"]) + "</h1>" +
      '<div class="meta"><code>' + esc(g.name) + "</code><span>pid " + g.pid + "</span><span>·</span><span>" + g.arch + "</span><span>·</span><span>" +
      L(["생성 2026-11-13 14:02 KST", "generated 2026-11-13 14:02 KST"]) + "</span><span>·</span><span>schema 1.3</span></div>" +
      '<nav><a href="#profile">' + L(["프로세스 프로필", "Process profile"]) + '</a><a href="#findings">' + L(["발견된 문제", "Findings"]) + '</a><a href="#checks">' +
      L(["검사", "Checks"]) + '</a><a href="#next">' + L(["다음에 할 일", "Next steps"]) + "</a>" + (ui.obs.inReport ? '<a href="#obs-report">' + L(["추가 관찰", "Additional observation"]) + "</a>" : "") + "</nav></section>";
  }
  function banner() {
    var v = C.verdict;
    return '<section class="card card-tone banner tone-' + v.tone + '" id="banner"><div class="card-content"><div class="line1"><span class="badge badge-tone badge-lg">' +
      L(["판정", "Verdict"]) + ": " + L(v.word) + '</span><span class="phase"><code>' + v.code + "</code> · " + L(v.mean) + '</span><span class="elapsed">' + L(v.dur) + "</span></div>" +
      '<p class="sum">' + L(v.sum) + '</p><a class="detail-link" href="#banner">' + L(["판정 근거 상세 기록", "Verdict detail record"]) + " ↗</a></div></section>";
  }
  function tiles() {
    var t = C.tiles, v = C.verdict, den = t.fail + t.inc + t.pass || 1;
    function tile(k, val, sub, extra) { return '<div class="card tile"><div class="k">' + L(k) + '</div><div class="v">' + val + "</div>" + (extra || "") + '<div class="s">' + sub + "</div></div>"; }
    var bar = '<div class="progress-stack" aria-hidden="true"><i class="s-FAIL" style="width:' + (100 * t.fail / den).toFixed(1) + '%"></i><i class="s-INCONCLUSIVE" style="width:' +
      (100 * t.inc / den).toFixed(1) + '%"></i><i class="s-PASS" style="width:' + (100 * t.pass / den).toFixed(1) + '%"></i></div>';
    return '<div class="tiles" id="tiles">' + tile(["검사", "Checks"], t.ran, "✖ " + t.fail + " · ? " + t.inc + " · ✔ " + t.pass + " · – " + t.skip, bar) +
      tile(["대상 정지 시간", "Target stop time"], v.stop, L(["한 번도 멈추지 않음", "never stopped"])) +
      tile(["읽은 데이터", "Data read"], v.bytes, L(C.target.transport)) + tile(["소요 시간", "Duration"], L(v.dur), "") + "</div>";
  }
  function kv(k, v) { return "<div><dt>" + L(k) + '</dt><dd title="' + esc(v) + '">' + esc(v) + "</dd></div>"; }
  function target() {
    var g = C.target;
    return '<section class="card" id="target"><div class="card-header"><h2 class="card-title">' + L(["대상", "Target"]) + '</h2><span class="card-description">' +
      L(["연결됨 · 읽기 전용", "connected · read-only"]) + '</span></div><div class="card-content"><dl class="kv">' +
      kv(["프로세스", "Process"], g.name + " · pid " + g.pid + " · threads " + g.threads) + kv(["아키텍처", "Architecture"], g.arch + " · " + g.libc) +
      kv(["실행 파일", "Executable"], g.exe) + kv(["Build ID", "Build ID"], g.buildid) + kv(["디버그 정보", "Debug info"], L(g.debug)) + kv(["전송", "Transport"], L(g.transport)) +
      "</dl>" + (C.illustrative ? '<p class="impact" style="margin-top:8px">' + L(C.illustrative) + "</p>" : "") + "</div></section>";
  }

  /* ------------------------------------------------------------------ the new Process profile card */
  function profile() {
    var P = C.profile, s = P.sum;
    function fig(v, k) { return "<div><b>" + v + "</b>" + L(k) + "</div>"; }
    var rows = [
      ["threads", ["스레드", "Threads"], L(P.threadsLine), threadsDetail],
      ["memory", ["메모리", "Memory"], L(P.memory.line), memoryDetail],
      ["locks", ["락", "Locks"], L(P.locks.line), locksDetail],
      ["files", ["파일·자원", "Files"], L(P.files.line), filesDetail],
      ["modules", ["모듈", "Modules"], L(P.modules.line), modulesDetail],
      ["vars", ["변수", "Variables"], L(P.vars.line), varsDetail]
    ];
    return '<section class="card" id="profile" aria-labelledby="h-profile"><div class="card-header"><h2 class="card-title" id="h-profile">' +
      L(["프로세스 프로필", "Process profile"]) + '</h2><span class="card-description">' + L(P.window) + '</span><span class="right">' +
      L(["줄을 누르면 그 자리에서 펼쳐집니다", "Rows open in place"]) + '</span></div><div class="card-content">' +
      '<div class="pf-sum">' + fig(s.threads, ["스레드", "threads"]) + fig(s.rss, ["RSS", "RSS"]) + fig(s.heap, ["힙", "heap"]) + fig(s.fds, ["열린 파일", "open files"]) + "</div>" +
      '<ul class="rows">' + rows.map(function (r) {
        var key = "pf:" + r[0], open = isOpen(key), dis = r[0] === "vars" && P.vars.disabled && false;
        return '<li><button type="button" class="row-btn" data-act="tog" data-key="' + key + '" aria-expanded="' + open + '"' + (dis ? ' aria-disabled="true"' : "") + ">" +
          '<span class="k">' + L(r[1]) + '</span><span class="v">' + r[2] + '</span><span class="src">' + L(ROW_SRC[r[0]]) + "</span>" + chev(open) + "</button>" +
          (open ? '<div class="dt-in" id="dt-' + r[0] + '">' + r[3]() + "</div>" : "") + "</li>";
      }).join("") + "</ul>" +
      '<p class="impact unseen" style="margin-top:10px">' + L(["관측하지 않음: 스레드별 CPU 추세, 소켓 상대방별 트래픽, 스레드별 메모리, 커널 안의 대기 원인 (무정지 읽기로 얻지 않음).",
        "Not observed: per-thread CPU trends, per-peer socket traffic, per-thread memory, in-kernel wait causes (not available from zero-stop reads)."]) + "</p>" +
      "</div></section>";
  }
  function backLink() {
    if (!ui.from) return "";
    var lbl = ui.from === "checks" ? ["← 검사로 돌아가기", "← Back to the checks"] : ["← 발견 1로 돌아가기", "← Back to finding 1"];
    return '<div class="dt-actions"><button type="button" class="btn btn-ghost btn-sm backlink" data-act="back">' + L(lbl) + "</button></div>";
  }
  function threadRow(t, hotTag) {
    var key = "th:" + t.tid, open = isOpen(key);
    return '<li><button type="button" class="row-btn" data-act="tog" data-key="' + key + '" aria-expanded="' + open + '"><span class="w">' + esc(t.name) +
      '</span><span class="n">' + t.tid + '</span><span class="st">' + t.st + '</span><span class="v mono">' + esc(t.top[0]) + " · " + esc(t.top[1]) +
      (t.waits ? " · " + L(["락 ", "lock "]) + esc(t.waits) + L([" 대기", " wait"]) : "") + "</span>" +
      (t.hot && hotTag ? '<span class="badge badge-outline">' + L(["발견 1", "finding 1"]) + "</span>" : "") + '<span class="src">CPU ' + t.cpu + "</span>" + chev(open) + "</button>" +
      (open ? '<div class="dt-in">' + threadDetail(t) + "</div>" : "") + "</li>";
  }
  function threadsDetail() {
    var P = C.profile, h = "";
    if (P.groups) {
      h += '<p class="dt-note">' + L(["301개를 (이름, 맨 위 위치)로 묶었습니다. 같은 묶음은 같은 스택이므로 스택을 한 번만 보입니다.", "301 threads grouped by (name, top frame). A group shares one stack, shown once."]) + "</p>";
      h += '<ul class="rows">' + P.groups.map(function (g) {
        var key = "grp:" + g.name, open = isOpen(key);
        return '<li><button type="button" class="row-btn" data-act="tog" data-key="' + key + '" aria-expanded="' + open + '"><span class="w">' + esc(g.name) + " × " + g.n +
          '</span><span class="v mono">' + esc(g.top[0]) + " · " + esc(g.top[1]) + '</span><span class="src">' + L(g.st) + "</span>" + chev(open) + "</button>" +
          (open ? '<div class="dt-in">' + groupDetail(g) + "</div>" : "") + "</li>";
      }).join("") + "</ul>";
      return h + backLink();
    }
    h += '<ul class="rows">' + P.threads.map(function (t) { return threadRow(t, true); }).join("") + "</ul>";
    h += '<p class="dt-note">' + L(["상태 열은 표본 5회의 상태(R 실행, S 대기). 행을 누르면 그 스레드의 스택을 한 번 다시 읽습니다.", "State column: 5 samples (R running, S sleeping). A row re-reads that thread's stack once."]) + "</p>";
    return h + backLink();
  }
  function groupDetail(g) {
    var shown = ui.memCount[g.name] || 20, mem = g.members.slice(0, shown), more = g.members.length - mem.length;
    var fake = { tid: "grp:" + g.name, name: g.name, frames: g.frames, locals: g.locals, holds: [], waits: null };
    var h = threadDetail(fake, ["구성원마다 지역 변수 값은 다를 수 있습니다. 구성원을 눌러 개별로 읽으세요.", "Locals may differ per member; open a member to read it."]);
    if (g.n > 1) {
      h += "<h4>" + L(["구성원", "Members"]) + " " + g.n + '</h4><div class="search"><input class="input mono addr" placeholder="' + L(["tid로 거르기", "filter by tid"]) + '" aria-label="tid"></div>' +
        '<div class="mem-grid">' + mem.map(function (m) {
          var key = "th:" + m.tid, open = isOpen(key);
          return '<button type="button" class="row-btn" data-act="tog" data-key="' + key + '" aria-expanded="' + open + '"><span class="n">' + m.tid + '</span><span class="st">' + m.st + "</span>" + chev(open) + "</button>";
        }).join("") + "</div>" + mem.filter(function (m) { return isOpen("th:" + m.tid); }).map(function (m) {
          return "<h4>" + esc(g.name) + " " + m.tid + '</h4><div class="dt-in">' + threadDetail(threadByTid(m.tid)) + "</div>"; }).join("") +
        (more > 0 ? '<div class="dt-actions"><button type="button" class="btn btn-outline btn-sm" data-act="more" data-grp="' + esc(g.name) + '" data-key="mem:' + esc(g.name) + '">' +
          L(["" + more + "개 더 (50개씩)", "" + more + " more (50 at a time)"]) + '</button><span class="dt-note">' + L(["목록은 진단 표본에서 · 스택은 누를 때 읽음", "list from the diagnosis samples · stacks read on open"]) + "</span></div>" : "");
    }
    return h;
  }
  function threadDetail(t, note) {
    var sel = ui.frame[t.tid] != null ? ui.frame[t.tid] : (t.frames.length > 2 ? 2 : 0), nodbg = C.profile.nodebug;
    var stack = '<ol class="stack" aria-label="' + L(["호출 스택", "call stack"]) + '">' + t.frames.map(function (f, i) {
      return '<li class="' + (f[2] ? "" : "nodbg") + '"><button type="button" data-act="frame" data-tid="' + t.tid + '" data-i="' + i + '" data-key="fr:' + t.tid + ":" + i + '" aria-current="' + (i === sel) + '">' +
        '<span class="i">#' + i + '</span><span class="fn">' + esc(f[0]) + '</span><span class="loc">' + esc(f[2] || f[1]) + "</span></button></li>";
    }).join("") + "</ol>";
    var fr = t.frames[sel], loc = t.locals && t.locals[sel], right;
    if (loc) right = '<dl class="locals">' + loc.map(function (l) { return "<dt>" + esc(l[0]) + '</dt><dd class="ty">' + esc(l[1]) + "</dd><dd>" + esc(l[2]) + "</dd>"; }).join("") + "</dl>";
    else right = '<p class="dt-note">' + (nodbg ? L(["지역 변수 없음: 디버그 정보가 없어 프레임 배치를 모릅니다.", "No locals: without debug info the frame layout is unknown."])
      : fr[2] ? L(["이 프레임에는 지역 변수가 없습니다.", "This frame has no locals."]) : L(["지역 변수 없음: " + fr[1] + " 은(는) 심볼만 있습니다.", "No locals: " + fr[1] + " has symbols only."])) + "</p>";
    var lk = "";
    if (t.holds && t.holds.length || t.waits) {
      lk = "<h4>" + L(["락", "Locks"]) + '</h4><ul class="ul">' + (t.holds || []).map(function (n) { return "<li>" + L(["잡고 있음 ", "holds "]) + '<button type="button" class="btn btn-ghost btn-sm" data-act="goto-lock" data-name="' + n + '"><code>' + n + "</code></button></li>"; }).join("") +
        (t.waits ? "<li>" + L(["기다림 ", "waits for "]) + '<button type="button" class="btn btn-ghost btn-sm" data-act="goto-lock" data-name="' + t.waits + '"><code>' + t.waits + "</code></button> " +
          L(["(소유자 ", "(owner "]) + esc(ownerName(t.waits)) + ")</li>" : "") + "</ul>";
    }
    return '<div class="split"><div><h4 style="margin-top:0">' + L(["호출 스택", "Call stack"]) + "</h4>" + stack + "</div><div><h4 style=\"margin-top:0\">" +
      L(["지역 변수", "Locals"]) + " · <span class=\"mono\">#" + sel + " " + esc(fr[0]) + "</span></h4>" + right + lk + "</div></div>" +
      (note ? '<p class="dt-note">' + L(note) + "</p>" : "") +
      '<p class="dt-note">' + L(["읽음 14:02:31 · 스택 1회, 스레드 정지 없음 (레지스터는 /proc/pid/task/tid/syscall, 스택은 process_vm_readv)", "read 14:02:31 · once, no thread stopped (registers via /proc/pid/task/tid/syscall, stack via process_vm_readv)"]) + "</p>";
  }
  function ownerName(lock) { var l = (C.profile.locks.list || []).filter(function (x) { return x.name === lock; })[0]; var t = l && threadByTid(l.owner); return t ? t.name + " " + t.tid : "?"; }

  function memoryDetail() {
    var M = C.profile.memory, tot = M.cats.reduce(function (a, c) { return a + c[1]; }, 0), h = "";
    h += "<h4 style=\"margin-top:0\">" + L(["주소 공간 구성 (상주 메모리 기준)", "Address space (resident)"]) + '</h4><div class="progress-stack addr-bar" aria-hidden="true">' + M.cats.map(function (c) {
      return '<i class="m' + c[2] + '" style="width:' + (100 * c[1] / tot).toFixed(1) + '%"></i>'; }).join("") + '</div><div class="legend">' + M.cats.map(function (c) {
      return '<span><i class="m' + c[2] + '"></i>' + L(c[0]) + " " + fmtN(c[1]) + " KiB</span>"; }).join("") + "</div>";
    var open = isOpen("maps");
    h += '<ul class="rows"><li><button type="button" class="row-btn" data-act="tog" data-key="maps" aria-expanded="' + open + '"><span class="k">' + L(["매핑 목록", "Mappings"]) +
      '</span><span class="v">' + (M.maps.length + M.more) + L(["개 · 주소, 권한, 크기, 종류", " · address, permissions, size, kind"]) + "</span>" + chev(open) + "</button>" +
      (open ? '<div class="dt-in">' + mapsTable(M) + "</div>" : "") + "</li>" +
      '<li><button type="button" class="row-btn" data-act="tog" data-key="range" aria-expanded="' + isOpen("range") + '"><span class="k">' + L(["범위 읽기", "Read a range"]) +
      '</span><span class="v">' + L(["주소를 입력하거나 매핑·변수에서 고르면 그 범위만 한 번 읽습니다 (최대 4 KiB)", "type an address or pick a mapping/variable: that range is read once (max 4 KiB)"]) + "</span>" + chev(isOpen("range")) + "</button>" +
      (isOpen("range") ? '<div class="dt-in">' + rangeView() + "</div>" : "") + "</li></ul>";
    return h;
  }
  function mapsTable(M) {
    var rg = C.profile.range;
    return '<div class="scroll-x"><table class="table compact"><thead><tr><th>' + L(["시작", "start"]) + "</th><th>" + L(["끝", "end"]) + "</th><th>" + L(["권한", "perm"]) +
      '</th><th class="num">' + L(["크기", "size"]) + "</th><th>" + L(["종류 · 경로", "kind · path"]) + "</th><th></th></tr></thead><tbody>" + M.maps.map(function (m) {
        var can = !!m[6];
        return '<tr><td class="mono">' + m[0] + '</td><td class="mono">' + m[1] + '</td><td class="mono">' + m[2] + '</td><td class="num">' + m[3] +
          '</td><td><span class="legend" style="display:inline"><i class="m' + m[4] + '"></i></span><span class="mono">' + esc(L(m[5])) + "</span></td><td>" +
          (can ? '<button type="button" class="btn btn-outline btn-sm" data-act="map-read">' + L(["범위 읽기", "Read"]) + "</button>" : "") + "</td></tr>";
      }).join("") + '<tr><td colspan="6" class="dt-note">' + L(["그 밖의 매핑 " + M.more + "개 · 전부 보기", M.more + " more mappings · show all"]) + "</td></tr></tbody></table></div>" +
      (rg ? "" : '<p class="dt-note">' + L(["이 사례의 목업에는 범위 데이터가 없습니다.", "No range data in this mock case."]) + "</p>");
  }
  function rangeView() {
    var R = C.profile.range;
    if (!R) return '<p class="dt-note">' + L(["주소를 입력해 읽기 (이 사례의 목업에는 데이터 없음)", "Type an address (no data in this mock case)"]) + "</p>";
    var h = '<div class="search"><input class="input mono addr" value="' + hexa(R.base) + '" aria-label="' + L(["주소", "address"]) + '">' +
      '<select class="input" aria-label="' + L(["길이", "length"]) + '"><option>64 B</option><option' + (R.len === 160 ? " selected" : "") + ">160 B</option><option>256 B</option><option>4 KiB</option></select>" +
      '<button type="button" class="btn btn-outline btn-sm" data-act="reread">' + L(["다시 읽기", "Re-read"]) + "</button>" +
      '<button type="button" class="btn btn-outline btn-sm" data-act="track" data-name="' + (C.profile.range.raw ? "0x55d0e3a3c040 (u64)" : "chunk(aux).size") + '">' + L(["추적에 추가", "Add to watch"]) + "</button></div>";
    if (ui.rangeErr) h += '<div class="alert alert-tone tone-fail" role="alert">' + L(["다시 읽기 실패: 대상이 종료되었습니다 (pid 812 없음, ESRCH). 아래는 14:07:28에 읽은 값입니다.", "Re-read failed: the target exited (pid 812 gone, ESRCH). Below: the values read at 14:07:28."]) + "</div>";
    h += '<p class="dt-note">' + hexa(R.base) + " … " + hexa(R.base + R.len) + " · " + R.len + " B · " + L(["한 번 읽음 14:02:31 (process_vm_readv 1회, 대상 정지 없음)", "read once 14:02:31 (one process_vm_readv, no stop)"]) + "</p>";
    var rows = "", i, j, b = R.bytes;
    function cls(off) { for (var k = 0; k < R.marks.length; k++) if (off >= R.marks[k][0] && off < R.marks[k][1]) return R.marks[k][2]; return ""; }
    function tagAt(o) { var out = []; R.marks.forEach(function (m) { if (m[0] >= o && m[0] < o + 16 && L(m[3])) out.push(L(m[3])); }); return out.join(" · "); }
    for (i = 0; i < R.len; i += 16) {
      var bs = "", as = "";
      for (j = i; j < i + 16; j++) { var c = cls(j); bs += "<span" + (c ? ' class="' + c + '"' : "") + ">" + ("0" + b[j].toString(16)).slice(-2) + "</span>"; as += b[j] >= 32 && b[j] < 127 ? esc(String.fromCharCode(b[j])) : "."; }
      rows += '<div class="r"><span class="o">' + hexa(R.base + i) + '</span><span class="bs">' + bs + '</span><span class="as">' + as + '</span><span class="tag">' + esc(tagAt(i)) + "</span></div>";
    }
    h += '<div class="hex" role="table" aria-label="' + L(["메모리 범위", "memory range"]) + '">' + rows + "</div>";
    if (!R.raw) h += '<div class="legend"><span><i class="b-hdr"></i>' + L(["청크 헤더", "chunk header"]) + '</span><span><i class="b-buf"></i>' + L(["버퍼 (사용 가능 영역)", "buffer (usable)"]) +
      '</span><span><i class="b-over"></i>' + L(["버퍼 끝을 넘은 쓰기", "written past the end"]) + "</span></div>";
    h += "<h4>" + L(R.raw ? ["원시 해석 (형식 정보 없음)", "Raw decode (no type information)"] : ["형식 해석 (DWARF + glibc 힙 배치)", "Typed decode (DWARF + glibc heap layout)"]) + "</h4>" +
      '<div class="scroll-x"><table class="table compact"><tbody>' + R.decode.map(function (d) {
        return (d[3] === "bad" ? '<tr class="hot">' : "<tr>") + '<td class="mono">' + d[0] + '</td><td class="mono">' + esc(L(d[1])) + "</td><td" + (d[3] === "bad" ? ' style="color:var(--destructive)"' : "") + ">" + esc(L(d[2])) + "</td></tr>";
      }).join("") + "</tbody></table></div>";
    h += '<div class="dt-actions"><button type="button" class="btn btn-ghost btn-sm">' + L(["← 이전 160 B", "← previous 160 B"]) + '</button><button type="button" class="btn btn-ghost btn-sm">' + L(["다음 160 B →", "next 160 B →"]) + "</button></div>";
    return h + backLink();
  }
  function locksDetail() {
    var K = C.profile.locks;
    if (K.unknown) return '<p class="dt-note">' + L(["뮤텍스가 어디 있는지 알려면 형식 정보가 필요합니다. 스레드 svc_log (tid 819)가 futex에서 기다리는 것은 보이지만, 그 futex가 어떤 락인지는 모릅니다.", "Locating mutexes needs type information. svc_log (tid 819) waits on a futex, but which lock it is cannot be told."]) + "</p>";
    if (!K.list.length) return '<p class="dt-note">' + L(["표본에서 락을 기다리거나 잡고 있는 스레드가 없었습니다. 전역 뮤텍스는 변수 검색으로 볼 수 있습니다.", "No thread held or waited on a lock in the samples. Global mutexes can be found via variable search."]) + "</p>";
    return '<ul class="rows">' + K.list.map(function (l) {
      var key = "lk:" + l.name, open = isOpen(key), own = threadByTid(l.owner);
      return '<li><button type="button" class="row-btn" data-act="tog" data-key="' + key + '" aria-expanded="' + open + '"><span class="w">' + l.name + '</span><span class="v">' +
        (own ? L(["소유자 ", "owner "]) + own.name + " " + own.tid : L(["소유자 없음", "unowned"])) + " · " + L(["대기 ", "waiters "]) + l.waiters.length + '</span><span class="src mono">' + l.type + " · " + l.decl + "</span>" + chev(open) + "</button>" +
        (open ? '<div class="dt-in">' + lockDetail(l) + "</div>" : "") + "</li>";
    }).join("") + "</ul>" + backLink();
  }
  function lockDetail(l) {
    var own = threadByTid(l.owner);
    function who(t, role) { return "<tr><td>" + L(role) + '</td><td><button type="button" class="lnk" data-act="goto-thread" data-tid="' + t.tid + '">' + esc(t.name) + " " + t.tid + '</button></td><td class="mono">' +
      esc(t.frames[2] ? t.frames[2][0] + " · " + (t.frames[2][2] || "") : t.top.join(" · ")) + '</td><td class="mono">' + esc(t.frames[0][0]) + "</td></tr>"; }
    return '<div class="scroll-x"><table class="table compact"><thead><tr><th></th><th>' + L(["스레드", "thread"]) + "</th><th>" + L(["멈춘 곳", "stopped at"]) + "</th><th>" + L(["맨 위 프레임", "top frame"]) + "</th></tr></thead><tbody>" +
      (own ? who(own, ["소유자", "owner"]) : "") + l.waiters.map(function (w) { return who(threadByTid(w), ["대기", "waiter"]); }).join("") + "</tbody></table></div>" +
      '<p class="dt-note mono">' + l.name + " @ 0x" + l.addr + " · __lock = " + l.lockw + (l.lockw === "2" ? L(["  (잠김, 대기자 있음)", "  (locked, has waiters)"]) : "") + " · __owner = " + l.owner + "</p>" +
      '<div class="dt-actions"><button type="button" class="btn btn-outline btn-sm" data-act="track" data-name="' + l.name + '">' + L(["소유자 추적", "Watch owner"]) + "</button>" + addedNote(l.name) + "</div>";
  }
  function filesDetail() {
    var F = C.profile.files;
    return '<table class="table compact"><thead><tr><th>fd</th><th>' + L(["종류", "kind"]) + "</th><th>" + L(["대상", "target"]) + "</th></tr></thead><tbody>" +
      F.list.map(function (f) { return '<tr><td class="mono">' + f[0] + "</td><td>" + f[1] + '</td><td class="mono">' + esc(L(f[2])) + "</td></tr>"; }).join("") + "</tbody></table>";
  }
  function modulesDetail() {
    var M = C.profile.modules;
    return '<table class="table compact"><thead><tr><th>' + L(["모듈", "module"]) + "</th><th>" + L(["기준 주소", "base"]) + "</th><th>" + L(["디버그 정보", "debug info"]) + "</th></tr></thead><tbody>" +
      M.list.map(function (m) { return '<tr><td class="mono">' + m[0] + '</td><td class="mono">0x' + m[1] + "</td><td>" + L(m[2]) + "</td></tr>"; }).join("") + "</tbody></table>";
  }
  function varsDetail() {
    var V = C.profile.vars;
    if (V.disabled) return '<div class="search"><input class="input mono" disabled placeholder="' + L(["전역·정적 변수 이름", "global/static name"]) + '" aria-label="' + L(["변수 검색", "variable search"]) + '">' +
      '<button type="button" class="btn btn-outline btn-sm" disabled>' + L(["검색", "Search"]) + "</button></div>" +
      '<div class="alert alert-tone tone-warn" role="note"><div><b>' + L(["변수를 검색할 수 없습니다: 디버그 정보가 없습니다.", "Variables cannot be searched: no debug information."]) + "</b><br>" +
      L(["svc_main 은 strip 되어 DWARF도 심볼 테이블도 없습니다. 같은 Build ID(e44b07c1…c805)의 디버그 ELF를 '디버그 ELF 경로'로 지정해 다시 진단하면 열립니다. 그동안에는 '메모리 → 범위 읽기'로 주소를 읽을 수 있습니다.",
        "svc_main is stripped (no DWARF, no symbol table). Give the debug ELF with the same Build ID (e44b07c1…c805) as Debug ELF path and run again. Meanwhile Memory → Read a range works by address."]) + "</div></div>";
    var q = ui.q == null ? V.query : ui.q;
    var res = V.list.filter(function (v) { return !v.hidden && (!q || v.name.indexOf(q) >= 0); });
    var h = '<div class="search"><input class="input mono" data-act="q" data-key="q" value="' + esc(q) + '" placeholder="' + L(["전역·정적 변수 이름 (일부만 써도 됨)", "global/static name (substring)"]) + '" aria-label="' + L(["변수 검색", "variable search"]) + '">' +
      '<span class="dt-note">' + L(["실행 파일의 DWARF에서 찾음 · 대상을 읽지 않음", "searched in the executable's DWARF · no target read"]) + "</span></div>";
    if (!V.list.length) return h + '<p class="dt-note">' + L(["이 실행 파일에는 전역·정적 변수가 없습니다.", "This executable has no globals or statics."]) + "</p>";
    h += '<div class="scroll-x"><table class="table compact"><thead><tr><th>' + L(["이름", "name"]) + "</th><th>" + L(["형식", "type"]) + '</th><th class="num">' + L(["크기", "size"]) + "</th><th>" + L(["위치", "where"]) + "</th><th></th></tr></thead><tbody>" +
      (res.length ? res.map(function (v) {
        var open = isOpen("var:" + v.name);
        return "<tr" + (open ? ' aria-current="true"' : "") + '><td class="mono">' + v.name + '</td><td class="mono">' + esc(v.type) + '</td><td class="num">' + v.size + '</td><td class="mono nw">' + esc(L(v.sect)) + " · " + v.decl +
          '</td><td class="nw"><button type="button" class="btn btn-outline btn-sm" data-act="tog" data-key="var:' + v.name + '" aria-expanded="' + open + '">' + L(["값 보기", "Show value"]) + "</button> " +
          (v.kind === "pool" ? '<button type="button" class="btn btn-outline btn-sm" data-act="pool-go">' + L(["풀로 보기", "View as pool"]) + "</button>"
            : '<button type="button" class="btn btn-ghost btn-sm" data-act="track" data-name="' + v.name + '">' + L(["추적에 추가", "Add to watch"]) + "</button>") + "</td></tr>";
      }).join("") : '<tr><td colspan="5" class="dt-note">' + L(["일치하는 변수 없음", "no match"]) + "</td></tr>") + "</tbody></table></div>";
    V.list.forEach(function (v) { if (isOpen("var:" + v.name)) h += valueView(v); });
    return h + backLink();
  }
  function valueView(v) {
    var t = ui.obs.tick, body;
    if (v.kind === "struct") body = v.name + " = (" + esc(v.type) + ") {\n" + v.fields.map(function (f) {
      var val = C.series[v.name + "." + f[0]] ? C.series[v.name + "." + f[0]](t) : f[2];
      return "  " + f[0] + " = " + val + (f[3] ? '   <button type="button" data-act="follow" data-name="' + f[3] + '">' + L(["따라가기 →", "follow →"]) + "</button>" : "") + '  <span class="c">' + esc(f[1]) + "</span>";
    }).join(",\n") + "\n}";
    else if (v.kind === "array") body = v.name + " = {" + v.elems.map(function (e) { return C.series[e[0]](t); }).join(", ") + '}   <span class="c">' + esc(v.type) + "</span>";
    else if (v.kind === "ptr") body = v.name + " = " + v.value + '   <span class="c">' + L(v.block) + '</span>   <button type="button" data-act="follow" data-name="' + v.name + '">' + L(["따라가기 →", "follow →"]) + "</button>";
    else if (v.kind === "pool") body = v.name + " = (" + v.type + ") {\n  [0] = {state = SLOT_READING, fd = 5, …},\n  [1] = {state = SLOT_FREE, fd = -1, …},\n  … " + L(["4,094개 더 · '풀로 보기'로 전체를 상태별로", "4,094 more · use View as pool"]) + "\n}";
    else if (v.kind === "num") body = v.name + " = " + C.series[v.name](t);
    else body = v.name + " = " + esc(v.value);
    return '<div><h4>' + L(["값", "Value"]) + ' · <span class="mono">' + v.name + "</span> @ 0x" + v.addr + '</h4><div class="valbox">' + body + "</div>" +
      '<div class="dt-actions" style="margin-top:6px"><span class="dt-note">' + L(["읽음 " + clock(t) + " · " + v.size + " 1회", "read " + clock(t) + " · " + v.size + " once"]) + "</span>" +
      (v.kind !== "pool" ? '<button type="button" class="btn btn-outline btn-sm" data-act="track" data-name="' + v.name + '">' + L(["추적에 추가", "Add to watch"]) + "</button>" : "") + addedNote(v.name) + "</div></div>";
  }
  function addedNote(name) {
    return ui.obs.track.some(function (x) { return x.name === name; }) ? '<a class="dt-note" href="#observe" data-act="to-obs">' + L(["관찰에 있음 ↓", "in Watch ↓"]) + "</a>" : "";
  }

  /* ------------------------------------------------------------------ findings with related-information chips */
  function chipsFor(f) {
    var out = [], seen = {};
    function add(key, lbl, kind, act, extra) { if (seen[key]) return; seen[key] = 1; out.push({ lbl: lbl, kind: kind, act: act, extra: extra || "" }); }
    f.subjects.forEach(function (s) {
      var k = s[0], n = s[1], t, v;
      if (k === "thread" && (t = threadByTid(n))) add("th" + n, t.name, ["스레드", "thread"], "goto", 'data-keys="pf:threads th:' + n + '" data-focus="th:' + n + '" data-frame="' + n + ':2"');
      else if (k === "lock") add("lk" + n, n, ["락", "lock"], "goto", 'data-keys="pf:locks lk:' + n + '" data-focus="lk:' + n + '"');
      else if (k === "variable" && (v = findVar(n))) {
        if (v.kind === "ptr") {
          add("mem" + n, L(["" + n + " 주변 메모리", "memory around " + n]), ["범위", "range"], "goto", 'data-keys="pf:memory range" data-focus="range"');
          add("trk" + n, n, ["추적", "watch"], "track", 'data-name="rb"');
        } else add("var" + n, n, ["값", "value"], "goto", 'data-keys="pf:vars var:' + n + '" data-focus="var:' + n + '" data-q="' + n + '"');
      } else if (k === "address") add("mem" + n, n, ["주변 메모리", "memory"], "goto", 'data-keys="pf:memory range" data-focus="range"');
    });
    return out;
  }
  function chipsHtml(id, chips) {
    var more = ui.chipsMore.has(id), shown = more ? chips : chips.slice(0, 4);
    return '<div class="related"><span class="lbl">' + L(["관련 정보", "Related"]) + "</span>" + shown.map(function (c) {
      return '<button type="button" class="btn btn-outline btn-sm" data-act="' + c.act + '" data-from="' + id + '" ' + c.extra + ' data-key="chip:' + esc(c.lbl) + '"><span class="kind">' + L(c.kind) + "</span> " + esc(c.lbl) + "</button>";
    }).join("") + (chips.length > 4 && !more ? '<button type="button" class="btn btn-ghost btn-sm" data-act="chips-more" data-id="' + id + '">+' + (chips.length - 4) + "</button>" : "") + "</div>";
  }
  function findings() {
    var list = C.findings, body;
    if (!list.length) body = '<p class="fnone">' + L(["이번 진단에서 발견된 문제가 없습니다.", "No problem was found in this diagnosis."]) + "</p>";
    else body = list.map(function (f) {
      var steps = '<ol class="dsv-steps">' + f.steps.map(function (s) {
        return "<li>" + L(s[0]) + ' <span class="dsv-chip dsv-chip-' + s[1] + '">' + L(s[1] === "obs" ? ["관측", "observed"] : ["재구성", "reconstructed"]) + "</span></li>"; }).join("") + "</ol>";
      var pic = f.mem ? '<div class="dsv-seq"><div>' + memPicture() + "</div><div>" + steps + "</div></div>" : steps + "<h4>" + L(["관측하는 동안 각 스레드의 상태", "Each thread while observed"]) + "</h4>" + threadsPicture();
      return '<article class="finding" id="finding-' + f.n + '"><div class="fhead"><h3>' + L(["발견 ", "Finding "]) + f.n + ": " + L(f.title) + " ( <code>" + f.cat + '</code> )</h3><span class="badge badge-tone tone-fail">' +
        L(f.status) + '</span><span class="badge badge-outline">' + L(["심각도 ", "severity "]) + L(f.sev) + "</span></div>" +
        '<div class="fbody dsv" lang="' + ui.lang + '">' + pic +
        '<p class="dsv-note">' + L(["관측 = 실행 중인 프로세스에서 직접 읽은 사실 · 재구성 = 관측된 사실에서 논리적으로 따라 나오는 것", "observed = read directly from the running process · reconstructed = follows logically from what was observed"]) + "</p>" +
        chipsHtml("finding-" + f.n, chipsFor(f)) +
        '<details class="collapsible" style="margin-top:12px"><summary>' + L(["근거", "Evidence"]) + '</summary><div class="in"><p class="dt-note">' + L(["(목업: 실제 화면의 근거 표와 같음)", "(mock: same as the live evidence table)"]) + "</p></div></details></div>" +
        '<a class="detail-link" href="#finding-' + f.n + '">' + L(["이 발견의 상세 기록 (보고서)", "This finding's detail record (report)"]) + " ↗</a></article>";
    }).join("");
    if (C.refuted) body += '<p class="text-xs text-muted" style="margin:10px 0 0">' + L(["반박된 경쟁 가설:", "Refuted competing hypotheses:"]) + " " + C.refuted.map(function (r) { return '<span class="badge badge-outline mono">' + r + "</span>"; }).join(" ") + "</p>";
    return '<section class="card" id="findings"><div class="card-header"><h2 class="card-title">' + L(["발견된 문제", "Findings"]) + '</h2><span class="card-description">' + list.length + "</span></div>" +
      '<div class="card-content">' + body + "</div></section>";
  }
  function threadsPicture() {
    var P = C.profile;
    return '<div class="dsv-scroll"><table class="dsv-tbl"><thead><tr><th>' + L(["스레드", "thread"]) + "</th><th>" + L(["표본별 상태", "per-sample state"]) + "</th><th>" + L(["머문 위치", "where"]) + "</th></tr></thead><tbody>" +
      P.threads.map(function (t) {
        return "<tr" + (t.hot ? ' class="dsv-hot"' : "") + "><td><code>" + t.name + "</code> tid " + t.tid + '</td><td><span class="dsv-smp">' + t.st.split(" ").map(function (s) { return '<i class="dsv-st-' + s + '">' + s + "</i>"; }).join("") +
          '</span></td><td class="mono" style="font-size:12px">' + t.top[1] + (t.waits ? "<br>" + L(["락 ", "lock "]) + t.waits + L([" 대기", " wait"]) : "") + "</td></tr>";
      }).join("") + "</tbody></table></div>";
  }
  function memPicture() {
    function cell(cls, b, s) { return '<div class="dsv-cell ' + cls + '"><b>' + b + "</b><small>" + s + "</small></div>"; }
    return '<div class="dsv-mem"><div class="dsv-seg"><span>' + L(["헤더", "header"]) + '</span><div class="dsv-cells">' + cell("dsv-c-hdr", "0x51", "size") + "</div></div>" +
      '<div class="dsv-seg dsv-seg-buf"><span>rb.buf · 72 B</span><div class="dsv-cells">' + cell("dsv-c-buf", "mmmm", "+0") + cell("dsv-c-buf", "mmmm", "+32") + cell("dsv-c-buf", "mmmm", "+64") + "</div></div>" +
      '<div class="dsv-wall"></div><div class="dsv-seg dsv-seg-over"><span>' + L(["넘침 24 B", "over 24 B"]) + '</span><div class="dsv-cells">' + cell("dsv-c-over", "6d6d…", "aux size") + cell("dsv-c-over", "mmmm", "aux +0") + "</div></div>" +
      '<div class="dsv-seg"><span>aux</span><div class="dsv-cells">' + cell("dsv-c-rest", "00…", "+16") + "</div></div></div>" +
      '<div class="dsv-memaxis"><span>0xabf89a76d290</span><span>0xabf89a76d330</span></div>';
  }

  /* ------------------------------------------------------------------ checks, not examined, next, report */
  var CK_CHIPS = { "스레드와 락": [["pf:threads", ["스레드", "Threads"]], ["pf:locks", ["락", "Locks"]]], "메모리 증가": [["pf:memory", ["메모리", "Memory"]]],
    "메모리 무결성": [["pf:memory", ["메모리", "Memory"]]], "프로그램 상태": [["pf:files", ["파일·자원", "Files"]], ["pf:threads", ["스레드", "Threads"]]] };
  function checks() {
    var rows = C.checks.map(function (c) {
      var d = CK[c[0]], open = ui.ckOpen.has(c[0]);
      return '<li><button type="button" class="ck-row" data-act="ck" data-rid="' + c[0] + '" data-key="ck:' + c[0] + '" aria-expanded="' + open + '">' + statusIcon(c[1]) + '<span class="nm">' + L([d[0], d[1]]) +
        '</span><span class="cat">' + L([d[2], d[3]]) + '</span><span class="ln">' + esc(L(c[2])) + '</span><span class="ms">' + c[3] + " ms</span>" + chev(open) + "</button>" +
        (open ? '<div class="dt"><p>' + esc(L(c[2])) + "</p>" + '<div class="related"><span class="lbl">' + L(["관련 정보", "Related"]) + "</span>" + (CK_CHIPS[d[2]] || []).map(function (x) {
          return '<button type="button" class="btn btn-outline btn-sm" data-act="goto" data-from="checks" data-keys="' + x[0] + '" data-focus="' + x[0] + '"><span class="kind">' + L(["프로필", "profile"]) + "</span> " + L(x[1]) + "</button>"; }).join("") +
          '</div><a class="detail-link" href="#checks">' + L(["이 검사의 상세 기록", "This check's detail record"]) + " ↗</a></div>" : "") + "</li>";
    }).join("");
    return '<section class="card" id="checks"><div class="card-header"><h2 class="card-title">' + L(["검사", "Checks"]) + '</h2><span class="card-description">' + C.checks.length + "/" + C.checks.length + L([" 완료", " done"]) +
      '</span><span class="right">' + L(["행을 누르면 그 검사의 결과만 펼쳐집니다", "Click a row to open that check only"]) + '</span></div><div class="card-content"><ul class="ck">' + rows + "</ul>" +
      '<details class="collapsible collapsible-plain skipgroup"><summary><b>' + L(["실행 안 함 ", "Not run "]) + C.tiles.skip + "</b> " + L(["정상이라는 근거가 아님", "not evidence of health"]) +
      '</summary><p class="cap">' + L(["이번 증상에 선택되지 않음 (목업에서는 생략)", "not selected for this symptom (omitted in the mock)"]) + "</p></details>" +
      '<a class="detail-link" href="#checks">' + L(["검사 범위 상세 기록", "Check scope detail record"]) + " ↗</a></div></section>";
  }
  function tail() {
    var ns = C.notseen.map(function (x) { return "<li>" + L(x[0].length > 2 ? [x[0][0], x[0][1]] : x[0]) + ' <span class="why">— ' + L(x[1]) + "</span></li>"; }).join("");
    return '<section class="card" id="notseen"><div class="card-header"><h2 class="card-title">' + L(["확인하지 못한 것", "Not examined"]) + '</h2><span class="card-description">' + C.notseen.length +
      '</span><span class="right">' + L(["정상이라는 근거가 아님", "not evidence of health"]) + '</span></div><div class="card-content"><ul class="ul">' + ns + "</ul></div></section>" +
      '<section class="card" id="next"><div class="card-header"><h2 class="card-title">' + L(["다음에 할 일", "Next steps"]) + '</h2></div><div class="card-content"><div class="prose"><p>' + L(C.next) + "</p></div></div></section>";
  }
  function reportCard() {
    var v = C.verdict, O = ui.obs;
    return '<section class="card" id="report"><div class="card-header"><h2 class="card-title">' + L(["보고서", "Report"]) + '</h2><span class="card-description">' + L(["이 화면과 같은 내용 + 부분별 상세 기록", "Same as this screen + per-part detail records"]) +
      '</span></div><div class="card-footer" style="padding-top:12px"><button type="button" class="btn" data-act="view-report">' + L(["HTML 보고서 열기", "Open HTML report"]) + '</button><button type="button" class="btn btn-outline">Markdown</button>' +
      '<button type="button" class="btn btn-outline">JSON ( <span class="mono">diagnose</span> ' + L(["결과", "result"]) + ' )</button><button type="button" class="btn btn-outline">' + L(["요약 복사", "Copy summary"]) + "</button>" +
      '<button type="button" class="btn btn-ghost">' + L(["같은 대상 다시 진단", "Diagnose again"]) + '</button></div><div class="card-content" style="padding-top:0"><p class="impact">' +
      L(["수집이 대상에 준 영향: 정지 ", "Impact on the target: stop "]) + v.stop + " · " + L(["읽기 ", "read "]) + v.bytes + " · " + L(v.dur) + " · " + L(["쓰기 없음", "no writes"]) +
      (O.inReport ? " · <b>" + L(["추가 관찰 포함 (" + clock(O.inReport.t) + " 시점)", "includes the additional observation (as of " + clock(O.inReport.t) + ")"]) + "</b>" : "") + "</p></div></section>";
  }
  function detailCard() {
    return '<section class="card" id="detail"><div class="card-header"><h2 class="card-title">' + L(["상세", "Detail"]) + '</h2><span class="card-description">' + L(["같은 진단 JSON에서 만든 부분별 기록", "per-part records from the same diagnosis JSON"]) +
      '</span></div><div class="card-content" style="display:flex;flex-direction:column;gap:8px"><details class="collapsible"><summary>' + L(["판정 근거", "Verdict basis"]) + '</summary><div class="in">…</div></details>' +
      '<details class="collapsible"><summary>' + L(["수집 방법", "Collection method"]) + '</summary><div class="in">…</div></details></div></section>';
  }

  /* ------------------------------------------------------------------ the Watch card */
  function obsActive() { return ui.obs.track.length > 0 || !!ui.obs.pool; }
  function nowT() { var O = ui.obs; return C.exitAt != null ? Math.min(O.tick, C.exitAt - 1) : O.tick; }
  var POOL_FIELDS = ["state", "fd", "peer", "rx", "tx", "last_ms"];
  function poolFrame(t) { var P = C.pool; if (!P.frames) P.frames = P.build(); return P.frames[Math.max(0, t) % P.frames.length]; }
  function lastChange(i, t) { for (var u = t; u > 0; u--) if (poolFrame(u)[i] !== poolFrame(u - 1)[i]) return u; return 0; }
  function poolField(i, f, t) {
    var st = poolFrame(t)[i], lc = lastChange(i, t);
    switch (f) {
      case "state": return C.pool.states[st].name;
      case "fd": return st === 0 ? -1 : 5 + (i * 37) % 1861;
      case "peer": return st === 0 ? "0.0.0.0:0" : "10.4." + (i >> 8) + "." + (i & 255) + ":" + (40000 + i % 20000);
      case "rx": return st === 0 ? 0 : 512 * (lc + 3) + (i % 97);
      case "tx": return st === 0 ? 0 : 256 * (lc + 1) + (i % 61);
      case "last_ms": return 81233000 + lc * 1000;
    }
  }
  function typeOf(name) {
    if (name === "chunk(aux).size") return "size_t · malloc_chunk";
    if (/^0x/.test(name)) return L(["u64 · 주소 (형식 없음)", "u64 · address (no type)"]);
    if (name === "g_slots_used") return "int";
    var v = findVar(name); return v ? v.type : "";
  }
  function mkItem(x) {
    var name = x.name, v = findVar(name), m = /^g_slots\[(\d+)\]$/.exec(name);
    var leaf = function (n, type, get) { return { name: n, type: type, get: get }; };
    var it = { name: name, at: x.at, type: m ? "struct slot" : typeOf(name) };
    if (m) it.fields = ["state", "fd", "rx", "tx", "last_ms"].map(function (f) { return leaf("." + f, f === "state" ? "enum slot_state" : "", function (t) { return poolField(+m[1], f, t); }); });
    else if (v && v.kind === "struct") it.fields = v.fields.map(function (f) { return leaf("." + f[0], f[1], function (t) { var s = C.series[name + "." + f[0]]; return s ? s(t) : f[2]; }); });
    else if (v && v.kind === "array") it.fields = v.elems.map(function (e) { return leaf(e[0].slice(name.length), e[1], function (t) { return C.series[e[0]](t); }); });
    else it.get = function (t) { var s = C.series[name]; return s ? s(t) : "—"; };
    return it;
  }
  function changes(get, from, to) { var n = 0, last = null; for (var u = from + 1; u <= to; u++) if (get(u) !== get(u - 1)) { n++; last = u; } return { n: n, last: last }; }
  function anyGet(it) { return it.get || function (t) { return it.fields.map(function (f) { return f.get(t); }).join("|"); }; }
  function spark(get, from, to, gone) {
    var a = [], u; for (u = Math.max(from, to - 29); u <= to; u++) a.push(get(u));
    var W = 110, H = 22, num = a.every(function (v) { return typeof v === "number"; });
    var flat = a.every(function (v) { return v === a[0]; });
    var cls = "spark" + (gone ? " gone" : flat ? " flat" : ""), n = a.length, step = n > 1 ? W / 29 : 0, x0 = W - step * (n - 1);
    if (num && !flat) {
      var mn = Math.min.apply(null, a), mx = Math.max.apply(null, a), pts = a.map(function (v, i) { return (x0 + i * step).toFixed(1) + "," + (H - 2 - (H - 4) * (v - mn) / (mx - mn)).toFixed(1); });
      return '<svg class="' + cls + '" viewBox="0 0 ' + W + " " + H + '" aria-hidden="true"><polygon class="ar" points="' + x0.toFixed(1) + "," + H + " " + pts.join(" ") + " " + W + "," + H + '"/><polyline class="ln" points="' + pts.join(" ") +
        '"/><circle class="pt" r="2" cx="' + pts[n - 1].split(",")[0] + '" cy="' + pts[n - 1].split(",")[1] + '"/></svg>';
    }
    var tk = ""; for (var i = 1; i < n; i++) if (a[i] !== a[i - 1]) tk += '<line class="tk" x1="' + (x0 + i * step).toFixed(1) + '" x2="' + (x0 + i * step).toFixed(1) + '" y1="4" y2="' + (H - 4) + '"/>';
    return '<svg class="' + cls + '" viewBox="0 0 ' + W + " " + H + '" aria-hidden="true"><line class="base" x1="' + x0.toFixed(1) + '" x2="' + W + '" y1="' + H / 2 + '" y2="' + H / 2 + '"/>' + tk +
      '<circle class="pt" r="2" cx="' + W + '" cy="' + H / 2 + '"/></svg>';
  }
  function trackTable(staticView) {
    var O = ui.obs, T = staticView ? O.inReport.t : nowT();
    if (!O.track.length) return '<p class="dt-note">' + L(["추적 중인 값이 없습니다. 프로필의 변수·락·범위에서 '추적에 추가'.", "Nothing tracked yet. Use Add to watch in the profile."]) + "</p>";
    var rows = O.track.map(function (x) {
      var it = mkItem(x), g = anyGet(it), ch = changes(g, it.at, T), open = O.openTrack.has(it.name), fields = "";
      if (it.fields && (open || staticView)) fields = it.fields.map(function (f) {
        var c = changes(f.get, it.at, T);
        return '<tr class="sub"><td class="mono">' + esc(f.name) + '</td><td class="mono nw">' + esc(f.type) + '</td><td class="mono num">' + esc(fmtN(f.get(T))) + "</td><td>" + spark(f.get, it.at, T, O.gone) +
          '</td><td class="num' + (c.n ? " chg" : "") + '">' + c.n + '</td><td class="mono nw">' + (c.last != null ? clock(c.last) : "—") + "</td>" + (staticView ? "" : "<td></td>") + "</tr>";
      }).join("");
      var val = it.fields ? (open || staticView ? "" : "{ " + it.fields.slice(0, 2).map(function (f) { return f.name.replace(/^\./, "") + " = " + fmtN(f.get(T)); }).join(", ") + (it.fields.length > 2 ? ", …" : "") + " }") : fmtN(it.get(T));
      return '<tr><td class="mono">' + (it.fields && !staticView ? '<button type="button" class="lnk" data-act="trk-open" data-name="' + esc(it.name) + '" aria-expanded="' + open + '" data-key="trk:' + esc(it.name) + '">' + (open ? "▾ " : "▸ ") + esc(it.name) + "</button>" : esc(it.name)) +
        '</td><td class="mono nw">' + esc(it.type) + '</td><td class="mono num">' + esc(val) + "</td><td>" + spark(g, it.at, T, O.gone) + '</td><td class="num' + (ch.n ? " chg" : "") + '">' + ch.n + '</td><td class="mono nw">' +
        (ch.last != null ? clock(ch.last) : L(["변화 없음", "unchanged"])) + "</td>" + (staticView ? "" : '<td><button type="button" class="btn btn-ghost btn-sm" data-act="untrack" data-name="' + esc(it.name) + '" aria-label="' + L(["추적 해제", "remove"]) + '">✕</button></td>') + "</tr>" + fields;
    }).join("");
    return '<div class="scroll-x"><table class="table compact"><thead><tr><th>' + L(["이름", "name"]) + "</th><th>" + L(["형식", "type"]) + '</th><th class="num">' + L(["현재 값", "current"]) + "</th><th>" + L(["최근 30회", "last 30"]) +
      '</th><th class="num">' + L(["변화", "changes"]) + "</th><th class=\"nw\">" + L(["마지막 변화", "last change"]) + "</th>" + (staticView ? "" : "<th></th>") + "</tr></thead><tbody>" + rows + "</tbody></table></div>";
  }
  function poolCounts(t) { var f = poolFrame(t), c = [0, 0, 0, 0, 0]; for (var i = 0; i < f.length; i++) c[f[i]]++; return c; }
  function poolSection(staticView) {
    var O = ui.obs, P = C.pool;
    if (!O.pool) {
      if (staticView) return "";
      return '<div class="obs-sec" id="pool-sec"><h3>' + L(["풀 보기", "Pool"]) + ' <span class="text-muted">' + L(["배열·풀의 원소를 상태 필드로 색칠", "colour an array's elements by a status field"]) + "</span></h3>" +
        (O.poolForm ? poolForm(false) : '<button type="button" class="btn btn-outline btn-sm" data-act="pool-form">' + L(["풀 보기 추가", "Add a pool view"]) + "</button>") + "</div>";
    }
    var T = staticView ? O.inReport.t : nowT(), fr = poolFrame(T), prev = poolFrame(Math.max(0, T - 1)), base = poolCounts(O.pool.at), cnt = poolCounts(T), cols = 64, i;
    var cells = "", labels = "", nchg = 0, size = P.n > 1024 ? "" : P.n > 256 ? " pool-md" : " pool-sm";
    for (i = 0; i < P.n; i++) {
      var s = P.states[fr[i]].cls;
      if (fr[i] !== prev[i]) nchg++;
      cells += '<i class="pc s' + s + (O.pool.sel === i ? " sel" : "") + (O.pool.cur === i && !staticView ? " cur" : "") + '" data-i="' + i + '"></i>';
    }
    for (i = 0; i < P.n / cols; i++) labels += "<span>" + (i % 8 === 0 ? i * cols : "") + "</span>";
    var legend = P.states.map(function (st, k) {
      var d = cnt[k] - base[k];
      return '<button type="button" data-act="pool-only" data-cls="' + st.cls + '" aria-pressed="' + (O.pool.only === st.cls) + '"><i class="pc s' + st.cls + '"></i>' + st.name + " <b>" + fmtN(cnt[k]) + "</b>" +
        (T > O.pool.at ? '<span class="d">' + (d > 0 ? "+" : "") + d + "</span>" : "") + "</button>";
    }).join("");
    var sel = "";
    if (O.pool.sel != null) {
      var e = O.pool.sel;
      sel = "<h4 style=\"margin-top:0\">" + L(["원소", "Element"]) + ' <span class="mono">g_slots[' + e + "]</span> @ " + hexa(P.base + e * P.elem) + '</h4><div class="scroll-x"><table class="table compact"><tbody>' + POOL_FIELDS.map(function (f) {
        return '<tr><td class="mono">' + f + '</td><td class="mono">' + esc(fmtN(poolField(e, f, T))) + "</td></tr>"; }).join("") + "</tbody></table></div>" +
        (staticView ? "" : '<div class="dt-actions"><span class="dt-note">' + L(["상태가 마지막으로 바뀐 표본: ", "state last changed at sample "]) + "#" + lastChange(e, T) + " (" + clock(lastChange(e, T)) + ")</span>" +
          '<button type="button" class="btn btn-outline btn-sm" data-act="track" data-name="g_slots[' + e + ']">' + L(["이 원소 추적", "Watch this element"]) + "</button>" + addedNote("g_slots[" + e + "]") + "</div>");
    }
    return '<div class="obs-sec" id="pool-sec"><h3>' + L(["풀 보기", "Pool"]) + ' <span class="text-muted mono">g_slots · 4,096 × struct slot (48 B) · state (enum slot_state)</span></h3>' +
      (staticView ? "" : poolForm(true)) +
      '<div class="pool-wrap"><div><div class="pool' + size + '" role="grid" aria-label="' + L(["풀 격자: 화살표로 이동, Enter로 선택", "pool grid: arrows move, Enter selects"]) + '" tabindex="' + (staticView ? -1 : 0) + '" data-key="pool-grid"' + (O.pool.only != null ? ' data-only="' + O.pool.only + '"' : "") +
      ' style="--cols:' + cols + '"><div class="rl" aria-hidden="true">' + labels + '</div><div class="cells" data-act="pool-cell">' + cells + "</div></div>" +
      '<div class="pool-legend">' + legend + "</div></div><div>" + (sel || '<p class="dt-note">' + L(["칸을 누르면 그 원소의 필드가 여기에 나옵니다.", "Click a cell to see that element's fields here."]) + "</p>") + "</div></div>" +
      '<p class="dt-note" style="margin-top:6px">' + L(["칸 하나 = 원소 하나 · 64개씩 한 줄 · 이번 표본에서 상태가 바뀐 칸 " + fmtN(nchg) + "개 · 범례를 누르면 그 상태만 · 숫자 옆은 관찰 시작 대비 증감 · 표본 #" + T + " (" + clock(T) + ") · 표본마다 196,608 B 한 번 읽기",
        "one cell per element · 64 per row · " + fmtN(nchg) + " cells changed state this sample · click a legend item to show only that status · deltas since the view started · sample #" + T + " (" + clock(T) + ") · one 196,608-byte read per sample"]) + "</p></div>";
  }
  function poolForm(filled) {
    var P = C.pool;
    return '<div class="obs-form" style="margin-bottom:10px"><label>' + L(["식", "expression"]) + '<input class="input mono" value="' + (filled || P ? "g_slots" : "") + '"></label><label>' + L(["개수", "count"]) +
      '<input class="input mono w-s" value="' + (filled || P ? "4096" : "") + '"></label><label>' + L(["상태 필드", "status field"]) + '<input class="input mono w-s" value="' + (filled || P ? "state" : "") + '"></label>' +
      '<button type="button" class="btn btn-outline btn-sm" data-act="pool-go">' + L(filled ? ["다시 보기", "Apply"] : ["보기", "View"]) + "</button>" +
      '<span class="dt-note">' + L(["형식에서 미리 채움: struct slot[4096], 열거형 필드 state", "prefilled from the type: struct slot[4096], enum field state"]) + "</span></div>";
  }
  function compareSection(staticView) {
    var O = ui.obs, T = staticView ? O.inReport.t : nowT();
    var head = '<div class="obs-sec" id="cmp-sec"><h3>' + L(["비교", "Compare"]) + ' <span class="text-muted">' + L(["고정한 시점 이후 바뀐 것만", "only what changed since the freeze"]) + "</span></h3>";
    if (!O.frozen) return staticView ? "" : head + '<button type="button" class="btn btn-outline btn-sm" data-act="freeze">' + L(["지금 값 고정", "Freeze now"]) + "</button></div>";
    var F = O.frozen.t, changed = [], same = 0;
    O.track.forEach(function (x) {
      var it = mkItem(x), leaves = it.fields ? it.fields.map(function (f) { return { n: it.name + f.name, get: f.get }; }) : [{ n: it.name, get: it.get }];
      leaves.forEach(function (l) { var a = l.get(F), b = l.get(T); if (a !== b) changed.push([l.n, a, b, typeof a === "number" && typeof b === "number" ? b - a : null]); else same++; });
    });
    if (O.pool) {
      var a = poolCounts(F), b = poolCounts(T);
      C.pool.states.forEach(function (st, k) { if (a[k] !== b[k]) changed.push([st.name + L([" 개수", " count"]), a[k], b[k], b[k] - a[k]]); else same++; });
      var fa = poolFrame(F), fb = poolFrame(T), n = 0; for (var i = 0; i < fa.length; i++) if (fa[i] !== fb[i]) n++;
      changed.push([L(["상태가 바뀐 칸", "cells whose state changed"]), "", fmtN(n) + " / 4,096", null]);
    }
    return head + '<p class="dt-note">' + L(["고정: 표본 #" + F + " (" + clock(F) + ") → 지금 #" + T + " (" + clock(T) + ") · 바뀜 " + changed.length + " · 그대로 " + same,
      "frozen: sample #" + F + " (" + clock(F) + ") → now #" + T + " (" + clock(T) + ") · changed " + changed.length + " · same " + same]) + "</p>" +
      (changed.length ? '<ul class="cmp">' + changed.map(function (c) {
        return '<li><span class="nm">' + esc(c[0]) + '</span><span class="was">' + esc(fmtN(c[1])) + '</span><span aria-hidden="true">→</span><span class="now">' + esc(fmtN(c[2])) + "</span>" + (c[3] != null ? '<span class="d">' + (c[3] > 0 ? "+" : "") + fmtN(c[3]) + "</span>" : "") + "</li>";
      }).join("") + "</ul>" : '<p class="dt-note">' + L(["고정 이후 바뀐 값이 없습니다.", "Nothing changed since the freeze."]) + "</p>") +
      (staticView ? "" : '<div class="dt-actions" style="margin-top:6px"><button type="button" class="btn btn-outline btn-sm" data-act="freeze">' + L(["다시 고정", "Freeze again"]) + '</button><button type="button" class="btn btn-ghost btn-sm" data-act="unfreeze">' + L(["고정 해제", "Clear"]) + "</button></div>") + "</div>";
  }
  function costLine() {
    var O = ui.obs, reads = O.track.length + (O.pool ? 1 : 0), per = reads / O.interval;
    var bytes = O.track.reduce(function (a, x) { var v = findVar(x.name); return a + (v ? parseInt(String(v.size).replace(/,/g, ""), 10) || 8 : 48); }, 0) + (O.pool ? 196608 : 0);
    var ssh = C.target.host;
    return L(["무정지 표본 추출 · 대상 정지 0 ms · 쓰기 없음 · 초당 읽기 " + per.toFixed(per % 1 ? 1 : 0) + "회, 약 " + fmtN(Math.round(bytes / O.interval)) + " B/s" + (ssh ? " · SSH 왕복 1회/표본 (약 18 ms)" : " · process_vm_readv"),
      "zero-stop sampling · target stop 0 ms · no writes · " + per.toFixed(per % 1 ? 1 : 0) + " reads/s, about " + fmtN(Math.round(bytes / O.interval)) + " B/s" + (ssh ? " · one SSH round trip per sample (~18 ms)" : " · process_vm_readv")]);
  }
  function observe() {
    var O = ui.obs;
    if (!obsActive()) return "";
    var ivs = [0.5, 1, 2, 5];
    var ctl = '<div class="obs-ctl"><div class="toggle-group" role="group" aria-label="' + L(["표본 간격", "interval"]) + '">' + ivs.map(function (v) {
      return '<button type="button" data-act="obs-int" data-v="' + v + '" aria-pressed="' + (O.interval === v) + '"' + (O.gone ? " disabled" : "") + ">" + v + L(["초", " s"]) + "</button>"; }).join("") + "</div>" +
      '<button type="button" class="btn btn-outline btn-sm" data-act="obs-pause"' + (O.gone ? " disabled" : "") + ">" + L(O.running ? ["멈춤", "Pause"] : ["계속", "Resume"]) + "</button>" +
      '<span class="grow"></span><button type="button" class="btn btn-outline btn-sm" data-act="obs-report">' + L(O.inReport ? ["보고서 갱신", "Update report"] : ["보고서에 추가", "Add to report"]) + "</button></div>" +
      '<p class="impact" style="margin-top:8px">' + costLine() + (O.inReport ? " · " + L(["보고서에 추가됨 (" + clock(O.inReport.t) + " 시점)", "added to the report (as of " + clock(O.inReport.t) + ")"]) : "") + "</p>";
    var gone = O.gone ? '<div class="alert alert-tone tone-fail" role="alert" style="margin-top:10px">' + L(["대상이 종료되었습니다 (pid 812, " + clock(C.exitAt) + "). 다음 읽기가 실패해 관찰을 멈췄습니다 (/proc/812 없음, ESRCH). 마지막 값까지 남아 있고, 보고서에 추가할 수 있습니다.",
      "The target exited (pid 812, " + clock(C.exitAt) + "). The next read failed and watching stopped (/proc/812 gone, ESRCH). Values up to the last sample are kept and can go into the report."]) + "</div>" : "";
    return '<section class="card" id="observe" aria-labelledby="h-observe"><div class="card-header"><h2 class="card-title" id="h-observe">' + L(["관찰", "Watch"]) + '</h2><span class="card-description">' +
      L(["시간에 따라 다시 읽는 것은 여기에만 있습니다", "the only place where things are re-read over time"]) + '</span><span class="right mono">' + L(["표본 #", "sample #"]) + nowT() + " · " + clock(nowT()) + '</span></div><div class="card-content">' +
      ctl + gone + '<div class="obs-sec"><h3>' + L(["추적 중", "Tracking"]) + ' <span class="text-muted">' + O.track.length + "</span></h3>" + trackTable(false) + "</div>" + poolSection(false) + compareSection(false) + "</div></section>";
  }
  function obsReport() {
    var O = ui.obs; if (!O.inReport) return "";
    var T = O.inReport.t;
    return '<section class="card" id="obs-report"><div class="card-header"><h2 class="card-title">' + L(["추가 관찰", "Additional observation"]) + '</h2><span class="card-description">' +
      L(["진단 뒤에 사용자가 추가 · 판정에 영향 없음", "added by the user after the diagnosis · does not change the verdict"]) + '</span></div><div class="card-content">' +
      '<p class="impact">' + L([clock(0) + " – " + clock(T) + " · 표본 " + T + "회 · " + O.interval + "초 간격 · 대상 정지 0 ms · 쓰기 없음", clock(0) + " – " + clock(T) + " · " + T + " samples · every " + O.interval + " s · target stop 0 ms · no writes"]) + "</p>" +
      (O.track.length ? '<div class="obs-sec"><h3>' + L(["추적한 값", "Tracked values"]) + "</h3>" + trackTable(true) + "</div>" : "") + poolSection(true) + compareSection(true) + "</div></section>";
  }

  /* ------------------------------------------------------------------ render */
  function render() {
    var a = document.activeElement, key = a && a.getAttribute && a.getAttribute("data-key");
    header();
    var html = (ui.view === "report" ? masthead() : "") + banner() + tiles() + target() + profile() + findings() + checks() + tail() +
      (ui.view === "report" ? obsReport() + detailCard() : observe() + reportCard());
    $("#main").innerHTML = html;
    if (key) { var n = document.querySelector('[data-key="' + cssq(key) + '"]'); if (n) n.focus({ preventScroll: true }); }
    mockBar();
  }
  function renderObs() {
    var n = document.getElementById("observe"); if (!n) { render(); return; }
    var a = document.activeElement, key = a && n.contains(a) && a.getAttribute("data-key");
    var tmp = document.createElement("div"); tmp.innerHTML = observe(); n.replaceWith(tmp.firstElementChild);
    header();
    if (key) { var m = document.querySelector('[data-key="' + cssq(key) + '"]'); if (m) m.focus({ preventScroll: true }); }
    document.querySelectorAll('#profile .valbox').forEach(function () { /* values in an opened value view refresh on the next full render */ });
  }
  function cssq(s) { return String(s).replace(/["\\]/g, "\\$&"); }
  function scrollToKey(key, flash) {
    var n = document.querySelector('[data-key="' + cssq(key) + '"]') || document.getElementById(key);
    if (!n) return;
    var y = n.getBoundingClientRect().top + window.scrollY - 64;
    window.scrollTo({ top: Math.max(0, y), behavior: ui.still ? "auto" : "smooth" });
    if (flash) { n.classList.remove("flash"); void n.offsetWidth; n.classList.add("flash"); }
    if (n.focus && n.tagName === "BUTTON") n.focus({ preventScroll: true });
  }

  /* ------------------------------------------------------------------ the sampling clock (canned values) */
  function restartTimer() {
    if (timer) clearInterval(timer); timer = null;
    if (ui.still || ui.view === "report") return;
    timer = setInterval(function () {
      var O = ui.obs;
      if (!obsActive() || !O.running || O.gone) return;
      O.tick++;
      if (C.exitAt != null && O.tick >= C.exitAt) { O.gone = true; O.running = false; ui.rangeErr = true; }
      renderObs();
    }, Math.round(ui.obs.interval * 1000));
  }

  /* ------------------------------------------------------------------ interaction */
  function toggle(key) { if (ui.open.has(key)) ui.open.delete(key); else ui.open.add(key); }
  function addTrack(name) {
    var O = ui.obs;
    if (!O.track.some(function (x) { return x.name === name; })) O.track.push({ name: name, at: O.tick });
    if (!O.gone) O.running = true;
  }
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest("[data-act]"); if (!b) return;
    var act = b.getAttribute("data-act"), O = ui.obs;
    if (act === "q" || act === "to-obs") { if (act === "to-obs") { ev.preventDefault(); scrollToKey("observe"); } return; }
    if (b.closest("#mock")) return;
    switch (act) {
      case "tog": toggle(b.getAttribute("data-key")); break;
      case "frame": ui.frame[b.getAttribute("data-tid")] = +b.getAttribute("data-i"); break;
      case "ck": var r = b.getAttribute("data-rid"); if (ui.ckOpen.has(r)) ui.ckOpen.delete(r); else ui.ckOpen.add(r); break;
      case "chips-more": ui.chipsMore.add(b.getAttribute("data-id")); break;
      case "goto": {
        b.getAttribute("data-keys").split(" ").forEach(function (k) { ui.open.add(k); });
        var fr = b.getAttribute("data-frame"); if (fr) ui.frame[fr.split(":")[0]] = +fr.split(":")[1];
        if (b.getAttribute("data-q")) ui.q = b.getAttribute("data-q");
        ui.from = b.getAttribute("data-from"); ui.backKey = b.getAttribute("data-key");
        render(); scrollToKey(b.getAttribute("data-focus"), true); return;
      }
      case "back": { var f = ui.from; ui.from = null; render(); scrollToKey(ui.backKey && document.querySelector('[data-key="' + cssq(ui.backKey) + '"]') ? ui.backKey : f, true); return; }
      case "goto-lock": ui.open.add("pf:locks"); ui.open.add("lk:" + b.getAttribute("data-name")); render(); scrollToKey("lk:" + b.getAttribute("data-name"), true); return;
      case "goto-thread": ui.open.add("pf:threads"); ui.open.add("th:" + b.getAttribute("data-tid")); render(); scrollToKey("th:" + b.getAttribute("data-tid"), true); return;
      case "follow": ui.open.add("pf:memory"); ui.open.add("range"); render(); scrollToKey("range", true); return;
      case "map-read": ui.open.add("range"); break;
      case "reread": if (C.exitAt != null && O.gone) ui.rangeErr = true; break;
      case "more": ui.memCount[b.getAttribute("data-grp")] = (ui.memCount[b.getAttribute("data-grp")] || 20) + 50; break;
      case "track": addTrack(b.getAttribute("data-name")); if (b.getAttribute("data-from")) { render(); restartTimer(); scrollToKey("observe", true); return; } break;
      case "untrack": O.track = O.track.filter(function (x) { return x.name !== b.getAttribute("data-name"); }); break;
      case "trk-open": var nm = b.getAttribute("data-name"); if (O.openTrack.has(nm)) O.openTrack.delete(nm); else O.openTrack.add(nm); break;
      case "obs-int": O.interval = +b.getAttribute("data-v"); restartTimer(); break;
      case "obs-pause": O.running = !O.running; break;
      case "obs-report": O.inReport = { t: nowT() }; break;
      case "freeze": O.frozen = { t: nowT() }; break;
      case "unfreeze": O.frozen = null; break;
      case "pool-form": O.poolForm = true; break;
      case "pool-go": if (C.pool) { if (!O.pool) O.pool = { at: O.tick, sel: null, only: null, cur: 0 }; O.running = !O.gone; render(); restartTimer(); scrollToKey("pool-grid", true); return; } break;
      case "pool-only": var c = +b.getAttribute("data-cls"); O.pool.only = O.pool.only === c ? null : c; break;
      case "pool-cell": { var i = ev.target.getAttribute("data-i"); if (i == null) return; O.pool.sel = +i; O.pool.cur = +i; break; }
      case "view-report": setView("report"); return;
      default: return;
    }
    render();
  });
  document.addEventListener("input", function (ev) {
    if (ev.target.getAttribute("data-act") === "q") { ui.q = ev.target.value; var pos = ev.target.selectionStart; render(); var n = document.querySelector('[data-key="q"]'); if (n) { n.focus(); n.setSelectionRange(pos, pos); } }
  });
  document.addEventListener("keydown", function (ev) {
    var g = ev.target.closest && ev.target.closest(".pool"); if (!g || !ui.obs.pool) return;
    var p = ui.obs.pool, d = { ArrowRight: 1, ArrowLeft: -1, ArrowDown: 64, ArrowUp: -64 }[ev.key];
    if (d) { p.cur = Math.max(0, Math.min(4095, p.cur + d)); ev.preventDefault(); renderObs(); }
    else if (ev.key === "Enter" || ev.key === " ") { p.sel = p.cur; ev.preventDefault(); renderObs(); }
  });

  /* ------------------------------------------------------------------ mock bar (not part of the proposal) */
  function mockBar() {
    var m = $("#mock"); if (!m) return;
    var st = C.stages[ui.stage];
    m.innerHTML = '<div class="ln"><b>' + L(["목업 사례", "Case"]) + "</b>" + D.ORDER.map(function (id) {
      return '<button type="button" class="btn btn-outline btn-sm" data-m="case" data-v="' + id + '" aria-pressed="' + (ui.case === id) + '">' + L(CASES[id].label) + "</button>"; }).join("") +
      '<button type="button" class="btn btn-ghost btn-sm" data-m="min" aria-label="' + L(["접기", "collapse"]) + '">' + (m.classList.contains("min") ? "▴" : "▾") + "</button></div>" +
      '<div class="ln"><b>' + L(["목업 단계", "Stage"]) + "</b>" + C.stages.map(function (s, i) {
        return '<button type="button" class="btn btn-outline btn-sm" data-m="stage" data-v="' + i + '" aria-pressed="' + (ui.stage === i && !playing.length) + '">' + i + " " + L(s.label) + "</button>"; }).join("") +
      '<button type="button" class="btn btn-sm" data-m="play">' + (playing.length ? "■ " + L(["정지", "Stop"]) : "▶ " + L(["재생", "Play"])) + "</button></div>" +
      '<div class="ln"><b></b><button type="button" class="btn btn-outline btn-sm" data-m="view">' + L(ui.view === "report" ? ["앱 화면 보기", "App view"] : ["보고서 보기", "Report view"]) + "</button>" +
      '<button type="button" class="btn btn-outline btn-sm" data-m="theme">' + L(["밝게/어둡게", "Light/dark"]) + '</button><button type="button" class="btn btn-outline btn-sm" data-m="lang">' + (ui.lang === "en" ? "KO" : "EN") + "</button></div>" +
      '<div class="ln cap">' + L(st.cap) + "</div>";
  }
  function setView(v) { ui.view = v; window.scrollTo(0, 0); render(); restartTimer(); syncUrl(); }
  function syncUrl() {
    var p = new URLSearchParams(location.search);
    p.set("case", ui.case); p.set("stage", String(ui.stage));
    if (ui.lang === "en") p.set("lang", "en"); else p.delete("lang");
    if (ui.view === "report") p.set("view", "report"); else p.delete("view");
    try { history.replaceState(null, "", "?" + p.toString()); } catch (e) { /* file:// in some browsers */ }
  }
  function stopPlay() { playing.forEach(clearTimeout); playing = []; }
  function go(caseId, k, opts) {
    stopPlay(); applyStage(caseId, k, false); render(); restartTimer(); syncUrl();
    var st = C.stages[ui.stage];
    if (st.focus && !(opts && opts.top)) setTimeout(function () { scrollToKey(st.focus, false); }, 0); else window.scrollTo(0, 0);
  }
  function play() {
    stopPlay(); applyStage(ui.case, 0, false); ui.still = false; render(); restartTimer(); window.scrollTo({ top: 0 });
    var t = 2600;
    C.stages.forEach(function (st, i) {
      if (i === 0) return;
      if (st.from) {
        playing.push(setTimeout(function () { var c = document.querySelector('[data-act="goto"][data-focus="' + cssq(st.focus) + '"]'); if (c) { scrollToKey(c.getAttribute("data-key"), true); } }, t));
        t += 1400;
      }
      playing.push(setTimeout(function () {
        if (st.view === "report") { applyStage(ui.case, i, true); ui.view = "report"; render(); window.scrollTo(0, 0); setTimeout(function () { scrollToKey(st.focus); }, 50); restartTimer(); return; }
        applyStage(ui.case, i, true); render(); restartTimer(); if (st.focus) scrollToKey(st.focus, true);
        else { var k = st.open && st.open[st.open.length - 1]; if (k) scrollToKey(k, true); }
        mockBar();
      }, t));
      t += st.track || st.pool ? 6000 : 3800;
    });
    playing.push(setTimeout(function () { playing = []; mockBar(); }, t));
    mockBar();
  }
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest("#mock [data-m]"); if (!b) return;
    var m = b.getAttribute("data-m");
    if (m === "case") go(b.getAttribute("data-v"), 0, { top: true });
    else if (m === "stage") go(ui.case, +b.getAttribute("data-v"));
    else if (m === "play") { if (playing.length) { stopPlay(); mockBar(); } else play(); }
    else if (m === "view") setView(ui.view === "report" ? "app" : "report");
    else if (m === "theme") toggleTheme();
    else if (m === "lang") { ui.lang = ui.lang === "en" ? "ko" : "en"; render(); syncUrl(); }
    else if (m === "min") { $("#mock").classList.toggle("min"); mockBar(); }
  });
  function toggleTheme() {
    var r = document.documentElement, dark = r.classList.contains("dark") || (!r.classList.contains("light") && matchMedia("(prefers-color-scheme: dark)").matches);
    r.classList.toggle("dark", !dark); r.classList.toggle("light", dark);
  }
  $("#btn-theme").addEventListener("click", toggleTheme);
  $("#btn-lang").addEventListener("click", function () { ui.lang = ui.lang === "en" ? "ko" : "en"; render(); syncUrl(); });

  /* ------------------------------------------------------------------ boot */
  var caseId = CASES[Q.get("case")] ? Q.get("case") : "healthy", sq = Q.get("stage"), k = 0;
  if (sq != null) { k = /^\d+$/.test(sq) ? +sq : CASES[caseId].stages.map(function (s) { return s.key; }).indexOf(sq); if (k < 0) k = 0; }
  if (Q.get("bar") === "0") { var mb = $("#mock"); if (mb) mb.remove(); }
  go(caseId, k);
  window.EXPLORE = { go: go, ui: function () { return ui; } };
})();
