/* dynamicState web UI: process exploration (docs/ui-redesign/EXPLORE_PROPOSAL_KO.md).
 *
 * Rows of the Process profile open in place; what opens is a fragment the server built for this job
 * (GET api/diagnose/{job}/...; words and markup in extractor/web/ui/explore_fragments.py).  This file only places
 * fragments where the server marked <!--slot:KEY-->, remembers which rows are open, and draws the observation card from
 * the server's samples.  The render functions are pure (state -> string) like ui.js; the browser part fetches and
 * reacts to clicks.  No framework, no external URL.
 */
(function (root) {
  "use strict";
  var U = root.DSUI || (typeof require === "function" ? require("./ui.js") : null);

  /* the module's own words (controls; every word about the target comes from the server) */
  var XSTR = {
    ko: {
      reading: "읽는 중…", addr: "주소", length: "길이", read: "읽기", reread: "다시 읽기", add_watch: "추적에 추가", in_watch: "관찰에 있음 ↓",
      range_hint: "주소(0x…)를 넣고 읽기를 누르면 그 범위를 한 번 읽습니다 (최대 4 KiB). 매핑 목록의 '범위 읽기'나 값의 '따라가기'로도 열립니다.",
      obs_h: "관찰", obs_desc: "시간에 따라 다시 읽는 것은 여기에만 있습니다", sample_n: "표본 #{n}", interval: "표본 간격", sec: "{v}초",
      pause: "멈춤", resume: "계속", to_report: "보고서에 추가", update_report: "보고서 갱신",
      cost: "무정지 표본 추출 · 대상 정지 0 ms · 쓰기 없음 · 초당 읽기 {r}회, 약 {b} B/s · {how}",
      how_local: "process_vm_readv", how_ssh: "SSH 왕복 1회/읽기",
      added: "보고서에 추가됨 ({t} 시점)", tracking: "추적 중", c_name: "이름", c_type: "형식", c_now: "현재 값", c_spark: "최근 30회",
      c_changes: "변화", c_last: "마지막 변화", unchanged: "변화 없음", remove: "추적 해제", nothing: "추적 중인 값이 없습니다. 프로필의 변수·락·범위에서 '추적에 추가'.",
      st_watching: "관찰 중", st_paused: "관찰 멈춤", st_gone: "대상 종료",
      gone: "대상이 종료되었습니다. 다음 읽기가 실패해 관찰을 멈췄습니다 ({m}). 마지막 값까지 남아 있고, 보고서에 추가할 수 있습니다.",
      stopped_idle: "아무도 보지 않아 관찰을 멈췄습니다 ({m}). '계속'을 누르면 다시 읽습니다.",
      stopped_life: "관찰이 최대 시간에 닿아 멈췄습니다 ({m}). '계속'을 누르면 새로 시작합니다.",
      stopped_fail: "읽기가 실패해 관찰을 멈췄습니다: {m}", stopped: "관찰을 멈췄습니다.",
      pool_h: "풀 보기", pool_sub: "배열·풀의 원소를 상태 필드로 색칠", pool_add: "풀 보기 추가", expr: "식", count: "개수", field: "상태 필드",
      view: "보기", apply: "다시 보기", pool_remove: "풀 보기 닫기",
      pool_prefill: "형식에서 미리 채움", pool_grid: "풀 격자: 화살표로 이동, Enter로 선택",
      pool_note: "칸 하나 = 원소 {per}개 · 64개씩 한 줄 · 이번 표본에서 상태가 바뀐 칸 {chg}개 · 범례를 누르면 그 상태만 · 숫자 옆은 관찰 시작 대비 증감 · 표본 #{n} ({t}) · 표본마다 {b} B 한 번 읽기",
      pool_cell: "칸을 누르면 그 원소의 필드가 여기에 나옵니다.", element: "원소", watch_el: "이 원소 추적", other: "그 밖",
      sel_changed: "상태가 마지막으로 바뀐 시각: {t}", bucket: "칸 #{c}: 원소 {a}–{b}",
      cmp_h: "비교", cmp_sub: "고정한 시점 이후 바뀐 것만", freeze: "지금 값 고정", refreeze: "다시 고정", unfreeze: "고정 해제",
      cmp_line: "고정: 표본 #{a} ({ta}) → 지금 #{b} ({tb}) · 바뀜 {c} · 그대로 {s}", cmp_none: "고정 이후 바뀐 값이 없습니다.",
      cmp_cells: "상태가 바뀐 칸", cmp_count: "{x} 개수",
      err_watch: "관찰을 바꾸지 못했습니다: {m}"
    },
    en: {
      reading: "reading…", addr: "address", length: "length", read: "Read", reread: "Re-read", add_watch: "Add to watch", in_watch: "in Watch ↓",
      range_hint: "Type an address (0x…) and press Read: that range is read once (max 4 KiB). Mappings' Read and a value's follow open it too.",
      obs_h: "Watch", obs_desc: "the only place where things are re-read over time", sample_n: "sample #{n}", interval: "interval", sec: "{v} s",
      pause: "Pause", resume: "Resume", to_report: "Add to report", update_report: "Update report",
      cost: "zero-stop sampling · target stop 0 ms · no writes · {r} reads/s, about {b} B/s · {how}",
      how_local: "process_vm_readv", how_ssh: "one SSH round trip per read",
      added: "added to the report (as of {t})", tracking: "Tracking", c_name: "name", c_type: "type", c_now: "current", c_spark: "last 30",
      c_changes: "changes", c_last: "last change", unchanged: "unchanged", remove: "remove", nothing: "Nothing tracked yet. Use Add to watch in the profile.",
      st_watching: "watching", st_paused: "watch paused", st_gone: "target exited",
      gone: "The target exited. The next read failed and watching stopped ({m}). Values up to the last sample are kept and can go into the report.",
      stopped_idle: "Watching stopped because nobody was looking ({m}). Press Resume to read again.",
      stopped_life: "Watching reached its maximum time and stopped ({m}). Press Resume to start again.",
      stopped_fail: "A read failed and watching stopped: {m}", stopped: "Watching stopped.",
      pool_h: "Pool", pool_sub: "colour an array's elements by a status field", pool_add: "Add a pool view", expr: "expression", count: "count",
      field: "status field", view: "View", apply: "Apply", pool_remove: "Close the pool view",
      pool_prefill: "prefilled from the type", pool_grid: "pool grid: arrows move, Enter selects",
      pool_note: "{per} element(s) per cell · 64 per row · {chg} cells changed state this sample · click a legend item to show only that status · deltas since the view started · sample #{n} ({t}) · one {b}-byte read per sample",
      pool_cell: "Click a cell to see that element's fields here.", element: "Element", watch_el: "Watch this element", other: "other",
      sel_changed: "state last changed at {t}", bucket: "cell #{c}: elements {a}–{b}",
      cmp_h: "Compare", cmp_sub: "only what changed since the freeze", freeze: "Freeze now", refreeze: "Freeze again", unfreeze: "Clear",
      cmp_line: "frozen: sample #{a} ({ta}) → now #{b} ({tb}) · changed {c} · same {s}", cmp_none: "Nothing changed since the freeze.",
      cmp_cells: "cells whose state changed", cmp_count: "{x} count",
      err_watch: "Could not change the watch: {m}"
    }
  };
  function xt(lang, k, vars) {
    var s = (XSTR[lang] || XSTR.ko)[k];
    if (s == null) s = XSTR.ko[k] != null ? XSTR.ko[k] : k;
    return vars ? String(s).replace(/\{(\w+)\}/g, function (m, n) { return vars[n] != null ? vars[n] : m; }) : s;
  }
  function esc(s) { return U.esc(s); }
  function X0() { return { frag: {}, frame: {}, memLimit: {}, memFilter: {}, q: "", range: null, chips: null, chipsMore: {}, watch: null, cfg: null, pool: { sel: null, cur: 0, only: null }, report: null, err: null }; }
  function xs(ui) { if (!ui.x) ui.x = X0(); return ui.x; }
  function fmtN(v) { return typeof v === "number" ? v.toLocaleString("en-US") : String(v == null ? "—" : v); }
  function clock(iso) {
    var d = new Date(iso);
    if (!isFinite(d.getTime())) return "—";
    var p = function (n) { return ("0" + n).slice(-2); };
    return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }

  /* ------------------------------------------------------------------ slots (pure) */
  function fragHtml(k, s, ui, depth) {
    var X = xs(ui), f = X.frag[k];
    if (!f) return "";
    if (f.st === "load") return '<p class="dt-note" role="status">' + esc(xt(ui.lang, "reading")) + "</p>" + (f.html ? frag(f, ui) : "");
    return U.fillSlots(decorate(k, frag(f, ui), ui), s, ui, depth);
  }
  function frag(f, ui) { return f.html ? (f.html[ui.lang] || f.html.ko || "") : ""; }
  /* the selected frame of a stack, and "in Watch" next to what is tracked */
  function decorate(k, html, ui) {
    var X = xs(ui), out = html;
    if (/^th:\d+$/.test(k)) {
      var f = X.frag[k], d = (f && f.data) || {}, sel = X.frame[k];
      if (sel == null) sel = pickFrame(d, X.wantFns && X.wantFns[k]);
      out = out.replace('data-i="' + sel + '" data-fn=', 'data-i="' + sel + '" data-sel="1" data-fn=')
        .replace(/(data-sel="1" data-fn="[^"]*") aria-current="false"/, '$1 aria-current="true"')
        .replace('<div class="fr-loc" data-fr="' + sel + '" hidden>', '<div class="fr-loc" data-fr="' + sel + '">');
    }
    var tracked = trackedExprs(ui);
    return out.replace(/(<button type="button" class="btn [^"]*" data-act="track" data-expr="([^"]*)">[^<]*<\/button>)/g, function (m, b, e) {
      return tracked[e] ? b + ' <a class="dt-note" href="#observe" data-act="to-obs">' + esc(xt(ui.lang, "in_watch")) + "</a>" : b;
    });
  }
  function pickFrame(d, fns) {
    var frames = d.frames || [];
    if (fns && fns.length) {
      for (var i = 0; i < frames.length; i++) if (fns.indexOf(frames[i].fn) >= 0 && i >= (d.default_frame || 0)) return frames[i].i;
    }
    return d.default_frame != null ? d.default_frame : 0;
  }
  function trackedExprs(ui) {
    var X = xs(ui), out = {}, items = (X.cfg && X.cfg.items) || [];
    items.forEach(function (it) { if (it.expr) out[esc(it.expr)] = 1; });
    return out;
  }
  function rangeForm(ui) {
    var X = xs(ui), r = X.range || {}, lang = ui.lang, len = r.len || 256;
    var opts = [64, 160, 256, 1024, 4096].map(function (n) {
      return '<option value="' + n + '"' + (n === len ? " selected" : "") + ">" + (n >= 1024 ? n / 1024 + " KiB" : n + " B") + "</option>";
    }).join("");
    return '<div class="search"><input class="input mono addr" id="rg-addr" data-act="rg-addr" value="' + esc(r.addr || "") + '" placeholder="0x…" aria-label="' +
      esc(xt(lang, "addr")) + '" autocomplete="off" spellcheck="false"><select class="input" id="rg-len" aria-label="' + esc(xt(lang, "length")) + '">' + opts +
      '</select><button type="button" class="btn btn-outline btn-sm" data-act="range-read">' + esc(xt(lang, X.frag["range:res"] ? "reread" : "read")) + "</button>" +
      (r.addr ? '<button type="button" class="btn btn-outline btn-sm" data-act="track-addr">' + esc(xt(lang, "add_watch")) + "</button>" : "") + "</div>" +
      (X.frag["range:res"] ? "" : '<p class="dt-note">' + esc(xt(lang, "range_hint")) + "</p>");
  }
  function slot(k, s, ui, depth) {
    var X = xs(ui), out;
    if (k === "range") out = rangeForm(ui) + fragHtml("range:res", s, ui, depth);
    else if (k === "vars") out = X.q ? fragHtml("vars", s, ui, depth) : "";
    else if (/^grp:/.test(k)) out = fragHtml(k + ":stack", s, ui, depth) + fragHtml(k + ":members", s, ui, depth);
    else out = fragHtml(k, s, ui, depth);
    return out + U.backLink(k, ui);
  }
  function findingChips(n, s, ui) {
    var X = xs(ui), c = X.chips && X.chips[String(n)];
    if (!c) return "";
    var h = c[ui.lang] || c.ko || "";
    if (X.chipsMore["finding-" + n]) h = h.replace(/ hidden data-act=/g, " data-act=").replace(/<button type="button" class="btn btn-ghost btn-sm" data-act="chips-more"[^>]*>[^<]*<\/button>/, "");
    return h;
  }

  /* ------------------------------------------------------------------ observation card (pure) */
  function spark(series, gone) {
    var a = (series || []).slice(-30), n = a.length, W = 110, H = 22;
    if (!n) return '<svg class="spark flat" viewBox="0 0 110 22" aria-hidden="true"></svg>';
    var num = a.every(function (v) { return typeof v === "number"; }), flat = a.every(function (v) { return v === a[0]; });
    var cls = "spark" + (gone ? " gone" : flat ? " flat" : ""), step = n > 1 ? W / 29 : 0, x0 = W - step * (n - 1);
    if (num && !flat) {
      var mn = Math.min.apply(null, a), mx = Math.max.apply(null, a), pts = a.map(function (v, i) {
        return (x0 + i * step).toFixed(1) + "," + (H - 2 - (H - 4) * (v - mn) / (mx - mn)).toFixed(1);
      });
      var last = pts[n - 1].split(",");
      return '<svg class="' + cls + '" viewBox="0 0 ' + W + " " + H + '" aria-hidden="true"><polygon class="ar" points="' + x0.toFixed(1) + "," + H + " " + pts.join(" ") +
        " " + W + "," + H + '"/><polyline class="ln" points="' + pts.join(" ") + '"/><circle class="pt" r="2" cx="' + last[0] + '" cy="' + last[1] + '"/></svg>';
    }
    var tk = "";
    for (var i = 1; i < n; i++) if (a[i] !== a[i - 1]) tk += '<line class="tk" x1="' + (x0 + i * step).toFixed(1) + '" x2="' + (x0 + i * step).toFixed(1) + '" y1="4" y2="' + (H - 4) + '"/>';
    return '<svg class="' + cls + '" viewBox="0 0 ' + W + " " + H + '" aria-hidden="true"><line class="base" x1="0" x2="' + W + '" y1="' + H / 2 +
      '" y2="' + H / 2 + '"/>' + tk + '<circle class="pt" r="2" cx="' + W + '" cy="' + H / 2 + '"/></svg>';
  }
  function obsActive(ui) { var X = xs(ui); return !!(X.cfg && ((X.cfg.items || []).length || X.cfg.pool)); }
  function chipStatus(s, ui) {
    var X = xs(ui), W = X.watch;
    if (!obsActive(ui) && !(W && W.reason === "target_exited")) return "";
    var gone = W && W.reason === "target_exited", run = W ? W.state === "running" : !!(X.cfg && X.cfg.running);
    return '<span class="sep">·</span>' + (gone ? '<span class="gone">' + esc(xt(ui.lang, "st_gone")) + "</span>"
      : '<span class="watch' + (run ? "" : " paused") + '"><i aria-hidden="true"></i>' + esc(xt(ui.lang, run ? "st_watching" : "st_paused")) + "</span>");
  }
  function observe(s, ui) {
    if (!s.verdict || !obsActive(ui)) return "";
    var X = xs(ui), W = X.watch || {}, lang = ui.lang, gone = W.reason === "target_exited", run = W.state === "running" || (!X.watch && X.cfg.running);
    var ivs = W.intervals || [0.5, 1, 2, 5], iv = (X.cfg && X.cfg.interval_s) || W.interval_s || 1;
    var ctl = '<div class="obs-ctl"><div class="toggle-group" role="group" aria-label="' + esc(xt(lang, "interval")) + '">' + ivs.map(function (v) {
      return '<button type="button" data-act="obs-int" data-v="' + v + '" aria-pressed="' + (iv === v) + '"' + (gone ? " disabled" : "") + ">" + esc(xt(lang, "sec", { v: v })) + "</button>";
    }).join("") + '</div><button type="button" class="btn btn-outline btn-sm" data-act="obs-pause"' + (gone ? " disabled" : "") + ">" + esc(xt(lang, run ? "pause" : "resume")) +
      '</button><span class="grow"></span><button type="button" class="btn btn-outline btn-sm" data-act="obs-report"' + (W.samples ? "" : " disabled") + ">" +
      esc(xt(lang, X.report ? "update_report" : "to_report")) + "</button></div>";
    var P = W.plan || {};
    var cost = '<p class="impact" style="margin-top:8px">' + esc(xt(lang, "cost", { r: fmtN(P.reads_per_s != null ? P.reads_per_s : 0), b: fmtN(P.bytes_per_s || 0),
      how: xt(lang, W.transport === "ssh" ? "how_ssh" : "how_local") })) + (X.report ? " · " + esc(xt(lang, "added", { t: clock(X.report.last_t) })) : "") + "</p>";
    var alert = "";
    if (W.state === "stopped" && W.reason) {
      var key = { target_exited: "gone", idle: "stopped_idle", max_lifetime: "stopped_life", read_failed: "stopped_fail" }[W.reason] || "stopped";
      alert = '<div class="alert alert-tone ' + (gone || W.reason === "read_failed" ? "tone-fail" : "tone-warn") + '" role="alert" style="margin-top:10px">' +
        esc(xt(lang, key, { m: W.reason_detail || "" })) + "</div>";
    }
    if (X.err) alert += '<div class="alert alert-tone tone-warn" role="alert" style="margin-top:10px">' + esc(xt(lang, "err_watch", { m: X.err })) + "</div>";
    var head = '<section class="card" id="observe" aria-labelledby="h-observe"><div class="card-header"><h2 class="card-title" id="h-observe">' + esc(xt(lang, "obs_h")) +
      '</h2><span class="card-description">' + esc(xt(lang, "obs_desc")) + '</span><span class="right mono">' + esc(xt(lang, "sample_n", { n: W.seq || 0 })) +
      (W.last_t ? " · " + esc(clock(W.last_t)) : "") + '</span></div><div class="card-content">';
    return head + ctl + cost + alert + trackSection(W, ui, false) + poolSection(W, ui, false) + compareSection(W, ui, false) + "</div></section>";
  }
  function trackSection(W, ui, still) {
    var X = xs(ui), lang = ui.lang, items = W.items || [], gone = W.reason === "target_exited";
    var h = '<div class="obs-sec"><h3>' + esc(xt(lang, "tracking")) + ' <span class="text-muted">' + items.length + "</span></h3>";
    if (!items.length) return h + '<p class="dt-note">' + esc(xt(lang, "nothing")) + "</p></div>";
    var rows = items.map(function (it) {
      var open = !!(X.openTrack && X.openTrack[it.id]), fields = "", val;
      if (it.fields) {
        val = open || still ? "" : "{ " + it.fields.slice(0, 2).map(function (f) { return f.name.replace(/^\./, "") + " = " + fmtN(f.value); }).join(", ") + (it.fields.length > 2 ? ", …" : "") + " }";
        if (open || still) fields = it.fields.map(function (f) {
          return '<tr class="sub"><td class="mono">' + esc(f.name) + '</td><td></td><td class="mono num">' + esc(fmtN(f.value)) + "</td><td>" + spark(f.spark, gone) +
            '</td><td class="num' + (f.changes ? " chg" : "") + '">' + f.changes + '</td><td class="mono nw">' + esc(f.last_change ? clock(f.last_change) : "—") + "</td>" + (still ? "" : "<td></td>") + "</tr>";
        }).join("");
      } else val = it.error ? it.error : fmtN(it.value);
      var name = it.fields && !still ? '<button type="button" class="lnk" data-act="trk-open" data-id="' + esc(it.id) + '" aria-expanded="' + open + '">' + (open ? "▾ " : "▸ ") + esc(it.label) + "</button>" : esc(it.label);
      return "<tr><td class=\"mono\">" + name + '</td><td class="mono nw">' + esc(it.type || "") + '</td><td class="mono num">' + esc(val) + "</td><td>" + spark(it.spark, gone) +
        '</td><td class="num' + (it.changes ? " chg" : "") + '">' + it.changes + '</td><td class="mono nw">' + esc(it.last_change ? clock(it.last_change) : xt(lang, "unchanged")) + "</td>" +
        (still ? "" : '<td><button type="button" class="btn btn-ghost btn-sm" data-act="untrack" data-id="' + esc(it.id) + '" aria-label="' + esc(xt(lang, "remove")) + '">✕</button></td>') + "</tr>" + fields;
    }).join("");
    return h + '<div class="scroll-x"><table class="table compact"><thead><tr><th>' + esc(xt(lang, "c_name")) + "</th><th>" + esc(xt(lang, "c_type")) + '</th><th class="num">' +
      esc(xt(lang, "c_now")) + "</th><th>" + esc(xt(lang, "c_spark")) + '</th><th class="num">' + esc(xt(lang, "c_changes")) + '</th><th class="nw">' + esc(xt(lang, "c_last")) +
      "</th>" + (still ? "" : "<th></th>") + "</tr></thead><tbody>" + rows + "</tbody></table></div></div>";
  }
  /* the pool view: one cell per element (a bucket of elements past 4,096), coloured by the status field's value */
  function poolForm(P, ui) {
    var lang = ui.lang, c = (xs(ui).cfg && xs(ui).cfg.pool) || {};
    var expr = P ? P.expr : c.expr || "", count = P ? P.count : c.count || "", field = P ? P.field : c.field || "";
    return '<div class="obs-form"><label>' + esc(xt(lang, "expr")) + '<input class="input mono" id="pl-expr" value="' + esc(expr) + '" autocomplete="off" spellcheck="false"></label>' +
      "<label>" + esc(xt(lang, "count")) + '<input class="input mono w-s" id="pl-count" value="' + esc(count) + '" autocomplete="off"></label>' +
      "<label>" + esc(xt(lang, "field")) + '<input class="input mono w-s" id="pl-field" value="' + esc(field) + '" autocomplete="off" spellcheck="false"></label>' +
      '<button type="button" class="btn btn-outline btn-sm" data-act="pool-apply">' + esc(xt(lang, P ? "apply" : "view")) + "</button>" +
      (P ? '<button type="button" class="btn btn-ghost btn-sm" data-act="pool-close">' + esc(xt(lang, "pool_remove")) + "</button>" : "") +
      (expr && field ? '<span class="dt-note">' + esc(xt(lang, "pool_prefill")) + "</span>" : "") + "</div>";
  }
  function poolSection(W, ui, still) {
    var X = xs(ui), lang = ui.lang, P = W.pool;
    if (!P) {
      if (still) return "";
      return '<div class="obs-sec" id="pool-sec"><h3>' + esc(xt(lang, "pool_h")) + ' <span class="text-muted">' + esc(xt(lang, "pool_sub")) + "</span></h3>" +
        (X.poolForm ? poolForm(null, ui) : '<button type="button" class="btn btn-outline btn-sm" data-act="pool-form">' + esc(xt(lang, "pool_add")) + "</button>") + "</div>";
    }
    var cells = P.cells || "", n = cells.length, cols = 64, sel = X.pool.sel, cur = X.pool.cur, only = X.pool.only;
    var size = n > 1024 ? "" : n > 256 ? " pool-md" : " pool-sm";
    var selCell = sel == null ? null : Math.floor(sel / (P.per_cell || 1));
    var h = [], labels = "", i;
    for (i = 0; i < n; i++) h.push('<i class="pc s' + cells.charAt(i) + (i === selCell ? " sel" : "") + (i === cur && !still ? " cur" : "") + '" data-i="' + i + '"></i>');
    for (i = 0; i < Math.ceil(n / cols); i++) labels += "<span>" + (i % 8 === 0 ? i * cols * (P.per_cell || 1) : "") + "</span>";
    var legend = (P.legend || []).map(function (L) {
      var name = L.name == null ? xt(lang, "other") : L.name;
      var inner = '<i class="pc s' + L.cls + '"></i>' + esc(name) + " <b>" + esc(fmtN(L.count)) + "</b>" +
        (W.seq > (P.start_seq || 0) ? '<span class="d">' + (L.delta > 0 ? "+" : "") + esc(fmtN(L.delta)) + "</span>" : "");
      return still ? "<li>" + inner + "</li>" : '<button type="button" data-act="pool-only" data-cls="' + L.cls + '" aria-pressed="' + (only === L.cls) + '">' + inner + "</button>";
    }).join("");
    var side = "";
    if (P.sel_view) {
      var sv = P.sel_view, fields = sv.fields || {};
      side = '<h4 style="margin-top:0">' + esc(xt(lang, "element")) + ' <span class="mono">' + esc(P.expr) + "[" + sv.index + "]</span> @ " + esc(sv.addr || "?") + "</h4>" +
        '<div class="scroll-x"><table class="table compact"><tbody>' + Object.keys(fields).map(function (k) {
          return '<tr><td class="mono">' + esc(k.replace(/^\./, "")) + '</td><td class="mono">' + esc(fmtN(fields[k])) + "</td></tr>";
        }).join("") + "</tbody></table></div>" +
        (still ? "" : '<div class="dt-actions">' + (sv.last_change ? '<span class="dt-note">' + esc(xt(lang, "sel_changed", { t: clock(sv.last_change) })) + "</span>" : "") +
          '<button type="button" class="btn btn-outline btn-sm" data-act="track" data-expr="' + esc(P.expr + "[" + sv.index + "]") + '">' + esc(xt(lang, "watch_el")) + "</button></div>");
    } else if (selCell != null && P.per_cell > 1 && !still) {
      var a = selCell * P.per_cell, b = Math.min(P.count, a + P.per_cell) - 1, list = "";
      for (i = a; i <= b; i++) list += '<button type="button" class="btn btn-ghost btn-sm" data-act="pool-el" data-i="' + i + '">[' + i + "]</button>";
      side = '<p class="dt-note">' + esc(xt(lang, "bucket", { c: selCell, a: a, b: b })) + '</p><div class="dt-actions">' + list + "</div>";
    } else if (!still) side = '<p class="dt-note">' + esc(xt(lang, "pool_cell")) + "</p>";
    var grid = '<div class="pool' + size + '" role="grid" aria-label="' + esc(xt(lang, "pool_grid")) + '" tabindex="' + (still ? -1 : 0) + '" id="pool-grid"' +
      (only != null && !still ? ' data-only="' + only + '"' : "") + ' style="--cols:' + cols + '"><div class="rl" aria-hidden="true">' + labels +
      '</div><div class="cells"' + (still ? "" : ' data-act="pool-cell"') + ">" + h.join("") + "</div></div>";
    return '<div class="obs-sec" id="pool-sec"><h3>' + esc(xt(lang, "pool_h")) + ' <span class="text-muted mono">' + esc(P.expr + " · " + fmtN(P.count) + " × " + P.elem_type +
      " (" + P.elem_size + " B) · " + P.field + (P.field_type ? " (" + P.field_type + ")" : "")) + "</span></h3>" + (still ? "" : poolForm(P, ui)) +
      '<div class="pool-wrap"><div>' + grid + (still ? '<ul class="pool-legend">' + legend + "</ul>" : '<div class="pool-legend">' + legend + "</div>") + "</div><div>" + side + "</div></div>" +
      '<p class="dt-note" style="margin-top:6px">' + esc(xt(lang, "pool_note", { per: P.per_cell || 1, chg: fmtN(P.changed || 0), n: W.seq || 0, t: clock(W.last_t), b: fmtN(P.bytes) })) + "</p></div>";
  }
  function compareSection(W, ui, still) {
    var X = xs(ui), lang = ui.lang, C = W.compare;
    var head = '<div class="obs-sec" id="cmp-sec"><h3>' + esc(xt(lang, "cmp_h")) + ' <span class="text-muted">' + esc(xt(lang, "cmp_sub")) + "</span></h3>";
    if (!C) return still ? "" : head + '<button type="button" class="btn btn-outline btn-sm" data-act="freeze"' + (W.samples ? "" : " disabled") + ">" + esc(xt(lang, "freeze")) + "</button></div>";
    var ch = (C.changed || []).map(function (c) { return [c.name, c.before, c.now, c.diff]; });
    if (C.pool) {
      (C.pool.counts || []).forEach(function (c) { ch.push([xt(lang, "cmp_count", { x: c.name == null ? xt(lang, "other") : c.name }), c.before, c.now, c.diff]); });
      ch.push([xt(lang, "cmp_cells"), "", fmtN(C.pool.cells_changed) + " / " + fmtN(C.pool.cells), null]);
    }
    return head + '<p class="dt-note">' + esc(xt(lang, "cmp_line", { a: C.from_seq, ta: clock(C.from_t), b: C.to_seq, tb: clock(C.to_t), c: (C.changed || []).length, s: C.same })) + "</p>" +
      (ch.length ? '<ul class="cmp">' + ch.map(function (c) {
        return '<li><span class="nm">' + esc(c[0]) + '</span><span class="was">' + esc(fmtN(c[1])) + '</span><span aria-hidden="true">→</span><span class="now">' + esc(fmtN(c[2])) +
          "</span>" + (c[3] != null ? '<span class="d">' + (c[3] > 0 ? "+" : "") + esc(fmtN(c[3])) + "</span>" : "") + "</li>";
      }).join("") + "</ul>" : '<p class="dt-note">' + esc(xt(lang, "cmp_none")) + "</p>") +
      (still ? "" : '<div class="dt-actions" style="margin-top:6px"><button type="button" class="btn btn-outline btn-sm" data-act="freeze">' + esc(xt(lang, "refreeze")) +
        '</button><button type="button" class="btn btn-ghost btn-sm" data-act="unfreeze">' + esc(xt(lang, "unfreeze")) + "</button></div>") + "</div>";
  }

  var api = { XSTR: XSTR, slot: slot, findingChips: findingChips, observe: observe, chipStatus: chipStatus, spark: spark, poolSection: poolSection, decorate: decorate,
    trackSection: trackSection, compareSection: compareSection, xt: xt, clock: clock, fmtN: fmtN, xs: xs };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.DSX = api;
  if (typeof document === "undefined" || !U || !U.shell) return;

  /* ================================================================== browser part */
  var S = U.shell, ui = S.ui;
  function base() { var j = S.job(); return j ? "api/diagnose/" + encodeURIComponent(j) + "/" : null; }
  function get(path) { return S.getJSON(base() + path); }
  function post(path, body) { return S.getJSON(base() + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) }); }
  function load(k, path, keep) {
    var X = xs(ui), b = base();
    if (!b) return;
    var prev = X.frag[k];
    X.frag[k] = { st: "load", html: keep && prev ? prev.html : null, data: prev && prev.data };
    S.draw();
    get(path).then(function (r) {
      X.frag[k] = { st: r.success ? "ok" : "err", html: r.html || null, data: r.data || null, cost: r.cost };
      S.draw();
    }).catch(function () { X.frag[k] = { st: "err", html: null }; S.draw(); });
  }
  function routeFor(k, el) {
    var m;
    if ((m = /^th:(\d+)$/.exec(k))) return "thread/" + m[1];
    if ((m = /^lk:(.+)$/.exec(k))) return "lock?name=" + encodeURIComponent(m[1]);
    if ((m = /^var:(.+)$/.exec(k))) return "value?expr=" + encodeURIComponent(m[1]);
    if (k === "maps") return "memory/maps";
    if (k === "files") return "files";
    if (k === "mods") return "modules";
    return null;
  }
  function opened(k, el) {
    var X = xs(ui);
    if (/^grp:/.test(k)) {
      var btn = el && el.getAttribute ? el : document.querySelector('[data-key="' + k + '"]');
      var tid = btn && btn.getAttribute("data-tid"), name = btn && btn.getAttribute("data-name");
      if (tid && !X.frag[k + ":stack"]) load(k + ":stack", "thread/" + tid);
      if (name && !X.frag[k + ":members"]) { X.grpName = X.grpName || {}; X.grpName[name] = k; loadMembers(name); }
      return;
    }
    var path = routeFor(k, el);
    if (path && (!X.frag[k] || X.frag[k].st === "err")) load(k, path);
  }
  function loadMembers(name) {
    var X = xs(ui), k = (X.grpName || {})[name];
    if (!k) return;
    load(k + ":members", "threads?name=" + encodeURIComponent(name) + "&limit=" + (X.memLimit[name] || 20) + (X.memFilter[name] ? "&filter=" + encodeURIComponent(X.memFilter[name]) : ""), true);
  }
  function onVerdict() {
    var X = xs(ui);
    if (X.chips) return;
    X.chips = {};
    get("chips").then(function (r) { if (r.success) { X.chips = r.findings || {}; S.draw(); } }).catch(function () { /* no chips */ });
    loadWatch();
  }
  function reset() { ui.x = X0(); closeWatch(); }
  function readRange(addr, len, expr) {
    var X = xs(ui);
    X.range = { addr: addr || (X.range && X.range.addr) || "", len: len || (X.range && X.range.len) || 256 };
    ui.open["pf:memory"] = true; ui.open.range = true;
    var q = expr && !addr ? "expr=" + encodeURIComponent(expr) : "addr=" + encodeURIComponent(X.range.addr);
    var b = base();
    if (!b) return;
    X.frag["range:res"] = { st: "load", html: X.frag["range:res"] && X.frag["range:res"].html };
    S.draw();
    get("memory/range?" + q + "&len=" + X.range.len).then(function (r) {
      X.frag["range:res"] = { st: r.success ? "ok" : "err", html: r.html || null, data: r.data };
      if (r.success && r.data && r.data.addr) X.range.addr = r.data.addr;
      S.draw();
    }).catch(function () { X.frag["range:res"] = { st: "err", html: null }; S.draw(); });
  }
  function scrollToKey(k, flash) {
    var n = document.querySelector('[data-key="' + k.replace(/["\\]/g, "\\$&") + '"]') || document.getElementById(k);
    if (!n) return;
    var y = n.getBoundingClientRect().top + window.scrollY - 64;
    window.scrollTo({ top: Math.max(0, y), behavior: "auto" });
    if (flash) { n.classList.remove("flash"); void n.offsetWidth; n.classList.add("flash"); }
    if (n.focus && n.tagName === "BUTTON") n.focus({ preventScroll: true });
  }
  function openKeys(keys) {
    keys.forEach(function (k) { if (!ui.open[k]) { ui.open[k] = true; opened(k, null); } });
  }

  /* ---- observation ---- */
  var es = null, pollT = null, wgen = 0;
  function closeWatch() { wgen++; if (es) { es.close(); es = null; } if (pollT) { clearTimeout(pollT); pollT = null; } }
  function applyWatch(r) {
    var X = xs(ui);
    if (!r) return;
    if (r.watch) {
      X.watch = r.watch;
      if (!X.cfg) X.cfg = { items: [], pool: null, interval_s: r.watch.interval_s, running: r.watch.state === "running" };
    }
    S.draw();
  }
  function loadWatch() {
    get("watch/status?after=0").then(function (r) {
      if (!r.success || !r.watch) return;
      var X = xs(ui), W = r.watch;
      X.cfg = { items: (W.items || []).map(function (it) { return it.id.indexOf("e:") === 0 ? { expr: it.id.slice(2) } : { addr: "0x" + it.id.split(":")[1], type: it.id.split(":")[2] }; }),
        pool: W.pool ? { expr: W.pool.expr, count: W.pool.count, field: W.pool.field, sel: W.pool.sel } : null, interval_s: W.interval_s, running: W.state === "running" };
      applyWatch(r);
      if (W.state === "running") listen();
    }).catch(function () { /* nothing observed */ });
  }
  function listen() {
    closeWatch();
    var my = wgen, X = xs(ui), after = (X.watchVersion || 0);
    if (window.EventSource) {
      var got = false;
      es = new EventSource(base() + "watch/events?after=" + after);
      es.addEventListener("watch", function (m) {
        if (my !== wgen) return;
        got = true;
        try { var d = JSON.parse(m.data); X.watchVersion = d.version; applyWatch(d); } catch (e) { /* skip */ }
        if (X.watch && X.watch.state !== "running") closeWatch();
      });
      es.onerror = function () { if (my !== wgen) return; if (es) { es.close(); es = null; } if (X.watch && X.watch.state !== "running") return; poll(my); };
      setTimeout(function () { if (my === wgen && !got && es) { es.close(); es = null; poll(my); } }, 4000);
    } else poll(my);
  }
  function poll(my) {
    var X = xs(ui);
    (function once() {
      if (my !== wgen) return;
      get("watch/status?after=" + (X.watchVersion || 0)).then(function (r) {
        if (my !== wgen) return;
        if (r.success) { X.watchVersion = r.version; applyWatch(r); }
        if (X.watch && X.watch.state === "running") pollT = setTimeout(once, Math.max(500, (X.watch.interval_s || 1) * 1000));
      }).catch(function () { if (my === wgen) pollT = setTimeout(once, 2000); });
    })();
  }
  function sendCfg(extra) {
    var X = xs(ui);
    var body = Object.assign({ items: X.cfg.items, pool: X.cfg.pool, interval_s: X.cfg.interval_s, running: X.cfg.running }, extra || {});
    return post("watch", body).then(function (r) {
      if (!r.success) { X.err = (r.error && r.error.message) || "error"; S.draw(); return r; }
      X.err = null;
      X.watchVersion = r.version;
      applyWatch(r);
      if (r.watch && r.watch.state === "running") listen(); else closeWatch();
      return r;
    }).catch(function () { X.err = "network"; S.draw(); });
  }
  /* the server's id of a tracked item (extractor/web/explore.py WatchSession._item_spec) */
  function itemId(it) { return it.expr ? "e:" + it.expr : "a:" + parseInt(it.addr, 16).toString(16) + ":" + (it.type || "u64"); }
  function track(item) {
    var X = xs(ui);
    if (!X.cfg) X.cfg = { items: [], pool: null, interval_s: 1, running: true };
    if (!X.cfg.items.some(function (it) { return itemId(it) === itemId(item); })) X.cfg.items.push(item);
    if (!(X.watch && X.watch.reason === "target_exited")) X.cfg.running = true;
    S.draw();
    return sendCfg();
  }

  function click(act, el, ev) {
    var X = xs(ui), k, m;
    switch (act) {
      case "frame": X.frame[el.getAttribute("data-k")] = +el.getAttribute("data-i"); S.drawNow(); break;
      case "goto": {
        openKeys(el.getAttribute("data-keys").split(" "));
        if (el.getAttribute("data-fns")) { X.wantFns = X.wantFns || {}; X.wantFns["th:" + el.getAttribute("data-tid")] = el.getAttribute("data-fns").split(" "); }
        if (el.getAttribute("data-q")) setQuery(el.getAttribute("data-q"));
        ui.from = el.getAttribute("data-from"); ui.fromKey = el.getAttribute("data-focus");
        S.drawNow(); scrollToKey(ui.fromKey, true);
        break;
      }
      case "goto-range": {
        openKeys(["pf:memory", "range"]);
        ui.from = el.getAttribute("data-from"); ui.fromKey = "range";
        readRange(el.getAttribute("data-addr"), +el.getAttribute("data-len") || 160, el.getAttribute("data-expr"));
        S.drawNow(); scrollToKey("range", true);
        break;
      }
      case "back": {
        var from = ui.from; ui.from = null; ui.fromKey = null; S.drawNow();
        var n = from && document.getElementById(from);
        if (n) { var t = n.querySelector(".related") || n; var y = t.getBoundingClientRect().top + window.scrollY - 80; window.scrollTo({ top: Math.max(0, y) }); t.classList.add("flash"); }
        break;
      }
      case "goto-lock": k = "lk:" + el.getAttribute("data-name"); openKeys(["pf:locks", k]); S.drawNow(); scrollToKey(k, true); break;
      case "goto-thread": k = "th:" + el.getAttribute("data-tid"); openKeys(["pf:threads", k]); S.drawNow(); scrollToKey(k, true); break;
      case "follow": readRange(el.getAttribute("data-addr"), 64); S.drawNow(); scrollToKey("range", true); break;
      case "map-read": readRange(el.getAttribute("data-addr"), 256); S.drawNow(); scrollToKey("range", true); break;
      case "range-step": readRange(el.getAttribute("data-addr"), +el.getAttribute("data-len")); break;
      case "range-read": {
        var a = document.getElementById("rg-addr"), l = document.getElementById("rg-len");
        if (a && a.value.trim()) readRange(a.value.trim(), +(l && l.value) || 256);
        break;
      }
      case "track-addr": if (X.range && X.range.addr) track({ addr: X.range.addr, type: "u64" }).then(function () { scrollToKey("observe"); }); break;
      case "more": m = el.getAttribute("data-name"); X.memLimit[m] = (X.memLimit[m] || 20) + 50; loadMembers(m); break;
      case "chips-more": X.chipsMore[el.getAttribute("data-id")] = true; S.drawNow(); break;
      case "to-obs": ev.preventDefault(); scrollToKey("observe"); break;
      case "track": track({ expr: el.getAttribute("data-expr") }).then(function () { if (el.getAttribute("data-from")) scrollToKey("observe", true); }); break;
      case "untrack": {
        var id = el.getAttribute("data-id");
        X.cfg.items = X.cfg.items.filter(function (it) { return itemId(it) !== id; });
        sendCfg(); break;
      }
      case "trk-open": X.openTrack = X.openTrack || {}; k = el.getAttribute("data-id"); X.openTrack[k] = !X.openTrack[k]; S.drawNow(); break;
      case "obs-int": X.cfg.interval_s = +el.getAttribute("data-v"); sendCfg(); break;
      case "obs-pause": X.cfg.running = !(X.watch && X.watch.state === "running"); sendCfg(); break;
      case "obs-report": post("observation", {}).then(function (r) { if (r.success) { X.report = r.observation; S.draw(); } else { X.err = (r.error || {}).message; S.draw(); } }); break;
      case "freeze": sendCfg({ pin: "now" }); break;
      case "unfreeze": sendCfg({ pin: "clear" }); break;
      default: if (root.DSX.poolClick) root.DSX.poolClick(act, el, ev, { ui: ui, X: X, sendCfg: sendCfg, S: S, scrollToKey: scrollToKey }); break;
    }
  }
  var qT = null, mT = null;
  function setQuery(q) {
    var X = xs(ui);
    X.q = q; ui.open.vars = !!q;
    var inp = document.getElementById("var-q");
    if (inp && inp.value !== q) inp.value = q;
    if (q) load("vars", "vars?q=" + encodeURIComponent(q), true); else S.draw();
  }
  document.addEventListener("input", function (ev) {
    var t = ev.target, act = t.getAttribute && t.getAttribute("data-act");
    if (act === "q") { clearTimeout(qT); qT = setTimeout(function () { setQuery(t.value.trim()); }, 250); }
    if (act === "mfilter") { clearTimeout(mT); var nm = t.getAttribute("data-name"); mT = setTimeout(function () { xs(ui).memFilter[nm] = t.value.trim(); loadMembers(nm); }, 300); }
  });
  document.addEventListener("keydown", function (ev) {
    var t = ev.target;
    if (ev.key === "Enter" && t && t.id === "rg-addr") { ev.preventDefault(); click("range-read", t, ev); }
    if (root.DSX.poolKey) root.DSX.poolKey(ev, { ui: ui, X: xs(ui), S: S, sendCfg: sendCfg });
  });
  window.addEventListener("pagehide", closeWatch);

  /* ---- pool view ---- */
  function setPool(p) {
    var X = xs(ui);
    if (!X.cfg) X.cfg = { items: [], pool: null, interval_s: 1, running: true };
    X.cfg.pool = p;
    if (!(X.watch && X.watch.reason === "target_exited")) X.cfg.running = true;
    return sendCfg();
  }
  function selectElement(i) {
    var X = xs(ui);
    X.pool.sel = i;
    if (X.cfg && X.cfg.pool) { X.cfg.pool.sel = i; sendCfg(); }
    S.drawNow();
  }
  function poolClick(act, el, ev) {
    var X = xs(ui), W = X.watch || {}, P = W.pool;
    switch (act) {
      case "pool-go": {
        X.pool = { sel: null, cur: 0, only: null };
        setPool({ expr: el.getAttribute("data-expr"), count: +el.getAttribute("data-count"), field: el.getAttribute("data-field"), sel: null })
          .then(function () { scrollToKey("pool-grid", true); });
        break;
      }
      case "pool-form": X.poolForm = true; S.drawNow(); break;
      case "pool-apply": {
        var e = document.getElementById("pl-expr"), c = document.getElementById("pl-count"), f = document.getElementById("pl-field");
        if (!e || !e.value.trim()) break;
        X.pool = { sel: null, cur: 0, only: null };
        setPool({ expr: e.value.trim(), count: c && c.value.trim() ? +c.value.trim() : undefined, field: f && f.value.trim() ? f.value.trim() : undefined, sel: null });
        break;
      }
      case "pool-close": X.cfg.pool = null; X.pool = { sel: null, cur: 0, only: null }; sendCfg(); break;
      case "pool-only": { var k = +el.getAttribute("data-cls"); X.pool.only = X.pool.only === k ? null : k; S.drawNow(); break; }
      case "pool-cell": {
        var i = ev.target.getAttribute && ev.target.getAttribute("data-i");
        if (i == null || !P) break;
        X.pool.cur = +i;
        if ((P.per_cell || 1) === 1) selectElement(+i);
        else { X.pool.sel = +i * P.per_cell; if (X.cfg.pool) { X.cfg.pool.sel = null; sendCfg(); } S.drawNow(); }
        break;
      }
      case "pool-el": selectElement(+el.getAttribute("data-i")); break;
      default: break;
    }
  }
  function poolKey(ev) {
    var g = ev.target && ev.target.closest && ev.target.closest(".pool");
    var X = xs(ui), P = X.watch && X.watch.pool;
    if (!g || !P || !P.cells) return;
    var n = P.cells.length, d = { ArrowRight: 1, ArrowLeft: -1, ArrowDown: 64, ArrowUp: -64 }[ev.key];
    if (d) { X.pool.cur = Math.max(0, Math.min(n - 1, (X.pool.cur || 0) + d)); ev.preventDefault(); S.drawNow(); }
    else if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      if ((P.per_cell || 1) === 1) selectElement(X.pool.cur || 0); else { X.pool.sel = (X.pool.cur || 0) * P.per_cell; S.drawNow(); }
    }
  }
  Object.assign(api, { opened: opened, click: click, onVerdict: onVerdict, reset: reset, poolClick: poolClick, poolKey: poolKey });
})(typeof window !== "undefined" ? window : globalThis);
