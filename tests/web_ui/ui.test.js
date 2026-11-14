// Pure tests of the web UI's reducer and renderer (node --test; no browser, nothing installed).
"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const UI = require(path.join(__dirname, "..", "..", "extractor", "web", "ui", "ui.js"));

const REPLAY = path.join(__dirname, "..", "..", "extractor", "web", "ui", "replay");
const NAMES = JSON.parse(fs.readFileSync(path.join(REPLAY, "index.json"), "utf8")).map((x) => x.name);
const load = (n) => JSON.parse(fs.readFileSync(path.join(REPLAY, n + ".json"), "utf8"));
const UIS = (lang, extra) => Object.assign({ lang, expanded: {}, elapsed: 1234, reportUrl: "r.{lang}.html" }, extra || {});

function shuffle(a, seed) {
  const r = a.slice();
  let x = seed;
  for (let i = r.length - 1; i > 0; i--) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    const j = x % (i + 1);
    [r[i], r[j]] = [r[j], r[i]];
  }
  return r;
}

/* every <... class="card ..."> opened inside another one: the design system forbids a card in a card */
function nestedCards(html) {
  const re = /<(\/?)([a-z0-9]+)([^>]*)>/g, stack = [], VOID = new Set(["br", "img", "input", "hr", "meta", "link", "path", "line", "rect", "circle", "polyline", "polygon", "use"]);
  let m, bad = 0;
  while ((m = re.exec(html))) {
    const [, close, tag, attrs] = m;
    if (VOID.has(tag) || attrs.endsWith("/")) continue;
    if (close) { while (stack.length && stack.pop().tag !== tag); continue; }
    const card = /class="(?:[^"]* )?card(?: [^"]*)?"/.test(attrs);
    if (card && stack.some((e) => e.card)) bad++;
    stack.push({ tag, card });
  }
  return bad;
}

test("every replay renders at every stage, in ko and en, without undefined/NaN", () => {
  for (const n of NAMES) {
    const d = load(n);
    for (const stage of [0, 1, 2, 3, 4, 5]) {
      const evs = d.events.slice(0, UI.stageIndex(d.events, stage));
      const s = UI.reduce(evs, d.request);
      for (const lang of ["ko", "en"]) {
        const html = UI.render(s, UIS(lang, { started: true }));
        const outside = html.replace(/<div class="fbody dsv"[\s\S]*?<\/article>/g, "");
        assert.ok(!/undefined|\[object Object\]|NaN/.test(outside), `${n} stage ${stage} ${lang}`);
        assert.strictEqual(nestedCards(html), 0, `card inside a card: ${n} stage ${stage}`);
        UI.renderChip(s, UIS(lang));
        UI.announce(s, lang);
      }
    }
  }
});

test("the reducer is order-tolerant: shuffled, duplicated and resumed event lists give the same screen", () => {
  for (const n of NAMES) {
    const d = load(n);
    const ref = UI.render(UI.reduce(d.events, d.request), UIS("ko"));
    for (const seed of [1, 7, 42]) {
      assert.strictEqual(UI.render(UI.reduce(shuffle(d.events, seed), d.request), UIS("ko")), ref, `${n} shuffled ${seed}`);
    }
    // a reconnect: the first part, then everything after the last seq seen, with an overlap re-sent
    const cut = Math.floor(d.events.length / 2);
    const resumed = d.events.slice(0, cut).concat(d.events.slice(cut - 3));
    assert.strictEqual(UI.render(UI.reduce(resumed, d.request), UIS("ko")), ref, `${n} resumed`);
    assert.strictEqual(UI.reduce(resumed, d.request).lastSeq, d.events[d.events.length - 1].seq);
  }
});

test("the column only grows: each stage's cards are a prefix of the next stage's (nothing reorders)", () => {
  for (const n of NAMES) {
    const d = load(n);
    let prev = [];
    for (let k = 1; k <= d.events.length; k++) {
      const html = UI.render(UI.reduce(d.events.slice(0, k), d.request), UIS("ko", { started: true }));
      const ids = (html.match(/<(?:section|div) class="(?:card[^"]*|tiles)" id="([a-z]+)"/g) || []).map((x) => x.match(/id="([a-z]+)"/)[1]);
      assert.deepStrictEqual(ids.slice(0, prev.length), prev, `${n} at event ${k}: ${ids} after ${prev}`);
      prev = ids;
    }
    assert.deepStrictEqual(prev, ["banner", "tiles", "target", "profile", "findings", "checks", "notseen", "next", "report"], n);
  }
});

test("check rows keep their place from the plan to the verdict", () => {
  for (const n of NAMES) {
    const d = load(n);
    const planAt = d.events.findIndex((e) => e.type === "plan") + 1;
    const early = UI.reduce(d.events.slice(0, planAt), d.request).order;
    const late = UI.reduce(d.events, d.request).order;
    assert.deepStrictEqual(late.slice(0, early.length), early, n);
  }
});

test("server envelope and flat events reduce to the same state", () => {
  const d = load("deadlock");
  const flat = d.events.map((e) => Object.assign({ seq: e.seq, ts: e.ts, t: e.t, type: e.type }, e.data));
  assert.strictEqual(UI.render(UI.reduce(flat, d.request), UIS("en")), UI.render(UI.reduce(d.events, d.request), UIS("en")));
});

test("a verdict without the view (contract as written) still renders a complete screen", () => {
  for (const n of NAMES) {
    const d = load(n);
    const bare = d.events.map((e) => {
      if (e.type !== "verdict") return e;
      const data = { result: e.data.result, human_summary: e.data.human_summary.ko,
        report_urls: { html: "api/diagnose/J/report?format=html", md: "api/diagnose/J/report?format=md", json: "api/diagnose/J/report?format=json" } };
      return { seq: e.seq, ts: e.ts, type: "verdict", data };
    });
    const s = UI.reduce(bare, d.request);
    const html = UI.render(s, UIS("ko"));
    assert.ok(!/undefined|\[object Object\]|NaN/.test(html), n);
    assert.ok(html.includes('id="report"') && html.includes("format=md&amp;lang=ko"), n);
    const word = d.events.find((e) => e.type === "verdict").data.result.verdict;     // no view: the verdict code itself
    assert.ok(html.includes(word), `${n}: ${word}`);
  }
});

test("errors: a stopped diagnosis keeps what it had and says why", () => {
  const d = load("deadlock");
  const part = d.events.slice(0, 10).concat([{ seq: 11, type: "error", data: { code: "TARGET_EXITED", message: "gone" } }]);
  const s = UI.reduce(part, { target: "4242" });
  const html = UI.render(s, UIS("ko"));
  assert.ok(html.includes(UI.STR.ko.err_TARGET_EXITED.slice(0, 10)));
  assert.ok(html.includes('role="alert"') && html.includes(UI.STR.ko.aborted));
  assert.ok(html.includes('id="checks"'));
  const conn = UI.render(UI.reduce(d.events.slice(0, 8), {}), UIS("en", { conn: "retry" }));
  assert.ok(conn.includes("reconnecting"));
  const lost = UI.render(UI.reduce(d.events.slice(0, 8), {}), UIS("en", { conn: "lost" }));
  assert.ok(lost.includes('data-act="reconnect"'));
  const unknown = UI.render(UI.reduce([{ seq: 1, type: "error", data: { code: "DIAGNOSE_ERROR", message: "RuntimeError: x" } }], {}), UIS("en"));
  assert.ok(unknown.includes("RuntimeError: x"));
});

test("the not-in-mode checks are their own group, never mixed with not-selected", () => {
  const d = load("healthy");
  const html = UI.render(UI.reduce(d.events, d.request), UIS("ko"));
  const g = html.slice(html.indexOf('id="skipped"'));
  const a = g.indexOf(UI.STR.ko.not_planned_h), b = g.indexOf(UI.STR.ko.not_in_mode_h);
  assert.ok(a > 0 && b > a, "both sub-groups present, in order");
  assert.ok(g.includes("필요한 것:"));
  const plan = d.events.find((e) => e.type === "plan").data;
  for (const c of plan.not_in_mode) assert.ok(g.slice(b).includes(c.recipe_id));
  for (const c of plan.not_in_mode) assert.ok(!g.slice(a, b).includes(c.recipe_id));
});

test("a check row expands to that check's own result only", () => {
  const d = load("deadlock");
  const s = UI.reduce(d.events, d.request);
  const rid = "RECIPE_POTENTIAL_DEADLOCK_PATTERNS";
  const html = UI.render(s, UIS("ko", { expanded: { [rid]: true } }));
  assert.strictEqual((html.match(/class="ckdetail dsv"/g) || []).length, 1);
  assert.ok(html.includes(`#check-${rid}-detail`));
  assert.ok(html.includes(`aria-expanded="true" aria-controls="ckd-${rid}"`));
});

test("no confidence or health score anywhere", () => {
  for (const n of NAMES) {
    const d = load(n);
    for (const lang of ["ko", "en"]) {
      const html = UI.render(UI.reduce(d.events, d.request), UIS(lang));
      assert.ok(!/신뢰도|confidence|health.?score/i.test(html), `${n} ${lang}`);
    }
  }
});

test("the string table is complete in both languages", () => {
  const ko = Object.keys(UI.STR.ko).sort(), en = Object.keys(UI.STR.en).sort();
  assert.deepStrictEqual(en, ko);
  for (const k of ko) assert.ok(String(UI.STR.en[k]).length > 0 && String(UI.STR.ko[k]).length > 0, k);
});

test("the idle screen: one button, the form fields, examples when the server is unreachable", () => {
  const idx = JSON.parse(fs.readFileSync(path.join(REPLAY, "index.json"), "utf8"));
  for (const lang of ["ko", "en"]) {
    const html = UI.renderIdle({ lang, form: { mode: "local" }, jobsState: "unreachable", examples: idx });
    assert.strictEqual((html.match(/type="submit"/g) || []).length, 1);
    for (const name of ["target", "symptom", "debug_image"]) assert.ok(html.includes(`name="${name}"`));
    assert.ok(html.includes("?replay=deadlock"));
    const ssh = UI.renderIdle({ lang, form: { mode: "ssh" } });
    for (const name of ["remote_host", "ssh_user", "ssh_port", "ssh_key"]) assert.ok(ssh.includes(`name="${name}"`));
    const jobs = UI.renderIdle({ lang, form: {}, jobs: [{ job_id: "abc", pid: 42, target_name: "svc", state: "done",
      verdict: "HEALTHY", verdict_word: { ko: "점검한 범위 안에서 정상", en: "healthy within the checked scope" }, started_at: new Date().toISOString() }] });
    assert.ok(jobs.includes("?job=abc") && jobs.includes((lang === "ko" ? "점검한 범위 안에서 정상" : "healthy within the checked scope")));
  }
});

test("the process profile card keeps its place: reserved from the plan, filled by the verdict, same words as the view", () => {
  for (const n of NAMES) {
    const d = load(n);
    const planAt = d.events.findIndex((e) => e.type === "plan") + 1;
    const ids = (html) => (html.match(/<(?:section|div) class="(?:card[^"]*|tiles)" id="([a-z]+)"/g) || []).map((x) => x.match(/id="([a-z]+)"/)[1]);
    const early = UI.render(UI.reduce(d.events.slice(0, planAt), d.request), UIS("ko", { started: true }));
    assert.ok(ids(early).indexOf("profile") === ids(early).indexOf("target") + 1, `${n}: reserved right after the target`);
    assert.match(early, /id="profile"[\s\S]*판정이 나오면 채워집니다/);
    for (const lang of ["ko", "en"]) {
      const late = UI.render(UI.reduce(d.events, d.request), UIS(lang, { started: true }));
      const V = d.events.filter((e) => e.type === "verdict")[0].data.view[lang].profile;
      assert.strictEqual(nestedCards(late), 0, n);
      const card = late.slice(late.indexOf('id="profile"'), late.indexOf('id="findings"'));
      assert.ok(card.includes(V.title), `${n} ${lang}: title from the view`);
      if (V.available) {
        const E = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
        assert.ok(V.figures.length <= 4, `${n} ${lang}: up to four summary figures (only observed ones)`);
        assert.deepStrictEqual(V.rows.map((r) => r.key), ["threads", "memory", "locks", "files", "modules", "vars"], n);
        for (const f of V.figures) assert.ok(card.includes(E(f.v)) && card.includes(E(f.k)), `${n} ${lang}: figure ${f.k}`);
        for (const r of V.rows) {
          assert.ok(card.includes(E(r.label)) && card.includes(E(r.line)) && card.includes(E(r.src)), `${n} ${lang}: row ${r.key}`);
          assert.ok(card.includes(`data-key="pf:${r.key}" aria-expanded="false"`), `${n}: row ${r.key} is a closed button`);
        }
        assert.ok(card.includes(E(V.unseen)), `${n} ${lang}: the not-observed line`);
        assert.doesNotMatch(card, /판정이 나오면|Filled in when/);
        assert.doesNotMatch(card, /<details/, "rows open in place, not in a collapsible");
        // a row opens its own detail in place, right under it; nothing else opens
        const opened = UI.render(UI.reduce(d.events, d.request), UIS(lang, { started: true, open: { "pf:threads": true } }));
        const oc = opened.slice(opened.indexOf('id="profile"'), opened.indexOf('id="findings"'));
        assert.ok(oc.includes('data-key="pf:threads" aria-expanded="true"'), n);
        assert.ok(oc.includes('id="dt-pf-threads"'), n);
        assert.ok(!oc.includes('id="dt-pf-memory"'), n);
        assert.ok(!/<!--slot:/.test(oc), `${n}: closed sub-rows leave no slot marker`);
        assert.strictEqual(nestedCards(opened), 0, n);
      }
    }
  }
});

/* ------------------------------------------------------------------ exploration (explore.js) */
global.DSUI = UI;
const XP = require(path.join(__dirname, "..", "..", "extractor", "web", "ui", "explore.js"));
const EVIL = '<script>alert(1)</script><img src=x onerror=alert(2)>"\'';
function watchState(extra) {
  return Object.assign({ seq: 5, samples: 5, state: "running", interval_s: 1, intervals: [0.5, 1, 2, 5], transport: "local",
    last_t: "2026-11-13T05:02:10Z", plan: { reads_per_s: 2, bytes_per_s: 16 }, cost: {},
    items: [{ id: "e:g_evil", label: EVIL, type: EVIL, value: EVIL, spark: [EVIL, "x"], changes: 1, last_change: "2026-11-13T05:02:09Z" },
      { id: "e:handled", label: "handled", type: "uint64_t[2]", changes: 4, spark: ["a", "b"],
        fields: [{ name: "[0]", value: 1, spark: [1, 2, 3], changes: 2 }, { name: EVIL, value: EVIL, spark: [EVIL], changes: 0 }] }],
    pool: null, compare: { from_seq: 1, to_seq: 5, changed: [{ name: EVIL, before: EVIL, now: 1, diff: null }], same: 0 } }, extra || {});
}

test("the watch card escapes every value read from the target and has no card inside", () => {
  const d = load(NAMES[0]);
  const s = UI.reduce(d.events, d.request);
  for (const lang of ["ko", "en"]) {
    const ui = UIS(lang, { started: true, open: {}, x: Object.assign(XP.xs({}), { cfg: { items: [{ expr: "g_evil" }], interval_s: 1, running: true },
      watch: watchState(), openTrack: { "e:handled": true } }) });
    const html = UI.render(s, ui);
    const card = html.slice(html.indexOf('id="observe"'), html.indexOf('id="report"'));
    assert.ok(card.length > 100, "the watch card is there, between next steps and the report");
    assert.ok(html.indexOf('id="next"') < html.indexOf('id="observe"'));
    assert.doesNotMatch(card, /<script|<img|<[^>]*\son[a-z]+=/);
    assert.match(card, /&lt;script&gt;/);
    assert.strictEqual(nestedCards(html), 0);
    assert.match(card, /<svg class="spark/);
  }
});

test("the watch card says why it stopped and the header says the target is gone", () => {
  const d = load(NAMES[0]);
  const s = UI.reduce(d.events, d.request);
  const ui = UIS("ko", { started: true, open: {}, x: Object.assign(XP.xs({}), { cfg: { items: [{ expr: "g" }], interval_s: 1, running: false },
    watch: watchState({ state: "stopped", reason: "target_exited", reason_detail: "process 1 exited" }) }) });
  const html = UI.render(s, ui);
  assert.match(html, /대상이 종료되었습니다/);
  assert.match(html, /data-act="obs-pause" disabled/);
  assert.match(XP.chipStatus(s, ui), /대상 종료/);
});

test("server fragments are placed in their slot only when the row is open; the stack shows the chosen frame", () => {
  const ui = UIS("ko", { open: { "th:7": true }, x: XP.xs({}) });
  ui.x.frag["th:7"] = { st: "ok", data: { frames: [{ i: 0, fn: "a" }, { i: 1, fn: "b" }], default_frame: 1 },
    html: { ko: '<button type="button" data-act="frame" data-k="th:7" data-i="0" data-fn="a" aria-current="false"></button>' +
      '<button type="button" data-act="frame" data-k="th:7" data-i="1" data-fn="b" aria-current="false"></button>' +
      '<div class="fr-loc" data-fr="0" hidden>A</div><div class="fr-loc" data-fr="1" hidden>B</div>' } };
  const out = UI.fillSlots('<button class="row-btn" data-act="tog" data-key="th:7" aria-expanded="false"></button><!--slot:th:7--><!--slot:th:8-->', {}, ui, 0);
  assert.match(out, /data-key="th:7" aria-expanded="true"/);
  assert.match(out, /data-i="1" data-sel="1" data-fn="b" aria-current="true"/);
  assert.match(out, /<div class="fr-loc" data-fr="1">B/);
  assert.match(out, /<div class="fr-loc" data-fr="0" hidden>/);
  assert.doesNotMatch(out, /slot:th:8/);
  ui.x.frame["th:7"] = 0;
  assert.match(UI.fillSlots("<!--slot:th:7-->", {}, ui, 0), /data-i="0" data-sel="1" data-fn="a" aria-current="true"/);
});

test("the exploration string table is complete in both languages", () => {
  assert.deepStrictEqual(Object.keys(XP.XSTR.ko).sort(), Object.keys(XP.XSTR.en).sort());
});

test("a pool that is only a part of a larger array says so in the card (ko and en)", () => {
  const d = load(NAMES[0]);
  const s = UI.reduce(d.events, d.request);
  const pool = { expr: "g_slots", count: 5459, total: 100000, truncated: true, elem_size: 48, elem_type: "slot", field: "state", per_cell: 2,
    bytes: 262032, legend: [{ cls: 0, value: 0, name: "FREE", count: 5000, delta: 0 }], cells: "0".repeat(2730), changed: 0, sel: null, sel_view: null, members: [] };
  const draw = (lang, p) => UI.render(s, UIS(lang, { started: true, open: {}, x: Object.assign(XP.xs({}), {
    cfg: { items: [], pool: { expr: "g_slots" }, interval_s: 1, running: true }, watch: watchState({ items: [], compare: null, pool: p }) }) }));
  for (const [lang, want] of [["en", /the array has 100,000 elements; only the first 5,459 are read/], ["ko", /배열은 원소 100,000개이고 앞의 5,459개만 읽습니다/]]) {
    const html = draw(lang, pool);
    assert.match(html.slice(html.indexOf('id="pool-sec"')), want);
  }
  assert.doesNotMatch(draw("en", Object.assign({}, pool, { count: 4096, total: 4096, truncated: false })), /only the first/);
});

test("the course of the diagnosis from the view is drawn under the checks, once, and never as a card in a card", () => {
  for (const n of NAMES) {
    const d = load(n);
    if (!d.events.some((e) => e.type === "verdict" && e.data.view)) continue;
    for (const lang of ["ko", "en"]) {
      const html = UI.render(UI.reduce(d.events, d.request), UIS(lang));
      assert.strictEqual((html.match(/id="dsv-timeline"/g) || []).length, 1, `${n} ${lang}`);
      assert.ok(html.indexOf('id="dsv-timeline"') > html.indexOf('id="checks"'), n);
      assert.ok(html.indexOf('id="dsv-timeline"') < html.indexOf('id="not-examined"') || html.indexOf('id="not-examined"') < 0, n);
      assert.strictEqual(nestedCards(html), 0, n);
    }
  }
});
