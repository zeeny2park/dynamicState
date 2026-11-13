// Renders the final state of each event file given on the command line (ko and en) and prints what the screen
// shows, as JSON, for tests/test_web_ui.py to compare with the report built from the same result.
"use strict";
const fs = require("fs");
const path = require("path");
const UI = require(path.join(__dirname, "..", "..", "extractor", "web", "ui", "ui.js"));

function shown(html) {
  const tile = html.match(/<div class="k">[^<]*<\/div><div class="v[^"]*">([^<]*)<\/div>/);
  const sub = html.match(/✖ (\d+)<\/span> · <span[^>]*>\? (\d+)<\/span> · <span[^>]*>✔ (\d+)<\/span> · <span[^>]*>– (\d+)/);
  const badge = html.match(/<section class="card card-tone banner[^"]*"[^>]*><div class="card-content"><div class="line1"><span class="badge[^"]*">([^<]*)<\/span>/);
  return {
    verdict_badge: badge ? badge[1] : null,
    checks_tile: tile ? tile[1] : null,
    counts: sub ? sub.slice(1, 5).map(Number) : null,
    findings: (html.match(/<article class="finding"/g) || []).length,
    rows_fail: (html.match(/status-icon FAIL/g) || []).length,
    bad: /undefined|\[object Object\]|NaN/.test(html.replace(/<div class="fbody dsv"[\s\S]*?<\/article>/g, "")),
    html_len: html.length,
  };
}

const out = {};
for (const file of process.argv.slice(2)) {
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  const events = doc.events || doc;
  const s = UI.reduce(events, doc.request || null);
  out[path.basename(file, ".json")] = {};
  for (const lang of ["ko", "en"]) {
    const html = UI.render(s, { lang, expanded: {}, elapsed: 0, reportUrl: "r.html" });
    out[path.basename(file, ".json")][lang] = shown(html);
  }
}
process.stdout.write(JSON.stringify(out));
