"""Real end-to-end run of the web UI in headless Chromium: the real server (``python3 -m extractor.web.workspace``),
real diagnoses of compiled benchmark targets, the UI driven like a user.  Prints one JSON summary on stdout.

    python3 tests/web_ui/e2e_real.py [--shots DIR]

Every process it starts (the targets and the server) goes through tests/support/fixture_process.py and is killed in
``finally``.  Targets: deadlock_pipeline (by name), ok_idle_server, overflow_ring (reloaded mid-run), a target that
exits during the diagnosis, and ok_idle_server again behind a buffering /dynamicstate/ proxy (polling fallback).
None of them grows memory.  Run by tests/test_web_ui_browser.py when playwright is importable.
"""
import argparse
import gzip  # noqa: F401  (kept for parity with the fixture tooling)
import json
import os
import re
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from tests.support.fixture_process import fixture_popen  # noqa: E402
from tests.web_ui.prefix_proxy import PrefixProxy  # noqa: E402

TARGETS = os.path.join(ROOT, "benchmarks", "diagnosis_accuracy", "targets")
EXITING_C = r"""
#include <stdio.h>
#include <unistd.h>
int main(void) { printf("READY\n"); fflush(stdout); usleep(1200000); return 0; }
"""
POS_JS = """(() => { const o = {}; for (const id of ['banner','tiles','target','findings','checks']) {
  const n = document.getElementById(id); if (n) o[id] = Math.round(n.getBoundingClientRect().top + scrollY); }
  const ck = document.getElementById('checks'); if (ck) o.checks_view = Math.round(ck.getBoundingClientRect().top); o.fail = document.querySelectorAll('#checks .status-icon.FAIL').length; o.done = !!document.querySelector('#report');
  o.live = document.getElementById('live').textContent; return o; })()"""


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def build(tmp: str, name: str, src: str = None) -> str:
    out = os.path.join(tmp, name)
    if src is None:
        src = os.path.join(TARGETS, name + ".c")
    subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", src, "-o", out], check=True)
    return out


def wait_ready(proc, timeout=20.0) -> None:
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    buf, end = b"", time.monotonic() + timeout
    while time.monotonic() < end:
        for _k, _ in sel.select(0.2):
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError("target closed stdout before READY")
            buf += chunk
        if b"READY" in buf:
            return
        if proc.poll() is not None:
            raise RuntimeError("target exited before READY")
    raise RuntimeError("no READY")


def start_target(binary: str):
    proc = fixture_popen([binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, name=os.path.basename(binary))
    wait_ready(proc)
    return proc


def stop(proc) -> None:
    if proc is not None:
        try:
            proc.kill_tree()
        except Exception:  # noqa: BLE001
            pass


class Run:
    """Drives one diagnosis in the page and records what was seen."""

    def __init__(self, page, base: str, shots: str):
        self.page, self.base, self.shots = page, base, shots

    def shot(self, name: str, full=True) -> None:
        if self.shots:
            self.page.screenshot(path=os.path.join(self.shots, name + ".png"), full_page=full)

    def start(self, target: str, symptom: str = "") -> None:
        p = self.page
        p.goto(self.base)
        p.wait_for_selector("#form")
        p.fill('#form input[name="target"]', target)
        if symptom:
            p.fill('#form input[name="symptom"]', symptom)
        p.press('#form input[name="target"]', "Enter")

    def follow(self, timeout=90.0, reload_after_plan=False, scroll_to_checks=False) -> dict:
        """Sample positions until the report card appears; the first ✖ time, whether it came while running, movement."""
        p, rec = self.page, {"moved": {}, "first_fail_running": None, "reloaded": False, "live": []}
        tops, t0, end = {}, time.monotonic(), time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                st = p.evaluate(POS_JS)
            except Exception:  # noqa: BLE001 - navigation in progress
                time.sleep(0.1)
                continue
            if st["live"] and (not rec["live"] or rec["live"][-1] != st["live"]):
                rec["live"].append(st["live"])
            if st["fail"] and rec["first_fail_running"] is None:
                rec["first_fail_running"] = not st["done"]
                rec["first_fail_s"] = round(time.monotonic() - t0, 2)
            if scroll_to_checks and "checks" in st and not rec.get("scrolled"):
                rec["scrolled"] = True
                p.evaluate("scrollTo(0, document.getElementById('checks').getBoundingClientRect().top + scrollY - 40)")
                continue
            if reload_after_plan and not rec["reloaded"] and "checks" in st and not st["done"]:
                rec["reloaded"] = True
                rec["url_at_reload"] = p.url
                p.reload()
                tops = {}
                continue
            for k in ("banner", "tiles", "target", "findings", "checks", "checks_view"):
                if k in st:
                    if k in tops and tops[k] != st[k]:
                        rec["moved"].setdefault(k, []).append([tops[k], st[k]])
                    tops[k] = st[k]
            if st["done"]:
                break
            time.sleep(0.08)
        rec["done"] = bool(p.query_selector("#report"))
        rec["seconds"] = round(time.monotonic() - t0, 1)
        rec["url"] = p.url
        return rec

    def screen(self) -> dict:
        """What the final screen says."""
        return self.page.evaluate("""(() => {
          const t = (s) => (document.querySelector(s) || {}).textContent || '';
          const sub = t('#tiles .tile .s'); const m = sub.match(/✖ (\\d+) · \\? (\\d+) · ✔ (\\d+) · – (\\d+)/);
          return { badge: t('#banner .badge'), notice: t('#banner [role=status]') || t('#banner [role=alert]'),
                   checks_tile: t('#tiles .tile .v'), counts: m ? m.slice(1).map(Number) : null,
                   findings: document.querySelectorAll('#findings article.finding').length,
                   pictures: document.querySelectorAll('#findings .fbody svg, #findings .fbody .dsv-mem').length,
                   anchors: Array.from(document.querySelectorAll('a[href*="report"]')).map(a => a.getAttribute('href')),
                   job: new URLSearchParams(location.search).get('job') };
        })()""")

    def compare_with_report(self, scr: dict, lang: str) -> dict:
        """The job's own report (HTML and JSON) against the screen: verdict, findings, counts, anchors."""
        from extractor.human_report import compose
        req = self.page.request
        job = scr["job"]
        rj = req.get(f"{self.base}api/diagnose/{job}/report?format=json")
        res = json.loads(rj.text())
        comp = compose(res, res.get("report"), lang)
        rh = req.get(f"{self.base}api/diagnose/{job}/report?format=html&lang={lang}")
        html = rh.text()
        c = comp["counts"]
        anchors = sorted({a.split("#", 1)[1] for a in scr["anchors"] if "#" in a})
        missing = [a for a in anchors if f'id="{a}"' not in html]
        word = comp["verdict_line"]
        return {"report_status": rh.status, "csp": rh.headers.get("content-security-policy"),
                "verdict_same": res.get("verdict") in scr["badge"] or bool(re.search(re.escape(scr["badge"].split(": ", 1)[-1]), word)),
                "report_verdict": res.get("verdict"), "findings_same": scr["findings"] == len(comp["blocks"]),
                "counts_same": scr["counts"] == [c["found"], c["undecided"], c["clean"], c["not_run"]],
                "checks_tile_same": scr["checks_tile"] == str(c["run"]), "anchors": anchors, "anchors_missing": missing,
                "report_has_script": "<script" in html.lower()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", default="")
    args = ap.parse_args()
    if args.shots:
        os.makedirs(args.shots, exist_ok=True)
    from playwright.sync_api import sync_playwright
    out = {"runs": {}, "errors": []}
    tmp = tempfile.mkdtemp(prefix="ds_e2e_")
    server = targets = None
    targets = []
    try:
        bins = {n: build(tmp, n) for n in ("deadlock_pipeline", "ok_idle_server", "overflow_ring")}
        src = os.path.join(tmp, "exits_soon.c")
        with open(src, "w") as fh:
            fh.write(EXITING_C)
        bins["exits_soon"] = build(tmp, "exits_soon", src)
        port = free_port()
        server = fixture_popen([sys.executable, "-m", "extractor.web", "--host", "127.0.0.1", "--port", str(port),
                                "--corpus", os.path.join(tmp, "corpus")], cwd=ROOT, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, name="dynamicstate-server", max_rss_mib=1400)
        base = f"http://127.0.0.1:{port}/"
        for _ in range(100):
            try:
                urllib.request.urlopen(base, timeout=1).read()
                break
            except OSError:
                time.sleep(0.1)
        procs = {n: start_target(bins[n]) for n in ("deadlock_pipeline", "ok_idle_server", "overflow_ring")}
        targets += list(procs.values())
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            ctx = browser.new_context(viewport={"width": 1100, "height": 900})
            page = ctx.new_page()
            page.on("pageerror", lambda e: out["errors"].append(f"pageerror: {e}"))
            bad = []
            page.on("response", lambda r: bad.append(f"{r.status} {r.url}") if r.status >= 400 else None)
            run = Run(page, base, args.shots)

            # 0. name lookup errors and recent list
            run.start("no_such_process_xyz")
            page.wait_for_selector("#form .alert")
            out["name_not_found"] = page.inner_text("#form .alert")

            # 1. deadlock, by name, ko
            run.start("deadlock_pipeline", "the service stopped responding")
            rec = run.follow(scroll_to_checks=True)
            scr = run.screen()
            run.shot("real-deadlock-ko")
            rec["screen"], rec["vs_report"] = scr, run.compare_with_report(scr, "ko")
            rec["pid_resolved"] = scr["job"] is not None
            # the report link opens the real report; the per-part anchors resolve
            rp = ctx.new_page()
            href = page.get_attribute("#report a.btn", "href")
            rp.goto(base + href.split("#")[0] + "#verdict-detail")
            rec["report_page_title"] = rp.title()
            rec["report_anchor_found"] = rp.evaluate("!!document.getElementById('verdict-detail')")
            if args.shots:
                rp.screenshot(path=os.path.join(args.shots, "real-deadlock-report.png"), full_page=False)
            rp.close()
            # en toggle and dark mode on the finished screen
            page.click("#btn-lang")
            page.wait_for_timeout(200)
            rec["en_badge"] = page.inner_text("#banner .badge")
            run.shot("real-deadlock-en")
            page.click("#btn-theme")
            page.wait_for_timeout(200)
            rec["dark"] = page.evaluate("document.documentElement.classList.contains('dark')")
            run.shot("real-deadlock-en-dark")
            page.click("#btn-theme")
            page.click("#btn-lang")
            out["runs"]["deadlock"] = rec

            # 2. healthy, by pid
            run.start(str(procs["ok_idle_server"].pid), "general health check")
            rec = run.follow()
            scr = run.screen()
            run.shot("real-healthy-ko")
            rec["screen"], rec["vs_report"] = scr, run.compare_with_report(scr, "ko")
            out["runs"]["healthy"] = rec

            # 3. heap overflow with a picture; the page is reloaded mid-run and must resume
            run.start(str(procs["overflow_ring"].pid), "this program shows occasional strange data and I suspect memory corruption")
            rec = run.follow(reload_after_plan=True)
            scr = run.screen()
            run.shot("real-overflow-ko")
            rec["screen"], rec["vs_report"] = scr, run.compare_with_report(scr, "ko")
            out["runs"]["overflow"] = rec

            # 4. a target that exits during the diagnosis
            exits = start_target(bins["exits_soon"])
            targets.append(exits)
            run.start(str(exits.pid))
            rec = run.follow()
            rec["screen"] = run.screen()
            run.shot("real-exited-ko")
            out["runs"]["exited"] = rec

            # 5. recent diagnoses
            page.goto(base)
            page.wait_for_selector("#recent .it")
            out["recent"] = page.eval_on_selector_all("#recent a.it", "els => els.map(e => e.textContent.trim().slice(0, 80))")
            run.shot("real-idle-recent", full=False)

            # 6. behind a buffering /dynamicstate/ proxy: polling fallback, static files through the prefix
            with PrefixProxy(port, hold_events_s=8.0) as proxy:
                bad_before = len(bad)
                prun = Run(page, proxy.base, args.shots)
                prun.start(str(procs["ok_idle_server"].pid), "memory keeps growing slowly over hours")
                rec = prun.follow()
                rec["screen"] = prun.screen()
                prun.shot("real-proxy-healthy-ko")
                rec["status_polls"] = sum(1 for x in proxy.log if "/status" in x["path"])
                rec["sse_requests"] = sum(1 for x in proxy.log if "/events" in x["path"])
                rec["static"] = sorted({x["path"] for x in proxy.log if x["path"].endswith((".css", ".js"))})
                rec["http_errors"] = bad[bad_before:]
                out["runs"]["proxy"] = rec
            out["http_errors"] = [b for b in bad if "no_such_process" not in b]
            browser.close()
    finally:
        for proc in targets:
            stop(proc)
        stop(server)
        shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
