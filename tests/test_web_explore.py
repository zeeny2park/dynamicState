"""Process exploration in the web UI (docs/ui-redesign/EXPLORE_PROPOSAL_KO.md): the job-bound read routes
``/api/diagnose/{job_id}/...`` and the observation (watch) session, against real compiled targets.

* security: session token, Host / Origin, job ids, parameter validation with hard bounds, the pid / host / debug image
  come from the job only, a gone or reused pid is refused, reads are rate-limited per job;
* zero-stop and read-only: the target is never stopped or traced while it is read, and keeps running;
* fragments are inert HTML, and every string read from the target (thread names, symbol names, string values in its
  memory, an open file's path) is escaped (``hostile_strings`` fixture);
* the observation session: limits (items, bytes per sample, bytes per second, intervals), sampling, pause, compare,
  stop on target exit with the last values kept, idle stop and maximum lifetime.

Every target is started through tests/support/fixture_process.py; the server runs in-process on a free port.

Run: python3 -m unittest tests.test_web_explore
"""
import http.client
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from extractor.agent_runtime import AgentRuntime
from extractor.web import explore as X
from extractor.web.diagnose_jobs import DiagnoseJob
from extractor.web.server import run_server
from tests.support.fixture_process import fixture_popen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures", "real_runtime")
BENCH = os.path.join(ROOT, "benchmarks", "diagnosis_accuracy", "targets")
_UNSAFE = re.compile(r"<\s*(?:script|iframe|object|embed|link|meta|base|form|img|svg)\b|<[^>]*\son[a-z]+\s*=|<[^>]*=\s*[\"']?\s*javascript:", re.I)


def _build(tmp, src, name):
    out = os.path.join(tmp, name)
    subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", src, "-o", out], check=True)
    return out


def _start(argv, ready=b"READY"):
    proc = fixture_popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, name=os.path.basename(argv[0]))
    line = proc.stdout.readline()
    if ready not in line:
        proc.kill_tree()
        raise RuntimeError(f"{argv[0]} did not start: {line!r}")
    return proc


def _status(pid):
    with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
        st = dict(line.split(":", 1) for line in fh.read().splitlines() if ":" in line)
    return st["State"].strip(), int(st["TracerPid"].strip())


class ExploreCase(unittest.TestCase):
    """A real server, real targets, and finished jobs bound to them (made directly: no diagnosis has to run)."""
    targets = ()

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ds_explore_")
        cls.runtime = AgentRuntime(corpus_dir=os.path.join(cls.tmp, "corpus"))
        cls.server = run_server(cls.runtime, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.thread.start()
        cls.procs, cls.bins = {}, {}
        for name, src, args in cls.targets:
            cls.bins[name] = _build(cls.tmp, src, name)
            cls.procs[name] = _start([cls.bins[name]] + [a.format(tmp=cls.tmp) for a in args])

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.adapter.diagnose_jobs.explore.stop_all()
        except Exception:  # noqa: BLE001
            pass
        for p in cls.procs.values():
            p.kill_tree()
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @property
    def mgr(self):
        return self.server.adapter.diagnose_jobs

    def job(self, name, result=None, **params):
        j = DiagnoseJob({"pid": self.procs[name].pid, "language": "ko", "debug_image": self.bins[name], **params})
        j.state, j.result = "done", (result or {"verdict": "HEALTHY", "findings": []})
        with self.mgr._lock:
            self.mgr._jobs[j.job_id] = j
        return j

    def request(self, method, path, body=None, headers=None, token=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        hdrs = {"X-Session-Token": self.server.session_token} if token else {}
        if method == "POST":
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        conn.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        try:
            return resp.status, json.loads(data) if data else {}
        except ValueError:
            return resp.status, {"raw": data}

    def get(self, job, path, **kw):
        return self.request("GET", f"/api/diagnose/{job.job_id}/{path}", **kw)

    def post(self, job, path, body, **kw):
        return self.request("POST", f"/api/diagnose/{job.job_id}/{path}", body, **kw)

    def assertInert(self, html_by_lang):
        for lang in ("ko", "en"):
            h = html_by_lang[lang]
            self.assertIsNone(_UNSAFE.search(h), h[:400])
            self.assertNotIn("<!--", re.sub(r"<!--slot:[A-Za-z0-9_.:\-]+-->", "", h))


# ---------------------------------------------------------------------------------------------- security
class TestRouteSecurity(ExploreCase):
    targets = (("ok_busy_server", os.path.join(BENCH, "ok_busy_server.c"), ()),)

    ROUTES = ("chips", "thread/{tid}", "threads?name=serve0", "memory/maps", "memory/range?addr={addr}&len=16", "files",
              "modules", "vars?q=hand", "value?expr=handled", "lock?name=m", "watch/status")

    def setUp(self):
        self.j = self.job("ok_busy_server")
        pid = self.procs["ok_busy_server"].pid
        self.tid = sorted(int(x) for x in os.listdir(f"/proc/{pid}/task"))[-1]

    def paths(self):
        st, b = self.get(self.j, "value?expr=handled")
        addr = b["data"] and "0x10000"
        return [p.format(tid=self.tid, addr=addr) for p in self.ROUTES]

    def test_token_host_and_origin_are_required(self):
        for p in self.paths() + ["watch"]:
            method = "POST" if p == "watch" else "GET"
            body = {"items": []} if method == "POST" else None
            path = f"/api/diagnose/{self.j.job_id}/{p}"
            self.assertEqual(self.request(method, path, body, token=False)[0], 401, p)
            self.assertEqual(self.request(method, path, body, token=False, headers={"X-Session-Token": "forged"})[0], 401, p)
            self.assertEqual(self.request(method, path + ("&" if "?" in path else "?") + f"token={self.server.session_token}", body,
                                          token=False)[0], 401, p)
            self.assertEqual(self.request(method, path, body, headers={"Origin": "https://evil.example.com"})[0], 403, p)
            self.assertEqual(self.request(method, path, body, headers={"Host": "rebind.attacker.com"})[0], 403, p)
        for p in ("observation", "watch/stop"):
            path = f"/api/diagnose/{self.j.job_id}/{p}"
            self.assertEqual(self.request("POST", path, {}, token=False)[0], 401, p)

    def test_bad_job_ids_are_404(self):
        for bad in ("1", "../../etc/passwd", "A" * 22, "x" * 200, "inv_3f9a1c20b7d4"):
            for p in ("memory/maps", "thread/1", "value?expr=handled", "watch/status"):
                self.assertEqual(self.request("GET", f"/api/diagnose/{bad}/{p}")[0], 404, (bad, p))
            self.assertEqual(self.request("POST", f"/api/diagnose/{bad}/watch", {"items": []})[0], 404, bad)

    def test_parameters_are_validated_with_hard_bounds(self):
        bad = ["thread/abc", "thread/-1", "thread/1e9", "thread/99999999999",
               "memory/range?addr=zz&len=16", "memory/range?addr=0x10000&len=4097", "memory/range?addr=0x10000&len=0",
               "memory/range?addr=0x10000&len=-1", "memory/range?addr=0x1ffffffffffffffff&len=16",
               "memory/range?addr=0x10000&expr=handled&len=16", "memory/range?len=16",
               "memory/range?addr=0x10000&addr=0x20000&len=16",
               "value?expr=handled;rm%20-rf", "value?expr=$(id)", "value?expr=handled%22onload", "value?expr=a+b",
               "value?expr=" + "a" * 300, "value?expr=", "value", "vars?q=" + "a" * 65, "vars?q=a%3Cb",
               "threads?name=", "threads?name=a&limit=99999", "threads?name=a&filter=x", "lock?name=",
               "watch/status?after=-1", "watch/status?after=abc"]
        for p in bad:
            st, b = self.get(self.j, p)
            self.assertIn(st, (400, 404), (p, st, b))
            self.assertFalse(b.get("success"), p)
            self.assertInert(b["html"])

    def test_pid_host_and_paths_come_from_the_job_only(self):
        other = os.getpid()
        for extra in (f"&pid={other}", "&remote_host=evil.example.com", "&debug_image=/etc/passwd", "&companion_elf=/etc/shadow"):
            st, b = self.get(self.j, "value?expr=handled" + extra)
            self.assertEqual(st, 200, extra)
        x = self.mgr.explore.get(self.j)
        self.assertEqual(x.target.pid, self.procs["ok_busy_server"].pid)
        self.assertIsNone(x.target.remote)
        self.assertEqual(x.target.elf(), self.bins["ok_busy_server"])
        # a thread of another process is not readable through this job
        st, b = self.get(self.j, f"thread/{other}")
        self.assertEqual(st, 404)

    def test_pid_reuse_is_refused(self):
        j = self.job("ok_busy_server")
        j.start_ticks = (j.start_ticks or 0) + 1        # as if the pid now belonged to a process started later
        st, b = self.get(j, "memory/maps")
        self.assertEqual((st, b["error"]["code"]), (410, "TARGET_EXITED"))
        self.assertInert(b["html"])

    def test_reads_are_rate_limited_per_job(self):
        j = self.job("ok_busy_server")
        codes = [self.get(j, "files")[0] for _ in range(X.READ_BURST + 5)]
        self.assertIn(429, codes)
        self.assertEqual(codes[0], 200)
        # another job of the same target has its own budget
        self.assertEqual(self.get(self.job("ok_busy_server"), "files")[0], 200)

    def test_an_errored_job_is_not_explored(self):
        j = self.job("ok_busy_server")
        j.state = "error"
        self.assertEqual(self.get(j, "memory/maps")[0], 409)


class TestReadOnlyZeroStop(ExploreCase):
    targets = (("ok_busy_server", os.path.join(BENCH, "ok_busy_server.c"), ()),
               ("deadlock_pipeline", os.path.join(BENCH, "deadlock_pipeline.c"), ()))

    def test_every_read_route_leaves_the_target_running_untraced(self):
        j = self.job("ok_busy_server")
        pid = self.procs["ok_busy_server"].pid
        tids = sorted(int(x) for x in os.listdir(f"/proc/{pid}/task"))
        st, before = self.get(j, "value?expr=handled[0]")
        self.assertEqual(st, 200, before)
        stop = threading.Event()
        seen = []

        def watch_state():
            while not stop.is_set():
                try:
                    for tid in tids:
                        with open(f"/proc/{pid}/task/{tid}/status", encoding="utf-8") as fh:
                            txt = fh.read()
                        state = re.search(r"State:\s+(\S)", txt).group(1)
                        tracer = int(re.search(r"TracerPid:\s+(\d+)", txt).group(1))
                        seen.append((state, tracer))
                except OSError:
                    pass
                time.sleep(0.002)

        th = threading.Thread(target=watch_state, daemon=True)
        th.start()
        try:
            for p in [f"thread/{t}" for t in tids] + ["memory/maps", "files", "modules", "vars?q=", "value?expr=handled",
                                                      "value?expr=digest", "memory/range?expr=handled&len=16"]:
                st, b = self.get(j, p)
                if p.startswith("memory/range"):
                    self.assertIn(st, (200, 404), p)     # handled is an array, not a pointer: 404 is the honest answer
                    continue
                self.assertEqual(st, 200, (p, b))
                self.assertEqual(b["cost"]["stop_ms"], 0)
                self.assertEqual(b["cost"]["writes"], 0)
                self.assertInert(b["html"])
        finally:
            stop.set()
            th.join(2)
        self.assertTrue(seen)
        self.assertFalse([s for s in seen if s[0] in ("t", "T") or s[1] != 0], "a thread was stopped or traced")
        time.sleep(0.05)
        st, after = self.get(j, "value?expr=handled[0]")
        self.assertGreater(int(after["data"]["status"] == "OBSERVED"), 0)
        self.assertEqual(_status(pid)[1], 0)

    def test_deadlock_thread_lock_and_chips(self):
        res = {"verdict": "CONFIRMED_FAULT", "findings": [{"category": "DEADLOCK_INDICATORS", "observed": [],
               "subject_details": [{"kind": "thread", "name": "0"}, {"kind": "lock", "name": "m_out"}, {"kind": "lock", "name": "m_in"},
                                   {"kind": "function", "name": "ingest"}]}]}
        pid = self.procs["deadlock_pipeline"].pid
        ingest = next(int(t) for t in os.listdir(f"/proc/{pid}/task")
                      if open(f"/proc/{pid}/task/{t}/comm").read().strip() == "ingest")
        res["findings"][0]["subject_details"][0]["name"] = str(ingest)
        res["process_profile"] = {"threads": {"rows": [{"tid": ingest, "name": "ingest", "count": 1, "tids": [ingest]}]}, "locks": {"items": []}}
        j = self.job("deadlock_pipeline", result=res)
        t0 = time.monotonic()
        st, b = self.get(j, f"thread/{ingest}")
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertEqual(st, 200, b)
        fns = [f["fn"] for f in b["data"]["frames"]]
        self.assertIn("ingest", fns)
        self.assertEqual(fns[b["data"]["default_frame"]], "ingest")
        self.assertIn('data-act="goto-lock" data-name="m_out"', b["html"]["ko"])      # waits for m_out
        self.assertIn('data-act="goto-lock" data-name="m_in"', b["html"]["ko"])       # holds m_in
        st, b = self.get(j, "lock?name=m_out")
        self.assertEqual(st, 200, b)
        self.assertEqual(b["data"]["waiters"], 1)
        self.assertIn("m_out.__data.__owner", b["html"]["en"])
        st, b = self.get(j, "chips")
        self.assertEqual(st, 200, b)
        kinds = [c["kind"] for c in b["data"]["1"]]
        self.assertEqual(kinds, ["ch_thread", "ch_lock", "ch_lock"])
        self.assertInert(b["findings"]["1"])
        self.assertIn(f"pf:threads th:{ingest}", b["findings"]["1"]["ko"])


# ---------------------------------------------------------------------------------------------- hostile target strings
class TestHostileTargetStrings(ExploreCase):
    targets = (("hostile_strings", os.path.join(FIX, "hostile_strings.c"), ("{tmp}/<img src=x onerror=alert(9)>.log",)),)

    def test_strings_from_the_target_are_escaped_everywhere(self):
        j = self.job("hostile_strings")
        pid = self.procs["hostile_strings"].pid
        tids = sorted(int(x) for x in os.listdir(f"/proc/{pid}/task"))
        outs = []
        for p in [f"thread/{t}" for t in tids] + ["threads?name=%3Cimg%20src%3Dx%3E", "memory/maps", "files", "modules",
                                                  "vars?q=g_", "value?expr=g_evil", "value?expr=g_evil_ptr", "value?expr=g_note",
                                                  "value?expr=*g_evil_ptr", "memory/range?expr=g_evil_ptr&len=64"]:
            st, b = self.get(j, p)
            self.assertEqual(st, 200, (p, b))
            self.assertInert(b["html"])
            outs.append(b["html"]["ko"] + b["html"]["en"])
        st, b = self.get(j, "value?expr=g_evil")
        addr = re.search(r"@ (0x[0-9a-f]+)", b["html"]["en"]).group(1)
        st, b = self.get(j, f"memory/range?addr={addr}&len=64")
        self.assertEqual(st, 200)
        self.assertInert(b["html"])
        outs.append(b["html"]["en"])
        blob = "\n".join(outs)
        # the hostile strings were really read and shown, as text
        self.assertIn("&lt;img src=x&gt;", blob)                     # a thread name
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", blob)  # a string global
        self.assertIn("&lt;b onmouseover=alert(5)&gt;", blob)          # a char array inside a struct
        self.assertIn("onerror=alert(9)&gt;.log", blob)                 # an open file's path
        self.assertNotIn("<script", blob.lower())

    def test_watch_values_are_data_not_markup(self):
        j = self.job("hostile_strings")
        st, b = self.post(j, "watch", {"items": [{"expr": "g_evil"}, {"expr": "g_note"}], "interval_s": 0.5})
        self.assertEqual(st, 200, b)
        try:
            deadline = time.time() + 5
            while time.time() < deadline:
                st, b = self.get(j, "watch/status")
                if b["watch"]["samples"] >= 1:
                    break
                time.sleep(0.1)
            vals = json.dumps(b["watch"]["items"])
            self.assertIn("<script>", vals)          # raw data: the UI escapes it (tests/web_ui/ui.test.js)
        finally:
            self.post(j, "watch/stop", {})


# ---------------------------------------------------------------------------------------------- pool & range
class TestPoolAndRange(ExploreCase):
    targets = (("slot_server", os.path.join(FIX, "slot_server.c"), ()),
               ("overflow_ring", os.path.join(BENCH, "overflow_ring.c"), ()))

    def test_variable_search_offers_the_pool_view(self):
        j = self.job("slot_server")
        st, b = self.get(j, "vars?q=g_slots")
        self.assertEqual(st, 200, b)
        self.assertEqual(b["cost"]["reads"], 0)                       # DWARF only
        self.assertIn('data-act="pool-go" data-expr="g_slots" data-count="4096" data-field="state"', b["html"]["ko"])

    def test_pointer_follow_and_range(self):
        j = self.job("slot_server")
        st, b = self.get(j, "value?expr=g_last")
        self.assertEqual(st, 200, b)
        self.assertTrue(b["data"]["pointer"])
        self.assertIn('data-act="follow"', b["html"]["ko"])
        st, r = self.get(j, "memory/range?expr=g_last&len=48")
        self.assertEqual(st, 200, r)
        self.assertEqual(r["cost"]["bytes"], 8 + 48)
        self.assertEqual(r["data"]["len"], 48)

    def test_overflow_marks_come_from_the_diagnosis(self):
        res_path = os.path.join(ROOT, "tests", "fixtures", "explore", "overflow_ring.min.json")
        j = self.job("overflow_ring")
        x = self.mgr.explore.get(j)
        st, v = self.get(j, "value?expr=rb.buf")
        user = int(v["html"]["en"].split("rb.buf = ")[1].split()[0], 16) if "rb.buf = " in v["html"]["en"] else None
        self.assertIsNotNone(user, v)
        j.result = {"verdict": "CONFIRMED_FAULT", "findings": [], "report": {"section_d_detailed_inspection_results": {"checks": [
            {"actual_observations": {"memory_integrity": {"heap": {"defects": [{
                "overflowing_buffer": {"chunk_address": hex(user - 16), "user_address": hex(user), "usable_size": 72, "variable_path": "rb.buf"},
                "damage": {"bytes_past_usable_end": 24, "pattern": "repeated byte 0x6d"}}]}}}}]}}}
        st, r = self.get(j, "memory/range?expr=rb.buf&len=160")
        self.assertEqual(st, 200, r)
        self.assertEqual(r["data"]["addr"], hex(user - 16))
        h = r["html"]["ko"]
        self.assertEqual(h.count('class="b-over"'), 24)
        self.assertEqual(h.count('class="b-buf"'), 72)
        self.assertEqual(h.count('class="b-hdr"'), 16)
        self.assertFalse(os.path.exists(res_path) and False)
        del x


# ---------------------------------------------------------------------------------------------- watch session
class TestWatchSession(ExploreCase):
    targets = (("ok_busy_server", os.path.join(BENCH, "ok_busy_server.c"), ()),
               ("slot_server", os.path.join(FIX, "slot_server.c"), ()))

    def wait_samples(self, j, n, timeout=8.0):
        deadline = time.time() + timeout
        b = {}
        while time.time() < deadline:
            st, b = self.get(j, "watch/status")
            w = b.get("watch") or {}
            if w.get("samples", 0) >= n or w.get("state") == "stopped":
                return w
            time.sleep(0.1)
        return b.get("watch") or {}

    def test_limits_are_enforced(self):
        j = self.job("ok_busy_server")
        too_many = [{"expr": f"handled[{i % 2}]"} for i in range(X.WATCH_MAX_ITEMS + 1)]
        cases = [{"items": too_many}, {"items": [{"expr": "handled"}], "interval_s": 0.1}, {"items": [{"expr": "handled"}], "interval_s": 7},
                 {"items": [{"expr": "handled"}], "interval_s": "x"}, {"items": [{"expr": "x;y"}]}, {"items": [{"addr": "0x10", "type": "u128"}]},
                 {"items": [{"expr": "handled"}, {"expr": "handled"}]}, {"items": "handled"}, {"items": [{"expr": "handled"}], "running": "yes"},
                 {"pool": {"expr": "handled", "count": 2}}]
        for body in cases:
            st, b = self.post(j, "watch", body)
            self.assertEqual(st, 400, (body, b))
        js = self.job("slot_server")
        st, b = self.post(js, "watch", {"pool": {"expr": "g_slots", "count": 5000}})
        self.assertEqual(st, 400, b)
        with mock.patch.object(X, "SAMPLE_BYTES_MAX", 100 * 1024):
            st, b = self.post(js, "watch", {"pool": {"expr": "g_slots"}})
            self.assertEqual((st, b["error"]["code"]), (400, "BUDGET"))
        with mock.patch.object(X, "BYTES_PER_S_MAX", 300 * 1024):
            st, b = self.post(js, "watch", {"pool": {"expr": "g_slots"}, "interval_s": 0.5})
            self.assertEqual((st, b["error"]["code"]), (400, "BUDGET"))
            st, b = self.post(js, "watch", {"pool": {"expr": "g_slots"}, "interval_s": 1})
            self.assertEqual(st, 200, b)
        self.post(js, "watch/stop", {})

    def test_counter_changes_every_sample_and_pause_compare(self):
        j = self.job("ok_busy_server")
        st, b = self.post(j, "watch", {"items": [{"expr": "handled[0]"}, {"expr": "handled"}], "interval_s": 0.5})
        self.assertEqual(st, 200, b)
        try:
            w = self.wait_samples(j, 4)
            it = w["items"][0]
            self.assertGreaterEqual(it["changes"], 3, it)
            self.assertEqual(len(set(it["spark"])), len(it["spark"]), "the counter changed at every sample")
            self.assertEqual(w["cost"]["stop_ms"], 0)
            self.assertEqual(w["plan"]["reads_per_s"], 4.0)
            arr = w["items"][1]
            self.assertEqual([f["name"] for f in arr["fields"]], ["[0]", "[1]"])
            # pin now, then only what changed since
            st, b = self.post(j, "watch", {"items": [{"expr": "handled[0]"}, {"expr": "handled"}], "interval_s": 0.5, "pin": "now"})
            w = self.wait_samples(j, w["samples"] + 2)
            names = [c["name"] for c in w["compare"]["changed"]]
            self.assertIn("handled[0]", names)
            self.assertTrue(all(c["diff"] > 0 for c in w["compare"]["changed"]))
            # pause: no more samples
            st, b = self.post(j, "watch", {"items": [{"expr": "handled[0]"}], "interval_s": 0.5, "running": False})
            n = b["watch"]["samples"]
            time.sleep(1.2)
            st, b = self.get(j, "watch/status")
            self.assertEqual(b["watch"]["state"], "paused")
            self.assertEqual(b["watch"]["samples"], n)
        finally:
            self.post(j, "watch/stop", {})

    def test_sse_stream_delivers_samples(self):
        j = self.job("ok_busy_server")
        self.post(j, "watch", {"items": [{"expr": "handled[1]"}], "interval_s": 0.5})
        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            conn.request("GET", f"/api/diagnose/{j.job_id}/watch/events?after=0", headers={"X-Session-Token": self.server.session_token})
            resp = conn.getresponse()
            self.assertTrue(resp.getheader("Content-Type").startswith("text/event-stream"))
            buf, deadline = b"", time.time() + 6
            while buf.count(b"event: watch") < 3 and time.time() < deadline:
                buf += resp.fp.readline()
            conn.close()
            self.assertGreaterEqual(buf.count(b"event: watch"), 3)
        finally:
            self.post(j, "watch/stop", {})

    def test_pool_grid_samples_and_selection(self):
        j = self.job("slot_server")
        st, b = self.post(j, "watch", {"pool": {"expr": "g_slots", "sel": 7}, "interval_s": 1})
        self.assertEqual(st, 200, b)
        try:
            w = self.wait_samples(j, 3, timeout=10)
            p = w["pool"]
            self.assertEqual((p["count"], p["elem_size"], p["field"], p["per_cell"], len(p["cells"])), (4096, 48, "state", 1, 4096))
            self.assertEqual(sum(x["count"] for x in p["legend"]), 4096)
            self.assertEqual([x["name"] for x in p["legend"]][:2], ["SLOT_FREE", "SLOT_ACCEPTING"])
            self.assertEqual(p["sel_view"]["index"], 7)
            self.assertIn(".state", p["sel_view"]["fields"])
            self.assertEqual(w["plan"]["bytes_per_sample"], 4096 * 48 + 48)
            self.assertLessEqual(w["cost"]["bytes"], X.SAMPLE_BYTES_MAX)
            self.assertGreater(w["pool"]["changed"] + sum(abs(x["delta"]) for x in p["legend"]), 0, "the pool moves")
        finally:
            self.post(j, "watch/stop", {})

    def test_pool_over_4096_elements_is_bucketed(self):
        j = self.job("slot_server")
        x = self.mgr.explore.get(j)
        ws = X.WatchSession(x)
        geo = {"name": "g", "count": 10000, "elem_size": 4, "elem_type": "int", "field": "v", "field_offset": 0, "field_size": 4,
               "enum": {0: "Z", 1: "A", 2: "B"}, "members": []}
        pool = {"key": "g", "expr": "g", "count": 10000, "geo": geo, "bytes": 40000, "sel": None, "per_cell": 3, "classes": None,
                "base_counts": None, "prev_cells": None, "frame": None, "base": 0, "sel_last_change": None, "sel_prev": None, "start_seq": None}
        vals = [(i // 3) % 3 for i in range(10000)]
        data = b"".join(v.to_bytes(4, "little") for v in vals)
        ws.pool = pool
        ws._pool_frame(pool, data, None)
        cells = pool["frame"]["cells"]
        self.assertEqual(len(cells), 3334)              # ceil(10000 / 3): every cell is 3 elements, majority colour
        self.assertEqual(cells[:4], "0120")

    def test_target_exit_stops_and_keeps_the_last_values(self):
        tmpbin = self.bins["ok_busy_server"]
        proc = _start([tmpbin])
        try:
            j = DiagnoseJob({"pid": proc.pid, "language": "en", "debug_image": tmpbin})
            j.state, j.result = "done", {"verdict": "HEALTHY", "findings": []}
            with self.mgr._lock:
                self.mgr._jobs[j.job_id] = j
            self.post(j, "watch", {"items": [{"expr": "handled[0]"}], "interval_s": 0.5})
            w = self.wait_samples(j, 2)
            last = w["items"][0]["value"]
            proc.kill_tree()
            deadline = time.time() + 6
            while time.time() < deadline:
                st, b = self.get(j, "watch/status")
                if b["watch"]["state"] == "stopped":
                    break
                time.sleep(0.1)
            w = b["watch"]
            self.assertEqual((w["state"], w["reason"]), ("stopped", "target_exited"))
            self.assertGreaterEqual(w["items"][0]["value"], last)
            # a resume does not restart sampling of a gone target; reads say why
            st, b = self.post(j, "watch", {"items": [{"expr": "handled[0]"}], "interval_s": 0.5, "running": True})
            self.assertEqual(b["watch"]["state"], "stopped")
            st, b = self.get(j, "memory/maps")
            self.assertEqual((st, b["error"]["code"]), (410, "TARGET_EXITED"))
        finally:
            proc.kill_tree()

    def test_idle_stop_and_maximum_lifetime(self):
        j = self.job("ok_busy_server")
        with mock.patch.object(X, "IDLE_STOP_S", 1.0):
            self.post(j, "watch", {"items": [{"expr": "handled[0]"}], "interval_s": 0.5})
            ws = self.mgr.explore.watch(j, create=False)
            deadline = time.time() + 6
            while ws.state == "running" and time.time() < deadline:
                time.sleep(0.1)                   # nobody asks for samples
            self.assertEqual((ws.state, ws.reason), ("stopped", "idle"))
            self.assertFalse(ws.thread.is_alive())
        j2 = self.job("ok_busy_server")
        with mock.patch.object(X, "MAX_LIFETIME_S", 1.0):
            self.post(j2, "watch", {"items": [{"expr": "handled[0]"}], "interval_s": 0.5})
            ws = self.mgr.explore.watch(j2, create=False)
            deadline = time.time() + 6
            while ws.state == "running" and time.time() < deadline:
                self.get(j2, "watch/status")      # a client keeps asking: the lifetime still ends it
                time.sleep(0.2)
            self.assertEqual((ws.state, ws.reason), ("stopped", "max_lifetime"))

    def test_concurrent_watches_are_capped(self):
        jobs = [self.job("ok_busy_server") for _ in range(X.MAX_ACTIVE_WATCHES + 1)]
        try:
            codes = [self.post(j, "watch", {"items": [{"expr": "handled[0]"}], "interval_s": 5})[0] for j in jobs]
            self.assertEqual(codes[:X.MAX_ACTIVE_WATCHES], [200] * X.MAX_ACTIVE_WATCHES)
            self.assertEqual(codes[-1], 429)
        finally:
            for j in jobs:
                self.post(j, "watch/stop", {})


if __name__ == "__main__":
    unittest.main()
