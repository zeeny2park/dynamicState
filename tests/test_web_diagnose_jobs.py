"""Web UI server side: non-blocking diagnosis jobs (start / events / status / jobs / report), the read-only engine
timeline listener, the new routing (`/`, `/legacy/`, `/legacy/workspace`) and the security checks on the new endpoints.

Most tests use a fake diagnose function and a fake session (no live process); one live test diagnoses a small
compiled fixture through start/events and through the synchronous endpoint and compares the verdicts.
"""

import http.client
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from extractor.agent_runtime import AgentRuntime
from extractor.diagnostic_methodology import DiagnosticCheck
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    ExpertDiagnosticEngine,
    InvestigationStep,
)
from extractor.web import diagnose_jobs
from extractor.web.diagnose_jobs import DiagnoseJobManager, is_valid_job_id
from extractor.web.server import _to_json_serializable, run_server


# ----------------------------------------------------------------------------------------- fakes
def _step(i, recipe, category="MEMORY_LEAK", domain="RESOURCE"):
    return InvestigationStep(step_id=f"step_{i}", recipe_id=recipe, recipe_name=f"Name of {recipe}", category=category,
                             domain=domain, rationale="r", priority=i, cost_score=1.0, safety_score=1.0,
                             expected_info_gain=0.5, multi_factor_score=0.5)


class FakeSession:
    """Just the attributes the listener reads (the same names as AdaptiveInvestigationSession)."""

    def __init__(self, pid):
        self.pid = pid
        self.investigation_id = "inv_fake00000001"
        self.raw_problem_statement = "memory keeps growing"
        self.classification_result = SimpleNamespace(candidate_categories=[("MEMORY_LEAK", 0.8)])
        self.target_assessment = SimpleNamespace(to_dict=lambda: {
            "pid": pid, "accessible": True, "thread_count": 3, "memory_regions_count": 40, "rss_kb": 1000,
            "companion_elf_valid": True, "dwarf_available": True, "build_id": "abcd", "limitations": []})
        self.plan = SimpleNamespace(steps=[_step(0, "RECIPE_A"), _step(1, "RECIPE_B"), _step(2, "RECIPE_C", "DEADLOCK")],
                                    current_step_index=0, total_steps=3, estimated_overhead_ms=5.0, plan_rationale="why")
        self.checks = []
        self.active_hypotheses = []
        self.rejected_hypotheses = []
        self.state = "CREATED"

    def get_plan(self):
        return {"steps": [vars(s) for s in self.plan.steps], "current_step_index": self.plan.current_step_index,
                "total_steps": 3, "estimated_overhead_ms": 5.0, "plan_rationale": "why"}

    def get_status(self):
        return {"state": self.state, "progress_percentage": 50}

    def add_check(self, recipe, status):
        c = DiagnosticCheck(check_id=f"chk_{recipe}", recipe_id=recipe, name=f"Check {recipe}")
        c.start()
        c.complete(status=status, technical_interpretation=f"{recipe} says {status}")
        self.checks.append(c)


class FakeEngine:
    corpus_dir = "/nonexistent"
    session_listener_factory = None

    def __init__(self):
        self.sessions = {}


def fake_diagnose_factory(gate=None, fail=False, calls=None):
    """A diagnose function that walks a fake timeline, optionally waiting on ``gate`` after the plan."""

    def fake(pid, debug_image=None, symptom=None, time_limit_s=None, engine=None, lang="en", target=None,
             symptom_fields=None):
        if calls is not None:
            calls.append({"pid": pid, "lang": lang, "symptom": symptom})
        s = FakeSession(pid)
        engine.sessions[s.investigation_id] = s
        listener = engine.session_listener_factory(s)

        def tl(event_type, details=None):
            if listener is not None:
                listener(s, {"timestamp": "t", "state": s.state, "event_type": event_type, "details": details or {}})

        tl("SESSION_CREATED")
        tl("PROBLEM_CLASSIFIED", {"primary_category": "MEMORY_LEAK", "confidence": 0.8, "is_vague": False})
        tl("TARGET_ASSESSED", {"accessible": True})
        tl("PLAN_GENERATED", {"total_steps": 3, "rationale": "why"})
        if gate is not None:
            gate.wait(10)
        for i, (recipe, status) in enumerate([("RECIPE_A", "PASS"), ("RECIPE_B", "FAIL"), ("RECIPE_C", "FAIL")]):
            s.add_check(recipe, status)
            s.plan.current_step_index = i
            tl("STEP_EXECUTED", {"step_id": f"step_{i}", "recipe_id": recipe, "eval_status": "SUPPORTED", "confidence": 0.7})
        s.active_hypotheses = [SimpleNamespace(hypothesis_id="h1", category="MEMORY_LEAK", domain="RESOURCE",
                                               status="CONFIRMED", confidence=0.9, problem_statement="p",
                                               confidence_basis="b", recommended_next_action="n",
                                               verification_execution_results=[{"k": i} for i in range(30)])]
        tl("HYPOTHESES_VERIFIED", {"active_count": 1, "rejected_count": 0})
        if fail:
            raise RuntimeError("boom")
        return ({"verdict": "CONFIRMED_FAULT", "investigation_id": s.investigation_id, "findings": [],
                 "report_path": "/corpus/reports/x.report.json", "checks_run": []}, "# summary")

    return fake


# ----------------------------------------------------------------------------------------- server helpers
class ServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="dynstate_jobs_")
        cls.runtime = AgentRuntime(corpus_dir=os.path.join(cls.tmp.name, "corpus"))
        cls.server = run_server(cls.runtime, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def install_fake(self, diagnose_fn):
        self.engine = FakeEngine()
        self.mgr = DiagnoseJobManager(lambda: self.engine, _to_json_serializable, diagnose_fn=diagnose_fn)
        self.server.adapter._diagnose_jobs = self.mgr
        return self.mgr

    def request(self, method, path, body=None, headers=None, token=True, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        hdrs = {}
        if token:
            hdrs["X-Session-Token"] = self.server.session_token
        if method == "POST":
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        out = (resp.status, {k.lower(): v for k, v in resp.getheaders()}, payload)
        conn.close()
        return out

    def jreq(self, method, path, body=None, **kw):
        st, hd, payload = self.request(method, path, body, **kw)
        return st, (json.loads(payload) if payload else {}), hd

    def sse(self, job_id, query="", headers=None):
        st, hd, payload = self.request("GET", f"/api/diagnose/{job_id}/events{query}", headers=headers)
        self.assertEqual(st, 200, payload[:200])
        self.assertTrue(hd["content-type"].startswith("text/event-stream"))
        self.assertEqual(hd.get("x-accel-buffering"), "no")
        events = []
        for block in payload.decode("utf-8").split("\n\n"):
            fields = dict(line.split(": ", 1) for line in block.split("\n") if ": " in line and not line.startswith(":"))
            if "data" in fields:
                env = json.loads(fields["data"])
                self.assertEqual(int(fields["id"]), env["seq"])
                self.assertEqual(fields["event"], env["type"])
                events.append(env)
        return events

    def wait_done(self, job_id, timeout=15):
        end = time.time() + timeout
        while time.time() < end:
            st, body, _ = self.jreq("GET", f"/api/diagnose/{job_id}/status")
            if body["job"]["state"] != "running":
                return body
            time.sleep(0.05)
        self.fail("job did not finish")

    def start(self, **extra):
        st, body, _ = self.jreq("POST", "/api/diagnose/start", {"pid": 4242, "language": "ko", **extra})
        self.assertEqual(st, 200)
        return body


# ----------------------------------------------------------------------------------------- behaviour
class TestJobEvents(ServerCase):
    def test_events_in_order_end_with_verdict(self):
        calls = []
        self.install_fake(fake_diagnose_factory(calls=calls))
        body = self.start(symptom="memory keeps growing")
        self.assertTrue(body["success"])
        self.assertTrue(is_valid_job_id(body["job_id"]))
        self.assertEqual(body["investigation_id"], "inv_fake00000001")
        self.assertEqual(calls[0]["lang"], "ko")
        events = self.sse(body["job_id"])
        self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))
        types = [e["type"] for e in events]
        self.assertEqual(types[:3], ["classified", "target", "plan"])
        self.assertEqual(types[-2:], ["verified", "verdict"])
        # every check_done is preceded by a check_start for the same step
        started = set()
        for e in events:
            if e["type"] == "check_start":
                started.add(e["data"]["step_id"])
            if e["type"] == "check_done":
                self.assertIn(e["data"]["step_id"], started)
        done = [e["data"] for e in events if e["type"] == "check_done"]
        self.assertEqual([d["status"] for d in done], ["PASS", "FAIL", "FAIL"])
        self.assertEqual(done[1]["name"], "Check RECIPE_B")
        self.assertEqual(done[1]["summary"], "RECIPE_B says FAIL")
        # one provisional finding per (category, domain): RECIPE_B (MEMORY_LEAK/RESOURCE) and RECIPE_C (DEADLOCK/RESOURCE)
        prov = [e["data"]["key"] for e in events if e["type"] == "finding_provisional"]
        self.assertEqual(prov, ["MEMORY_LEAK/RESOURCE", "DEADLOCK/RESOURCE"])
        self.assertEqual(len(prov), 2)
        plan = next(e for e in events if e["type"] == "plan")["data"]
        self.assertEqual([s["recipe_id"] for s in plan["steps"]], ["RECIPE_A", "RECIPE_B", "RECIPE_C"])
        verified = next(e for e in events if e["type"] == "verified")["data"]
        self.assertEqual(len(verified["hypotheses"][0]["verification_execution_results"]), 10)
        verdict = events[-1]["data"]
        self.assertEqual(verdict["result"]["verdict"], "CONFIRMED_FAULT")
        self.assertEqual(verdict["result"]["human_summary"], "# summary")
        self.assertEqual(verdict["human_summary"], "# summary")
        self.assertEqual(verdict["report_path"], "/corpus/reports/x.report.json")
        self.assertIn(f"api/diagnose/{body['job_id']}/report?format=html", verdict["report_urls"]["html"])
        self.assertIsNotNone(self.engine.sessions["inv_fake00000001"])

    def test_status_equals_concatenated_events_and_after(self):
        self.install_fake(fake_diagnose_factory())
        jid = self.start()["job_id"]
        events = self.sse(jid)
        status = self.wait_done(jid)
        self.assertEqual(status["job"]["state"], "done")
        self.assertEqual(status["job"]["verdict"], "CONFIRMED_FAULT")
        self.assertEqual(status["job"]["last_seq"], len(events))
        self.assertEqual(status["events"], events)
        st, part, _ = self.jreq("GET", f"/api/diagnose/{jid}/status?after=5")
        self.assertEqual(part["events"], events[5:])

    def test_reconnect_gets_only_what_was_missed(self):
        gate = threading.Event()
        self.install_fake(fake_diagnose_factory(gate=gate))
        jid = self.start()["job_id"]
        # running: poll until the plan is there, then reconnect after seq 2
        end = time.time() + 10
        while time.time() < end:
            _, body, _ = self.jreq("GET", f"/api/diagnose/{jid}/status")
            if body["job"]["last_seq"] >= 3:       # classified, target, plan
                break
            time.sleep(0.05)
        self.assertEqual(body["job"]["state"], "running")
        self.assertEqual(body["job"]["engine_state"], "CREATED")
        self.assertEqual(body["job"]["progress_percentage"], 50)
        first = body["events"]
        gate.set()
        self.wait_done(jid)
        rest_header = self.sse(jid, headers={"Last-Event-ID": "2"})
        rest_query = self.sse(jid, "?after=2")
        full = self.sse(jid)
        self.assertEqual(rest_header, full[2:])
        self.assertEqual(rest_query, full[2:])
        self.assertEqual(first, full[:len(first)])
        self.assertEqual(self.sse(jid, f"?after={len(full)}"), [])        # nothing missed: replay closes with no events

    def test_live_stream_follows_a_running_job(self):
        gate = threading.Event()
        self.install_fake(fake_diagnose_factory(gate=gate))
        jid = self.start()["job_id"]
        threading.Timer(0.3, gate.set).start()
        events = self.sse(jid)               # opened while running, closes after verdict
        self.assertEqual(events[-1]["type"], "verdict")
        self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))

    def test_second_start_for_same_pid_returns_running_job(self):
        gate = threading.Event()
        self.install_fake(fake_diagnose_factory(gate=gate))
        a = self.start()
        b = self.start()
        self.assertEqual(a["job_id"], b["job_id"])
        self.assertTrue(b["already_running"])
        other = self.start(pid=4243)
        self.assertNotEqual(other["job_id"], a["job_id"])
        gate.set()
        self.wait_done(a["job_id"])
        self.wait_done(other["job_id"])
        c = self.start()
        self.assertNotEqual(c["job_id"], a["job_id"])      # finished: a new job
        self.wait_done(c["job_id"])

    def test_failing_diagnosis_gives_error_event_and_finished_job(self):
        self.install_fake(fake_diagnose_factory(fail=True))
        jid = self.start()["job_id"]
        events = self.sse(jid)
        self.assertEqual(events[-1]["type"], "error")
        self.assertIn("boom", events[-1]["data"]["message"])
        self.assertNotIn("verdict", [e["type"] for e in events])
        status = self.wait_done(jid)
        self.assertEqual(status["job"]["state"], "error")
        self.assertIsNone(status["job"]["verdict"])
        st, _, _ = self.request("GET", f"/api/diagnose/{jid}/report")
        self.assertEqual(st, 404)

    def test_jobs_list_is_bounded_and_newest_first(self):
        self.install_fake(fake_diagnose_factory())
        ids = []
        for pid in range(3000, 3000 + diagnose_jobs.MAX_FINISHED_JOBS + 3):
            jid = self.start(pid=pid)["job_id"]
            self.wait_done(jid)
            ids.append(jid)
        st, body, _ = self.jreq("GET", "/api/diagnose/jobs")
        jobs = body["jobs"]
        self.assertEqual(len(jobs), diagnose_jobs.MAX_FINISHED_JOBS)
        self.assertEqual(jobs[0]["job_id"], ids[-1])
        self.assertEqual(jobs[0]["verdict"], "CONFIRMED_FAULT")
        self.assertEqual(jobs[0]["pid"], 3000 + diagnose_jobs.MAX_FINISHED_JOBS + 2)
        for k in ("investigation_id", "target_name", "state", "started_at", "finished_at"):
            self.assertIn(k, jobs[0])
        self.assertNotIn(ids[0], [j["job_id"] for j in jobs])
        self.assertEqual(self.jreq("GET", f"/api/diagnose/{ids[0]}/status")[0], 404)

    def test_report_formats_languages_and_single_renderer(self):
        self.install_fake(fake_diagnose_factory())
        jid = self.start()["job_id"]
        self.wait_done(jid)
        fake = mock.Mock(return_value={"success": True, "report_html": "<html>H</html>", "report_markdown": "# M",
                                       "report_json": "{\"a\": 1}"})
        with mock.patch("extractor.incident_report.export_incident_report", fake):
            st, hd, body = self.request("GET", f"/api/diagnose/{jid}/report?format=html&lang=ko")
            self.assertEqual((st, body), (200, b"<html>H</html>"))
            self.assertTrue(hd["content-type"].startswith("text/html"))
            self.assertIn("default-src 'none'", hd["content-security-policy"])
            self.assertEqual(hd["x-content-type-options"], "nosniff")
            st, hd, body = self.request("GET", f"/api/diagnose/{jid}/report?format=md&lang=ko")
            self.assertEqual((st, body), (200, b"# M"))
            self.assertTrue(hd["content-type"].startswith("text/markdown"))
            st, hd, body = self.request("GET", f"/api/diagnose/{jid}/report?format=json&lang=ko")
            self.assertEqual(json.loads(body), {"a": 1})
            self.assertEqual(fake.call_count, 1)                    # cached per (job, lang)
            self.request("GET", f"/api/diagnose/{jid}/report?lang=en")
            self.assertEqual(fake.call_count, 2)
            kw = fake.call_args.kwargs
            self.assertEqual(kw["language"], "en")
            self.assertIs(kw["session"], self.engine.sessions["inv_fake00000001"])
            for bad in kw:                                          # no client-chosen path ever reaches the exporter
                self.assertNotIn("path", bad)

    def test_report_of_running_job_is_409(self):
        gate = threading.Event()
        self.install_fake(fake_diagnose_factory(gate=gate))
        jid = self.start()["job_id"]
        try:
            self.assertEqual(self.request("GET", f"/api/diagnose/{jid}/report")[0], 409)
        finally:
            gate.set()
            self.wait_done(jid)


class TestListenerCannotBreakDiagnosis(unittest.TestCase):
    def test_raising_listener_is_swallowed_by_the_session(self):
        s = AdaptiveInvestigationSession.__new__(AdaptiveInvestigationSession)
        s.timeline, s.state = [], "CREATED"
        s.timeline_listener = mock.Mock(side_effect=RuntimeError("listener bug"))
        s._record_timeline_event("X", {"a": 1})
        self.assertEqual(len(s.timeline), 1)
        s.timeline_listener.assert_called_once()
        self.assertIs(s.timeline_listener.call_args.args[0], s)

    def test_default_has_no_listener(self):
        self.assertIsNone(AdaptiveInvestigationSession.timeline_listener)
        self.assertIsNone(ExpertDiagnosticEngine.session_listener_factory)

    def test_raising_factory_does_not_break_session_creation(self):
        with tempfile.TemporaryDirectory() as d:
            eng = ExpertDiagnosticEngine(corpus_dir=d)
            eng.session_listener_factory = mock.Mock(side_effect=RuntimeError("factory bug"))
            sess = eng.start_investigation(problem_statement="x", pid=None)
            self.assertIn(sess.investigation_id, eng.sessions)
            self.assertIsNone(sess.timeline_listener)

    def test_running_step_is_announced_by_the_read_only_watcher(self):
        job = diagnose_jobs.DiagnoseJob({"pid": 4242})
        tr = diagnose_jobs._TimelineTranslator(job, _to_json_serializable)
        sess = FakeSession(4242)
        sess.plan.steps[1].status = "RUNNING"
        tr.watch_running_steps(sess)
        end = time.time() + 5
        while not job.events and time.time() < end:
            time.sleep(0.02)
        job.finish("done", None)
        self.assertEqual([(e["type"], e["data"]["step_id"], e["data"]["index"]) for e in job.events],
                         [("check_start", "step_1", 1)])
        self.assertEqual(sess.plan.steps[1].status, "RUNNING")      # read only

    def test_translator_errors_lose_an_event_not_the_diagnosis(self):
        job = diagnose_jobs.DiagnoseJob({"pid": 4242})
        tr = diagnose_jobs._TimelineTranslator(job, _to_json_serializable)
        tr(object(), {"event_type": "PLAN_GENERATED", "details": {}})    # session lacks everything: no exception
        tr(object(), {"event_type": "STEP_EXECUTED"})
        self.assertEqual(job.events, [])


# ----------------------------------------------------------------------------------------- routing
class TestRouting(ServerCase):
    def test_root_is_new_ui_and_legacy_moved(self):
        st, hd, body = self.request("GET", "/", token=False)
        self.assertEqual(st, 200)
        self.assertIn(b"dynamicState", body)
        self.assertIn(self.server.session_token.encode(), body)
        self.assertIn(f"dynamicstate_session={self.server.session_token}", hd["set-cookie"])
        self.assertNotIn(b"runtime-summary-bar", body)
        st, _, legacy = self.request("GET", "/legacy/", token=False)
        self.assertEqual(st, 200)
        self.assertIn(b"runtime-summary-bar", legacy)
        st, _, ws = self.request("GET", "/legacy/workspace", token=False)
        self.assertEqual(st, 200)
        self.assertIn(b"dynamicState Workspace", ws)
        self.assertEqual(self.request("GET", "/legacy/workspace/", token=False)[0], 200)

    def test_legacy_assets_and_api_aliases_resolve(self):
        self.assertEqual(self.request("GET", "/legacy/static/app.js", token=False)[0], 200)
        self.assertEqual(self.request("GET", "/legacy/static/app.css", token=False)[0], 200)
        self.assertEqual(self.request("GET", "/static/app.js", token=False)[0], 200)      # old URL kept
        for p in ("/api/health", "/legacy/api/health", "/legacy/workspace/api/health"):
            st, body, _ = self.jreq("GET", p)
            self.assertEqual((st, body.get("status")), (200, "ok"), p)
        self.assertEqual(self.request("GET", "/legacy/api/health", token=False)[0], 401)

    def test_redirects_are_relative_so_a_path_prefix_works(self):
        for path, loc in (("/legacy", "legacy/"), ("/workspace", "legacy/workspace"), ("/workspace/", "../legacy/workspace")):
            st, hd, _ = self.request("GET", path, token=False)
            self.assertEqual((st, hd["location"]), (301, loc), path)
            self.assertFalse(hd["location"].startswith("/"))

    def test_static_files_of_the_ui_directory_and_no_absolute_urls_in_placeholder(self):
        with tempfile.TemporaryDirectory() as d:
            for name, text in (("index.html", "<html><head></head><body>ui</body></html>"), ("ui.css", "body{}"),
                               ("ui.js", "var a=1;")):
                with open(os.path.join(d, name), "w") as fh:
                    fh.write(text)
            old = self.server.static_dir
            self.server.static_dir = d
            try:
                st, hd, body = self.request("GET", "/ui.css", token=False)
                self.assertEqual((st, hd["content-type"].split(";")[0]), (200, "text/css"))
                st, hd, body = self.request("GET", "/ui.js", token=False)
                self.assertEqual(st, 200)
                self.assertEqual(self.request("GET", "/missing.js", token=False)[0], 404)
                for bad in ("/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/legacy/static/../../../../etc/passwd"):
                    st, _, body = self.request("GET", bad, token=False)
                    self.assertNotIn(b"root:", body, bad)
            finally:
                self.server.static_dir = old
        src = open(os.path.join(os.path.dirname(diagnose_jobs.__file__), "ui", "index.html"), encoding="utf-8").read()
        self.assertNotRegex(src, r'(?:src|href)="/(?!/)')        # no root-absolute URLs: they would break under /dynamicstate/

    def test_ui_dir_has_no_root_absolute_urls(self):
        ui = os.path.join(os.path.dirname(diagnose_jobs.__file__), "ui")
        for name in os.listdir(ui):
            if name.endswith((".html", ".js", ".css")):
                text = open(os.path.join(ui, name), encoding="utf-8").read()
                self.assertNotRegex(text, r"""(?:src|href)=["']/(?!/)""", name)
                self.assertNotRegex(text, r"""fetch\(\s*["'`]/""", name)


# ----------------------------------------------------------------------------------------- security
class TestSecurity(ServerCase):
    def setUp(self):
        self.install_fake(fake_diagnose_factory())

    def test_new_endpoints_require_the_session_token(self):
        jid = self.start()["job_id"]
        self.wait_done(jid)
        for method, path in (("POST", "/api/diagnose/start"), ("GET", "/api/diagnose/jobs"),
                             ("GET", f"/api/diagnose/{jid}/events"), ("GET", f"/api/diagnose/{jid}/status"),
                             ("GET", f"/api/diagnose/{jid}/report")):
            st, _, _ = self.request(method, path, {} if method == "POST" else None, token=False)
            self.assertEqual(st, 401, path)
            st, _, _ = self.request(method, path, {} if method == "POST" else None, headers={"X-Session-Token": "forged"}, token=False)
            self.assertEqual(st, 401, path)
            # a token in the query string is never accepted
            st, _, _ = self.request(method, f"{path}?token={self.server.session_token}", {} if method == "POST" else None, token=False)
            self.assertEqual(st, 401, path)
        # the HttpOnly cookie (what EventSource sends) is accepted
        st, _, _ = self.request("GET", f"/api/diagnose/{jid}/status", token=False,
                                headers={"Cookie": f"dynamicstate_session={self.server.session_token}"})
        self.assertEqual(st, 200)

    def test_cross_origin_and_untrusted_host_are_rejected(self):
        jid = self.start()["job_id"]
        self.wait_done(jid)
        for method, path in (("POST", "/api/diagnose/start"), ("GET", "/api/diagnose/jobs"),
                             ("GET", f"/api/diagnose/{jid}/events"), ("GET", f"/api/diagnose/{jid}/status"),
                             ("GET", f"/api/diagnose/{jid}/report")):
            body = {"pid": 4242} if method == "POST" else None
            st, hd, _ = self.request(method, path, body, headers={"Origin": "https://evil.example.com"})
            self.assertEqual(st, 403, path)
            self.assertNotIn("access-control-allow-origin", hd)
            st, _, _ = self.request(method, path, body, headers={"Host": "rebind.attacker.com"})
            self.assertEqual(st, 403, path)

    def test_start_requires_json_object(self):
        st, body, _ = self.jreq("POST", "/api/diagnose/start", raw=b"{bad")
        self.assertEqual((st, body["error"]["code"]), (400, "BAD_REQUEST"))
        for raw in (b"[1]", b'"s"', b"12"):
            self.assertEqual(self.jreq("POST", "/api/diagnose/start", raw=raw)[0], 400)
        st, body, _ = self.jreq("POST", "/api/diagnose/start", raw=b"pid=4242", headers={"Content-Type": "text/plain"})
        self.assertIn(st, (400, 415))

    def test_start_rejects_what_the_synchronous_endpoint_rejects(self):
        bad_bodies = [
            {}, {"pid": 1}, {"pid": 0}, {"pid": -5}, {"pid": True}, {"pid": "abc"}, {"pid": None},
            {"pid": 4242, "debug_image": 5}, {"pid": 4242, "symptom": ["x"]},
            {"pid": 4242, "time_limit_s": "x"}, {"pid": 4242, "time_limit_s": -1}, {"pid": 4242, "time_limit_s": True},
            {"pid": 4242, "language": "fr"},
            {"pid": 4242, "ssh_password": "pw"}, {"pid": 4242, "ssh_private_key": "-----BEGIN"},
            {"pid": 4242, "remote_host": "h", "ssh_port": "99999"}, {"pid": 4242, "remote_host": "h", "ssh_user": 5},
            {"pid": 4242, "symptom_kind": "not-a-kind"},
        ]
        for b in bad_bodies:
            sync = self.jreq("POST", "/api/diagnose", b)[1]
            new = self.jreq("POST", "/api/diagnose/start", b)[1]
            self.assertFalse(sync.get("success"), b)
            self.assertEqual(new, sync, b)
        self.assertEqual(self.jreq("GET", "/api/diagnose/jobs")[1]["jobs"], [])     # no job was created

    def test_job_ids_are_unguessable_and_bad_ids_are_404(self):
        a, b = self.start(pid=5001)["job_id"], self.start(pid=5002)["job_id"]
        for jid in (a, b):
            self.assertRegex(jid, r"^[A-Za-z0-9_-]{22}$")
        self.assertNotEqual(a, b)
        self.assertNotEqual(a[:8], b[:8])
        for bad in ("1", "../../etc/passwd", "..%2f..%2fetc", "A" * 22, "A" * 21 + "!", "x" * 200, "inv_3f9a1c20b7d4"):
            for action in ("events", "status", "report"):
                self.assertEqual(self.request("GET", f"/api/diagnose/{bad}/{action}")[0], 404, (bad, action))
        self.assertEqual(self.request("GET", f"/api/diagnose/{a}/other")[0], 404)
        self.assertEqual(self.request("GET", f"/api/diagnose/{a}")[0], 404)
        self.wait_done(a)
        self.wait_done(b)

    def test_bad_query_values_are_400_and_report_paths_are_not_a_thing(self):
        jid = self.start()["job_id"]
        self.wait_done(jid)
        for q in ("?after=abc", "?after=-1", "?after=1.5", "?after=" + "9" * 30):
            self.assertEqual(self.request("GET", f"/api/diagnose/{jid}/events{q}")[0], 400, q)
            self.assertEqual(self.request("GET", f"/api/diagnose/{jid}/status{q}")[0], 400, q)
        self.assertEqual(self.request("GET", f"/api/diagnose/{jid}/events", headers={"Last-Event-ID": "zz"})[0], 400)
        for q in ("?format=exe", "?format=../../etc/passwd", "?format=html&lang=fr", "?lang=../x"):
            self.assertEqual(self.request("GET", f"/api/diagnose/{jid}/report{q}")[0], 400, q)
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "should_not_exist.html")
            fake = mock.Mock(return_value={"success": True, "report_html": "<p>x</p>", "report_markdown": "x", "report_json": "{}"})
            with mock.patch("extractor.incident_report.export_incident_report", fake):
                st, _, body = self.request("GET", f"/api/diagnose/{jid}/report?format=html&output_path={target}&report_html_path={target}&path={target}")
            self.assertEqual((st, body), (200, b"<p>x</p>"))
            self.assertFalse(os.path.exists(target))
            for k in ("output_path", "report_html_path", "report_json_path", "template_path"):
                self.assertNotIn(k, fake.call_args.kwargs)

    def test_too_many_running_jobs_are_refused(self):
        gate = threading.Event()
        self.install_fake(fake_diagnose_factory(gate=gate))
        started = [self.start(pid=6000 + i) for i in range(diagnose_jobs.MAX_RUNNING_JOBS)]
        try:
            extra = self.start(pid=6999)
            self.assertFalse(extra["success"])
            self.assertEqual(extra["error"]["code"], "TOO_MANY_JOBS")
        finally:
            gate.set()
            for s in started:
                self.wait_done(s["job_id"])


# ----------------------------------------------------------------------------------------- live
LIVE_C = r"""
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static char *g_buf;
int main(void) {
    g_buf = malloc(4096);
    memset(g_buf, 7, 4096);
    for (;;) { usleep(50000); }
    return 0;
}
"""


@unittest.skipUnless(shutil.which("gcc"), "gcc is required for the live fixture")
class TestLiveParity(ServerCase):
    def test_start_events_verdict_equals_synchronous_endpoint(self):
        tmp = tempfile.mkdtemp(prefix="dynstate_jobs_live_")
        proc = None
        try:
            src, exe = os.path.join(tmp, "t.c"), os.path.join(tmp, "t")
            with open(src, "w") as fh:
                fh.write(LIVE_C)
            subprocess.run(["gcc", "-g", "-O0", src, "-o", exe], check=True)
            proc = subprocess.Popen([exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            time.sleep(0.3)
            req = {"pid": proc.pid, "debug_image": exe, "symptom": "health check", "time_limit_s": 10, "language": "en"}
            _, sync, _ = self.jreq("POST", "/api/diagnose", req)
            self.assertTrue(sync["success"], sync)
            _, started, _ = self.jreq("POST", "/api/diagnose/start", req)
            self.assertTrue(started["success"], started)
            events = self.sse(started["job_id"])
            types = [e["type"] for e in events]
            self.assertEqual(types[-1], "verdict", types)
            self.assertIn("plan", types)
            self.assertIn("check_done", types)
            self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))
            result = events[-1]["data"]["result"]
            self.assertEqual(result["verdict"], sync["result"]["verdict"])
            self.assertEqual(len(result["checks_run"]), len(sync["result"]["checks_run"]))
            self.assertEqual(sorted(f.get("category", "") for f in result["findings"]),
                             sorted(f.get("category", "") for f in sync["result"]["findings"]))
            # a real report through the one renderer
            st, hd, html = self.request("GET", f"/api/diagnose/{started['job_id']}/report?format=html&lang=en")
            self.assertEqual(st, 200)
            self.assertIn(b"<html", html.lower())
            st, hd, md = self.request("GET", f"/api/diagnose/{started['job_id']}/report?format=md&lang=ko")
            self.assertEqual(st, 200)
            self.assertEqual(self.request("GET", f"/api/diagnose/{started['job_id']}/report?format=json")[0], 200)
        finally:
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.wait(timeout=5)
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
