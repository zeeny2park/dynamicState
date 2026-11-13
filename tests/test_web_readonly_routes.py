"""The web server is read-only towards the target: no HTTP route writes target memory, stops or signals the target,
runs an arbitrary or gdb command, or mutates / checkpoints / restores state.

How the routes are enumerated: ``API_ROUTES`` in extractor/web/server.py is the table of every (method, path pattern)
the server answers (``{name}`` = one path segment). This file checks

1. the table itself: every route is GET or POST under /api/, no path segment names a write / stop / command / mutate /
   restore / checkpoint / transition / explore / inject ... operation, and every POST is under /api/diagnose;
2. that the table is complete: every "/api/..." (or relative "api/...") literal in extractor/web/ (Python, JS, HTML) is
   a route of the table or a leading part of one;
3. the dispatch over real HTTP: each route of the table answers (a probe per route, in ``PROBES``), the same paths with
   the other method are 404, and the known dangerous paths of the removed UIs are 404 for GET and POST with a valid
   session token.

To add a route: add it to ``API_ROUTES`` (server.py) and add a probe for it to ``PROBES`` below (the test fails until
both exist). A path segment that matches ``FORBIDDEN_SEGMENT`` is refused unless ``ALLOWED_SEGMENTS`` lists it for that
route with the reason it acts on the server only (e.g. a sampler's "stop"); widen ``POST_PREFIXES`` only for POSTs that
never touch the target (server-side state such as a sampler or the report).
"""

import http.client
import json
import os
import re
import tempfile
import threading
import time
import unittest
from unittest import mock

from extractor.agent_runtime import AgentRuntime
from extractor.web import server as web_server
from extractor.web.diagnose_jobs import DiagnoseJobManager
from extractor.web.server import API_ROUTES, _to_json_serializable, is_api_route, run_server
from tests.test_web_diagnose_jobs import FakeEngine, fake_diagnose_factory

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(ROOT, "extractor", "web")

# A route path segment matching this names an operation the web server must never offer.
FORBIDDEN_SEGMENT = re.compile(
    r"write|poke|store|stop|kill|signal|pause|halt|interrupt|resume|continue|attach|detach|ptrace|gdb|command|cmd|"
    r"exec|shell|eval|mutat|restore|checkpoint|transition|explore|inject|replay|branch|capture|deploy|chat|llm|"
    r"arbitrary|set-?value|patch|delete|upload|determinism|restart",
    re.I,
)

# (method, pattern) -> {segment: reason}: a segment that matches FORBIDDEN_SEGMENT but names a server-side operation
# (for example stopping the server's own sampler, never the target). Every entry needs its reason.
ALLOWED_SEGMENTS = {}

# Every POST lives under one of these prefixes (POSTs start or steer server-side work, never a write to the target).
POST_PREFIXES = ("/api/diagnose",)

# One probe per route: path ({job_id} is replaced by a finished job's id), JSON body for POST, statuses that count as
# "the route answered". The probe only proves dispatch reaches the route; behaviour is tested elsewhere.
PROBES = {
    ("GET", "/api/health"): ("/api/health", None, {200}),
    ("GET", "/api/target/processes"): ("/api/target/processes?process_name=no_such_process_e5", None, {200}),
    ("POST", "/api/diagnose"): ("/api/diagnose", {"pid": 1}, {200}),          # pid 1 is refused by validation: no run
    ("POST", "/api/diagnose/start"): ("/api/diagnose/start", {"pid": 4242, "language": "en"}, {200}),
    ("GET", "/api/diagnose/jobs"): ("/api/diagnose/jobs", None, {200}),
    ("GET", "/api/diagnose/{job_id}/events"): ("/api/diagnose/{job_id}/events", None, {200}),
    ("GET", "/api/diagnose/{job_id}/status"): ("/api/diagnose/{job_id}/status", None, {200}),
    ("GET", "/api/diagnose/{job_id}/report"): ("/api/diagnose/{job_id}/report?format=json", None, {200}),
}

# Paths of the removed UIs and their routes that wrote, stopped, ran commands or changed state, plus a few read routes
# that only they used. Each must be 404 for GET and for POST, with a valid token.
DANGEROUS_PATHS = (
    "/api/write-memory", "/api/gdb-command", "/api/arbitrary-command", "/api/eval-expression",
    "/api/mutation", "/api/mutation-candidates", "/api/mutation/candidates", "/api/transition", "/api/transitions",
    "/api/transitions/T001", "/api/checkpoint", "/api/restore", "/api/explore", "/api/observe", "/api/capture",
    "/api/snapshot", "/api/snapshots", "/api/snapshots/s1/mutate", "/api/snapshots/s1/branch", "/api/snapshots/s1/replay",
    "/api/snapshots/s1/diff/s2", "/api/verify-determinism", "/api/runtime", "/api/runtime/verify_determinism",
    "/api/state-graph", "/api/state-lab/tree", "/api/states", "/api/states/s1", "/api/state/s1", "/api/impact/s1",
    "/api/objects/o1", "/api/capabilities", "/api/memory-summary", "/api/modules", "/api/provenance",
    "/api/workspace/chat", "/api/llm/status", "/api/investigation/chat", "/api/investigation/start",
    "/api/investigation/validate-target", "/api/investigation/save", "/api/investigation/load", "/api/investigations",
    "/api/investigations/x/step", "/api/watch/session/create", "/api/watch/session/x/stop", "/api/watch/sessions",
    "/api/watch/memory-map", "/api/watch/frame-locals", "/api/watch/thread-callstacks", "/api/watch/scan-pool",
    "/api/watch/eval-paths", "/api/watch/batch-execute", "/api/watch/until-condition", "/api/watch/recipe",
    "/api/watch/baseline/save", "/api/target/inspect-range", "/api/target/deploy-collector",
    "/api/target/find-processes", "/legacy/api/health", "/legacy/workspace/api/diagnose",
)

_API_LITERAL = re.compile(r"""(?<![A-Za-z0-9_.])/?api(?:/[A-Za-z0-9_\-{}.]*)*""")


def _api_literals():
    """(file, literal) for every "/api..." or "api/..." in extractor/web/ (Python, JS, HTML), comments included."""
    out = []
    for dp, _dn, fns in os.walk(WEB_DIR):
        if "__pycache__" in dp:
            continue
        for fn in fns:
            if not fn.endswith((".py", ".js", ".html")):
                continue
            path = os.path.join(dp, fn)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            for m in _API_LITERAL.finditer(text):
                lit = m.group(0)
                if not lit.startswith("/") and not text[m.end():m.end() + 1] in ("/", "?", '"', "'", "`"):
                    continue          # a bare word "api" in prose, not a URL
                lit = "/" + lit.lstrip("/")
                lit = re.sub(r"/\.+(?=/|$)", "", lit).rstrip("/.") or "/api"
                out.append((os.path.relpath(path, ROOT), lit))
    return out


def _covered_by_table(literal):
    """True when the literal is a route of the table, a concrete path of one, or a leading part of one."""
    lit_segs = literal.strip("/").split("/")
    for method, pattern in API_ROUTES:
        if literal == pattern or is_api_route(method, literal):
            return True
        pat_segs = pattern.strip("/").split("/")
        if len(lit_segs) <= len(pat_segs) and all(
                a == b or b.startswith("{") or a.startswith("{") for a, b in zip(lit_segs, pat_segs)):
            return True
    return False


class TestRouteTable(unittest.TestCase):
    def test_table_is_well_formed(self):
        self.assertTrue(API_ROUTES)
        self.assertEqual(len(set(API_ROUTES)), len(API_ROUTES), "duplicate route")
        for method, pattern in API_ROUTES:
            with self.subTest(route=(method, pattern)):
                self.assertIn(method, ("GET", "POST"))
                self.assertTrue(pattern.startswith("/api/"), pattern)
                self.assertNotIn("?", pattern)
                self.assertFalse(pattern.endswith("/"), pattern)

    def test_no_route_writes_stops_runs_commands_or_mutates(self):
        for method, pattern in API_ROUTES:
            for seg in pattern.strip("/").split("/"):
                if seg.startswith("{") or seg in ALLOWED_SEGMENTS.get((method, pattern), {}):
                    continue
                with self.subTest(route=(method, pattern), segment=seg):
                    self.assertIsNone(FORBIDDEN_SEGMENT.search(seg), f"{method} {pattern}: '{seg}' names a forbidden operation")

    def test_every_post_is_under_an_allowed_prefix(self):
        for method, pattern in API_ROUTES:
            if method == "POST":
                with self.subTest(route=pattern):
                    self.assertTrue(any(pattern == p or pattern.startswith(p + "/") for p in POST_PREFIXES), pattern)

    def test_forbidden_pattern_catches_the_removed_dangerous_routes(self):
        # guard the guard: the pattern must flag every write / stop / command / state-change path that used to exist
        for path in ("/api/write-memory", "/api/gdb-command", "/api/arbitrary-command", "/api/eval-expression",
                     "/api/mutation", "/api/transition", "/api/checkpoint", "/api/restore", "/api/explore",
                     "/api/snapshots/s/mutate", "/api/snapshots/s/replay", "/api/snapshots/s/branch", "/api/capture",
                     "/api/watch/session/x/stop", "/api/target/deploy-collector", "/api/workspace/chat",
                     "/api/investigation/chat", "/api/runtime/verify_determinism"):
            with self.subTest(path=path):
                self.assertTrue(any(FORBIDDEN_SEGMENT.search(s) for s in path.strip("/").split("/")), path)

    def test_every_api_literal_in_extractor_web_is_a_route(self):
        lits = _api_literals()
        self.assertTrue(any(lit == "/api/diagnose/start" for _f, lit in lits), "the scan found nothing: is it broken?")
        for fname, lit in lits:
            with self.subTest(file=fname, literal=lit):
                self.assertTrue(_covered_by_table(lit), f"{fname}: '{lit}' is not in API_ROUTES (server.py)")

    def test_every_route_has_a_probe(self):
        self.assertEqual(set(PROBES), set(API_ROUTES), "add a probe to PROBES for every route of API_ROUTES")


class TestDispatchOverHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="dynstate_routes_")
        cls.server = run_server(AgentRuntime(corpus_dir=os.path.join(cls.tmp.name, "corpus")), host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.thread.start()
        # a fake diagnosis (no live process): POST /api/diagnose/start returns a job that finishes at once
        cls.server.adapter._diagnose_jobs = DiagnoseJobManager(lambda: FakeEngine(), _to_json_serializable,
                                                               diagnose_fn=fake_diagnose_factory())
        st, body = cls._request("POST", "/api/diagnose/start", {"pid": 4242, "language": "en"})
        assert st == 200 and body.get("job_id"), body
        cls.job_id = body["job_id"]
        end = time.time() + 15
        while time.time() < end:
            if cls._request("GET", f"/api/diagnose/{cls.job_id}/status")[1]["job"]["state"] != "running":
                break
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    @classmethod
    def _request(cls, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=30)
        try:
            hdrs = {"X-Session-Token": cls.server.session_token}
            data = None
            if method == "POST":
                hdrs["Content-Type"] = "application/json"
                data = json.dumps(body if body is not None else {}).encode()
            conn.request(method, path, body=data, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read()
            try:
                parsed = json.loads(raw) if raw and resp.getheader("Content-Type", "").startswith("application/json") else {}
            except ValueError:
                parsed = {}
            return resp.status, parsed
        finally:
            conn.close()

    def test_every_route_answers(self):
        # the fake session has no report: the exporter is replaced (the report route itself is tested in test_web_diagnose_jobs)
        fake_export = mock.Mock(return_value={"success": True, "report_html": "<html></html>", "report_markdown": "#",
                                              "report_json": "{}"})
        with mock.patch("extractor.incident_report.export_incident_report", fake_export):
            for (method, pattern), (path, body, ok) in PROBES.items():
                with self.subTest(route=(method, pattern)):
                    st, out = self._request(method, path.replace("{job_id}", self.job_id), body)
                    self.assertIn(st, ok, out)

    def test_the_other_method_is_404(self):
        for (method, pattern), (path, _body, _ok) in PROBES.items():
            other = "POST" if method == "GET" else "GET"
            if (other, pattern) in PROBES:
                continue
            with self.subTest(route=(other, pattern)):
                st, out = self._request(other, path.replace("{job_id}", self.job_id).split("?")[0], {})
                self.assertEqual(st, 404, out)

    def test_dangerous_paths_are_404_with_a_valid_token(self):
        for path in DANGEROUS_PATHS:
            for method in ("GET", "POST"):
                with self.subTest(path=path, method=method):
                    st, _out = self._request(method, path, {"pid": os.getpid(), "cmd": "print 1", "value": 1})
                    if method == "GET" and path.startswith("/legacy/"):
                        self.assertEqual(st, 301)      # an old page URL: a redirect to the root page, never the API
                    else:
                        self.assertEqual(st, 404)
                    self.assertFalse(is_api_route(method, path))

    def test_unknown_job_actions_are_404(self):
        for action in ("restore", "write", "stop", "mutate", "gdb", "command", "bogus"):
            with self.subTest(action=action):
                self.assertEqual(self._request("GET", f"/api/diagnose/{self.job_id}/{action}")[0], 404)
                self.assertEqual(self._request("POST", f"/api/diagnose/{self.job_id}/{action}")[0], 404)

    def test_server_module_exposes_the_table(self):
        self.assertIs(web_server.API_ROUTES, API_ROUTES)


if __name__ == "__main__":
    unittest.main()
