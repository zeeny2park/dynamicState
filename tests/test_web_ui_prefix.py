"""The UI behind the demo's reverse proxy, without a browser: served under /dynamicstate/ with the prefix stripped and
every response buffered (nginx without ``proxy_buffering off``).  Every static file of the page loads through the
prefix, the token reaches the page, a diagnosis started through the proxy completes for a client that polls
``status`` (the SSE stream arrives only in one piece at the end, which is why ui.js falls back to polling).

Run: python3 -m unittest tests.test_web_ui_prefix
"""
import http.client
import json
import os
import re
import tempfile
import threading
import time
import unittest

from extractor.agent_runtime import AgentRuntime
from extractor.web.diagnose_jobs import DiagnoseJobManager
from extractor.web.server import _to_json_serializable, run_server
from tests.test_web_diagnose_jobs import FakeEngine, fake_diagnose_factory
from tests.web_ui.prefix_proxy import PREFIX, PrefixProxy


class TestBehindBufferingPrefixProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="dynstate_prefix_")
        cls.server = run_server(AgentRuntime(corpus_dir=os.path.join(cls.tmp.name, "corpus")), host="127.0.0.1", port=0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.thread.start()
        cls.proxy = PrefixProxy(cls.server.server_address[1]).__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.proxy.__exit__(None, None, None)
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def get(self, path, method="GET", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy.port, timeout=30)
        try:
            conn.request(method, PREFIX + path, body=body, headers=headers or {})
            r = conn.getresponse()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
        finally:
            conn.close()

    def test_page_and_every_static_file_load_through_the_prefix(self):
        st, hd, html = self.get("")
        self.assertEqual(st, 200)
        self.assertIn(self.server.session_token.encode(), html)
        self.assertIn("dynamicstate_session=", hd.get("set-cookie", ""))
        refs = re.findall(rb'(?:href|src)="([^"#?]+)"', html)
        self.assertTrue({b"theme.css", b"ui.css", b"ui.js"} <= set(refs), refs)
        for ref in refs:
            if ref.startswith(b"legacy/") or ref in (b"./",):
                continue
            with self.subTest(ref=ref):
                self.assertFalse(ref.startswith(b"/"), "a root-absolute URL escapes the prefix")
                self.assertEqual(self.get(ref.decode())[0], 200)
        self.assertEqual(self.get("replay/index.json")[0], 200)
        st, hd, _ = self.get("legacy/")              # the removed old UI: a relative redirect that stays under the prefix
        self.assertEqual((st, hd.get("location")), (301, "../"))
        for private in ("view.py", "replay_gen.py", "__init__.py", "__pycache__/view.cpython-312.pyc"):
            with self.subTest(private=private):
                self.assertEqual(self.get(private)[0], 404, "the UI directory serves page assets only")

    def test_a_diagnosis_completes_by_polling_status_through_the_buffering_proxy(self):
        gate = threading.Event()
        mgr = DiagnoseJobManager(lambda: FakeEngine(), _to_json_serializable, diagnose_fn=fake_diagnose_factory(gate=gate))
        self.server.adapter._diagnose_jobs = mgr
        tok = {"X-Session-Token": self.server.session_token, "Content-Type": "application/json"}
        st, _, body = self.get("api/diagnose/start", "POST", json.dumps({"pid": 4242}), tok)
        started = json.loads(body)
        self.assertTrue(started["success"], started)
        jid = started["job_id"]
        # the stream is buffered: while the job waits on the gate, an SSE request through the proxy delivers nothing
        result = {}

        def sse():
            t0 = time.monotonic()
            result["sse"] = self.get(f"api/diagnose/{jid}/events", headers={"X-Session-Token": self.server.session_token})
            result["sse_s"] = time.monotonic() - t0

        th = threading.Thread(target=sse, daemon=True)
        th.start()
        time.sleep(1.0)
        self.assertNotIn("sse", result, "a buffering proxy must not deliver a running stream")
        # polling status works meanwhile and shows the events so far
        st, _, body = self.get(f"api/diagnose/{jid}/status?after=0", headers={"X-Session-Token": self.server.session_token})
        self.assertEqual(st, 200)
        early = json.loads(body)
        self.assertEqual(early["job"]["state"], "running")
        self.assertIn("plan", [e["type"] for e in early["events"]])
        gate.set()
        deadline, last, events = time.time() + 20, early["events"][-1]["seq"], list(early["events"])
        while time.time() < deadline:
            st, _, body = self.get(f"api/diagnose/{jid}/status?after={last}",
                                   headers={"X-Session-Token": self.server.session_token})
            got = json.loads(body)
            events += got["events"]
            last = events[-1]["seq"] if events else last
            if got["job"]["state"] != "running":
                break
            time.sleep(0.1)
        self.assertEqual(events[-1]["type"], "verdict")
        self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))
        th.join(20)
        self.assertIn("sse", result)
        self.assertGreater(result["sse_s"], 0.9)           # arrived only when the server closed the stream
        self.assertIn(b"event: verdict", result["sse"][2])


if __name__ == "__main__":
    unittest.main()
