"""Shared plumbing of the end-to-end exploration tests (tests/test_web_explore_{remote,nodebug,bigpool}.py):
a real server in-process, a diagnosis job started through ``POST /api/diagnose/start`` and every exploration route."""
import http.client
import json
import os
import re
import subprocess
import threading
import time

from extractor.agent_runtime import AgentRuntime
from extractor.web.server import run_server

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIX = os.path.join(ROOT, "tests", "fixtures", "real_runtime")
UNSAFE = re.compile(r"<\s*(?:script|iframe|object|embed|link|meta|base|form|img|svg)\b|<[^>]*\son[a-z]+\s*=", re.I)


def build(tmp, src, name, flags=("-g", "-O0"), strip=False):
    out = os.path.join(tmp, name)
    subprocess.run(["gcc", *flags, "-pthread", "-Wl,--build-id=sha1", src, "-o", out], check=True, capture_output=True, timeout=120)
    if strip:
        subprocess.run(["strip", out], check=True)
    return out


class Client:
    def __init__(self, corpus_dir):
        self.runtime = AgentRuntime(corpus_dir=corpus_dir)
        self.server = run_server(self.runtime, host="127.0.0.1", port=0)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    @property
    def mgr(self):
        return self.server.adapter.diagnose_jobs

    def close(self):
        try:
            self.mgr.explore.stop_all()
        except Exception:  # noqa: BLE001
            pass
        self.server.shutdown()
        self.server.server_close()

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        hdrs = {"X-Session-Token": self.server.session_token}
        if method == "POST":
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        try:
            return resp.status, (json.loads(data) if data else {})
        except ValueError:
            return resp.status, {"raw": data}

    def diagnose(self, pid, debug_image=None, timeout=120, **params):
        body = {"pid": pid, "language": "en", **params}
        if debug_image:
            body["debug_image"] = debug_image
        st, b = self.request("POST", "/api/diagnose/start", body)
        assert st == 200, (st, b)
        jid = b["job_id"]
        end = time.time() + timeout
        while time.time() < end:
            st, s = self.request("GET", f"/api/diagnose/{jid}/status")
            if s["job"]["state"] != "running":
                return jid, s
            time.sleep(0.2)
        raise AssertionError("diagnosis did not finish")

    def get(self, jid, path):
        return self.request("GET", f"/api/diagnose/{jid}/{path}")

    def post(self, jid, path, body):
        return self.request("POST", f"/api/diagnose/{jid}/{path}", body)

    def wait_samples(self, jid, n, timeout=10.0):
        end, w = time.time() + timeout, {}
        while time.time() < end:
            st, b = self.get(jid, "watch/status")
            w = b.get("watch") or {}
            if w.get("samples", 0) >= n or w.get("state") == "stopped":
                return w
            time.sleep(0.1)
        return w


def tids(pid):
    return sorted(int(x) for x in os.listdir(f"/proc/{pid}/task"))
