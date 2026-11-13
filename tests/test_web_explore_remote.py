"""Process exploration of a REMOTE (SSH) job, end to end.

Setup of tests/test_imp006_remote_diagnose.py: the natively built collector reads real fixture processes behind a
fake ``ssh`` executable on PATH (it logs every invocation, drops the host and runs the command locally).  A diagnosis is
started through ``POST /api/diagnose/start`` with ``remote_host``; then every exploration route is called.

Verified:
* nothing reads ``/proc/<pid>`` of the target in this process (``open`` / ``readlink`` / ``listdir`` / ``scandir`` /
  ``stat`` on it, any ``LocalTargetAdapter`` method): a pid on the remote side is never read locally;
* the 2 s minimum watch interval is enforced for SSH targets (and the observation samples through the daemon channel);
* the number of ``ssh`` processes started per request stays bounded (the channel is opened once per job).

Run: python3 -m unittest tests.test_web_explore_remote
"""
import builtins
import os
import re
import threading
import traceback
import unittest
from unittest import mock

import tests.test_imp006_remote_diagnose as base
from extractor.target_adapter import LocalTargetAdapter
from tests.support.explore_e2e import UNSAFE, Client, tids

FAKE_SSH_LOGGING = """#!/bin/sh
# test double for ssh: log the invocation, drop the options up to "--", drop the host, run the command locally
echo x >> "$DS_SSH_LOG"
while [ "$1" != "--" ]; do shift; done
shift
shift
exec sh -c "$1"
"""

MAX_SSH_PER_DIAGNOSIS_AND_EXPLORATION = 40     # measured in this file's run; a diagnosis alone is <= 15 (test_imp022)
MAX_SSH_PER_ROUTE = 4                          # one-shot reads reuse the daemon channel; a route may open the shell fallback
MAX_SSH_WATCH_SESSION = 3                      # a whole observation session (items + pool, several samples)


class LocalReadRecorder:
    """Records every in-process access to /proc/<pid> of the target and every LocalTargetAdapter call."""

    def __init__(self, pid):
        self.rx = re.compile(r"^/proc/%d(/|$)" % pid)
        self.hits = []
        self.patches = []
        self.lock = threading.Lock()

    def _wrap(self, fn, label):
        def inner(path, *a, **k):
            try:
                p = os.fspath(path)
            except TypeError:
                p = None
            if isinstance(p, bytes):
                p = p.decode("utf-8", "replace")
            if isinstance(p, str) and self.rx.match(os.path.normpath(p)):
                where = " < ".join("%s:%d" % (os.path.basename(f.filename), f.lineno) for f in reversed(traceback.extract_stack(limit=8)[:-1])
                                   if "extractor" in f.filename)
                with self.lock:
                    self.hits.append((label, p, where))
            return fn(path, *a, **k)
        return inner

    def __enter__(self):
        for mod, name in ((builtins, "open"), (os, "readlink"), (os, "listdir"), (os, "scandir"), (os, "stat"), (os, "lstat"),
                          (os.path, "isdir"), (os.path, "exists"), (os.path, "isfile"), (os, "access")):
            p = mock.patch.object(mod, name, self._wrap(getattr(mod, name), name))
            p.start()
            self.patches.append(p)
        for name, fn in list(vars(LocalTargetAdapter).items()):
            if callable(fn) and not name.startswith("__"):
                def mk(fn, name):
                    def inner(*a, **k):
                        with self.lock:
                            self.hits.append(("LocalTargetAdapter." + name, ""))
                        return fn(*a, **k)
                    return inner
                p = mock.patch.object(LocalTargetAdapter, name, mk(fn, name))
                p.start()
                self.patches.append(p)
        return self

    def __exit__(self, *exc):
        for p in reversed(self.patches):
            p.stop()


class RemoteExploreTests(base.RemoteDiagnoseTests):
    """Reuses the IMP-006 fixture plumbing (collector build, fixtures); its own tests are disabled below."""

    def setUp(self):
        self.ssh_log = os.path.join(self.tmp, "ssh.log.%d" % id(self))
        open(self.ssh_log, "w").close()
        with open(os.path.join(self.fakebin, "ssh"), "w") as fh:
            fh.write(FAKE_SSH_LOGGING)
        os.chmod(os.path.join(self.fakebin, "ssh"), 0o755)
        for key, val in (("PATH", self.fakebin + os.pathsep + os.environ["PATH"]), ("DS_SSH_LOG", self.ssh_log)):
            p = mock.patch.dict(os.environ, {key: val})
            p.start()
            self.addCleanup(p.stop)
        self.c = Client(os.path.join(self.tmp, "corpus_web_%d" % id(self)))
        self.addCleanup(self.c.close)

    def ssh_count(self):
        with open(self.ssh_log) as fh:
            return sum(1 for _ in fh)

    def remote_job(self, src, recorder_pid=None, **extra):
        proc, binary, _ = self._launch(src, ready=False)       # slot_server prints "READY <name>", not READY alone
        remote = {"remote_host": "board.example", "ssh_user": "root", "collector_path": self.collector}
        jid, status = self.c.diagnose(proc.pid, binary, **remote, **extra)
        self.assertEqual(status["job"]["state"], "done", status)
        self.assertEqual(status["job"]["remote_host"], "board.example")
        return proc, binary, jid

    def text(self, r, lang):
        return re.sub(r"<[^>]+>", " ", r["html"][lang])

    def assertFragment(self, r):
        self.assertTrue(r["success"], r)
        for lang in ("ko", "en"):
            self.assertIsNone(UNSAFE.search(r["html"][lang]))
        self.assertEqual(r["cost"]["transport"], "ssh")
        self.assertEqual(r["cost"]["writes"], 0)
        self.assertEqual(r["cost"]["stop_ms"], 0)

    # ------------------------------------------------------------------------------------------------
    def test_every_route_reads_through_the_adapter_and_ssh_stays_bounded(self):
        proc, binary, jid = self.remote_job("slot_server.c")
        pid, c = proc.pid, self.c
        n_diag = self.ssh_count()
        self.assertGreater(n_diag, 0)                       # the diagnosis really went over "ssh"
        tid = [t for t in tids(pid) if open(f"/proc/{pid}/task/{t}/comm").read().strip() == "slot_churn"][0]
        with open(f"/proc/{pid}/maps") as fh:
            first = next(ln for ln in fh if ln.rstrip().endswith(os.path.basename(binary)))
        addr = "0x" + first.split("-", 1)[0]
        per_route = {}
        rec = LocalReadRecorder(pid)
        with rec:
            def call(label, path):
                before = self.ssh_count()
                st, r = c.get(jid, path)
                per_route[label] = self.ssh_count() - before
                return st, r

            st, r = call("chips", "chips")
            self.assertEqual(st, 200, r)
            st, r = call("thread", f"thread/{tid}")
            self.assertEqual(st, 200, r)
            self.assertFragment(r)
            self.assertEqual(r["data"]["name"], "slot_churn")
            self.assertGreaterEqual(len(r["data"]["frames"]), 3)
            st, r = call("threads", "threads?name=slot_churn")
            self.assertEqual((st, r["data"]["count"]), (200, 1), r)
            self.assertFragment(r)
            st, r = call("maps", "memory/maps")
            self.assertEqual(st, 200, r)
            self.assertFragment(r)
            self.assertGreater(r["data"]["count"], 5)
            st, r = call("range_addr", f"memory/range?addr={addr}&len=64")
            self.assertEqual((st, r["data"]["status"]), (200, "OBSERVED"), r)
            self.assertFragment(r)
            self.assertRegex(self.text(r, "en").lower(), r"7f\s+45\s+4c\s+46")
            st, r = call("range_expr", "memory/range?expr=g_last&len=48")
            self.assertEqual(st, 200, r)
            self.assertFragment(r)
            self.assertEqual(r["data"]["len"], 48)
            st, r = call("files", "files")                   # documented: local targets only (API_CONTRACT)
            self.assertEqual((st, r["error"]["code"]), (409, "UNSUPPORTED_REMOTE"), r)
            st, r = call("modules", "modules")
            self.assertEqual(st, 200, r)
            self.assertFragment(r)
            self.assertIn(os.path.basename(binary), self.text(r, "en"))
            st, r = call("vars", "vars?q=g_slots")
            self.assertEqual(st, 200, r)
            self.assertIn("pool-go", r["html"]["en"])
            st, r = call("value", "value?expr=g_ticks")
            self.assertEqual((st, r["data"]["status"]), (200, "OBSERVED"), r)
            self.assertFragment(r)
            st, r = call("lock", "lock?name=g_nomutex")
            self.assertIn(st, (404,), r)                      # no such mutex in this fixture: a plain NOT_FOUND
            self.assertEqual(r["error"]["code"], "NOT_FOUND")
            st, r = call("watch_status", "watch/status")
            self.assertEqual(st, 200, r)

            # observation: the 2 s minimum is enforced for SSH targets
            for bad in (0.5, 1, 1.0):
                st, r = c.post(jid, "watch", {"items": [{"expr": "g_ticks"}], "interval_s": bad})
                self.assertEqual((st, r["error"]["code"]), (400, "INVALID_PARAM"), (bad, r))
                self.assertIn("2.0", r["error"]["message"])
            before = self.ssh_count()
            st, r = c.post(jid, "watch", {"items": [{"expr": "g_ticks"}, {"addr": addr, "type": "u32"}],
                                          "pool": {"expr": "g_slots", "count": 512}, "interval_s": 2})
            self.assertEqual(st, 200, r)
            w = r["watch"]
            self.assertEqual((w["transport"], w["interval_s"]), ("ssh", 2.0))
            self.assertEqual(w["intervals"], [2.0, 5.0])
            try:
                w = c.wait_samples(jid, 3, timeout=14)
                self.assertGreaterEqual(w["samples"], 3, w)
                self.assertEqual(w["state"], "running")
                self.assertEqual(w["cost"]["transport"], "ssh")
                ticks = [i for i in w["items"] if i["label"] == "g_ticks"][0]
                self.assertIsNotNone(ticks["value"])
                self.assertEqual(len(w["pool"]["cells"]), 512)
                # sample spacing is >= 2 s (first_t .. last_t over >= 2 sampling intervals)
                from datetime import datetime
                t0, t1 = (datetime.fromisoformat(w[k]) for k in ("first_t", "last_t"))
                self.assertGreaterEqual((t1 - t0).total_seconds(), 2 * 2.0 - 0.3, w)
                st, o = c.post(jid, "observation", {})
                self.assertEqual(st, 200, o)
            finally:
                c.post(jid, "watch/stop", {})
            per_route["watch_session"] = self.ssh_count() - before
        print("\n[explore-remote] ssh processes: diagnosis %d, per route %s" % (n_diag, per_route))
        self.assertEqual(rec.hits, [], "a remote job read the local /proc/<pid> or used the local adapter: %r" % rec.hits[:10])
        for label, n in per_route.items():
            limit = MAX_SSH_WATCH_SESSION if label == "watch_session" else MAX_SSH_PER_ROUTE
            self.assertLessEqual(n, limit, (label, per_route))
        self.assertLessEqual(self.ssh_count(), MAX_SSH_PER_DIAGNOSIS_AND_EXPLORATION, per_route)

    def test_locks_and_threads_of_a_deadlocked_remote_target(self):
        proc, binary, jid = self.remote_job("proc_thread_circular_deadlock.c")
        c = self.c
        threads = tids(proc.pid)
        rec = LocalReadRecorder(proc.pid)
        with rec:
            st, r = c.get(jid, "chips")
            self.assertEqual(st, 200, r)
            st, r = c.get(jid, "lock?name=g_mutex_a")
            self.assertEqual(st, 200, r)
            self.assertFragment(r)
            self.assertTrue(r["data"]["owner_tid"], r)
            self.assertGreaterEqual(r["data"]["waiters"], 1, r)
            for t in threads[1:]:
                st, r = c.get(jid, f"thread/{t}")
                self.assertEqual(st, 200, r)
                self.assertFragment(r)
        self.assertEqual(rec.hits, [], rec.hits[:10])
        # a thread id that is not on the target is a plain 404, read through the adapter
        st, r = c.get(jid, "thread/999999")
        self.assertEqual(st, 404, r)

    def test_a_pid_that_is_gone_on_the_remote_side_is_target_exited(self):
        proc, binary, jid = self.remote_job("slot_server.c")
        proc.kill()
        proc.wait(timeout=10)
        st, r = self.c.get(jid, "memory/maps")
        self.assertEqual((st, r["error"]["code"]), (410, "TARGET_EXITED"), r)


for _name in [n for n in dir(base.RemoteDiagnoseTests) if n.startswith("test_")]:
    setattr(RemoteExploreTests, _name, None)

if __name__ == "__main__":
    unittest.main()
