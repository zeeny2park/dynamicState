"""IMP-006 (remote): the single ``diagnose`` entry point against a REMOTE target.

The "remote" side is real: the natively built collector (daemon channel) reads the memory of real fixture
processes behind a local ``sh`` transport (injected runner / stream opener for the Python API, a fake ``ssh``
executable on PATH for the MCP / CLI / web interfaces).  Nothing is injected into the evidence: the same
fixtures are diagnosed locally and "remotely" and the results are compared.

 a. deadlock fixture: same verdict, categories and subjects remote vs local
 b. IMP-008 leak fixture: same growth-owner path (exercises remote glibc identification + heap walk)
 c. IMP-009 overrun fixture: same overflowing buffer / victim
 d. missing debug image on a remote target -> INCONCLUSIVE, ``missing_debug_image``
 e. unreachable host / SSH failure -> INCONCLUSIVE, ``target_unreachable``, no exception, no credentials
 f. MCP, CLI and web agree on the remote target
 g. a planned-only session cannot produce a report
 + remote glibc identification, large-slice reads through the 64 KiB collector, struct-member mutex widening
"""

import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import scripts.mcp_server as mcp_srv
from extractor.expert_diagnostic_engine import ExpertDiagnosticEngine, TargetSpec, diagnose
from extractor.heap_walker import STATUS_OK, HeapWalker
from extractor.target_abi import detect_target_abi
from extractor.target_adapter import LocalTargetAdapter, RemoteSshTargetAdapter
from tests.support.fixture_process import fixture_popen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "real_runtime")
COLLECTOR_SRC = os.path.join(ROOT, "target", "collector")
MEMORY_SYMPTOM = "memory usage of this process keeps growing"
FAULT = ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT")

FAKE_SSH = """#!/bin/sh
# test double for ssh: drop the options up to "--", drop the host, run the command locally
while [ "$1" != "--" ]; do shift; done
shift
shift
exec sh -c "$1"
"""


def local_sh_runner(args, timeout, input_bytes=None):
    res = subprocess.run(["sh", "-c", args[-1]], input=input_bytes, capture_output=True, timeout=timeout)
    return res.returncode, res.stdout.decode(), res.stderr.decode()


def local_sh_stream(args):
    return subprocess.Popen(["sh", "-c", args[-1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)


def shape(d):
    cats = sorted({str(f["category"]) for f in d["findings"]})
    subj = sorted({s for f in d["findings"] for s in f["subjects"] if not s.isdigit()})
    return d["verdict"], cats, subj


@unittest.skipUnless(shutil.which("gcc") and shutil.which("make") and os.path.exists("/proc/self/mem"),
                     "gcc/make/procfs not available")
class RemoteDiagnoseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp006r_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        build = os.path.join(cls.tmp, "build")
        shutil.copytree(COLLECTOR_SRC, build,
                        ignore=shutil.ignore_patterns("*.o", "dist", "dynamicstate-collector", "test_crypto"))
        r = subprocess.run(["make", "-C", build, "dynamicstate-collector"], capture_output=True, text=True)
        if r.returncode != 0:
            raise unittest.SkipTest("native collector build failed: " + r.stderr[-300:])
        cls.collector = os.path.join(build, "dynamicstate-collector")
        cls.corpus = os.path.join(cls.tmp, "corpus")
        cls.bins = {}
        cls.fakebin = os.path.join(cls.tmp, "fakebin")
        os.makedirs(cls.fakebin)
        with open(os.path.join(cls.fakebin, "ssh"), "w") as fh:
            fh.write(FAKE_SSH)
        os.chmod(os.path.join(cls.fakebin, "ssh"), 0o755)

    def _binary(self, src):
        if src not in self.bins:
            out = os.path.join(self.tmp, os.path.splitext(src)[0])
            subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", os.path.join(FIXTURES, src),
                            "-o", out], check=True, capture_output=True, timeout=120)
            self.bins[src] = out
        return self.bins[src]

    def _launch(self, src, ready=True):
        binary = self._binary(src)
        proc = fixture_popen([binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

        def _kill():
            try:
                proc.kill()
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                pass
            proc.stdout.close()

        self.addCleanup(_kill)
        lines, buf = [], b""
        deadline = time.monotonic() + 60
        while ready and "READY" not in lines:
            self.assertLess(time.monotonic(), deadline, "fixture %s did not print READY" % src)
            r, _, _ = select.select([proc.stdout], [], [], 0.2)
            if r:
                chunk = os.read(proc.stdout.fileno(), 65536)
                self.assertTrue(chunk, "fixture %s exited before READY" % src)
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    lines.append(line.decode().strip())
        if not ready:
            time.sleep(0.6)
        time.sleep(0.1)
        self.assertIsNone(proc.poll(), "fixture exited prematurely")
        return proc, binary, lines

    def _spec(self, **kw):
        base = dict(remote_host="board.example", ssh_user="root", collector_path=self.collector,
                    command_runner=local_sh_runner, stream_opener=local_sh_stream)
        base.update(kw)
        return TargetSpec(**base)

    def _local_and_remote(self, src, symptom=None, ready=True):
        out = {}
        for mode in ("local", "remote"):
            proc, binary, lines = self._launch(src, ready=ready)
            kw = {"target": self._spec()} if mode == "remote" else {}
            res = diagnose(proc.pid, binary, symptom, corpus_dir=self.corpus, include_report=True, **kw).to_dict()
            out[mode] = (res, lines)
        return out

    # ------------------------------------------------------------------------------------------ a
    def test_a_deadlock_same_as_local(self):
        proc, binary, _ = self._launch("proc_thread_circular_deadlock.c", ready=False)
        loc = diagnose(proc.pid, binary, corpus_dir=self.corpus).to_dict()
        rem = diagnose(proc.pid, binary, corpus_dir=self.corpus, target=self._spec()).to_dict()
        print("\n[a] local %s remote %s" % (shape(loc), shape(rem)[:2]))
        self.assertIn(loc["verdict"], FAULT)
        self.assertEqual(shape(rem), shape(loc))
        self.assertTrue({"g_mutex_a", "g_mutex_b"} <= set(shape(rem)[2]))
        self.assertEqual(rem["target"]["transport"], "ssh")
        self.assertEqual(rem["target"]["host"], "board.example")
        self.assertEqual(rem["target"]["pid"], proc.pid)
        self.assertEqual(rem["target"]["abi"]["status"], "DETECTED")
        self.assertTrue(rem["collection_impact"]["zero_stop"])
        kinds = {n["kind"] for n in rem["not_covered"]}
        self.assertIn("remote_limitation", kinds)           # TLS / running stacks / library symbols are recorded
        self.assertEqual({n["item"] for n in rem["not_covered"] if n["kind"] == "remote_limitation"},
                         {"thread_local_storage", "running_thread_stacks", "library_symbolisation"})
        self.assertNotIn("remote_limitation", {n["kind"] for n in loc["not_covered"]})

    def test_a2_struct_member_mutexes_are_named_remotely(self):
        """The lock-candidate widening (variable.member) also runs remotely, through the thread syscall data of
        the collector (without it the remote result was INCONCLUSIVE)."""
        proc, binary, _ = self._launch("proc_thread_member_mutex_deadlock.c", ready=False)
        loc = diagnose(proc.pid, binary, corpus_dir=self.corpus).to_dict()
        rem = diagnose(proc.pid, binary, corpus_dir=self.corpus, target=self._spec()).to_dict()
        self.assertIn(loc["verdict"], FAULT)
        self.assertEqual(shape(rem), shape(loc))
        self.assertTrue({"g_acct_a.guard", "g_acct_b.guard"} <= set(shape(rem)[2]), shape(rem))

    # ------------------------------------------------------------------------------------------ b
    def test_b_leak_owner_same_as_local(self):
        res = self._local_and_remote("proc_leak_append_list.c", MEMORY_SYMPTOM)
        (loc, _), (rem, _) = res["local"], res["remote"]

        def li(d):
            for c in d["report"]["section_d_detailed_inspection_results"]["checks"]:
                x = (c.get("actual_observations") or {}).get("leak_investigation")
                if isinstance(x, dict) and c["recipe_id"] == "RECIPE_PROCESS_MEMORY_GROWTH":
                    return x
            self.fail("no leak_investigation")

        l, r = li(loc), li(rem)
        print("\n[b] remote: %s" % r.get("summary"))
        self.assertEqual(r["verdict"], l["verdict"], r.get("limitations"))
        self.assertGreaterEqual(r["walks"], 3)
        paths = lambda x: sorted(o["variable_path"] for o in x["growth_owners"])
        # Local and remote are two separate observation windows on a live growing list: secondary roots of the same
        # structure (e.g. a tail pointer) may or may not show growth inside a given window (seen on the x86_64
        # runner: local reported head + tail, remote only head). The owner that the finding names must agree.
        self.assertTrue(paths(r))
        self.assertTrue(paths(l))
        self.assertTrue(set(paths(r)) & set(paths(l)), (paths(r), paths(l)))
        leak = [f for f in rem["findings"] if f["category"] == "MEMORY_LEAK"]
        self.assertEqual(len(leak), 1, rem["findings"])
        self.assertTrue(set(paths(r)) & set(leak[0]["subjects"]), (paths(r), leak[0]["subjects"]))
        self.assertEqual(shape(rem)[:2], shape(loc)[:2])
        self.assertTrue(rem["collection_impact"]["zero_stop"])
        self.assertGreater(rem["collection_impact"]["bytes_read"], 0)

    # ------------------------------------------------------------------------------------------ c
    def test_c_overrun_same_as_local(self):
        res = self._local_and_remote("proc_imp009_heap_overrun.c")
        (loc, lines), (rem, rlines) = res["local"], res["remote"]
        buf_var = [l.split() for l in rlines if l.startswith("OVERRUN")][0][1]
        victim_var = [l.split() for l in rlines if l.startswith("OVERRUN")][0][5]
        self.assertEqual(loc["verdict"], "CONFIRMED_FAULT")
        self.assertEqual(rem["verdict"], "CONFIRMED_FAULT", rem["summary"])
        fs = [f for f in rem["findings"] if f["category"] == "MEMORY_CORRUPTION"]
        self.assertTrue(fs, rem["findings"])
        self.assertTrue({buf_var, victim_var} <= set(fs[0]["subjects"]), fs[0]["subjects"])
        self.assertEqual(shape(rem)[:2], shape(loc)[:2])

    # ------------------------------------------------------------------------------------------ d
    def test_d_missing_debug_image_is_inconclusive(self):
        proc, binary, _ = self._launch("proc_thread_circular_deadlock.c", ready=False)
        rem = diagnose(proc.pid, None, corpus_dir=self.corpus, target=self._spec()).to_dict()
        self.assertEqual(rem["verdict"], "INCONCLUSIVE")
        miss = [n for n in rem["not_covered"] if n["kind"] == "missing_debug_image"]
        self.assertTrue(miss)
        self.assertIn("unstripped", miss[0]["reason"])
        self.assertEqual(rem["findings"], [])
        self.assertIsNone(rem["investigation_id"])
        # a path that is not on this host is the same cause
        rem2 = diagnose(proc.pid, os.path.join(self.tmp, "nope.elf"), corpus_dir=self.corpus,
                        target=self._spec()).to_dict()
        self.assertEqual(rem2["verdict"], "INCONCLUSIVE")
        self.assertIn("missing_debug_image", {n["kind"] for n in rem2["not_covered"]})

    # ------------------------------------------------------------------------------------------ e
    def test_e_unreachable_host_is_inconclusive_and_leaks_no_credentials(self):
        def dead_runner(args, timeout, input_bytes=None):
            return 255, "", "ssh: connect to host board.example port 22: Connection refused\n"

        spec = self._spec(command_runner=dead_runner, ssh_key="/home/secret/id_super_secret", ssh_port=2222)
        res = diagnose(os.getpid(), os.path.join(self.tmp, "x"), corpus_dir=self.corpus, target=spec)
        d = res.to_dict()
        self.assertEqual(d["verdict"], "INCONCLUSIVE")
        self.assertEqual([n["kind"] for n in d["not_covered"]][:1], ["target_unreachable"])
        self.assertIn("Connection refused", d["not_covered"][0]["reason"])
        self.assertEqual(d["target"]["host"], "board.example")
        self.assertEqual(d["target"]["port"], 2222)
        self.assertNotIn("id_super_secret", json.dumps(d))
        self.assertFalse(d["findings"])

    @unittest.skipUnless(shutil.which("ssh"), "ssh client not installed")
    def test_e2_real_ssh_connection_refused(self):
        """No injected runner: the real ssh client against a closed local port."""
        res = diagnose(12345, os.path.join(self.tmp, "x"), corpus_dir=self.corpus,
                       target={"host": "127.0.0.1", "port": 1, "user": "nobody"}).to_dict()
        self.assertEqual(res["verdict"], "INCONCLUSIVE")
        self.assertIn("target_unreachable", {n["kind"] for n in res["not_covered"]})

    def test_e3_invalid_target_descriptions(self):
        for bad in ({"remote_host": "-oProxyCommand=x"}, {"foo": 1}, {"ssh_user": "u"}, {"remote_host": "h", "ssh_port": 99999},
                    "not-a-dict"):
            res = diagnose(1234, "/bin/true", target=bad).to_dict()
            self.assertEqual(res["verdict"], "INCONCLUSIVE", bad)
            self.assertEqual(res["not_covered"][0]["kind"], "invalid_target", bad)

    def test_e4_target_spec_aliases(self):
        s = TargetSpec.from_value({"host": " h ", "user": "u", "port": "2200", "identity": "/k", "proxy_jump": "j"})
        self.assertEqual((s.remote_host, s.ssh_user, s.ssh_port, s.ssh_key, s.ssh_proxy_jump),
                         ("h", "u", 2200, "/k", "j"))
        self.assertNotIn("/k", json.dumps(s.describe()))

    # ------------------------------------------------------------------------------------------ f
    def _fake_env(self):
        env = dict(os.environ)
        env["PATH"] = self.fakebin + os.pathsep + env.get("PATH", "")
        return env

    def _start_web(self):
        import http.client
        from extractor.agent_runtime import AgentRuntime
        from extractor.web.server import run_server
        server = run_server(AgentRuntime(corpus_dir=self.corpus), host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()

        def _stop():
            server.shutdown()
            server.server_close()

        self.addCleanup(_stop)
        port = server.server_address[1]

        def post(path, raw):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=180)
            conn.request("POST", path, body=raw, headers={"Content-Type": "application/json",
                                                          "X-Session-Token": server.session_token})
            resp = conn.getresponse()
            data = resp.read().decode("utf-8", errors="replace")
            conn.close()
            return resp.status, json.loads(data) if data else {}

        return post

    def test_f_mcp_cli_web_agree_on_remote_target(self):
        proc, binary, _ = self._launch("proc_thread_circular_deadlock.c", ready=False)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = self.fakebin + os.pathsep + old_path
        self.addCleanup(os.environ.__setitem__, "PATH", old_path)
        remote = {"remote_host": "board.example", "ssh_user": "root", "ssh_port": 22, "collector_path": self.collector}
        mcp_out = json.loads(mcp_srv.runtime_diagnose_process(pid=proc.pid, debug_image=binary, **remote))
        cli = subprocess.run(
            [sys.executable, "-m", "extractor.cli", "diagnose", "--pid", str(proc.pid), "--debug-image", binary,
             "--host", "board.example", "--user", "root", "--port", "22", "--identity", "/nonexistent/key",
             "--collector-path", self.collector, "--corpus", self.corpus, "--json"],
            capture_output=True, text=True, cwd=ROOT, timeout=240, env=self._fake_env())
        self.assertEqual(cli.returncode, 0, cli.stderr)
        cli_out = json.loads(cli.stdout)
        post = self._start_web()
        status, web = post("/api/diagnose", json.dumps({"pid": proc.pid, "debug_image": binary, **remote}).encode())
        self.assertEqual(status, 200)
        self.assertTrue(web["success"], web)
        web_out = web["result"]
        print("\n[f] mcp=%s cli=%s web=%s" % (mcp_out["verdict"], cli_out["verdict"], web_out["verdict"]))
        self.assertIn(mcp_out["verdict"], FAULT)
        self.assertEqual(shape(mcp_out), shape(cli_out))
        self.assertEqual(shape(mcp_out), shape(web_out))
        for o in (mcp_out, cli_out, web_out):
            self.assertEqual(o["target"]["transport"], "ssh")
            self.assertEqual(o["target"]["host"], "board.example")
            self.assertIn("remote_limitation", {n["kind"] for n in o["not_covered"]})
            self.assertTrue(o["human_summary"])
            self.assertNotIn("/nonexistent/key", json.dumps(o))
        self.assertEqual(set(mcp_out) - {"success"}, set(web_out))
        self.assertEqual(set(cli_out), set(web_out))
        # missing debug image: all three interfaces say the same
        m2 = json.loads(mcp_srv.runtime_diagnose_process(pid=proc.pid, **remote))
        _s, w2 = post("/api/diagnose", json.dumps({"pid": proc.pid, **remote}).encode())
        c2 = subprocess.run([sys.executable, "-m", "extractor.cli", "diagnose", "--pid", str(proc.pid), "--host",
                             "board.example", "--corpus", self.corpus, "--json"],
                            capture_output=True, text=True, cwd=ROOT, timeout=120, env=self._fake_env())
        for o in (m2, w2["result"], json.loads(c2.stdout)):
            self.assertEqual(o["verdict"], "INCONCLUSIVE")
            self.assertIn("missing_debug_image", {n["kind"] for n in o["not_covered"]})
        # web rules: key is a path only; passwords / key material are refused; bad port is INVALID_PARAM
        for bad in ({"ssh_password": "x"}, {"ssh_port": "http"}, {"ssh_user": 5}):
            _s, w = post("/api/diagnose", json.dumps({"pid": proc.pid, "debug_image": binary,
                                                      "remote_host": "h", **bad}).encode())
            self.assertFalse(w["success"])
            self.assertEqual(w["error"]["code"], "INVALID_PARAM")

    # ------------------------------------------------------------------------------------------ remote glibc / reads
    def test_remote_glibc_version_is_identified_bounded_and_cached(self):
        proc, _binary, _ = self._launch("proc_leak_append_list.c")
        ad = RemoteSshTargetAdapter(host="board.example", command_runner=local_sh_runner, stream_opener=local_sh_stream,
                                    collector_path=self.collector)
        self.addCleanup(ad.close)
        walker = HeapWalker(ad, proc.pid)
        res = walker.walk()
        self.assertEqual(res.status, STATUS_OK, res.message)
        self.assertGreater(len(res.chunks), 100)
        want = detect_target_abi(LocalTargetAdapter(), proc.pid).libc_version     # the local path reads the banner file
        self.assertTrue(want)
        self.assertTrue(res.abi["libc_version"].startswith(want.rsplit(".", 1)[0] if want.count(".") > 1 else want))
        self.assertIn("glibc version banner read from the target's mapped libc", res.abi["evidence"])
        cache = getattr(ad, "_glibc_version_cache", {})
        self.assertEqual(len(cache), 1)
        # the second walker of the session does not read libc again
        w2 = HeapWalker(ad, proc.pid)
        w2._maps = ad.get_proc_maps(proc.pid)
        abi = detect_target_abi(ad, proc.pid, maps=w2._maps)
        before = w2.reader.bytes_read
        self.assertIsNotNone(w2._glibc_version_from_memory(abi))
        self.assertEqual(w2.reader.bytes_read, before)

    def test_large_slices_are_split_for_the_64k_collector(self):
        proc, _binary, _ = self._launch("proc_leak_append_list.c")
        ad = RemoteSshTargetAdapter(host="board.example", command_runner=local_sh_runner, stream_opener=local_sh_stream,
                                    collector_path=self.collector)
        self.addCleanup(ad.close)
        libc = [m for m in ad.get_proc_maps(proc.pid) if "libc" in (m.get("pathname") or "") and m["is_readable"]
                and m["size"] > 300000][0]
        n = 300000
        (data, status, _), = ad.read_memory_batch(proc.pid, [(libc["start_int"], n)])
        with open("/proc/%d/mem" % proc.pid, "rb") as fh:
            fh.seek(libc["start_int"])
            truth = fh.read(n)
        self.assertEqual(status, "OBSERVED")
        self.assertEqual(data, truth)
        # an unreadable tail: partial, never padded
        # (a readable mapping of >= 70000 bytes that is followed by an unmapped gap: on some layouts libc's last
        # mapping is directly followed by another readable one, so pick the boundary from /proc/PID/maps)
        maps = sorted(ad.get_proc_maps(proc.pid), key=lambda m: m["start_int"])
        end = None
        for m, nxt in zip(maps, maps[1:] + [None]):
            if m["is_readable"] and m["size"] >= 70000 and (nxt is None or nxt["start_int"] > m["end_int"] + 4096):
                end = m["end_int"]
                break
        self.assertIsNotNone(end, "no readable mapping followed by a gap")
        (data, status, _), = ad.read_memory_batch(proc.pid, [(end - 70000, 140000)])
        self.assertEqual(status, "PARTIAL")
        self.assertEqual(len(data), 70000)

    # ------------------------------------------------------------------------------------------ g
    def test_g_planned_only_session_never_yields_a_diagnosis(self):
        from unittest import mock
        from extractor.expert_diagnostic_engine import AdaptiveInvestigationSession
        proc, binary, _ = self._launch("proc_thread_circular_deadlock.c", ready=False)
        engine = ExpertDiagnosticEngine(corpus_dir=self.corpus)
        session = engine.start_investigation(problem_statement="process hangs", pid=proc.pid, companion_elf=binary,
                                             adapter=LocalTargetAdapter())
        self.assertEqual(session.executed_check_count(), 0)
        # an engine-built report of a planned-only session is built, but unmistakably marked, never PASS
        rep = session.export_report(format="json")
        self.assertEqual(rep["report_completeness"], "PLANNED_ONLY")
        self.assertEqual(rep["section_a_executive_summary"]["overall_result"], "INCONCLUSIVE")
        self.assertTrue(any("PLANNED_ONLY" in x for x in rep["section_h_limitations_and_unverified"]["unexecuted_checks"]))
        statuses = {c["status"] for c in rep["section_d_detailed_inspection_results"]["checks"]}
        self.assertNotIn("PASS", statuses)
        self.assertNotIn("FAIL", statuses)
        # diagnose() on a session that plans but executes nothing: INCONCLUSIVE, no report, no findings
        with mock.patch.object(AdaptiveInvestigationSession, "run_to_completion", lambda self_, max_steps=30: None):
            res = diagnose(proc.pid, binary, corpus_dir=self.corpus, include_report=True).to_dict()
        self.assertEqual(res["verdict"], "INCONCLUSIVE")
        self.assertIn("not_executed", {n["kind"] for n in res["not_covered"]})
        self.assertIsNone(res["report"])
        self.assertIsNone(res["report_path"])
        self.assertEqual(res["findings"], [])
        # an executed session is COMPLETE
        session2 = engine.start_investigation(problem_statement="process hangs", pid=proc.pid, companion_elf=binary,
                                              adapter=LocalTargetAdapter())
        session2.run_to_completion(max_steps=30)
        self.assertGreater(session2.executed_check_count(), 0)
        self.assertEqual(session2.export_report(format="json")["report_completeness"], "COMPLETE")


if __name__ == "__main__":
    unittest.main()
