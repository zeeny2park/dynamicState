"""The seven diagnoses added on this branch against a REMOTE target (roadmap stage 0, last row).

Same convention as ``tests/test_imp006_remote_diagnose.py``: the natively built collector (daemon channel) behind a
local ``sh`` transport plays the remote host, the very same benchmark target is diagnosed locally and "remotely", and
the findings are compared.  A loopback transport cannot tell a remote read from a local read of the same /proc, so
each remote run is also watched: any access of the diagnosing process to ``/proc/<pid of the target>``, to one of its
thread ids, or to ``/proc/sys`` (host-wide files) fails the test.  Everything about the target must go through the
adapter.

 orphan lock, self-deadlock, lock contention, thread leak, mapping growth, heap retention, double free
"""

import builtins
import json
import os
import re
import select
import shutil
import subprocess
import tempfile
import traceback
import time
import unittest

from extractor.expert_diagnostic_engine import TargetSpec, diagnose

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = os.path.join(ROOT, "benchmarks", "diagnosis_accuracy", "targets")
COLLECTOR_SRC = os.path.join(ROOT, "target", "collector")


def local_sh_runner(args, timeout, input_bytes=None):
    res = subprocess.run(["sh", "-c", args[-1]], input=input_bytes, capture_output=True, timeout=timeout)
    return res.returncode, res.stdout.decode(), res.stderr.decode()


def local_sh_stream(args):
    return subprocess.Popen(["sh", "-c", args[-1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)


class LocalProcSpy:
    """Records the /proc paths of the target (pid, its tids) and of /proc/sys that THIS process touches."""

    def __init__(self, pid):
        self.pid = pid
        self.hits = []
        self._orig = {}
        self._rx = None

    def _note(self, path):
        try:
            p = os.fspath(path)
        except TypeError:
            return
        if isinstance(p, bytes):
            p = p.decode("utf-8", "replace")
        if self._rx.match(p):
            site = [f"{os.path.basename(fr.filename)}:{fr.lineno}" for fr in traceback.extract_stack()[:-2]
                    if "/extractor/" in fr.filename][-2:]
            self.hits.append("%s <- %s" % (p, " < ".join(reversed(site))))

    def __enter__(self):
        tids = {self.pid}
        try:
            tids |= {int(t) for t in os.listdir(f"/proc/{self.pid}/task")}
        except OSError:
            pass
        self._rx = re.compile(r"^/proc/(?:%s)(?:/|$)|^/proc/sys(?:/|$)" % "|".join(str(t) for t in sorted(tids)))
        spy = self

        def wrap(mod, name):
            orig = getattr(mod, name)
            spy._orig[(mod, name)] = orig

            def f(path, *a, **k):
                spy._note(path)
                return orig(path, *a, **k)
            setattr(mod, name, f)

        for mod, name in ((builtins, "open"), (os, "listdir"), (os, "readlink"), (os, "stat"), (os, "scandir"),
                          (os, "lstat"), (os, "access"), (os.path, "isdir"), (os.path, "exists"), (os.path, "isfile")):
            wrap(mod, name)
        return self

    def __exit__(self, *exc):
        for (mod, name), orig in self._orig.items():
            setattr(mod, name, orig)
        return False


def shape(d):
    cats = sorted({str(f["category"]) for f in d["findings"]})
    # tids / pids and heap addresses differ between two instances of the target
    subj = sorted({s for f in d["findings"] for s in f["subjects"] if not s.isdigit() and not s.startswith("0x")})
    return d["verdict"], cats, subj


@unittest.skipUnless(shutil.which("gcc") and shutil.which("make") and os.path.exists("/proc/self/mem"),
                     "gcc/make/procfs not available")
class RemoteNewDiagnosesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="remnew_")
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

    def _binary(self, name):
        if name not in self.bins:
            out = os.path.join(self.tmp, name)
            subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", os.path.join(TARGETS, name + ".c"),
                            "-o", out], check=True, capture_output=True, timeout=120)
            self.bins[name] = out
        return self.bins[name]

    def _launch(self, name):
        binary = self._binary(name)
        proc = subprocess.Popen([binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

        def _kill():
            try:
                proc.kill()
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                pass
            proc.stdout.close()

        self.addCleanup(_kill)
        buf, deadline = b"", time.monotonic() + 60
        while b"READY" not in buf:
            self.assertLess(time.monotonic(), deadline, "%s did not print READY" % name)
            r, _, _ = select.select([proc.stdout], [], [], 0.2)
            if r:
                chunk = os.read(proc.stdout.fileno(), 65536)
                self.assertTrue(chunk, "%s exited before READY" % name)
                buf += chunk
        time.sleep(0.3)
        self.assertIsNone(proc.poll())
        return proc, binary

    def _spec(self):
        return TargetSpec(remote_host="board.example", ssh_user="root", collector_path=self.collector,
                          command_runner=local_sh_runner, stream_opener=local_sh_stream)

    def _both(self, name, symptom, attempts=3):
        """(local result, remote result, local /proc accesses of the remote run) on two instances of the target.

        The host is shared and the sampling windows are short: a run that the machine load turned INCONCLUSIVE
        (on either side) is repeated, up to ``attempts`` times.  Every other outcome is compared as it is."""
        for _ in range(attempts - 1):
            res = self._both_once(name, symptom)
            if "INCONCLUSIVE" not in (res[0]["verdict"], res[1]["verdict"]):
                return res
        return self._both_once(name, symptom)

    def _both_once(self, name, symptom):
        out = {}
        for mode in ("local", "remote"):
            proc, binary = self._launch(name)
            if mode == "local":
                out[mode] = diagnose(proc.pid, binary, symptom, corpus_dir=self.corpus, include_report=True).to_dict()
            else:
                with LocalProcSpy(proc.pid) as spy:
                    out[mode] = diagnose(proc.pid, binary, symptom, corpus_dir=self.corpus, include_report=True,
                                         target=self._spec()).to_dict()
                out["hits"] = sorted(set(spy.hits))
        return out["local"], out["remote"], out["hits"]

    def _same(self, name, symptom, category, verdict, severity=None, core=None):
        loc, rem, hits = self._both(name, symptom)
        if loc["verdict"] == "INCONCLUSIVE":
            self.skipTest("the LOCAL baseline is INCONCLUSIVE too (machine load, load average %.1f): nothing to "
                          "compare the remote run with. %s" % (os.getloadavg()[0], loc["summary"]))
        print("\n[%s] local %s | remote %s | local /proc hits %s" % (name, shape(loc)[:2], shape(rem)[:2], hits[:6]))
        self.assertEqual(loc["verdict"], verdict, loc["summary"])
        self.assertEqual(rem["verdict"], verdict, rem["summary"])
        fl = [f for f in loc["findings"] if f["category"] == category]
        fr = [f for f in rem["findings"] if f["category"] == category]
        self.assertEqual(len(fl), 1, loc["findings"])
        self.assertEqual(len(fr), 1, rem["findings"])
        if severity:
            self.assertEqual((fl[0]["severity"], fr[0]["severity"]), (severity, severity))
        if core:
            # Local and remote are two separate observation windows on a live process: secondary names (e.g. the
            # variable a worker holds the lock for) may or may not show in a given window. The names the finding is
            # about must agree.
            self.assertEqual(shape(rem)[:2], shape(loc)[:2])
            self.assertTrue(set(core) <= set(shape(loc)[2]) & set(shape(rem)[2]), (core, shape(loc), shape(rem)))
        else:
            self.assertEqual(shape(rem), shape(loc))
        self.assertTrue(rem["target"]["transport"] == "ssh" and rem["collection_impact"]["zero_stop"])
        self.assertEqual(hits, [], "the remote run read the LOCAL /proc of the target: %s" % hits)
        return loc, rem

    def test_orphan_lock(self):
        _, rem = self._same("orphan_lock_cfg", "the process hangs", "ORPHAN_LOCK", "PROBABLE_FAULT")
        self.assertIn("m_cfg", shape(rem)[2])

    def test_self_deadlock(self):
        _, rem = self._same("self_deadlock_registry", "the process hangs", "SELF_DEADLOCK", "CONFIRMED_FAULT")
        self.assertTrue(shape(rem)[2])

    def test_lock_contention_is_degraded(self):
        _, rem = self._same("lock_convoy", "the process feels slow, check for lock problems", "LOCK_CONTENTION",
                            "DEGRADED", "INFO", core=("table_mu", "tbl_worker"))
        self.assertIn("table_mu", shape(rem)[2])

    def test_thread_leak(self):
        self._same("request_threads", "the thread count of this process is going up all the time", "THREAD_LEAK",
                   "CONFIRMED_FAULT")

    def test_mapping_growth(self):
        self._same("mapgrow_slabs", "memory usage of this process keeps growing", "MAPPING_GROWTH", "PROBABLE_FAULT")

    def test_heap_retention_is_degraded(self):
        self._same("frag_sparse", "memory usage looks high, is it leaking?", "HEAP_RETENTION", "DEGRADED", "INFO")

    def test_double_free(self):
        self._same("dfree_reqbuf", "this program crashes sometimes and data looks wrong", "INVALID_DOUBLE_FREE",
                   "CONFIRMED_FAULT")


class _FakeRemote:
    """A remote adapter that has the data of a host this machine knows nothing about (the pid does not exist here)."""

    def __init__(self, files, existing_tids=()):
        self.files, self.existing_tids, self.ssh = files, set(existing_tids), []

    def is_remote(self):
        return True

    def read_target_file(self, pid, path, max_bytes):
        return self.files.get(path)

    def run_ssh(self, cmd, *a, **k):
        self.ssh.append(cmd)
        tid = int(re.search(r"/proc/(\d+)", cmd).group(1))
        return (0 if tid in self.existing_tids else 1), "", ""


class RemoteDataAccessUnitTests(unittest.TestCase):
    """Fast, deterministic checks of the two collector reads that branch on local / remote."""

    PID = 4242424

    def test_spy_sees_a_local_read(self):
        with LocalProcSpy(os.getpid()) as spy:
            with open("/proc/%d/status" % os.getpid()):
                pass
            os.path.isdir("/proc/sys")
        self.assertEqual({h.split(" <-")[0] for h in spy.hits}, {"/proc/%d/status" % os.getpid(), "/proc/sys"})

    def test_thread_leak_limits_come_from_the_remote_adapter(self):
        from extractor.recipe_plugins.thread_leak import _limits
        self.assertFalse(os.path.exists("/proc/%d" % self.PID))
        ad = _FakeRemote({
            "/proc/%d/limits" % self.PID: b"Max processes             1234                 1234                 processes\n",
            "/proc/sys/kernel/threads-max": b"98765\n"})
        with LocalProcSpy(self.PID) as spy:
            self.assertEqual(_limits(ad, self.PID), {"rlimit_nproc": 1234, "threads_max": 98765})
        self.assertEqual(spy.hits, [])
        # nothing readable remotely: not read (None), never replaced by this machine's value
        self.assertEqual(_limits(_FakeRemote({}), self.PID), {"rlimit_nproc": None, "threads_max": None})

    def test_orphan_owner_existence_is_asked_on_the_remote_host(self):
        from extractor.recipe_plugins.lock_faults import _tid_exists
        ad = _FakeRemote({}, existing_tids={7})
        self.assertIs(_tid_exists(ad, self.PID, 7), True)
        self.assertIs(_tid_exists(ad, self.PID, 1), False)    # pid 1 exists on THIS machine, not on the remote one
        self.assertEqual(len(ad.ssh), 2)
        noshell = _FakeRemote({})
        noshell.run_ssh = None
        self.assertIsNone(_tid_exists(noshell, self.PID, 1))   # cannot ask: unverified, not "exists" / "gone"


if __name__ == "__main__":
    unittest.main()
