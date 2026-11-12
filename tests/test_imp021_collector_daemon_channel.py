"""IMP-021: persistent collector daemon channel (one long-lived "ssh" child per adapter).

The "remote" side is real: the natively built collector runs in daemon mode behind a local
``sh -c`` transport (the same trick as the IMP-016 deploy tests), reading the memory of a real
target process.  Collector executions are counted through a wrapper script that logs its PID and
then ``exec``s the real binary.
"""

import os
import shutil
import shlex
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest

from extractor.target_adapter import RemoteSshTargetAdapter

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COLLECTOR_SRC = os.path.join(REPO_ROOT, "target", "collector")

TARGET_PROG = textwrap.dedent(
    """
    import ctypes, mmap, sys, time
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(0x59616d61, ctypes.c_ulong(-1 & 0xFFFFFFFFFFFFFFFF), 0, 0, 0)  # PR_SET_PTRACER_ANY
    m = mmap.mmap(-1, 4 * 4096)
    m.write(bytes((i * 7 + 3) % 251 for i in range(4 * 4096)))
    addr = ctypes.addressof(ctypes.c_char.from_buffer(m))
    print(addr, flush=True)
    time.sleep(120)
    """
)


def pattern(off, n):
    return bytes(((off + i) * 7 + 3) % 251 for i in range(n))


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:  # zombie counts as dead
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def local_sh_runner(args, timeout, input_bytes=None):
    res = subprocess.run(["sh", "-c", args[-1]], input=input_bytes, capture_output=True, timeout=timeout)
    return res.returncode, res.stdout.decode(), res.stderr.decode()


def local_sh_stream(args):
    return subprocess.Popen(["sh", "-c", args[-1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)


@unittest.skipUnless(shutil.which("make") and shutil.which("cc") and os.path.exists("/proc/self/mem"),
                     "make/cc/procfs not available")
class DaemonChannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp021_")
        build = os.path.join(cls.tmp, "build")
        shutil.copytree(COLLECTOR_SRC, build,
                        ignore=shutil.ignore_patterns("*.o", "dist", "dynamicstate-collector", "test_crypto"))
        r = subprocess.run(["make", "-C", build, "dynamicstate-collector"], capture_output=True, text=True)
        if r.returncode != 0:
            raise unittest.SkipTest("native collector build failed: " + r.stderr[-300:])
        cls.real = os.path.join(build, "dynamicstate-collector")
        cls.target = subprocess.Popen([sys.executable, "-c", TARGET_PROG], stdout=subprocess.PIPE, text=True)
        cls.base = int(cls.target.stdout.readline())
        cls.pid = cls.target.pid

    @classmethod
    def tearDownClass(cls):
        cls.target.kill()
        cls.target.wait()
        cls.target.stdout.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.adapters = []
        self.addCleanup(self._close_all)
        self.log = os.path.join(self.tmp, f"spawn_{self._testMethodName}.log")
        open(self.log, "w").close()

    def _close_all(self):
        for a in self.adapters:
            a.close()

    def _script(self, name, body):
        path = os.path.join(self.tmp, f"{name}_{self._testMethodName}")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755)
        return path

    def _counting_collector(self):
        return self._script("coll", f"echo $$ >> {shlex.quote(self.log)}\nexec {shlex.quote(self.real)} \"$@\"\n")

    def _spawned_pids(self):
        with open(self.log) as f:
            return [int(x) for x in f.read().split()]

    def _adapter(self, collector, **kw):
        a = RemoteSshTargetAdapter(host="localhost", command_runner=local_sh_runner,
                                   stream_opener=local_sh_stream, collector_path=collector, **kw)
        self.adapters.append(a)
        return a

    def _direct_read(self, off, n):
        with open(f"/proc/{self.pid}/mem", "rb") as f:
            f.seek(self.base + off)
            return f.read(n)

    # ---- acceptance 1 -------------------------------------------------------------------
    def test_100_reads_spawn_one_collector_and_bytes_match(self):
        ad = self._adapter(self._counting_collector())
        for i in range(100):
            off = (i * 613) % 8192
            data, status, err = ad.read_memory(self.pid, self.base + off, 4096)
            self.assertEqual(status, "OBSERVED", err)
            self.assertEqual(data, self._direct_read(off, 4096))
            self.assertEqual(data, pattern(off, 4096))
        pids = self._spawned_pids()
        self.assertEqual(len(pids), 1, pids)
        self.assertEqual(ad.daemon_stats["opens"], 1)
        ad.close()
        self.assertFalse(pid_alive(pids[0]))

    def test_batch_reads_and_unmapped_status_over_daemon(self):
        ad = self._adapter(self._counting_collector())
        res = ad.read_memory_batch(self.pid, [(self.base + 5, 100), (self.base + 4090, 20), (self.base, 0)])
        self.assertEqual([r[1] for r in res], ["OBSERVED"] * 3)
        self.assertEqual(res[0][0], pattern(5, 100))
        self.assertEqual(res[1][0], pattern(4090, 20))
        self.assertEqual(res[2][0], b"")
        bad = ad.read_memory(self.pid, 0x10, 16)
        self.assertIsNone(bad[0])
        self.assertIn(bad[1], ("UNAVAILABLE", "PERMISSION_DENIED"))
        # channel still healthy after a per-slice failure
        self.assertEqual(ad.read_memory(self.pid, self.base, 8)[0], pattern(0, 8))
        self.assertEqual(len(self._spawned_pids()), 1)

    def test_many_slices_split_into_bounded_request_lines(self):
        ad = self._adapter(self._counting_collector())
        slices = [(self.base + (i * 37) % 8000, 8) for i in range(900)]
        res = ad.read_memory_batch(self.pid, slices)
        self.assertEqual(len(res), 900)
        for (a, n), (data, st, _) in zip(slices, res):
            self.assertEqual(st, "OBSERVED")
            self.assertEqual(data, pattern(a - self.base, n))
        self.assertEqual(len(self._spawned_pids()), 1)
        self.assertEqual(ad.daemon_stats["reopens"], 0)

    def test_concurrent_readers_share_one_channel(self):
        ad = self._adapter(self._counting_collector())
        errors = []

        def worker(k):
            for i in range(25):
                off = (k * 1000 + i * 97) % 8000
                d, st, err = ad.read_memory(self.pid, self.base + off, 512)
                if st != "OBSERVED" or d != pattern(off, 512):
                    errors.append((k, i, st, err))

        ts = [threading.Thread(target=worker, args=(k,)) for k in range(4)]
        [t.start() for t in ts]
        [t.join(30) for t in ts]
        self.assertEqual(errors, [])
        self.assertEqual(len(self._spawned_pids()), 1)

    # ---- acceptance 2 -------------------------------------------------------------------
    def test_recovers_after_channel_is_killed(self):
        ad = self._adapter(self._counting_collector())
        self.assertEqual(ad.read_memory(self.pid, self.base, 64)[0], pattern(0, 64))
        first = self._spawned_pids()[0]
        os.kill(first, signal.SIGKILL)  # the collector (== the sh child after exec) dies: EOF
        deadline = time.time() + 3
        while pid_alive(first) and time.time() < deadline:
            time.sleep(0.02)
        data, status, err = ad.read_memory(self.pid, self.base + 100, 64)
        self.assertEqual(status, "OBSERVED", err)
        self.assertEqual(data, pattern(100, 64))
        pids = self._spawned_pids()
        self.assertEqual(len(pids), 2)
        self.assertEqual(ad.daemon_stats["opens"], 2)
        ad.close()
        for p in pids:
            self.assertFalse(pid_alive(p), p)

    def test_garbage_reply_reopens_once_then_falls_back_per_call(self):
        garbage = self._script("garbage", textwrap.dedent(f"""\
            echo $$ >> {shlex.quote(self.log)}
            if [ "$1" = "--daemon" ]; then
              while read l; do
                case "$l" in
                  PING*) echo '{{"success":true,"status":"PONG"}}';;
                  QUIT*) exit 0;;
                  *) echo 'this is not json';;
                esac
              done
              exit 0
            fi
            exec {shlex.quote(self.real)} "$@"
            """))
        ad = self._adapter(garbage)
        data, status, err = ad.read_memory(self.pid, self.base + 9, 33)
        self.assertEqual((status, data), ("OBSERVED", pattern(9, 33)), err)
        self.assertEqual(ad.daemon_stats["reopens"], 1)
        self.assertEqual(ad.daemon_stats["fallbacks"], 1)
        ad.close()
        for p in self._spawned_pids():
            self.assertFalse(pid_alive(p), p)

    def test_timeout_closes_channel_and_reaps_child(self):
        hang = self._script("hang", textwrap.dedent(f"""\
            echo $$ >> {shlex.quote(self.log)}
            if [ "$1" = "--daemon" ]; then
              while read l; do
                case "$l" in
                  PING*) echo '{{"success":true,"status":"PONG"}}';;
                  *) sleep 30;;
                esac
              done
              exit 0
            fi
            exec {shlex.quote(self.real)} "$@"
            """))
        ad = self._adapter(hang, timeout_sec=0.3)
        t0 = time.time()
        data, status, _ = ad.read_memory(self.pid, self.base, 16)
        self.assertLess(time.time() - t0, 10)
        self.assertEqual((status, data), ("OBSERVED", pattern(0, 16)))  # served by per-call fallback
        ad.close()
        time.sleep(0.2)
        # the hung daemons (the shell scripts) were killed, not leaked
        for p in self._spawned_pids():
            self.assertFalse(pid_alive(p), p)

    # ---- fallback decision ----------------------------------------------------------------
    def test_old_collector_without_daemon_falls_back_once_per_session(self):
        old = self._script("old", textwrap.dedent(f"""\
            echo "$1" >> {shlex.quote(self.log)}
            case "$1" in
              --daemon) echo "unrecognized option '--daemon'" >&2; exit 2;;
            esac
            exec {shlex.quote(self.real)} "$@"
            """))
        ad = self._adapter(old)
        for i in range(5):
            d, st, err = ad.read_memory(self.pid, self.base + i * 10, 40)
            self.assertEqual((st, d), ("OBSERVED", pattern(i * 10, 40)), err)
        with open(self.log) as f:
            calls = f.read().split()
        self.assertEqual(calls.count("--daemon"), 1, calls)
        self.assertEqual(calls.count("-p"), 5, calls)
        self.assertEqual(ad.daemon_stats["opens"], 0)

    def test_use_daemon_false_keeps_per_call_behaviour(self):
        ad = self._adapter(self._counting_collector(), use_daemon=False)
        for _ in range(3):
            self.assertEqual(ad.read_memory(self.pid, self.base, 8)[0], pattern(0, 8))
        self.assertEqual(len(self._spawned_pids()), 3)

    # ---- orphan safety ---------------------------------------------------------------------
    def test_collector_exits_when_host_is_killed(self):
        driver = textwrap.dedent(f"""
            import sys
            sys.path.insert(0, {REPO_ROOT!r})
            from extractor.target_adapter import RemoteSshTargetAdapter
            sys.path.insert(0, {os.path.join(REPO_ROOT, 'tests')!r})
            from test_imp021_collector_daemon_channel import local_sh_runner, local_sh_stream
            a = RemoteSshTargetAdapter(host="localhost", command_runner=local_sh_runner,
                                       stream_opener=local_sh_stream, collector_path={self._counting_collector()!r})
            print(a.read_memory({self.pid}, {self.base}, 8)[1], flush=True)
            import time; time.sleep(60)
        """)
        host = subprocess.Popen([sys.executable, "-c", driver], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(host.stdout.readline().strip(), "OBSERVED")
            pids = self._spawned_pids()
            self.assertEqual(len(pids), 1)
            self.assertTrue(pid_alive(pids[0]))
            host.kill()  # no atexit, no QUIT: only the pipe EOF can stop the collector
            host.wait()
            deadline = time.time() + 5
            while pid_alive(pids[0]) and time.time() < deadline:
                time.sleep(0.05)
            self.assertFalse(pid_alive(pids[0]), "collector survived the death of its host")
        finally:
            host.kill()
            host.wait()
            host.stdout.close()

    # ---- acceptance 3: block-wise fallback without a collector --------------------------------
    def test_no_collector_fallback_is_per_slice_not_per_byte(self):
        cmds = []

        def runner(args, timeout, input_bytes=None):
            cmds.append(args[-1])
            return local_sh_runner(args, timeout, input_bytes)

        ad = RemoteSshTargetAdapter(host="localhost", command_runner=runner, stream_opener=local_sh_stream)
        self.adapters.append(ad)
        cases = [(1, 1), (4095, 2), (4096, 4096), (123, 5000), (4000, 4200), (0, 16384), (8191, 3)]
        for off, n in cases:
            cmds.clear()
            d, st, err = ad.read_memory(self.pid, self.base + off, n)
            self.assertEqual((st, d), ("OBSERVED", pattern(off, n)), (off, n, err))
            self.assertEqual(len(cmds), 1, cmds)
            self.assertNotIn("bs=1 ", cmds[0] + " ")
        cmds.clear()
        sl = [(off, n) for off, n in cases]
        res = ad.read_memory_batch(self.pid, [(self.base + o, n) for o, n in sl])
        for (o, n), (d, st, err) in zip(sl, res):
            self.assertEqual((st, d), ("OBSERVED", pattern(o, n)), (o, n, err))
        self.assertEqual(len(cmds), 1, "batch must be a single command (O(slices) work in one round trip)")
        self.assertNotIn("bs=1 ", cmds[0] + " ")
        self.assertEqual(cmds[0].count("dd if="), len(sl))  # one block-wise dd per slice

    def test_no_collector_fallback_reports_unmapped_as_unavailable(self):
        ad = RemoteSshTargetAdapter(host="localhost", command_runner=local_sh_runner, stream_opener=local_sh_stream)
        d, st, _ = ad.read_memory(self.pid, 0x10, 32)
        self.assertIsNone(d)
        self.assertNotEqual(st, "OBSERVED")


# Optional overrides (e.g. a private sshd): IMP021_SSH_PORT, IMP021_SSH_KEY.
_SSH_PORT = int(os.environ.get("IMP021_SSH_PORT", "22"))
_SSH_KEY = os.environ.get("IMP021_SSH_KEY") or None


def _localhost_ssh_ok():
    if not shutil.which("ssh"):
        return "ssh client not installed"
    try:
        cmd = ["ssh", "-p", str(_SSH_PORT)] + (["-i", _SSH_KEY] if _SSH_KEY else [])
        r = subprocess.run(cmd + ["-o", "BatchMode=yes", "-o", "ConnectTimeout=2",
                            "-o", "StrictHostKeyChecking=accept-new", "localhost", "echo ok"],
                           capture_output=True, text=True, timeout=8)
    except Exception as e:  # noqa: BLE001
        return f"ssh localhost failed: {e}"
    return None if (r.returncode == 0 and "ok" in r.stdout) else "no key-auth sshd reachable on localhost"


_SSH_SKIP = _localhost_ssh_ok()


@unittest.skipIf(_SSH_SKIP is not None, _SSH_SKIP or "")
class TrueSshTests(unittest.TestCase):
    def test_100_reads_over_real_ssh_use_one_collector(self):
        tmp = tempfile.mkdtemp(prefix="imp021_ssh_")
        self.addCleanup(shutil.rmtree, tmp, True)
        build = os.path.join(tmp, "build")
        shutil.copytree(COLLECTOR_SRC, build,
                        ignore=shutil.ignore_patterns("*.o", "dist", "dynamicstate-collector", "test_crypto"))
        r = subprocess.run(["make", "-C", build, "dynamicstate-collector"], capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest("native collector build failed")
        log = os.path.join(tmp, "spawn.log")
        wrapper = os.path.join(tmp, "coll")
        with open(wrapper, "w") as f:
            f.write(f"#!/bin/sh\necho $$ >> {shlex.quote(log)}\nexec {shlex.quote(os.path.join(build, 'dynamicstate-collector'))} \"$@\"\n")
        os.chmod(wrapper, 0o755)
        target = subprocess.Popen([sys.executable, "-c", TARGET_PROG], stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (target.kill(), target.wait(), target.stdout.close()))
        base = int(target.stdout.readline())
        ad = RemoteSshTargetAdapter(host="localhost", port=_SSH_PORT, key_file=_SSH_KEY,
                                     collector_path=wrapper, timeout_sec=10)
        self.addCleanup(ad.close)
        for i in range(100):
            off = (i * 613) % 8192
            d, st, err = ad.read_memory(target.pid, base + off, 4096)
            self.assertEqual((st, d), ("OBSERVED", pattern(off, 4096)), err)
        with open(log) as f:
            pids = [int(x) for x in f.read().split()]
        self.assertEqual(len(pids), 1)
        ad.close()
        time.sleep(0.3)
        self.assertFalse(pid_alive(pids[0]))


if __name__ == "__main__":
    unittest.main()
