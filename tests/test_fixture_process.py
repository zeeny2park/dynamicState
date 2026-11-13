"""Containment of fixture processes: no way of ending the runner leaves a fixture behind or lets it eat the host.

Safe on a shared host: the only memory-growing fixture here is a tiny Python script that allocates in 4 MiB
steps and is limited by a 64 MiB test ceiling (and caps itself at 400 MiB if every layer failed).
"""
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
import unittest

from tests.support.fixture_process import (
    FixtureLifetimeExceeded,
    FixtureMemoryCeilingExceeded,
    fixture_popen,
    fixture_process,
    kill_all_fixtures,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GROWER = textwrap.dedent("""
    import time
    blocks = []
    print("READY", flush=True)
    for _ in range(100):            # self-cap: 400 MiB even if every containment layer failed
        blocks.append(bytearray(b"x" * (4 << 20)))
        time.sleep(0.02)
    time.sleep(60)
""")

# Runner that starts one fixture through the launcher, reports its pid and then idles.
RUNNER = textwrap.dedent("""
    import sys, time
    sys.path.insert(0, %r)
    from tests.support.fixture_process import fixture_popen
    p = fixture_popen(["sleep", "300"])
    print(p.pid, flush=True)
    time.sleep(300)
""" % REPO_ROOT)


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def _wait_gone(pid: int, timeout: float) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.02)
    return not _alive(pid)


class RunnerEndsTests(unittest.TestCase):
    def _start_runner(self):
        runner = subprocess.Popen([sys.executable, "-c", RUNNER], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, start_new_session=True)
        self.addCleanup(lambda: (runner.poll() is None and runner.kill(), runner.wait(), runner.stdout.close()))
        fixture_pid = int(runner.stdout.readline())
        self.addCleanup(lambda: os.kill(fixture_pid, signal.SIGKILL) if _alive(fixture_pid) else None)
        self.assertTrue(_alive(fixture_pid))
        return runner, fixture_pid

    def test_runner_sigkill_removes_fixture_within_a_second(self):
        runner, pid = self._start_runner()
        runner.kill()
        runner.wait()
        self.assertTrue(_wait_gone(pid, 1.0), "fixture survived SIGKILL of its runner")

    def test_runner_sigterm_removes_fixture(self):
        runner, pid = self._start_runner()
        runner.terminate()
        runner.wait(timeout=10)
        self.assertEqual(runner.returncode, -signal.SIGTERM, "the runner must still die from SIGTERM (re-raise)")
        self.assertTrue(_wait_gone(pid, 1.0), "fixture survived SIGTERM of its runner")

    def test_runner_sigint_removes_fixture(self):
        runner, pid = self._start_runner()
        runner.send_signal(signal.SIGINT)
        runner.wait(timeout=10)
        self.assertTrue(_wait_gone(pid, 1.0), "fixture survived SIGINT of its runner")

    def test_runner_normal_exit_removes_fixture(self):
        code = RUNNER.replace("time.sleep(300)", "")
        runner = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
        pid = int(runner.stdout.split()[0])
        self.assertTrue(_wait_gone(pid, 1.0), "fixture survived a normal runner exit (atexit sweep)")


class LimitTests(unittest.TestCase):
    def test_memory_ceiling_kills_and_reports_distinct_error(self):
        t0 = time.monotonic()
        with self.assertRaises(FixtureMemoryCeilingExceeded) as ctx:
            with fixture_process([sys.executable, "-c", GROWER], stdout=subprocess.PIPE, text=True,
                                 max_rss_mib=64, max_lifetime_s=30, name="grower") as proc:
                proc.stdout.readline()
                proc.wait(timeout=20)   # killed by the watchdog; wait() must raise, not return -9 quietly
        self.assertIn("fixture exceeded memory ceiling", str(ctx.exception))
        self.assertLess(time.monotonic() - t0, 10)

    def test_memory_ceiling_is_visible_through_poll_and_check(self):
        proc = fixture_popen([sys.executable, "-c", GROWER], stdout=subprocess.DEVNULL, max_rss_mib=64)
        self.addCleanup(proc.kill_tree)
        with self.assertRaises(FixtureMemoryCeilingExceeded):
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    break
                time.sleep(0.05)
        with self.assertRaises(FixtureMemoryCeilingExceeded):
            proc.check()
        self.assertEqual(proc.returncode, -signal.SIGKILL)

    def test_ceiling_counts_child_processes(self):
        parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',%r]); time.sleep(60)" % GROWER
        with self.assertRaises(FixtureMemoryCeilingExceeded):
            with fixture_process([sys.executable, "-c", parent], max_rss_mib=64, max_lifetime_s=30,
                                 stdout=subprocess.DEVNULL) as proc:
                proc.wait(timeout=20)

    def test_lifetime_limit(self):
        t0 = time.monotonic()
        with self.assertRaises(FixtureLifetimeExceeded):
            with fixture_process(["sleep", "60"], max_lifetime_s=1.0) as proc:
                proc.wait(timeout=20)
        self.assertLess(time.monotonic() - t0, 5)

    def test_healthy_fixture_is_not_reported(self):
        with fixture_process(["sleep", "60"], max_lifetime_s=30) as proc:
            time.sleep(0.4)
            self.assertIsNone(proc.poll())
            proc.check()
        self.assertIsNotNone(proc.returncode)

    def test_context_exit_kills_whole_process_group(self):
        code = "import subprocess,sys,time; p=subprocess.Popen(['sleep','300']); print(p.pid,flush=True); time.sleep(300)"
        with fixture_process([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True) as proc:
            child = int(proc.stdout.readline())
            self.assertTrue(_alive(child))
        self.assertTrue(_wait_gone(child, 2.0), "grandchild survived the end of the fixture context")


class ThreadTests(unittest.TestCase):
    def test_launch_from_worker_thread_survives_thread_exit(self):
        box = {}

        def worker():
            box["proc"] = fixture_popen(["sleep", "300"])

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        proc = box["proc"]
        self.addCleanup(proc.kill_tree)
        time.sleep(0.5)   # PDEATHSIG would already have fired if it were tied to the exited worker thread
        self.assertIsNone(proc.poll(), "fixture died when the launching worker thread exited")
        self.assertTrue(_alive(proc.pid))

    def test_sweep_kills_everything_started(self):
        procs = [fixture_popen(["sleep", "300"]) for _ in range(2)]
        for p in procs:
            self.addCleanup(p.kill_tree)
        self.assertGreaterEqual(kill_all_fixtures(), 2)
        for p in procs:
            self.assertTrue(_wait_gone(p.pid, 2.0))


if __name__ == "__main__":
    unittest.main()
