"""Lock waiters come from the futex syscall record; the stack scan is a marked fallback only."""
import collections
import os
import subprocess
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from benchmarks.diagnosis_accuracy import run_benchmark as rb  # noqa: E402
from extractor.thread_sampler import _lock_digest  # noqa: E402
from extractor.watch_session import WatchSessionManager  # noqa: E402


class LockDigestSeparatesInferredWaiters(unittest.TestCase):
    def test_inferred_waiter_is_not_counted(self):
        info = {"threads": [
            {"tid": 11, "waiting_on_lock": {"lock_address": "0x10", "lock_name": "m"}},
            {"tid": 12, "waiting_on_lock": {"lock_address": "0x10", "lock_name": "m", "inferred": True}},
        ], "locks": [{"name": "m", "runtime_address": "0x10", "owner_tid": 10, "lock_state_word": 2}]}
        row = _lock_digest(info)[0]
        self.assertEqual(row["waiter_tids"], [11])
        self.assertEqual(row["inferred_waiter_tids"], [12])


@unittest.skipUnless(sys.platform.startswith("linux") and os.path.exists("/usr/bin/gcc"), "needs Linux and gcc")
class LiveWaiterSources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        gt = next(g for g in rb.load_ground_truth() if g["id"] == "lock_hotspot")
        cls.binary = rb.build_target(gt, cls.tmp)
        cls.proc = subprocess.Popen([cls.binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    stdin=subprocess.DEVNULL, start_new_session=True)
        rb._wait_ready(cls.proc, gt)

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.wait()

    def _inspect(self, wsm):
        return wsm.inspect_thread_callstacks_and_locks(pid=self.proc.pid, companion_elf_path=self.binary)

    def test_readable_syscall_record_is_authoritative(self):
        wsm = WatchSessionManager(corpus_dir=os.path.join(self.tmp, "c"))
        seen = {}
        orig = wsm._imp011_read_syscall

        def spy(pid, tid):
            r = orig(pid, tid)
            seen[tid] = r.get("state")
            return r
        wsm._imp011_read_syscall = spy
        futex_waiters = 0
        for _ in range(15):
            info = self._inspect(wsm)
            for t in info["threads"]:
                w = t.get("waiting_on_lock")
                if w:
                    self.assertNotEqual(seen.get(t["tid"]), "running", "a running thread was named as a waiter")
                    self.assertFalse(w.get("inferred"), "the syscall record was readable; nothing may be inferred")
                    self.assertEqual(t["syscall"], "futex")
                    futex_waiters += 1
            for lk in info["locks"]:
                self.assertEqual(lk["inferred_waiting_tids"], [])
            time.sleep(0.03)
        self.assertGreater(futex_waiters, 0)

    def test_unreadable_syscall_record_falls_back_and_marks_inferred(self):
        wsm = WatchSessionManager(corpus_dir=os.path.join(self.tmp, "c2"))
        wsm._imp011_read_syscall = lambda pid, tid: {"state": "unavailable"}
        kinds = collections.Counter()
        for _ in range(25):
            info = self._inspect(wsm)
            for t in info["threads"]:
                w = t.get("waiting_on_lock")
                if w:
                    self.assertEqual(w.get("resolved_via"), "STACK_MUTEX_POINTER_SCAN")
                    self.assertIs(w.get("inferred"), True)
                    self.assertEqual(w.get("confidence"), "LOW")
                    kinds["inferred"] += 1
            for lk in info["locks"]:
                self.assertEqual(lk["waiting_tids"], [], "inferred waiters must not enter waiting_tids")
            time.sleep(0.03)
        self.assertGreater(kinds["inferred"], 0)


if __name__ == "__main__":
    unittest.main()
