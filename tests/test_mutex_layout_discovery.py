"""Locks are recognised by their LAYOUT, not by their type name.

* A C++ ``std::mutex`` (``std::recursive_mutex`` / ``std::timed_mutex``) wraps a glibc ``pthread_mutex_t`` at offset
  0.  The orphan-lock / self-deadlock checks used to accept only type names containing "pthread_mutex_t", so a
  ``std::mutex`` whose owner thread had exited was skipped ("0 mutex(es) inspected ... every locked one is owned by
  a live thread") and the diagnosis stayed INCONCLUSIVE.
* Conversely a type whose name merely contains "lock" (clock_t, struct flock, struct Blocker) or a lock type without
  the mutex layout (sem_t, pthread_rwlock_t) must not be decoded as a pthread_mutex_t, and application fields of a
  struct named owner_tid / lock_count must not override the decoded owner / lock word.
* "0 mutexes inspected" is "nothing inspected" (INCONCLUSIVE, listed as a HEALTHY scope item), never a pass that
  claims every mutex is owned by a live thread.
"""
import os
import shutil
import subprocess
import time
import unittest

from extractor.dwarf_indexer import DwarfIndexer
from extractor.inspection.threads import glibc_mutex_layout
from tests.support import adversarial_healthy as adv
from tests.support.fixture_process import fixture_popen
from tests.support.tmpdirs import temp_dir

STD_MUTEX_FAULTS_CPP = r"""
#include <chrono>
#include <cstdio>
#include <mutex>
#include <thread>
#include <unistd.h>
std::mutex g_config_mu;            // locked by a thread that then exits: orphaned
std::recursive_mutex g_rec_mu;     // layout check only
std::timed_mutex g_timed_mu;       // layout check only
std::mutex g_reload_mu;            // locked twice by the same thread: self-deadlock
static void reload_twice() {
    std::lock_guard<std::mutex> a(g_reload_mu);
    g_reload_mu.lock();            // never returns
}
int main() {
    std::thread([] { g_config_mu.lock(); }).join();          // exits holding the lock
    std::thread w1([] { std::lock_guard<std::mutex> g(g_config_mu); });
    std::thread w2([] { std::lock_guard<std::mutex> g(g_config_mu); });
    std::thread s(reload_twice);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::puts("READY");
    std::fflush(stdout);
    for (;;) pause();
}
"""

HAVE_CXX = bool(shutil.which("g++") and shutil.which("gcc"))


@unittest.skipUnless(HAVE_CXX, "needs g++")
class MutexLayoutTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = temp_dir(cls, "mutex_layout_")
        src = os.path.join(cls.out, "std_mutex_faults.cpp")
        with open(src, "w") as fh:
            fh.write(STD_MUTEX_FAULTS_CPP)
        cls.exe = os.path.join(cls.out, "std_mutex_faults")
        subprocess.run(["g++", "-g", "-O0", "-pthread", src, "-o", cls.exe], check=True, capture_output=True)
        cls.lockish = adv.build("lockish_types", cls.out)

    def _var_type(self, exe, name):
        idx = DwarfIndexer.get_index(exe)
        v = next(v for v in idx.global_variables if v.name == name)
        return idx, v.type_offset

    def test_layout_from_dwarf(self):
        for n in ("g_config_mu", "g_rec_mu", "g_timed_mu"):
            self.assertTrue(glibc_mutex_layout(*self._var_type(self.exe, n)), n)
        for n in ("g_last_clock", "g_fl", "g_blocker", "g_block_header", "g_sem_avail", "g_rw", "g_blk"):
            self.assertFalse(glibc_mutex_layout(*self._var_type(self.lockish, n)), n)
        for n in ("g_guarded", "g_cv_mu"):
            self.assertTrue(glibc_mutex_layout(*self._var_type(self.lockish, n)), n)

    def test_std_mutex_orphan_and_self_deadlock_are_found(self):
        from extractor.expert_diagnostic_engine import diagnose
        p = fixture_popen([self.exe], stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (p.kill(), p.wait(timeout=5), p.stdout.close()))
        p.stdout.readline()
        time.sleep(0.3)
        r = diagnose(p.pid, self.exe, "the process hangs", corpus_dir=os.path.join(self.out, "corpus")).to_dict()
        cats = {f.get("category") for f in r.get("findings") or []}
        self.assertIn("ORPHAN_LOCK", cats, r.get("verdict"))
        self.assertIn("SELF_DEADLOCK", cats, r.get("verdict"))
        self.assertIn(r.get("verdict"), ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT"))

    def test_lockish_types_are_not_read_as_mutexes(self):
        from extractor.runtime_evidence_provider import RuntimeEvidenceProvider
        from extractor.inspection.threads import inspect_thread_callstacks_and_locks  # noqa: F401 - import check
        p = fixture_popen([self.lockish], stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (p.kill(), p.wait(timeout=5), p.stdout.close()))
        p.stdout.readline()
        info = RuntimeEvidenceProvider()._inspect_locks(p.pid, self.lockish)
        by_name = {l["name"]: l for l in info.get("locks") or []}
        for n in ("g_sem_avail", "g_sem_wait", "g_rw"):
            if n in by_name:
                self.assertIs(by_name[n].get("glibc_mutex_layout"), False, n)
                self.assertIsNone(by_name[n].get("owner_tid"), n)
        for n in ("g_last_clock", "g_fl", "g_blocker", "g_block_header", "g_blk"):
            self.assertNotIn(n, by_name)
        g = by_name.get("g_guarded") or by_name.get("g_guarded.mu")
        self.assertIsNotNone(g)
        self.assertIsNone(g.get("owner_tid"))            # not the application field owner_tid = 99997
        self.assertFalse(g.get("is_locked"))
        self.assertFalse(info.get("wait_for_edges"))
        self.assertFalse(info.get("deadlock_detected"))


class NothingInspectedTest(unittest.TestCase):
    def test_zero_mutexes_is_not_a_pass(self):
        from extractor.diagnostic_recipes import DiagnosticRecipeRegistry as Registry
        from extractor.recipe_plugins.lock_faults import OBS_LOCK_WAIT_STATE, no_mutex_to_inspect
        lw = {"samples": [{"thread_ids": [1], "locks": [], "waits": []}] * 2, "lock_owner_status": "SUPPORTED",
              "orphan_locks": [], "self_waits": []}
        for rid in ("RECIPE_ORPHAN_LOCK", "RECIPE_SELF_DEADLOCK"):
            r = Registry.evaluate_recipe(rid, {OBS_LOCK_WAIT_STATE: lw})
            self.assertEqual(r.status, "INSUFFICIENT_EVIDENCE", rid)
            self.assertNotIn("owned by a live thread", r.confidence_basis)
            self.assertTrue(r.details.get("nothing_inspected"))
        self.assertTrue(no_mutex_to_inspect({OBS_LOCK_WAIT_STATE: lw}))
        lw2 = dict(lw, samples=[{"thread_ids": [1], "locks": [{"glibc_mutex_layout": True, "state_word": 0}],
                                 "waits": []}] * 2)
        self.assertEqual(Registry.evaluate_recipe("RECIPE_ORPHAN_LOCK", {OBS_LOCK_WAIT_STATE: lw2}).status,
                         "CONTRADICTED")
        self.assertFalse(no_mutex_to_inspect({OBS_LOCK_WAIT_STATE: lw2}))


if __name__ == "__main__":
    unittest.main()
