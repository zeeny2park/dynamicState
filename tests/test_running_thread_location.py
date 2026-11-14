"""A running thread has no observed program counter: its stack-sample line is not exact and not "where it runs".

Known defect this guards against: for a busy loop (spin_flag), the line of a stale return address left on the stack
by an earlier call (``pthread_setname_np``) was labelled ``source_line_exact: true`` and reported as the line the
thread spins on.  No zero-stop, read-only source gives a running thread's PC on Linux: ``/proc/<pid>/task/<tid>/stat``
kstkeip/kstkesp are 0, ``syscall`` says ``running`` (no registers), ``wchan`` is 0, ``stack`` needs root and is the
kernel stack.  So such a frame keeps its function (labelled estimated), its location falls back to the function's
definition line, the scanned line is kept apart as ``sampled_source_location``, and the thread summary has no
``top_source_location`` (nothing observed), only ``top_function_decl_location``.
"""

import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.inspection.threads import LINE_BASIS_NOT_OBSERVED, _unobserved_line_frame
from extractor.thread_sampler import ThreadSamplingConfig, ThreadSeries, _top_frame, judge
from tests.support.fixture_process import fixture_popen

SPIN_SRC = """#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

static volatile int go;
static volatile unsigned long laps;

static void *poll_loop(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "poller");
    while (!go)
        laps++;
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, poll_loop, NULL);
    usleep(300000);
    write(1, "READY\\n", 6);
    for (;;)
        pause();
}
"""

EXACT_FRAME = {"function_name": "poll_loop", "resolution_source": "DWARF_SUBPROGRAM", "estimated": True,
               "unwind": "running_sample_estimated", "source_location": "s.c:11", "source_line": 11,
               "source_line_exact": True, "source_line_basis": "DWARF_LINE_TABLE",
               "source_line_text": "pthread_setname_np(pthread_self(), \"poller\");",
               "function_decl_location": "s.c:8", "function_decl_line": 8,
               "inlined_chain": [{"function": "a", "file": "s.c", "line": 11}], "inlined_function": "a",
               "inlined_into": "poll_loop"}


class TestUnobservedFrame(unittest.TestCase):
    def test_exact_line_of_a_sampled_frame_is_demoted(self):
        f = _unobserved_line_frame(EXACT_FRAME)
        self.assertFalse(f["source_line_exact"])
        self.assertEqual(f["source_line_basis"], LINE_BASIS_NOT_OBSERVED)
        self.assertEqual(f["source_location"], "s.c:8")
        self.assertEqual(f["sampled_source_location"], "s.c:11")
        self.assertNotIn("source_line_text", f)
        self.assertNotIn("inlined_function", f)
        self.assertEqual(f["function_name"], "poll_loop")
        self.assertTrue(f["estimated"])
        self.assertTrue(EXACT_FRAME["source_line_exact"])  # input not modified

    def test_non_exact_frame_unchanged(self):
        f = dict(EXACT_FRAME, source_line_exact=False, source_location="s.c:8")
        self.assertIs(_unobserved_line_frame(f), f)

    def test_thread_summary_has_no_observed_location(self):
        top = _top_frame({"callstack": [_unobserved_line_frame(EXACT_FRAME)], "top_user_frame_index": 0})
        self.assertFalse(top["location_observed"])
        s = ThreadSeries(pid=1, config=ThreadSamplingConfig())
        for i in range(5):
            rec = {"tid": 7, "name": "poller", "state": "R", "utime_ticks": i * 25, "stime_ticks": 0,
                   "voluntary_ctxt_switches": 0, "nonvoluntary_ctxt_switches": 0, "io_syscalls": 0,
                   "syscall": None, "top_frame": top}
            s.samples.append({"index": i + 1, "t": i * 0.25, "threads": {7: rec}})
        j = judge(s)
        rows = j["runaway_threads"] or j["thread_summary"]
        r = rows[0]
        self.assertIsNone(r["top_source_location"])
        self.assertFalse(r["top_source_line_exact"])
        self.assertIs(r["top_location_observed"], False)
        self.assertEqual(r["top_function_decl_location"], "s.c:8")
        self.assertEqual(r["top_sampled_return_location"], "s.c:11")
        self.assertNotIn("top_source_text", r)

    def test_report_says_not_observed_and_definition_line(self):
        from extractor.human_report import _Ctx, _render_thread
        row = {"name": "poller", "tid": 7, "top_function": "poll_loop", "top_source_location": None,
               "top_function_decl_location": "s.c:8", "top_location_observed": False, "top_source_line_exact": False,
               "runnable_fraction": 1.0, "cpu_share": 1.0, "cpu_share_pct": 100.0}
        rep = {"section_d_detailed_inspection_results": {"checks": [
            {"recipe_id": "R1", "actual_observations": {"runaway_threads": [row]}}]}}
        for lang, want, not_want in (("en", "was not observed", "running at"), ("ko", "관측하지 못했습니다", None)):
            text = "\n".join(_render_thread(_Ctx(lang), {"recipe_ids": ["R1"], "subjects": []}, rep)["lines"])
            self.assertIn(want, text, lang)
            self.assertIn("s.c:8", text, lang)
            self.assertNotIn("s.c:11", text, lang)
            if not_want:
                self.assertNotIn(not_want, text, lang)


@unittest.skipUnless(shutil.which("gcc"), "gcc not available")
class TestRealSpinningThread(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="runloc_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        src = os.path.join(cls.tmp, "spin_rt.c")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(SPIN_SRC)
        cls.bin = os.path.join(cls.tmp, "spin_rt")
        subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", src, "-o", cls.bin], check=True)
        lines = SPIN_SRC.splitlines()
        cls.setname_line = next(i for i, t in enumerate(lines, 1) if "pthread_setname_np" in t)
        cls.decl_line = next(i for i, t in enumerate(lines, 1) if "static void *poll_loop" in t)

    def _launch(self):
        p = fixture_popen([self.bin], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, max_lifetime_s=120)
        self.addCleanup(p.stdout.close)
        self.addCleanup(p.kill_tree)
        self.assertEqual(p.stdout.readline().strip(), b"READY")
        time.sleep(0.2)
        return p

    def test_no_proc_source_gives_a_running_pc(self):
        p = self._launch()
        tid = next(t for t in os.listdir(f"/proc/{p.pid}/task") if int(t) != p.pid)
        base = f"/proc/{p.pid}/task/{tid}"

        def read(name):
            with open(f"{base}/{name}", encoding="utf-8") as fh:
                return fh.read()
        stat = read("stat")
        rest = stat[stat.rfind(")") + 2:].split()
        self.assertEqual(rest[0], "R")
        self.assertEqual((rest[26], rest[27]), ("0", "0"))      # kstkesp, kstkeip
        for _ in range(5):
            self.assertEqual(read("syscall").strip(), "running")
            self.assertEqual(read("wchan").strip(), "0")

    def test_callstack_and_diagnosis_do_not_claim_the_stale_line(self):
        from extractor.expert_diagnostic_engine import diagnose
        from extractor.human_report import render_human_report
        from extractor.watch_session import WatchSessionManager
        p = self._launch()
        mgr = WatchSessionManager(corpus_dir=os.path.join(self.tmp, "c1"))
        res = mgr.inspect_thread_callstacks_and_locks(pid=p.pid, companion_elf_path=self.bin, max_frames=16)
        th = next(t for t in res["threads"] if t["name"] == "poller")
        self.assertFalse(th["pc_observed"])
        for f in th["callstack"]:
            self.assertFalse(f.get("source_line_exact"), f)
        pl = [f for f in th["callstack"] if f.get("function_name") == "poll_loop"]
        for f in pl:
            self.assertEqual(f["source_location"], f["function_decl_location"])
            self.assertEqual(int(f["source_location"].rsplit(":", 1)[1]), self.decl_line)

        r = diagnose(p.pid, debug_image=self.bin, symptom="this process uses a full CPU core while doing nothing useful",
                     corpus_dir=os.path.join(self.tmp, "c2"), include_report=True)
        d = r.to_dict()
        spin = [f for f in d["findings"] if f["category"] == "PROCESS_INSTABILITY"]
        self.assertTrue(spin, d["findings"])
        locs = [s for f in spin for s in f["subjects"] if re.match(r"^.*spin_rt\.c:\d+$", s)]
        self.assertEqual(locs, [], "a running thread's line is not an observed location")
        self.assertIn("poll_loop", [s for f in spin for s in f["subjects"]])
        md = render_human_report(d, d.get("report"), lang="en")
        self.assertNotIn(f"spin_rt.c:{self.setname_line}", md)
        self.assertNotIn("running at", md)


if __name__ == "__main__":
    unittest.main()
