"""Exact source line of a blocked call (DWARF line table) instead of the function's definition line.

Real processes, fixtures compiled at test time (-g -O0 and -g -O2).  The expected lines are read from the
fixture sources, not hard-coded.  Covers: call-stack result fields, ``diagnose()`` subjects, the en/ko human
summary, inlined-subroutine chain (-O2), the honest fallback for an image without a line table, and the
depth-5 CFI fixture (every caller frame is the call line of the next callee; `addr2line -i` as oracle).
"""

import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.dwarf_indexer import DwarfIndexer
from extractor.expert_diagnostic_engine import diagnose
from extractor.human_report import render_human_report
from extractor.watch_session import WatchSessionManager
from tests.test_imp_011_cfi_unwinding import GROUND_TRUTH, REAL_MAIN_SRC, REAL_MID_SRC
from tests.support.fixture_process import fixture_popen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "real_runtime")
DL_SRC = os.path.join(FIXTURES, "proc_thread_circular_deadlock.c")
IL_SRC = os.path.join(FIXTURES, "proc_thread_inlined_deadlock.c")


def _lines(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read().splitlines()


def _line_of(path, needle, nth=1):
    hits = [i for i, t in enumerate(_lines(path), 1) if needle in t]
    return hits[nth - 1]


def _basename_line(loc):
    m = re.match(r"^(.*):(\d+)$", loc or "")
    return (os.path.basename(m.group(1)), int(m.group(2))) if m else (None, None)


@unittest.skipUnless(shutil.which("gcc"), "gcc not available")
class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="srcline_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.addClassCleanup(DwarfIndexer.clear_cache)
        cls.mgr = WatchSessionManager(corpus_dir=os.path.join(cls.tmp, "corpus"))

    @classmethod
    def build(cls, src, name, *flags):
        out = os.path.join(cls.tmp, name)
        subprocess.run(["gcc", "-g", *flags, "-Wl,--build-id=sha1", src, "-o", out, "-pthread"], check=True)
        return out

    def launch(self, binary, *args, settle=0.6):
        proc = fixture_popen([binary, *args], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)

        def _kill():
            proc.kill()
            proc.wait()

        self.addCleanup(_kill)
        time.sleep(settle)
        self.assertIsNone(proc.poll())
        return proc

    def stacks(self, pid, companion):
        res = self.mgr.inspect_thread_callstacks_and_locks(pid=pid, companion_elf_path=companion, max_frames=32)
        by_fn = {}
        for t in res["threads"]:
            for f in t["callstack"]:
                if f.get("resolution_source") == "DWARF_SUBPROGRAM" and f["function_name"] in ("worker_1", "worker_2"):
                    by_fn[f["function_name"]] = f
        return res, by_fn


class TestDeadlockExactLine(_Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.bin_o0 = cls.build(DL_SRC, "dl_o0", "-O0")
        # same program, image whose line table was removed: subprograms remain, addresses are uncovered
        cls.bin_nolines = os.path.join(cls.tmp, "dl_nolines")
        shutil.copy(cls.bin_o0, cls.bin_nolines)
        subprocess.run(["objcopy", "--remove-section=.debug_line", "--remove-section=.debug_line_str",
                        cls.bin_nolines], check=True)
        cls.line_w1 = _line_of(DL_SRC, "pthread_mutex_lock(&g_mutex_b)")   # worker_1 blocks here
        cls.line_w2 = _line_of(DL_SRC, "pthread_mutex_lock(&g_mutex_a)", 2)  # worker_2 blocks here
        cls.decl_w1 = _line_of(DL_SRC, "static void *worker_1")
        cls.decl_w2 = _line_of(DL_SRC, "static void *worker_2")

    def test_callstack_frames_carry_exact_line_and_definition_line(self):
        p = self.launch(self.bin_o0)
        _res, fr = self.stacks(p.pid, self.bin_o0)
        for fn, line, decl, text in (("worker_1", self.line_w1, self.decl_w1, "g_mutex_b"),
                                     ("worker_2", self.line_w2, self.decl_w2, "g_mutex_a")):
            f = fr[fn]
            self.assertEqual(_basename_line(f["source_location"]), ("proc_thread_circular_deadlock.c", line), f)
            self.assertTrue(f["source_line_exact"])
            self.assertEqual(f["source_line_basis"], "DWARF_LINE_TABLE")
            self.assertEqual(f["function_decl_line"], decl)
            self.assertEqual(f["decl_line"], decl)
            self.assertEqual(_basename_line(f["function_decl_location"])[1], decl)
            self.assertIn(text, f["source_line_text"])
            self.assertNotIn("inlined_chain", f)

    def test_diagnose_subjects_and_summaries(self):
        p = self.launch(self.bin_o0)
        res = diagnose(p.pid, debug_image=self.bin_o0, corpus_dir=os.path.join(self.tmp, "c_diag"),
                       include_report=True)
        dl = [f for f in res.findings if f["category"] == "DEADLOCK_INDICATORS"]
        self.assertTrue(dl, res.findings)
        locs = {_basename_line(s) for f in dl for s in f["subjects"]}
        self.assertIn(("proc_thread_circular_deadlock.c", self.line_w1), locs)
        self.assertIn(("proc_thread_circular_deadlock.c", self.line_w2), locs)
        self.assertNotIn(("proc_thread_circular_deadlock.c", self.decl_w1), locs)
        d = res.to_dict()
        for lang in ("en", "ko"):
            md = render_human_report(d, d.get("report"), lang=lang)
            self.assertIn(f"proc_thread_circular_deadlock.c:{self.line_w1}", md, lang)
            self.assertIn(f"proc_thread_circular_deadlock.c:{self.line_w2}", md, lang)
            self.assertIn("`pthread_mutex_lock(&g_mutex_b)`", md, lang)
            self.assertNotIn(f"proc_thread_circular_deadlock.c:{self.decl_w1}`", md, lang)
            self.assertNotIn("not resolved" if lang == "en" else "해석하지 못했습니다", md, lang)
        en = render_human_report(d, d.get("report"), lang="en")
        self.assertRegex(en, r"`worker_1` \(tid \d+\) is blocked at `[^`]*proc_thread_circular_deadlock\.c:%d`"
                         % self.line_w1)
        ko = render_human_report(d, d.get("report"), lang="ko")
        self.assertRegex(ko, r"proc_thread_circular_deadlock\.c:%d`[^\n]*에서 멈춰 있습니다" % self.line_w1)

    def test_no_line_table_falls_back_to_definition_line_with_honest_wording(self):
        p = self.launch(self.bin_o0)
        _res, fr = self.stacks(p.pid, self.bin_nolines)
        for fn, decl in (("worker_1", self.decl_w1), ("worker_2", self.decl_w2)):
            f = fr[fn]
            self.assertFalse(f["source_line_exact"], f)
            self.assertNotIn("source_line_basis", f)
            self.assertEqual(f["function_decl_line"], decl)
            self.assertEqual(f["source_location"], f["function_decl_location"])
        res = diagnose(p.pid, debug_image=self.bin_nolines, corpus_dir=os.path.join(self.tmp, "c_nl"),
                       include_report=True)
        d = res.to_dict()
        for lang, wording in (("en", "the exact line of the call it is blocked in was not resolved"),
                              ("ko", "정확한 줄은 해석하지 못했습니다")):
            md = render_human_report(d, d.get("report"), lang=lang)
            if "DEADLOCK_INDICATORS" in md:
                self.assertIn(wording, md, lang)
                self.assertNotIn(f"proc_thread_circular_deadlock.c:{self.line_w1}", md, lang)


class TestInlinedChain(_Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.bin_o2 = cls.build(IL_SRC, "il_o2", "-O2", "-fomit-frame-pointer")
        cls.bin_o0 = cls.build(IL_SRC, "il_o0", "-O0")
        cls.line_second = _line_of(IL_SRC, "pthread_mutex_lock(second)")
        cls.decl_lock_pair = _line_of(IL_SRC, "void lock_pair")

    def test_o2_inlined_function_is_named_with_innermost_line(self):
        p = self.launch(self.bin_o2)
        _res, fr = self.stacks(p.pid, self.bin_o2)
        for fn in ("worker_1", "worker_2"):
            f = fr[fn]
            self.assertTrue(f["source_line_exact"], f)
            self.assertEqual(_basename_line(f["source_location"]),
                             ("proc_thread_inlined_deadlock.c", self.line_second), f)
            self.assertEqual(f["inlined_function"], "lock_pair")
            self.assertEqual(f["inlined_into"], fn)
            chain = f["inlined_chain"]
            self.assertEqual([c["function"] for c in chain], ["lock_pair", fn])
            self.assertEqual(chain[0]["line"], self.line_second)
        d = diagnose(p.pid, debug_image=self.bin_o2, corpus_dir=os.path.join(self.tmp, "c_il"),
                     include_report=True).to_dict()
        en = render_human_report(d, d.get("report"), lang="en")
        self.assertIn(f"proc_thread_inlined_deadlock.c:{self.line_second}", en)
        self.assertRegex(en, r"in `lock_pair`, inlined into `worker_[12]`")
        ko = render_human_report(d, d.get("report"), lang="ko")
        self.assertRegex(ko, r"`lock_pair`, `worker_[12]`에 인라인됨")

    def test_o0_has_no_inlined_chain_but_exact_line(self):
        p = self.launch(self.bin_o0)  # always_inline: still inlined at -O0, so the chain is present too
        _res, fr = self.stacks(p.pid, self.bin_o0)
        for fn in ("worker_1", "worker_2"):
            self.assertTrue(fr[fn]["source_line_exact"], fr[fn])
            self.assertEqual(_basename_line(fr[fn]["source_location"])[1], self.line_second)


class TestDepth5CallLines(_Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for name, src in (("main.c", REAL_MAIN_SRC), ("mid.c", REAL_MID_SRC)):
            with open(os.path.join(cls.tmp, name), "w", encoding="utf-8") as fh:
                fh.write(src)
        cls.bins = {}
        for tag, flags in (("o0", ["-O0"]), ("o2", ["-O2", "-fomit-frame-pointer"])):
            out = os.path.join(cls.tmp, f"d5_{tag}")
            subprocess.run(["gcc", "-g", *flags, os.path.join(cls.tmp, "main.c"), os.path.join(cls.tmp, "mid.c"),
                            "-o", out, "-pthread"], check=True)
            cls.bins[tag] = out

    def test_every_caller_frame_line_is_the_call_to_the_next_callee(self):
        for tag, binary in self.bins.items():
            with self.subTest(build=tag):
                p = fixture_popen([binary], stdout=subprocess.PIPE)
                self.addCleanup(p.stdout.close)
                self.addCleanup(p.wait)
                self.addCleanup(p.kill)
                self.assertEqual(p.stdout.readline().strip(), b"READY")
                time.sleep(0.3)
                res = self.mgr.inspect_thread_callstacks_and_locks(pid=p.pid, companion_elf_path=binary,
                                                                    max_frames=32)
                th = next(t for t in res["threads"] if int(t["tid"]) == p.pid)
                frames = th["callstack"]
                names = [f["function_name"] for f in frames]
                i_d = names.index("imp011_level_d")
                chain = frames[i_d:i_d + len(GROUND_TRUTH)]
                self.assertEqual([f["function_name"] for f in chain], GROUND_TRUTH)
                for callee, caller in zip(GROUND_TRUTH, GROUND_TRUTH[1:]):
                    f = chain[GROUND_TRUTH.index(caller)]
                    self.assertTrue(f["source_line_exact"], f)
                    file_, line = _basename_line(f["source_location"])
                    src = _lines(os.path.join(self.tmp, file_))[line - 1]
                    self.assertIn(callee + "(", src, (caller, f["source_location"], src))
                    self.assertGreater(f["function_decl_line"], 0)
                    self.assertNotEqual(line, f["function_decl_line"])
                    if shutil.which("addr2line"):
                        lt = f["low_pc_int"] + f["offset_in_func"]
                        out = subprocess.run(["addr2line", "-i", "-e", binary, f"0x{lt:x}"], capture_output=True,
                                             text=True).stdout.split()[0]
                        self.assertEqual(_basename_line(re.sub(r" .*", "", out))[1], line, (caller, out))
                # the leaf-most user frame (blocked in pthread_mutex_lock) names the lock call itself
                d = chain[0]
                self.assertIn("pthread_mutex_lock(", _lines(os.path.join(self.tmp, "main.c"))[
                    _basename_line(d["source_location"])[1] - 1])


class SourceLineIsCheckoutIndependentTest(unittest.TestCase):
    """The same fixture compiled in two differently named / nested directories (relative source path, different
    cwd and DW_AT_comp_dir, different build-id) resolves to the same exact call line; a transient addr2line
    failure is retried instead of being memoised as "no line table"."""

    @classmethod
    def setUpClass(cls):
        if not (shutil.which("gcc") and shutil.which("addr2line")):
            raise unittest.SkipTest("gcc/addr2line not available")
        cls.tmp = tempfile.mkdtemp(prefix="srcline_dirs_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.addClassCleanup(DwarfIndexer.clear_cache)
        cls.want = _line_of(DL_SRC, "pthread_mutex_lock(&g_mutex_b);", 1)  # worker_1's blocking call

    def _build(self, *parts):
        d = os.path.join(self.tmp, *parts)
        os.makedirs(os.path.join(d, "benchmarks", "t"))
        shutil.copy(DL_SRC, os.path.join(d, "benchmarks", "t", "fx.c"))
        out = os.path.join(d, "fx")
        subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", os.path.join("benchmarks", "t", "fx.c"),
                        "-o", out], cwd=d, check=True)
        return out

    def _call_line_of_worker_1(self, binary):
        idx = DwarfIndexer.get_index(binary)
        sp = next(x for x in idx.subprograms if x.name == "worker_1" and x.low_pc is not None)
        hi = sp.high_pc if sp.high_pc and sp.high_pc > sp.low_pc else sp.low_pc + sp.high_pc
        lines = set()
        for pc in range(sp.low_pc, hi):
            r = idx.resolve_source_line(pc)
            if r:
                lines.add((r["file"], r["line"]))
        return idx, sp, lines

    def test_same_fixture_in_two_checkouts_resolves_the_exact_call_line(self):
        a = self._build("a", ".claude", "worktrees", "agent-x")
        b = self._build("b")
        for binary in (a, b):
            _idx, sp, lines = self._call_line_of_worker_1(binary)
            self.assertIn(("fx.c", self.want), lines, binary)
            self.assertNotEqual(sp.decl_line, self.want)
        cwd = os.getcwd()
        try:  # a relative image path and an unrelated cwd must not matter either
            os.chdir(os.path.dirname(b))
            idx = DwarfIndexer.get_index(os.path.relpath(a))
            self.assertEqual(idx.resolve_source_line(
                next(x for x in idx.subprograms if x.name == "worker_1").low_pc + 4)["file"], "fx.c")
        finally:
            os.chdir(cwd)

    def test_transient_addr2line_failure_is_not_memoised(self):
        from unittest import mock
        binary = self._build("c")
        idx = DwarfIndexer.get_index(binary)
        pc = next(x for x in idx.subprograms if x.name == "worker_1").low_pc + 4
        real = subprocess.run
        calls = []

        def flaky(*args, **kw):
            calls.append(1)
            if len(calls) <= 2:
                raise subprocess.TimeoutExpired(args[0], 1)
            return real(*args, **kw)

        with mock.patch("extractor.dwarf_indexer.subprocess.run", side_effect=flaky):
            self.assertIsNone(idx.resolve_source_line(pc))      # both attempts timed out: unresolved ...
            self.assertEqual(idx.resolve_source_line(pc)["file"], "fx.c")  # ... but not cached as "no entry"


if __name__ == "__main__":
    unittest.main()
