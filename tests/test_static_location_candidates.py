"""Static location candidates (roadmap stage 3): extractor.static_location_candidates.

Candidates are statically derived (DWARF + line table + source text), labelled as such, ranked, capped, each with
its reason; they never enter ``subjects``, never change a status or verdict, and a finding without a defensible
candidate shows none.  The module never touches the target process (no /proc), so a remote (SSH) target goes the same
way; the end-to-end remote check reuses the loopback transport of ``tests/test_remote_new_diagnoses.py``.
"""

import builtins
import copy
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from extractor import static_location_candidates as slc
from extractor.human_report import REPORT_SECTION_ORDER, render_human_report

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = os.path.join(ROOT, "benchmarks", "diagnosis_accuracy", "targets")
sys.path.insert(0, os.path.join(ROOT, "benchmarks", "diagnosis_accuracy"))
import run_benchmark as rb  # noqa: E402

HAVE_GCC = bool(shutil.which("gcc") and shutil.which("readelf"))


def _finding(category, **subjects):
    det = [{"kind": k, "name": n} for k, names in subjects.items() for n in names]
    return {"category": category, "status": "PROBABLE_CAUSE", "severity": "HIGH",
            "subjects": [d["name"] for d in det], "subject_details": det, "recipe_ids": ["RX"]}


def _runaway_report(function, thread):
    return {"section_d_detailed_inspection_results": {"checks": [{
        "recipe_id": "RX", "status": "FAIL",
        "actual_observations": {"runaway_threads": [{"name": thread, "top_function": function}]}}]}}


@unittest.skipUnless(HAVE_GCC, "gcc/readelf not available")
class StaticCandidateRules(unittest.TestCase):
    """One target per defect kind: the rule finds the ground-truth line, and the honesty contract holds."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="slc_test_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.bins = {}

    def _bin(self, name, src=None, flags=("-g", "-O0")):
        key = (name, src, flags)
        if key not in self.bins:
            out = os.path.join(self.tmp, f"{name}{len(self.bins)}")
            subprocess.run(["gcc", *flags, "-pthread", src or os.path.join(TARGETS, name + ".c"), "-o", out],
                           check=True, capture_output=True, timeout=120)
            self.bins[key] = out
        return self.bins[key]

    def _check_contract(self, lc, finding_before, finding_after):
        self.assertEqual(lc["basis"], "static")
        self.assertIs(lc["observed"], False)
        self.assertLessEqual(len(lc["candidates"]), slc.CANDIDATE_CAP)
        self.assertEqual([c["rank"] for c in lc["candidates"]], list(range(1, len(lc["candidates"]) + 1)))
        for c in lc["candidates"]:
            self.assertEqual((c["basis"], c["observed"]), ("static", False))
            self.assertTrue(c["reason"] and c["reason_ko"], c)
            self.assertNotIn("%", c["reason"] + c["reason_ko"])          # no confidence numbers
            self.assertRegex(c["location"], r"^[\w.\-]+\.c:\d+$")
        self.assertEqual(finding_after, finding_before)                  # subjects / status untouched

    def _top(self, name, finding, truth_lines, report=None, max_rank=1):
        before = copy.deepcopy(finding)
        lc = slc.location_candidates(finding, self._bin(name), report=report)
        self._check_contract(lc, before, finding)
        self.assertEqual(lc["status"], slc.STATUS_FOUND, lc)
        ranks = [c["rank"] for c in lc["candidates"]
                 if c["file"] == name + ".c" and any(abs(c["line"] - t) <= rb.LINE_TOLERANCE for t in truth_lines)]
        self.assertTrue(ranks and min(ranks) <= max_rank, (truth_lines, lc["candidates"]))
        return lc

    def test_leak_with_owner_points_at_the_allocation_linked_into_it(self):
        lc = self._top("leak_registry", _finding("MEMORY_LEAK", variable=["reg_head", "reg_head(->next)*"],
                                                 thread_name=["intake"]), [21])
        self.assertEqual(lc["candidates"][0]["action"], "allocation")

    def test_unreachable_leak_points_at_the_unlink_without_free(self):
        lc = self._top("leak_lru_cache", _finding("MEMORY_LEAK", thread_name=["filler"]), [41])
        self.assertEqual(lc["candidates"][0]["function"], "lru_evict")

    def test_mapping_growth_points_at_the_mmap(self):
        self._top("mapgrow_pool", _finding("MAPPING_GROWTH", variable=["store", "store.head"]), [26])
        self._top("mapgrow_slabs", _finding("MAPPING_GROWTH", variable=["slabs", "slabs[*]"]), [19])

    def test_overflow_points_at_the_copy(self):
        self._top("overflow_tbl", _finding("MEMORY_CORRUPTION", variable=["tbl", "tbl[3]"]), [17])
        # through a parameter of the same type as the named global
        self._top("overflow_ring", _finding("MEMORY_CORRUPTION", variable=["rb", "rb.buf", "aux"]), [24])

    def test_use_after_free_and_double_free(self):
        self._top("uaf_jobq", _finding("USE_AFTER_FREE", variable=["cur"]), [37, 38])
        self._top("uaf_sessions", _finding("USE_AFTER_FREE", variable=["g_sessions", "g_sessions[1]"]), [17, 27])
        self._top("dfree_outbox", _finding("INVALID_DOUBLE_FREE", variable=["last_sent"]), [43, 48])
        self._top("dfree_reqbuf", _finding("INVALID_DOUBLE_FREE", variable=["current"]), [37, 43])

    def test_lock_rules(self):
        self._top("orphan_lock_cfg", _finding("ORPHAN_LOCK", lock=["m_cfg"], thread_name=["reader"]), [11, 19])
        self._top("self_deadlock_registry", _finding("SELF_DEADLOCK", lock=["reg_mu"], thread_name=["registrar"]),
                  [11, 21])
        self._top("deadlock_pipeline", _finding("DEADLOCK_INDICATORS", lock=["m_in", "m_out"],
                                                function=["ingest", "flush"]), [13, 15, 25, 27])

    def test_thread_leak_points_at_the_create_call(self):
        self._top("accept_workers", _finding("THREAD_LEAK", thread_name=["conn_worker"], function=["idle_worker"]),
                  [22])

    def test_busy_loop_needs_an_observed_spinning_thread(self):
        f = _finding("PROCESS_INSTABILITY", thread_name=["poller"], function=["poll_loop"])
        lc = self._top("spin_flag", f, [12], report=_runaway_report("poll_loop", "poller"))
        self.assertIn("`go`", lc["candidates"][0]["reason"])
        # the same finding without a runaway (busy) thread observed: a long wait is no loop to point at
        self.assertEqual(slc.location_candidates(f, self._bin("spin_flag"))["candidates"], [])
        # a loop with a blocking call is not a spin
        self.assertEqual(slc.location_candidates(
            _finding("PROCESS_INSTABILITY", thread_name=["conn_worker"]), self._bin("accept_workers"),
            report=_runaway_report("idle_worker", "conn_worker"))["candidates"], [])

    def test_optimised_build_keeps_the_function_a_statement_is_written_in(self):
        """-O2 inlines job_finish into main: the candidate still names job_finish (source extent of the DIE)."""
        lc = slc.location_candidates(_finding("USE_AFTER_FREE", variable=["cur"]),
                                     self._bin("uaf_jobq", flags=("-g", "-O2")))
        self.assertEqual([(c["location"], c["function"]) for c in lc["candidates"]][:1], [("uaf_jobq.c:37", "job_finish")])

    def test_nothing_defensible_gives_nothing(self):
        lc = slc.location_candidates(_finding("MEMORY_CORRUPTION", variable=["no_such_variable"]),
                                     self._bin("overflow_tbl"))
        self.assertEqual((lc["status"], lc["candidates"]), (slc.STATUS_NONE, []))
        lc = slc.location_candidates(_finding("HEAP_RETENTION", variable=["recs"]), self._bin("overflow_tbl"))
        self.assertEqual((lc["status"], lc["candidates"]), (slc.STATUS_NOT_APPLICABLE, []))

    def test_without_debug_info_there_are_no_candidates(self):
        lc = slc.location_candidates(_finding("MEMORY_CORRUPTION", variable=["tbl"]),
                                     self._bin("overflow_tbl", flags=("-g0", "-O0")))
        self.assertEqual((lc["status"], lc["candidates"]), (slc.STATUS_NO_DEBUG_INFO, []))
        lc = slc.location_candidates(_finding("MEMORY_CORRUPTION", variable=["tbl"]), None)
        self.assertEqual(lc["candidates"], [])

    def test_missing_or_newer_source_gives_no_candidates(self):
        d = tempfile.mkdtemp(dir=self.tmp)
        src = os.path.join(d, "overflow_tbl.c")
        shutil.copy(os.path.join(TARGETS, "overflow_tbl.c"), src)
        os.utime(src, (time.time() - 100, time.time() - 100))
        out = os.path.join(d, "bin")
        subprocess.run(["gcc", "-g", "-O0", src, "-o", out], check=True, capture_output=True, timeout=120)
        f = _finding("MEMORY_CORRUPTION", variable=["tbl"])
        self.assertEqual(slc.location_candidates(f, out)["status"], slc.STATUS_FOUND)
        slc._PROGRAM_CACHE.clear()
        os.utime(src, (time.time() + 100, time.time() + 100))          # edited after the build
        lc = slc.location_candidates(f, out)
        self.assertEqual((lc["status"], lc["candidates"]), (slc.STATUS_NO_SOURCE, []))
        slc._PROGRAM_CACHE.clear()
        os.unlink(src)
        lc = slc.location_candidates(f, out)
        self.assertEqual((lc["status"], lc["candidates"]), (slc.STATUS_NO_SOURCE, []))

    def test_no_process_access(self):
        """Only the debug image and source files are read: nothing under /proc (local or a remote target's pid)."""
        seen = []
        orig_open, orig_stat = builtins.open, os.stat

        def spy_open(p, *a, **k):
            seen.append(os.fspath(p) if not isinstance(p, int) else "")
            return orig_open(p, *a, **k)

        def spy_stat(p, *a, **k):
            seen.append(os.fspath(p) if not isinstance(p, int) else "")
            return orig_stat(p, *a, **k)
        slc._PROGRAM_CACHE.clear()
        builtins.open, os.stat = spy_open, spy_stat
        try:
            lc = slc.location_candidates(_finding("USE_AFTER_FREE", variable=["cur"]), self._bin("uaf_jobq"))
        finally:
            builtins.open, os.stat = orig_open, orig_stat
        self.assertTrue(lc["candidates"])
        self.assertFalse([p for p in seen if str(p).startswith("/proc")], seen)

    def test_attach_sets_the_field_on_every_finding_and_never_raises(self):
        fs = [_finding("USE_AFTER_FREE", variable=["cur"]), _finding("UNKNOWN_THING"), "not a dict"]
        slc.attach_location_candidates(fs, self._bin("uaf_jobq"))
        self.assertTrue(fs[0]["location_candidates"]["candidates"])
        self.assertEqual(fs[1]["location_candidates"]["status"], slc.STATUS_NOT_APPLICABLE)
        slc.attach_location_candidates(fs, "/nonexistent/binary")
        self.assertEqual(fs[0]["location_candidates"]["candidates"], [])


class CandidateScoring(unittest.TestCase):
    """The benchmark keeps candidates out of the strict location metric and reports them on their own."""

    def test_candidate_rank_is_separate_from_location_match(self):
        g = next(x for x in rb.load_ground_truth() if x["id"] == "spin_flag")
        cat = sorted(rb.KIND_CATEGORIES[g["kind"]])[0]
        loc = g["locations"][0]
        cands = {"basis": "static", "observed": False, "candidates": [
            {"rank": 1, "location": "spin_flag.c:99"},
            {"rank": 2, "location": f"{os.path.basename(loc['file'])}:{loc['line'] + 1}"}]}
        res = {"verdict": "PROBABLE_FAULT", "findings": [{"category": cat, "subjects": ["go"],
                                                          "location_candidates": cands}]}
        row = rb.score_result(g, res)
        self.assertFalse(row["location_match"])
        self.assertEqual((row["location_candidate_rank"], row["location_candidate_hit"]), (2, True))
        o = rb.summarize([row])["overall"]
        self.assertEqual((o["location_match"], o["location_candidate_hit"], o["location_candidate_rank1"]), (0, 1, 0))
        # a candidate of a finding of another category does not count
        res["findings"][0]["category"] = "MEMORY_LEAK"
        self.assertIsNone(rb.score_result(g, res)["location_candidate_rank"])


class CandidateReport(unittest.TestCase):
    RESULT = {
        "verdict": "PROBABLE_FAULT", "summary": "", "target": {"pid": 1, "process_name": "spin_flag"},
        "findings": [{
            "category": "PROCESS_INSTABILITY", "status": "PROBABLE_CAUSE", "severity": "MEDIUM",
            "subjects": ["poller", "poll_loop"], "subject_details": [{"kind": "thread_name", "name": "poller"},
                                                                     {"kind": "function", "name": "poll_loop"}],
            "recipe_ids": ["RECIPE_THREAD_STATE_ANOMALIES"],
            "location_candidates": {"basis": "static", "observed": False, "status": "FOUND", "candidates": [{
                "rank": 1, "location": "spin_flag.c:12", "file": "spin_flag.c", "line": 12, "function": "poll_loop",
                "action": "loop", "statement": "while (!go)", "reason": "loop in `poll_loop`; polls `go`",
                "reason_ko": "`poll_loop`의 반복문; `go`를 반복해서 읽음", "basis": "static", "observed": False}]}}],
        "checks_run": [], "not_covered": [],
    }

    def test_markdown_line_and_list_are_labelled_candidates(self):
        md = render_human_report(self.RESULT, lang="ko")
        line = next(x for x in md.splitlines() if "위치 후보" in x and "spin_flag.c:12" in x)
        self.assertIn("관측 아님", line)
        self.assertIn("`go`를 반복해서 읽음", md)
        self.assertNotRegex(md.split("위치 후보", 1)[1].split("##", 1)[0], r"\d+\s*%")
        en = render_human_report(self.RESULT, lang="en")
        self.assertIn("**Location candidates** (static analysis, not observed): `spin_flag.c:12`.", en)

    def test_no_candidates_no_line(self):
        res = copy.deepcopy(self.RESULT)
        res["findings"][0]["location_candidates"] = {"basis": "static", "observed": False, "status": "NO_SOURCE",
                                                     "candidates": []}
        self.assertNotIn("위치 후보", render_human_report(res, lang="ko"))
        del res["findings"][0]["location_candidates"]
        self.assertNotIn("위치 후보", render_human_report(res, lang="ko"))

    def test_html_card_has_the_candidate_disclosure_and_section_order_is_unchanged(self):
        from extractor.human_report import compose
        from extractor.report_visuals import _finding_card, _Lx
        comp = compose(self.RESULT, None, "ko")
        html = _finding_card(_Lx("ko"), 1, comp["res"]["findings"][0], None, comp["blocks"][0])
        m = re.search(r'<details class="collapsible dsv-cands" id="finding-1-candidates">(.*?)</details>', html, re.S)
        self.assertTrue(m, html[:2000])
        self.assertIn("위치 후보 (정적 분석, 관측 아님)", m.group(1))
        self.assertIn("spin_flag.c:12", m.group(1))
        self.assertEqual(REPORT_SECTION_ORDER, ("conclusion", "tiles", "target", "profile", "findings", "checks",
                                                "not_examined", "next", "hypothesis", "method", "reproducibility",
                                                "reference"))


@unittest.skipUnless(HAVE_GCC and shutil.which("make") and os.path.exists("/proc/self/mem"),
                     "gcc/make/procfs not available")
class CandidatesEndToEnd(unittest.TestCase):
    """diagnose() attaches the candidates, local and through the remote (SSH) adapter path, identically, and the
    remote run reads nothing of the target from the local /proc."""

    def test_local_and_remote(self):
        from extractor.expert_diagnostic_engine import TargetSpec, diagnose
        from tests.support.fixture_process import fixture_popen
        from tests.test_remote_new_diagnoses import COLLECTOR_SRC, LocalProcSpy, local_sh_runner, local_sh_stream
        tmp = tempfile.mkdtemp(prefix="slc_e2e_")
        self.addCleanup(shutil.rmtree, tmp, True)
        build = os.path.join(tmp, "build")
        shutil.copytree(COLLECTOR_SRC, build,
                        ignore=shutil.ignore_patterns("*.o", "dist", "dynamicstate-collector", "test_crypto"))
        if subprocess.run(["make", "-C", build, "dynamicstate-collector"], capture_output=True).returncode != 0:
            self.skipTest("native collector build failed")
        binary = os.path.join(tmp, "uaf_jobq")
        subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", os.path.join(TARGETS, "uaf_jobq.c"),
                        "-o", binary], check=True, capture_output=True, timeout=120)

        def launch():
            proc = fixture_popen([binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

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
                self.assertLess(time.monotonic(), deadline)
                r, _, _ = select.select([proc.stdout], [], [], 0.2)
                if r:
                    chunk = os.read(proc.stdout.fileno(), 65536)
                    self.assertTrue(chunk)
                    buf += chunk
            return proc

        symptom = "this program crashes sometimes and data looks wrong"
        corpus = os.path.join(tmp, "corpus")
        loc = diagnose(launch().pid, binary, symptom, corpus_dir=corpus).to_dict()
        proc = launch()
        spec = TargetSpec(remote_host="board.example", ssh_user="root",
                          collector_path=os.path.join(build, "dynamicstate-collector"),
                          command_runner=local_sh_runner, stream_opener=local_sh_stream)
        with LocalProcSpy(proc.pid) as spy:
            rem = diagnose(proc.pid, binary, symptom, corpus_dir=corpus, target=spec).to_dict()
        self.assertEqual(spy.hits, [])

        def cands(d):
            f = next((f for f in d["findings"] if f["category"] == "USE_AFTER_FREE"), None)
            if f is None:
                self.skipTest(f"no USE_AFTER_FREE finding in this window (load {os.getloadavg()[0]:.1f}): {d['summary']}")
            lc = f["location_candidates"]
            self.assertFalse({c["location"] for c in lc["candidates"]} & set(f["subjects"]))
            return [(c["rank"], c["location"]) for c in lc["candidates"]]
        self.assertEqual(cands(loc)[0], (1, "uaf_jobq.c:37"))
        self.assertEqual(cands(rem), cands(loc))


if __name__ == "__main__":
    unittest.main()
