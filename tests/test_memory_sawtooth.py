"""Memory that rises and falls (a sawtooth): what the memory-growth baseline check may and may not clear.

docs/HEALTHY_VERDICT.md, "Scope limit: memory that rises and falls".

Rule-level (no process):
* a fall of the in-use TOTAL across the heap walks refutes a leak only when no unreachable size class and no
  global/static owner grew across every walk (a leak under a periodic working set rises and falls too);
* the cheap /proc trend clears growth only for a series that stayed flat within its resolution: a series that rose
  and fell back, or only fell, escalates to the heap walks;
* when the walks cannot run (heap larger than the walk read budget) the investigation explains why in plain words,
  and the human report's INCONCLUSIVE conclusion quotes it.

Real processes (gcc -g -O0, children killed):
* proc_leak_sawtooth_small.c (unreachable 2000-byte blocks under a 40 x 64 KB batch, walkable heap) -> a MEMORY_LEAK
  finding, never HEALTHY, with the leak question and with the generic symptom (was HEALTHY before the fix);
* proc_leak_sawtooth_large.c (the same leak under ok_sawtooth's ~100 MB batch, heap above the walk budget) -> never
  HEALTHY in either symptom mode;
* the benchmark's healthy control ok_sawtooth (same batch, no leak) -> INCONCLUSIVE, not HEALTHY and no finding, with
  RECIPE_PROCESS_MEMORY_GROWTH the blocking check and the reason "memory growth not judged ..." (the pinned scope
  limit: the walks that could clear it do not fit the default read budget).
"""

import os
import select
import shutil
import subprocess
import tempfile
import time
import unittest
from collections import Counter

from extractor.expert_diagnostic_engine import diagnose
from extractor.human_report import render_human_report
from extractor.leak_attribution import (
    INV_LIMITED,
    V_GROWTH_OWNED,
    V_INSUFFICIENT,
    V_LEAK_UNREACHABLE,
    V_NO_GROWTH,
    V_SHRANK,
    MemoryObservationConfig,
    cheap_trend,
    judge,
    not_judged_explanation,
)
from tests.support.fixture_process import fixture_popen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "real_runtime")
OK_SAWTOOTH = os.path.join(ROOT, "benchmarks", "diagnosis_accuracy", "targets", "ok_sawtooth.c")
LEAK_QUESTION = "memory usage looks high, is it leaking?"
GENERIC = "general health check"
FAULTS = ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT")


def _walk(t, inuse, owners=None, unreach=None):
    return {"ok": True, "t": t, "in_use_bytes": inuse, "in_use_count": inuse // 1024, "mmapped_bytes": 0,
            "owners": owners or {}, "unreachable": unreach or {}}


def _own(kind, root, count, label=None):
    return {"kind": kind, "label": label or kind, "root": root, "count": count, "bytes": count * 1024,
            "paths": Counter({(root or "") + "(->next)*": count}), "arenas": Counter({1: count})}


def _unreach(count, size=2016):
    return {size: {"count": count, "usable_size": size - 8, "mmapped": False, "arenas": Counter({1: count}),
                   "example": "0x1000"}}


SAWTOOTH_TOTAL = (10 << 20, 40 << 20, 70 << 20, 12 << 20)


class TestJudgeFallDoesNotHideALeak(unittest.TestCase):
    cfg = MemoryObservationConfig()

    def test_fall_with_growing_unreachable_class_is_a_leak(self):
        ws = [_walk(i, tot, unreach=_unreach(100 + 80 * i)) for i, tot in enumerate(SAWTOOTH_TOTAL)]
        j = judge(ws, self.cfg)
        self.assertEqual(j["verdict"], V_LEAK_UNREACHABLE)
        self.assertFalse(j["in_use_monotonic_growth"])
        self.assertEqual(j["unreachable_growth"][0]["chunk_size"], 2016)
        self.assertIn("kept growing across every walk", j["facts"][0])

    def test_fall_with_growing_global_owner_is_owned_growth(self):
        ws = [_walk(i, tot, owners={"var::g": _own("static", "g", 1024 + 512 * i)})
              for i, tot in enumerate(SAWTOOTH_TOTAL)]
        self.assertEqual(judge(ws, self.cfg)["verdict"], V_GROWTH_OWNED)

    def test_fall_with_only_stack_held_or_wobbling_classes_is_released(self):
        held = [_walk(i, tot, owners={"stack:7": _own("stack_conservative", None, c, "stack of thread batcher")},
                      unreach=_unreach(u))
                for i, (tot, c, u) in enumerate(zip(SAWTOOTH_TOTAL, (100, 400, 700, 900), (5, 9, 3, 6)))]
        j = judge(held, self.cfg)
        self.assertEqual(j["verdict"], V_SHRANK)          # stack-held growth is a working set; unreachable wobbles
        self.assertEqual(j["held_growth"], [])
        self.assertIn("no unreachable size class or global/static owner grew", j["facts"][0])

    def test_plain_sawtooth_and_plateau_unchanged(self):
        self.assertEqual(judge([_walk(i, t) for i, t in enumerate(SAWTOOTH_TOTAL)], self.cfg)["verdict"], V_SHRANK)
        self.assertEqual(judge([_walk(i, (8 << 20) + (i % 2) * 4096) for i in range(4)], self.cfg)["verdict"],
                         V_NO_GROWTH)


def _samples(rss):
    return [{"t": 0.2 * i, "rss_kb": v, "anon_rw_kb": v + 7000, "heap_vma_kb": 132} for i, v in enumerate(rss)]


class TestCheapTrendClearsOnlyAFlatSeries(unittest.TestCase):
    cfg = MemoryObservationConfig()

    def test_rise_and_fall_is_unsettled(self):
        t = cheap_trend(_samples([50504, 88732, 102896, 64840, 64840, 64840]), self.cfg)   # ok_sawtooth, measured
        self.assertFalse(t["indicates_growth"])
        self.assertTrue(t["unsettled"])
        self.assertTrue(t["rose_and_fell"])
        self.assertEqual(t["max_rise_kb"], 102896 - 50504)

    def test_fall_only_window_is_unsettled(self):
        t = cheap_trend(_samples([100560, 64840, 64840, 64840, 64840]), self.cfg)
        self.assertFalse(t["indicates_growth"])
        self.assertTrue(t["unsettled"])
        self.assertFalse(t["rose_and_fell"])

    def test_flat_or_below_resolution_is_settled(self):
        for rss in ([1352] * 6, [1352, 1400, 1360, 1420, 1380, 1352]):
            t = cheap_trend(_samples(rss), self.cfg)
            self.assertFalse(t["indicates_growth"], rss)
            self.assertFalse(t["unsettled"], rss)

    def test_monotonic_growth_is_growth_not_unsettled(self):
        t = cheap_trend(_samples([3724, 4008, 4360, 4604, 4880, 5048]), self.cfg)   # leak_lru_cache, measured
        self.assertTrue(t["indicates_growth"])
        self.assertFalse(t["unsettled"])


class TestNotJudgedExplanation(unittest.TestCase):
    cfg = MemoryObservationConfig()
    LIMS = ["heap walk 1: BUDGET_EXHAUSTED observation budget exhausted during heap walk: PRECHECK_EXCEEDED_BYTES_READ: "
            "current 139616B + reserved 0B + estimated 65015808B > max 25160609B",
            "only 0 usable heap walk(s); 3 are needed to establish a trend"]

    def test_budget_and_sawtooth(self):
        trend = cheap_trend(_samples([50504, 88732, 102896, 64840, 64840, 64840]), self.cfg)
        nj = not_judged_explanation({"status": INV_LIMITED, "verdict": V_INSUFFICIENT, "limitations": self.LIMS},
                                    trend, self.cfg)
        self.assertEqual(nj["cause"], "heap_above_walk_budget")
        self.assertEqual(nj["walk_bytes_estimated"], 65015808)
        self.assertEqual(nj["bytes_needed"], 3 * 65015808)
        self.assertTrue(nj["rose_and_fell"])
        self.assertTrue(nj["text"].startswith("memory growth not judged: one heap walk of this process needs about "
                                              "62.0 MiB of reads, more than the 24.0 MiB budget"))
        self.assertIn("rose by 51.2 MiB and fell back by 37.2 MiB", nj["text"])
        self.assertIn("a leak under it", nj["text"])
        self.assertNotIn("; ", nj["text"])          # quoted whole as the first limitation

    def test_only_for_insufficient_walks(self):
        trend = cheap_trend(_samples([1352] * 6), self.cfg)
        self.assertIsNone(not_judged_explanation({"status": "COMPLETED", "verdict": V_SHRANK, "limitations": []},
                                                 trend, self.cfg))
        self.assertIsNone(not_judged_explanation({"status": "UNSUPPORTED", "verdict": V_INSUFFICIENT,
                                                  "limitations": []}, trend, self.cfg))

    def test_human_report_conclusion_quotes_the_blocking_check(self):
        why = ("memory growth not judged: one heap walk of this process needs about 62.0 MiB of reads, more than the "
               "24.0 MiB budget left for it")
        res = {"verdict": "INCONCLUSIVE", "findings": [], "target": {"pid": 42, "process_name": "batchd"},
               "checks_run": [{"recipe_id": "RECIPE_PROCESS_MEMORY_GROWTH", "status": "INCONCLUSIVE"}],
               "not_covered": [], "healthy_scope": {"healthy": False, "blocking": [
                   {"kind": "baseline_check_inconclusive", "item": "RECIPE_PROCESS_MEMORY_GROWTH",
                    "reason": "baseline check ended INCONCLUSIVE: " + why + "; heap walk 1: BUDGET_EXHAUSTED x"}]}}
        for lang, word in (("en", "it is not called healthy because the baseline check for memory growth"),
                           ("ko", "정상으로 판정하지 않았습니다")):
            text = render_human_report(res, None, lang=lang)
            conclusion = text.split("\n## ", 2)[1]
            self.assertIn(word, conclusion)
            self.assertIn(why, conclusion)
            self.assertNotIn("BUDGET_EXHAUSTED", conclusion)


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestSawtoothRealProcesses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sawtooth_")
        cls.bins = {}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _launch(self, src):
        if src not in self.bins:
            out = os.path.join(self.tmp, os.path.splitext(os.path.basename(src))[0])
            subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", src, "-o", out],
                           check=True, capture_output=True, timeout=120)
            self.bins[src] = out
        proc = fixture_popen([self.bins[src]], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL)
        self.addCleanup(self._kill, proc)
        buf, deadline = b"", time.monotonic() + 60.0
        while b"READY" not in buf:
            if time.monotonic() > deadline or proc.poll() is not None:
                self.fail("%s did not reach READY" % src)
            r, _, _ = select.select([proc.stdout], [], [], 0.2)
            if r:
                buf += os.read(proc.stdout.fileno(), 4096)
        return proc, self.bins[src]

    @staticmethod
    def _kill(proc):
        try:
            proc.kill()
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            pass
        if proc.stdout:
            proc.stdout.close()

    def _diagnose(self, src, symptom):
        proc, binary = self._launch(src)
        return diagnose(proc.pid, binary, symptom, corpus_dir=os.path.join(self.tmp, "corpus"),
                        include_report=True).to_dict()

    @staticmethod
    def _trend(d):
        for c in d["report"]["section_d_detailed_inspection_results"]["checks"]:
            if c["recipe_id"] == "RECIPE_PROCESS_MEMORY_GROWTH":
                return (c.get("actual_observations") or {}).get("memory_trend") or {}
        return {}

    def test_small_sawtooth_with_leak_is_a_leak(self):
        for symptom in (LEAK_QUESTION, GENERIC):
            with self.subTest(symptom=symptom):
                d = self._diagnose(os.path.join(FIXTURES, "proc_leak_sawtooth_small.c"), symptom)
                self.assertNotEqual(d["verdict"], "HEALTHY", d["summary"])
                self.assertIn("MEMORY_LEAK", [f["category"] for f in d["findings"]], d["summary"])

    def test_large_sawtooth_with_leak_is_never_healthy(self):
        for symptom in (LEAK_QUESTION, GENERIC):
            with self.subTest(symptom=symptom):
                d = self._diagnose(os.path.join(FIXTURES, "proc_leak_sawtooth_large.c"), symptom)
                self.assertNotEqual(d["verdict"], "HEALTHY", d["summary"])
                self.assertFalse(d["healthy_scope"]["healthy"])

    def test_large_healthy_sawtooth_is_inconclusive_with_the_reason(self):
        for symptom in (LEAK_QUESTION, GENERIC):
            with self.subTest(symptom=symptom):
                d = self._diagnose(OK_SAWTOOTH, symptom)
                self.assertEqual(d["findings"], [])
                self.assertNotIn(d["verdict"], FAULTS)
                trend = self._trend(d)
                print("[ok_sawtooth/%s] verdict=%s rss=%s" % (symptom, d["verdict"], trend.get("rss_kb_series")))
                if symptom == GENERIC and not (trend.get("unsettled") or trend.get("indicates_growth")):
                    # the whole window fell on the flat part of a cycle (possible on a loaded host, where the batch
                    # slows down): a flat window clears within its scope; nothing more to pin
                    continue
                self.assertEqual(d["verdict"], "INCONCLUSIVE", d["summary"])
                blocking = d["healthy_scope"]["blocking"]
                mem = [b for b in blocking if b["item"] == "RECIPE_PROCESS_MEMORY_GROWTH"]
                self.assertTrue(mem, blocking)
                self.assertIn("baseline check ended INCONCLUSIVE: memory growth not judged:", mem[0]["reason"])
                text = render_human_report(d, None, lang="en")
                self.assertIn("could not decide: `memory growth not judged", text.split("\n## ", 2)[1])


if __name__ == "__main__":
    unittest.main()
