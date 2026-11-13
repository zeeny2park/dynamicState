"""Double free from free-list repeats (extractor/recipe_plugins/double_free.py, recipe RECIPE_DOUBLE_FREE).

1. Detector on a synthetic glibc 2.39 heap (tcache struct, chunks, an arena) whose "live" memory can differ from
   the walk's copy: a stable repeat is a finding, a repeat that does not hold on re-read is not evidence, clean
   lists are walked completely, a list that never reads consistently is not walked completely.
2. The verdict rule on plain observations (repeat confirmed / transient repeat / clean -> CONTRADICTED / not
   walked -> INSUFFICIENT) and the per-chunk record a caller may supply.
3. Presentation: en/ko text, the chain picture, escaping, no script / event handlers, no Hangul in en.
4. Real processes (gcc): the double-free states that survive glibc's checks are found and named; healthy
   fixtures produce no double-free finding.
"""

import os
import re
import select
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from extractor.diagnostic_recipes import BASELINE_RECIPE_IDS, RECIPE_DOUBLE_FREE, DiagnosticRecipeRegistry
from extractor.heap_walker import (ST_FASTBIN, ST_FREE, ST_IN_USE, ST_INTERNAL, ST_TCACHE, ST_TOP, ChunkTable,
                                   HeapWalkResult, MemorySnapshot, layout_for_version)
from extractor.recipe_plugins.double_free import (OBS_FREE_LIST_REPEATS, DoubleFreeConfig, FreeListRepeatDetector,
                                                  double_free_finding_viz, double_free_rule)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_runtime")
EVIL = "<script>alert(1)</script>"
HEAP = 0x555500000000
ARENA = 0x7f0000010000
LAY = layout_for_version((2, 39))
SZ = 64                                     # chunk size of the lists used below (tcache bin 2 / fastbin 2)
BIN = (SZ - LAY.min_chunk) // LAY.malloc_alignment


class FakeHeap:
    """A heap segment + an arena; ``snap`` is the walk's copy, ``live`` what the reader returns now."""

    def __init__(self, n_chunks=6, size=SZ):
        self.tc = HEAP                      # tcache struct chunk (first chunk of the segment)
        self.chunks = [HEAP + LAY.tcache_chunk_size + i * size for i in range(n_chunks)]
        self.top = self.chunks[-1] + size
        self.end = self.top + 0x1000
        self.mem = bytearray(self.end - HEAP)
        self.arena = bytearray(LAY.ms["bins"] + 254 * 8 + 64)
        self._hdr(self.tc, LAY.tcache_chunk_size | 1)
        for c in self.chunks:
            self._hdr(c, size | 1)
        self._hdr(self.top, (self.end - self.top) | 1)
        self.size = size
        self.states = {c: ST_IN_USE for c in self.chunks}

    # raw memory
    def _hdr(self, c, sf):
        struct.pack_into("<Q", self.mem, c + 8 - HEAP, sf)

    def put(self, addr, val, n=8):
        buf, base = (self.arena, ARENA) if ARENA <= addr < ARENA + len(self.arena) else (self.mem, HEAP)
        struct.pack_into("<Q" if n == 8 else ("<H" if n == 2 else "<i"), buf, addr - base, val)

    def get(self, addr, n):
        for buf, base in ((self.mem, HEAP), (self.arena, ARENA)):
            if base <= addr and addr + n <= base + len(buf):
                return bytes(buf[addr - base:addr - base + n])
        return None

    @staticmethod
    def mangle(slot, ptr):
        return (slot >> 12) ^ ptr

    # free lists
    def tcache(self, chain, count=None, b=BIN):
        user = self.tc + 16
        self.put(user + 2 * b, len(chain) if count is None else count, 2)
        self.put(user + LAY.tcache_entries_off + 8 * b, chain[0] + 16 if chain else 0)
        for i, c in enumerate(chain):
            nxt = chain[i + 1] + 16 if i + 1 < len(chain) else 0
            self.put(c + 16, self.mangle(c + 16, nxt))
            self.states[c] = ST_TCACHE

    def fastbin(self, chain, b=BIN):
        self.put(ARENA + LAY.ms["fastbinsY"] + 8 * b, chain[0] if chain else 0)
        for i, c in enumerate(chain):
            nxt = chain[i + 1] if i + 1 < len(chain) else 0
            self.put(c + 16, self.mangle(c + 16, nxt))
            self.states[c] = ST_FASTBIN

    def walk(self):
        w = HeapWalkResult(status="OK", layout=LAY)
        ct = ChunkTable()
        ct.append(self.tc, LAY.tcache_chunk_size, ST_INTERNAL, 0)
        for c in self.chunks:
            ct.append(c, self.size, self.states[c], 0)
        ct.append(self.top, self.end - self.top, ST_TOP, 0)
        ct.finalize()
        w.chunks = ct
        snap = MemorySnapshot()
        snap.add(HEAP, bytes(self.mem))
        snap.add(ARENA, bytes(self.arena))
        w.snapshot = snap
        w.arenas = [{"address": "0x%x" % ARENA, "segments": [{"first_chunk": "0x%x" % self.tc}]}]
        w.tcache_structs = []
        w.heap_ranges = [(HEAP, self.end)]
        return w


class FakeReader:
    def __init__(self, heap):
        self.heap = heap
        self.bytes_read = 0
        self.on_read = None

    def read_ranges(self, ranges):
        if self.on_read:
            self.on_read()
        out = []
        for a, n in ranges:
            b = self.heap.get(a, n)
            self.bytes_read += len(b or b"")
            out.append(b)
        return out

    def read(self, a, n):
        return self.read_ranges([(a, n)])[0]


def _detect(heap, mutate_live=None, cfg=None):
    w = heap.walk()                          # the walk's copy is taken now
    if mutate_live:
        mutate_live(heap)                    # the target changed its lists after the walk
    r = FakeReader(heap)
    det = FreeListRepeatDetector(w, r, cfg or DoubleFreeConfig(interval_s=0.0), sleep=lambda s: None)
    return det.run(), r


class TestDetector(unittest.TestCase):
    def test_tcache_cycle_counted_twice_is_a_confirmed_repeat(self):
        h = FakeHeap()
        a, b = h.chunks[1], h.chunks[3]
        h.tcache([a, b])
        h.put(b + 16, h.mangle(b + 16, a + 16))          # b -> a: the list returns to a
        h.put(h.tc + 16 + 2 * BIN, 3, 2)                  # free(a), free(b), free(a): count 3
        rec, _ = _detect(h)
        self.assertEqual(rec["status"], "COMPLETED")
        self.assertEqual(len(rec["findings"]), 1, rec)
        f = rec["findings"][0]
        self.assertEqual(f["kind"], "repeat_in_one_list")
        self.assertEqual(f["level"], "confirmed")
        self.assertEqual(f["chunk_address"], "0x%x" % a)
        self.assertEqual(f["chunk_size"], SZ)
        self.assertEqual(f["request_sizes"], [41, 56])
        x = f["lists"][0]
        self.assertEqual((x["list_kind"], x["returns_to"], x["tcache_count"], x["distinct_entries"]), ("tcache", 0, 3, 2))
        self.assertTrue(x["count_includes_repeat"])
        self.assertEqual(f["stable_rereads"], 2)
        self.assertIn("not observable", f["who_freed"])

    def test_fastbin_cycle_and_tcache_plus_fastbin(self):
        h = FakeHeap()
        a, b = h.chunks[0], h.chunks[2]
        h.fastbin([a, b])
        h.put(b + 16, h.mangle(b + 16, a))               # a -> b -> a
        rec, _ = _detect(h)
        self.assertEqual([f["kind"] for f in rec["findings"]], ["repeat_in_one_list"])
        self.assertEqual(rec["findings"][0]["lists"][0]["list_kind"], "fastbin")
        h = FakeHeap()
        a = h.chunks[4]
        h.fastbin([a])
        h.tcache([a])                                    # same word: the tcache next (NULL) is the fastbin fd too
        rec, _ = _detect(h)
        self.assertEqual(len(rec["findings"]), 1, rec)
        f = rec["findings"][0]
        self.assertEqual(f["kind"], "listed_on_two_lists")
        self.assertEqual(sorted(x["list_kind"] for x in f["lists"]), ["fastbin", "tcache"])

    def test_tcache_and_regular_bin(self):
        h = FakeHeap()
        a = h.chunks[1]
        h.tcache([a])
        h._hdr(h.chunks[2], SZ)                          # next chunk's PREV_INUSE clear: a is free in a bin
        h.put(ARENA + LAY.ms["bins"], a)                 # unsorted bin fd
        h.put(ARENA + LAY.ms["bins"] + 8, a)             # unsorted bin bk
        rec, _ = _detect(h)
        self.assertEqual(len(rec["findings"]), 1, rec)
        kinds = [x["list_kind"] for x in rec["findings"][0]["lists"]]
        self.assertEqual(kinds, ["tcache", "bin"])
        self.assertIn("unsorted bin", rec["findings"][0]["lists"][1]["list"])
        # boundary tag alone (no bin link to the chunk) is no claim
        h.put(ARENA + LAY.ms["bins"], 0)
        h.put(ARENA + LAY.ms["bins"] + 8, 0)
        rec, _ = _detect(h)
        self.assertEqual(rec["findings"], [])

    def test_clean_lists_are_walked_completely(self):
        h = FakeHeap()
        h.tcache([h.chunks[0], h.chunks[1], h.chunks[2]])
        h.fastbin([h.chunks[3], h.chunks[5]])
        rec, r = _detect(h)
        self.assertEqual(rec["status"], "COMPLETED")
        self.assertEqual(rec["findings"], [])
        self.assertEqual(rec["not_evidence"], [])
        self.assertEqual((rec["checked"]["tcache_lists"], rec["checked"]["fastbin_lists"],
                          rec["checked"]["list_entries"]), (1, 1, 5))
        self.assertEqual(r.bytes_read, 0)               # nothing re-read when the copy is consistent

    def test_transient_repeat_is_not_evidence(self):
        h = FakeHeap()
        a, b = h.chunks[1], h.chunks[3]
        h.tcache([a, b])
        h.put(b + 16, h.mangle(b + 16, a + 16))
        h.put(h.tc + 16 + 2 * BIN, 3, 2)

        def at_rest(heap):                               # by the time we re-read, the list is a -> b, count 2
            heap.tcache([a, b])
        rec, _ = _detect(h, at_rest)
        self.assertEqual(rec["findings"], [])
        self.assertEqual(len(rec["not_evidence"]), 1)
        self.assertIn("not evidence", rec["not_evidence"][0]["why"])
        self.assertEqual(rec["status"], "COMPLETED")    # the live re-walk ended cleanly

    def test_repeat_that_keeps_changing_is_not_evidence_and_not_complete(self):
        h = FakeHeap()
        a, b, c = h.chunks[1], h.chunks[3], h.chunks[4]
        h.tcache([a, b])
        h.put(b + 16, h.mangle(b + 16, a + 16))
        h.put(h.tc + 16 + 2 * BIN, 3, 2)
        w = h.walk()
        flip = {"n": 0}

        def churn(_s):                                   # the target rewrites the list between our reads
            flip["n"] += 1
            if flip["n"] % 2:
                h.put(b + 16, h.mangle(b + 16, c + 16))
                h.put(c + 16, h.mangle(c + 16, 0x1234560))   # c's link leaves the heap: no clean walk
            else:
                h.put(b + 16, h.mangle(b + 16, a + 16))
        rec = FreeListRepeatDetector(w, FakeReader(h), DoubleFreeConfig(interval_s=0.0), sleep=churn).run()
        self.assertEqual(rec["findings"], [])
        self.assertTrue(rec["not_evidence"])
        self.assertEqual(rec["status"], "INCOMPLETE")
        self.assertTrue(rec["lists_not_walked_completely"])

    def test_list_that_leaves_the_heap_is_not_walked_completely(self):
        h = FakeHeap()
        a = h.chunks[0]
        h.tcache([a])
        h.put(a + 16, h.mangle(a + 16, 0x4141414141410))
        h.put(h.tc + 16 + 2 * BIN, 2, 2)
        rec, _ = _detect(h)
        self.assertEqual(rec["status"], "INCOMPLETE")
        self.assertEqual(rec["findings"], [])
        self.assertIn("not a walked chunk", rec["lists_not_walked_completely"][0]["why"])

    def test_locked_arena_is_not_at_rest(self):
        h = FakeHeap()
        a, b = h.chunks[0], h.chunks[2]
        h.fastbin([a, b])
        h.put(b + 16, h.mangle(b + 16, a))
        h.put(ARENA + LAY.ms["mutex"], 1, 4)             # arena mutex held in every re-read
        rec, _ = _detect(h)
        self.assertEqual(rec["findings"], [])
        self.assertIn("locked", rec["not_evidence"][0]["why"])

    def test_no_safe_linking_caps_at_probable(self):
        lay = layout_for_version((2, 31))
        self.assertFalse(lay.safe_linking)
        h = FakeHeap()
        a, b = h.chunks[1], h.chunks[3]
        # 2.31: raw pointers, 2-byte counts; build the list by hand
        user = h.tc + 16
        h.put(user + 2 * BIN, 3, 2)
        h.put(user + lay.tcache_entries_off + 8 * BIN, a + 16)
        h.put(a + 16, b + 16)
        h.put(b + 16, a + 16)
        w = h.walk()
        w.layout = lay
        rec = FreeListRepeatDetector(w, FakeReader(h), DoubleFreeConfig(interval_s=0.0), sleep=lambda s: None).run()
        self.assertEqual(len(rec["findings"]), 1, rec)
        self.assertEqual(rec["findings"][0]["level"], "confirmed")    # reached straight from the head slot
        h.put(user + lay.tcache_entries_off + 8 * BIN, h.chunks[0] + 16)
        h.put(h.chunks[0] + 16, a + 16)                  # head -> c0 -> a -> b -> a
        h.put(user + 2 * BIN, 4, 2)
        w = h.walk()
        w.layout = lay
        rec = FreeListRepeatDetector(w, FakeReader(h), DoubleFreeConfig(interval_s=0.0), sleep=lambda s: None).run()
        self.assertEqual(rec["findings"][0]["level"], "probable")
        self.assertIn("safe-linking", rec["findings"][0]["level_reason"])


class TestRule(unittest.TestCase):
    def setUp(self):
        self.recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_DOUBLE_FREE)

    def _rule(self, rec, **extra):
        return double_free_rule(self.recipe, dict({OBS_FREE_LIST_REPEATS: rec}, **extra))

    def test_registered_once_from_the_plugin_as_baseline(self):
        self.assertIn(RECIPE_DOUBLE_FREE, BASELINE_RECIPE_IDS)
        self.assertEqual(self.recipe.observations, (OBS_FREE_LIST_REPEATS,))
        self.assertIs(self.recipe.rule, double_free_rule)
        from extractor import diagnostic_recipes as dr
        self.assertFalse(hasattr(dr, "_rule_double_free"))
        self.assertNotIn(RECIPE_DOUBLE_FREE, dr._RULES)
        self.assertIn(RECIPE_DOUBLE_FREE, dr.BUILTIN_RECIPE_IDS)

    def test_confirmed_repeat_is_supported(self):
        f = {"level": "confirmed", "description": "block 0x10 listed twice", "variable": "g_last",
             "chunk_address": "0x0", "user_address": "0x10", "lists": []}
        r = self._rule({"status": "COMPLETED", "findings": [f]})
        self.assertEqual(r.status, "SUPPORTED")
        self.assertEqual(r.details["finding_category"], "INVALID_DOUBLE_FREE")
        self.assertTrue(r.details["corruption_confirmed"])
        self.assertNotIn("certainty_cap", r.details)
        r = self._rule({"status": "COMPLETED", "findings": [dict(f, level="probable", level_reason="no safe-linking")]})
        self.assertEqual(r.status, "SUPPORTED")
        self.assertEqual(r.details["certainty_cap"], "PROBABLE")
        self.assertFalse(r.details["corruption_confirmed"])

    def test_transient_repeat_is_not_a_finding(self):
        rec = {"status": "COMPLETED", "findings": [], "checked": {"tcache_lists": 2, "fastbin_lists": 1},
               "not_evidence": [{"chunk_address": "0x10", "why": "changed between reads: not evidence"}]}
        r = self._rule(rec)
        self.assertEqual(r.status, "CONTRADICTED")
        self.assertIn("transient repeat", r.confidence_basis)

    def test_clean_and_not_walked(self):
        r = self._rule({"status": "COMPLETED", "findings": [], "checked": {"tcache_lists": 3, "list_entries": 9}})
        self.assertEqual(r.status, "CONTRADICTED")
        self.assertIn("walked completely", r.confidence_basis)
        for rec in ({"status": "NOT_CHECKED", "findings": [], "heap_not_checked_reason": "above_baseline_cap",
                     "limitations": ["double free not checked: no usable heap walk (heap larger than baseline cap)"]},
                    {"status": "UNSUPPORTED", "findings": [], "limitations": ["not glibc"]},
                    {"status": "INCOMPLETE", "findings": [],
                     "lists_not_walked_completely": [{"list": "fastbin 2", "why": "torn"}]},
                    {"status": "FAILED", "findings": [], "limitations": ["x"]}, {}):
            with self.subTest(rec=rec.get("status")):
                r = self._rule(rec)
                self.assertEqual(r.status, "INSUFFICIENT_EVIDENCE")
                self.assertTrue(r.confidence_basis)
        self.assertIn("fastbin 2 not walked completely", self._rule(
            {"status": "INCOMPLETE", "findings": [], "lists_not_walked_completely": [{"list": "fastbin 2", "why": "torn"}]}
        ).confidence_basis)

    def test_caller_supplied_chunk_record(self):
        rid = RECIPE_DOUBLE_FREE
        ev = DiagnosticRecipeRegistry.evaluate_recipe
        self.assertEqual(ev(rid, {"double_free_recorded": True}).status, "SUPPORTED")
        self.assertEqual(ev(rid, {"freelist_occurrences": 0, "prev_inuse": 1, "double_free_recorded": False}).status,
                         "CONTRADICTED")
        self.assertEqual(ev(rid, {"freelist_occurrences": 1}).status, "INSUFFICIENT_EVIDENCE")
        self.assertEqual(ev(rid, {}).status, "INSUFFICIENT_EVIDENCE")
        # a recorded duplicate free wins over a clean walk; a clean walk wins over "one chunk unknown"
        self.assertEqual(self._rule({"status": "COMPLETED", "findings": []}, double_free_recorded=True).status, "SUPPORTED")
        self.assertEqual(self._rule({"status": "COMPLETED", "findings": []}, freelist_occurrences=1).status,
                         "CONTRADICTED")


# ------------------------------------------------------------------------------------------------ presentation
def _report(findings):
    return {"section_d_detailed_inspection_results": {"checks": [
        {"recipe_id": RECIPE_DOUBLE_FREE, "status": "FAIL",
         "actual_observations": {OBS_FREE_LIST_REPEATS: {"status": "COMPLETED", "findings": findings}}}]}}


def _result(findings):
    rep = _report(findings)
    return {"verdict": "CONFIRMED_FAULT", "confidence": 0.9, "target": {"pid": 1, "process_name": "p"},
            "findings": [{"category": "INVALID_DOUBLE_FREE", "severity": "HIGH", "status": "CONFIRMED_ROOT_CAUSE",
                          "description": "d", "recipe_ids": [RECIPE_DOUBLE_FREE],
                          "subject_details": [{"kind": "variable", "name": EVIL}], "subjects": [EVIL], "observed": []}],
            "checks_run": [{"recipe_id": RECIPE_DOUBLE_FREE, "status": "FAIL"}], "not_covered": [], "report": rep}


REPEAT = {"kind": "repeat_in_one_list", "level": "confirmed", "chunk_address": "0x5000", "user_address": "0x5010",
          "chunk_size": 64, "request_sizes": [41, 56], "stable_rereads": 2,
          "lists": [{"list": "tcache bin 2 " + EVIL, "list_kind": "tcache", "chain": ["0x5000", "0x5040"],
                     "position": 0, "returns_to": 0, "tcache_count": 3, "distinct_entries": 2}],
          "variable": EVIL, "variable_path": EVIL, "owners": [{"variable": EVIL, "variable_path": EVIL}]}
TWO = {"kind": "listed_on_two_lists", "level": "confirmed", "chunk_address": "0x6000", "user_address": "0x6010",
       "chunk_size": 272, "request_sizes": [249, 264], "stable_rereads": 2,
       "lists": [{"list": "tcache bin 15", "list_kind": "tcache", "chain": ["0x6000"], "position": 0, "returns_to": None},
                 {"list": "unsorted bin of arena 0", "list_kind": "bin", "chain": [], "position": None,
                  "returns_to": None, "evidence": "PREV_INUSE clear " + EVIL}],
       "owner_unknown": "no reference to this block was found"}
LONG = dict(REPEAT, chunk_address="0x7020", user_address="0x7030", lists=[
    {"list": "fastbin 2", "list_kind": "fastbin", "chain": ["0x%x" % (0x7000 + 0x20 * k) for k in range(9)],
     "position": 1, "returns_to": 1}])


class TestPresentation(unittest.TestCase):
    def test_text_en_ko(self):
        from extractor.human_report import render_human_report
        res = _result([REPEAT])
        en = render_human_report(res, res["report"], "en")
        self.assertIn("is listed twice as free on", en)
        self.assertIn("after 2 entries the list returns to it", en)
        self.assertIn("count of that bin says 3 entries, but the list holds only 2", en)
        self.assertIn("the next two allocations of 41-56 bytes can both return `0x5010`", en)
        self.assertIn("free calls are not traced", en)
        self.assertNotRegex(en, "[가-힣]")
        ko = render_human_report(res, res["report"], "ko")
        self.assertIn("두 번 올라 있습니다", ko)
        self.assertIn("관측되지 않았습니다", ko)
        res = _result([TWO])
        en = render_human_report(res, res["report"], "en")
        self.assertIn("on two lists at once: `tcache bin 15`, `unsorted bin of arena 0`", en)
        self.assertIn("No typed variable still points at it", en)

    def test_who_sentence_occurs_once_in_the_picture(self):
        from extractor.report_visuals import build_visual_summary
        for fs in ([REPEAT], [TWO]):
            res = _result(fs)
            for lang, s in (("en", "Which code called free() the second time was not observed"),
                            ("ko", "어느 코드가 두 번째로 free()를 불렀는지는 관측되지 않았습니다")):
                h = build_visual_summary(res, res["report"], lang)
                h = re.sub(r'(?s)<details class="dsv-ck dsv-s-SKIPPED dsv-astext">.*?</details>', "", h)
                self.assertEqual(h.count(s), 1, (fs[0]["kind"], lang))
                self.assertIn("dsv-chip-no", h)

    def test_korean_picture_has_no_english_list_names(self):
        from extractor.report_visuals import build_visual_summary
        f = dict(TWO, lists=[
            {"list": "fastbin 2 (chunk size 64) of arena 0", "list_kind": "fastbin", "chain": ["0x6000"], "position": 0,
             "returns_to": None},
            {"list": "unsorted bin of arena 0", "list_kind": "bin", "chain": [], "position": None, "returns_to": None,
             "evidence": "next chunk's PREV_INUSE bit clear (boundary tag at 0x6118) and unsorted bin fd points to the chunk"}])
        res = _result([f])
        ko = build_visual_summary(res, res["report"], "ko")
        self.assertIn("아레나 0의 fastbin 2 (청크 크기 64)", ko)
        self.assertNotIn("of arena", ko)
        self.assertNotIn("PREV_INUSE bit clear", ko)
        en = build_visual_summary(res, res["report"], "en")
        self.assertIn("fastbin 2 (chunk size 64) of arena 0", en)
        self.assertNotRegex(en, "[가-힣]")

    def test_picture(self):
        from extractor.report_visuals import build_visual_summary
        for fs in ([REPEAT], [TWO], [LONG]):
            res = _result(fs)
            for lang in ("en", "ko"):
                with self.subTest(kind=fs[0]["kind"], lang=lang):
                    h = build_visual_summary(res, res["report"], lang)
                    self.assertNotIn("<script", h)
                    self.assertNotRegex(h, r"\son[a-z]+\s*=")
                    if lang == "en":
                        self.assertNotRegex(h, "[가-힣]")
                    self.assertIn("&lt;script&gt;", h)
                    self.assertIn("dsv-chip-no", h)              # which code freed it twice: not observed
                    self.assertIn("fill:var(--bad-bg)", h)       # the repeated block is highlighted
        lx = type("Lx", (), {"i": 0, "lang": "en", "t": lambda self, k, **kw: k})()
        h = double_free_finding_viz(lx, {}, _report([REPEAT]), "u1")
        self.assertIn('class="dsv-arrow-bad"', h)                # the arrow that returns to the block
        self.assertIn("back to 0x5010", h)
        self.assertIn("Two later allocations of 41-56 bytes can both receive", h)
        self.assertIn("Which code freed it twice", h)
        self.assertEqual(len(re.findall(r'<li data-step="(\d+)"', h)), 4)
        steps = [int(x) for x in re.findall(r'<li data-step="(\d+)"', h)]
        self.assertEqual(steps, [1, 2, 3, 4])
        h = double_free_finding_viz(lx, {}, _report([LONG]), "u2")
        self.assertIn("5 more", h)
        self.assertIn("entry 7", h)                              # boxes after the gap keep their list position
        steps = [int(x) for x in re.findall(r'<li data-step="(\d+)"', h)]
        self.assertEqual(steps, list(range(1, len(steps) + 1)))
        self.assertEqual(double_free_finding_viz(lx, {}, _report([]), "u3"), "")


# ------------------------------------------------------------------------------------------------ real processes
@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="dfree_")
        cls.corpus = os.path.join(cls.tmp, "corpus")
        cls.bins = {}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _launch(self, src):
        if src not in self.bins:
            out = os.path.join(self.tmp, os.path.splitext(src)[0])
            subprocess.run(["gcc", "-g", "-O0", "-pthread", os.path.join(FIXTURES, src), "-o", out], check=True,
                           capture_output=True, timeout=120)
            self.bins[src] = out
        proc = subprocess.Popen([self.bins[src]], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL)

        def kill():
            proc.kill()
            proc.wait(timeout=10)
            proc.stdout.close()
        self.addCleanup(kill)
        deadline = time.monotonic() + 60
        buf = b""
        while b"READY" not in buf:
            r, _, _ = select.select([proc.stdout], [], [], max(0.0, deadline - time.monotonic()))
            if not r:
                self.fail("%s did not print READY" % src)
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                self.fail("%s exited before READY (rc=%s): glibc aborted the double free?" % (src, proc.wait()))
            buf += chunk
        time.sleep(0.1)
        self.assertIsNone(proc.poll())
        return proc, self.bins[src]

    def _diagnose(self, src, symptom=None):
        from extractor.expert_diagnostic_engine import diagnose
        proc, binary = self._launch(src)
        r = diagnose(proc.pid, binary, symptom, corpus_dir=self.corpus, include_report=True).to_dict()
        rec = None
        for c in r["report"]["section_d_detailed_inspection_results"]["checks"]:
            ob = c.get("actual_observations") or {}
            if isinstance(ob.get(OBS_FREE_LIST_REPEATS), dict):
                rec = ob[OBS_FREE_LIST_REPEATS]
        return r, rec

    def test_surviving_double_free_states_are_found_and_named(self):
        for src, kind in (("proc_double_free_fastbin.c", "repeat_in_one_list"),
                          ("proc_double_free_tcache_key.c", "repeat_in_one_list"),
                          ("proc_double_free_tcache_fastbin.c", "listed_on_two_lists"),
                          ("proc_double_free_tcache_bin.c", "listed_on_two_lists")):
            with self.subTest(fixture=src):
                r, rec = self._diagnose(src)
                df = [f for f in r["findings"] if f["category"] == "INVALID_DOUBLE_FREE"]
                self.assertEqual(len(df), 1, (r["verdict"], r["findings"], rec))
                self.assertIn("g_last", df[0]["subjects"])
                self.assertEqual(r["verdict"], "CONFIRMED_FAULT")
                self.assertEqual([f["kind"] for f in rec["findings"]], [kind])
                self.assertEqual(rec["findings"][0]["level"], "confirmed")

    def test_healthy_fixtures_have_no_double_free(self):
        for src in ("proc_heap_churn.c", "proc_uaf_pool_freelist.c", "proc_imp009_churn_mt.c"):
            with self.subTest(fixture=src):
                with open(os.path.join(FIXTURES, src), encoding="utf-8", errors="replace") as fh:
                    if "READY" not in fh.read():
                        self.skipTest("fixture prints no READY")
                for _ in range(3):
                    r, rec = self._diagnose(src)
                    self.assertFalse([f for f in r["findings"] if f["category"] == "INVALID_DOUBLE_FREE"],
                                     (r["findings"], rec))
                    self.assertIsNotNone(rec)
                    self.assertEqual(rec.get("findings"), [], rec)


if __name__ == "__main__":
    unittest.main()
