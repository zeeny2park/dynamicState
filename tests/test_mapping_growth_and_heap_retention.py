"""Memory growth outside malloc (recipe_plugins/mapping_growth) and heap retention (recipe_plugins/heap_retention).

Rules and presentation on synthetic observations (positive, healthy -> CONTRADICTED, too little evidence ->
INSUFFICIENT_EVIDENCE), the pure helpers, and one live check per diagnosis on the benchmark targets.
"""
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor import report_registry as rr  # noqa: E402
from extractor.diagnostic_recipes import (  # noqa: E402
    BASELINE_RECIPE_IDS,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipeRegistry,
)
from extractor.human_report import render_human_report  # noqa: E402
from extractor.recipe_plugins import heap_retention as hr  # noqa: E402
from extractor.recipe_plugins import mapping_growth as mg  # noqa: E402
from extractor.report_visuals import build_visual_summary  # noqa: E402
from tests.support.fixture_process import fixture_popen

EVIL = "<script>alert(1)</script>"
HANGUL = "[가-힣]"


def _mg_obs(nets=(1536, 1536, 1536), rss=(10000, 11536, 13072, 14608), owners=True, walks=True, path="slabs[*]"):
    samples, cum = [], 0
    for k, r in enumerate(rss):
        if k:
            cum += nets[k - 1]
        samples.append({"t_s": 0.3 * k, "rss_kb": r, "threads": 2, "anon_rw_kb": 20000 + cum, "malloc_heap_kb": 132,
                        "outside_growth_kb": cum})
    steps = [{"added_outside_kb": max(n, 0), "added_stack_like_kb": 0, "added_malloc_kb": 0,
              "removed_outside_kb": max(-n, 0), "removed_malloc_kb": 0, "net_outside_kb": n} for n in nets]
    o = {"samples": samples, "steps": steps, "t0": 100.0, "outside_growth_kb": cum, "rss_growth_kb": rss[-1] - rss[0],
         "malloc_growth_kb": 0,
         "grown_mappings": [{"start": "0x7f0000000000", "end": "0x7f0001800000", "size_kb": 24576, "added_kb": cum,
                             "kind": "anonymous", "appeared": False}],
         "grown_mapping_count": 1, "new_anonymous_mappings": 0, "thread_stack_like_kb": 0,
         "owner_search": {"status": "COMPLETED", "owners": [
             {"variable": path.split("[")[0].split(".")[0], "variable_path": path, "root_kind": "static",
              "module": "t", "pointers_into_new_ranges": 18}] if owners else []},
         "heap_walks": [{"t": 99.5, "in_use_bytes": 288}, {"t": 100.4, "in_use_bytes": 288}] if walks else []}
    return o


def _hr_obs(sysm=20 << 20, inuse=5 << 20, free=15 << 20, status="COMPLETED", flat=True, leak_walks=()):
    ps = [{"t_s": 0.0, "heap_mapping_bytes": sysm, "rss_kb": 21000},
          {"t_s": 0.3, "heap_mapping_bytes": sysm if flat else sysm + (1 << 20), "rss_kb": 21000},
          {"t_s": 0.6, "heap_mapping_bytes": sysm if flat else sysm + (2 << 20), "rss_kb": 21000}]
    ar = {"index": 0, "is_main": True, "system_mem": sysm, "in_use_bytes": inuse, "free_bytes": free,
          "free_chunks": 20004, "top_bytes": 65536, "free_by_list": {"bins": free - 2048, "tcache": 2048, "fastbins": 0},
          "largest_free": 768}
    o = {"status": status, "proc_samples": ps, "limitations": [], "leak_walks": list(leak_walks)}
    if status == "COMPLETED":
        o.update(arenas=[ar], totals={k: ar[k] for k in ("system_mem", "in_use_bytes", "free_bytes", "free_chunks",
                                                         "top_bytes", "largest_free")},
                 mmapped_bytes=0, mmapped_chunks=0, walk_source="own_walk", walk_status="OK")
    return o


def _eval(rule, rid, obs_key, obs):
    return rule(DiagnosticRecipeRegistry.get_recipe(rid), {obs_key: obs})


class TestMappingGrowthRule(unittest.TestCase):
    def ev(self, obs):
        return _eval(mg.mapping_growth_rule, mg.RECIPE_MAPPING_GROWTH, mg.OBS_MAPPING_GROWTH, obs)

    def test_registered_as_baseline_with_its_own_category(self):
        self.assertIn(mg.RECIPE_MAPPING_GROWTH, BASELINE_RECIPE_IDS)
        self.assertEqual(DiagnosticRecipeRegistry.get_recipe(mg.RECIPE_MAPPING_GROWTH).problem_category, "MAPPING_GROWTH")

    def test_sustained_growth_outside_malloc_is_supported_capped_and_names_the_owner(self):
        r = self.ev(_mg_obs())
        self.assertEqual(r.status, RECIPE_STATUS_SUPPORTED)
        self.assertEqual(r.details["finding_category"], "MAPPING_GROWTH")
        self.assertEqual(r.details["certainty_cap"], "PROBABLE")
        self.assertEqual(r.details["owners"], [{"variable": "slabs", "variable_path": "slabs[*]"}])
        self.assertTrue(any("slabs[*]" in f for f in r.supporting_facts))
        self.assertTrue(any("+4608 KB" in f for f in r.supporting_facts))

    def test_nothing_outside_malloc_is_contradicted(self):
        r = self.ev(_mg_obs(nets=(0, 0, 0), rss=(10000, 10000, 10000, 10000), owners=False))
        self.assertEqual(r.status, RECIPE_STATUS_CONTRADICTED)
        r = self.ev(_mg_obs(nets=(64, -64, 0), rss=(10000, 10300, 10600, 10900), owners=False))   # churn, net 0
        self.assertEqual(r.status, RECIPE_STATUS_CONTRADICTED)

    def test_too_little_evidence_is_insufficient(self):
        o = _mg_obs()
        o["samples"], o["steps"] = o["samples"][:1], []
        self.assertEqual(self.ev(o).status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(self.ev({"unavailable": "x", "samples": [], "steps": []}).status,
                         RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        # growth that is not sustained at every step, or not resident, decides nothing
        self.assertEqual(self.ev(_mg_obs(nets=(2048, -512, 1024))).status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(self.ev(_mg_obs(rss=(10000, 10000, 10010, 10020))).status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)


class TestMappingGrowthHelpers(unittest.TestCase):
    def test_subtract(self):
        self.assertEqual(mg._subtract([(0, 100)], [(10, 20), (50, 60)]), [(0, 10), (20, 50), (60, 100)])
        self.assertEqual(mg._subtract([(0, 100)], [(0, 100)]), [])
        self.assertEqual(mg._subtract([(0, 10), (20, 30)], []), [(0, 10), (20, 30)])

    def test_anonymous_mapping_classes(self):
        H = mg.HEAP_MAX_SIZE
        maps = [{"start_int": 0x1000, "end_int": 0x2000, "permissions": "rw-p", "pathname": "[heap]"},
                {"start_int": 4 * H, "end_int": 4 * H + 0x21000, "permissions": "rw-p", "pathname": ""},
                {"start_int": 5 * H + 0x1000, "end_int": 5 * H + 0x2000, "permissions": "---p", "pathname": ""},
                {"start_int": 5 * H + 0x2000, "end_int": 5 * H + 0x802000, "permissions": "rw-p", "pathname": ""},
                {"start_int": 6 * H + 0x5000, "end_int": 6 * H + 0x45000, "permissions": "rw-p", "pathname": ""},
                {"start_int": 7 * H, "end_int": 7 * H + 0x1000, "permissions": "r--p", "pathname": "/lib/x.so"}]
        kinds = [m["kind"] for m in mg._anon_rw(maps)]
        self.assertEqual(kinds, ["malloc_heap", "malloc_heap", "thread_stack_like", "anonymous"])

    def test_mmapped_chunk_chain_is_malloc(self):
        class Rd(mg._Reader):
            def __init__(self, mem):
                super().__init__(None, 1)
                self.mem = mem

            def read_many(self, ranges):
                return [self.mem.get(a) for a, _ in ranges]
        base = 0x7f0000000000
        two = {base: struct.pack("<QQ", 0, 0x200000 | 0x2), base + 0x200000: struct.pack("<QQ", 0, 0x200000 | 0x2)}
        self.assertEqual(mg._malloc_chain(Rd(two), base, base + 0x400000), 0x400000)
        self.assertEqual(mg._malloc_chain(Rd({base: b"\x5a" * 16}), base, base + 0x40000), 0)   # application data
        self.assertEqual(mg._malloc_chain(Rd({}), base, base + 0x40000), 0)                     # unreadable


class TestHeapRetentionRule(unittest.TestCase):
    def ev(self, obs):
        return _eval(hr.heap_retention_rule, hr.RECIPE_HEAP_RETENTION, hr.OBS_HEAP_RETENTION, obs)

    def test_not_baseline_and_planned_for_memory_symptoms_under_its_own_category(self):
        self.assertNotIn(hr.RECIPE_HEAP_RETENTION, BASELINE_RECIPE_IDS)
        rec = DiagnosticRecipeRegistry.get_recipe(hr.RECIPE_HEAP_RETENTION)
        self.assertEqual(rec.problem_category, "HEAP_RETENTION")        # contradicting evidence never joins MEMORY_LEAK
        self.assertIn("MEMORY_LEAK", rec.applicable_problem_categories)

    def test_large_free_but_held_heap_with_flat_in_use_is_a_non_fault_finding(self):
        r = self.ev(_hr_obs(leak_walks=[{"t": 1.0, "in_use_bytes": 5 << 20}, {"t": 1.5, "in_use_bytes": 5 << 20}]))
        self.assertEqual(r.status, RECIPE_STATUS_SUPPORTED)
        self.assertEqual(r.details["finding_category"], "HEAP_RETENTION")
        self.assertEqual(r.details["finding_severity"], "INFO")
        self.assertTrue(r.details["non_fault"])
        self.assertEqual(r.details["certainty_cap"], "PROBABLE")
        self.assertIn("15.0 MiB free", r.confidence_basis)

    def test_small_heap_or_little_free_memory_is_contradicted(self):
        small = {"status": "SMALL_HEAP", "reason": "heap mappings 1.0 MiB, below 16 MiB", "proc_samples": [],
                 "limitations": []}
        self.assertEqual(self.ev(small).status, RECIPE_STATUS_CONTRADICTED)
        self.assertEqual(self.ev(_hr_obs(sysm=12 << 20, inuse=2 << 20, free=10 << 20)).status, RECIPE_STATUS_CONTRADICTED)
        self.assertEqual(self.ev(_hr_obs(inuse=14 << 20, free=6 << 20)).status, RECIPE_STATUS_CONTRADICTED)
        self.assertEqual(self.ev(_hr_obs(sysm=40 << 20, inuse=22 << 20, free=18 << 20)).status,
                         RECIPE_STATUS_CONTRADICTED)                       # free < 50 % of the arena memory

    def test_no_walk_or_growing_heap_is_insufficient(self):
        for st in ("NOT_CHECKED", "UNSUPPORTED", "HEAP_GROWING"):
            self.assertEqual(self.ev(_hr_obs(status=st)).status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE, st)
        self.assertEqual(self.ev({}).status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(self.ev(_hr_obs(flat=False)).status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        growing = [{"t": 1.0, "in_use_bytes": 5 << 20}, {"t": 1.5, "in_use_bytes": 6 << 20}]
        self.assertEqual(self.ev(_hr_obs(leak_walks=growing)).status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    def test_arena_usage_from_a_walk(self):
        from extractor.heap_walker import (ST_FASTBIN, ST_FREE, ST_IN_USE, ST_INTERNAL, ST_MMAPPED, ST_TCACHE, ST_TOP,
                                           ChunkTable)

        class W:
            pass
        w = W()
        w.arenas = [{"index": 0, "is_main": True, "system_mem": 1 << 20}, {"index": 1, "is_main": False, "system_mem": 1 << 16}]
        ct = ChunkTable()
        for a, sz, st, ai in ((0x1000, 0x290, ST_INTERNAL, 0), (0x1290, 0x100, ST_IN_USE, 0), (0x1390, 0x100, ST_FREE, 0),
                              (0x1490, 0x40, ST_TCACHE, 0), (0x14d0, 0x20, ST_FASTBIN, 0), (0x14f0, 0x1000, ST_TOP, 0),
                              (0x9000, 0x200, ST_IN_USE, 1), (0x80000, 0x21000, ST_MMAPPED, -1)):
            ct.append(a, sz, st, ai)
        ct.finalize()
        w.chunks = ct
        u = hr.arena_usage(w)
        a0 = u["arenas"][0]
        self.assertEqual((a0["in_use_bytes"], a0["free_bytes"], a0["free_chunks"], a0["top_bytes"]),
                         (0x390, 0x160, 3, 0x1000))
        self.assertEqual(a0["free_by_list"], {"bins": 0x100, "tcache": 0x40, "fastbins": 0x20})
        self.assertEqual(u["totals"]["system_mem"], (1 << 20) + (1 << 16))
        self.assertEqual((u["mmapped_bytes"], u["mmapped_chunks"]), (0x21000, 1))


def _result(cat, rid, obs_key, obs, verdict, severity, subjects):
    f = {"category": cat, "severity": severity, "status": "PROBABLE_CAUSE", "description": "d", "recipe_ids": [rid],
         "subjects": [s["name"] for s in subjects], "subject_details": subjects, "observed": ["seen"]}
    check = {"recipe_id": rid, "status": "FAIL", "name": "n", "actual_observations": {obs_key: obs}}
    return {"verdict": verdict, "confidence": 0.8, "findings": [f], "not_covered": [],
            "checks_run": [{"recipe_id": rid, "status": "FAIL"}], "target": {"pid": 1, "process_name": "p"},
            "report": {"section_d_detailed_inspection_results": {"checks": [check]}}}


class TestPresentation(unittest.TestCase):
    def test_labels_registered_from_the_plugin_files(self):
        self.assertEqual(rr.category_label("MAPPING_GROWTH")[0], "memory growth outside malloc")
        self.assertEqual(rr.category_label("HEAP_RETENTION")[0], "heap memory held but not in use (fragmentation)")
        self.assertEqual(rr.recipe_label(mg.RECIPE_MAPPING_GROWTH)[0], "MEMORY_GROWTH")
        self.assertEqual(rr.recipe_label(hr.RECIPE_HEAP_RETENTION)[0], "MEMORY_GROWTH")

    def _check_html(self, h, lang):
        self.assertNotIn("<script", h)
        self.assertNotIn(EVIL, h)
        self.assertNotRegex(h, r"\son[a-z]+\s*=")                  # no event-handler attributes
        if lang == "en":
            self.assertNotRegex(h, HANGUL)

    def test_mapping_growth_text_and_picture(self):
        obs = _mg_obs(path=EVIL)
        obs["grown_mappings"][0]["start"] = EVIL
        res = _result("MAPPING_GROWTH", mg.RECIPE_MAPPING_GROWTH, mg.OBS_MAPPING_GROWTH, obs, "PROBABLE_FAULT", "MEDIUM",
                      [{"kind": "variable", "name": EVIL}])
        en = render_human_report(res, res["report"], "en")
        self.assertIn("Memory outside malloc grew by +4608 KB in 0.9 s while RSS grew by +4608 KB", en)
        self.assertIn("18 pointer(s) in the static variable", en)
        self.assertIn("The heap in use changed by +0 KB across 2 heap walks.", en)
        self.assertIn("Which code maps this memory was not observed", en)
        self.assertNotRegex(en, HANGUL)
        ko = render_human_report(res, res["report"], "ko")
        self.assertIn("malloc 밖의 메모리가 +4608 KB 늘었고", ko)
        for lang in ("en", "ko"):
            h = build_visual_summary(res, res["report"], lang)
            self._check_html(h, lang)
            self.assertIn("&lt;script&gt;", h)
            # RSS, outside malloc, malloc heap; the heap in use has one walk inside the sampled window: no lone dot
            self.assertEqual(h.count("<polyline"), 3)
            self.assertIn("dsv-chip-no", h)                           # which code mapped it: not observed
        h = build_visual_summary(res, res["report"], "en")
        self.assertIn("Mappings that appeared or grew", h)
        self.assertIn("anonymous mappings outside the malloc heap", h)

    def test_mapping_growth_chart_shares_one_time_axis(self):
        obs = _mg_obs()
        obs["heap_walks"] = [{"t": 100.0, "in_use_bytes": 288}, {"t": 100.6, "in_use_bytes": 576}]
        res = _result("MAPPING_GROWTH", mg.RECIPE_MAPPING_GROWTH, mg.OBS_MAPPING_GROWTH, obs, "PROBABLE_FAULT", "MEDIUM",
                      [{"kind": "variable", "name": "x"}])
        h = build_visual_summary(res, res["report"], "en")
        self.assertEqual(h.count("<polyline"), 4)
        # the first sample sits on the left edge of the plot (x = 70) for every series, incl. the heap walks
        self.assertEqual(len(re.findall(r'<circle class="dsv-pt"[^>]* cx="70\.0"', h)), 4)
        ticks = re.findall(r'text-anchor="middle" font-size="11">(\d+\.\d)</text>', h)
        self.assertEqual(ticks, ["0.0", "0.2", "0.4", "0.7", "0.9"])   # seconds on the x axis
        ys = [t for t in re.findall(r'text-anchor="end" font-size="11">([\d,]+)</text>', h)]
        self.assertEqual(ys[0], "0")                                      # y axis starts at 0
        self.assertEqual(len(set(ys)), len(ys))
        # a single heap walk: no lone dot, its value is in the facts
        obs["heap_walks"] = [{"t": 100.2, "in_use_bytes": 4096}]
        res = _result("MAPPING_GROWTH", mg.RECIPE_MAPPING_GROWTH, mg.OBS_MAPPING_GROWTH, obs, "PROBABLE_FAULT", "MEDIUM",
                      [{"kind": "variable", "name": "x"}])
        h = build_visual_summary(res, res["report"], "en")
        self.assertEqual(h.count("<polyline"), 3)
        self.assertNotIn("heap in use (heap walks)", h)
        self.assertIn("The heap in use was 4 KB at the one heap walk", h)

    def test_mapping_growth_without_owner_or_walk_says_so(self):
        res = _result("MAPPING_GROWTH", mg.RECIPE_MAPPING_GROWTH, mg.OBS_MAPPING_GROWTH,
                      _mg_obs(owners=False, walks=False), "PROBABLE_FAULT", "MEDIUM", [{"kind": "variable", "name": "x"}])
        en = render_human_report(res, res["report"], "en")
        self.assertIn("No typed global or static variable points into the new memory", en)
        self.assertIn("The heap in use was not walked in this diagnosis.", en)

    def test_heap_retention_text_and_picture_without_subjects(self):
        res = _result("HEAP_RETENTION", hr.RECIPE_HEAP_RETENTION, hr.OBS_HEAP_RETENTION, _hr_obs(), "DEGRADED", "INFO", [])
        en = render_human_report(res, res["report"], "en")
        self.assertIn("The malloc arenas hold 20.0 MiB from the system, but only 5.0 MiB of it is in use", en)
        self.assertIn("not a leak", en)
        self.assertIn("Which allocation pattern left these gaps was not observed.", en)
        self.assertNotRegex(en, HANGUL)
        ko = render_human_report(res, res["report"], "ko")
        self.assertIn("malloc 아레나가 시스템에서 20.0 MiB를 받아 두고", ko)
        for lang in ("en", "ko"):
            h = build_visual_summary(res, res["report"], lang)
            self._check_html(h, lang)
            self.assertIn("dsv-meter", h)
            self.assertIn("dsv-chip-no", h)
        self.assertIn("free but held", build_visual_summary(res, res["report"], "en"))

    def test_heap_retention_small_chunks_print_bytes_and_missing_value_drops_the_clause(self):
        for lang, word in (("en", "the largest free chunk 768 B"), ("ko", "가장 큰 빈 청크 768 B")):
            res = _result("HEAP_RETENTION", hr.RECIPE_HEAP_RETENTION, hr.OBS_HEAP_RETENTION, _hr_obs(), "DEGRADED", "INFO", [])
            self.assertIn(word, render_human_report(res, res["report"], lang))
            self.assertNotIn("0 KB.", render_human_report(res, res["report"], lang))
        obs = _hr_obs()
        obs["arenas"][0]["largest_free"] = 512
        self.assertEqual(hr._mib(512), "512 B")
        self.assertEqual(hr._mib(2048), "2 KB")
        obs["arenas"][0].pop("largest_free")
        for lang in ("en", "ko"):
            res = _result("HEAP_RETENTION", hr.RECIPE_HEAP_RETENTION, hr.OBS_HEAP_RETENTION, obs, "DEGRADED", "INFO", [])
            t = render_human_report(res, res["report"], lang)
            self.assertNotIn("largest free chunk", t)
            self.assertNotIn("가장 큰 빈 청크", t)
            self.assertIn("20004", t)

    def test_heap_retention_info_finding_has_neutral_badge(self):
        res = _result("HEAP_RETENTION", hr.RECIPE_HEAP_RETENTION, hr.OBS_HEAP_RETENTION, _hr_obs(), "DEGRADED", "INFO", [])
        en = build_visual_summary(res, res["report"], "en")
        card = en[en.index('id="dsv-finding-1"'):][:900]
        self.assertIn("not a fault: degradation", card)
        self.assertIn("badge-tone tone-skip", card)                      # the theme's neutral tone
        self.assertNotIn("probable cause", card)
        ko = build_visual_summary(res, res["report"], "ko")
        self.assertIn("결함 아님: 성능 저하", ko)
        self.assertNotIn("probable cause", render_human_report(res, res["report"], "en"))
        self.assertIn("not a fault: degradation", render_human_report(res, res["report"], "en"))

    def test_no_picture_without_evidence(self):
        self.assertEqual(mg.mapping_finding_viz(type("L", (), {"i": 0})(), {}, None), "")
        self.assertEqual(hr.retention_finding_viz(type("L", (), {"i": 0})(), {}, None), "")


TARGETS = os.path.join(ROOT, "benchmarks", "diagnosis_accuracy", "targets")


@unittest.skipUnless(shutil.which("gcc") and sys.platform.startswith("linux"), "gcc / Linux needed")
class TestLiveTargets(unittest.TestCase):
    """One diagnose per diagnosis on the benchmark targets (a few seconds each)."""

    def _run(self, name, symptom):
        from extractor.expert_diagnostic_engine import diagnose
        tmp = tempfile.mkdtemp(prefix="mgr_")
        self.addCleanup(shutil.rmtree, tmp, True)
        exe = os.path.join(tmp, name)
        subprocess.run(["gcc", "-g", "-O0", "-pthread", os.path.join(TARGETS, name + ".c"), "-o", exe], check=True)
        p = fixture_popen([exe], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        self.assertEqual(p.stdout.readline().strip(), b"READY")
        time.sleep(0.3)
        r = diagnose(p.pid, None, symptom, corpus_dir=tmp).to_dict()
        with open(r["report_path"]) as fh:
            return r, json.load(fh)

    def test_mmap_growth_is_named_by_its_variable(self):
        r, _ = self._run("mapgrow_slabs", "memory usage of this process keeps growing")
        f = [x for x in r["findings"] if x["category"] == "MAPPING_GROWTH"]
        self.assertTrue(f, r["findings"])
        self.assertIn("slabs", f[0]["subjects"])
        self.assertEqual(f[0]["status"], "PROBABLE_CAUSE")

    def test_fragmented_heap_is_degraded_not_a_fault(self):
        r, _ = self._run("frag_sparse", "memory usage looks high, is it leaking?")
        self.assertEqual(r["verdict"], "DEGRADED", r["summary"])
        self.assertEqual([(x["category"], x["severity"]) for x in r["findings"]], [("HEAP_RETENTION", "INFO")])


if __name__ == "__main__":
    unittest.main()
