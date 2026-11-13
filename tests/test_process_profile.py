"""The process profile: the model on saved results, and its Markdown / HTML wording.

Fixtures ``tests/fixtures/profile/*.json.gz`` are real full diagnoses of benchmark targets (AArch64 glibc), pruned of
bulk the profile never reads (``scripts/make_profile_fixtures.py``).  ``tests/fixtures/ko_report`` results are trimmed
(a passing check keeps no observations), so there the profile must show only what survived and say the rest is missing.
"""
import copy
import gzip
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor.process_profile import MAX_THREAD_ROWS, SECTIONS, build_process_profile  # noqa: E402
from extractor.profile_render import W, profile_html, profile_lines  # noqa: E402

PROFILE = os.path.join(ROOT, "tests", "fixtures", "profile")
KO = os.path.join(ROOT, "tests", "fixtures", "ko_report")


def load(name, base=PROFILE):
    with gzip.open(os.path.join(base, name + ".json.gz"), "rt", encoding="utf-8") as fh:
        return json.load(fh)


def prof(name, base=PROFILE):
    d = load(name, base)
    return build_process_profile(d, d["report"])


class TestModel(unittest.TestCase):
    def test_healthy_idle_server_has_every_section_with_its_basis(self):
        p = prof("ok_idle_server")
        self.assertTrue(p["available"])
        for k in SECTIONS:
            self.assertIn(k, p, k)
        th = p["threads"]
        self.assertEqual(th["count"]["v"], 2)
        self.assertEqual(th["series"]["basis"]["kind"], "series")
        self.assertEqual(th["series"]["basis"]["samples"], 5)
        self.assertEqual(th["trend"], "stable")
        self.assertEqual({r["name"] for r in th["rows"]}, {"ok_idle_server", "acceptor"})
        self.assertTrue(all(r["state"] == "waiting" and r["waits_on"]["name"] == "ppoll" for r in th["rows"]))
        self.assertEqual(th["rows"][0]["location"], "ok_idle_server.c:27")
        rss = p["memory"]["rss"]
        self.assertEqual((rss["v"], rss["unit"]), (1348, "kB"))
        self.assertEqual(rss["basis"]["kind"], "series")
        self.assertEqual(rss["change_kb"], 0)
        self.assertEqual(p["resources"]["fds"]["v"], 5)
        self.assertEqual(p["resources"]["fds"]["by_kind"], {"pipe": 3, "file": 2})
        self.assertEqual(p["locks"]["items"], [])                  # sampled, and nothing was held: said, not omitted
        self.assertEqual(p["locks"]["samples"], 5)
        self.assertEqual(p["summary"], {"threads": 2, "rss_kb": 1348, "heap_kb": 132, "heap_kind": "mapping", "fds": 5})
        self.assertEqual(p["window"]["samples"], 38)
        self.assertEqual({o["key"] for o in p["not_observed"]}, {"heap_walk", "load_addresses"})
        self.assertEqual([o["reason"] for o in p["not_observed"] if o["key"] == "heap_walk"], ["no_growth"])

    def test_address_space_categories_sum_to_the_total(self):
        for name in ("ok_idle_server", "leak_lru_cache", "frag_sparse", "request_threads"):
            asp = prof(name)["memory"]["address_space"]
            self.assertEqual(sum(c["kb"] for c in asp["categories"]), asp["total_kb"], name)
            self.assertTrue(all(c["kb"] > 0 for c in asp["categories"]))

    def test_deadlock_names_locks_owners_and_waiters(self):
        p = prof("deadlock_pipeline")
        items = {i["name"]: i for i in p["locks"]["items"]}
        self.assertEqual(set(items), {"m_in", "m_out"})
        self.assertEqual(items["m_out"]["owner"]["name"], "flush")
        self.assertEqual([w["name"] for w in items["m_out"]["waiters"]], ["ingest"])
        self.assertEqual(items["m_out"]["seen_samples"], 5)
        rows = {r["name"]: r for r in p["threads"]["rows"]}
        self.assertEqual(rows["ingest"]["state"], "lock")
        self.assertEqual(rows["ingest"]["waits_on"]["name"], "m_out")
        self.assertEqual(rows["ingest"]["waits_on"]["owner_name"], "flush")
        self.assertEqual(p["threads"]["rows"][0]["state"], "lock")          # lock waiters come first

    def test_heap_walk_figures_appear_only_when_a_walk_ran(self):
        leak = prof("leak_lru_cache")["memory"]["heap"]
        self.assertEqual(leak["walk"]["basis"]["kind"], "series")
        self.assertNotIn("free_kb", leak["walk"])
        self.assertTrue(leak["growing_classes"])
        frag = prof("frag_sparse")["memory"]["heap"]["walk"]
        self.assertGreater(frag["free_kb"], frag["in_use_kb"])
        self.assertNotIn("walk", prof("ok_idle_server")["memory"]["heap"])
        keys = {o["key"] for o in prof("leak_lru_cache")["not_observed"]}
        self.assertIn("heap_free", keys)
        self.assertNotIn("heap_free", {o["key"] for o in prof("frag_sparse")["not_observed"]})

    def test_growing_thread_count_keeps_the_last_read_and_the_sampled_trend(self):
        th = prof("request_threads")["threads"]
        self.assertEqual(th["trend"], "growing")
        self.assertGreater(th["count"]["v"], th["series"]["v"][-1])        # last read is later than the window
        self.assertEqual(th["count"]["basis"]["kind"], "read")
        self.assertLess(th["detailed"], th["listed"])
        self.assertIn("thread_detail_partial", {o["key"] for o in prof("request_threads")["not_observed"]})

    def test_many_threads_stay_bounded_and_grouped(self):
        d = copy.deepcopy(load("request_threads"))
        for c in d["report"]["section_d_detailed_inspection_results"]["checks"]:
            o = c["actual_observations"]
            if isinstance(o.get("threads"), list) and o["threads"]:
                base = o["threads"][-1]
                names = ["req_handler", "worker_a", "worker_b", "io_pool", "gc", "timer"]
                o["threads"] = [dict(base, tid=50000 + i, name=names[i % 6] + ("_%d" % (i // 6) if i % 50 == 0 else ""))
                                for i in range(300)]
                o["thread_count"] = 300
        p = build_process_profile(d, d["report"])
        th = p["threads"]
        self.assertEqual(th["count"]["v"], 300)
        self.assertLessEqual(len(th["rows"]), MAX_THREAD_ROWS)
        self.assertEqual(sum(r["count"] for r in th["rows"]) + (th["omitted"] or {}).get("threads", 0), th["listed"])
        self.assertTrue(any(r["count"] > 10 for r in th["rows"]))
        md = "\n".join(profile_lines(p, "ko"))
        self.assertLessEqual(len(md.splitlines()), 20)
        self.assertIn("×", md)

    def test_trimmed_fixture_shows_only_what_survived(self):
        d = load("ok_idle_server", KO)
        p = build_process_profile(d, d["report"])
        self.assertNotIn("resources", p)                                    # no fd_usage survived the trimming
        self.assertIn("fds", {o["key"] for o in p["not_observed"]})
        self.assertNotIn("fds", p["summary"])

    def test_no_report_means_unavailable_not_empty_sections(self):
        p = build_process_profile({"verdict": "INCONCLUSIVE"}, None)
        self.assertFalse(p["available"])
        for k in SECTIONS:
            self.assertNotIn(k, p)
        self.assertEqual(profile_lines(p, "ko"), [])
        self.assertEqual(profile_html(p, "ko"), "")

    def test_pruned_fixture_agrees_with_a_second_build_and_is_json(self):
        for name in ("ok_idle_server", "deadlock_pipeline", "leak_lru_cache"):
            p = prof(name)
            self.assertEqual(json.loads(json.dumps(p)), p)
            self.assertEqual(p, prof(name))

    def test_no_value_is_empty_or_unitless_guess(self):
        def walk(x, path=""):
            if isinstance(x, dict):
                for k, v in x.items():
                    if k in ("items", "rows", "omitted") or v is None:
                        continue
                    self.assertNotIn(v, ("", [], {}), path + "/" + k)
                    walk(v, path + "/" + k)
            elif isinstance(x, list):
                for v in x:
                    walk(v, path)
        for name in ("ok_idle_server", "deadlock_pipeline", "leak_lru_cache", "frag_sparse", "request_threads", "mapgrow_slabs"):
            walk(prof(name), name)


class TestWording(unittest.TestCase):
    def test_markdown_ko_and_en_have_the_same_shape(self):
        for name in ("ok_idle_server", "deadlock_pipeline", "leak_lru_cache", "frag_sparse"):
            p = prof(name)
            ko, en = profile_lines(p, "ko"), profile_lines(p, "en")
            self.assertEqual(len(ko), len(en), name)
            self.assertLessEqual(len(ko), 20, name)
            self.assertEqual([l.startswith("  -") for l in ko], [l.startswith("  -") for l in en])
            self.assertIn("관측 구간", ko[0])
            self.assertIn("표본", ko[0])
            self.assertIn("Observation window", en[0])

    def test_markdown_deadlock_reads_as_designed(self):
        text = "\n".join(profile_lines(prof("deadlock_pipeline"), "ko"))
        self.assertIn("락 `m_out`, 소유 `flush`", text)
        self.assertIn("관측하지 못한 것:", text)

    def test_html_is_collapsed_under_a_three_line_summary(self):
        for lang in ("ko", "en"):
            h = profile_html(prof("ok_idle_server"), lang)
            self.assertTrue(h.startswith('<p class="profile-glance">'))
            head, detail = h.split('<details class="collapsible"', 1)
            self.assertEqual(head.count("<p"), 2)                                # glance + window line
            self.assertNotIn(" open", detail.split(">", 1)[0])
            self.assertNotRegex(h, r"https?://")
            self.assertNotRegex(h, r"#[0-9a-fA-F]{3,8}\b(?![\w-])")
            levels = [int(x) for x in re.findall(r"<h([1-6])\b", h)]
            self.assertTrue(all(b - a <= 1 for a, b in zip([2] + levels, levels)), levels)

    def test_html_has_chart_bars_and_a_scrolling_thread_table(self):
        h = profile_html(prof("leak_lru_cache"), "ko")
        self.assertIn("<svg", h)                                                 # RSS series grew: a picture
        self.assertIn("dsv-meter", h)
        self.assertIn('<div class="dsv-scroll"><table class="dsv-tbl">', h)

    def test_korean_html_and_markdown_have_no_english_sentences(self):
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        from test_korean_report_language import english_sentences
        for name in ("ok_idle_server", "deadlock_pipeline", "leak_lru_cache", "frag_sparse", "request_threads"):
            p = prof(name)
            self.assertEqual(english_sentences("\n".join(profile_lines(p, "ko"))), [], name)
            self.assertEqual(english_sentences(profile_html(p, "ko")), [], name)

    def test_every_word_key_has_both_languages(self):
        for k, v in W.items():
            self.assertEqual(len(v), 2, k)
            self.assertTrue(v[0] and v[1], k)


class TestInReport(unittest.TestCase):
    def _render(self, name, lang):
        import extractor.expert_diagnostic_engine as ede
        from extractor.incident_report import export_incident_report
        d = load(name)

        class S:
            def to_dict(self_):
                return json.loads(json.dumps(d))
        orig = ede.diagnose
        ede.diagnose = lambda *a, **k: S()
        try:
            return export_incident_report(pid=1234, language=lang)
        finally:
            ede.diagnose = orig

    def test_section_sits_after_the_target_in_md_and_html(self):
        for lang, title in (("ko", "프로세스 프로필"), ("en", "Process profile")):
            out = self._render("deadlock_pipeline", lang)
            h2 = re.findall(r"^## \d+\. (.+)$", out["report_markdown"], re.M)
            self.assertEqual(h2[2], title)
            self.assertIn('id="sec-profile"', out["report_html"])
            self.assertLess(out["report_html"].index('id="sec-target"'), out["report_html"].index('id="sec-profile"'))
            self.assertLess(out["report_html"].index('id="sec-profile"'), out["report_html"].index('id="dsv-findings"'))

    def test_healthy_markdown_adds_a_bounded_number_of_lines(self):
        out = self._render("ok_idle_server", "ko")
        sec = out["report_markdown"].split("## 3. 프로세스 프로필")[1].split("\n## ")[0].strip().splitlines()
        self.assertLessEqual(len(sec), 13)
        self.assertLessEqual(len(" ".join(sec).split()), 270)


if __name__ == "__main__":
    unittest.main()
