"""The pool grid of the observation card for arrays of MORE than 4,096 elements (10,000 and 100,000 slots).

Real ``slot_server`` fixtures built with ``-DNSLOTS=N`` (48-byte slots: 480,000 and 4,800,000 bytes), a diagnosis job
started through ``POST /api/diagnose/start``, then the variable search, the pool watch, the report.

How the grid works (extractor/web/explore.py): one read of ``count * elem_size`` bytes per sample, one cell per
``ceil(count / 4096)`` elements.  A pool that the per-sample budget (256 KiB) cannot cover is observed as its FIRST
``count`` elements: the variable search offers exactly that count and says it is a part, an explicit larger count or the
default (the whole array) is ``400 BUDGET`` whose message names the largest count that fits, the observation says
``total`` / ``truncated`` and the UI / report print "first n of N elements".

Run: python3 -m unittest tests.test_web_explore_bigpool
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from extractor.web import explore as X
from tests.support.explore_e2e import FIX, UNSAFE, Client, build
from tests.support.fixture_process import fixture_popen

ES = 48                                                    # sizeof(struct slot) in slot_server.c


class BigPoolCase:
    nslots = 0

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ds_bigpool_")
        cls.binary = build(cls.tmp, os.path.join(FIX, "slot_server.c"), "slot_big", flags=("-g", "-O0", f"-DNSLOTS={cls.nslots}"))
        cls.proc = fixture_popen([cls.binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, name=f"slot_server_{cls.nslots}")
        if b"READY" not in cls.proc.stdout.readline():
            cls.proc.kill_tree()
            raise RuntimeError("fixture did not start")
        cls.c = Client(os.path.join(cls.tmp, "corpus"))
        cls.jid, cls.status = cls.c.diagnose(cls.proc.pid, cls.binary)
        cls.fit = X.pool_fit_count(ES)

    @classmethod
    def tearDownClass(cls):
        cls.c.close()
        cls.proc.kill_tree()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def tearDown(self):
        self.c.post(self.jid, "watch/stop", {})

    def text(self, r, lang):
        return re.sub(r"<[^>]+>", " ", r["html"][lang])

    def test_fixture_really_is_that_big(self):
        self.assertEqual(self.status["job"]["state"], "done", self.status)
        self.assertGreater(os.path.getsize(self.binary), 0)
        self.assertEqual(self.fit, (X.SAMPLE_BYTES_MAX // ES) - X.POOL_RESERVE_ELEMS)
        self.assertLess(self.fit, self.nslots)

    def test_variable_search_offers_only_what_the_budget_covers_and_says_so(self):
        st, r = self.c.get(self.jid, "vars?q=g_slots")
        self.assertEqual(st, 200, r)
        self.assertEqual(r["cost"]["reads"], 0)
        en = r["html"]["en"]
        self.assertIn(f'data-act="pool-go" data-expr="g_slots" data-count="{self.fit}" data-field="state"', en)
        self.assertIn(f"first {self.fit:,} of {self.nslots:,} elements", self.text(r, "en"))
        self.assertIn(f"원소 {self.nslots:,}개 중 앞의 {self.fit:,}개", self.text(r, "ko"))
        for lang in ("ko", "en"):
            self.assertIsNone(UNSAFE.search(r["html"][lang]))

    def test_too_large_counts_are_refused_with_the_largest_that_fits(self):
        for body in ({"pool": {"expr": "g_slots"}}, {"pool": {"expr": "g_slots", "count": self.nslots}},
                     {"pool": {"expr": "g_slots", "count": self.fit + 1}}, {"pool": {"expr": "g_slots", "count": self.fit + 2}}):
            st, r = self.c.post(self.jid, "watch", body)
            self.assertEqual((st, r["error"]["code"]), (400, "BUDGET"), (body, r))
            self.assertIn(f"give count {self.fit} or less", r["error"]["message"])
            self.assertIn(f"{self.nslots} elements", r["error"]["message"])
            self.assertIn("BUDGET", r["html"]["en"] + r["html"]["ko"] + "BUDGET")          # a fragment exists for both languages
        st, r = self.c.post(self.jid, "watch", {"pool": {"expr": "g_slots", "count": 10}, "interval_s": 1})
        self.assertEqual(st, 200, r)                       # nothing of the refused requests was applied
        self.assertEqual(r["watch"]["pool"]["count"], 10)

    def test_sel_beyond_the_observed_part_is_refused(self):
        st, r = self.c.post(self.jid, "watch", {"pool": {"expr": "g_slots", "count": 100, "sel": 100}})
        self.assertEqual((st, r["error"]["code"]), (400, "INVALID_PARAM"), r)

    def test_the_largest_pool_is_bounded_in_size_and_read_cost(self):
        # 0.5 s is the tightest interval: 256 KiB per sample and 512 KiB/s must both hold
        st, r = self.c.post(self.jid, "watch", {"pool": {"expr": "g_slots", "count": self.fit}, "interval_s": 0.5})
        self.assertEqual(st, 200, r)
        plan = r["watch"]["plan"]
        self.assertLessEqual(plan["bytes_per_sample"], X.SAMPLE_BYTES_MAX)
        self.assertLessEqual(plan["bytes_per_s"], X.BYTES_PER_S_MAX)
        w = self.c.wait_samples(self.jid, 4, timeout=15)
        self.assertGreaterEqual(w["samples"], 4, w)
        self.assertEqual(w["state"], "running", w)
        p = w["pool"]
        self.assertEqual((p["count"], p["total"], p["truncated"]), (self.fit, self.nslots, True))
        self.assertEqual(p["per_cell"], -(-self.fit // X.POOL_CELLS))
        self.assertGreater(p["per_cell"], 1)                                      # aggregated: more than one element per cell
        self.assertEqual(len(p["cells"]), -(-self.fit // p["per_cell"]))
        self.assertLessEqual(len(p["cells"]), X.POOL_CELLS)
        self.assertRegex(p["cells"], r"^[0-5]+$")
        self.assertEqual(sum(x["count"] for x in p["legend"]), self.fit)
        # real cost of the last sample: never past the limits (sampling reads only the first `fit` elements)
        cost = w["cost"]
        self.assertLessEqual(cost["bytes"], X.SAMPLE_BYTES_MAX, cost)
        self.assertLessEqual(cost["bytes_per_s"], X.BYTES_PER_S_MAX, cost)
        self.assertLessEqual(cost["reads"], 2, cost)
        self.assertEqual((cost["writes"], cost["stop_ms"]), (0, 0))
        # the status response stays small whatever the array length (cells are capped at 4,096)
        st, raw = self.c.request("GET", f"/api/diagnose/{self.jid}/watch/status")
        import json
        self.assertLess(len(json.dumps(raw)), 40 * 1024)
        # one element of the observed part can be selected, a bounded extra read
        st, r = self.c.post(self.jid, "watch", {"pool": {"expr": "g_slots", "count": self.fit, "sel": self.fit - 1}, "interval_s": 1})
        self.assertEqual(st, 200, r)
        self.assertLessEqual(r["watch"]["plan"]["bytes_per_sample"], X.SAMPLE_BYTES_MAX)

    def test_report_says_the_grid_is_a_part(self):
        st, r = self.c.post(self.jid, "watch", {"pool": {"expr": "g_slots", "count": self.fit}, "interval_s": 1})
        self.assertEqual(st, 200, r)
        self.c.wait_samples(self.jid, 2, timeout=10)
        st, o = self.c.post(self.jid, "observation", {})
        self.assertEqual(st, 200, o)
        for lang, phrase in (("en", f"only the first {self.fit} are read"), ("ko", f"앞의 {self.fit}개만 읽음")):
            st, rep = self.c.request("GET", f"/api/diagnose/{self.jid}/report?format=html&lang={lang}")
            body = rep["raw"].decode() if "raw" in rep else str(rep)
            self.assertEqual(st, 200)
            self.assertIn(phrase, body)
            self.assertLessEqual(body.count('class="pc s'), X.POOL_CELLS + 8)          # the report grid is capped too


class TestTenThousandSlots(BigPoolCase, unittest.TestCase):
    nslots = 10000


class TestHundredThousandSlots(BigPoolCase, unittest.TestCase):
    nslots = 100000


if __name__ == "__main__":
    unittest.main()
