"""Use-after-free detection from memory reads alone (extractor.uaf_detection, recipe RECIPE_FREED_MEMORY_USE).

Real-process tests: every fixture is compiled at test time (gcc -g -O0), prints its own ground truth and READY,
then keeps running (writing into a chunk that stays free, or idling); ``diagnose()`` runs on the live process.

 a. global pointer kept after free + periodic writes through it -> confirmed USE_AFTER_FREE naming the variable,
    the freed chunk and "written while free"
 b. struct-member dangling pointer reached through the typed graph -> ``g_conn->rx`` named
 c. dangling pointer, no write                                     -> candidate (WARNING), never confirmed
 d. healthy: IMP-008/009 healthy fixtures, the multi-thread malloc/free churner diagnosed 20 times, a program-
    managed free list of in-use chunks                             -> zero USE_AFTER_FREE findings
 e. chunk freed and immediately re-allocated                       -> nothing
 + a write at offset 0 of a freed chunk (free-list damage, IMP-009) referenced by a global -> USE_AFTER_FREE,
   not MEMORY_CORRUPTION; an overflow into a freed neighbour stays MEMORY_CORRUPTION
 + the verdict rule on plain data
"""

import os
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from extractor.diagnostic_recipes import BASELINE_RECIPE_IDS, DiagnosticRecipeRegistry
from extractor.expert_diagnostic_engine import diagnose
from extractor.recipe_plugins.use_after_free import RECIPE_FREED_MEMORY_USE, freed_memory_use_rule
from tests.support.fixture_process import fixture_popen

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_runtime")
READY_TIMEOUT_S = 60.0
UAF = "USE_AFTER_FREE"


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="uaf_")
        cls.corpus = os.path.join(cls.tmp, "corpus")
        cls.bins = {}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _binary(self, src):
        if src not in self.bins:
            out = os.path.join(self.tmp, os.path.splitext(src)[0])
            subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", os.path.join(FIXTURES, src),
                            "-o", out], check=True, capture_output=True, timeout=120)
            self.bins[src] = out
        return self.bins[src]

    def _launch(self, src):
        binary = self._binary(src)
        proc = fixture_popen([binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        self.addCleanup(self._kill, proc)
        lines, buf = [], b""
        deadline = time.monotonic() + READY_TIMEOUT_S
        while "READY" not in lines:
            left = deadline - time.monotonic()
            if left <= 0:
                self.fail("fixture %s did not print READY in time" % src)
            r, _, _ = select.select([proc.stdout], [], [], left)
            if not r:
                continue
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                self.fail("fixture %s exited before READY (rc=%s)" % (src, proc.wait()))
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                lines.append(line.decode().strip())
        time.sleep(0.1)
        self.assertIsNone(proc.poll(), "fixture crashed after READY")
        return proc, binary, lines

    def _settle(self, src):
        binary = self._binary(src)
        proc = fixture_popen([binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        self.addCleanup(self._kill, proc)
        time.sleep(1.0)
        self.assertIsNone(proc.poll())
        return proc, binary, []

    @staticmethod
    def _kill(proc):
        try:
            proc.kill()
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            pass
        if proc.stdout:
            proc.stdout.close()

    def _diagnose(self, pid, binary, symptom=None):
        r = diagnose(pid, binary, symptom, corpus_dir=self.corpus, include_report=True).to_dict()
        rec, mi = None, None
        for c in r["report"]["section_d_detailed_inspection_results"]["checks"]:
            ob = c.get("actual_observations") or {}
            if isinstance(ob.get("freed_memory_use"), dict):
                rec = ob["freed_memory_use"]
            if isinstance(ob.get("memory_integrity"), dict):
                mi = ob["memory_integrity"]
        return r, rec, mi

    @staticmethod
    def _uaf(r):
        return [f for f in r["findings"] if f["category"] == UAF]

    @staticmethod
    def _gt(lines, tag):
        f = [l.split() for l in lines if l.startswith(tag + " ")][0]
        return f[1], int(f[2], 16), int(f[3])


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestUseAfterFree(_Base):
    def test_a_global_pointer_written_after_free_is_confirmed(self):
        proc, binary, lines = self._launch("proc_uaf_global_written.c")
        var, user, csize = self._gt(lines, "UAF")
        r, rec, _ = self._diagnose(proc.pid, binary)
        fs = self._uaf(r)
        self.assertTrue(fs, (r["findings"], rec))
        self.assertIn(var, fs[0]["subjects"])
        self.assertIn("0x%x" % (user - 16), fs[0]["subjects"])
        self.assertEqual(fs[0]["status"], "CONFIRMED_ROOT_CAUSE", fs[0])
        self.assertEqual(r["verdict"], "CONFIRMED_FAULT", r["summary"])
        row = [x for x in rec["findings"] if x["freed_chunk"] == "0x%x" % (user - 16)][0]
        sys.stderr.write("\nUAF a: %s\n" % row["description"])
        self.assertEqual(row["level"], "confirmed")
        self.assertEqual(row["variable"], var)
        self.assertEqual(row["chunk_size"], csize)
        self.assertTrue(row["written_while_free"])
        self.assertIn("written while free", row["description"])
        self.assertIn("tcache", row["free_list"])
        self.assertTrue(r["collection_impact"]["zero_stop"])
        self.assertIsNone(proc.poll())

    def test_b_struct_member_dangling_pointer_is_named_through_the_graph(self):
        proc, binary, lines = self._launch("proc_uaf_member_dangling.c")
        path, user, csize = self._gt(lines, "UAF")
        r, rec, _ = self._diagnose(proc.pid, binary)
        fs = self._uaf(r)
        self.assertTrue(fs, (r["findings"], rec))
        self.assertIn(path, fs[0]["subjects"])
        self.assertIn("g_conn", fs[0]["subjects"])
        row = [x for x in rec["findings"] if x["freed_chunk"] == "0x%x" % (user - 16)][0]
        sys.stderr.write("\nUAF b: %s\n" % row["description"])
        self.assertEqual(row["variable_path"], path)
        self.assertEqual(row["chunk_size"], csize)
        self.assertEqual(row["level"], "confirmed")
        self.assertNotIn("g_conn->tx", fs[0]["subjects"], "the live member is not dangling")

    def test_c_dangling_pointer_without_writes_is_a_candidate_only(self):
        proc, binary, lines = self._launch("proc_uaf_dangling_only.c")
        var, user, csize = self._gt(lines, "DANGLING")
        r, rec, _ = self._diagnose(proc.pid, binary)
        fs = self._uaf(r)
        self.assertTrue(fs, (r["findings"], rec))
        sys.stderr.write("\nUAF c: %s -> verdict %s, finding %s/%s\n" % (
            rec["findings"][0]["description"], r["verdict"], fs[0]["status"], fs[0]["severity"]))
        self.assertIn(var, fs[0]["subjects"])
        self.assertEqual(fs[0]["status"], "PROBABLE_CAUSE")
        self.assertEqual(fs[0]["severity"], "WARNING")
        self.assertNotEqual(r["verdict"], "CONFIRMED_FAULT")
        self.assertEqual([x["level"] for x in rec["findings"]], ["candidate"])
        self.assertFalse(rec["findings"][0]["written_while_free"])
        self.assertNotIn("g_live", fs[0]["subjects"])

    def test_write_into_freed_chunk_without_typed_referrer_is_probable_owner_unknown(self):
        proc, binary, lines = self._launch("proc_uaf_unreferenced_write.c")
        user = int([l.split() for l in lines if l.startswith("UNREF ")][0][1], 16)
        r, rec, _ = self._diagnose(proc.pid, binary)
        fs = self._uaf(r)
        self.assertTrue(fs, (r["findings"], rec))
        row = [x for x in rec["findings"] if x["freed_chunk"] == "0x%x" % (user - 16)][0]
        sys.stderr.write("\nUAF unreferenced: %s\n" % row["description"])
        self.assertEqual(row["level"], "probable")
        self.assertTrue(row["written_while_free"])
        self.assertIn("no reference remains", row["owner_unknown"])
        self.assertEqual(fs[0]["status"], "PROBABLE_CAUSE")
        self.assertNotIn("g_cookie", fs[0]["subjects"], "an integer is not a pointer")

    def test_e_chunk_freed_and_reallocated_reports_nothing(self):
        proc, binary, lines = self._launch("proc_uaf_freed_reused.c")
        self.assertIn("REUSED 1", lines, "the fixture expects the same chunk back (LIFO tcache)")
        r, rec, _ = self._diagnose(proc.pid, binary)
        self.assertFalse(self._uaf(r), r["findings"])
        self.assertEqual(rec["status"], "COMPLETED", rec)
        self.assertEqual(rec["findings"], [])

    def test_freelist_write_through_dangling_global_is_use_after_free_not_overflow(self):
        proc, binary, lines = self._launch("proc_uaf_freelist_write.c")
        var, user, _ = self._gt(lines, "UAFMETA")
        r, rec, mi = self._diagnose(proc.pid, binary)
        d = [x for x in mi["heap"]["defects"] if x["kind"] == "tcache_pointer_damaged"]
        self.assertTrue(d, mi["heap"])
        self.assertEqual(d[0]["use_after_free"]["variable"], var)
        sys.stderr.write("\nUAF meta: %s\n" % d[0]["description"])
        self.assertFalse([f for f in r["findings"] if f["category"] == "MEMORY_CORRUPTION"], r["findings"])
        fs = self._uaf(r)
        self.assertTrue(fs, r["findings"])
        self.assertIn(var, fs[0]["subjects"])
        self.assertEqual(fs[0]["status"], "CONFIRMED_ROOT_CAUSE")
        self.assertIn("0x%x" % (user - 16), [x["freed_chunk"] for x in rec["findings"]])

    def test_overflow_into_freed_neighbour_stays_memory_corruption(self):
        """IMP-009 fixture: the freed neighbour's header AND its tcache pointer are damaged by an overflow."""
        proc, binary, lines = self._launch("proc_imp009_freed_neighbour.c")
        r, rec, mi = self._diagnose(proc.pid, binary)
        self.assertTrue([f for f in r["findings"] if f["category"] == "MEMORY_CORRUPTION"], r["findings"])
        self.assertFalse([d for d in mi["heap"]["defects"] if d.get("use_after_free")], mi["heap"]["defects"])


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestHealthyNoUaf(_Base):
    HEALTHY = ("proc_scenario_a_healthy.c", "proc_thread_normal_cv.c", "proc_idle_pool_uncontended_mutex.c",
               "proc_heap_ownership.c", "proc_cache_plateau.c", "proc_heap_churn.c", "proc_uaf_pool_freelist.c")

    def _prints_ready(self, src):
        with open(os.path.join(FIXTURES, src), encoding="utf-8", errors="replace") as f:
            return "READY" in f.read()

    def test_d_healthy_fixtures_have_no_uaf_findings(self):
        for src in self.HEALTHY:
            proc, binary, _ = self._launch(src) if self._prints_ready(src) else self._settle(src)
            with self.subTest(fixture=src):
                r, rec, _ = self._diagnose(proc.pid, binary)
                self.assertFalse(self._uaf(r), (src, r["findings"], rec and rec.get("findings")))
                self.assertIsNotNone(rec)
                self.assertEqual(rec.get("findings"), [], rec)
            self._kill(proc)

    def test_d_twenty_diagnoses_of_a_multithread_churner(self):
        proc, binary, _ = self._launch("proc_imp009_churn_mt.c")
        dropped = 0
        for i in range(20):
            r, rec, _ = self._diagnose(proc.pid, binary)
            self.assertIsNone(proc.poll(), "churner died")
            self.assertFalse(self._uaf(r), "diagnosis %d: %s / %s" % (i, r["findings"], rec and rec.get("findings")))
            dropped += len((rec or {}).get("not_evidence") or [])
        sys.stderr.write("\nUAF churn: 20 diagnoses, %d observations classified as not evidence\n" % dropped)


class TestRule(unittest.TestCase):
    def setUp(self):
        self.recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_FREED_MEMORY_USE)

    def test_registered_as_baseline_plugin(self):
        self.assertIn(RECIPE_FREED_MEMORY_USE, BASELINE_RECIPE_IDS)
        self.assertEqual(self.recipe.observations, ("freed_memory_use",))

    def _rule(self, rec):
        return freed_memory_use_rule(self.recipe, {"freed_memory_use": rec})

    def test_levels(self):
        cand = {"level": "candidate", "description": "dangling", "variable": "p"}
        prob = {"level": "probable", "description": "written, owner unknown"}
        conf = {"level": "confirmed", "description": "both", "variable": "p"}
        r = self._rule({"status": "COMPLETED", "findings": [cand]})
        self.assertEqual(r.status, "SUPPORTED")
        self.assertEqual(r.details["finding_severity"], "WARNING")
        self.assertEqual(r.details["certainty_cap"], "PROBABLE")
        r = self._rule({"status": "COMPLETED", "findings": [prob, cand]})
        self.assertNotIn("finding_severity", r.details)
        self.assertEqual(r.details["certainty_cap"], "PROBABLE")
        r = self._rule({"status": "COMPLETED", "findings": [conf, cand]})
        self.assertNotIn("certainty_cap", r.details)
        self.assertTrue(r.details["corruption_confirmed"])
        self.assertEqual(r.details["finding_category"], UAF)
        r = self._rule({"status": "COMPLETED", "findings": [], "checked": {"tracked_chunks": 3}})
        self.assertEqual(r.status, "CONTRADICTED")
        r = self._rule({"status": "NOT_CHECKED", "findings": [], "limitations": ["heap larger than cap"]})
        self.assertEqual(r.status, "INSUFFICIENT_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
