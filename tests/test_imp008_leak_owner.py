"""IMP-008: identify WHO leaks (leak owner by variable path) - real-process acceptance tests.

Every fixture is compiled at test time (gcc -g -O0), prints its own ground truth ("GT ...") and READY once in its
steady state, and keeps running; the single entry point ``diagnose()`` is called on it.  Nothing here waits a
fixed, machine-tuned time: readiness is a bounded poll on the READY line, and the observation schedule is the
engine's own (>= 3 heap walks spaced over the session's observation window).

 a. append-only list            -> MEMORY_LEAK finding naming the list's global (and its growth path)
 b. dropped pointers            -> "N unreachable blocks, size class X", N growing
 c. memory rises then falls     -> no leak verdict
 d. only large (mmapped) leaks  -> growth caught (unreachable mmapped size class)
 e. plateauing cache            -> no leak verdict
 f. interposed allocator        -> leak-owner attribution explicitly "not supported", no guessed owner
 g. default diagnose on an idle process performs no heap walk and stays within its time envelope
 h. IMP-004 follow-ups run for real after a supported growth result (no evaluation seam) and use the walks
 + pure-function checks of the verdict rules (sawtooth, plateau, stack-held growth, RSS-only growth).
"""

import os
import select
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.expert_diagnostic_engine import ExpertDiagnosticEngine, diagnose
from extractor.leak_attribution import (
    V_GROWTH_OWNED,
    V_LEAK_UNREACHABLE,
    V_NO_GROWTH,
    V_NOT_ESTABLISHED,
    V_SHRANK,
    MemoryObservationConfig,
    _NormPaths,
    judge,
)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_runtime")
READY_TIMEOUT_S = 60.0
MEMORY_SYMPTOM = "memory usage of this process keeps growing"
# classified MEMORY_LEAK: asks about memory, so the heap walks run even without a /proc growth trend
LEAK_QUESTION = "memory usage looks high, is it leaking?"
LEAK_VERDICTS = (V_LEAK_UNREACHABLE, V_GROWTH_OWNED)


def _request2chunk(n: int) -> int:
    return max(32, (n + 8 + 15) & ~15)


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestImp008LeakOwner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp008_")
        cls.corpus = os.path.join(cls.tmp, "corpus")
        cls.bins = {}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _binary(self, src: str) -> str:
        if src not in self.bins:
            out = os.path.join(self.tmp, os.path.splitext(src)[0])
            subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", os.path.join(FIXTURES, src),
                            "-o", out], check=True, capture_output=True, timeout=120)
            self.bins[src] = out
        return self.bins[src]

    def _launch(self, src: str):
        binary = self._binary(src)
        proc = subprocess.Popen([binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        self.addCleanup(self._kill, proc)
        gt = {}
        buf = b""
        deadline = time.monotonic() + READY_TIMEOUT_S
        while b"READY" not in buf:
            if time.monotonic() > deadline:
                self.fail("fixture %s did not print READY in time" % src)
            if proc.poll() is not None:
                self.fail("fixture %s exited before READY" % src)
            r, _, _ = select.select([proc.stdout], [], [], 0.2)
            if r:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    self.fail("fixture %s closed stdout before READY" % src)
                buf += chunk
        for line in buf.decode().splitlines():
            if line.startswith("GT "):
                for kv in line[3:].split():
                    k, v = kv.split("=", 1)
                    gt[k] = v
        print("[%s] READY, ground truth %s" % (src, gt))
        return proc, binary, gt

    @staticmethod
    def _kill(proc):
        try:
            proc.kill()
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            pass
        if proc.stdout:
            proc.stdout.close()

    def _diagnose(self, pid, binary, symptom=MEMORY_SYMPTOM):
        r = diagnose(pid, binary, symptom, corpus_dir=self.corpus, include_report=True).to_dict()
        lis = []
        for c in r["report"]["section_d_detailed_inspection_results"]["checks"]:
            li = (c.get("actual_observations") or {}).get("leak_investigation")
            if isinstance(li, dict):
                lis.append((c["recipe_id"], c["status"], li))
        return r, lis

    def _growth_li(self, lis):
        return next(li for rid, _st, li in lis if rid == "RECIPE_PROCESS_MEMORY_GROWTH")

    def _leak_findings(self, r):
        return [f for f in r["findings"] if f["category"] == "MEMORY_LEAK"]

    # ------------------------------------------------------------------------------------------ a
    def test_a_append_only_list_names_the_owning_global(self):
        proc, binary, gt = self._launch("proc_leak_append_list.c")
        r, lis = self._diagnose(proc.pid, binary)
        li = self._growth_li(lis)
        print("[a] verdict=%s summary=%s cost=%s" % (li.get("verdict"), li.get("summary"), li.get("cost")))
        self.assertEqual(li["verdict"], V_GROWTH_OWNED, li.get("limitations"))
        self.assertGreaterEqual(li["walks"], 3)
        owners = {o["variable"]: o for o in li["growth_owners"]}
        self.assertIn(gt["owner"], owners)
        o = owners[gt["owner"]]
        self.assertTrue(o["variable_path"].startswith(gt["owner"]))
        self.assertIn("(->next)*", o["variable_path"])
        self.assertTrue(all(b >= a for a, b in zip(o["count_series"], o["count_series"][1:])))
        self.assertGreater(o["blocks_delta"], 0)
        leaks = self._leak_findings(r)
        self.assertEqual(len(leaks), 1, r["findings"])
        self.assertIn(gt["owner"], leaks[0]["subjects"])
        self.assertIn(o["variable_path"], leaks[0]["subjects"])
        self.assertIn(gt["owner"], leaks[0]["description"])
        # still referenced: unbounded growth under that owner, never a confirmed leak
        self.assertEqual(leaks[0]["status"], "PROBABLE_CAUSE")
        self.assertEqual(r["collection_impact"]["measured_stop_ms"], 0.0)
        self.assertTrue(r["collection_impact"]["zero_stop"])

    # ------------------------------------------------------------------------------------------ b
    def test_b_dropped_pointers_report_unreachable_size_class(self):
        proc, binary, gt = self._launch("proc_leak_dropped_ptrs.c")
        r, lis = self._diagnose(proc.pid, binary)
        li = self._growth_li(lis)
        print("[b] verdict=%s summary=%s" % (li.get("verdict"), li.get("summary")))
        self.assertEqual(li["verdict"], V_LEAK_UNREACHABLE, li.get("limitations"))
        want = _request2chunk(int(gt["leak_request_size"]))
        row = next((u for u in li["unreachable_growth"] if u["chunk_size"] == want), None)
        self.assertIsNotNone(row, li["unreachable_growth"])
        self.assertFalse(row["mmapped"])
        self.assertTrue(all(b >= a for a, b in zip(row["count_series"], row["count_series"][1:])))
        self.assertGreater(row["blocks_delta"], 0)
        self.assertIn("no reachable path", li["summary"])
        self.assertIn("size class %d" % want, li["summary"])
        leaks = self._leak_findings(r)
        self.assertEqual(len(leaks), 1, r["findings"])
        self.assertIn("no reachable path", leaks[0]["description"])
        # no variable can own an unreachable block; a name only appears through the arena's attached thread
        self.assertTrue(set(leaks[0]["subjects"]) <= {gt["thread"], str(row.get("allocating_thread_tid"))},
                        leaks[0]["subjects"])
        if leaks[0]["subjects"]:
            self.assertEqual(row.get("allocating_thread_name"), gt["thread"])
        else:
            self.assertEqual(leaks[0]["status"], "PROBABLE_CAUSE")

    # ------------------------------------------------------------------------------------------ c
    def test_c_rise_then_fall_is_not_a_leak(self):
        proc, binary, _gt = self._launch("proc_mem_rise_fall.c")
        r, lis = self._diagnose(proc.pid, binary, symptom=LEAK_QUESTION)
        li = self._growth_li(lis)
        print("[c] verdict=%s summary=%s" % (li.get("verdict"), li.get("summary")))
        self.assertGreaterEqual(li["walks"], 3)                  # the walks did run
        self.assertNotIn(li["verdict"], LEAK_VERDICTS)
        self.assertEqual(self._leak_findings(r), [])
        self.assertNotIn(r["verdict"], ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT"))

    # ------------------------------------------------------------------------------------------ d
    def test_d_large_mmapped_leak_is_caught(self):
        proc, binary, gt = self._launch("proc_leak_large_blocks.c")
        r, lis = self._diagnose(proc.pid, binary)
        li = self._growth_li(lis)
        print("[d] verdict=%s summary=%s" % (li.get("verdict"), li.get("summary")))
        self.assertEqual(li["verdict"], V_LEAK_UNREACHABLE, li.get("limitations"))
        rows = [u for u in li["unreachable_growth"] if u["mmapped"]]
        self.assertTrue(rows, li["unreachable_growth"])
        self.assertGreaterEqual(rows[0]["usable_size"], int(gt["leak_request_size"]))
        self.assertGreater(rows[0]["blocks_delta"], 0)
        self.assertGreater(li["mmapped_bytes_series"][-1], li["mmapped_bytes_series"][0])
        self.assertEqual(len(self._leak_findings(r)), 1, r["findings"])

    # ------------------------------------------------------------------------------------------ e
    def test_e_plateauing_cache_is_not_a_leak(self):
        proc, binary, _gt = self._launch("proc_cache_plateau.c")
        r, lis = self._diagnose(proc.pid, binary, symptom=LEAK_QUESTION)
        li = self._growth_li(lis)
        print("[e] verdict=%s summary=%s" % (li.get("verdict"), li.get("summary")))
        self.assertGreaterEqual(li["walks"], 3)
        self.assertNotIn(li["verdict"], LEAK_VERDICTS)
        self.assertEqual(self._leak_findings(r), [])

    # ------------------------------------------------------------------------------------------ f
    def test_f_interposed_allocator_is_not_supported_no_guess(self):
        proc, binary, _gt = self._launch("proc_heap_custom_allocator.c")
        r, lis = self._diagnose(proc.pid, binary, symptom=LEAK_QUESTION)
        li = self._growth_li(lis)
        print("[f] verdict=%s limitations=%s" % (li.get("verdict"), li.get("limitations")))
        self.assertEqual(li["status"], "UNSUPPORTED")
        nc = [n for n in r["not_covered"] if n["item"] == "leak_owner_attribution"]
        self.assertTrue(nc, r["not_covered"])
        self.assertEqual(nc[0]["kind"], "unsupported_on_target")
        self.assertIn("not supported on this target", nc[0]["reason"])
        for f in self._leak_findings(r):
            self.assertEqual(f["subjects"], [])          # no owner is guessed

    # ------------------------------------------------------------------------------------------ g
    def test_g_default_diagnose_on_idle_process_does_no_heap_walk(self):
        proc, binary, _gt = self._launch("proc_cache_plateau.c")
        t0 = time.monotonic()
        r, lis = self._diagnose(proc.pid, binary, symptom=None)
        wall = time.monotonic() - t0
        li = self._growth_li(lis)
        print("[g] wall=%.2fs bytes_read=%s verdict=%s" % (wall, r["collection_impact"]["bytes_read"], li.get("verdict")))
        self.assertEqual(li["walks"], 0)
        self.assertEqual(li["status"], "NOT_RUN")
        self.assertEqual(li["cost"]["bytes_read"], 0)
        trend = next((c.get("actual_observations") or {}).get("memory_trend")
                     for c in r["report"]["section_d_detailed_inspection_results"]["checks"]
                     if c["recipe_id"] == "RECIPE_PROCESS_MEMORY_GROWTH")
        self.assertGreaterEqual(trend["samples"], 3)
        self.assertLess(r["collection_impact"]["bytes_read"], 256 * 1024)
        # previous envelope ~1.1-1.3 s on this class of host; generous bound for loaded CI machines
        self.assertLess(r["duration_s"], 3.0)
        self.assertEqual(self._leak_findings(r), [])

    # ------------------------------------------------------------------------------------------ h
    def test_h_growth_follow_ups_run_for_real_and_use_the_walks(self):
        proc, binary, gt = self._launch("proc_leak_append_list.c")
        eng = ExpertDiagnosticEngine(corpus_dir=self.corpus)
        run = eng.run_recipe(recipe_id="RECIPE_PROCESS_MEMORY_GROWTH", pid=proc.pid, companion_elf=binary)
        checks = {c["recipe_id"]: c for c in run["checks"]}
        self.assertEqual(checks["RECIPE_PROCESS_MEMORY_GROWTH"]["status"], "FAIL")
        for fid in ("RECIPE_HEAP_GROWTH", "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION"):
            self.assertIn(fid, checks)
            obs = checks[fid]["actual_observations"]
            self.assertGreaterEqual(obs["leak_investigation"]["walks"], 3)
            self.assertEqual(checks[fid]["status"], "FAIL")
        lla = checks["RECIPE_LONG_LIVED_OBJECT_ACCUMULATION"]["actual_observations"]["leak_investigation"]
        self.assertIn(gt["owner"], [o["variable"] for o in lla["growth_owners"]])


class TestImp008VerdictRules(unittest.TestCase):
    """Pure-function checks of the strict verdict rules on synthetic walk censuses."""

    cfg = MemoryObservationConfig()

    @staticmethod
    def _walk(t, inuse, owners=None, unreach=None):
        return {"ok": True, "t": t, "in_use_bytes": inuse, "in_use_count": inuse // 1024, "mmapped_bytes": 0,
                "owners": owners or {}, "unreachable": unreach or {}}

    @staticmethod
    def _own(kind, root, count, label=None):
        from collections import Counter
        return {"kind": kind, "label": label or kind, "root": root, "count": count, "bytes": count * 1024,
                "paths": Counter({(root or "") + "(->next)*": count}), "arenas": Counter({1: count})}

    def test_sawtooth_drop_is_not_a_leak(self):
        ws = [self._walk(0, 10 << 20), self._walk(1, 40 << 20), self._walk(2, 70 << 20), self._walk(3, 12 << 20)]
        self.assertEqual(judge(ws, self.cfg)["verdict"], V_SHRANK)

    def test_plateau_is_no_growth(self):
        ws = [self._walk(i, (8 << 20) + (i % 2) * 4096) for i in range(4)]
        self.assertEqual(judge(ws, self.cfg)["verdict"], V_NO_GROWTH)

    def test_stack_held_growth_is_not_established(self):
        ws = [self._walk(i, (1 + i) << 20, owners={"stack:7": self._own("stack_conservative", None, (1 + i) * 1024,
                                                                           "stack of thread w")})
              for i in range(4)]
        j = judge(ws, self.cfg)
        self.assertEqual(j["verdict"], V_NOT_ESTABLISHED)
        self.assertTrue(any("not established as a leak" in x for x in j["limitations"]))

    def test_owned_growth_needs_monotonic_owner_series(self):
        grow = [self._walk(i, (1 + i) << 20, owners={"var::g": self._own("static", "g", (1 + i) * 1024)})
                for i in range(4)]
        self.assertEqual(judge(grow, self.cfg)["verdict"], V_GROWTH_OWNED)
        wobble = [self._walk(i, (1 + i) << 20, owners={"var::g": self._own("static", "g", c)})
                  for i, c in enumerate((1024, 3000, 2000, 4096))]
        self.assertNotEqual(judge(wobble, self.cfg)["verdict"], V_GROWTH_OWNED)

    def test_fewer_than_three_walks_never_judge(self):
        ws = [self._walk(0, 1 << 20), self._walk(1, 9 << 20)]
        self.assertNotIn(judge(ws, self.cfg)["verdict"], LEAK_VERDICTS)

    def test_path_normalisation_aggregates_lists_and_arrays(self):
        class _An:
            node_suffix = ["g_list", "", "->next", "->next", "->next", "g_tab", ".slot[3]", "->chain", "->chain"]
            node_parent = [-1, 0, 1, 2, 3, -1, 5, 6, 7]
        n = _NormPaths(_An())
        self.assertEqual(n.path(3, "->next"), "g_list(->next)*")
        self.assertEqual(n.path(4, "->next"), "g_list(->next)*")
        self.assertEqual(n.path(8, "->chain"), "g_tab.slot[*](->chain)*")


if __name__ == "__main__":
    unittest.main()
