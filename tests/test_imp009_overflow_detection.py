"""IMP-009: buffer overflow detection that names the overflowed buffer's owning variable - real-process tests.

Every fixture is compiled at test time (gcc -g -O0), prints its own ground truth and READY once the bad write
(if any) is done, then idles without calling malloc/free on the damaged chunks.  ``diagnose()`` is called on the
running process (zero-stop).

 a. heap buffer written 8 bytes past its end   -> MEMORY_CORRUPTION, damaged chunk + owning variable of the
                                                   overflowed buffer (and of the victim), 8 bytes of damage
 b. global array overrun into the next global   -> both variable names (probable)
 c. healthy fixtures, all 8 healthy benchmark controls (both symptom modes), and a multi-thread malloc/free
    churner diagnosed 20 times in a row        -> zero overflow / corruption findings
 d. thread close to its stack guard            -> named, with the remaining bytes (warning, not a fault)
 + overrun into a freed (tcache) neighbour      -> damaged header + damaged tcache next pointer
 + off-by-one inside the usable slack           -> NOT reported (documented limit)
 + interposed allocator                         -> "not supported" in not_covered
 + stable vs transient rule (simulated torn / persistent reads), resynchronisation after a damaged header,
   no signal / stop during the integrity walk (separate /proc poller process), 64 MB heap above the baseline cap
 + the legacy name / poison-value heuristic can no longer confirm corruption on its own
"""

import json
import os
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from extractor.diagnostic_recipes import (
    BASELINE_RECIPE_IDS,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipeRegistry,
)
from extractor.expert_diagnostic_engine import diagnose
from extractor.heap_integrity import HeapIntegrityChecker
from extractor.heap_walker import HeapWalker
from extractor.memory_integrity import IntegrityConfig, run_integrity
from extractor.reachability import analyze_heap_ownership
from extractor.target_adapter import LocalTargetAdapter
from tests.support.fixture_process import fixture_popen

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_runtime")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
READY_TIMEOUT_S = 60.0
CORRUPTION_SYMPTOM = "data in this program looks garbled, I suspect memory corruption"
CORRUPTION_CATS = ("MEMORY_CORRUPTION", "STACK_CORRUPTION")

_POLLER = r"""
import json, os, sys
pid, stopf, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
polls = 0; stops = []; traced = 0; tids = []
open(out + ".ready", "w").close()
while not os.path.exists(stopf):
    if polls % 200 == 0:
        try:
            tids = os.listdir("/proc/%d/task" % pid)
        except OSError:
            break
    for tid in tids:
        try:
            with open("/proc/%d/task/%s/stat" % (pid, tid)) as f:
                st = f.read()
        except OSError:
            continue
        state = st[st.rfind(")") + 2]
        if state in "tT":
            stops.append([tid, state])
    if polls % 50 == 0:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith("TracerPid:") and int(line.split()[1]) != 0:
                    traced += 1
    polls += 1
with open(out, "w") as f:
    json.dump({"polls": polls, "stops": stops, "traced": traced}, f)
"""


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp009_")
        cls.corpus = os.path.join(cls.tmp, "corpus")
        cls.bins = {}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _binary(self, src, extra=()):
        key = (src, tuple(extra))
        if key not in self.bins:
            out = os.path.join(self.tmp, os.path.splitext(src)[0])
            subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", os.path.join(FIXTURES, src),
                            "-o", out] + list(extra), check=True, capture_output=True, timeout=120)
            self.bins[key] = out
        return self.bins[key]

    def _launch(self, src, extra=()):
        binary = self._binary(src, extra)
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
        time.sleep(0.05)
        self.assertIsNone(proc.poll(), "fixture crashed after READY")
        return proc, binary, lines

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
        mi = None
        for c in r["report"]["section_d_detailed_inspection_results"]["checks"]:
            x = (c.get("actual_observations") or {}).get("memory_integrity")
            if isinstance(x, dict):
                mi = x
        return r, mi

    @staticmethod
    def _cat(r, *cats):
        return [f for f in r["findings"] if f["category"] in cats]


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestHeapOverflow(_Base):
    def test_a_eight_bytes_past_a_heap_buffer_names_the_buffer(self):
        proc, binary, lines = self._launch("proc_imp009_heap_overrun.c")
        f = [l.split() for l in lines if l.startswith("OVERRUN")][0]
        buf_var, buf_user, usable, past, victim_var, victim_user = f[1], int(f[2], 16), int(f[3]), int(f[4]), \
            f[5], int(f[6], 16)
        slack_var = [l.split() for l in lines if l.startswith("SLACK")][0][1]
        for symptom in (None, CORRUPTION_SYMPTOM):
            with self.subTest(symptom=symptom):
                r, mi = self._diagnose(proc.pid, binary, symptom)
                self.assertEqual(r["verdict"], "CONFIRMED_FAULT", r["summary"])
                fs = self._cat(r, "MEMORY_CORRUPTION")
                self.assertTrue(fs, r["findings"])
                self.assertEqual(fs[0]["status"], "CONFIRMED_ROOT_CAUSE")
                self.assertIn(buf_var, fs[0]["subjects"])
                self.assertIn(victim_var, fs[0]["subjects"])
                self.assertNotIn(slack_var, fs[0]["subjects"], "the off-by-one inside the slack is not visible")
                defects = mi["heap"]["defects"]
                d = [x for x in defects if x["kind"] == "chunk_header_damaged"]
                self.assertEqual(len(d), 1, defects)
                d = d[0]
                sys.stderr.write("\nIMP-009 a (%s): %s\n" % (symptom or "default", d["description"]))
                self.assertEqual(d["status"], "confirmed")
                self.assertEqual(int(d["at"], 16), victim_user - 16, "damaged chunk = the victim's header")
                self.assertEqual(d["overflowing_buffer"]["variable"], buf_var)
                self.assertEqual(int(d["overflowing_buffer"]["user_address"], 16), buf_user)
                self.assertEqual(d["overflowing_buffer"]["usable_size"], usable)
                self.assertEqual(d["damage"]["bytes_past_usable_end"], past)
                self.assertEqual(d["victim"]["variable"], victim_var)
                self.assertTrue(r["collection_impact"]["zero_stop"])

    def test_off_by_one_inside_usable_slack_is_not_reported(self):
        """Documented limit: malloc(20) has 24 usable bytes on LP64; a 21-byte write damages no metadata."""
        proc, binary, lines = self._launch("proc_imp009_heap_overrun.c")
        slack = [l.split() for l in lines if l.startswith("SLACK")][0]
        var, user = slack[1], int(slack[2], 16)
        rec = run_integrity(LocalTargetAdapter(), proc.pid, binary, IntegrityConfig(), None, full_reason="test")
        for d in rec["heap"]["defects"]:
            self.assertNotEqual(d["overflowing_buffer"].get("variable"), var)
            self.assertNotEqual(int(d["at"], 16), user + 24 - 8, "slack write must not look like damage")
        self.assertEqual(len(rec["heap"]["defects"]), 1, "only the real 8-byte overrun is reported")

    def test_overflow_into_freed_tcache_neighbour(self):
        proc, binary, lines = self._launch("proc_imp009_freed_neighbour.c")
        f = [l.split() for l in lines if l.startswith("OVERRUN")][0]
        buf_var, usable, past, stale_var, stale_user = f[1], int(f[3]), int(f[4]), f[5], int(f[6], 16)
        rec = run_integrity(LocalTargetAdapter(), proc.pid, binary, IntegrityConfig(), None, full_reason="test")
        kinds = {d["kind"]: d for d in rec["heap"]["defects"]}
        self.assertIn("chunk_header_damaged", kinds, rec["heap"])
        self.assertIn("tcache_pointer_damaged", kinds, rec["heap"])
        h, t = kinds["chunk_header_damaged"], kinds["tcache_pointer_damaged"]
        sys.stderr.write("\nIMP-009 freed neighbour: %s | %s\n" % (h["description"], t["description"]))
        self.assertEqual(int(h["at"], 16), stale_user - 16)
        self.assertEqual(h["overflowing_buffer"]["variable"], buf_var)
        self.assertEqual(h["overflowing_buffer"]["usable_size"], usable)
        self.assertEqual(h["damage"]["bytes_past_usable_end"], past)
        self.assertEqual(int(t["victim"]["chunk_address"], 16), stale_user - 16)
        self.assertEqual(t["victim"].get("variable"), stale_var, "the dangling pointer to the freed chunk is named")
        self.assertEqual(t["status"], "probable")
        r, _mi = self._diagnose(proc.pid, binary)
        fs = self._cat(r, "MEMORY_CORRUPTION")
        self.assertTrue(fs and buf_var in fs[0]["subjects"], r["findings"])

    def test_resynchronisation_after_a_damaged_header(self):
        """One damaged header does not hide the chunks after it: the walk resumes at the next valid header chain."""
        proc, binary, lines = self._launch("proc_imp009_heap_overrun.c")
        f = [l.split() for l in lines if l.startswith("OVERRUN")][0]
        victim_user = int(f[6], 16)
        small_user = int([l.split() for l in lines if l.startswith("SLACK")][0][2], 16)
        an = analyze_heap_ownership(proc.pid, binary, adapter=LocalTargetAdapter(), include_typed_locals=False,
                                    use_libc_debug_info=False, cache=False)
        w = an.walk
        self.assertEqual(len(w.damaged_regions), 1, w.inconsistencies)
        self.assertEqual(int(w.damaged_regions[0]["at"], 16), victim_user - 16)
        ct = w.chunks
        self.assertIsNotNone(ct.index_of_user(small_user), "chunk after the damaged one was not walked")
        self.assertTrue(any(ct.states[i] == 5 for i in range(len(ct))), "top not reached after resync")
        # the damaged region is still attributed to its owner (reverse map works on resynchronised chunks)
        self.assertEqual(an.lookup(victim_user)["referrers"][0]["path"], f[5])


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestGlobalAndStack(_Base):
    def test_b_global_array_overrun_names_both_variables(self):
        proc, binary, lines = self._launch("proc_imp009_global_overrun.c", extra=("-fno-toplevel-reorder",))
        if "LAYOUT ok" not in lines:
            self.skipTest("compiler did not lay the globals out in definition order: %s" % lines)
        pairs = [tuple(l.split()[1:3]) for l in lines if l.startswith("GLOBAL_OVERRUN")]
        r, mi = self._diagnose(proc.pid, binary)
        fs = self._cat(r, "MEMORY_CORRUPTION")
        self.assertTrue(fs, r["findings"])
        self.assertEqual(fs[0]["status"], "PROBABLE_CAUSE", "an adjacent-overwrite candidate is never confirmed")
        cands = mi["globals"]["candidates"]
        got = {(c["overflowed_array"]["variable"], c["overwritten_neighbour"]["variable"]) for c in cands}
        sys.stderr.write("\nIMP-009 b: %s\n" % "; ".join(c["description"] for c in cands))
        for a, n in pairs:
            self.assertIn((a, n), got)
            self.assertIn(a, fs[0]["subjects"])
            self.assertIn(n, fs[0]["subjects"])
        self.assertEqual(len(got), len(pairs), "the intact control pair must not be reported")
        self.assertNotIn("g_spare", fs[0]["subjects"])

    def test_d_thread_near_its_stack_guard_is_named_with_remaining_bytes(self):
        proc, binary, lines = self._launch("proc_imp009_deep_stack.c")
        deep = [l.split() for l in lines if l.startswith("DEEP")][0]
        tid, name, margin_gt = int(deep[1]), deep[2], int(deep[5])
        shallow = [l.split() for l in lines if l.startswith("SHALLOW")][0][2]
        r, mi = self._diagnose(proc.pid, binary)
        ws = mi["stacks"]["warnings"]
        sys.stderr.write("\nIMP-009 d: %s\n" % "; ".join(w["description"] for w in ws))
        self.assertEqual([w["thread_name"] for w in ws], [name])
        w = ws[0]
        self.assertEqual(w["kind"], "EXHAUSTION_WARNING")
        self.assertEqual(w["tid"], tid)
        self.assertLess(w["margin_bytes"], 16 * 1024)
        self.assertLess(abs(w["margin_bytes"] - margin_gt), 4096, "margin differs from the fixture's own (%d)" % margin_gt)
        fs = self._cat(r, "RESOURCE_EXHAUSTION")
        self.assertTrue(fs, r["findings"])
        self.assertIn(name, fs[0]["subjects"])
        self.assertNotIn(shallow, fs[0]["subjects"])
        self.assertEqual(fs[0]["status"], "PROBABLE_CAUSE")
        self.assertEqual(fs[0]["severity"], "WARNING")
        self.assertFalse(self._cat(r, *CORRUPTION_CATS), "a small margin is not corruption")


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestHealthy(_Base):
    HEALTHY = ("proc_scenario_a_healthy.c", "proc_thread_normal_cv.c", "proc_idle_pool_uncontended_mutex.c",
               "proc_heap_ownership.c", "proc_cache_plateau.c")

    def test_c_healthy_fixtures_have_no_corruption_findings(self):
        for src in self.HEALTHY:
            proc, binary, _ = self._launch(src) if self._prints_ready(src) else self._settle(src)
            for symptom in (None, CORRUPTION_SYMPTOM):
                with self.subTest(fixture=src, symptom=symptom):
                    r, mi = self._diagnose(proc.pid, binary, symptom)
                    self.assertFalse(self._cat(r, *CORRUPTION_CATS), r["findings"])
                    self.assertFalse([f for f in r["findings"] if "RECIPE_HEAP_METADATA_CORRUPTION" in f["recipe_ids"]],
                                     r["findings"])
                    self.assertIsNotNone(mi)
                    # A heap above the baseline cap is honestly NOT_CHECKED (defects None); a checked heap must
                    # have an empty defect list. Either way no corruption may be reported for a healthy program.
                    self.assertIn(mi["heap"].get("status"), ("COMPLETED", "PARTIAL", "NOT_CHECKED"), mi["heap"])
                    self.assertFalse(mi["heap"].get("defects"), mi["heap"])
                    self.assertEqual(mi["stacks"]["warnings"], [])
                    self.assertEqual(mi["globals"].get("candidates", []), [])
            self._kill(proc)

    def _prints_ready(self, src):
        with open(os.path.join(FIXTURES, src), encoding="utf-8", errors="replace") as f:
            return "READY" in f.read()

    def _settle(self, src):
        binary = self._binary(src)
        proc = fixture_popen([binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        self.addCleanup(self._kill, proc)
        time.sleep(1.0)
        self.assertIsNone(proc.poll())
        return proc, binary, []

    def test_c_benchmark_healthy_controls_both_symptom_modes(self):
        sys.path.insert(0, REPO)
        from benchmarks.diagnosis_accuracy import run_benchmark as rb
        healthy = [g for g in rb.load_ground_truth() if g["kind"] == "none"]
        self.assertEqual(len(healthy), 8)
        cwd = os.getcwd()
        os.chdir(REPO)
        self.addCleanup(os.chdir, cwd)
        for mode in ("ground_truth", "generic"):
            rep = rb.run_all(healthy, symptom_mode=mode)
            for row in rep["rows"]:
                with self.subTest(target=row["id"], mode=mode):
                    self.assertIsNone(row.get("error"), row)
                    self.assertFalse(row["false_positive"], row)
                    self.assertFalse([c for c in row["finding_categories"] if c in CORRUPTION_CATS], row)

    def test_c_torn_read_stress_twenty_diagnoses_of_a_churning_heap(self):
        """Four threads malloc/calloc/realloc/free continuously; inconsistent copies must stay 'not evidence'."""
        proc, binary, _ = self._launch("proc_imp009_churn_mt.c")
        transient = 0
        for i in range(20):
            symptom = CORRUPTION_SYMPTOM if i % 2 else None
            r, mi = self._diagnose(proc.pid, binary, symptom)
            self.assertIsNone(proc.poll(), "churner died")
            bad = self._cat(r, *CORRUPTION_CATS)
            self.assertFalse(bad, "diagnosis %d reported corruption on a healthy churning heap: %s" % (i, bad))
            if mi and mi["heap"].get("defects") is not None:
                self.assertEqual(mi["heap"]["defects"], [], mi["heap"])
                transient += len(mi["heap"].get("inconsistent_reads_not_evidence") or [])
        sys.stderr.write("\nIMP-009 churn: 20 diagnoses, %d inconsistent copies classified as not evidence\n" % transient)


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestStableVersusTransient(_Base):
    """Simulated read paths on a real healthy process: a header garbled in some reads only is a torn read; the
    same garbage in every read is damage; damage seen while the arena mutex is held is not at rest."""

    def _victim(self, pid, binary):
        an = analyze_heap_ownership(pid, binary, adapter=LocalTargetAdapter(), include_typed_locals=False,
                                    use_libc_debug_info=False, cache=False)
        ct = an.walk.chunks
        mid = [i for i in range(1, len(ct) - 1) if ct.states[i] == 1 and ct.states[i - 1] == 1]
        self.assertTrue(mid)
        return int(ct.addrs[mid[len(mid) // 2]]), an

    def _adapter(self, victim, garble_reads, lock_arena=None):
        state = {"n": 0}

        class A(LocalTargetAdapter):
            def read_memory_batch(self, pid, slices):
                out = super().read_memory_batch(pid, slices)
                res = []
                for (a, n), (data, st, err) in zip(slices, out):
                    if data and a <= victim + 8 and victim + 16 <= a + len(data):
                        state["n"] += 1
                        if garble_reads(state["n"]):
                            b = bytearray(data)
                            b[victim + 8 - a:victim + 16 - a] = b"\x13\xff\x13\xff\x13\xff\x13\xff"
                            data = bytes(b)
                    if data and lock_arena is not None and a == lock_arena and n == 4:
                        data = struct.pack("<i", 1)
                    res.append((data, st, err))
                return res
        return A()

    def _check(self, pid, adapter):
        walker = HeapWalker(adapter, pid, use_libc_debug_info=False)
        walk = walker.walk()
        chk = HeapIntegrityChecker(walk, walker, walker.reader, stability_interval_s=0.01)
        chk.detect()
        chk.confirm_stability()
        return chk, chk.attribute(None)

    def test_transient_persistent_and_locked(self):
        proc, binary, _ = self._launch("proc_heap_ownership.c")      # healthy heap: no real damage
        victim, an = self._victim(proc.pid, binary)
        # garbled in the walker's first read only: retried, walk is clean, nothing reported
        chk, defects = self._check(proc.pid, self._adapter(victim, lambda n: n == 1))
        self.assertFalse([d for d in defects if int(d["at"], 16) == victim], defects)
        # garbled in all three walker reads, intact in the stability re-reads: not evidence
        chk, defects = self._check(proc.pid, self._adapter(victim, lambda n: n <= 3))
        self.assertFalse([d for d in defects if int(d["at"], 16) == victim], defects)
        self.assertTrue([t for t in chk.transient if int(t["at"], 16) == victim], chk.transient)
        # garbled in every read: stable damage at that header
        chk, defects = self._check(proc.pid, self._adapter(victim, lambda n: True))
        mine = [d for d in defects if int(d["at"], 16) == victim]
        self.assertEqual(len(mine), 1, defects)
        self.assertEqual(mine[0]["status"], "probable", "no owner map was given: owner unknown -> probable")
        # garbled in every read but the arena mutex is held in every re-read: not at rest -> not evidence
        arena = an.analyzer.walker._arena_addrs[0]
        chk, defects = self._check(proc.pid, self._adapter(victim, lambda n: True, lock_arena=arena))
        self.assertFalse([d for d in defects if int(d["at"], 16) == victim], defects)
        self.assertIn("locked", " ".join(t["why"] for t in chk.transient))


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestSupportCostAndZeroStop(_Base):
    def test_interposed_allocator_is_reported_not_supported(self):
        proc, binary, _ = self._launch("proc_heap_custom_allocator.c")
        r, mi = self._diagnose(proc.pid, binary, CORRUPTION_SYMPTOM)
        self.assertEqual(mi["heap"]["status"], "UNSUPPORTED")
        nc = [n for n in r["not_covered"] if n["item"] == "memory_integrity"]
        self.assertTrue([n for n in nc if n["kind"] == "unsupported_on_target"], r["not_covered"])
        self.assertFalse(self._cat(r, *CORRUPTION_CATS))

    def test_integrity_walk_never_stops_target_and_64mb_heap_cost(self):
        proc, binary, lines = self._launch("proc_heap_big.c")
        progress_addr = int([l for l in lines if l.startswith("PROGRESS")][0].split()[1], 16)
        stopf = os.path.join(self.tmp, "stop")
        outf = os.path.join(self.tmp, "poll.json")
        poller = fixture_popen([sys.executable, "-c", _POLLER, str(proc.pid), stopf, outf])
        self.addCleanup(self._kill, poller)
        deadline = time.monotonic() + 30
        while not os.path.exists(outf + ".ready"):
            self.assertLess(time.monotonic(), deadline, "poller did not start")
            time.sleep(0.01)

        def _progress():
            with open("/proc/%d/mem" % proc.pid, "rb") as f:
                f.seek(progress_addr)
                return struct.unpack("<Q", f.read(8))[0]
        p0 = _progress()
        t0 = time.monotonic()
        rec = run_integrity(LocalTargetAdapter(), proc.pid, binary, IntegrityConfig(), None, full_reason="test")
        wall = time.monotonic() - t0
        # default diagnose (baseline mode): the 64 MB heap is above the cap -> not checked, said so
        r, mi = self._diagnose(proc.pid, binary)
        p1 = _progress()
        open(stopf, "w").close()
        poller.wait(timeout=30)
        with open(outf) as f:
            poll = json.load(f)
        sys.stderr.write("\nIMP-009 64MB integrity walk (full mode, owner map): wall=%.2fs bytes=%d walk_ms=%s chunks=%s "
                         "polls=%d stops=%d\n" % (wall, rec["heap"]["cost"]["bytes_read"],
                                                  rec["heap"]["cost"]["walk_wall_ms"], rec["heap"]["checked"]["chunks"],
                                                  poll["polls"], len(poll["stops"])))
        self.assertEqual(rec["heap"]["defects"], [])
        self.assertEqual(poll["stops"], [], "target observed stopped during the integrity walk")
        self.assertEqual(poll["traced"], 0)
        self.assertGreater(poll["polls"], 50)
        self.assertGreater(p1, p0, "target progress counter did not advance")
        self.assertEqual(mi["heap"]["status"], "NOT_CHECKED")
        self.assertTrue([n for n in r["not_covered"] if n["item"] == "memory_integrity"
                         and "heap larger than baseline cap" in n["reason"]], r["not_covered"])
        self.assertTrue(r["collection_impact"]["zero_stop"])

    def test_baseline_check_is_planned_and_cheap_on_a_small_idle_process(self):
        self.assertIn("RECIPE_HEAP_METADATA_CORRUPTION", BASELINE_RECIPE_IDS)
        proc, binary, _ = self._launch("proc_imp009_deep_stack.c")
        r, mi = self._diagnose(proc.pid, binary)
        row = [c for c in r["checks_run"] if c["recipe_id"] == "RECIPE_HEAP_METADATA_CORRUPTION"]
        self.assertTrue(row)
        self.assertEqual(mi["mode"], "baseline")
        self.assertEqual(mi["heap"]["status"], "COMPLETED")
        self.assertLess(row[0]["duration_s"], 1.0)
        self.assertLess(mi["heap"]["cost"]["bytes_read"], 4 * 1024 * 1024)


class TestLegacyHeuristicDemoted(unittest.TestCase):
    def test_name_and_poison_value_alone_are_capped_at_probable(self):
        for rid in ("RECIPE_HEAP_METADATA_CORRUPTION", "RECIPE_INVALID_MEMORY_ACCESS"):
            data = {"magic_corrupted": True, "chunk_state": "CORRUPTED", "observed_magic": "0xdeadbeef",
                    "faulting_address": "0x55550000", "is_mapped": True, "vma_permissions": "rw-p"}
            res = DiagnosticRecipeRegistry.evaluate_recipe(rid, data)
            with self.subTest(recipe=rid):
                self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
                self.assertEqual(res.details.get("certainty_cap"), "PROBABLE")
                self.assertTrue(res.details.get("corruption_hint_only"))

    def test_integrity_record_decides_and_hint_does_not_confirm(self):
        rec = {"mode": "baseline", "limitations": [], "heap": {"status": "COMPLETED", "defects": [], "checked": {"chunks": 9}},
               "globals": {"candidates": []}, "stacks": {"warnings": []}}
        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_HEAP_METADATA_CORRUPTION", {"memory_integrity": rec})
        self.assertEqual(res.status, "CONTRADICTED")
        res = DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_HEAP_METADATA_CORRUPTION",
                                                       {"memory_integrity": rec, "magic_corrupted": True})
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertEqual(res.details.get("certainty_cap"), "PROBABLE")


if __name__ == "__main__":
    unittest.main()
