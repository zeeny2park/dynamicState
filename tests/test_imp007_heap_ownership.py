"""IMP-007: heap walker + reverse reference map (address -> variable), real-process tests.

Every acceptance test runs a C/C++ fixture compiled at test time (gcc -g -O0) that prints its own
ground truth (true block addresses, sizes, owning variable paths, leaked and freed blocks) and then
blocks in a steady state (all threads in pause(), the 64MB fixture keeps one spinning thread).
The tool output is compared against that ground truth.

Acceptance criteria covered:
 AC1 address of a malloc'ed block -> global path name(s) + block size  (test_ac1_*)
 AC2 block referenced only by a local -> thread/function/variable when the frame decoder supports
     the target, else a conservative stack reference naming the thread       (test_ac2_*)
 AC3 erased pointer -> "no reachable path"; live and freed blocks are not leak candidates (test_ac3_*)
 AC4 plain C structs (all C fixtures) and C++ objects without virtual functions (test_ac4_*)
 AC5 non-glibc / foreign allocator -> refused as unsupported allocator   (test_ac5_*)
 AC6 64MB heap walk: no signal / stop observed by a separate polling PROCESS, target progress
     counter keeps advancing                                              (test_ac6_*)
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

from extractor.heap_walker import (
    STATUS_INCONCLUSIVE,
    STATUS_OK,
    STATUS_PARTIAL,
    STATUS_UNSUPPORTED_ALLOCATOR,
    STATUS_UNSUPPORTED_GLIBC_VERSION,
    HeapWalker,
    parse_glibc_version,
)
from extractor.reachability import analyze_heap_ownership, get_cached_analysis
from extractor.target_abi import TargetABI, detect_target_abi
from extractor.target_adapter import LocalTargetAdapter
from extractor.watch_session import WatchSessionManager, read_process_memory_slice
from tests.support.fixture_process import fixture_popen

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_runtime")
READY_TIMEOUT_S = 60.0

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


def _compile(src, out, cxx=False, extra=()):
    cc = "g++" if cxx else "gcc"
    cmd = [cc, "-g", "-O0", "-Wl,--build-id=sha1", os.path.join(FIXTURES, src), "-o", out] + list(extra)
    if not cxx:
        cmd.append("-pthread")
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    return out


def _launch(testcase_or_cls, binary):
    proc = fixture_popen([binary], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lines = []
    buf = b""
    deadline = time.monotonic() + READY_TIMEOUT_S
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            proc.kill()
            raise AssertionError("fixture did not print READY in time")
        r, _, _ = select.select([proc.stdout], [], [], left)
        if not r:
            continue
        chunk = os.read(proc.stdout.fileno(), 65536)
        if not chunk:
            proc.wait()
            raise AssertionError("fixture exited before READY")
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            line = line.decode().strip()
            lines.append(line)
            if line == "READY":
                return proc, lines


def _kill(proc):
    try:
        proc.kill()
    except OSError:
        pass
    proc.wait()
    if proc.stdout is not None:
        proc.stdout.close()


def _parse(lines):
    gt = {"BLOCK": [], "LEAK": [], "FREED": [], "LOCAL": [], "OPAQUE": [], "INTERIOR": []}
    for l in lines:
        f = l.split()
        if f and f[0] in gt:
            gt[f[0]].append(f)
    return gt


def _metrics(an, gt):
    """Recall of in-use blocks, leak-candidate precision/recall against the fixture's ground truth."""
    ct = an.analyzer.ct
    live = [int(f[1], 16) for f in gt["BLOCK"]] + [int(f[1], 16) for f in gt["LOCAL"]] + \
        [int(f[1], 16) for f in gt["OPAQUE"]] + [int(f[2], 16) for f in gt["INTERIOR"]]
    leaks = {int(f[1], 16) for f in gt["LEAK"]}
    found_in_use = 0
    for a in list(live) + list(leaks):
        i = ct.index_of_user(a)
        if i is not None and ct.chunk_dict(i)["in_use"]:
            found_in_use += 1
    cands = set(an.leak_candidate_addresses())
    return {
        "ground_truth_in_use_blocks": len(live) + len(leaks),
        "found_as_in_use_chunks": found_in_use,
        "true_leaks": len(leaks),
        "leak_candidates": len(cands),
        "true_leaks_reported": len(leaks & cands),
        "fixture_live_blocks_misreported_as_leaks": len(set(live) & cands),
        "unexplained_candidates": len(cands - leaks - set(live)),
    }


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestHeapOwnershipRealProcess(unittest.TestCase):
    """One run of the multi-threaded C fixture, analysed with the default arena-location method and
    with the symbol-free signature scan."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp007_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.binary = _compile("proc_heap_ownership.c", os.path.join(cls.tmp, "proc_heap_ownership"))
        cls.proc, lines = _launch(cls, cls.binary)
        cls.addClassCleanup(_kill, cls.proc)
        cls.gt = _parse(lines)
        cls.manager = WatchSessionManager(corpus_dir=os.path.join(cls.tmp, "corpus"))
        cls.an = analyze_heap_ownership(cls.proc.pid, cls.binary, manager=cls.manager)
        cls.an_sig = analyze_heap_ownership(cls.proc.pid, cls.binary, manager=cls.manager, force_signature_scan=True)

    def _lookup(self, addr, an=None):
        return (an or self.an).lookup(int(addr, 16) if isinstance(addr, str) else addr)

    def test_walk_status_and_arenas(self):
        for an in (self.an, self.an_sig):
            self.assertEqual(an.status, STATUS_OK, an.message)
            hw = an.summary()["heap_walk"]
            self.assertEqual(hw["inconsistencies"], [])
            # main arena + one arena per worker / holder thread
            self.assertGreaterEqual(len(hw["arenas"]), 5)
            self.assertTrue(any(not a["is_main"] for a in hw["arenas"]))
            # a tcache_perthread_struct per thread that allocated (main, 4 workers, holder)
            self.assertGreaterEqual(len(hw["tcache_structs"]), 6)
        self.assertEqual(self.an_sig.summary()["heap_walk"]["arena_location"]["method"], "signature_scan")

    def test_signature_scan_agrees_with_default_method(self):
        a = self.an.summary()["heap_walk"]
        b = self.an_sig.summary()["heap_walk"]
        self.assertEqual(a["arena_location"]["main_arena"], b["arena_location"]["main_arena"])
        self.assertEqual(a["counts"], b["counts"])
        self.assertEqual(sorted(self.an.leak_candidate_addresses()), sorted(self.an_sig.leak_candidate_addresses()))

    def test_ac1_global_paths_and_block_size(self):
        self.assertGreater(len(self.gt["BLOCK"]), 250)
        for an in (self.an, self.an_sig):
            for f in self.gt["BLOCK"]:
                _, addr, size, path = f
                r = self._lookup(addr, an)
                self.assertEqual(r["status"], "FOUND", f)
                self.assertTrue(r["chunk"]["in_use"], f)
                self.assertGreaterEqual(r["chunk"]["usable_size"], int(size), f)
                self.assertLess(r["chunk"]["usable_size"], int(size) + 65536 + 32, f)   # mmapped: page rounding
                paths = [x.get("path") for x in r["referrers"]]
                self.assertIn(path, paths, f)
                ref = [x for x in r["referrers"] if x.get("path") == path][0]
                self.assertTrue(ref["typed"])
                self.assertIn(ref["kind"], ("global", "static"))
                self.assertFalse(r["leak_candidate"], f)
        # file-static variable is reported as such
        st = [f for f in self.gt["BLOCK"] if f[3] == "s_static_owned"][0]
        self.assertEqual([x["kind"] for x in self._lookup(st[1])["referrers"]], ["static"])

    def test_ac1_interior_pointer_maps_to_containing_block(self):
        for _, inner, block, path in self.gt["INTERIOR"]:
            r = self._lookup(inner)
            self.assertEqual(r["chunk"]["user_address"], "0x%x" % int(block, 16))
            self.assertEqual(r["offset_in_block"], int(inner, 16) - int(block, 16))
            refs = [x for x in r["referrers"] if x.get("path") == path]
            self.assertEqual(len(refs), 1)
            self.assertEqual(refs[0]["interior_offset"], int(inner, 16) - int(block, 16))

    def test_ac1_mmapped_large_block(self):
        f = [f for f in self.gt["BLOCK"] if f[3] == "g_big"][0]
        r = self._lookup(f[1])
        self.assertEqual(r["chunk"]["state"], "in_use_mmapped")
        self.assertGreaterEqual(r["chunk"]["usable_size"], 2 * 1024 * 1024)
        # an address in the middle of the block maps to the same chunk
        mid = self._lookup(int(f[1], 16) + 1024 * 1024)
        self.assertEqual(mid["chunk"]["user_address"], r["chunk"]["user_address"])
        self.assertIn("g_big", [x.get("path") for x in mid["referrers"]])

    def test_ac1_untyped_parent_is_reachable_not_leak(self):
        for _, addr, _size, parent in self.gt["OPAQUE"]:
            r = self._lookup(addr)
            self.assertFalse(r["leak_candidate"])
            self.assertEqual(r["reachability"], "conservative")
            self.assertTrue(any(x["kind"] == "heap_conservative" and x.get("path", "").startswith(parent)
                                for x in r["referrers"]), r["referrers"])

    def test_ac2_local_only_block(self):
        locs = self.an.summary()["root_sources"]["locals"]
        decoder_supported = "SUPPORTED" in set((locs.get("decoder_status") or {}).values())
        for _, addr, size, thread, function, variable in self.gt["LOCAL"]:
            r = self._lookup(addr)
            self.assertTrue(r["chunk"]["in_use"])
            self.assertGreaterEqual(r["chunk"]["usable_size"], int(size))
            self.assertFalse(r["leak_candidate"])
            if decoder_supported:
                typed = [x for x in r["referrers"] if x["kind"] == "local"]
                self.assertTrue(typed, r["referrers"])
                self.assertEqual((typed[0]["thread"], typed[0]["function"], typed[0]["variable"]),
                                 (thread, function, variable))
            else:
                # frame-locals decoder unsupported on this target (IMP-011): conservative stack reference
                cons = [x for x in r["referrers"] if x["kind"] == "stack_conservative"]
                self.assertTrue(cons, r["referrers"])
                self.assertEqual(cons[0]["thread"], thread)
                self.assertIn("conservative, no variable name", cons[0]["description"])
                self.assertFalse(cons[0]["typed"])

    def test_ac2_typed_local_reported_as_thread_function_variable(self):
        """Typed-local plumbing, independent of the unwinder: feed the analysis the frame decoder's
        output format for the real slot of `only_local` and check the thread/function/variable report
        and that the conservative stack reference for the same slot is suppressed."""
        _, addr, _size, thread, function, variable = self.gt["LOCAL"][0]
        refs = self._lookup(addr)["referrers"]
        slot = [x for x in refs if x["kind"] in ("local", "stack_conservative")][0]["slot_address"]
        tid = [x for x in refs if x["kind"] in ("local", "stack_conservative")][0]["tid"]

        class DecoderOutput(WatchSessionManager):
            def inspect_thread_locals_and_frame_vars(self, **kw):
                return {"threads": [{"tid": tid, "name": thread, "frame_decode_status": "SUPPORTED", "frames": [
                    {"function_name": function, "parameters": [],
                     "locals": [{"name": variable, "runtime_address": slot}]}]}]}

        an = analyze_heap_ownership(self.proc.pid, self.binary, cache=False,
                                    manager=DecoderOutput(corpus_dir=os.path.join(self.tmp, "corpus2")))
        r = an.lookup(int(addr, 16))
        typed = [x for x in r["referrers"] if x["kind"] == "local"]
        self.assertEqual(len(typed), 1, r["referrers"])
        self.assertEqual((typed[0]["thread"], typed[0]["function"], typed[0]["variable"], typed[0]["path"]),
                         (thread, function, variable, variable))
        self.assertEqual(typed[0]["description"], "thread %s, function %s, variable %s" % (thread, function, variable))
        self.assertEqual(r["reachability"], "typed")
        self.assertFalse([x for x in r["referrers"] if x["kind"] == "stack_conservative" and x["slot_address"] == slot])

    def test_ac3_leaks_and_freed_blocks(self):
        cands = set(self.an.leak_candidate_addresses())
        for _, addr, size in self.gt["LEAK"]:
            r = self._lookup(addr)
            self.assertTrue(r["leak_candidate"], r)
            self.assertEqual(r["classification"], "no reachable path (leak candidate)")
            self.assertEqual(r["referrers"], [])
            self.assertGreaterEqual(r["chunk"]["usable_size"], int(size))
        for kind in ("BLOCK", "LOCAL", "OPAQUE"):
            for f in self.gt[kind]:
                self.assertNotIn(int(f[1], 16), cands, f)
        states = {}
        for _, addr, size in self.gt["FREED"]:
            r = self._lookup(addr)
            self.assertFalse(r["chunk"]["in_use"], (addr, r["chunk"]))
            self.assertFalse(r["leak_candidate"])
            self.assertNotIn(int(addr, 16), cands)
            states.setdefault(size, []).append(r["chunk"]["state"])
        # 10 frees of one size class: 7 fill the tcache (in-use bit still set), 3 go to the fastbin
        self.assertEqual(sorted(states["56"]).count("free_tcache"), 7, states)
        self.assertEqual(sorted(states["56"]).count("free_fastbin"), 3, states)
        m = _metrics(self.an, self.gt)
        sys.stderr.write("\nIMP-007 fixture metrics: %s\n" % json.dumps(m))
        self.assertEqual(m["found_as_in_use_chunks"], m["ground_truth_in_use_blocks"])
        self.assertEqual(m["true_leaks_reported"], m["true_leaks"])
        self.assertEqual(m["fixture_live_blocks_misreported_as_leaks"], 0)
        self.assertLessEqual(m["unexplained_candidates"], 2, m)   # libc-internal blocks, if any
        report = self.an.leak_report()
        self.assertEqual(report["total_candidates"], len(cands))
        self.assertTrue(report["leak_candidates_complete"])

    def test_thread_arena_tcache_and_fastbins(self):
        hw = self.an.summary()["heap_walk"]
        thread_tc = [t for t in hw["tcache_structs"] if t["arena_index"] != 0 and t["cached_chunks"] == 7]
        self.assertGreaterEqual(len(thread_tc), 4, hw["tcache_structs"])   # 4 workers: 7 cached each
        thread_fast = [a for a in hw["arenas"] if not a["is_main"] and a.get("fastbin_chunks") == 2]
        self.assertGreaterEqual(len(thread_fast), 4)

    def test_reads_are_budgeted_and_zero_stop(self):
        s = self.an.summary()
        self.assertEqual(s["target_stop_ms"], 0.0)
        self.assertEqual(s["cost"]["budget_target_stop_ms"], 0.0)
        self.assertGreater(s["cost"]["bytes_read"], 0)
        self.assertGreaterEqual(s["cost"]["budget_bytes_charged"], s["cost"]["bytes_read"])

    def test_budget_exhaustion_is_reported_not_raised(self):
        an = analyze_heap_ownership(self.proc.pid, self.binary, manager=self.manager,
                                    budget_limits={"max_bytes_read": 64 * 1024})
        self.assertIn(an.status, ("BUDGET_EXHAUSTED", STATUS_PARTIAL))
        self.assertFalse(an.leak_candidates_complete)

    def test_unsupported_and_inconclusive_targets_are_refused(self):
        pid = self.proc.pid
        real = detect_target_abi(LocalTargetAdapter(), pid)
        musl = TargetABI.from_dict({**real.to_dict(), "libc": "musl", "libc_version": None})
        an = analyze_heap_ownership(pid, self.binary, abi=musl, cache=False)
        self.assertEqual(an.status, STATUS_UNSUPPORTED_ALLOCATOR)
        self.assertIn("not supported on this target", an.message)
        self.assertEqual(an.lookup(0x1234)["status"], STATUS_UNSUPPORTED_ALLOCATOR)
        self.assertIsNone(an.leak_report()["leak_candidates"])
        undetected = TargetABI()   # ABI detection failed
        self.assertEqual(analyze_heap_ownership(pid, self.binary, abi=undetected, cache=False).status,
                         STATUS_INCONCLUSIVE)
        old = TargetABI.from_dict({**real.to_dict(), "libc_version": "2.23"})
        self.assertEqual(HeapWalker(LocalTargetAdapter(), pid, abi=old).walk().status, STATUS_UNSUPPORTED_GLIBC_VERSION)
        # version not known from files (e.g. remote target): recovered from the libc banner in target memory
        unknown_ver = TargetABI.from_dict({**real.to_dict(), "libc_version": None})
        w = HeapWalker(LocalTargetAdapter(), pid, abi=unknown_ver, force_signature_scan=True).walk()
        self.assertEqual(w.status, STATUS_OK, w.message)
        self.assertEqual(w.abi["libc_version"], "%d.%d" % parse_glibc_version(real.libc_version))
        # ... and refused as inconclusive when no libc mapping is identifiable to read it from
        no_libc = TargetABI.from_dict({**real.to_dict(), "libc_version": None, "libc_path": None})
        self.assertEqual(HeapWalker(LocalTargetAdapter(), pid, abi=no_libc).walk().status, STATUS_INCONCLUSIVE)

    def test_mcp_tools(self):
        import scripts.mcp_server as mcp_srv
        f = [f for f in self.gt["BLOCK"] if f[3] == "g_cache.entries[3].data"][0]
        leak = self.gt["LEAK"][0]
        out = json.loads(mcp_srv.runtime_heap_owner_lookup(addresses="%s,%s" % (f[1], leak[1]),
                                                            pid=self.proc.pid, companion_elf=self.binary))
        self.assertTrue(out["success"], out)
        r0, r1 = out["results"]
        self.assertIn("g_cache.entries[3].data", [x.get("path") for x in r0["referrers"]])
        self.assertTrue(r1["leak_candidate"])
        aid = out["analysis_id"]
        self.assertIsNotNone(get_cached_analysis(aid))
        out2 = json.loads(mcp_srv.runtime_heap_leak_candidates(analysis_id=aid))
        self.assertTrue(out2["success"], out2)
        listed = {e["user_address"] for g in out2["by_size_class"] for e in g["examples"]}
        self.assertIn("0x%x" % int(leak[1], 16), listed)


class TestLayoutTable(unittest.TestCase):
    def test_supported_version_range_and_layout_switches(self):
        from extractor.heap_walker import layout_for_version, parse_glibc_version
        self.assertEqual(parse_glibc_version("2.39"), (2, 39))
        self.assertEqual(parse_glibc_version("2.35.1"), (2, 35))
        self.assertIsNone(parse_glibc_version(None))
        self.assertIsNone(layout_for_version((2, 26)))
        self.assertIsNone(layout_for_version((2, 42)))
        l27, l30, l32, l35 = (layout_for_version(v) for v in ((2, 27), (2, 30), (2, 32), (2, 35)))
        self.assertEqual((l27.tcache_count_width, l27.safe_linking, l27.tcache_chunk_size), (1, False, 0x250))
        self.assertEqual((l30.tcache_count_width, l30.safe_linking, l30.tcache_chunk_size), (2, False, 0x290))
        self.assertTrue(l32.safe_linking)
        self.assertEqual((l32.heap_info_size, l35.heap_info_size), (32, 48))
        self.assertEqual(l35.ms["top"], 96)
        self.assertEqual(l35.ms["next"], 2160)
        self.assertEqual(l35.bin_at(0x1000, 1), 0x1000 + 112 - 16)


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestHeapWalkTornReads(unittest.TestCase):
    """The target runs while it is read: torn headers are retried, then reported, never crash/loop."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp007t_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.binary = _compile("proc_heap_ownership.c", os.path.join(cls.tmp, "proc_heap_ownership"))
        cls.proc, _ = _launch(cls, cls.binary)
        cls.addClassCleanup(_kill, cls.proc)
        cls.clean = HeapWalker(LocalTargetAdapter(), cls.proc.pid, force_signature_scan=True).walk()

    def _corrupting_adapter(self, times):
        heap = [m for m in LocalTargetAdapter().get_proc_maps(self.proc.pid) if m.get("pathname") == "[heap]"][0]
        victim = heap["start_int"] + 0x2000          # some chunk-ish offset inside the brk heap
        state = {"left": times}

        class Corrupting(LocalTargetAdapter):
            def read_memory_batch(self, pid, slices):
                out = super().read_memory_batch(pid, slices)
                res = []
                for (a, n), (data, st, err) in zip(slices, out):
                    if data and state["left"] > 0 and a <= victim < a + len(data) - 64:
                        # find the chunk header covering the victim offset and garble its size field
                        b = bytearray(data)
                        off = victim - a
                        b[off:off + 64] = b"\xff\x13" * 32
                        data = bytes(b)
                        state["left"] -= 1
                    res.append((data, st, err))
                return res
        return Corrupting()

    def test_transient_tear_is_retried(self):
        w = HeapWalker(self._corrupting_adapter(times=1), self.proc.pid, force_signature_scan=True)
        r = w.walk()
        self.assertEqual(r.status, STATUS_OK, r.inconsistencies)
        self.assertEqual(r.counts(), self.clean.counts())

    def test_persistent_tear_marks_region_inconsistent(self):
        w = HeapWalker(self._corrupting_adapter(times=1000), self.proc.pid, force_signature_scan=True)
        t0 = time.monotonic()
        r = w.walk()
        self.assertLess(time.monotonic() - t0, 30.0)
        self.assertEqual(r.status, STATUS_PARTIAL)
        self.assertTrue(r.inconsistencies)
        inc = r.inconsistencies[0]
        self.assertGreater(inc["unwalked_bytes"], 0)
        self.assertEqual(inc["retries"], w.max_retries)
        # chunks before the torn region are still reported
        self.assertGreater(r.counts()["chunks"], 10)

    def test_live_concurrent_churn_is_bounded_and_never_crashes(self):
        """Two threads malloc/free continuously while the heap is walked: every walk terminates with
        OK or PARTIAL (inconsistent regions reported), and the stable blocks before any torn region are
        found with their owner."""
        binary = _compile("proc_heap_churn.c", os.path.join(self.tmp, "proc_heap_churn"))
        proc, lines = _launch(self, binary)
        self.addCleanup(_kill, proc)
        stable = _parse(lines)["BLOCK"]
        statuses = []
        found = 0
        for _ in range(5):
            t0 = time.monotonic()
            an = analyze_heap_ownership(proc.pid, binary, force_signature_scan=True, cache=False,
                                        include_typed_locals=False)
            self.assertLess(time.monotonic() - t0, 60.0)
            statuses.append(an.status)
            self.assertIn(an.status, (STATUS_OK, STATUS_PARTIAL), an.message)
            if an.ok:
                for _, addr, _size, path in stable:
                    r = an.lookup(int(addr, 16))
                    if r.get("status") == "FOUND" and path in [x.get("path") for x in r["referrers"]]:
                        found += 1
        sys.stderr.write("\nIMP-007 churn walks: statuses=%s stable-owner hits=%d/%d\n"
                         % (statuses, found, 5 * len(stable)))
        self.assertGreater(found, 0)

    def test_random_garbage_heap_never_crashes(self):
        import random
        rnd = random.Random(7)

        class Garbage(LocalTargetAdapter):
            def read_memory_batch(self, pid, slices):
                out = super().read_memory_batch(pid, slices)
                return [((bytes(rnd.getrandbits(8) for _ in range(len(d))) if d and len(d) > 4096 else d), s, e)
                        for (d, s, e) in out]
        r = HeapWalker(Garbage(), self.proc.pid, force_signature_scan=True).walk()
        self.assertIn(r.status, (STATUS_OK, STATUS_PARTIAL, "ARENA_NOT_FOUND"))


@unittest.skipUnless(shutil.which("g++"), "g++ not available: cannot compile the C++ fixture")
class TestHeapOwnershipCpp(unittest.TestCase):
    def test_ac4_cpp_objects_without_virtual_functions(self):
        tmp = tempfile.mkdtemp(prefix="imp007c_")
        self.addCleanup(shutil.rmtree, tmp, True)
        binary = _compile("proc_heap_ownership_cpp.cpp", os.path.join(tmp, "proc_heap_ownership_cpp"), cxx=True)
        proc, lines = _launch(self, binary)
        self.addCleanup(_kill, proc)
        gt = _parse(lines)
        an = analyze_heap_ownership(proc.pid, binary, manager=WatchSessionManager(corpus_dir=os.path.join(tmp, "c")))
        self.assertEqual(an.status, STATUS_OK, an.message)
        self.assertGreaterEqual(len(gt["BLOCK"]), 15)
        for _, addr, size, path in gt["BLOCK"]:
            r = an.lookup(int(addr, 16))
            self.assertGreaterEqual(r["chunk"]["usable_size"], int(size))
            self.assertIn(path, [x.get("path") for x in r["referrers"]], (path, r["referrers"]))
        cands = set(an.leak_candidate_addresses())
        self.assertFalse(cands & {int(f[1], 16) for f in gt["BLOCK"]})


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestHeapOwnershipRefusals(unittest.TestCase):
    def test_ac5_interposed_allocator_is_refused(self):
        tmp = tempfile.mkdtemp(prefix="imp007r_")
        self.addCleanup(shutil.rmtree, tmp, True)
        binary = _compile("proc_heap_custom_allocator.c", os.path.join(tmp, "proc_heap_custom_allocator"))
        proc, _ = _launch(self, binary)
        self.addCleanup(_kill, proc)
        an = analyze_heap_ownership(proc.pid, binary, cache=False)
        self.assertEqual(an.status, STATUS_UNSUPPORTED_ALLOCATOR, an.message)
        self.assertIn("unsupported allocator", an.message)
        self.assertIn("interposed", an.message)
        self.assertEqual(an.lookup(0x1000)["status"], STATUS_UNSUPPORTED_ALLOCATOR)

    def test_ac5_static_binary_without_identifiable_libc_is_inconclusive(self):
        tmp = tempfile.mkdtemp(prefix="imp007s_")
        self.addCleanup(shutil.rmtree, tmp, True)
        try:
            binary = _compile("proc_heap_custom_allocator.c", os.path.join(tmp, "static_fixture"), extra=["-static"])
        except subprocess.CalledProcessError:
            self.skipTest("static libc not available")
        proc, _ = _launch(self, binary)
        self.addCleanup(_kill, proc)
        an = analyze_heap_ownership(proc.pid, binary, cache=False)
        self.assertIn(an.status, (STATUS_INCONCLUSIVE, STATUS_UNSUPPORTED_ALLOCATOR), an.message)
        self.assertFalse(an.ok)


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestHeapWalk64MBNoStop(unittest.TestCase):
    def test_ac6_64mb_heap_walk_never_stops_target(self):
        tmp = tempfile.mkdtemp(prefix="imp007b_")
        self.addCleanup(shutil.rmtree, tmp, True)
        binary = _compile("proc_heap_big.c", os.path.join(tmp, "proc_heap_big"))
        proc, lines = _launch(self, binary)
        self.addCleanup(_kill, proc)
        progress_addr = int([l for l in lines if l.startswith("PROGRESS")][0].split()[1], 16)
        live, leaked, freed, requested, _n = (int(x) for x in [l for l in lines if l.startswith("STATS")][0].split()[1:])
        self.assertGreaterEqual(requested, 64 * 1024 * 1024)
        gt_leaks = {int(l.split()[1], 16) for l in lines if l.startswith("LEAK")}
        self.assertEqual(len(gt_leaks), leaked)

        stopf = os.path.join(tmp, "stop")
        outf = os.path.join(tmp, "poll.json")
        poller = fixture_popen([sys.executable, "-c", _POLLER, str(proc.pid), stopf, outf])
        self.addCleanup(_kill, poller)
        deadline = time.monotonic() + 30
        while not os.path.exists(outf + ".ready"):
            self.assertLess(time.monotonic(), deadline, "poller did not start")
            time.sleep(0.01)

        def _progress():
            data, st, _ = read_process_memory_slice(proc.pid, progress_addr, 8)
            self.assertEqual(st, "OBSERVED")
            return struct.unpack("<Q", data)[0]

        p0 = _progress()
        t0 = time.monotonic()
        an = analyze_heap_ownership(proc.pid, binary, manager=WatchSessionManager(corpus_dir=os.path.join(tmp, "c")))
        wall = time.monotonic() - t0
        p1 = _progress()
        open(stopf, "w").close()
        poller.wait(timeout=30)
        with open(outf) as f:
            poll = json.load(f)

        s = an.summary()
        sys.stderr.write("\nIMP-007 64MB walk: wall=%.2fs heap_walk_ms=%s bytes_read=%d batches=%d polls=%d stops=%d "
                         "in_use=%s leak_candidates=%d\n" % (
                             wall, s["heap_walk"]["stats"]["wall_ms"], s["cost"]["bytes_read"],
                             s["cost"]["read_batches"], poll["polls"], len(poll["stops"]),
                             s["heap_walk"]["counts"]["by_state"].get("in_use"),
                             len(an.leak_candidate_addresses())))
        self.assertEqual(an.status, STATUS_OK, an.message)
        self.assertEqual(poll["stops"], [], "target observed stopped ('T'/'t') during the walk")
        self.assertEqual(poll["traced"], 0, "target observed traced during the walk")
        self.assertGreater(poll["polls"], 50)
        self.assertGreater(p1, p0, "target progress counter did not advance during the walk")
        self.assertEqual(s["cost"]["budget_target_stop_ms"], 0.0)
        # ground truth: every leaked block reported, no live block reported as leak
        cands = set(an.leak_candidate_addresses())
        missed = gt_leaks - cands
        self.assertEqual(
            missed, set(),
            "leaked blocks not reported (referrers shown to tell a stale root from a walker miss): %s"
            % {hex(a): an.lookup(a) for a in sorted(missed)})
        self.assertLessEqual(len(cands - gt_leaks), 2,
                             "unexpected extra candidates: %s" % sorted(hex(a) for a in cands - gt_leaks))
        self.assertGreaterEqual(s["heap_walk"]["counts"]["by_state"].get("in_use", 0), live + leaked)
        self.assertGreaterEqual(s["heap_walk"]["counts"]["in_use_chunk_bytes"], 60 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
