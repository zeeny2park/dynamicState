"""Roadmap stage 3: libstdc++ containers in the default diagnosis (extractor.cpp_containers).

 a. every container kind of the fixture decodes through the target adapter to its ground truth (sizes, counts,
    pointee), and only after its invariants were checked;
 b. corrupted / implausible headers are NOT decoded (begin > end, length > capacity, a tree whose root does not link
    back, counts beyond writable memory, a libc++ or old-ABI layout) - the result says why and carries no value;
 c. reachability paths through the library's private members are rewritten to the container;
 d. a growing std::vector / std::map owner: the MEMORY_LEAK finding names the container variable and the report
    states its element count and growth across the heap walks; a growing std::string (one block) is reported as a
    container observation, never as a finding of its own;
 e. the heap-owner lookup of an element block names the container.
"""

import os
import select
import shutil
import struct
import subprocess
import tempfile
import time
import unittest

from extractor import cpp_containers as cc
from extractor.dwarf_indexer import DwarfIndexer
from extractor.target_adapter import LocalTargetAdapter
from tests.support.fixture_process import fixture_popen

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_runtime",
                       "proc_cpp_container_leak.cpp")
READY_TIMEOUT_S = 60.0
MEMORY_SYMPTOM = "memory usage of this process keeps growing"


def _gt(buf: bytes):
    gt = {}
    for line in buf.decode().splitlines():
        if line.startswith("GT "):
            for kv in line[3:].split():
                k, v = kv.split("=", 1)
                gt[k] = v
    return gt


@unittest.skipUnless(shutil.which("g++"), "g++ not available: cannot compile the C++ fixture")
class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="stage3_cpp_")
        cls.binary = os.path.join(cls.tmp, "proc_cpp_container_leak")
        subprocess.run(["g++", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", FIXTURE, "-o", cls.binary],
                       check=True, capture_output=True, timeout=180)
        cls.idx = DwarfIndexer.get_index(cls.binary)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def launch(self, mode):
        proc = fixture_popen([self.binary, mode], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL)
        self.addCleanup(self._kill, proc)
        buf = b""
        deadline = time.monotonic() + READY_TIMEOUT_S
        while b"READY" not in buf:
            if time.monotonic() > deadline or proc.poll() is not None:
                self.fail("fixture %s did not reach READY" % mode)
            r, _, _ = select.select([proc.stdout], [], [], 0.2)
            if r:
                buf += os.read(proc.stdout.fileno(), 4096)
        return proc, _gt(buf)

    @staticmethod
    def _kill(proc):
        try:
            proc.kill()
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            pass
        if proc.stdout:
            proc.stdout.close()

    def paths_for(self, pid, adapter):
        maps = adapter.get_proc_maps(pid)
        exe = os.path.realpath(self.binary)
        bias = next(int(m["start_int"]) - int(str(m.get("offset") or "0"), 16) for m in maps
                    if os.path.realpath(m.get("pathname") or "") == exe)
        return cc.ContainerPaths([("proc_cpp_container_leak", self.idx, bias, True)]), maps

    def layout(self, name):
        v = next(v for v in self.idx.global_variables if v.name == name)
        return cc.classify(self.idx, v.type_offset)


class TestDecodeLiveProcess(_Base):
    def test_a_every_kind_decodes_to_ground_truth_through_the_adapter(self):
        proc, gt = self.launch("static")
        ad = LocalTargetAdapter()
        cp, maps = self.paths_for(proc.pid, ad)

        def dec(name):
            ref = cp.at_variable(None, name)
            self.assertIsNotNone(ref, name)
            d = cc.decode(ref.layout, ref.address, cc.ContainerMemory.from_adapter(ad, proc.pid, maps))
            self.assertTrue(d["decoded"], (name, d))
            self.assertTrue(d.get("checks"), name)
            return d

        for name, kind in (("g_index", cc.K_UMAP), ("g_backlog", cc.K_DEQUE), ("g_history", cc.K_LIST),
                           ("g_ids", cc.K_SET)):
            d = dec(name)
            self.assertEqual(d["kind"], kind)
            self.assertEqual(d["size"], int(gt[name]), name)
        self.assertEqual(dec("g_registry")["size"], 0)
        self.assertEqual(dec("g_sessions")["size"], 0)
        s = dec("g_short_name")
        self.assertEqual((s["size"], s["inline"]), (int(gt["g_short_name"]), True))
        s = dec("g_long_name")
        self.assertEqual((s["size"], s["capacity"], s["inline"]),
                         (int(gt["g_long_name"]), int(gt["g_long_name_cap"]), False))
        for name in ("g_settings", "g_settings_alias", "g_settings_observer"):
            d = dec(name)
            self.assertEqual(d["use_count"], int(gt["g_settings_use"]), name)
            self.assertEqual(d["weak_count"], 1, name)          # one weak_ptr (the libstdc++ +1 is not shown)
            self.assertEqual(int(d["pointee"]["address"], 16), int(gt["g_settings_ptr"], 16))
        d = dec("g_owner")
        self.assertEqual(int(d["pointee"]["address"], 16), int(gt["g_owner_ptr"], 16))
        self.assertIn("std::vector<Record*>", cc.text(dec("g_registry")))

    def test_e_heap_owner_lookup_names_the_container(self):
        from extractor.reachability import analyze_heap_ownership
        proc, _gt_ = self.launch("vector")
        an = analyze_heap_ownership(proc.pid, companion_elf_path=self.binary, adapter=LocalTargetAdapter(),
                                    cache=False, include_typed_locals=False, use_libc_debug_info=False)
        self.assertTrue(an.ok, an.message)
        cp = cc.ContainerPaths(an.analyzer.modules)
        ref = cp.at_variable(None, "g_registry")
        hdr = an.reader.read_ranges([(ref.address, 24)])[0]
        storage = struct.unpack_from("<Q", hdr, 0)[0]
        first = struct.unpack_from("<Q", an.reader.read_ranges([(storage, 8)])[0], 0)[0]
        res = an.lookup(first)
        oc = res.get("owner_container")
        self.assertIsNotNone(oc, res)
        self.assertEqual((oc["path"], oc["kind"], oc["readable_path"]), ("g_registry", cc.K_VECTOR, "g_registry[*]"))
        self.assertTrue(oc["decoded"], oc)
        self.assertGreater(oc["size"], 0)


class _FakeMem(cc.ContainerMemory):
    """Memory made of given byte ranges, one big writable mapping."""

    def __init__(self, blobs, lo=0x10000, hi=0x7fff0000):
        self.blobs = blobs

        def rr(ranges):
            out = []
            for a, n in ranges:
                hit = None
                for base, data in blobs.items():
                    if base <= a and a + n <= base + len(data):
                        hit = data[a - base:a - base + n]
                out.append(hit)
            return out
        super().__init__(rr, [{"start_int": lo, "end_int": hi, "permissions": "rw-p", "pathname": ""}])


class TestRejection(_Base):
    def _vec(self, b, e, c):
        lay = self.layout("g_registry")
        return cc.decode(lay, 0x20000, _FakeMem({0x20000: struct.pack("<QQQ", b, e, c)}))

    def test_b_vector_invariants(self):
        ok = self._vec(0x30000, 0x30010, 0x30020)
        self.assertTrue(ok["decoded"])
        self.assertEqual((ok["size"], ok["capacity"]), (2, 4))
        for args, why in (((0x30010, 0x30000, 0x30020), "begin <= end"), ((0x30000, 0x30030, 0x30020), "begin <= end"),
                          ((0x30000, 0x30004, 0x30020), "multiple"), ((0x30000, 0x30010, 0x7fff0010), "writable")):
            d = self._vec(*args)
            self.assertFalse(d["decoded"], args)
            self.assertIn(why, d["reason"])
            self.assertNotIn("size", d)

    def test_b_string_and_tree_and_list_invariants(self):
        lay = self.layout("g_journal")
        a = 0x20000
        bad = cc.decode(lay, a, _FakeMem({a: struct.pack("<QQQQ", 0x30000, 500, 100, 0), 0x30000: b"x" * 600}))
        self.assertFalse(bad["decoded"])
        self.assertIn("capacity", bad["reason"])
        sso = cc.decode(lay, a, _FakeMem({a: struct.pack("<QQ", a + 16, 40) + b"\0" * 16}))
        self.assertFalse(sso["decoded"])
        # tree: the root does not link back to the header
        lay = self.layout("g_ids")
        H = a + lay.off["_M_header"]
        hdr = bytearray(48)
        struct.pack_into("<QQQ", hdr, lay.off["_M_header"] + 8, 0x30000, 0x30000, 0x30000)
        struct.pack_into("<Q", hdr, lay.off["_M_node_count"], 1)
        node = struct.pack("<QQQQ", 0, 0x40000, 0, 0)
        d = cc.decode(lay, a, _FakeMem({a: bytes(hdr), 0x30000: node + b"\0" * 32}))
        self.assertFalse(d["decoded"])
        self.assertIn("root", d["reason"])
        good = struct.pack("<QQQQ", 0, H, 0, 0)
        self.assertTrue(cc.decode(lay, a, _FakeMem({a: bytes(hdr), 0x30000: good + b"\0" * 32}))["decoded"])
        struct.pack_into("<Q", hdr, lay.off["_M_node_count"], 1 << 40)
        d = cc.decode(lay, a, _FakeMem({a: bytes(hdr), 0x30000: good + b"\0" * 32}))
        self.assertFalse(d["decoded"])
        self.assertIn("implausible", d["reason"])
        # list: empty list whose sentinel does not point to itself
        lay = self.layout("g_history")
        d = cc.decode(lay, a, _FakeMem({a: struct.pack("<QQQ", 0x30000, 0x30000, 0)}))
        self.assertFalse(d["decoded"])

    def test_b_shared_ptr_counts(self):
        lay = self.layout("g_settings")
        a = 0x20000
        blobs = {a: struct.pack("<QQ", 0x30010, 0x30000), 0x30000: struct.pack("<Qii", 0x50000, 0, 1)}
        d = cc.decode(lay, a, _FakeMem(blobs))
        self.assertFalse(d["decoded"])               # a live shared_ptr with use_count 0
        self.assertIn("use >= 1", d["reason"])

    def test_b_foreign_layouts_are_not_decoded(self):
        class T:
            def __init__(self, name, members=(), size=24):
                self.tag, self.name, self.byte_size, self.members, self.base_classes = \
                    "DW_TAG_class_type", name, size, list(members), []
                self.die_offset, self.target_type_offset = 1, None

        class Idx:
            pointer_size = 8

            def __init__(self, t):
                self.t = t

            def resolve_canonical_type(self, off):
                return self.t if off == 1 else None

        lay = cc.classify(Idx(T("vector<int, std::__1::allocator<int> >")), 1)
        self.assertIn("libc++", lay.unsupported)
        lay = cc.classify(Idx(T("vector<int, std::allocator<int> >")), 1)       # no _M_start members
        self.assertTrue(lay.unsupported)
        d = cc.decode(lay, 0x20000, _FakeMem({}))
        self.assertFalse(d["decoded"])
        self.assertIsNone(cc.classify(Idx(T("Registry")), 1))


class TestPaths(_Base):
    def test_c_private_member_paths_name_the_container(self):
        cp = cc.ContainerPaths([("m", self.idx, 0, True)])
        cases = {
            "g_registry._M_impl._M_start[*]": "g_registry[*]",
            "g_registry._M_impl._M_start[3]->payload": "g_registry[*]->payload",
            "g_registry._M_impl._M_start": "g_registry",
            "g_sessions._M_t._M_impl._M_header._M_parent([*]._M_right)*([*]._M_left)*": "g_sessions[*]",
            "g_index._M_h._M_buckets[*]": "g_index[*]",
            "g_index._M_h._M_buckets": "g_index",
            "g_backlog._M_impl._M_map[*]": "g_backlog",
            "g_history._M_impl._M_node._M_next(->_M_next)*": "g_history[*]",
            "g_owner._M_t._M_t._M_head_impl": "g_owner",
            "g_settings._M_refcount._M_pi": "g_settings",
            "g_journal._M_dataplus._M_p": "g_journal",
        }
        for raw, want in cases.items():
            hit = cp.resolve("m", raw)
            self.assertIsNotNone(hit, raw)
            self.assertEqual(hit[1], want, raw)
        self.assertIsNone(cp.resolve("m", "g_count"))
        self.assertIsNone(cp.resolve("m", "g_registry"))       # the container itself is not a private path


class TestLeakFinding(_Base):
    def _diagnose(self, pid):
        from extractor.expert_diagnostic_engine import diagnose
        r = diagnose(pid, self.binary, MEMORY_SYMPTOM, corpus_dir=os.path.join(self.tmp, "corpus"),
                     include_report=True).to_dict()
        li = next((c.get("actual_observations") or {}).get("leak_investigation")
                  for c in r["report"]["section_d_detailed_inspection_results"]["checks"]
                  if c["recipe_id"] == "RECIPE_PROCESS_MEMORY_GROWTH")
        return r, li

    def _assert_container_leak(self, mode, var, kind):
        from extractor.human_report import render_human_report
        proc, gt = self.launch(mode)
        r, li = self._diagnose(proc.pid)
        leaks = [f for f in r["findings"] if f["category"] == "MEMORY_LEAK"]
        self.assertEqual(len(leaks), 1, r["findings"])
        self.assertIn(var, leaks[0]["subjects"])
        self.assertIn(var + "[*]", leaks[0]["subjects"])
        self.assertFalse(any("._M_" in s for s in leaks[0]["subjects"]), leaks[0]["subjects"])
        self.assertIn(gt["thread"], leaks[0]["subjects"])
        row = next(o for o in li["growth_owners"] if o["variable"] == var)
        c = row["container"]
        self.assertEqual((c["path"], c["kind"]), (var, kind))
        self.assertTrue(c["decoded"], c)
        self.assertGreaterEqual(c["walks_decoded"], 2, c)
        self.assertGreater(c["size_last"], 300)
        self.assertGreater(c["size_delta"], 0)
        decoded = [x for x in c["size_series"] if x is not None]
        self.assertEqual(decoded, sorted(decoded))
        # the relation model of the finding (extractor.object_relations): blocks <- variable <- thread
        chain = next(ch for ch in leaks[0]["object_relations"]["chains"]
                     if any(n["role"] == "variable" and n.get("name") == var + "[*]" for n in ch["nodes"]))
        how = {x["target"]: x["how"] for x in chain["links"]}
        self.assertEqual((how["v"], how["t"]), ("typed_pointer_path", "arena_attribution"))
        self.assertEqual(next(n for n in chain["nodes"] if n["role"] == "thread")["name"], gt["thread"])
        for lang, unit in (("en", "elements"), ("ko", "원소")):
            md = render_human_report(r, lang=lang)
            self.assertIn("`%s`" % c["type"], md)
            self.assertIn(unit, md)
            self.assertIn(str(c["size_last"]), md)
        return r, li

    def test_d_growing_vector(self):
        r, li = self._assert_container_leak("vector", "g_registry", cc.K_VECTOR)
        self.assertGreaterEqual(li["growth_owners"][0]["container"]["capacity"],
                                li["growth_owners"][0]["container"]["size_last"])

    def test_d_growing_map(self):
        self._assert_container_leak("map", "g_sessions", cc.K_MAP)

    def test_d_growing_string_is_an_observation_not_a_finding(self):
        proc, _gt_ = self.launch("string")
        r, li = self._diagnose(proc.pid)
        self.assertFalse([f for f in r["findings"] if "g_journal" in (f.get("subjects") or [])])
        obs = {o["variable"]: o for o in li.get("container_observations") or []}
        self.assertIn("g_journal", obs, li.get("container_observations"))
        o = obs["g_journal"]
        self.assertEqual(o["kind"], cc.K_STRING)
        self.assertGreater(o["size_delta"], 0)
        self.assertGreaterEqual(o["capacity"], o["size_last"])


@unittest.skipUnless(shutil.which("make") and shutil.which("gcc"), "make/gcc needed for the native collector")
class TestRemoteTarget(_Base):
    """The same decode through the remote adapter (native collector behind a local ``sh`` transport, as in
    tests/test_imp006_remote_diagnose.py): no local /proc read of the target is needed for it."""

    def test_d_remote_vector_owner_is_decoded(self):
        from extractor.expert_diagnostic_engine import TargetSpec, diagnose
        from tests.test_imp006_remote_diagnose import COLLECTOR_SRC, local_sh_runner, local_sh_stream
        build = os.path.join(self.tmp, "collector")
        if not os.path.isdir(build):
            shutil.copytree(COLLECTOR_SRC, build,
                            ignore=shutil.ignore_patterns("*.o", "dist", "dynamicstate-collector", "test_crypto"))
        r = subprocess.run(["make", "-C", build, "dynamicstate-collector"], capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest("native collector build failed: " + r.stderr[-300:])
        spec = TargetSpec(remote_host="board.example", ssh_user="root",
                          collector_path=os.path.join(build, "dynamicstate-collector"),
                          command_runner=local_sh_runner, stream_opener=local_sh_stream)
        proc, gt = self.launch("vector")
        res = diagnose(proc.pid, self.binary, MEMORY_SYMPTOM, corpus_dir=os.path.join(self.tmp, "corpus_r"),
                       include_report=True, target=spec).to_dict()
        leaks = [f for f in res["findings"] if f["category"] == "MEMORY_LEAK"]
        self.assertEqual(len(leaks), 1, res["findings"])
        self.assertIn("g_registry[*]", leaks[0]["subjects"])
        li = next((c.get("actual_observations") or {}).get("leak_investigation")
                  for c in res["report"]["section_d_detailed_inspection_results"]["checks"]
                  if c["recipe_id"] == "RECIPE_PROCESS_MEMORY_GROWTH")
        c = next(o for o in li["growth_owners"] if o["variable"] == "g_registry")["container"]
        self.assertTrue(c["decoded"], c)
        self.assertGreater(c["size_last"], 300)


if __name__ == "__main__":
    unittest.main()
