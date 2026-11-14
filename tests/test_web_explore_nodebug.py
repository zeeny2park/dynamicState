"""Process exploration against a target WITHOUT debug information (stripped, and compiled without -g).

End to end: a real fixture process, a diagnosis job started through ``POST /api/diagnose/start``, every exploration route.
* routes that need DWARF (vars, value, lock, range by expression, watch of an expression or a pool) answer ``409
  NO_DEBUG_INFO`` with a ko/en fragment that says so (not an empty success, not "symbol not found", not a 500);
* routes that do not (chips, thread, threads, maps, range by address, files, modules, watch of an address) still work.

Run: python3 -m unittest tests.test_web_explore_nodebug
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from tests.support.explore_e2e import FIX, UNSAFE, Client, build, tids
from tests.support.fixture_process import fixture_popen

NODBG_KO = "디버그 정보가 없습니다"
NODBG_EN = "No debug information for this target"


class NoDebugCase:
    """Mixin: ``self.variant`` selects the fixture build; the tests below run once per variant."""
    variant = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ds_nodbg_")
        src = os.path.join(FIX, "slot_server.c")
        if cls.variant == "stripped":
            cls.binary = build(cls.tmp, src, "slot_stripped", flags=("-O0",), strip=True)
        else:                                            # no -g, symbols kept
            cls.binary = build(cls.tmp, src, "slot_nog", flags=("-O0",))
        cls.proc = fixture_popen([cls.binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, name="slot_nodebug")
        if b"READY" not in cls.proc.stdout.readline():
            cls.proc.kill_tree()
            raise RuntimeError("fixture did not start")
        cls.c = Client(os.path.join(cls.tmp, "corpus"))
        cls.jid, cls.status = cls.c.diagnose(cls.proc.pid, cls.binary if cls.variant == "stripped" else None)

    @classmethod
    def tearDownClass(cls):
        cls.c.close()
        cls.proc.kill_tree()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def text(self, r, lang):
        return re.sub(r"<[^>]+>", " ", r["html"][lang])

    def assertNoDebug(self, st, r):
        self.assertEqual(st, 409, r)
        self.assertEqual(r["error"]["code"], "NO_DEBUG_INFO")
        self.assertIn(NODBG_EN, self.text(r, "en"))
        self.assertIn(NODBG_KO, self.text(r, "ko"))
        for lang in ("ko", "en"):
            self.assertIsNone(UNSAFE.search(r["html"][lang]))

    def test_job_finished_and_has_no_dwarf(self):
        self.assertEqual(self.status["job"]["state"], "done", self.status)

    def test_routes_that_need_dwarf_say_so(self):
        c, j = self.c, self.jid
        for path in ("vars?q=g_", "value?expr=g_ticks", "value?expr=g_slots", "lock?name=g_mutex", "memory/range?expr=g_last&len=16"):
            st, r = c.get(j, path)
            self.assertNoDebug(st, r)
        for body in ({"items": [{"expr": "g_ticks"}]}, {"pool": {"expr": "g_slots"}}):
            st, r = c.post(j, "watch", body)
            self.assertNoDebug(st, r)
        st, r = c.get(j, "watch/status")                      # nothing was configured by the refused requests
        w = r["watch"] or {}
        self.assertEqual((st, w.get("pool")), (200, None), r)
        self.assertEqual([i for i in w.get("items") or [] if i["id"].startswith("e:")], [], r)

    def test_routes_that_do_not_need_dwarf_work(self):
        c, j, pid = self.c, self.jid, self.proc.pid
        st, r = c.get(j, "chips")
        self.assertEqual(st, 200, r)
        tid = [t for t in tids(pid) if open(f"/proc/{pid}/task/{t}/comm").read().strip() == "slot_churn"][0]
        st, r = c.get(j, f"thread/{tid}")
        self.assertEqual(st, 200, r)
        self.assertGreaterEqual(len(r["data"]["frames"]), 3)
        self.assertEqual(r["data"]["name"], "slot_churn")
        self.assertIn("without debug info the frame layout is unknown", self.text(r, "en"))
        self.assertIn("디버그 정보가 없어 프레임 배치를 모릅니다", self.text(r, "ko"))
        st, r = c.get(j, "threads?name=slot_churn")
        self.assertEqual((st, r["data"]["count"]), (200, 1), r)
        st, r = c.get(j, "memory/maps")
        self.assertEqual(st, 200, r)
        self.assertGreater(r["data"]["count"], 5)
        st, r = c.get(j, "files")
        self.assertEqual(st, 200, r)
        self.assertGreaterEqual(r["data"]["total"], 3)
        st, r = c.get(j, "modules")
        self.assertEqual(st, 200, r)
        en = self.text(r, "en")
        self.assertIn(os.path.basename(self.binary), en)
        self.assertRegex(en, r"debug info\s+" + re.escape(os.path.basename(self.binary)) + r".*?\bnone\b")
        # a raw read by address: the first page of the executable is its ELF header
        with open(f"/proc/{pid}/maps") as fh:
            first = next(ln for ln in fh if ln.rstrip().endswith(os.path.basename(self.binary)))
        addr = "0x" + first.split("-", 1)[0]
        st, r = c.get(j, f"memory/range?addr={addr}&len=16")
        self.assertEqual(st, 200, r)
        self.assertEqual(r["data"]["status"], "OBSERVED", r)
        self.assertRegex(self.text(r, "en").lower(), r"7f\s+45\s+4c\s+46")
        # observing a raw address needs no DWARF
        st, r = c.post(j, "watch", {"items": [{"addr": addr, "type": "u32"}], "interval_s": 0.5})
        self.assertEqual(st, 200, r)
        try:
            w = c.wait_samples(j, 2)
            self.assertGreaterEqual(w.get("samples", 0), 2, w)
            self.assertEqual(w["items"][0]["value"], 0x464c457f)
        finally:
            c.post(j, "watch/stop", {})

    def test_unknown_things_are_still_plain_errors(self):
        c, j = self.c, self.jid
        self.assertEqual(c.get(j, "thread/999999")[0], 404)
        self.assertEqual(c.get(j, "memory/range?addr=0x10&len=4")[0], 200)   # unmapped: answered as UNAVAILABLE, not a 5xx


class TestStripped(NoDebugCase, unittest.TestCase):
    variant = "stripped"


class TestNoGFlag(NoDebugCase, unittest.TestCase):
    variant = "nog"


if __name__ == "__main__":
    unittest.main()
