"""IMP-006 (thin): the single `diagnose` entry point, run against real processes.

Fixtures from tests/fixtures/real_runtime are compiled at test time and diagnosed once each.
No evidence or verdict is injected.  What `diagnose` honestly returns for the healthy fixture is
recorded, not forced.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import scripts.mcp_server as mcp_srv
from extractor.expert_diagnostic_engine import DiagnoseResult, ExpertDiagnosticEngine, diagnose
from extractor.diagnostic_verdict_aggregator import ALL_OVERALL_VERDICTS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "real_runtime")
SETTLE_S = 0.5

RESULT_KEYS = {
    "schema_version", "verdict", "confidence", "confidence_basis", "summary", "findings", "checks_run",
    "not_covered", "collection_impact", "report_path", "report", "investigation_id", "target", "state",
    "stop_reason", "duration_s",
}


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestDiagnoseEntryPoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp006_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.bins = {}
        for name in ("proc_thread_circular_deadlock", "proc_scenario_a_healthy"):
            out = os.path.join(cls.tmp, name)
            subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", os.path.join(FIXTURES, name + ".c"),
                            "-o", out, "-pthread"], check=True)
            cls.bins[name] = out
        cls.corpus = os.path.join(cls.tmp, "corpus")

    def _launch(self, name):
        proc = subprocess.Popen([self.bins[name]], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def _kill():
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()

        self.addCleanup(_kill)
        time.sleep(SETTLE_S)
        self.assertIsNone(proc.poll(), "fixture exited prematurely")
        return proc

    def _diagnose(self, pid, **kw):
        t0 = time.monotonic()
        res = diagnose(pid, corpus_dir=self.corpus, **kw)
        print(f"\n[diagnose pid={pid}] {time.monotonic() - t0:.2f}s verdict={res.verdict} "
              f"findings={[(f['category'], f['subjects']) for f in res.findings]}")
        return res

    def _assert_contract(self, res):
        self.assertIsInstance(res, DiagnoseResult)
        d = res.to_dict()
        self.assertEqual(set(d), RESULT_KEYS)
        json.dumps(d)  # JSON-serialisable
        self.assertIn(d["verdict"], ALL_OVERALL_VERDICTS)
        self.assertTrue(d["summary"])
        for key in ("pid", "process_name", "abi", "debug_image"):
            self.assertIn(key, d["target"])
        for key in ("capture_mode", "measured_stop_ms", "zero_stop"):
            self.assertIn(key, d["collection_impact"])
        for f in d["findings"]:
            self.assertTrue({"category", "severity", "subjects"} <= set(f))
        return d

    def test_deadlock_finding_names_both_locks(self):
        proc = self._launch("proc_thread_circular_deadlock")
        res = self._diagnose(proc.pid, debug_image=self.bins["proc_thread_circular_deadlock"])
        d = self._assert_contract(res)
        self.assertEqual(d["target"]["pid"], proc.pid)
        self.assertEqual(d["target"]["process_name"], "proc_thread_circular_deadlock"[:15])
        self.assertTrue(d["target"]["abi"] and d["target"]["abi"]["status"] == "DETECTED")
        dl = [f for f in d["findings"] if "DEADLOCK" in str(f["category"]).upper()]
        self.assertTrue(dl, f"no deadlock finding: {d['findings']} / {d['summary']}")
        self.assertTrue({"g_mutex_a", "g_mutex_b"} <= set(dl[0]["subjects"]), dl[0]["subjects"])
        self.assertIn(d["verdict"], ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT"))
        self.assertTrue(d["checks_run"])
        self.assertTrue(d["collection_impact"]["zero_stop"])
        self.assertEqual(d["collection_impact"]["capture_mode"], "ZERO_STOP_LIVE_RUNTIME")
        self.assertTrue(d["report_path"] and os.path.isfile(d["report_path"]))
        self.assertTrue(d["investigation_id"])

    def test_healthy_process_has_no_problem_finding(self):
        proc = self._launch("proc_scenario_a_healthy")
        res = self._diagnose(proc.pid, debug_image=self.bins["proc_scenario_a_healthy"])
        d = self._assert_contract(res)
        self.assertEqual(d["findings"], [], d["findings"])
        self.assertNotIn(d["verdict"], ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT"))
        self.assertTrue(d["checks_run"])
        self.assertTrue(d["collection_impact"]["zero_stop"])

    def test_nonexistent_pid_is_inconclusive(self):
        with open("/proc/sys/kernel/pid_max") as fh:
            dead = int(fh.read()) + 1000  # above pid_max: cannot exist
        d = self._assert_contract(self._diagnose(dead))
        self.assertEqual(d["verdict"], "INCONCLUSIVE")
        self.assertEqual(d["findings"], [])
        self.assertEqual(d["checks_run"], [])
        self.assertTrue(any("does not exist" in n["reason"] for n in d["not_covered"]), d["not_covered"])
        self.assertIsNone(d["report_path"])

    @unittest.skipIf(os.geteuid() == 0, "root can read any process")
    def test_unreadable_pid_is_inconclusive(self):
        self.assertTrue(os.path.isdir("/proc/2"), "no kernel thread PID 2")
        d = self._assert_contract(self._diagnose(2))
        self.assertEqual(d["verdict"], "INCONCLUSIVE")
        self.assertEqual(d["findings"], [])
        self.assertTrue(d["not_covered"])
        self.assertIsNone(d["report_path"])

    def test_missing_debug_image_is_inconclusive(self):
        proc = self._launch("proc_scenario_a_healthy")
        d = self._assert_contract(self._diagnose(proc.pid, debug_image=os.path.join(self.tmp, "nope.elf")))
        self.assertEqual(d["verdict"], "INCONCLUSIVE")
        self.assertTrue(any(n["kind"] == "missing_debug_image" for n in d["not_covered"]), d["not_covered"])

    def test_stage_exception_is_inconclusive_not_raised(self):
        proc = self._launch("proc_scenario_a_healthy")

        class Boom(ExpertDiagnosticEngine):
            def start_investigation(self, *a, **k):
                raise RuntimeError("boom")

        d = self._assert_contract(diagnose(proc.pid, self.bins["proc_scenario_a_healthy"],
                                           engine=Boom(corpus_dir=self.corpus)))
        self.assertEqual(d["verdict"], "INCONCLUSIVE")
        self.assertTrue(any("boom" in n["reason"] for n in d["not_covered"]))

    def test_mcp_and_cli_agree_on_same_live_target(self):
        proc = self._launch("proc_thread_circular_deadlock")
        image = self.bins["proc_thread_circular_deadlock"]
        mcp_out = json.loads(mcp_srv.runtime_diagnose_process(pid=proc.pid, debug_image=image))
        cli = subprocess.run(
            [sys.executable, "-m", "extractor.cli", "diagnose", "--pid", str(proc.pid), "--debug-image", image,
             "--corpus", self.corpus, "--json"],
            capture_output=True, text=True, cwd=ROOT, timeout=120,
        )
        self.assertEqual(cli.returncode, 0, cli.stderr)
        cli_out = json.loads(cli.stdout)
        self.assertEqual(set(mcp_out) - {"success"}, set(cli_out))
        self.assertEqual(set(cli_out), RESULT_KEYS | {"human_summary"})  # IMP-012 adds the readable summary
        self.assertEqual(mcp_out["verdict"], cli_out["verdict"])
        self.assertIn(mcp_out["verdict"], ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT"))
        plain = subprocess.run(
            [sys.executable, "-m", "extractor.cli", "diagnose", "--pid", str(proc.pid), "--debug-image", image,
             "--corpus", self.corpus],
            capture_output=True, text=True, cwd=ROOT, timeout=120,
        )
        self.assertEqual(plain.returncode, 0)
        self.assertIn(cli_out["verdict"], plain.stdout)

    def test_mcp_tool_registered_with_description(self):
        self.assertIn("runtime_diagnose_process", mcp_srv.runtime_diagnose_process.__name__)
        self.assertIn("ONE call", mcp_srv.runtime_diagnose_process.__doc__)


if __name__ == "__main__":
    unittest.main()
