"""End-to-End Real C++ Target Investigation Fixture Test.

Tests acceptance criterion 10:
10. A small end-to-end fixture using a real C/C++ sample binary and matching debug information,
    where the existing toolchain permits it.
"""

import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

from extractor.capture_backend import ProcessVmCaptureBackend, ProcfsCaptureBackend
from extractor.debug_image import inspect_elf
from extractor.investigation import InvestigationManager
from extractor.raw_snapshot import RawRuntimeSnapshot
from extractor.static_analyzer import DwarfStaticAnalysisProvider


class TestInvestigationE2EFixture(unittest.TestCase):
    """End-to-end integration test of investigation pipeline on a real compiled C++ process."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_e2e_inv_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        cls.fixture_src = os.path.abspath("tests/fixtures/real_runtime/main.cpp")

        # Compile unstripped debug artifact with DWARF symbols & GNU build-id
        cls.debug_bin = os.path.join(cls.work_dir, "app_debug.elf")
        cmd_debug = [
            "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
            "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin, "-lpthread"
        ]
        subprocess.run(cmd_debug, check=True)

        # Extract stripped production binary
        cls.stripped_bin = os.path.join(cls.work_dir, "app_prod.stripped")
        subprocess.run(["strip", "-s", "-o", cls.stripped_bin, cls.debug_bin], check=True)

        cls.mgr = InvestigationManager(corpus_dir=cls.corpus_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def _start_target_process(self):
        proc = subprocess.Popen(
            [self.stripped_bin],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        line = proc.stdout.readline().strip()
        self.assertEqual(line, "READY", f"Process failed to report READY: {line}")
        return proc

    def _stop_target_process(self, proc):
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()

    def test_e2e_real_binary_investigation_and_comparison(self):
        """Run full investigation pipeline against a real multithreaded C++ process."""
        proc = self._start_target_process()
        try:
            # 1. Capture first runtime memory snapshot (procfs fallback if process_vm_readv restricted)
            backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()
            snap1 = backend.capture(pid=proc.pid)
            self.assertGreater(snap1.bytes_captured, 0)

            # Save snapshot to corpus
            snap1_dir = os.path.join(self.corpus_dir, "memory_snapshots", "snap_e2e_01")
            snap1.save(snap1_dir)

            # Let process execute and increment heartbeats
            time.sleep(0.08)

            # Capture second snapshot for observation comparison
            snap2 = backend.capture(pid=proc.pid)
            snap2_dir = os.path.join(self.corpus_dir, "memory_snapshots", "snap_e2e_02")
            snap2.save(snap2_dir)

        finally:
            self._stop_target_process(proc)

        # 2. Start offline investigation from first raw snapshot
        session_info = self.mgr.start_investigation(
            goal="Investigate worker runtime state and heartbeats",
            memory_snapshot_path=snap1_dir,
            debug_image=self.debug_bin,
            budgets={"max_objects": 50, "timeout_ms": 5000},
            authorize_target=False,  # strictly read-only offline analysis
        )
        inv_id = session_info["investigation_id"]
        self.assertIn("inv_", inv_id)

        # 3. Verify Target Identity Stage
        id_stage = session_info["stages"]["target_identity"]
        self.assertEqual(id_stage["status"], "COMPLETED")
        self.assertEqual(id_stage["details"]["build_id_status"], "VERIFIED")
        self.assertIsNotNone(id_stage["details"]["target_build_id"])
        self.assertEqual(
            id_stage["details"]["target_build_id"],
            id_stage["details"]["debug_build_id"]
        )

        # 4. Verify Capture Quality Stage
        cq_stage = session_info["stages"]["capture_quality"]
        self.assertEqual(cq_stage["status"], "COMPLETED")
        self.assertIn(cq_stage["details"]["consistency_level"], ("NON_ATOMIC", "STOPPED"))
        self.assertEqual(cq_stage["details"]["failed_reads"], 0)

        # 5. Verify DWARF Semantic Interpretation Stage
        sem_stage = session_info["stages"]["semantic_interpretation"]
        self.assertEqual(sem_stage["status"], "COMPLETED")
        self.assertGreater(sem_stage["details"]["roots_count"], 0)
        self.assertGreater(sem_stage["details"]["objects_count"], 0)

        # 6. Verify Static Code Link Stage
        static_stage = session_info["stages"]["static_code_link"]
        self.assertIn("dwarf", static_stage["details"]["provider"])

        self.assertGreater(static_stage["details"]["linked_count"], 0)

        # 7. Verify Findings & Report Synthesis
        report = self.mgr.generate_report(inv_id)
        self.assertEqual(report["investigation_id"], inv_id)
        self.assertGreater(len(report["findings"]["observed_facts"]), 0)
        self.assertGreater(len(report["recommended_next_steps"]), 0)

        # Verify findings reference actual typed C++ paths (Worker/Session/Global)
        fact_paths = [f["c_type_path"] for f in report["findings"]["observed_facts"] if f.get("c_type_path")]
        self.assertTrue(any("worker" in p.lower() or "session" in p.lower() or "state" in p.lower() for p in fact_paths))

        # 8. Verify Provenance Chain Tracing
        first_fact = report["findings"]["observed_facts"][0]
        ev_id = first_fact["evidence_ids"][0]
        ev_data = self.mgr.get_evidence(inv_id, evidence_id=ev_id)
        self.assertIn("evidence", ev_data)
        self.assertIn("provenance_chain", ev_data)
        self.assertEqual(ev_data["evidence"]["evidence_id"], ev_id)

        # 9. Verify Cross-Observation Comparison
        cmp_res = self.mgr.compare_observations(inv_id, snap1_dir, snap2_dir)
        self.assertNotIn("error", cmp_res)
        summary = cmp_res["summary"]
        self.assertGreaterEqual(summary["value_changes"], 1)

        # Check uncertainty note presence due to low-impact zero-stop capture
        if cq_stage["details"]["consistency_level"] == "NON_ATOMIC":
            self.assertIsNotNone(cmp_res["uncertainty"])
            self.assertIn("non-atomically", cmp_res["uncertainty"])


if __name__ == "__main__":
    unittest.main()
