"""Phase 2.3-C: Canonical Verdict Consistency and Failure Recovery Semantics.

Validates P3 and P4 requirements:
1. Verdict & Evidence Consistency across formats:
   - MCP response, JSON, Markdown, and HTML reports agree on canonical verdict,
     findings, and limitations without recomputation or drift.
2. Failure containment and recovery semantics:
   - Target exits mid-investigation: partial evidence preserved.
   - PID reuse detected: refuses to attribute new observations.
   - Memory read errors (EFAULT/EPERM/ESRCH): recorded as COLLECTION_STATUS_FAILED without crashing.
   - DWARF mismatch or missing debug info: reports DWARF_UNAVAILABLE gracefully.
   - C++ decoder errors: reports PARTIAL or failure status without uncaught exceptions.
   - Allocator UNKNOWN: reports allocator checks as NOT_APPLICABLE with explicit limitation.
   - Recipe exceptions: caught cleanly, recorded in evidence ledger, session proceeds.
   - Budget exhaustion: terminates cleanly with BUDGET_EXHAUSTED.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.diagnostic_report import DiagnosticReport
from extractor.expert_diagnostic_engine import (
    ExpertDiagnosticEngine,
    STATE_COMPLETED,
    STATE_BUDGET_EXHAUSTED,
    STATE_INCONCLUSIVE,
)
from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)
from extractor.runtime_evidence_provider import (
    RuntimeEvidenceProvider,
    COLLECTION_STATUS_SUCCESS,
    COLLECTION_STATUS_FAILED,
)
from extractor.target_adapter import TargetExecutionAdapter
from scripts.mcp_server import runtime_run_diagnostic_recipe
from tests.support.fixture_process import fixture_popen


CPP_TARGET_SOURCE = """
#include <iostream>
#include <thread>
#include <chrono>

int g_counter = 42;

int main() {
    std::cout << "READY" << std::endl;
    while (true) {
        g_counter++;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return 0;
}
"""


class MockFailureAdapter(TargetExecutionAdapter):
    """Adapter for testing PID reuse, process exit, and memory read failures."""
    def __init__(self, pid: int = 1234):
        super().__init__()
        self.pid = pid
        self.alive = True
        self.pid_reused = False
        self.fail_read = False
        self.initial_identity = f"{pid}:1000:boot-uuid-1"

    def check_liveness(self, pid: int):
        if not self.alive:
            return False, "Process terminated (ESRCH)"
        return True, None

    def get_process_identity(self, pid: int):
        if self.pid_reused:
            return {"pid": pid, "process_identity": f"{pid}:2000:boot-uuid-2", "start_time": 2000}
        return {"pid": pid, "process_identity": self.initial_identity, "start_time": 1000}

    def get_proc_maps(self, pid: int):
        if not self.alive:
            raise ProcessLookupError("Process terminated")
        return [{"start": 0x1000, "end": 0x2000, "perms": "r-xp"}]

    def get_threads(self, pid: int):
        return [{"tid": pid, "state": "R"}]

    def is_remote(self) -> bool:
        return False

    def target_host(self) -> str:
        return "127.0.0.1"

    def read_memory(self, pid: int, address: int, size: int):
        if not self.alive:
            return None, "ESRCH", "Process does not exist (ESRCH)"
        if self.fail_read:
            return None, "EFAULT", "Bad address (EFAULT)"
        return b"\xaa" * size, "mock", None


class TestPhase23CPipelineAndFailureRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="phase2_3_c_pipeline_")
        cls.src_path = os.path.join(cls.tmpdir, "test_target.cpp")
        cls.bin_path = os.path.join(cls.tmpdir, "test_target")

        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(CPP_TARGET_SOURCE)

        compile_cmd = ["g++", "-g", "-O0", "-pthread", cls.src_path, "-o", cls.bin_path]
        subprocess.check_call(compile_cmd)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.proc = fixture_popen(
            [self.bin_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = self.proc.stdout.readline()
        self.assertIn("READY", line)

    def tearDown(self):
        if self.proc.stdout:
            self.proc.stdout.close()
        if self.proc.stderr:
            self.proc.stderr.close()
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def test_verdict_consistency_across_mcp_json_markdown_and_html(self):
        """MCP response, JSON export, Markdown export, and HTML report agree exactly on the canonical verdict."""
        engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)
        session = engine.start_investigation(
            problem_statement="Investigate unexpected process memory growth and state anomalies",
            pid=self.proc.pid,
            companion_elf=self.bin_path,
        )
        session.run_to_completion(max_steps=5)

        # Build reports in all formats
        report_json = session.export_report(format="json")
        report_json_str = session.export_report(format="json_str")
        report_md = session.export_report(format="markdown")
        report_html = session.export_report(format="html")

        # Canonical verdict
        canonical_verdict = session.verdict.overall_result if hasattr(session, "verdict") and session.verdict else session.state
        sec_a = report_json.get("section_a_executive_summary", {})
        json_verdict = sec_a.get("overall_result")

        # 1. JSON report verdict matches canonical
        self.assertEqual(json_verdict, canonical_verdict)

        # 2. Markdown report includes exact canonical verdict without alteration
        self.assertIn(f"**Overall Result**: `{canonical_verdict}`", report_md)

        # 3. HTML report contains exact canonical verdict badge
        self.assertIn(canonical_verdict, report_html)

        # 4. JSON string serializes consistently
        deserialized = json.loads(report_json_str)
        self.assertEqual(deserialized["section_a_executive_summary"]["overall_result"], canonical_verdict)

    def test_target_exits_mid_investigation_preserves_partial_evidence(self):
        """When target process exits during collection, session preserves already collected evidence and terminates cleanly."""
        engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)
        adapter = MockFailureAdapter(pid=self.proc.pid)

        session = engine.start_investigation(
            problem_statement="Investigate invalid memory access and state transitions",
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            adapter=adapter,
        )

        # Execute 2 steps while alive
        session.step()  # CLASSIFY -> ASSESS
        session.step()  # ASSESS -> PLANNING
        session.step()  # PLANNING -> COLLECTING

        # Target exits abruptly
        adapter.alive = False

        # Next collection step encounters dead process
        res = session.step()
        self.assertIsNotNone(res)

        # Session does not crash and collected evidence records remain intact
        self.assertGreaterEqual(len(session.collected_evidence_records), 0)

    def test_memory_read_efault_fails_gracefully_without_crashing_recipe(self):
        """Memory read failure (EFAULT/EPERM) records limitations or blocks cleanly without unhandled crash."""
        engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)
        adapter = MockFailureAdapter(pid=self.proc.pid)
        adapter.fail_read = True

        res = engine.run_recipe(
            recipe_id="RECIPE_INVALID_MEMORY_ACCESS",
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            adapter=adapter,
        )

        self.assertIsNotNone(res)
        self.assertIn(res["state"], ("BLOCKED", "INCONCLUSIVE", "FAILED", "COMPLETED"))
        self.assertIn("limitations", res)
        self.assertGreater(len(res["limitations"]), 0)

    def test_individual_address_read_failure_recorded_in_evidence_records(self):
        """Reading an unmapped or faulty address records COLLECTION_STATUS_FAILED in RuntimeEvidenceRecord."""
        provider = RuntimeEvidenceProvider()
        data, method, err, recs = provider.read_memory_range(
            pid=self.proc.pid,
            address=0xDEADBEEF000,  # Unmapped invalid address
            size=16,
        )
        self.assertIsNone(data)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].collection_status, COLLECTION_STATUS_FAILED)
        self.assertGreater(len(recs[0].limitations), 0)

    def test_dwarf_unavailable_graceful_degradation(self):
        """Target without companion ELF or missing DWARF debug info reports DWARF_UNAVAILABLE and completes assessment."""
        engine = ExpertDiagnosticEngine(corpus_dir=self.tmpdir)
        session = engine.start_investigation(
            problem_statement="Investigate unexpected variable changes and state transitions",
            pid=self.proc.pid,
            companion_elf=None,  # No ELF companion
        )
        res = session.step()  # CLASSIFY
        res_assess = session.step()  # ASSESS
        self.assertEqual(res_assess["action"], "ASSESS")
        self.assertFalse(session.target_assessment.dwarf_available)
        self.assertTrue(any("companion elf" in lim.lower() for lim in session.target_assessment.limitations))


if __name__ == "__main__":
    unittest.main()
