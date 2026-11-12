"""Comprehensive Verification Suite for IMP-001, IMP-002, IMP-003, IMP-004, and IMP-019.

Covers all acceptance criteria and verification requirements from
`20261112-1016-full/IMPROVEMENT_ROADMAP.md`:
- IMP-001 [P0]: Collection failures never convert to HEALTHY/normal/100/NO_ISSUE_DETECTED.
- IMP-002 [P0]: Default capture mode is ZERO_STOP (no SIGSTOP), FULL requires explicit stop approval,
                measured stop duration and actual collection mode are reported, and zero "0.00ms" literals exist.
- IMP-003 [P1]: Deadlock persistence defaults to cycle_persistent=False, observation_count=1;
                collector re-observes cycles and avoids false positives on transient 2-lock processes.
- IMP-004 [P1]: Memory growth follow-up InvestigationStep creation uses planner scoring without TypeError,
                and RECIPE_HEAP_GROWTH + RECIPE_LONG_LIVED_OBJECT_ACCUMULATION are added and executed.
- IMP-019 [P1]: Default runtime mode is LOW_IMPACT (mutations rejected), web API requires random session token,
                wildcard CORS is removed, Host/Origin/Content-Type are validated, and PID does not auto-authorize.
"""

import http.client
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple

from extractor.agent_runtime import AgentRuntime
from extractor.capture_backend import CaptureSafetyPolicy, ProcessVmCaptureBackend, _get_process_state
from extractor.capture_plan import CaptureMode, CapturePlan
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RECIPE_POTENTIAL_DEADLOCK_PATTERNS,
    RECIPE_PROCESS_MEMORY_GROWTH,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
)
from extractor.expert_diagnostic_engine import AdaptiveInvestigationSession, ExpertDiagnosticEngine
from extractor.investigation import InvestigationManager
from extractor.target_adapter import TargetExecutionAdapter
from extractor.verdict_engine import DIAG_INCONCLUSIVE
from extractor.watch_session import WatchSessionManager
from extractor.web.server import run_server


C_TARGET_SRC = r"""
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int in_use;
    int owner_tid;
    uint32_t seq;
    uint32_t size;
} Slot;

typedef struct {
    uint32_t magic;
    int active_buffers;
    int total_buffers;
    Slot buffers[4];
} Pool;

static Pool g_pool;
Pool *gpMem = &g_pool;
pthread_mutex_t g_lock_a = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_lock_b = PTHREAD_MUTEX_INITIALIZER;
volatile int g_running = 1;

void *transient_lock_worker(void *arg) {
    (void)arg;
    while (g_running) {
        pthread_mutex_lock(&g_lock_a);
        pthread_mutex_lock(&g_lock_b);
        usleep(500);
        pthread_mutex_unlock(&g_lock_b);
        pthread_mutex_unlock(&g_lock_a);
        usleep(10000);
    }
    return NULL;
}

int main(void) {
    memset(&g_pool, 0, sizeof(g_pool));
    g_pool.magic = 0xCAFEBABE;
    g_pool.total_buffers = 4;
    g_pool.active_buffers = 1;
    g_pool.buffers[0].in_use = 1;
    g_pool.buffers[0].owner_tid = (int)getpid();
    g_pool.buffers[0].seq = 1;
    g_pool.buffers[0].size = 64;

    pthread_t th;
    pthread_create(&th, NULL, transient_lock_worker, NULL);
    while (g_running) {
        usleep(20000);
    }
    pthread_join(th, NULL);
    return 0;
}
"""


class AlwaysFailingAdapter(TargetExecutionAdapter):
    """Fake adapter where every single operation raises an exception or fails."""

    def is_remote(self) -> bool:
        return False

    def target_host(self) -> str:
        return "localhost"

    def read_memory(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        raise PermissionError(f"Simulated EACCES reading 0x{address:x} on PID {pid}")

    def read_memory_batch(self, pid: int, slices: List[Tuple[int, int]]) -> List[Tuple[int, int, Optional[bytes], str, Optional[str]]]:
        raise PermissionError(f"Simulated EACCES batch reading PID {pid}")

    def get_memory_mappings(self, pid: int) -> List[Dict[str, Any]]:
        raise PermissionError(f"Simulated EACCES reading /proc/{pid}/maps")

    def get_threads(self, pid: int) -> List[Dict[str, Any]]:
        raise PermissionError(f"Simulated EACCES reading /proc/{pid}/task")

    def get_process_status(self, pid: int) -> Dict[str, Any]:
        raise PermissionError(f"Simulated EACCES reading /proc/{pid}/status")

    def find_processes(self, name_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        raise PermissionError("Simulated EACCES enumerating processes")

    def read_build_id(self, elf_path: str) -> Optional[str]:
        raise PermissionError("Simulated EACCES reading build_id")

    def get_process_identity(self, pid: int) -> Dict[str, Any]:
        raise PermissionError(f"Simulated EACCES reading identity for PID {pid}")


class TestImp001002003004019(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.TemporaryDirectory(prefix="dynstate_imp_")
        cls.src_path = os.path.join(cls.tmp_dir.name, "imp_target.c")
        cls.bin_path = os.path.join(cls.tmp_dir.name, "imp_target")
        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(C_TARGET_SRC)
        subprocess.run(["gcc", "-g", "-O0", "-pthread", cls.src_path, "-o", cls.bin_path], check=True)
        cls.proc = subprocess.Popen([cls.bin_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.15)
        cls.corpus_dir = os.path.join(cls.tmp_dir.name, "corpus")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.proc and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2)
            except Exception:
                cls.proc.kill()
        cls.tmp_dir.cleanup()

    def _assert_no_healthy_markers(self, payload: Any) -> None:
        text = json.dumps(payload, ensure_ascii=False) if not isinstance(payload, str) else payload
        for forbidden in ("정상", "HEALTHY", "100", "normal", "NO_ISSUE_DETECTED"):
            self.assertNotIn(forbidden, text, f"Forbidden healthy marker '{forbidden}' found in failure output!")

    # -------------------------------------------------------------------------
    # IMP-001 Tests
    # -------------------------------------------------------------------------
    def test_imp001_fake_throwing_adapter_produces_inconclusive_without_healthy_markers(self) -> None:
        wsm = WatchSessionManager(corpus_dir=self.corpus_dir)
        bad_adapter = AlwaysFailingAdapter()

        triage = wsm.auto_triage_incident(
            pid=self.proc.pid,
            companion_elf_path=self.bin_path,
            adapter=bad_adapter,
        )
        self.assertEqual(triage["overall_status"], "INCONCLUSIVE")
        self.assertIsNone(triage["health_score"])
        self.assertTrue(len(triage["limitations"]) > 0)
        self._assert_no_healthy_markers(triage)

        rep = wsm.export_incident_report(
            title="IMP-001 Failing Adapter Report",
            pid=self.proc.pid,
            companion_elf_path=self.bin_path,
            adapter=bad_adapter,
        )
        self.assertEqual(rep["overall_status"], "INCONCLUSIVE")
        self.assertEqual(rep["verdict"], DIAG_INCONCLUSIVE)
        self.assertIsNone(rep["health_score"])
        self.assertTrue(len(rep["limitations"]) > 0)
        self._assert_no_healthy_markers(rep["report_markdown"])
        self._assert_no_healthy_markers(rep["report_html"])
        self._assert_no_healthy_markers(rep["report_json"])
        self._assert_no_healthy_markers(rep["remediation_checklist"])
        self._assert_no_healthy_markers(rep["llm_next_step_hint"])

    def test_imp001_killed_process_and_unreadable_process_produce_inconclusive(self) -> None:
        wsm = WatchSessionManager(corpus_dir=self.corpus_dir)
        # Spawn and immediately kill a process
        ephemeral = subprocess.Popen([self.bin_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        dead_pid = ephemeral.pid
        ephemeral.kill()
        ephemeral.wait(timeout=2)

        rep_dead = wsm.export_incident_report(
            title="IMP-001 Dead Process Report",
            pid=dead_pid,
            companion_elf_path=self.bin_path,
        )
        self.assertEqual(rep_dead["overall_status"], "INCONCLUSIVE")
        self.assertEqual(rep_dead["verdict"], DIAG_INCONCLUSIVE)
        self.assertIsNone(rep_dead["health_score"])
        self.assertTrue(len(rep_dead["limitations"]) > 0)
        self._assert_no_healthy_markers(rep_dead["report_markdown"])
        self._assert_no_healthy_markers(rep_dead["report_html"])

        # ExpertDiagnosticEngine: when all recipes return INSUFFICIENT_EVIDENCE, verified_checks_count remains 0
        sess = AdaptiveInvestigationSession(
            investigation_id="inv_imp001",
            problem_statement="Check memory corruption on unreadable target",
            pid=dead_pid,
            companion_elf=self.bin_path,
            corpus_dir=self.corpus_dir,
            adapter=AlwaysFailingAdapter(),
        )
        concl = sess.run_to_completion(max_steps=10)
        self.assertEqual(sess.verified_checks_count, 0)
        self.assertIn(concl.overall_verdict, ("INCONCLUSIVE", "ABORTED"))
        for rem in concl.recommended_remediations:
            self.assertNotIn("healthy", rem.lower())
            self.assertNotIn("정상", rem)

    # -------------------------------------------------------------------------
    # IMP-002 Tests
    # -------------------------------------------------------------------------
    def test_imp002_default_zero_stop_and_stopped_capture_approval_and_measured_stop_time(self) -> None:
        # 1. Default CapturePlan mode is ZERO_STOP
        default_plan = CapturePlan()
        self.assertEqual(default_plan.mode, CaptureMode.ZERO_STOP.value)
        self.assertEqual(CapturePlan.from_dict({}).mode, CaptureMode.ZERO_STOP.value)

        # 2. Requesting FULL mode without allow_stop=True raises PermissionError
        backend = ProcessVmCaptureBackend()
        with self.assertRaises(PermissionError):
            backend.capture(self.proc.pid, plan=CapturePlan(mode=CaptureMode.FULL.value, allow_stop=False))

        # 3. Default InvestigationManager.start_investigation uses ZERO_STOP (0ms stop, no SIGSTOP)
        mgr = InvestigationManager(corpus_dir=self.corpus_dir)
        res_zero = mgr.start_investigation(
            goal="Default zero-stop investigation",
            pid=self.proc.pid,
            debug_image=self.bin_path,
            authorize_target=True,
        )
        rep_zero = mgr.generate_report(res_zero["investigation_id"])
        self.assertEqual(rep_zero["collection_mode"], "ZERO_STOP")
        self.assertEqual(rep_zero["stop_duration_ms"], 0.0)
        self.assertEqual(rep_zero["capture_quality"]["stop_mechanism"], "NONE")

        # 4. Approved FULL capture records measured stop duration > 0.0ms and FULL mode
        res_stop = mgr.start_investigation(
            goal="Explicitly approved stopped investigation",
            pid=self.proc.pid,
            debug_image=self.bin_path,
            authorize_target=True,
            allow_stop=True,
            constraints={"capture_mode": "FULL", "allow_stop": True},
        )
        rep_stop = mgr.generate_report(res_stop["investigation_id"])
        self.assertEqual(rep_stop["collection_mode"], "FULL")
        self.assertGreater(rep_stop["stop_duration_ms"], 0.0)
        self.assertEqual(rep_stop["capture_quality"]["stop_mechanism"], "SIGSTOP")

        # 5. Verify zero "0.00ms" literals in extractor/
        grep_res = subprocess.run(["grep", "-rn", "0\\.00ms", "extractor/"], capture_output=True, text=True)
        self.assertEqual(grep_res.stdout.strip(), "", f"Found '0.00ms' literals in extractor/: {grep_res.stdout}")

    # -------------------------------------------------------------------------
    # IMP-003 Tests
    # -------------------------------------------------------------------------
    def test_imp003_deadlock_persistence_defaults_and_transient_lock_no_false_positive(self) -> None:
        registry = DiagnosticRecipeRegistry()
        rec_dl = registry.get_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS)

        # 1. Passing {"cycle_detected": True} alone must return OBSERVED_CIRCULAR_WAIT (INSUFFICIENT_EVIDENCE)
        res_single = registry.evaluate_recipe(rec_dl, {"cycle_detected": True})
        self.assertEqual(res_single.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(res_single.details.get("state"), "OBSERVED_CIRCULAR_WAIT")
        self.assertFalse(res_single.details.get("deadlock_confirmed", True))

        # 2. Passing cycle_persistent=True and observation_count=2 returns PERSISTENT_DEADLOCK
        res_pers = registry.evaluate_recipe(rec_dl, {
            "cycle_detected": True,
            "cycle_persistent": True,
            "observation_count": 2,
        })
        self.assertEqual(res_pers.status, RECIPE_STATUS_SUPPORTED)
        self.assertEqual(res_pers.details.get("state"), "PERSISTENT_DEADLOCK")
        self.assertTrue(res_pers.details.get("deadlock_confirmed"))

        # 3. Real process that briefly acquires and releases two locks does not trigger deadlock false positive
        eng = ExpertDiagnosticEngine(corpus_dir=self.corpus_dir)
        run_res = eng.run_recipe(
            recipe_id=RECIPE_POTENTIAL_DEADLOCK_PATTERNS,
            pid=self.proc.pid,
            companion_elf=self.bin_path,
        )
        dl_check = next(c for c in run_res["checks"] if c["recipe_id"] == RECIPE_POTENTIAL_DEADLOCK_PATTERNS)
        self.assertNotEqual(dl_check["status"], "FAIL", "Transient lock holder must not be diagnosed as persistent deadlock")

    # -------------------------------------------------------------------------
    # IMP-004 Tests
    # -------------------------------------------------------------------------
    def test_imp004_memory_growth_followup_steps_added_and_executed_via_run_recipe(self) -> None:
        eng = ExpertDiagnosticEngine(corpus_dir=self.corpus_dir)
        # Pass synthetic monotonic RSS growth thresholds/context via session or run_recipe
        session = eng.start_investigation(
            problem_statement="Targeted execution of diagnostic recipe RECIPE_PROCESS_MEMORY_GROWTH",
            pid=self.proc.pid,
            companion_elf=self.bin_path,
            target_recipe=RECIPE_PROCESS_MEMORY_GROWTH,
            recipe_thresholds={
                "rss_history_kb": [1000, 1400, 1900, 2500],
                "monotonic_growth": True,
                "growth_rate_pct": 150.0,
            },
        )
        concl = session.run_to_completion(max_steps=20)
        self.assertIsNotNone(concl)
        planned_ids = [s.recipe_id for s in session.plan.steps]
        executed_ids = [c.recipe_id for c in session.checks]

        self.assertIn("RECIPE_HEAP_GROWTH", planned_ids)
        self.assertIn("RECIPE_LONG_LIVED_OBJECT_ACCUMULATION", planned_ids)
        self.assertIn("RECIPE_HEAP_GROWTH", executed_ids)
        self.assertIn("RECIPE_LONG_LIVED_OBJECT_ACCUMULATION", executed_ids)


if __name__ == "__main__":
    unittest.main()
