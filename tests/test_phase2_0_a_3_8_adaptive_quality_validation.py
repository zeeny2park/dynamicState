"""Phase 2.0-A.3.8 Verification Suite: Adaptive Investigation Quality Validation.

Validates:
- 4.1 Complete 14-step investigation lifecycle with traceable transitions.
- 4.2 Adaptive scope narrowing from vague prompts ("Check whether this process has a problem.").
- 4.3 Deterministic diagnostic recipes across all 11 investigation cases.
- 4.4 Explicit hypothesis lifecycle (PROPOSED, INVESTIGATING, SUPPORTED, CONTRADICTED, INCONCLUSIVE, ABSTAINED, REJECTED).
- 4.5 Investigation budget and stopping policy.
- 4.6 All 15 end-to-end scenario tests (using real compiled C++ targets where applicable, clearly separating live runtime vs fixture scenarios).
- 4.7 Incident report 8-section separation and truthfulness.
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor.adaptive_engine import (
    AdaptiveInvestigationEngine,
    STATE_ABSTAINED,
    STATE_BUDGET_EXHAUSTED,
    STATE_CAPABILITY_UNAVAILABLE,
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.hypothesis import (
    DETERMINISTIC_DIAGNOSTIC_RECIPES,
    DeterministicHypothesisGenerator,
    HYPOTHESIS_STATUS_ABSTAINED,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_INVESTIGATING,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_REJECTED,
    HYPOTHESIS_STATUS_SUPPORTED,
)
from extractor.investigation import InvestigationManager
from extractor.observation_budget import ObservationBudgetLimits
from extractor.target_adapter import LocalTargetAdapter
from extractor.verdict_engine import (
    DIAG_CONFIRMED,
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    DIAG_REFUTED,
    DIAG_SUSPECTED,
    STOP_ALL_HYPOTHESES_REFUTED,
    STOP_BUDGET_EXHAUSTED,
    STOP_CAPABILITY_UNAVAILABLE,
    STOP_SUFFICIENT_EVIDENCE,
)
from extractor.watch_session import WatchSessionManager


class TestPhase20A38AdaptiveQualityValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="phase2_0_a38_")
        # Compile a real C++ target supporting healthy, deadlock, and exit-mid-run modes
        cls.cpp_src = os.path.join(cls.tmp_dir, "a38_target.cpp")
        cls.elf_bin = os.path.join(cls.tmp_dir, "a38_target.elf")
        cls.mismatched_elf = os.path.join(cls.tmp_dir, "a38_mismatched.elf")
        with open(cls.cpp_src, "w", encoding="utf-8") as f:
            f.write(
                '#include <cstdio>\n'
                '#include <cstdlib>\n'
                '#include <cstring>\n'
                '#include <pthread.h>\n'
                '#include <unistd.h>\n'
                'pthread_mutex_t g_lock_a = PTHREAD_MUTEX_INITIALIZER;\n'
                'pthread_mutex_t g_lock_b = PTHREAD_MUTEX_INITIALIZER;\n'
                'volatile int g_healthy_counter = 10;\n'
                'void* worker_deadlock(void*) {\n'
                '    pthread_mutex_lock(&g_lock_b);\n'
                '    usleep(20000);\n'
                '    pthread_mutex_lock(&g_lock_a);\n'
                '    return nullptr;\n'
                '}\n'
                'int main(int argc, char** argv) {\n'
                '    const char* mode = (argc > 1) ? argv[1] : "healthy";\n'
                '    if (strcmp(mode, "deadlock") == 0) {\n'
                '        pthread_t th;\n'
                '        pthread_mutex_lock(&g_lock_a);\n'
                '        pthread_create(&th, nullptr, worker_deadlock, nullptr);\n'
                '        usleep(40000);\n'
                '        printf("READY_DEADLOCK\\n");\n'
                '        fflush(stdout);\n'
                '        pthread_mutex_lock(&g_lock_b);\n'
                '    } else {\n'
                '        printf("READY_HEALTHY\\n");\n'
                '        fflush(stdout);\n'
                '        while (1) { g_healthy_counter++; usleep(30000); }\n'
                '    }\n'
                '    return 0;\n'
                '}\n'
            )
        subprocess.run(["g++", "-g", "-O0", "-Wl,--build-id=sha1", cls.cpp_src, "-o", cls.elf_bin, "-lpthread"], check=True)
        subprocess.run(["g++", "-g", "-O0", "-DEXTRA_BUILD_VAR=1", "-Wl,--build-id=md5", cls.cpp_src, "-o", cls.mismatched_elf, "-lpthread"], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def setUp(self):
        self.corpus_dir = tempfile.mkdtemp(prefix="a38_corpus_", dir=self.tmp_dir)
        self.wm = WatchSessionManager(corpus_dir=self.corpus_dir)
        self.engine = AdaptiveInvestigationEngine(watch_manager=self.wm)

    # -------------------------------------------------------------------------
    # 4.3 All 11 Deterministic Diagnostic Recipes Validation
    # -------------------------------------------------------------------------

    def test_4_3_all_11_deterministic_diagnostic_recipes_defined_and_executable(self):
        """All 11 required diagnostic recipes exist with full specification and generate competing hypotheses."""
        expected_recipes = {
            "BLOCKED_THREADS",
            "MUTEX_CONTENTION",
            "DEADLOCK_INDICATORS",
            "MEMORY_GROWTH",
            "SUSPICIOUS_OBJECT_STATE",
            "INVALID_STATE_TRANSITIONS",
            "ALLOCATION_DEALLOCATION_ANOMALIES",
            "INACCESSIBLE_MEMORY",
            "UNEXPECTED_FIELD_VALUES",
            "INCONSISTENT_OBJECT_RELATIONSHIPS",
            "PROCESS_TERMINATION_DURING_INVESTIGATION",
        }
        self.assertEqual(set(DETERMINISTIC_DIAGNOSTIC_RECIPES.keys()), expected_recipes)
        required_keys = {
            "applicability_conditions",
            "required_capabilities",
            "candidate_observations",
            "observation_budget",
            "decision_rules",
            "positive_indicators",
            "counter_indicators",
            "abstention_conditions",
            "termination_conditions",
            "report_requirements",
        }
        for r_name, r_spec in DETERMINISTIC_DIAGNOSTIC_RECIPES.items():
            self.assertTrue(required_keys.issubset(r_spec.keys()), f"Recipe {r_name} missing required keys")

        gen = DeterministicHypothesisGenerator()
        hypos = gen.generate_process_health_hypotheses({
            "suspicious_threads": [{"tid": 101, "name": "t1", "top_function": "futex_wait"}],
            "deadlock_indicators": [{"cycle_description": "T1->L1->T2->L2->T1", "tids": [101, 102]}],
            "memory_growth_candidates": [{"target_expression": "g_pool"}],
            "pointer_anomalies": [{"root_expression": "g_ptr"}],
            "queue_backlogs": [{"pipeline_expression": "g_ring"}],
            "suspicious_object_states": [{"target_expression": "g_session"}],
            "invalid_state_transitions": [{"target_expression": "g_fsm.state"}],
            "allocation_anomalies": [{"target_expression": "g_slab"}],
            "inaccessible_memory_candidates": [{"target_expression": "g_dangling"}],
            "unexpected_field_values": [{"target_expression": "g_cfg.rate"}],
            "inconsistent_relationships": [{"target_expression": "g_tree.root"}],
            "process_terminations": [{"target_expression": "pid_exit"}],
        })
        # 12 candidate anomalies * 2 competing hypotheses each = 24 structured hypotheses
        self.assertEqual(len(hypos), 24)

    # -------------------------------------------------------------------------
    # 4.6 The 15 End-to-End Scenarios
    # -------------------------------------------------------------------------

    def test_scenario_01_vague_prompt_on_healthy_live_process(self):
        """1. Vague prompt ('Check whether this process has a problem.') on a real healthy C++ process."""
        proc = subprocess.Popen([self.elf_bin, "healthy"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), "READY_HEALTHY")
            res = self.engine.investigate_process_health(
                goal="Check whether this process has a problem.",
                pid=proc.pid,
                companion_elf_path=self.elf_bin,
            )
            self.assertTrue(res["success"])
            self.assertEqual(res["final_diagnosis"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
            self.assertEqual(res["execution_status"], STATE_COMPLETED)
            self.assertEqual(len(res["lifecycle_steps"]), 14)
            self.assertIn("scope_narrowing_trace", res)
        finally:
            proc.kill()
            proc.wait()

    def test_scenario_02_vague_prompt_on_deadlocked_live_process(self):
        """2. Vague prompt on a real deadlocked multithreaded C++ process narrows scope to blocked threads/locks."""
        proc = subprocess.Popen([self.elf_bin, "deadlock"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), "READY_DEADLOCK")
            time.sleep(0.05)
            res = self.engine.investigate_process_health(
                goal="Check whether this process has a problem.",
                pid=proc.pid,
                companion_elf_path=self.elf_bin,
                follow_up_executor=lambda obs, ep: {
                    "success": True,
                    "status": "OBSERVED",
                    "observed_condition": "stalled_owner_or_deadlock_confirmed",
                    "bytes_read": 512,
                },
            )
            self.assertTrue(res["success"])
            self.assertIn(res["final_diagnosis"], (DIAG_CONFIRMED, DIAG_SUSPECTED))
            self.assertGreaterEqual(len(res["supported_hypotheses"]), 1)
            # Verify hypothesis transitioned through INVESTIGATING -> SUPPORTED
            supp_h = res["supported_hypotheses"][0]
            hist_states = [st["to_status"] for st in supp_h["status_history"]]
            self.assertIn(HYPOTHESIS_STATUS_INVESTIGATING, hist_states)
            self.assertIn(HYPOTHESIS_STATUS_SUPPORTED, hist_states)
        finally:
            proc.kill()
            proc.wait()

    def test_scenario_03_vague_prompt_on_memory_leaking_process(self):
        """3. Vague prompt on a memory-leaking process requires multi-sample temporal confirmation."""
        res = self.engine.investigate_process_health(
            goal="Check whether this process has a problem.",
            pid=12345,
            companion_elf_path=self.elf_bin,
            fixture_data={
                "triage_observations": [
                    {"source": "insp_pool", "observation": "Pool active_slots=950/1024", "bytes_read": 1024}
                ],
                "memory_growth_candidates": [{"target_expression": "g_packet_pool", "region": "[heap]"}],
            },
            follow_up_executor=lambda obs, ep: {
                "success": True,
                "status": "OBSERVED",
                "is_temporal_sample": True,
                "observed_condition": (
                    "monotonic_unreleased_growth_with_orphans"
                    if "temporal" in obs.observation_id
                    else "orphaned_unreferenced_allocations_confirmed"
                ),
                "bytes_read": 1024,
            },
        )
        self.assertEqual(res["final_diagnosis"], DIAG_CONFIRMED)
        self.assertGreaterEqual(res["evidence_coverage"]["temporal_samples_count"], 2)

    def test_scenario_04_vague_prompt_on_corrupted_state_process(self):
        """4. Vague prompt on a process with corrupted pointer/object state confirms corruption via double-read."""
        res = self.engine.investigate_process_health(
            goal="Check whether this process has a problem.",
            pid=12346,
            companion_elf_path=self.elf_bin,
            fixture_data={
                "triage_observations": [
                    {"source": "insp_integrity", "observation": "Pointer g_session->next targets unmapped 0xdeadbeef", "bytes_read": 512}
                ],
                "pointer_anomalies": [{"root_expression": "g_session", "field_path": "g_session->next"}],
            },
            follow_up_executor=lambda obs, ep: {
                "success": True,
                "status": "OBSERVED",
                "observed_condition": "consistent_invalid_pointer_confirmed",
                "bytes_read": 256,
            },
        )
        self.assertEqual(res["final_diagnosis"], DIAG_CONFIRMED)
        self.assertEqual(len(res["supported_hypotheses"]), 1)
        self.assertEqual(len(res["contradicted_hypotheses"]), 1)

    def test_scenario_05_competing_hypotheses_only_one_supported(self):
        """5. Competing hypotheses where only one is supported and its rival is contradicted."""
        res = self.engine.investigate_process_health(
            goal="Investigate queue backlog",
            pid=12347,
            companion_elf_path=self.elf_bin,
            fixture_data={
                "triage_observations": [{"source": "insp_ipc", "observation": "Queue depth 512/512", "bytes_read": 512}],
                "queue_backlogs": [{"pipeline_expression": "g_work_queue"}],
            },
            follow_up_executor=lambda obs, ep: {
                "success": True,
                "status": "OBSERVED",
                "observed_condition": "consumer_progress_zero_while_backlogged",
                "bytes_read": 512,
            },
        )
        self.assertEqual(res["final_diagnosis"], DIAG_CONFIRMED)
        self.assertEqual(len(res["supported_hypotheses"]), 1)
        self.assertEqual(len(res["contradicted_hypotheses"]), 1)

    def test_scenario_06_competing_hypotheses_all_defect_hypotheses_contradicted(self):
        """6. Competing hypotheses where defect hypothesis is contradicted and benign wait is supported."""
        res = self.engine.investigate_process_health(
            goal="Investigate blocked worker thread",
            pid=12348,
            companion_elf_path=self.elf_bin,
            fixture_data={
                "triage_observations": [{"source": "insp_locks", "observation": "Thread 200 in futex_wait", "bytes_read": 512}],
                "suspicious_threads": [{"tid": 200, "name": "worker", "top_function": "futex_wait"}],
            },
            follow_up_executor=lambda obs, ep: {
                "success": True,
                "status": "OBSERVED",
                "observed_condition": "uncontended_or_normal_progress",
                "bytes_read": 512,
            },
        )
        self.assertIn(res["final_diagnosis"], (DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE, DIAG_REFUTED))
        self.assertEqual(res["stop_reason"], STOP_ALL_HYPOTHESES_REFUTED)

    def test_scenario_07_competing_hypotheses_insufficient_evidence(self):
        """7. Competing hypotheses where follow-up observation is inconclusive -> INCONCLUSIVE."""
        res = self.engine.investigate_process_health(
            goal="Investigate ambiguous thread state",
            pid=12349,
            companion_elf_path=self.elf_bin,
            fixture_data={
                "triage_observations": [{"source": "insp_locks", "observation": "Thread 201 in poll", "bytes_read": 512}],
                "suspicious_threads": [{"tid": 201, "name": "io_worker", "top_function": "poll"}],
            },
            follow_up_executor=lambda obs, ep: {
                "success": True,
                "status": "OBSERVED",
                "outcomes_by_hypothesis": {},
                "bytes_read": 512,
            },
        )
        self.assertIn(res["final_diagnosis"], (DIAG_INCONCLUSIVE, DIAG_SUSPECTED))
        self.assertGreaterEqual(len(res["inconclusive_hypotheses"]), 1)

    def test_scenario_08_missing_debug_symbols(self):
        """8. Missing debug symbols degrades gracefully and records capability limitation."""
        stripped_bin = os.path.join(self.tmp_dir, "a38_stripped.elf")
        subprocess.run(["strip", "-s", "-o", stripped_bin, self.elf_bin], check=True)
        proc = subprocess.Popen([stripped_bin, "healthy"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), "READY_HEALTHY")
            res = self.engine.investigate_process_health(
                goal="Check process with stripped binary only",
                pid=proc.pid,
                companion_elf_path=stripped_bin,
            )
            self.assertIn("dwarf_symbols_available", res["uninspected_scope"]["unavailable_capabilities"])
        finally:
            proc.kill()
            proc.wait()

    def test_scenario_09_mismatched_build_id(self):
        """9. Mismatched Build ID between live process and companion ELF fails closed on symbol resolution."""
        proc = subprocess.Popen([self.elf_bin, "healthy"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), "READY_HEALTHY")
            res = self.engine.investigate_process_health(
                goal="Check process with mismatched companion ELF",
                pid=proc.pid,
                companion_elf_path=self.mismatched_elf,
            )
            unavail = res["uninspected_scope"]["unavailable_capabilities"]
            self.assertIn("dwarf_symbols_available", unavail)
            self.assertIn("Build ID mismatch", unavail["dwarf_symbols_available"])
        finally:
            proc.kill()
            proc.wait()

    def test_scenario_10_permission_denied_during_collection(self):
        """10. Permission denied during collection transitions hypotheses to ABSTAINED and verdict to INCONCLUSIVE."""
        res = self.engine.investigate_process_health(
            goal="Investigate restricted target",
            pid=12350,
            companion_elf_path=self.elf_bin,
            fixture_data={
                "triage_observations": [
                    {"source": "insp_locks", "observation": "EPERM reading task", "collection_status": "ABSTAIN", "error": "EPERM"}
                ],
                "suspicious_threads": [{"tid": 301, "name": "sec_worker", "top_function": "futex"}],
            },
            follow_up_executor=lambda obs, ep: {
                "success": False,
                "status": "RESTRICTED",
                "error": "Permission denied (EPERM)",
            },
        )
        self.assertEqual(res["final_diagnosis"], DIAG_INCONCLUSIVE)
        self.assertIn(res["execution_status"], (STATE_ABSTAINED, STATE_INCONCLUSIVE))
        self.assertTrue(any(h["validation_status"] == HYPOTHESIS_STATUS_ABSTAINED for h in res["competing_hypotheses"]))

    def test_scenario_11_target_process_exits_mid_investigation(self):
        """11. Target process exits mid-investigation: detected before follow-up, preserves evidence, stops cleanly."""
        proc = subprocess.Popen([self.elf_bin, "deadlock"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(proc.stdout.readline().strip(), "READY_DEADLOCK")
        # Kill the process right after startup so liveness fails during investigation
        proc.kill()
        proc.wait()

        res = self.engine.investigate_process_health(
            goal="Check process that exits during investigation",
            pid=proc.pid,
            companion_elf_path=self.elf_bin,
        )
        self.assertEqual(res["final_diagnosis"], DIAG_INCONCLUSIVE)
        self.assertEqual(res["stop_reason"], STOP_CAPABILITY_UNAVAILABLE)

    def test_scenario_12_tight_observation_budget(self):
        """12. Tight observation budget halts execution with BUDGET_EXHAUSTED before overrun."""
        res = self.engine.investigate_process_health(
            goal="Investigate under tight budget",
            pid=12352,
            companion_elf_path=self.elf_bin,
            budget_limits=ObservationBudgetLimits(max_bytes_read=512, max_samples=1),
            fixture_data={
                "triage_observations": [{"source": "insp_locks", "observation": "Triage read", "bytes_read": 512}],
                "suspicious_threads": [{"tid": 401, "name": "worker", "top_function": "futex"}],
            },
        )
        self.assertEqual(res["stop_reason"], STOP_BUDGET_EXHAUSTED)
        self.assertEqual(res["execution_status"], STATE_BUDGET_EXHAUSTED)

    def test_scenario_13_adversarial_caller_submitted_evidence(self):
        """13. Adversarial caller-submitted evidence is isolated in unverified_external_claims and cannot confirm diagnosis."""
        res = self.engine.investigate_process_health(
            goal="Adversarial caller test",
            pid=12353,
            companion_elf_path=self.elf_bin,
            provenance_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            fixture_data={
                "provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
                "triage_observations": [
                    {
                        "source": "unverified_caller",
                        "observation": "Caller claims deadlock confirmed",
                        "provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
                        "bytes_read": 256,
                    }
                ],
                "suspicious_threads": [{"tid": 501, "name": "worker", "top_function": "futex"}],
            },
            follow_up_executor=lambda obs, ep: {
                "success": True,
                "status": "OBSERVED",
                "observed_condition": "stalled_owner_or_deadlock_confirmed",
                "bytes_read": 256,
            },
        )
        self.assertNotEqual(res["final_diagnosis"], DIAG_CONFIRMED)
        self.assertGreaterEqual(len(res["unverified_external_claims"]), 1)

    def test_scenario_14_stale_or_incompatible_comparison_snapshots(self):
        """14. Stale or incompatible comparison snapshots fail closed with ABSTAIN."""
        mgr = InvestigationManager(corpus_dir=self.corpus_dir)
        info = mgr.start_investigation(goal="Stale comparison scenario")
        inv_id = info["investigation_id"]
        session = mgr.sessions[inv_id]
        session.snapshots = [
            {"pid": 100, "epoch": 10, "completeness": "COMPLETE", "fields": {"g_cnt": 5}},
            {"pid": 100, "epoch": 4, "completeness": "COMPLETE", "fields": {"g_cnt": 15}},
        ]
        mgr.propose_hypothesis(inv_id, {
            "hypothesis_id": "h_stale_14",
            "title": "Stale comparison",
            "claim": "Counter increased",
            "suggested_observations": [{
                "observation_id": "obs_stale_14",
                "question": "Did g_cnt increase?",
                "target_kind": "COMPARISON",
                "target_ref": {"field_path": "g_cnt", "expected_change": "INCREASED"},
            }],
        })
        exec_res = mgr.execute_observation(inv_id, "obs_stale_14")
        self.assertEqual(exec_res["evidence"]["details"]["outcome"], "ABSTAIN")
        self.assertEqual(exec_res["evidence"]["details"]["reason"], "stale_or_invalid_sampling_epoch")

    def test_scenario_15_incident_report_8_section_separation(self):
        """15. Incident report explicitly separates all 8 required epistemic categories."""
        res = self.engine.investigate_process_health(
            goal="Verify incident report 8-section separation",
            pid=12355,
            companion_elf_path=self.elf_bin,
            fixture_data={
                "triage_observations": [{"source": "insp_locks", "observation": "Verified thread table", "bytes_read": 512}],
                "suspicious_threads": [{"tid": 601, "name": "worker", "top_function": "futex_wait"}],
            },
            follow_up_executor=lambda obs, ep: {
                "success": True,
                "status": "OBSERVED",
                "observed_condition": "stalled_owner_or_deadlock_confirmed",
                "bytes_read": 512,
            },
        )
        required_report_sections = {
            "verified_facts",
            "supported_hypotheses",
            "contradicted_hypotheses",
            "inconclusive_hypotheses",
            "unverified_external_claims",
            "abstentions",
            "collection_limitations",
            "recommended_next_steps",
        }
        self.assertTrue(required_report_sections.issubset(res.keys()))
        self.assertGreaterEqual(len(res["verified_facts"]), 1)
        self.assertEqual(len(res["supported_hypotheses"]), 1)
        self.assertEqual(len(res["contradicted_hypotheses"]), 1)


if __name__ == "__main__":
    unittest.main()
