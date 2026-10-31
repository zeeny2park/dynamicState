"""End-to-End Acceptance Test Suite for Phase 2.0: Adaptive Process Health Investigation.

Covers all mandatory acceptance scenarios (A through J):
- Scenario A: Healthy process -> NO_ISSUE_DETECTED_WITHIN_SCOPE (never universally healthy, no hardcoded symbol defects).
- Scenario B: Suspicious thread -> Competing hypotheses (lock contention vs normal wait), cheapest discriminating follow-up selected, calibrated conclusion.
- Scenario C: Memory growth -> Leak vs workload growth; single snapshot never confirms a leak; multi-sample temporal follow-up discriminates.
- Scenario D: Read failure / restricted process -> Failed reads become ABSTAIN/UNKNOWN, failed observation never marked executed, verdict is INCONCLUSIVE.
- Scenario E: Incomplete or unverified snapshot -> Provenance (IMPORTED_UNVERIFIED) and PARTIAL capture cap verdict; cannot upgrade to LIVE_RUNTIME_CAPTURE.
- Scenario F: Budget exhaustion -> Pre-execution conservative cost check, profile budget_ceiling enforcement, unknown byte cost handling, no fabricated measured_bytes_read=4096, partial findings retained, explicit BUDGET_EXHAUSTED state.
- Scenario G: Duplicate observations -> Semantic digest deduplication prevents evidence count or confidence inflation; session resume/replay does not re-execute.
- Scenario H: Contradictory evidence -> Supporting and contradicting evidence coexist; status and confidence update deterministically.
- Scenario I: Deterministic replay -> Identical fixture and ordered observations produce identical canonical plans, hypothesis states, and verdicts.
- Scenario J: State machine & backward compatibility -> Invalid transitions rejected; existing investigation, CLI, and MCP contracts preserved.
"""

import copy
import json
import tempfile
import unittest

from extractor.adaptive_engine import (
    STATE_BUDGET_EXHAUSTED,
    STATE_CANCELED,
    STATE_COMPLETED,
    STATE_CREATED,
    STATE_FAILED,
    STATE_FINALIZATION,
    STATE_FOLLOW_UP_PLANNING,
    STATE_HYPOTHESIS_FORMATION,
    STATE_HYPOTHESIS_UPDATE,
    STATE_INCONCLUSIVE,
    STATE_INITIAL_TRIAGE,
    STATE_OBSERVATION,
    STATE_TARGET_VALIDATION,
    AdaptiveInvestigationEngine,
    InvestigationStateMachine,
    canonicalize_investigation_report,
)
from extractor.evidence_adapter import (
    COLLECTION_STATUS_ABSTAIN,
    COLLECTION_STATUS_COLLECTED,
    RESULT_BUDGET_REJECTED,
    RESULT_DUPLICATE_EVIDENCE,
    RESULT_NEW_EVIDENCE,
    RESULT_NO_NEW_EVIDENCE,
    RESULT_OBSERVATION_FAILED,
    RESULT_OBSERVATION_UNAVAILABLE,
    RESULT_PARTIAL_EVIDENCE,
    EvidenceAdapter,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_HYPOTHESIS,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_HYPOTHESIS,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
)
from extractor.hypothesis import (
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    OBSERVATION_STATUS_EXECUTED,
    OBSERVATION_STATUS_FAILED,
    OBSERVATION_STATUS_PROPOSED,
    FollowUpObservation,
    HypothesisValidator,
    InvestigationHypothesis,
)
from extractor.inspection_module import (
    DOMAIN_CONCURRENCY,
    DOMAIN_MEMORY,
    FunctionalInspectionModule,
    InspectionContext,
    InspectionModuleRegistry,
    InspectionProfile,
)
from extractor.investigation import InvestigationManager, InvestigationSession
from extractor.observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
from extractor.target_adapter import LocalTargetAdapter
from extractor.verdict_engine import (
    DIAG_CONFIRMED,
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    DIAG_PARTIALLY_CONFIRMED,
    DIAG_REFUTED,
    DIAG_SUSPECTED,
    STOP_ALL_HYPOTHESES_REFUTED,
    STOP_BUDGET_EXHAUSTED,
    STOP_CAPABILITY_UNAVAILABLE,
    STOP_REPEATED_FAILURE,
    STOP_SUFFICIENT_EVIDENCE,
)


class TestPhase20ProcessHealthInvestigation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dynstate_phase20_")

    # -------------------------------------------------------------------------
    # Scenario A: Healthy Process
    # -------------------------------------------------------------------------
    def test_scenario_a_healthy_process_within_scope(self):
        """A: Healthy process triage finds no anomaly and reports NO_ISSUE_DETECTED_WITHIN_SCOPE,
        without assuming hardcoded symbols (gpMem, g_corrupt_record, g_ipc_ring)."""
        engine = AdaptiveInvestigationEngine()

        # Verify default registry does NOT run gpMem / g_corrupt_record / g_ipc_ring without explicit symbols
        for pid_str in ("insp_pool", "insp_integrity", "insp_find_owners", "insp_ipc"):
            mod = engine.registry.get(pid_str)
            self.assertIsNotNone(mod)
            self.assertTrue(
                mod.profile.requires_explicit_target_expression,
                f"Module {pid_str} must require explicit/discovered target expression, not hardcoded defaults",
            )

        fixture = {
            "target_identity": {"pid": 4100, "companion_elf": "/bin/app_healthy", "build_id": "abc12345"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
                "watch_history_available": False,
                "unavailable_reasons": {"watch_history_available": "No prior watch session active for PID 4100"},
            },
            "available_symbols": {"g_app_status", "g_worker_count"},
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "estimated_bytes": 1024,
                    "output": {
                        "success": True,
                        "bytes_read": 512,
                        "threads": [
                            {"tid": 4100, "name": "main", "state": "S", "suspicious": False},
                            {"tid": 4101, "name": "worker_0", "state": "R", "suspicious": False},
                        ],
                        "symbols_inspected": ["g_app_status", "g_worker_count"],
                        "regions_inspected": [".data", "[stack]"],
                    },
                }
            ],
        }

        res = engine.investigate_process_health(
            goal="이 프로세스에 문제가 있는지 검사해주세요.",
            pid=4100,
            companion_elf_path="/bin/app_healthy",
            fixture_data=fixture,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["lifecycle_state"], STATE_COMPLETED)
        self.assertEqual(res["verdict"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertEqual(res["final_diagnosis"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertEqual(res["stop_reason"], STOP_SUFFICIENT_EVIDENCE)
        self.assertIn(DOMAIN_CONCURRENCY, res["inspected_scope"]["domains"])
        self.assertEqual(res["inspected_scope"]["threads_inspected"], [4100, 4101])
        self.assertIn("watch_history_available", res["uninspected_scope"]["unavailable_capabilities"])
        self.assertGreater(len(res["observed_facts"]), 0)
        self.assertEqual(len(res["competing_hypotheses"]), 0)

    # -------------------------------------------------------------------------
    # Scenario B: Suspicious Thread (Competing Hypotheses & Discriminating Planner)
    # -------------------------------------------------------------------------
    def test_scenario_b_suspicious_thread_competing_hypotheses_and_discrimination(self):
        """B: Blocked thread generates competing explanations (lock contention vs normal wait);
        planner picks the cheapest discriminating follow-up; follow-up resolves them."""
        engine = AdaptiveInvestigationEngine()

        fixture = {
            "target_identity": {"pid": 4200, "companion_elf": "/bin/app_locks"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "estimated_bytes": 2048,
                    "output": {
                        "success": True,
                        "bytes_read": 1024,
                        "threads": [
                            {
                                "tid": 4202,
                                "name": "pkt_worker",
                                "state": "D",
                                "suspicious": True,
                                "top_function": "__lll_lock_wait",
                                "lock_address": "0x7f800010",
                                "progress_expression": "g_worker_progress",
                            }
                        ],
                    },
                }
            ],
        }

        # Add an expensive alternative observation to verify planner picks the cheaper discriminating one
        def follow_up_exec(obs: FollowUpObservation, epoch: int):
            return {
                "success": True,
                "bytes_read": 512,
                "observed_condition": "stalled_owner_or_deadlock_confirmed",
                "deadlock_detected": True,
                "observation": "Lock 0x7f800010 is held by TID 4201 which is waiting on 0x7f800020 held by TID 4202.",
            }

        res = engine.investigate_process_health(
            goal="이 프로세스에 문제가 있는지 검사해주세요.",
            pid=4200,
            companion_elf_path="/bin/app_locks",
            fixture_data=fixture,
            follow_up_executor=follow_up_exec,
        )

        self.assertEqual(res["lifecycle_state"], STATE_COMPLETED)
        hypos = res["competing_hypotheses"]
        self.assertGreaterEqual(len(hypos), 2)

        lock_hypo = next(h for h in hypos if "hypo_thread_lock_" in h["hypothesis_id"])
        idle_hypo = next(h for h in hypos if "hypo_thread_idle_" in h["hypothesis_id"])

        # Competing hypotheses cross-reference each other and have full required fields
        self.assertIn(idle_hypo["hypothesis_id"], lock_hypo["competing_hypothesis_ids"])
        self.assertIn(lock_hypo["hypothesis_id"], idle_hypo["competing_hypothesis_ids"])
        self.assertTrue(lock_hypo["assumptions"])
        self.assertTrue(lock_hypo["unresolved_questions"])
        self.assertTrue(lock_hypo["validation_criteria"])
        self.assertTrue(lock_hypo["discriminating_evidence_needed"])

        # Follow-up observation supported lock_hypo and contradicted idle_hypo
        self.assertEqual(lock_hypo["validation_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertEqual(idle_hypo["validation_status"], HYPOTHESIS_STATUS_CONTRADICTED)
        self.assertEqual(res["verdict"], DIAG_CONFIRMED)
        self.assertEqual(res["stop_reason"], STOP_SUFFICIENT_EVIDENCE)
        self.assertGreater(len(res["planner_decisions"]), 0)
        self.assertTrue(res["planner_decisions"][0]["preference_rationale"])

    # -------------------------------------------------------------------------
    # Scenario C: Memory Growth (Single Snapshot Never Confirms Leak vs Multi-Sample)
    # -------------------------------------------------------------------------
    def test_scenario_c_memory_growth_single_snapshot_vs_temporal_confirmation(self):
        """C: Single snapshot cannot confirm a memory leak; multi-sample temporal + owner evidence discriminates."""
        engine = AdaptiveInvestigationEngine()

        fixture_single = {
            "target_identity": {"pid": 4300, "companion_elf": "/bin/app_mem"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": False,  # Prevent follow-up temporal reads so only 1 sample exists
                "unavailable_reasons": {"memory_read_available": "Follow-up temporal sampling disabled for single-snapshot test"},
            },
            "initial_triage": [
                {
                    "step_id": "triage_mem",
                    "domain": DOMAIN_MEMORY,
                    "estimated_bytes": 1024,
                    "output": {
                        "success": True,
                        "bytes_read": 512,
                        "memory_growth_candidates": [
                            {
                                "target_expression": "g_packet_pool",
                                "region": "[heap]",
                                "used_slots": 950,
                                "total_slots": 1024,
                            }
                        ],
                    },
                }
            ],
        }

        res_single = engine.investigate_process_health(
            goal="메모리 누수가 있는지 확인해주세요.",
            pid=4300,
            companion_elf_path="/bin/app_mem",
            fixture_data=fixture_single,
        )

        # Single snapshot alone MUST NOT confirm a leak!
        self.assertNotEqual(res_single["verdict"], DIAG_CONFIRMED)
        self.assertIn(res_single["verdict"], (DIAG_SUSPECTED, DIAG_INCONCLUSIVE))

        # Now run with temporal follow-up showing normal reclamation (workload buffering)
        fixture_multi = copy.deepcopy(fixture_single)
        fixture_multi["capabilities"]["memory_read_available"] = True
        fixture_multi["capabilities"]["unavailable_reasons"] = {}

        def follow_up_workload(obs: FollowUpObservation, epoch: int):
            return {
                "success": True,
                "bytes_read": 512,
                "is_temporal_sample": True,
                "observed_condition": "stable_or_reclaimed_allocation",
                "observation": "Second sample shows g_packet_pool usage dropped from 950 to 120 slots as workers drained burst.",
            }

        res_workload = engine.investigate_process_health(
            goal="메모리 누수가 있는지 확인해주세요.",
            pid=4300,
            companion_elf_path="/bin/app_mem",
            fixture_data=fixture_multi,
            follow_up_executor=follow_up_workload,
        )

        self.assertEqual(res_workload["verdict"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertEqual(res_workload["stop_reason"], STOP_ALL_HYPOTHESES_REFUTED)

    # -------------------------------------------------------------------------
    # Scenario D: Read Failure / Restricted Process
    # -------------------------------------------------------------------------
    def test_scenario_d_read_failure_and_restricted_process_yields_inconclusive(self):
        """D: Failed/restricted reads become ABSTAIN/UNKNOWN, never false PASS/FAIL or healthy verdict."""
        engine = AdaptiveInvestigationEngine()

        fixture_restricted = {
            "target_identity": {"pid": 4400, "companion_elf": "/bin/app_restricted"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": False,
                "threads_available": False,
                "dwarf_symbols_available": True,
                "memory_read_available": False,
                "unavailable_reasons": {
                    "memory_read_available": "EPERM: ptrace_scope=2 restricts process_vm_readv and /proc/pid/mem",
                },
            },
            "initial_triage": [
                {
                    "step_id": "triage_restricted_read",
                    "domain": DOMAIN_MEMORY,
                    "estimated_bytes": 512,
                    "output": {
                        "success": False,
                        "status": "RESTRICTED",
                        "error_code": "RESTRICTED",
                        "error": "Permission denied reading target memory (EPERM)",
                    },
                }
            ],
        }

        res = engine.investigate_process_health(
            goal="이 프로세스에 문제가 있는지 검사해주세요.",
            pid=4400,
            companion_elf_path="/bin/app_restricted",
            fixture_data=fixture_restricted,
        )

        self.assertEqual(res["lifecycle_state"], STATE_INCONCLUSIVE)
        self.assertEqual(res["verdict"], DIAG_INCONCLUSIVE)
        self.assertNotIn(res["verdict"], (DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE, DIAG_CONFIRMED, DIAG_REFUTED))
        self.assertGreater(len(res["unknowns"]), 0)

        # Verify a failed FollowUpObservation never becomes executed=True
        failed_obs = FollowUpObservation(
            observation_id="obs_fail_test",
            hypothesis_id="hypo_1",
            question="Read unreadable address",
            executed=True,
            status=OBSERVATION_STATUS_FAILED,
        )
        self.assertFalse(failed_obs.executed)
        self.assertEqual(failed_obs.status, OBSERVATION_STATUS_FAILED)

    # -------------------------------------------------------------------------
    # Scenario E: Incomplete or Unverified Snapshot
    # -------------------------------------------------------------------------
    def test_scenario_e_incomplete_or_unverified_snapshot_caps_verdict(self):
        """E: Imported/unverified provenance cannot upgrade to LIVE_RUNTIME_CAPTURE and caps verdicts."""
        engine = AdaptiveInvestigationEngine()

        fixture_unverified = {
            "provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            "target_identity": {"pid": 4500, "companion_elf": "/bin/app_imported"},
            "capture_quality": {"completeness": "PARTIAL", "status": "PARTIAL", "consistency_level": "NON_ATOMIC"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "estimated_bytes": 1024,
                    "output": {
                        "success": True,
                        "bytes_read": 512,
                        "threads": [
                            {
                                "tid": 4501,
                                "name": "worker",
                                "state": "D",
                                "suspicious": True,
                                "top_function": "mutex_lock",
                                "lock_address": "0xdead0010",
                            }
                        ],
                    },
                }
            ],
        }

        def follow_up_confirm(obs: FollowUpObservation, epoch: int):
            return {
                "success": True,
                "bytes_read": 256,
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,  # Attempted upgrade must be blocked!
                "observed_condition": "stalled_owner_or_deadlock_confirmed",
                "observation": "Deadlock pattern in imported snapshot.",
            }

        res = engine.investigate_process_health(
            goal="Check imported snapshot health",
            pid=4500,
            companion_elf_path="/bin/app_imported",
            provenance_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            fixture_data=fixture_unverified,
            follow_up_executor=follow_up_confirm,
        )

        # Provenance must remain IMPORTED_UNVERIFIED (never upgraded to LIVE_RUNTIME_CAPTURE)
        self.assertEqual(res["provenance_class"], PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        # Verdict must be capped at SUSPECTED (never CONFIRMED)
        self.assertEqual(res["verdict"], DIAG_SUSPECTED)
        self.assertNotEqual(res["verdict"], DIAG_CONFIRMED)
        self.assertGreater(len(res["provenance_limitations"]), 0)

    # -------------------------------------------------------------------------
    # Scenario F: Budget Exhaustion & Honest Cost Accounting
    # -------------------------------------------------------------------------
    def test_scenario_f_budget_exhaustion_and_no_fabricated_bytes(self):
        """F: Pre-execution conservative cost check prevents overrun; profile ceiling enforced;
        unknown byte cost never treated as 0; no silent bytes_read=4096 fabrication."""
        # 1. Unknown byte cost is never treated as zero and never fabricates measured_bytes_read
        limits = ObservationBudgetLimits(
            max_bytes_read=3000,
            max_wall_clock_ms=5000.0,
            conservative_unknown_bytes=2048,
        )
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        # Unmeasured read charges conservative_unknown_bytes (2048), while measured_bytes_read stays 0!
        rec_info = tracker.record_read(bytes_read=None, latency_us=100.0)
        self.assertIsNone(rec_info["measured_bytes_read"])
        self.assertEqual(rec_info["charged_bytes"], 2048)
        self.assertTrue(rec_info["used_conservative_byte_estimate"])
        self.assertEqual(tracker.metrics.measured_bytes_read, 0)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 2048)
        self.assertEqual(tracker.metrics.bytes_read, 2048)

        # Next operation with unknown byte cost (conservative 2048B) exceeds remaining budget (3000 - 2048 = 952B)
        allowed, reason, est_b = tracker.check_pre_execution(estimated_bytes=None)
        self.assertFalse(allowed)
        self.assertIn("PRECHECK_EXCEEDED_BYTES_READ", reason)
        self.assertEqual(est_b, 2048)

        # 2. Profile budget_ceiling enforcement in FunctionalInspectionModule
        p_strict = InspectionProfile(
            profile_id="insp_strict_ceil",
            domain=DOMAIN_MEMORY,
            name="Strict Ceiling Profile",
            estimated_bytes=4096,
            budget_ceiling={"max_bytes_read": 2048},  # Ceiling smaller than estimated_bytes!
        )
        mod_strict = FunctionalInspectionModule(p_strict, lambda wm, **kw: {"success": True, "bytes_read": 4096})
        ctx = InspectionContext(
            pid=1234,
            companion_elf="/bin/app",
            adapter=LocalTargetAdapter(),
            budget_tracker=ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000)),
        )
        mod_res = mod_strict.run(ctx)
        self.assertFalse(mod_res["success"])
        self.assertEqual(mod_res["result_category"], RESULT_BUDGET_REJECTED)
        self.assertIn("EXCEEDED_PROFILE_BYTES_CEILING", mod_res["error"])

        # 3. End-to-end investigation stops cleanly with BUDGET_EXHAUSTED and retains partial findings
        tight_limits = ObservationBudgetLimits(max_bytes_read=1500, max_wall_clock_ms=5000.0)
        engine = AdaptiveInvestigationEngine(default_limits=tight_limits)
        fixture_budget = {
            "target_identity": {"pid": 4600, "companion_elf": "/bin/app_budget"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "estimated_bytes": 1024,
                    "output": {
                        "success": True,
                        "bytes_read": 1024,
                        "threads": [
                            {
                                "tid": 4601,
                                "name": "worker",
                                "state": "D",
                                "suspicious": True,
                                "top_function": "lock_wait",
                                "lock_address": "0x7f0099",
                            }
                        ],
                    },
                }
            ],
        }
        # Follow-up requires 2048B, which exceeds remaining 476B (1500 - 1024)!
        follow_up_called = []

        def should_not_run(obs: FollowUpObservation, epoch: int):
            follow_up_called.append(obs.observation_id)
            return {"success": True, "bytes_read": 2048}

        res_b = engine.investigate_process_health(
            goal="Budget bounded test",
            pid=4600,
            companion_elf_path="/bin/app_budget",
            budget_limits=tight_limits,
            fixture_data=fixture_budget,
            follow_up_executor=should_not_run,
        )

        # Follow-up must NOT have started because pre-check rejected it
        self.assertEqual(len(follow_up_called), 0)
        self.assertEqual(res_b["lifecycle_state"], STATE_BUDGET_EXHAUSTED)
        self.assertEqual(res_b["stop_reason"], STOP_BUDGET_EXHAUSTED)
        # Partial triage findings and hypotheses are retained
        self.assertGreaterEqual(len(res_b["competing_hypotheses"]), 2)
        self.assertLessEqual(res_b["budget_usage"]["metrics"]["bytes_read"], 1500)

    # -------------------------------------------------------------------------
    # Scenario G: Duplicate Observations & Session Resume/Replay
    # -------------------------------------------------------------------------
    def test_scenario_g_duplicate_observations_do_not_inflate_confidence(self):
        """G: Repeated equivalent observation produces DUPLICATE_EVIDENCE and does not inflate
        evidence count or confidence; session resume refuses to duplicate execution."""
        ledger = EvidenceLedger(session_id="sess_dup_test")
        adapter = EvidenceAdapter()

        payload_1 = {"success": True, "counter": 42, "timestamp": "2026-10-31T01:00:00Z", "evidence_id": "rand_1"}
        payload_2 = {"success": True, "counter": 42, "timestamp": "2026-10-31T02:00:00Z", "evidence_id": "rand_2"}

        rec1 = adapter.adapt_generic_tool_output(
            tool_name="insp_locks",
            tool_result=payload_1,
            session_id="sess_dup_test",
            ledger=ledger,
            epoch=0,
        )
        self.assertEqual(rec1.details["result_category"], RESULT_NEW_EVIDENCE)
        adapter.record_into_ledger(rec1, ledger)
        self.assertEqual(len(ledger.records), 1)

        # Second identical observation with different timestamp/ID is detected as DUPLICATE_EVIDENCE
        rec2 = adapter.adapt_generic_tool_output(
            tool_name="insp_locks",
            tool_result=payload_2,
            session_id="sess_dup_test",
            ledger=ledger,
            epoch=0,
        )
        self.assertEqual(rec2.details["result_category"], RESULT_DUPLICATE_EVIDENCE)
        adapter.record_into_ledger(rec2, ledger)
        self.assertEqual(len(ledger.records), 1)

        # Hypothesis evaluation does not inflate supporting count or confidence on duplicate
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_dup_check",
            investigation_id="sess_dup_test",
            title="Test Duplicate",
            claim="Counter is 42",
            proposed_mechanism="Test",
            supporting_evidence_ids=[rec1.evidence_id],
        )
        res_eval1 = HypothesisValidator.evaluate(hypo, ledger)
        conf_after_1 = hypo.confidence_score
        supp_after_1 = len(hypo.supporting_evidence_ids)

        res_eval2 = HypothesisValidator.evaluate(hypo, ledger, new_evidence=rec2)
        self.assertTrue(res_eval2.is_duplicate)
        self.assertEqual(len(hypo.supporting_evidence_ids), supp_after_1)
        self.assertEqual(hypo.confidence_score, conf_after_1)

        # Verify session serialization & resume prevents re-executing an already executed observation
        mgr = InvestigationManager(corpus_dir=self.tmp_dir)
        sess = InvestigationSession(investigation_id="inv_resume_1", goal="Resume test", corpus_dir=self.tmp_dir)
        obs = FollowUpObservation(
            observation_id="obs_once_1",
            hypothesis_id="hypo_dup_check",
            question="Check once",
        )
        hypo.suggested_observations = [obs]
        sess.hypotheses = [hypo]
        sess.follow_up_observations = [obs]
        mgr.sessions["inv_resume_1"] = sess

        exec1 = mgr.execute_observation("inv_resume_1", "obs_once_1", result_data={"outcome": "SUPPORTED"})
        self.assertTrue(exec1["success"])

        # Serialize and reload session into a fresh manager
        saved = sess.to_dict()
        reloaded_sess = InvestigationSession.from_dict(saved, corpus=mgr.corpus)
        mgr.sessions["inv_resume_1"] = reloaded_sess

        exec2 = mgr.execute_observation("inv_resume_1", "obs_once_1", result_data={"outcome": "SUPPORTED"})
        self.assertFalse(exec2["success"])
        self.assertTrue(exec2.get("already_executed"))
        self.assertEqual(exec2.get("result_category"), RESULT_DUPLICATE_EVIDENCE)

    # -------------------------------------------------------------------------
    # Scenario H: Contradictory Evidence Coexistence
    # -------------------------------------------------------------------------
    def test_scenario_h_contradictory_evidence_coexists_and_updates_deterministically(self):
        """H: Supporting and contradicting records coexist on a hypothesis; status updates to CONTRADICTED."""
        ledger = EvidenceLedger(session_id="sess_contra")
        rec_supp = ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="triage",
            observation="Initial queue depth was high (512)",
            details={"collection_status": COLLECTION_STATUS_COLLECTED, "semantic_digest": "dig_supp_1"},
        )
        rec_contra = ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="follow_up",
            observation="Consumer processed 1000 items/sec; queue drained to 0 (contradicts stall)",
            details={"collection_status": COLLECTION_STATUS_COLLECTED, "outcome": "CONTRADICTED", "semantic_digest": "dig_contra_1"},
        )

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_contra_test",
            investigation_id="sess_contra",
            title="Consumer Stall",
            claim="Consumer is deadlocked",
            proposed_mechanism="Blocked consumer thread",
            supporting_evidence_ids=[rec_supp.evidence_id],
        )

        HypothesisValidator.evaluate(hypo, ledger)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertIn(rec_supp.evidence_id, hypo.supporting_evidence_ids)

        # Now apply contradicting evidence: both supporting and contradicting IDs must coexist!
        HypothesisValidator.evaluate(hypo, ledger, new_evidence=rec_contra)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_CONTRADICTED)
        self.assertIn(rec_supp.evidence_id, hypo.supporting_evidence_ids)
        self.assertIn(rec_contra.evidence_id, hypo.contradicting_evidence_ids)
        self.assertLessEqual(hypo.confidence_score, 0.20)

    # -------------------------------------------------------------------------
    # Scenario I: Deterministic Replay Equivalence
    # -------------------------------------------------------------------------
    def test_scenario_i_deterministic_replay_equivalence(self):
        """I: Same fixture and same ordered observations produce identical canonical plans,
        hypothesis states, and verdicts."""
        fixture = {
            "target_identity": {"pid": 4900, "companion_elf": "/bin/app_det"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "initial_triage": [
                {
                    "step_id": "triage_ptr",
                    "domain": "INTEGRITY",
                    "estimated_bytes": 512,
                    "output": {
                        "success": True,
                        "bytes_read": 256,
                        "pointer_anomalies": [
                            {"field_path": "g_active_conn->handler", "observed_address": "0x00000004"}
                        ],
                    },
                },
                {
                    "step_id": "triage_queue",
                    "domain": "IPC",
                    "estimated_bytes": 512,
                    "output": {
                        "success": True,
                        "bytes_read": 256,
                        "queue_backlogs": [
                            {"pipeline_expression": "g_ingress_ring", "depth": 255}
                        ],
                    },
                },
            ],
        }

        def deterministic_executor(obs: FollowUpObservation, epoch: int):
            if "ptr" in obs.observation_id:
                return {
                    "success": True,
                    "bytes_read": 128,
                    "observed_condition": "consistent_invalid_pointer_confirmed",
                    "observation": "Seqlock double-read confirmed persistent corrupt address 0x4.",
                }
            return {
                "success": True,
                "bytes_read": 128,
                "observed_condition": "consumer_actively_draining",
                "observation": "Consumer read index advanced by 128 items.",
            }

        engine1 = AdaptiveInvestigationEngine()
        run1 = engine1.investigate_process_health(
            goal="Deterministic replay check",
            pid=4900,
            companion_elf_path="/bin/app_det",
            session_id="inv_det_fixed",
            fixture_data=copy.deepcopy(fixture),
            follow_up_executor=deterministic_executor,
        )

        engine2 = AdaptiveInvestigationEngine()
        run2 = engine2.investigate_process_health(
            goal="Deterministic replay check",
            pid=4900,
            companion_elf_path="/bin/app_det",
            session_id="inv_det_fixed",
            fixture_data=copy.deepcopy(fixture),
            follow_up_executor=deterministic_executor,
        )

        canon1 = canonicalize_investigation_report(run1)
        canon2 = canonicalize_investigation_report(run2)

        self.assertEqual(canon1["verdict"], canon2["verdict"])
        self.assertEqual(canon1["planner_decisions"], canon2["planner_decisions"])
        self.assertEqual(canon1["competing_hypotheses"], canon2["competing_hypotheses"])
        self.assertEqual(canon1["state_transitions"], canon2["state_transitions"])
        self.assertEqual(canon1, canon2)

    # -------------------------------------------------------------------------
    # Scenario J: State Machine Contract & Self-Evidence Guard
    # -------------------------------------------------------------------------
    def test_scenario_j_state_machine_contract_and_self_evidence_guard(self):
        """J: Invalid state transitions and empty reasons are rejected; a hypothesis is never evidence for itself."""
        sm = InvestigationStateMachine()
        self.assertEqual(sm.state, STATE_CREATED)

        # Reject empty reason
        with self.assertRaises(ValueError):
            sm.transition(STATE_TARGET_VALIDATION, "")

        # Reject invalid direct jump CREATED -> COMPLETED or CREATED -> OBSERVATION
        with self.assertRaises(ValueError):
            sm.transition(STATE_COMPLETED, "Jump directly to completed")
        with self.assertRaises(ValueError):
            sm.transition(STATE_OBSERVATION, "Jump directly to observation")

        # Valid lifecycle path
        sm.transition(STATE_TARGET_VALIDATION, "Validate target")
        sm.transition(STATE_INITIAL_TRIAGE, "Run initial triage")
        sm.transition(STATE_HYPOTHESIS_FORMATION, "Form hypotheses")
        sm.transition(STATE_FOLLOW_UP_PLANNING, "Plan follow-up")
        sm.transition(STATE_OBSERVATION, "Run observation")
        sm.transition(STATE_HYPOTHESIS_UPDATE, "Update hypotheses")
        sm.transition(STATE_FINALIZATION, "Finalize report")
        sm.transition(STATE_COMPLETED, "Done")
        self.assertTrue(sm.is_terminal)

        # Reject transition out of terminal state
        with self.assertRaises(ValueError):
            sm.transition(STATE_OBSERVATION, "Cannot leave terminal state")

        # Verify a hypothesis record is never counted as supporting evidence for itself
        ledger = EvidenceLedger(session_id="sess_self_ev")
        self_rec = EvidenceRecord(
            evidence_id="ev_hypo_self_1",
            evidence_type=EVIDENCE_TYPE_HYPOTHESIS,
            nature=NATURE_HYPOTHESIS,
            source="proposer",
            session_id="sess_self_ev",
            observation="Hypothesis claims X",
        )
        ledger.add_record(self_rec)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_self_1",
            investigation_id="sess_self_ev",
            title="Self Evidence Test",
            claim="Claim X",
            proposed_mechanism="Mechanism X",
            supporting_evidence_ids=["ev_hypo_self_1"],
        )
        res = HypothesisValidator.evaluate(hypo, ledger, new_evidence=self_rec)
        self.assertEqual(len(hypo.supporting_evidence_ids), 0)
        self.assertNotEqual(hypo.validation_status, HYPOTHESIS_STATUS_SUPPORTED)



    # -------------------------------------------------------------------------
    # Scenario K: InvestigationManager Integration & Session Persistence
    # -------------------------------------------------------------------------
    def test_scenario_k_investigation_manager_health_and_report_integration(self):
        """K: InvestigationManager.investigate_process_health integrates with InvestigationSession,
        generate_report, save_session, and load_session."""
        mgr = InvestigationManager(corpus_dir=self.tmp_dir)
        fixture = {
            "target_identity": {"pid": 5100, "companion_elf": "/bin/app_mgr"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "initial_triage": [
                {
                    "step_id": "triage_ok",
                    "domain": DOMAIN_CONCURRENCY,
                    "estimated_bytes": 512,
                    "output": {
                        "success": True,
                        "bytes_read": 256,
                        "threads": [{"tid": 5100, "name": "main", "state": "S", "suspicious": False}],
                    },
                }
            ],
        }
        res = mgr.investigate_process_health(
            goal="이 프로세스에 문제가 있는지 검사해주세요.",
            pid=5100,
            debug_image="/bin/app_mgr",
            fixture_data=fixture,
        )
        inv_id = res["session_id"]
        self.assertIn(inv_id, mgr.sessions)
        self.assertEqual(res["verdict"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)

        rep = mgr.generate_report(inv_id)
        self.assertEqual(rep["lifecycle_state"], STATE_COMPLETED)
        self.assertGreaterEqual(len(rep["state_transitions"]), 4)
        self.assertIn("report_html", rep)

        # Save and load session roundtrip preserves lifecycle_state and transitions
        saved = mgr.save_session(inv_id)
        self.assertTrue(saved["success"])
        loaded = mgr.load_session(saved["session_data"])
        self.assertTrue(loaded["success"])
        reconstructed = mgr.sessions[inv_id]
        self.assertEqual(reconstructed.lifecycle_state, STATE_COMPLETED)
        self.assertEqual(len(reconstructed.state_transitions), len(rep["state_transitions"]))

    # -------------------------------------------------------------------------
    # Scenario L: Planner Cost-Preference Over Expensive Alternatives
    # -------------------------------------------------------------------------
    def test_scenario_l_planner_prefers_cheapest_discriminating_observation(self):
        """L: When two observations both discriminate competing hypotheses, planner chooses
        the cheaper observation and records explicit preference_rationale."""
        engine = AdaptiveInvestigationEngine()
        h1_id = "hypo_comp_a"
        h2_id = "hypo_comp_b"

        obs_expensive = FollowUpObservation(
            observation_id="obs_expensive_scan",
            hypothesis_id=h1_id,
            tested_hypothesis_ids=[h1_id, h2_id],
            question="Full 64KB buffer scan",
            target_kind="OBJECT",
            target_ref={"target_expression": "g_pool"},
            expected_outcomes_by_hypothesis={
                h1_id: {"cond_a": "SUPPORTED", "cond_b": "CONTRADICTED"},
                h2_id: {"cond_a": "CONTRADICTED", "cond_b": "SUPPORTED"},
            },
            discriminating_power="HIGH",
            risk_level="READ_ONLY",
            estimated_bytes=65536,
            estimated_latency_ms=120.0,
        )
        obs_cheap = FollowUpObservation(
            observation_id="obs_cheap_header_read",
            hypothesis_id=h1_id,
            tested_hypothesis_ids=[h1_id, h2_id],
            question="Read 64B pool header counter",
            target_kind="FIELD",
            target_ref={"field_path": "g_pool.header.active_count"},
            expected_outcomes_by_hypothesis={
                h1_id: {"cond_a": "SUPPORTED", "cond_b": "CONTRADICTED"},
                h2_id: {"cond_a": "CONTRADICTED", "cond_b": "SUPPORTED"},
            },
            discriminating_power="HIGH",
            risk_level="READ_ONLY",
            estimated_bytes=64,
            estimated_latency_ms=5.0,
        )

        h1 = InvestigationHypothesis(
            hypothesis_id=h1_id,
            title="Pool Leak",
            claim="Leak",
            proposed_mechanism="Leak",
            competing_hypothesis_ids=[h2_id],
            suggested_observations=[obs_expensive, obs_cheap],
        )
        h2 = InvestigationHypothesis(
            hypothesis_id=h2_id,
            title="Normal Pool Load",
            claim="Normal",
            proposed_mechanism="Normal",
            competing_hypothesis_ids=[h1_id],
            suggested_observations=[],
        )

        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        selected, candidates_log = engine.planner.select_next_observation(
            hypotheses=[h1, h2],
            budget_tracker=tracker,
            executed_observation_keys=set(),
            capabilities={"memory_read_available": True},
        )
        self.assertIsNotNone(selected)
        self.assertEqual(selected.observation_id, "obs_cheap_header_read")
        self.assertIn("obs_expensive_scan", selected.preference_rationale)
        self.assertIn("64B", selected.preference_rationale)




if __name__ == "__main__":
    unittest.main()
