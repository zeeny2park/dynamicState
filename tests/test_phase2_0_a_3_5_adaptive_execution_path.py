# -*- coding: utf-8 -*-
"""Phase 2.0-A.3.5 — Adaptive Investigation Execution-Path Verification Suite.

Validates the complete 7-step Adaptive Investigation pipeline:
1. User request -> diagnostic recipe selection
2. Initial process inspection -> candidate problem identification
3. Evidence-driven scope narrowing
4. Variable/object/memory investigation
5. Hypothesis generation and deterministic validation
6. Finding confidence and evidence provenance
7. Investigation termination and root-cause report generation

Proves that a vague user request (e.g. "이 프로세스에 문제가 있는지 검사해주세요" or
"check whether this process has a problem") produces an evidence-grounded, reproducible
investigation without requiring manual variable selection or diagnostic step selection.
"""

import os
import tempfile
import unittest
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

from extractor.adaptive_engine import (
    AdaptiveInvestigationEngine,
    DIAG_CONFIRMED,
    DIAG_NO_ISSUE_DETECTED,
    DOMAIN_CONCURRENCY,
    HYP_STATE_CONTRADICTED,
    HYP_STATE_SUPPORTED,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    STATE_COMPLETED,
    STATE_FINALIZATION,
    STATE_FOLLOW_UP_PLANNING,
    STATE_HYPOTHESIS_FORMATION,
    STATE_HYPOTHESIS_UPDATE,
    STATE_INITIAL_TRIAGE,
    STATE_OBSERVATION,
    STATE_TARGET_VALIDATION,
    STOP_SUFFICIENT_EVIDENCE,
)
from extractor.evidence_adapter import (
    COLLECTION_STATUS_ABSTAIN,
    COLLECTION_STATUS_COLLECTED,
    RESULT_NEW_EVIDENCE,
    RESULT_OBSERVATION_FAILED,
)
from extractor.evidence_ledger import (
    issue_live_capture_receipt,
    setup_test_capture_authorities,
    reset_capture_authorities,
)
from extractor.hypothesis import (
    FollowUpObservation,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    InvestigationHypothesis,
    TARGET_KIND_FIELD,
    TARGET_KIND_THREAD,
)
from extractor.investigation import (
    InvestigationManager,
    InvestigationSession,
)
from extractor.target_adapter import LocalTargetAdapter, ReadOnlyTargetAdapter
from extractor.watch_session import WatchSessionManager


class TestPhase20A35AdaptiveExecutionPath(unittest.TestCase):
    """End-to-end verification of Phase 2.0-A.3.5 Adaptive Investigation execution path."""

    @classmethod
    def setUpClass(cls):
        cls.signer, cls.verifier = setup_test_capture_authorities()

    @classmethod
    def tearDownClass(cls):
        reset_capture_authorities()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.corpus_dir = os.path.join(self.temp_dir.name, "corpus")
        os.makedirs(self.corpus_dir, exist_ok=True)
        self.watch_manager = WatchSessionManager(corpus_dir=self.corpus_dir)
        self.inv_manager = InvestigationManager(corpus_dir=self.corpus_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_vague_intent_gateway_routes_to_autonomous_symptom_investigation(self):
        """Vague user requests route via Universal Intent Gateway to 7-stage autonomous investigation."""
        korean_vague_goal = "이 프로세스에 문제가 있는지 검사해주세요."
        english_vague_goal = "check whether this process has a problem"

        # Mock investigate_symptom to verify routing behavior
        with patch.object(self.watch_manager, "investigate_symptom") as mock_investigate:
            mock_investigate.return_value = {
                "symptom_query": korean_vague_goal,
                "root_cause_hypothesis": "[SUPPORTED] Deadlock detected",
                "confidence_score": 0.95,
                "findings": [],
            }

            res = self.watch_manager.ask_runtime_question(
                question=korean_vague_goal,
                pid=1234,
                companion_elf_path="/bin/sample_app",
            )

            self.assertEqual(res["routed_tool"], "runtime_investigate_symptom")
            mock_investigate.assert_called_once()
            call_kwargs = mock_investigate.call_args[1]
            self.assertEqual(call_kwargs["pid"], 1234)
            self.assertEqual(call_kwargs["companion_elf_path"], "/bin/sample_app")
            self.assertEqual(call_kwargs["symptom_query"], korean_vague_goal)

        # Also test English vague goal
        with patch.object(self.watch_manager, "investigate_symptom") as mock_investigate_en:
            mock_investigate_en.return_value = {
                "symptom_query": english_vague_goal,
                "root_cause_hypothesis": "[SUPPORTED] General health inspection clean",
                "confidence_score": 0.90,
                "findings": [],
            }

            res_en = self.watch_manager.ask_runtime_question(
                question=english_vague_goal,
                pid=5678,
                companion_elf_path="/bin/sample_app2",
            )

            self.assertEqual(res_en["routed_tool"], "runtime_investigate_symptom")
            mock_investigate_en.assert_called_once()

    def test_02_seven_stage_adaptive_investigation_end_to_end_execution(self):
        """End-to-end execution of all 7 adaptive investigation stages from vague request."""
        engine = AdaptiveInvestigationEngine(watch_manager=self.watch_manager)

        fixture = {
            "target_identity": {
                "pid": 5500,
                "binary": "/bin/worker_daemon",
                "build_id": "aa11bb22cc33",
            },
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
                                "tid": 5501,
                                "name": "worker_th",
                                "state": "D",
                                "suspicious": True,
                                "top_function": "__lll_lock_wait",
                                "lock_address": "0x600010",
                                "progress_expression": "g_worker_progress",
                            }
                        ],
                    },
                }
            ],
        }

        def follow_up_exec(obs: FollowUpObservation, epoch: int) -> Dict[str, Any]:
            return {
                "success": True,
                "bytes_read": 256,
                "observed_condition": "stalled_owner_or_deadlock_confirmed",
                "deadlock_detected": True,
                "observation": "Lock 0x600010 held by TID 5502.",
            }

        rcpt = issue_live_capture_receipt(
            session_id="sess_adaptive_7stages",
            pid=5500,
            executable_path="/bin/worker_daemon",
        )

        vague_goal = "이 프로세스에 문제가 있는지 검사해주세요."
        res = engine.investigate_process_health(
            goal=vague_goal,
            pid=5500,
            companion_elf_path="/bin/worker_daemon",
            fixture_data=fixture,
            follow_up_executor=follow_up_exec,
            capture_receipt=rcpt,
        )

        # 1. State machine completed cleanly
        self.assertEqual(res["lifecycle_state"], STATE_COMPLETED)
        self.assertEqual(res["verdict"], DIAG_CONFIRMED)
        self.assertEqual(res["stop_reason"], STOP_SUFFICIENT_EVIDENCE)

        # 2. Verify state transitions traversed all key stages
        transitions = [t["to_state"] for t in res["state_transitions"]]
        self.assertIn(STATE_TARGET_VALIDATION, transitions)
        self.assertIn(STATE_INITIAL_TRIAGE, transitions)
        self.assertIn(STATE_HYPOTHESIS_FORMATION, transitions)
        self.assertIn(STATE_FOLLOW_UP_PLANNING, transitions)
        self.assertIn(STATE_OBSERVATION, transitions)
        self.assertIn(STATE_HYPOTHESIS_UPDATE, transitions)
        self.assertIn(STATE_FINALIZATION, transitions)
        self.assertIn(STATE_COMPLETED, transitions)

        # 3. Competing hypotheses formed and discriminated
        hypos = res["competing_hypotheses"]
        self.assertGreaterEqual(len(hypos), 2)
        lock_hypo = next(h for h in hypos if "hypo_thread_lock_" in h["hypothesis_id"])
        idle_hypo = next(h for h in hypos if "hypo_thread_idle_" in h["hypothesis_id"])

        self.assertEqual(lock_hypo["validation_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertEqual(idle_hypo["validation_status"], HYPOTHESIS_STATUS_CONTRADICTED)

        # 4. Zero-CDN report HTML and JSON generated
        self.assertTrue(res["report_html"].startswith("<!DOCTYPE html>"))
        self.assertIn("Process Health Investigation", res["report_html"])
        self.assertTrue(res["report_json"])

    def test_03_investigate_symptom_elevates_adaptive_summary(self):
        """investigate_symptom elevates final diagnosis, hypothesis state, and confidence from adaptive engine."""
        with patch.object(self.watch_manager, "auto_triage_incident") as mock_triage, \
             patch.object(self.watch_manager, "build_dependency_graph") as mock_dep, \
             patch.object(self.watch_manager, "scan_heap_objects") as mock_heap, \
             patch.object(self.watch_manager, "correlate_source_and_state") as mock_src, \
             patch("extractor.adaptive_engine.AdaptiveInvestigationEngine.investigate_process_health") as mock_adap:

            mock_triage.return_value = {"findings": [], "health_score": 70}
            mock_dep.return_value = {"nodes_count": 0, "edges_count": 0, "causal_chains": []}
            mock_heap.return_value = {"leaked_candidates_count": 0}
            mock_src.return_value = {"snippets": []}

            mock_adap.return_value = {
                "final_diagnosis": "Deadlock cycle verified between thread 1 and thread 2 on mutex 0x1000",
                "hypothesis_state": "SUPPORTED",
                "confidence_score": 0.96,
                "recommended_next_steps": [{"action": "Release mutex 0x1000 before acquiring secondary lock"}],
            }

            res = self.watch_manager.investigate_symptom(
                pid=9999,
                companion_elf_path="/bin/deadlock_test",
                symptom_query="왜 멈췄지?",
            )

            # Hypothesis and confidence elevated from adaptive investigation
            self.assertEqual(
                res["root_cause_hypothesis"],
                "[SUPPORTED] Deadlock cycle verified between thread 1 and thread 2 on mutex 0x1000"
            )
            self.assertEqual(res["confidence_score"], 0.96)
            self.assertIn("Release mutex 0x1000 before acquiring secondary lock", res["remediation_steps"])

    def test_04_execute_observation_contradiction_and_support_from_snapshot(self):
        """execute_observation deterministically supports or contradicts hypothesis based on snapshot values."""
        inv_session = self.inv_manager.start_investigation(goal="Field inspection test")
        inv_id = inv_session["investigation_id"]
        session: InvestigationSession = self.inv_manager.sessions[inv_id]

        # Attach mock active snapshot with object fields
        mock_snapshot = {
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_worker_1",
                        "fields": [
                            {"name": "worker_status", "value": 3},  # 3 = ERROR
                            {"name": "processed_count", "value": 100},
                        ],
                    }
                ]
            }
        }
        session.active_snapshot = mock_snapshot

        # Hypothesis 1: worker_status is IDLE (expected 0) -> Should CONTRADICT because actual is 3
        obs_contradict = FollowUpObservation(
            observation_id="obs_status_idle",
            question="Check if worker_status is 0 (IDLE)",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="obj_worker_1.worker_status",
            target_ref={
                "field_path": "worker_status",
                "expected_value": 0,  # Expected 0, actual is 3
            },
        )
        hypo1 = InvestigationHypothesis(
            hypothesis_id="hypo_worker_idle",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="worker_status",
            suggested_observations=[obs_contradict],
        )
        session.hypotheses.append(hypo1)

        res1 = self.inv_manager.execute_observation(inv_id, "obs_status_idle")
        self.assertTrue(res1["success"])
        # Outcome must be CONTRADICTED because 3 != 0
        ev1 = session.ledger.get_record(obs_contradict.result_evidence_id)
        self.assertEqual(ev1.details["outcome"], "CONTRADICTED")
        self.assertEqual(hypo1.validation_status, HYPOTHESIS_STATUS_CONTRADICTED)

        # Hypothesis 2: worker_status is ERROR (expected 3) -> Should SUPPORT because actual is 3
        obs_support = FollowUpObservation(
            observation_id="obs_status_err",
            question="Check if worker_status is 3 (ERROR)",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="obj_worker_1.worker_status",
            target_ref={
                "field_path": "worker_status",
                "expected_value": 3,  # Expected 3, actual is 3
            },
        )
        hypo2 = InvestigationHypothesis(
            hypothesis_id="hypo_worker_err",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="worker_status",
            suggested_observations=[obs_support],
        )
        session.hypotheses.append(hypo2)

        res2 = self.inv_manager.execute_observation(inv_id, "obs_status_err")
        self.assertTrue(res2["success"])
        ev2 = session.ledger.get_record(obs_support.result_evidence_id)
        self.assertEqual(ev2.details["outcome"], "SUPPORTED")
        self.assertEqual(hypo2.validation_status, HYPOTHESIS_STATUS_SUPPORTED)

    def test_05_failed_observation_sets_abstain_and_never_falsely_validates(self):
        """Failed observation sets COLLECTION_STATUS_ABSTAIN and never grants false support."""
        inv_session = self.inv_manager.start_investigation(goal="Failed observation safety test")
        inv_id = inv_session["investigation_id"]
        session: InvestigationSession = self.inv_manager.sessions[inv_id]

        obs_fail = FollowUpObservation(
            observation_id="obs_read_timeout",
            question="Inspect restricted memory region",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="secret_ptr",
            target_ref={
                "field_path": "secret_ptr",
                "force_failed": True,  # Simulates read error / timeout
            },
        )
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_secret_tamper",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="secret_ptr",
            suggested_observations=[obs_fail],
        )
        session.hypotheses.append(hypo)

        res = self.inv_manager.execute_observation(inv_id, "obs_read_timeout")
        # Read failed -> execution returns failure dictionary
        self.assertFalse(res["success"])
        self.assertTrue(res.get("failed"))
        self.assertEqual(res.get("result_category"), RESULT_OBSERVATION_FAILED)

        # Observation status is failed, executed is False
        self.assertFalse(obs_fail.executed)
        self.assertEqual(obs_fail.status, "failed")

        # Hypothesis must NOT be supported or validated
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_PROPOSED)
        self.assertEqual(len(hypo.supporting_evidence_ids), 0)

    def test_06_deterministic_replay_and_provenance_integrity(self):
        """Identical fixture and observations produce identical verdicts and state transitions."""
        engine1 = AdaptiveInvestigationEngine(watch_manager=self.watch_manager)
        engine2 = AdaptiveInvestigationEngine(watch_manager=self.watch_manager)

        fixture = {
            "target_identity": {
                "pid": 6000,
                "binary": "/bin/app_rep",
                "build_id": "bb22cc33dd44",
            },
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
                                "tid": 6001,
                                "name": "worker",
                                "state": "D",
                                "suspicious": True,
                                "top_function": "__lll_lock_wait",
                                "lock_address": "0x800010",
                            }
                        ],
                    },
                }
            ],
        }

        def follow_up(obs: FollowUpObservation, epoch: int) -> Dict[str, Any]:
            return {
                "success": True,
                "bytes_read": 256,
                "observed_condition": "stalled_owner_or_deadlock_confirmed",
                "deadlock_detected": True,
                "observation": "Lock 0x800010 held by TID 6002.",
            }

        rcpt1 = issue_live_capture_receipt(session_id="rep_1", pid=6000, executable_path="/bin/app_rep")
        res1 = engine1.investigate_process_health(
            goal="이 프로세스에 문제가 있는지 검사해주세요.",
            pid=6000,
            companion_elf_path="/bin/app_rep",
            fixture_data=fixture,
            follow_up_executor=follow_up,
            capture_receipt=rcpt1,
        )

        rcpt2 = issue_live_capture_receipt(session_id="rep_2", pid=6000, executable_path="/bin/app_rep")
        res2 = engine2.investigate_process_health(
            goal="이 프로세스에 문제가 있는지 검사해주세요.",
            pid=6000,
            companion_elf_path="/bin/app_rep",
            fixture_data=fixture,
            follow_up_executor=follow_up,
            capture_receipt=rcpt2,
        )

        self.assertEqual(res1["verdict"], res2["verdict"])
        self.assertEqual(res1["lifecycle_state"], res2["lifecycle_state"])
        self.assertEqual(res1["stop_reason"], res2["stop_reason"])
        trans1 = [t["to_state"] for t in res1["state_transitions"]]
        trans2 = [t["to_state"] for t in res2["state_transitions"]]
        self.assertEqual(trans1, trans2)

    def test_07_mcp_server_universal_gateway_integration(self):
        """scripts/mcp_server.py runtime_ask handles vague natural-language questions end-to-end."""
        import json
        from scripts.mcp_server import runtime_ask

        # Mock the underlying watch session investigate_symptom
        with patch("scripts.mcp_server.runtime.watch_session_manager.investigate_symptom") as mock_inv:
            mock_inv.return_value = {
                "pid": 8000,
                "symptom_query": "이 프로세스에 문제가 있는지 검사해주세요",
                "root_cause_hypothesis": "[SUPPORTED] Worker lock contention",
                "confidence_score": 0.92,
                "findings": [{"category": "LOCK", "title": "Lock wait", "severity": "HIGH"}],
                "adaptive_investigation": {"final_diagnosis": "Lock contention on mutex"},
            }

            raw_out = runtime_ask(
                question="이 프로세스에 문제가 있는지 검사해주세요",
                pid=8000,
                companion_elf="/bin/worker_app",
            )
            data = json.loads(raw_out)
            self.assertEqual(data["routed_tool"], "runtime_investigate_symptom")
            self.assertEqual(data["root_cause_hypothesis"], "[SUPPORTED] Worker lock contention")
            self.assertEqual(data["confidence_score"], 0.92)

    def test_08_llm_hallucination_and_overclaim_protection_on_observation(self):
        """Unverified caller claims of VALIDATED or causal proof are sanitized down to SUPPORTED."""
        inv_session = self.inv_manager.start_investigation(goal="LLM protection test")
        inv_id = inv_session["investigation_id"]
        session: InvestigationSession = self.inv_manager.sessions[inv_id]

        obs = FollowUpObservation(
            observation_id="obs_caller_claim",
            question="Verify root cause mechanism",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="obj.field",
        )
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_llm_claim",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="obj.field",
            suggested_observations=[obs],
        )
        session.hypotheses.append(hypo)

        # Caller attempts to submit fabricated VALIDATED claim without cryptographic verifier token
        fake_result = {
            "outcome": "VALIDATED",
            "causal_proof": True,
            "verified_transition": True,
            "details": {
                "outcome": "VALIDATED",
                "causal_proof": True,
                "verified_writer": True,
            },
        }

        res = self.inv_manager.execute_observation(inv_id, "obs_caller_claim", result_data=fake_result)
        self.assertTrue(res["success"])

        ev = session.ledger.get_record(obs.result_evidence_id)
        # Outcome MUST be demoted to SUPPORTED and flagged as unverified caller claim
        self.assertEqual(ev.details["outcome"], "SUPPORTED")
        self.assertTrue(ev.details.get("unverified_caller_claim"))
        self.assertFalse(ev.details.get("causal_proof"))
        self.assertFalse(ev.details.get("verified_transition"))
        # Hypothesis MUST NOT be VALIDATED
        self.assertNotEqual(hypo.validation_status, "VALIDATED")
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_SUPPORTED)


if __name__ == "__main__":
    unittest.main()
