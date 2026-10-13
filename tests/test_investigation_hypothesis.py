"""Tests for Structured Hypothesis Generation, Observation Planning, and Validation Engine.

Verifies:
1. Hypothesis & observation data models (serialization, enums, post-init invariants)
2. Deterministic hypothesis generation from state diffs and scalar anomalies
3. Discriminative follow-up observation planning with expected outcomes
4. Strict separation between static candidates and validated causal functions
5. Capture quality trust boundaries (COMPLETE vs PARTIAL/NON_ATOMIC vs FAILED/INVALID)
6. Hypothesis validation state machine (PROPOSED, SUPPORTED, CONTRADICTED, INCONCLUSIVE, VALIDATED)
7. Multi-hop cycle detection and duplicate evidence rejection
8. Deterministic transition causal upgrade (VALIDATED + VALIDATED_CAUSAL_FUNCTION)
9. InvestigationManager integration, report synthesis, and safety constraints
10. Agent Runtime Protocol (ARP) action dispatch and Web API adapter endpoints
"""

import json
import unittest
from typing import Any, Dict, List
from unittest.mock import MagicMock

from extractor.agent_models import AgentAction
from extractor.agent_runtime import AgentRuntime
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_HYPOTHESIS,
    EVIDENCE_TYPE_OBJECT_STATE,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
)
from extractor.hypothesis import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_SPECULATIVE,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    TARGET_KIND_COMPARISON,
    TARGET_KIND_FIELD,
    TARGET_KIND_THREAD,
    DeterministicHypothesisGenerator,
    FollowUpObservation,
    HypothesisValidator,
    InvestigationHypothesis,
)
from extractor.investigation import (
    InvestigationFinding,
    InvestigationManager,
    InvestigationSession,
)
from extractor.web.server import WebApiAdapter


class TestHypothesisModels(unittest.TestCase):
    """Test data structures, enums, and serialization for hypotheses and observations."""

    def test_follow_up_observation_lifecycle(self):
        obs = FollowUpObservation(
            observation_id="obs_001",
            hypothesis_id="hypo_001",
            question="Does field X change during transition?",
            target_kind=TARGET_KIND_FIELD,
            target_ref={"field_path": "obj.counter"},
            discriminating_criteria="Compare across snapshots",
            expected_outcomes={"mutated": "SUPPORTED", "unchanged": "CONTRADICTED"},
            safety_constraints=["Read-only inspection"],
        )
        self.assertEqual(obs.observation_id, "obs_001")
        self.assertEqual(obs.discriminating_power, "HIGH")
        self.assertFalse(obs.executed)

        # Round-trip serialization
        data = obs.to_dict()
        self.assertEqual(data["question"], "Does field X change during transition?")
        restored = FollowUpObservation.from_dict(data)
        self.assertEqual(restored.observation_id, obs.observation_id)
        self.assertEqual(restored.expected_outcomes, obs.expected_outcomes)

        # Invalid target kind
        with self.assertRaises(ValueError):
            FollowUpObservation(
                observation_id="obs_bad",
                hypothesis_id="hypo_001",
                question="test",
                target_kind="INVALID_KIND",
                target_ref={},
                discriminating_criteria="",
                expected_outcomes={},
            )

    def test_investigation_hypothesis_serialization(self):
        obs = FollowUpObservation(
            observation_id="obs_10",
            hypothesis_id="hypo_10",
            question="Check stack",
            target_kind=TARGET_KIND_THREAD,
            target_ref={"thread_id": "1"},
            discriminating_criteria="Look for worker fn",
            expected_outcomes={"found": "SUPPORTED"},
        )
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_10",
            investigation_id="inv_test",
            title="Counter Increment",
            claim="counter was incremented by worker_fn",
            proposed_mechanism="Worker thread mutated counter from 42 to 100",
            supporting_evidence_ids=["ev_1"],
            confidence=CONFIDENCE_MEDIUM,
            confidence_rationale="Grounded in COMPLETE diff",
            function_candidates=[{
                "function_name": "worker_fn",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }],
            suggested_observations=[obs],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )
        self.assertEqual(len(hypo.status_history), 1)
        self.assertEqual(hypo.status_history[0]["to_status"], HYPOTHESIS_STATUS_PROPOSED)

        # Round-trip
        data = hypo.to_dict()
        restored = InvestigationHypothesis.from_dict(data)
        self.assertEqual(restored.hypothesis_id, "hypo_10")
        self.assertEqual(len(restored.suggested_observations), 1)
        self.assertEqual(restored.suggested_observations[0].observation_id, "obs_10")
        self.assertEqual(restored.function_candidates[0]["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)

        # Invalid status & confidence
        with self.assertRaises(ValueError):
            InvestigationHypothesis(
                hypothesis_id="h_bad",
                investigation_id="inv",
                title="t",
                claim="c",
                proposed_mechanism="m",
                validation_status="INVALID_STATUS",
            )
        with self.assertRaises(ValueError):
            InvestigationHypothesis(
                hypothesis_id="h_bad",
                investigation_id="inv",
                title="t",
                claim="c",
                proposed_mechanism="m",
                confidence="SUPER_HIGH",
            )


class TestDeterministicHypothesisGeneration(unittest.TestCase):
    """Test deterministic generation from comparative diffs, observations, and capture qualities."""

    def _create_mock_session(self, findings, cap_status="COMPLETE", consistency_level="STOPPED"):
        session = MagicMock()
        session.investigation_id = "inv_sess_1"
        session.findings = findings
        session.comparison_results = []
        session.stages = {
            "capture_quality": {
                "status": cap_status,
                "details": {
                    "consistency_level": consistency_level,
                    "consistency_classification": consistency_level,
                },
            }
        }
        return session

    def test_state_diff_mutation_hypothesis_generation(self):
        finding = InvestigationFinding(
            finding_id="fnd_1",
            category="fact",
            title="State transition: counter changed 42 -> 100",
            description="Value mutated",
            confidence="high",
            evidence_ids=["ev_diff_1"],
            object_id="obj_root",
            field_name="counter",
            c_type_path="AppState.counter",
            before_value=42,
            after_value=100,
            function_candidates=[{
                "function_name": "increment_counter",
                "evidence_level": "static",
                "source_file": "app.cpp",
                "source_line": 25,
            }],
        )
        session = self._create_mock_session([finding], cap_status="COMPLETE")

        gen = DeterministicHypothesisGenerator()
        hypotheses = gen.generate(session)

        self.assertEqual(len(hypotheses), 1)
        hypo = hypotheses[0]
        self.assertIn("State Transition Mutation", hypo.title)
        self.assertIn("42", hypo.claim)
        self.assertIn("100", hypo.claim)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_PROPOSED)
        self.assertEqual(hypo.confidence, CONFIDENCE_MEDIUM)
        self.assertEqual(hypo.supporting_evidence_ids, ["ev_diff_1"])

        # Candidate function verification: static candidate NEVER automatically confirmed
        self.assertEqual(len(hypo.function_candidates), 1)
        fc = hypo.function_candidates[0]
        self.assertEqual(fc["function_name"], "increment_counter")
        self.assertEqual(fc["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(fc["confirmed_root_cause"])
        self.assertIn("not confirmed root-cause function", fc["tier_limitation"])

        # Follow-up observation plans
        self.assertGreaterEqual(len(hypo.suggested_observations), 2)
        obs_kinds = {obs.target_kind for obs in hypo.suggested_observations}
        self.assertIn(TARGET_KIND_THREAD, obs_kinds)
        self.assertIn(TARGET_KIND_COMPARISON, obs_kinds)

    def test_non_atomic_capture_degrades_confidence_and_adds_caveat(self):
        finding = InvestigationFinding(
            finding_id="fnd_2",
            category="fact",
            title="State transition: flags changed 0 -> 1",
            description="Value mutated",
            confidence="high",
            evidence_ids=["ev_diff_2"],
            object_id="obj_root",
            field_name="flags",
            c_type_path="AppState.flags",
            before_value=0,
            after_value=1,
            function_candidates=[],
        )
        session = self._create_mock_session([finding], cap_status="PARTIAL", consistency_level="NON_ATOMIC")

        gen = DeterministicHypothesisGenerator()
        hypotheses = gen.generate(session)

        self.assertEqual(len(hypotheses), 1)
        hypo = hypotheses[0]
        self.assertEqual(hypo.confidence, CONFIDENCE_LOW)
        self.assertIn("NON_ATOMIC", hypo.confidence_rationale)
        self.assertTrue(any("NON_ATOMIC" in a for a in hypo.assumptions))

    def test_untrusted_capture_caps_hypothesis_at_inconclusive(self):
        finding = InvestigationFinding(
            finding_id="fnd_3",
            category="fact",
            title="State transition: val changed 10 -> 20",
            description="Value mutated",
            evidence_ids=["ev_diff_3"],
            object_id="obj_root",
            field_name="val",
            c_type_path="AppState.val",
            before_value=10,
            after_value=20,
        )
        session = self._create_mock_session([finding], cap_status="FAILED")

        gen = DeterministicHypothesisGenerator()
        hypotheses = gen.generate(session)

        self.assertEqual(len(hypotheses), 1)
        hypo = hypotheses[0]
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_INCONCLUSIVE)
        self.assertEqual(hypo.confidence, CONFIDENCE_LOW)
        self.assertIn("FAILED", hypo.confidence_rationale)

    def test_scalar_anomaly_invariant_hypothesis_generation(self):
        finding = InvestigationFinding(
            finding_id="fnd_4",
            category="fact",
            title="Observed status_flag = 7",
            description="Scalar value observed",
            evidence_ids=["ev_fact_4"],
            object_id="obj_cfg",
            field_name="status_flag",
            c_type_path="Config.status_flag",
            before_value=None,
            after_value=None,
            observed_value=7,
        )
        session = self._create_mock_session([finding], cap_status="COMPLETE")

        gen = DeterministicHypothesisGenerator()
        hypotheses = gen.generate(session)

        self.assertEqual(len(hypotheses), 1)
        hypo = hypotheses[0]
        self.assertIn("Potential Dynamic Invariant", hypo.title)
        self.assertIn("7", hypo.claim)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_PROPOSED)


class TestHypothesisValidator(unittest.TestCase):
    """Test hypothesis evaluation, cycle detection, duplication guards, and causal elevation."""

    def setUp(self):
        self.ledger = EvidenceLedger()

    def test_contradiction_immediately_demotes_to_contradicted(self):
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_c1",
            investigation_id="inv_1",
            title="Claim",
            claim="Field X mutated due to event E",
            proposed_mechanism="Event E wrote 100",
            supporting_evidence_ids=["ev_supp_1"],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
            confidence=CONFIDENCE_MEDIUM,
        )
        rec_supp = EvidenceRecord(
            evidence_id="ev_supp_1",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="test",
            observation="Field X was 100",
            capture_quality={"completeness": "COMPLETE"},
        )
        self.ledger.add_record(rec_supp)

        # Add contradicting evidence
        rec_contra = EvidenceRecord(
            evidence_id="ev_contra_1",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="test",
            observation="Observed mismatch: Event E did not execute; Field X changed spontaneously",
            details={"outcome": "CONTRADICTED"},
            capture_quality={"completeness": "COMPLETE"},
        )
        self.ledger.add_record(rec_contra)

        res = HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_contra)
        self.assertEqual(res.to_status, HYPOTHESIS_STATUS_CONTRADICTED)
        self.assertEqual(res.confidence, CONFIDENCE_HIGH)
        self.assertTrue(res.status_changed)
        self.assertIn("Contradicted by 1", res.reason)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_CONTRADICTED)
        self.assertEqual(len(hypo.status_history), 2)
        self.assertEqual(hypo.status_history[-1]["to_status"], HYPOTHESIS_STATUS_CONTRADICTED)

    def test_multi_hop_cycle_detection_prevents_recursive_reasoning(self):
        # Create cycle: ev_1 -> ev_2 -> ev_3 -> ev_1
        rec1 = EvidenceRecord(
            evidence_id="ev_cyc_1",
            evidence_type=EVIDENCE_TYPE_HYPOTHESIS,
            nature=NATURE_INFERENCE,
            source="test",
            observation="Node 1",
            parent_evidence_ids=["ev_cyc_2"],
        )
        rec2 = EvidenceRecord(
            evidence_id="ev_cyc_2",
            evidence_type=EVIDENCE_TYPE_HYPOTHESIS,
            nature=NATURE_INFERENCE,
            source="test",
            observation="Node 2",
            parent_evidence_ids=["ev_cyc_3"],
        )
        rec3 = EvidenceRecord(
            evidence_id="ev_cyc_3",
            evidence_type=EVIDENCE_TYPE_HYPOTHESIS,
            nature=NATURE_INFERENCE,
            source="test",
            observation="Node 3",
            parent_evidence_ids=["ev_cyc_1"],  # Back edge to ev_cyc_1!
        )
        self.ledger._records = [rec1, rec2, rec3]
        self.ledger._by_id = {r.evidence_id: r for r in [rec1, rec2, rec3]}

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_cyc",
            investigation_id="inv_1",
            title="Cyclic Claim",
            claim="Cyclic reasoning",
            proposed_mechanism="Cycle",
            supporting_evidence_ids=["ev_cyc_1"],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )

        res = HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec1)
        self.assertTrue(res.cycle_detected)
        self.assertEqual(res.to_status, HYPOTHESIS_STATUS_INCONCLUSIVE)
        self.assertIn("Cyclic evidence provenance detected", res.reason)

    def test_duplicate_evidence_does_not_count_as_independent_corroboration(self):
        rec1 = EvidenceRecord(
            evidence_id="ev_dup_1",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="unit_test",
            observation="Counter is 42",
            details={"val": 42},
            capture_quality={"completeness": "COMPLETE"},
        )
        self.ledger.add_record(rec1)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_dup",
            investigation_id="inv_1",
            title="Dup Test",
            claim="Counter is 42",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_dup_1"],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )

        # Duplicate record with new ID but identical observation, type, source, and details
        rec2 = EvidenceRecord(
            evidence_id="ev_dup_2",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="unit_test",
            observation="Counter is 42",
            details={"val": 42},
            capture_quality={"completeness": "COMPLETE"},
        )
        self.ledger.add_record(rec2)

        res = HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec2)
        self.assertTrue(res.is_duplicate)
        # Should NOT add to supporting evidence list
        self.assertNotIn("ev_dup_2", hypo.supporting_evidence_ids)

    def test_deterministic_transition_elevates_to_validated_and_promotes_function(self):
        rec_supp = EvidenceRecord(
            evidence_id="ev_det_1",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="test",
            session_id=self.ledger.session_id,
            observation="Deterministic transition reproduced 42 -> 100",
            details={
                "target_function": "mutate_state",
                "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        self.ledger.add_record(rec_supp)
        self.ledger.attest_causal_proof("ev_det_1", target_function="mutate_state")

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_valid",
            investigation_id=self.ledger.session_id,
            title="Valid Claim",
            claim="Function mutate_state caused counter transition",
            proposed_mechanism="mutate_state wrote counter=100",
            supporting_evidence_ids=["ev_det_1"],
            function_candidates=[{
                "function_name": "mutate_state",
                "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED,
                "confirmed_root_cause": False,
            }],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )

        res = HypothesisValidator.evaluate(
            hypo,
            self.ledger,
            deterministic_transition_verified=True,
            proof_evidence_id="ev_det_1",
        )

        self.assertEqual(res.to_status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(res.confidence, CONFIDENCE_HIGH)
        self.assertIn("Deterministic transition verified causal relationship", res.reason)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_VALIDATED)

        # Candidate upgraded to VALIDATED_CAUSAL_FUNCTION
        fc = hypo.function_candidates[0]
        self.assertEqual(fc["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertTrue(fc["confirmed_root_cause"])

    def test_partial_capture_blocks_upgrade_to_validated(self):
        rec_partial = EvidenceRecord(
            evidence_id="ev_part_1",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="test",
            observation="Partial transition observed",
            capture_quality={"completeness": "PARTIAL"},
        )
        self.ledger.add_record(rec_partial)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_part",
            investigation_id="inv_1",
            title="Partial Claim",
            claim="Claim under partial capture",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_part_1"],
            function_candidates=[{
                "function_name": "worker_fn",
                "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED,
                "confirmed_root_cause": False,
            }],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )

        # Even with deterministic_transition_verified=True, PARTIAL capture caps at SUPPORTED
        res = HypothesisValidator.evaluate(
            hypo,
            self.ledger,
            deterministic_transition_verified=True,
        )
        self.assertEqual(res.to_status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertNotEqual(res.to_status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertIn("capped at SUPPORTED", res.reason)
        # Function must NOT be promoted to validated causal
        self.assertFalse(hypo.function_candidates[0]["confirmed_root_cause"])


class TestInvestigationManagerHypothesisIntegration(unittest.TestCase):
    """Test InvestigationManager integration, follow-up observation execution, and report generation."""

    def setUp(self):
        self.manager = InvestigationManager()

    def test_full_investigation_lifecycle_with_hypotheses_and_observations(self):
        # 1. Start investigation
        start_res = self.manager.start_investigation(
            goal="Analyze root cause of counter discrepancy",
        )
        inv_id = start_res["investigation_id"]
        session = self.manager.sessions[inv_id]

        # 2. Add finding to session
        finding = InvestigationFinding(
            finding_id="fnd_test",
            category="fact",
            title="Counter mutated from 42 to 100",
            description="Mutation observed",
            evidence_ids=["ev_start_1"],
            object_id="obj_1",
            field_name="counter",
            c_type_path="State.counter",
            before_value=42,
            after_value=100,
            function_candidates=[{
                "function_name": "update_counter",
                "evidence_level": "static",
            }],
        )
        session.findings.append(finding)

        # 3. Execute synthesis stage to generate hypotheses
        self.manager._execute_stage_synthesis(session)
        self.assertGreaterEqual(len(session.hypotheses), 1)

        # 4. Query hypotheses via get_hypotheses API
        hypo_list = self.manager.get_hypotheses(inv_id)
        self.assertGreaterEqual(len(hypo_list), 1)
        hypo = hypo_list[0]
        hypo_id = hypo["hypothesis_id"]
        self.assertEqual(hypo["validation_status"], HYPOTHESIS_STATUS_PROPOSED)

        # Filter by status
        proposed_list = self.manager.get_hypotheses(inv_id, status_filter=HYPOTHESIS_STATUS_PROPOSED)
        self.assertEqual(len(proposed_list), len(hypo_list))
        empty_list = self.manager.get_hypotheses(inv_id, status_filter=HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(len(empty_list), 0)

        # 5. Execute a suggested follow-up observation
        self.assertGreaterEqual(len(hypo["suggested_observations"]), 1)
        obs_id = hypo["suggested_observations"][0]["observation_id"]

        obs_exec_res = self.manager.execute_observation(
            inv_id,
            obs_id,
            result_data={
                "observation": "Call stack contains candidate function update_counter",
                "outcome": "SUPPORTED",
            },
        )
        self.assertTrue(obs_exec_res["success"])
        self.assertEqual(obs_exec_res["observation"]["observation_id"], obs_id)
        self.assertTrue(obs_exec_res["observation"]["executed"])

        # Re-fetch hypothesis: should now be SUPPORTED
        updated_hypo = self.manager.get_hypothesis(inv_id, hypo_id)
        self.assertEqual(updated_hypo["validation_status"], HYPOTHESIS_STATUS_SUPPORTED)

        # 6a. Attempt evaluation with caller-supplied boolean alone (Invariant 3: rejected!)
        unverified_eval = self.manager.evaluate_hypothesis(
            inv_id,
            hypo_id,
            deterministic_transition_verified=True,
        )
        self.assertTrue(unverified_eval["success"])
        self.assertEqual(unverified_eval["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(unverified_eval["transition"]["unverified_claim_rejected"])

        # 6b. Evaluate with verifiable deterministic transition proof evidence
        proof_eid = "ev_proof_full"
        rec_proof = EvidenceRecord(
            evidence_id=proof_eid,
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Deterministic transition reproduced 42 -> 100",
            details={
                "target_function": "update_counter",
                "field_path": "State.counter",
                "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_proof)
        self.manager.attest_causal_proof(
            inv_id,
            proof_eid,
            target_function="update_counter",
            field_path="State.counter",
        )
        eval_res = self.manager.evaluate_hypothesis(
            inv_id,
            hypo_id,
            proof_evidence_id=proof_eid,
            deterministic_transition_verified=True,
        )
        self.assertTrue(eval_res["success"])
        self.assertEqual(eval_res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)

        # 7. Generate report and inspect causal conclusions
        report = self.manager.generate_report(inv_id)
        self.assertIn("hypotheses", report)
        self.assertIn("causal_conclusions", report)
        cc = report["causal_conclusions"]
        self.assertEqual(cc["hypotheses_count"], len(session.hypotheses))
        self.assertEqual(cc["validated_causal_count"], 1)
        self.assertTrue(cc["causal_proof_established"])
        self.assertIsNone(cc["causal_limitation_notice"])

    def test_unauthorized_live_mutation_observation_is_blocked(self):
        start_res = self.manager.start_investigation(
            goal="Safety check",
            authorize_target=False,
        )
        inv_id = start_res["investigation_id"]
        session = self.manager.sessions[inv_id]
        session.safety["target_authorized"] = False  # Explicitly unauthorized

        hypo = InvestigationHypothesis(
            hypothesis_id="h_mut",
            investigation_id=inv_id,
            title="Mutation Hypothesis",
            claim="Claim",
            proposed_mechanism="Mech",
            suggested_observations=[
                FollowUpObservation(
                    observation_id="obs_mut_live",
                    hypothesis_id="h_mut",
                    question="Mutate target live?",
                    target_kind="MUTATION",
                    target_ref={},
                    discriminating_criteria="",
                    expected_outcomes={},
                )
            ],
        )
        session.hypotheses.append(hypo)

        res = self.manager.execute_observation(inv_id, "obs_mut_live")
        self.assertFalse(res["success"])
        self.assertTrue(res.get("blocked", False))
        self.assertIn("Target authorization required", res["error"])


class TestAgentRuntimeAndWebAdapterHypothesisEndpoints(unittest.TestCase):
    """Test Agent Runtime Protocol (ARP) actions and Web API Adapter routes."""

    def setUp(self):
        self.runtime = AgentRuntime()
        self.adapter = WebApiAdapter(self.runtime)

    def test_arp_dispatch_and_adapter_methods(self):
        # 1. Start investigation via runtime
        start_act = AgentAction(
            action="START_INVESTIGATION",
            goal="Test ARP Hypotheses",
        )
        start_res = self.runtime.dispatch_action(start_act)
        self.assertTrue(start_res.success)
        inv_id = start_res.data["investigation_id"]

        session = self.runtime.investigation_manager.sessions[inv_id]
        # Add finding and run synthesis
        session.findings.append(InvestigationFinding(
            finding_id="fnd_arp",
            category="fact",
            title="Diff 1 -> 2",
            description="Mutated",
            evidence_ids=["ev_1"],
            object_id="obj_x",
            field_name="val",
            before_value=1,
            after_value=2,
        ))
        self.runtime.investigation_manager._execute_stage_synthesis(session)
        self.assertGreaterEqual(len(session.hypotheses), 1)
        hypo_id = session.hypotheses[0].hypothesis_id

        # 2. GET_HYPOTHESES via ARP
        get_act = AgentAction(
            action="GET_HYPOTHESES",
            investigation_id=inv_id,
        )
        get_res = self.runtime.dispatch_action(get_act)
        self.assertTrue(get_res.success)
        self.assertIn("hypotheses", get_res.data)
        self.assertEqual(len(get_res.data["hypotheses"]), 1)

        # 3. GET_HYPOTHESES via WebAdapter
        adapt_get = self.adapter.get_hypotheses(inv_id)
        self.assertTrue(adapt_get["success"])
        self.assertIn("hypotheses", adapt_get["data"])
        self.assertEqual(len(adapt_get["data"]["hypotheses"]), 1)

        # 4. EXECUTE_OBSERVATION via ARP
        obs_id = session.hypotheses[0].suggested_observations[0].observation_id
        obs_act = AgentAction(
            action="EXECUTE_OBSERVATION",
            investigation_id=inv_id,
            observation_id=obs_id,
            result_data={"outcome": "SUPPORTED", "observation": "Observed via ARP"},
        )
        obs_res = self.runtime.dispatch_action(obs_act)
        self.assertTrue(obs_res.success)

        # 5a. EVALUATE_HYPOTHESIS with boolean alone is rejected (Invariant 3)
        eval_res_bool = self.adapter.evaluate_hypothesis({
            "investigation_id": inv_id,
            "hypothesis_id": hypo_id,
            "deterministic_transition_verified": True,
        })
        self.assertTrue(eval_res_bool["success"])
        self.assertEqual(eval_res_bool["data"]["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(eval_res_bool["data"]["transition"]["unverified_claim_rejected"])

        # 5b. EVALUATE_HYPOTHESIS with unverified caller new_evidence is disarmed and rejected
        eval_res_injected = self.adapter.evaluate_hypothesis({
            "investigation_id": inv_id,
            "hypothesis_id": hypo_id,
            "new_evidence": {
                "evidence_id": "ev_proof_injected",
                "evidence_type": EVIDENCE_TYPE_COMPARISON,
                "nature": NATURE_OBSERVATION,
                "source": "investigation_observer",
                "observation": "Deterministic transition reproduced 1 -> 2",
                "details": {"verified_transition": True},
                "capture_quality": {"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            },
            "deterministic_transition_verified": True,
        })
        self.assertTrue(eval_res_injected["success"])
        self.assertEqual(eval_res_injected["data"]["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(eval_res_injected["data"]["transition"]["unverified_claim_rejected"])

        # 5c. EVALUATE_HYPOTHESIS with authentic internal verifier attested proof succeeds
        rec_arp_proof = EvidenceRecord(
            evidence_id="ev_proof_arp",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Deterministic transition reproduced 1 -> 2",
            details={
                "field_path": "obj_x.val",
                "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_arp_proof)
        self.runtime.investigation_manager.attest_causal_proof(inv_id, "ev_proof_arp", field_path="obj_x.val")
        eval_res = self.adapter.evaluate_hypothesis({
            "investigation_id": inv_id,
            "hypothesis_id": hypo_id,
            "proof_evidence_id": "ev_proof_arp",
            "deterministic_transition_verified": True,
        })
        self.assertTrue(eval_res["success"])
        self.assertEqual(eval_res["data"]["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)


if __name__ == "__main__":
    unittest.main()
