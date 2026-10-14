"""Phase 12: Evidence-Driven Root Cause Investigation & Conversational Validation Test Suite.

Verifies all 11 core scenarios:
1. Field change with DWARF-linked static candidate.
2. Two competing hypotheses with distinct discriminating observations.
3. Observation outcome supports one hypothesis while contradicting the competing hypothesis.
4. Insufficient or inconclusive evidence produces UNKNOWN/INCONCLUSIVE outcomes without false support.
5. LLM hypothesis generation disarms fabricated evidence IDs and unauthorized status promotions.
6. STATIC_CANDIDATE functions cannot be promoted to VALIDATED_CAUSAL_FUNCTION without verified causal instrumentation.
7. Degraded capture quality (NON_ATOMIC / PARTIAL) strictly caps hypotheses.
8. Caller-controlled trust flags, forged receipts, and invalid PIDs fail closed.
9. Bounded investigation cycle respects iteration limits, observation limits, and safety authorization.
10. Investigation session persistence disarms tampered serialized states upon re-evaluation against the ledger.
11. Complete semantic agreement between ARP actions, REST API endpoints, and web models.
"""

import json
import os
import tempfile
import unittest
from typing import Any, Dict, List
from unittest.mock import MagicMock

from extractor.agent_models import AgentAction, AgentActionResult
from extractor.agent_runtime import AgentRuntime
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_HYPOTHESIS,
    EVIDENCE_TYPE_OBJECT_STATE,
    ControlledExecutionResult,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    compute_receipt_signature,
)
from extractor.hypothesis import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_SPECULATIVE,
    EVIDENCE_CLASSIFICATION_FACT,
    EVIDENCE_CLASSIFICATION_INFERENCE,
    EVIDENCE_CLASSIFICATION_PROPOSED_ACTION,
    EVIDENCE_CLASSIFICATION_UNKNOWN,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    OBSERVATION_STATUS_CANCELED,
    OBSERVATION_STATUS_EXECUTED,
    OBSERVATION_STATUS_FAILED,
    OBSERVATION_STATUS_PROPOSED,
    OBSERVATION_STATUS_VERIFIED,
    TARGET_KIND_COMPARISON,
    TARGET_KIND_FIELD,
    TARGET_KIND_THREAD,
    DeterministicHypothesisGenerator,
    FollowUpObservation,
    HypothesisValidator,
    InvestigationHypothesis,
    OptionalLLMHypothesisAdapter,
    PluggableHypothesisEngine,
    sanitize_and_disarm_llm_hypothesis,
)
from extractor.investigation import (
    InvestigationFinding,
    InvestigationManager,
    InvestigationSession,
    TrustedCausalVerifier,
)
from extractor.static_analyzer import FunctionCandidate
from extractor.web.server import WebRuntimeAdapter


class TestPhase12InvestigationLoop(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.corpus_dir = self.temp_dir.name
        self.manager = InvestigationManager(corpus_dir=self.corpus_dir)
        self.runtime = AgentRuntime(corpus_dir=self.corpus_dir)
        self.adapter = WebRuntimeAdapter(self.runtime)

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # Scenario 1: Field Change with DWARF-Linked Static Candidate
    # -------------------------------------------------------------------------
    def test_scenario_1_field_change_with_dwarf_linked_static_candidate(self):
        """Memory inspection reveals field change linked via DWARF to a candidate function.

        Hypothesis is generated with:
        - Concise proposed mechanism
        - Target object/field
        - Classification INFERENCE
        - Candidate tier STATIC_CANDIDATE
        """
        finding = InvestigationFinding(
            finding_id="find_field_01",
            category="fact",
            title="State Discrepancy: WorkerPool.active_workers",
            description="Value changed unexpectedly from 0 to 4",
            object_id="obj_worker_pool_0x1000",
            field_name="active_workers",
            c_type_path="WorkerPool::active_workers",
            status="CONFIRMED",
            confidence=CONFIDENCE_HIGH,
            supporting_evidence_ids=["ev_field_change_01"],
            classification=EVIDENCE_CLASSIFICATION_FACT,
        )

        func_candidate = FunctionCandidate(
            function_name="WorkerPool::spawn_worker(int)",
            source_location="/src/pool.cpp:42",
            related_target="active_workers",
            reason="DWARF reference in member function",
            evidence_level="static",
            basis_source="DWARF",
            limitations="Static analysis only",
            causal_classification="STATIC_CANDIDATE",
        )

        generator = DeterministicHypothesisGenerator()
        hypotheses = generator.generate_from_findings([finding], function_candidates=[func_candidate])

        self.assertGreaterEqual(len(hypotheses), 1)
        h = hypotheses[0]
        self.assertEqual(h.target_object_id, "obj_worker_pool_0x1000")
        self.assertEqual(h.target_field_path, "WorkerPool::active_workers")
        self.assertEqual(h.classification, EVIDENCE_CLASSIFICATION_INFERENCE)
        self.assertIn("spawn_worker", h.proposed_mechanism)
        self.assertIn("ev_field_change_01", h.supporting_evidence_ids)

        # Check candidate function tier: MUST be STATIC_CANDIDATE
        self.assertEqual(len(h.function_candidates), 1)
        fc = h.function_candidates[0]
        tier = fc.get("candidate_tier") or fc.get("causal_classification")
        self.assertEqual(tier, FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(fc.get("confirmed_root_cause", False))
        self.assertFalse(fc.get("causal_proof_established", False))

    # -------------------------------------------------------------------------
    # Scenario 2: Two Competing Hypotheses Requiring Discriminating Observations
    # -------------------------------------------------------------------------
    def test_scenario_2_competing_hypotheses_with_discriminating_observations(self):
        """Two candidate functions for the same field change produce competing hypotheses.

        Generator produces distinct hypotheses with discriminating questions and criteria.
        """
        finding = InvestigationFinding(
            finding_id="find_pkt_queue",
            category="fact",
            title="Queue Overflow: PacketRouter.dropped_count",
            description="dropped_count incremented from 10 to 25",
            object_id="obj_router_0x5000",
            field_name="dropped_count",
            c_type_path="PacketRouter::dropped_count",
            status="CONFIRMED",
            confidence=CONFIDENCE_HIGH,
            supporting_evidence_ids=["ev_diff_01"],
            classification=EVIDENCE_CLASSIFICATION_FACT,
        )

        candidate_a = FunctionCandidate(
            function_name="PacketRouter::handle_burst_ingress()",
            source_location="/src/router.cpp:110",
            related_target="dropped_count",
            reason="Writes to dropped_count on buffer saturation",
            evidence_level="static",
            basis_source="DWARF",
            limitations="Static analysis only",
            causal_classification="STATIC_CANDIDATE",
        )

        candidate_b = FunctionCandidate(
            function_name="PacketRouter::prune_expired_sessions()",
            source_location="/src/router.cpp:240",
            related_target="dropped_count",
            reason="Writes to dropped_count on TTL expiration",
            evidence_level="static",
            basis_source="DWARF",
            limitations="Static analysis only",
            causal_classification="STATIC_CANDIDATE",
        )

        generator = DeterministicHypothesisGenerator()
        hypotheses = generator.generate_from_findings([finding], function_candidates=[candidate_a, candidate_b])

        self.assertGreaterEqual(len(hypotheses), 2)
        h_a = next(h for h in hypotheses if "handle_burst_ingress" in h.proposed_mechanism)
        h_b = next(h for h in hypotheses if "prune_expired_sessions" in h.proposed_mechanism)

        # Both must require discriminating evidence to resolve
        self.assertTrue(len(h_a.discriminating_evidence_needed) > 0)
        self.assertTrue(len(h_b.discriminating_evidence_needed) > 0)

        # Observations must be distinct
        self.assertGreaterEqual(len(h_a.suggested_observations), 1)
        self.assertGreaterEqual(len(h_b.suggested_observations), 1)
        obs_a = h_a.suggested_observations[0]
        obs_b = h_b.suggested_observations[0]
        self.assertNotEqual(obs_a.observation_id, obs_b.observation_id)
        self.assertIn("handle_burst_ingress", obs_a.question)
        self.assertIn("prune_expired_sessions", obs_b.question)

    # -------------------------------------------------------------------------
    # Scenario 3: Observation Outcome Supports One & Contradicts Another
    # -------------------------------------------------------------------------
    def test_scenario_3_observation_outcome_supports_one_contradicts_other(self):
        """Executing an observation with verified outcome supports H1 and contradicts H2.

        Timeline records both the execution and evaluation events.
        """
        session_dict = self.manager.start_investigation(goal="Resolve router drop discrepancy")
        inv_id = session_dict["investigation_id"]
        session = self.manager.sessions[inv_id]

        # Seed initial evidence record
        seed_ev = session.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="memory_inspector",
            details={"object_id": "router_01", "field": "dropped", "value": 15},
            summary="Initial dropped count is 15",
        )

        obs_a = FollowUpObservation(
            observation_id="obs_trace_burst",
            question="Did handle_burst_ingress execute during the interval?",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="router_01",
            discriminating_criteria="Active caller trace shows handle_burst_ingress in call stack",
            expected_outcomes={"true": "Supports burst hypothesis", "false": "Contradicts burst hypothesis"},
            safety_constraints=["READ_ONLY"],
        )

        obs_b = FollowUpObservation(
            observation_id="obs_trace_ttl",
            question="Did prune_expired_sessions execute during the interval?",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="router_01",
            discriminating_criteria="Active caller trace shows prune_expired_sessions in call stack",
            expected_outcomes={"true": "Supports TTL hypothesis", "false": "Contradicts TTL hypothesis"},
            safety_constraints=["READ_ONLY"],
        )

        hypo_a = InvestigationHypothesis(
            hypothesis_id="hypo_burst",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="router_01.dropped",
            proposed_mechanism="Packet burst overflow in handle_burst_ingress",
            claim="handle_burst_ingress caused drop counter bump",
            supporting_evidence_ids=[seed_ev.evidence_id],
            suggested_observations=[obs_a],
            competing_hypothesis_ids=["hypo_ttl"],
            function_candidates=[{"function_name": "handle_burst_ingress", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE}],
        )

        hypo_b = InvestigationHypothesis(
            hypothesis_id="hypo_ttl",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="router_01.dropped",
            proposed_mechanism="Session TTL expiration in prune_expired_sessions",
            claim="prune_expired_sessions caused drop counter bump",
            supporting_evidence_ids=[seed_ev.evidence_id],
            suggested_observations=[obs_b],
            competing_hypothesis_ids=["hypo_burst"],
            function_candidates=[{"function_name": "prune_expired_sessions", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE}],
        )

        session.hypotheses.extend([hypo_a, hypo_b])
        session.follow_up_observations.extend([obs_a, obs_b])

        # Execute observation for burst: outcome confirms burst activity
        exec_res = self.manager.execute_observation(
            inv_id,
            "obs_trace_burst",
            result_data={
                "outcome": "CONFIRMED",
                "verified": True,
                "evidence_summary": "Trace proves handle_burst_ingress called with buffer queue full",
            },
        )
        self.assertTrue(exec_res["success"])
        self.assertEqual(obs_a.status, OBSERVATION_STATUS_VERIFIED)

        # Evaluate hypo_a (supported)
        eval_a = self.manager.evaluate_hypothesis(inv_id, "hypo_burst")
        self.assertTrue(eval_a["success"])
        self.assertEqual(hypo_a.status, HYPOTHESIS_STATUS_SUPPORTED)

        # Evaluate hypo_b with contradiction evidence from hypo_a
        contradicting_ev = eval_a["new_evidence_id"]
        eval_b = self.manager.evaluate_hypothesis(
            inv_id,
            "hypo_ttl",
            new_evidence_data={
                "evidence_type": EVIDENCE_TYPE_HYPOTHESIS,
                "nature": NATURE_OBSERVATION,
                "summary": "Competing burst mechanism proved active, contradicting TTL hypothesis",
                "contradicts_hypothesis_id": "hypo_ttl",
                "parent_evidence_ids": [contradicting_ev],
            },
        )
        self.assertTrue(eval_b["success"])
        self.assertEqual(hypo_b.status, HYPOTHESIS_STATUS_CONTRADICTED)
        self.assertIn(contradicting_ev, hypo_b.contradicting_evidence_ids)

        # Timeline verification
        timeline_res = self.manager.get_investigation_timeline(inv_id)
        self.assertTrue(timeline_res["success"])
        events = timeline_res["timeline"]
        event_types = [e["event_type"] for e in events]
        self.assertIn("OBSERVATION_EXECUTED", event_types)
        self.assertIn("HYPOTHESIS_STATUS_UPDATED", event_types)

    # -------------------------------------------------------------------------
    # Scenario 4: Insufficient Evidence Produces UNKNOWN / INCONCLUSIVE
    # -------------------------------------------------------------------------
    def test_scenario_4_inconclusive_or_insufficient_evidence_never_falsely_supports(self):
        """Observations with inconclusive or insufficient data do not grant false support.

        Hypothesis remains INCONCLUSIVE or PROPOSED, and unknowns are made explicit.
        """
        session_dict = self.manager.start_investigation(goal="Investigate inconclusive state")
        inv_id = session_dict["investigation_id"]
        session = self.manager.sessions[inv_id]

        obs = FollowUpObservation(
            observation_id="obs_ambiguous",
            question="Is mutex contention causing the worker lag?",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="worker_01.lag",
            discriminating_criteria="Lock wait latency exceeds 50ms",
            expected_outcomes={"true": "Supported", "false": "Contradicted"},
        )
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_contention",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="worker_01.lag",
            proposed_mechanism="Mutex contention on task dispatch",
            claim="Lock latency caused lag",
            suggested_observations=[obs],
        )
        session.hypotheses.append(hypo)
        session.follow_up_observations.append(obs)

        # Execute observation returning INCONCLUSIVE
        res = self.manager.execute_observation(
            inv_id,
            "obs_ambiguous",
            result_data={
                "outcome": "INCONCLUSIVE",
                "verified": False,
                "evidence_summary": "Lock counters unreadable due to partial debug symbols; insufficient evidence.",
            },
        )
        self.assertTrue(res["success"])

        # Evaluate hypothesis: MUST NOT BE SUPPORTED
        eval_res = self.manager.evaluate_hypothesis(inv_id, "hypo_contention")
        self.assertTrue(eval_res["success"])
        self.assertIn(hypo.status, (HYPOTHESIS_STATUS_INCONCLUSIVE, HYPOTHESIS_STATUS_PROPOSED))
        self.assertNotEqual(hypo.status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertNotEqual(hypo.status, HYPOTHESIS_STATUS_VALIDATED)

        # Supporting count must not be inflated
        self.assertEqual(len(hypo.supporting_evidence_ids), 0)

    # -------------------------------------------------------------------------
    # Scenario 5: LLM Hallucinations & Overclaims Disarmed
    # -------------------------------------------------------------------------
    def test_scenario_5_llm_hallucinations_and_overclaims_disarmed(self):
        """Sanitizer disarms fabricated evidence IDs, unproven VALIDATED status, and candidate tier."""
        session_dict = self.manager.start_investigation(goal="Test LLM Sanitization")
        inv_id = session_dict["investigation_id"]
        session = self.manager.sessions[inv_id]

        real_ev = session.ledger.record(
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            nature=NATURE_OBSERVATION,
            source="test",
            details={"foo": "bar"},
            summary="Real evidence",
        )

        malicious_or_hallucinated_llm_dict = {
            "hypothesis_id": "hypo_hallucinated",
            "claim": "Root cause definitively located in kernel driver",
            "proposed_mechanism": "Attacker memory overwrite",
            "status": "VALIDATED",  # Claiming validated without proof
            "confidence": "HIGH",
            "supporting_evidence_ids": [real_ev.evidence_id, "ev_fabricated_9999", "fake_ledger_entry"],
            "classification": "EXECUTIVE_DECISION",  # Invalid enum
            "function_candidates": [
                {
                    "function_name": "malicious_fn",
                    "candidate_tier": "VALIDATED_CAUSAL_FUNCTION",  # Self-promotion
                    "confirmed_root_cause": True,
                }
            ],
            "execution_provenance": {"unverified_claim": True},
        }

        sanitized = sanitize_and_disarm_llm_hypothesis(malicious_or_hallucinated_llm_dict, session.ledger)

        # 1. Status disarmed to PROPOSED
        self.assertEqual(sanitized.status, HYPOTHESIS_STATUS_PROPOSED)

        # 2. Fabricated evidence IDs stripped
        self.assertEqual(sanitized.supporting_evidence_ids, [real_ev.evidence_id])
        self.assertNotIn("ev_fabricated_9999", sanitized.supporting_evidence_ids)
        self.assertNotIn("fake_ledger_entry", sanitized.supporting_evidence_ids)

        # 3. Candidate tier downgraded to STATIC_CANDIDATE
        fc = sanitized.function_candidates[0]
        self.assertEqual(fc["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(fc["confirmed_root_cause"])

        # 4. Classification normalized to INFERENCE
        self.assertEqual(sanitized.classification, EVIDENCE_CLASSIFICATION_INFERENCE)

    # -------------------------------------------------------------------------
    # Scenario 6: STATIC_CANDIDATE Never Promoted Without Causal Instrumentation
    # -------------------------------------------------------------------------
    def test_scenario_6_static_candidate_never_promoted_without_causal_instrumentation(self):
        """Caller booleans, DWARF references, or call graphs alone cannot promote STATIC_CANDIDATE.

        Only a verified ControlledExecutionResult with single-writer proof can upgrade tier.
        """
        session_dict = self.manager.start_investigation(goal="Attribution test")
        inv_id = session_dict["investigation_id"]
        session = self.manager.sessions[inv_id]

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_func_attribution",
            investigation_id=inv_id,
            target_kind=TARGET_KIND_FIELD,
            target_identifier="obj.counter",
            proposed_mechanism="increment() modified counter",
            function_candidates=[{"function_name": "increment()", "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE}],
        )
        session.hypotheses.append(hypo)

        # Attempt 1: Caller claims deterministic_transition_verified=True without proof_evidence_id
        res1 = self.manager.evaluate_hypothesis(
            inv_id,
            "hypo_func_attribution",
            deterministic_transition_verified=True,
            proof_evidence_id=None,
        )
        self.assertTrue(res1["success"])
        self.assertNotEqual(hypo.status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(hypo.function_candidates[0]["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)

        # Attempt 2: Attest causal proof via TrustedCausalVerifier
        rec = session.ledger.record(
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="controlled_reproduction",
            details={
                "observation": "deterministic transition reproduced",
                "target_function": "increment()",
                "field_path": "obj.counter",
            },
            summary="Controlled reproduction step",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        hypo.supporting_evidence_ids.append(rec.evidence_id)

        verifier = TrustedCausalVerifier(session)
        res_temp = ControlledExecutionResult(
            execution_id="exec_receipt_01",
            investigation_id=inv_id,
            target_function="increment()",
            field_path="obj.counter",
            before_value=10,
            after_value=11,
            execution_status="REPRODUCED",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            hypothesis_id="hypo_func_attribution",
            evidence_id=rec.evidence_id,
            function_attribution_verified=True,
            attribution_basis="SINGLE_WRITER_ISOLATED",
        )
        sig = compute_receipt_signature(session._session_secret, res_temp)
        receipt = ControlledExecutionResult(
            execution_id=res_temp.execution_id,
            investigation_id=res_temp.investigation_id,
            target_function=res_temp.target_function,
            field_path=res_temp.field_path,
            before_value=res_temp.before_value,
            after_value=res_temp.after_value,
            execution_status=res_temp.execution_status,
            capture_quality=res_temp.capture_quality,
            hypothesis_id=res_temp.hypothesis_id,
            evidence_id=res_temp.evidence_id,
            function_attribution_verified=res_temp.function_attribution_verified,
            attribution_basis=res_temp.attribution_basis,
            receipt_signature=sig,
        )

        verifier.verify_execution_and_attest(
            evidence_id=rec.evidence_id,
            hypothesis_id="hypo_func_attribution",
            execution_result=receipt,
        )

        res2 = self.manager.evaluate_hypothesis(
            inv_id,
            "hypo_func_attribution",
            deterministic_transition_verified=True,
            proof_evidence_id=rec.evidence_id,
        )
        self.assertTrue(res2["success"])
        self.assertEqual(hypo.status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(hypo.function_candidates[0]["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertTrue(hypo.function_candidates[0]["confirmed_root_cause"])

    # -------------------------------------------------------------------------
    # Scenario 7: Degraded Capture Quality Caps Hypotheses
    # -------------------------------------------------------------------------
    def test_scenario_7_degraded_capture_quality_caps_hypotheses(self):
        """NON_ATOMIC and PARTIAL capture quality caps hypothesis confidence and blocks causal proof."""
        session_dict = self.manager.start_investigation(goal="Non-atomic capture test")
        inv_id = session_dict["investigation_id"]
        session = self.manager.sessions[inv_id]

        # Inject non-atomic quality stage
        session.stages["capture_quality"] = {
            "status": "COMPLETED",
            "details": {
                "consistency_level": "NON_ATOMIC",
                "stop_mechanism": "NONE",
                "partial_reads": 2,
                "limitations": ["Zero-stop capture: memory read concurrently with running target"],
            },
        }

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_skew",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="obj.skewed_field",
            proposed_mechanism="Possible writer race",
            confidence=CONFIDENCE_HIGH,
        )
        session.hypotheses.append(hypo)

        eval_res = self.manager.evaluate_hypothesis(inv_id, "hypo_skew")
        self.assertTrue(eval_res["success"])

        # Confidence capped due to NON_ATOMIC capture
        self.assertIn(hypo.confidence, (CONFIDENCE_LOW, CONFIDENCE_SPECULATIVE))
        self.assertIn("non-atomic", hypo.confidence_rationale.lower())

        # Overall session conclusions must reflect limitation
        conclusions = session.synthesize_causal_conclusions()
        self.assertFalse(conclusions["causal_proof_established"])
        self.assertIsNotNone(conclusions["causal_limitation_notice"])
        self.assertIn("NON_ATOMIC", conclusions["causal_limitation_notice"])

    # -------------------------------------------------------------------------
    # Scenario 8: Caller-Controlled Trust Flags & Forged Ingress Fail Closed
    # -------------------------------------------------------------------------
    def test_scenario_8_caller_trust_flags_and_forged_ingress_fail_closed(self):
        """Invalid PIDs, forged receipts, and fake parent evidence fail closed."""
        # 1. Invalid PID formats fail closed
        res_pid_str = self.manager.start_investigation(goal="Invalid PID", pid="not_a_pid_123")
        self.assertEqual(res_pid_str["status"], "FAILED")
        self.assertIn("Invalid PID format", res_pid_str["summary"]["error"])

        res_pid_bool = self.manager.start_investigation(goal="Bool PID", pid=True)
        self.assertEqual(res_pid_bool["status"], "FAILED")
        self.assertIn("Invalid PID format", res_pid_bool["summary"]["error"])

        # 2. Forged execution receipt signature fails closed
        session_dict = self.manager.start_investigation(goal="Forged receipt test")
        inv_id = session_dict["investigation_id"]
        session = self.manager.sessions[inv_id]

        forged_result = ControlledExecutionResult(
            execution_id="exec_forged_01",
            investigation_id=inv_id,
            target_function="steal_data",
            field_path="obj.secret",
            before_value=0,
            after_value=1,
            execution_status="REPRODUCED",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            receipt_signature="deadbeef000000000000000000000000",
        )
        self.assertFalse(forged_result.verify_authenticity(session._session_secret))

        verifier = TrustedCausalVerifier(session)
        with self.assertRaises(ValueError) as ctx:
            verifier.verify_execution_and_attest(
                evidence_id="ev_dummy",
                hypothesis_id="hypo_dummy",
                execution_result=forged_result,
            )
        self.assertIn("signature", str(ctx.exception).lower())

    # -------------------------------------------------------------------------
    # Scenario 9: Bounded Investigation Cycle Limits & Safety
    # -------------------------------------------------------------------------
    def test_scenario_9_bounded_investigation_cycle_limits_and_safety(self):
        """Bounded loop enforces iteration limits, stops on contradiction, and handles safety."""
        session_dict = self.manager.start_investigation(goal="Cycle test")
        inv_id = session_dict["investigation_id"]
        session = self.manager.sessions[inv_id]

        obs1 = FollowUpObservation(
            observation_id="obs_loop_1",
            question="Step 1 check",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="obj.f1",
            safety_constraints=["READ_ONLY"],
        )
        obs2 = FollowUpObservation(
            observation_id="obs_loop_2",
            question="Step 2 check",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="obj.f2",
            safety_constraints=["MUTATION", "REQUIRES_AUTHORIZATION"],  # Unsafe/blocked
        )
        obs3 = FollowUpObservation(
            observation_id="obs_loop_3",
            question="Step 3 check",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="obj.f3",
            safety_constraints=["READ_ONLY"],
        )

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_loop",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="obj.f1",
            proposed_mechanism="Loop mechanism",
            suggested_observations=[obs1, obs2, obs3],
        )
        session.hypotheses.append(hypo)
        session.follow_up_observations.extend([obs1, obs2, obs3])

        # Run cycle with max_iterations=2: loop MUST NOT exceed 2 iterations
        cycle_res = self.manager.run_investigation_cycle(
            inv_id,
            max_iterations=2,
            max_observations=1,
            stop_on_contradiction=True,
        )
        self.assertTrue(cycle_res["success"])
        self.assertLessEqual(cycle_res["iterations_completed"], 2)
        self.assertLessEqual(cycle_res["observations_executed"], 1)

        # Unsafe observation requiring authorization must not execute silently
        blocked_res = self.manager.execute_observation(inv_id, "obs_loop_2")
        self.assertFalse(blocked_res["success"])
        self.assertTrue(blocked_res.get("blocked", False))
        self.assertEqual(obs2.status, OBSERVATION_STATUS_PROPOSED)

    # -------------------------------------------------------------------------
    # Scenario 10: Resumed Session Persistence Revalidates Tampered State
    # -------------------------------------------------------------------------
    def test_scenario_10_resumed_session_persistence_revalidates_tampered_state(self):
        """Persisted investigation session is saved and reloaded.

        If an attacker tampers with the saved file/dict (e.g. promoting status),
        revalidation against the ledger disarms the injection.
        """
        session_dict = self.manager.start_investigation(goal="Persistence validation")
        inv_id = session_dict["investigation_id"]
        session = self.manager.sessions[inv_id]

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_persist",
            target_kind=TARGET_KIND_FIELD,
            target_identifier="obj.x",
            proposed_mechanism="Test mechanism",
            status=HYPOTHESIS_STATUS_PROPOSED,
        )
        session.hypotheses.append(hypo)

        # Save session
        save_file = os.path.join(self.corpus_dir, f"{inv_id}.json")
        save_res = self.manager.save_session(inv_id, file_path=save_file)
        self.assertTrue(save_res["success"])

        # Malicious attacker tampers with the saved JSON on disk
        with open(save_file, "r", encoding="utf-8") as f:
            saved_data = json.load(f)

        # Inject fake validated status and fake evidence into hypothesis
        for h in saved_data["hypotheses"]:
            h["status"] = "VALIDATED"
            h["supporting_evidence_ids"] = ["ev_injected_attacker_99"]

        with open(save_file, "w", encoding="utf-8") as f:
            json.dump(saved_data, f)

        # Load session back: revalidation against ledger MUST DISARM the injected status
        loaded_res = self.manager.load_session(save_file)
        self.assertTrue(loaded_res["success"])
        loaded_session = self.manager.sessions[loaded_res["investigation_id"]]

        loaded_hypo = loaded_session.hypotheses[0]
        self.assertNotEqual(loaded_hypo.status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(loaded_hypo.status, HYPOTHESIS_STATUS_PROPOSED)
        self.assertNotIn("ev_injected_attacker_99", loaded_hypo.supporting_evidence_ids)

    # -------------------------------------------------------------------------
    # Scenario 11: ARP, REST API & UI Semantic Agreement
    # -------------------------------------------------------------------------
    def test_scenario_11_rest_api_arp_and_ui_semantic_agreement(self):
        """Verify contract agreement between ARP action dispatcher and REST API routes."""
        # 1. Start investigation via ARP
        arp_start = self.runtime.dispatch_action(
            AgentAction(action="START_INVESTIGATION", goal="Semantic parity check")
        )
        self.assertTrue(arp_start.success)
        inv_id = arp_start.data["investigation_id"]

        # 2. GET_INVESTIGATION_TIMELINE via ARP & REST
        arp_timeline = self.runtime.dispatch_action(
            AgentAction(action="GET_INVESTIGATION_TIMELINE", investigation_id=inv_id)
        )
        self.assertTrue(arp_timeline.success)
        rest_timeline = self.adapter.get_investigation_timeline(inv_id)
        self.assertTrue(rest_timeline["success"])
        self.assertEqual(len(arp_timeline.data["timeline"]), len(rest_timeline["data"]["timeline"]))

        # 3. GET_FINDING_DRILLDOWN via ARP & REST
        # Seed a finding in session
        session = self.runtime.investigation_manager.sessions[inv_id]
        finding = InvestigationFinding(
            finding_id="find_parity_01",
            category="fact",
            title="Parity Check Finding",
            description="Testing contract agreement",
            object_id="obj_parity",
            field_name="val",
            status="CONFIRMED",
        )
        session.findings.append(finding)

        arp_drill = self.runtime.dispatch_action(
            AgentAction(action="GET_FINDING_DRILLDOWN", investigation_id=inv_id, finding_id="find_parity_01")
        )
        self.assertTrue(arp_drill.success)
        rest_drill = self.adapter.get_finding_drilldown(inv_id, "find_parity_01")
        self.assertTrue(rest_drill["success"])
        self.assertEqual(arp_drill.data["drilldown"]["finding"]["finding_id"], rest_drill["data"]["drilldown"]["finding"]["finding_id"])

        # 4. PROPOSE_HYPOTHESIS via ARP & REST
        hypo_dict = {
            "hypothesis_id": "hypo_parity_arp",
            "target_kind": "FIELD",
            "target_identifier": "obj_parity.val",
            "claim": "Claim via ARP",
            "proposed_mechanism": "Mechanism ARP",
        }
        arp_propose = self.runtime.dispatch_action(
            AgentAction(action="PROPOSE_HYPOTHESIS", investigation_id=inv_id, hypothesis_data=hypo_dict)
        )
        self.assertTrue(arp_propose.success)

        rest_propose = self.adapter.propose_hypothesis({
            "investigation_id": inv_id,
            "hypothesis_data": {
                "hypothesis_id": "hypo_parity_rest",
                "target_kind": "FIELD",
                "target_identifier": "obj_parity.val",
                "claim": "Claim via REST",
                "proposed_mechanism": "Mechanism REST",
            },
        })
        self.assertTrue(rest_propose["success"])

        # Both hypotheses now in session
        self.assertEqual(len(session.hypotheses), 2)

        # 5. RUN_INVESTIGATION_CYCLE via ARP & REST
        arp_cycle = self.runtime.dispatch_action(
            AgentAction(action="RUN_INVESTIGATION_CYCLE", investigation_id=inv_id, max_iterations=2)
        )
        self.assertTrue(arp_cycle.success)

        rest_cycle = self.adapter.run_investigation_cycle({
            "investigation_id": inv_id,
            "max_iterations": 2,
        })
        self.assertTrue(rest_cycle["success"])


if __name__ == "__main__":
    unittest.main()
